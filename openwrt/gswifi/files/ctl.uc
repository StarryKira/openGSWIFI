#!/usr/bin/ucode
// SPDX-License-Identifier: MIT
//
// gswifi ctl - what the init script, the LuCI app and a person on the
// console use to look at and steer the service.
//
//   ctl networks               write the TOML of every enabled network;
//                              prints "<id> TAB <device> TAB <file>" each
//   ctl interfaces             netifd interfaces whose changes matter here
//   ctl status                 JSON snapshot of all networks
//   ctl drivers                `gswifi drivers --json`
//   ctl protect                JSON: applied plan, live counters, proxy
//   ctl protect-apply [force]  bring the rules in line with UCI
//   ctl protect-remove         take the rules out (service stop, removal)
//   ctl protect-check          text of `gswifi protect check`, side-effect free
//   ctl protect-show           text of `gswifi protect show`
//   ctl restart [id]           re-authenticate one network, or all
//   ctl enable <id> <0|1>      switch one network on or off and apply
//   ctl pppoe <ver> <user> [offset]   NetKeeper dial-up name as JSON
//   ctl log [lines]            the service's lines from the system log
//   ctl diag                   text bundle for bug reports (no passwords)
//
// protect-apply and protect-remove must run under the lock taken by
// /usr/libexec/gswifi/protect; call that wrapper, not these, by hand.

'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import * as config from 'gswifi.config';
import * as protect from 'gswifi.protect';
import * as status from 'gswifi.status';
import * as util from 'gswifi.util';

const INIT = '/etc/init.d/gswifi';
const PROTECT = '/usr/libexec/gswifi/protect';

function out_json(value) {
	print(sprintf('%J', value), '\n');
}

function cmd_networks() {
	config.ensure_dirs();

	let cur = cursor();
	let conn = connect();

	cur.load('network');

	let conf = config.load(cur);
	let drivers = config.load_drivers();
	let keep = {};

	if (drivers == null)
		warn(`无法从 ${config.BIN} 读取认证方式列表，不启动任何会话\n`);

	for (let net in conf.networks) {
		let id = net['.name'];

		if (!config.flag(net.enabled, false))
			continue;

		let info = drivers?.[net.driver ?? 'ruijie'];
		let device = status.network_device(conn, cur, net, info);
		let r = config.network_toml(net, device, info);

		for (let p in r.problems)
			warn(`网络 ${id}：${p}\n`);

		if (r.toml == null)
			continue;

		let name = `net.${id}.toml`;

		config.write_private(`${config.ETC_DIR}/${name}`, r.toml);
		keep[name] = true;
		print(`${id}\t${device}\t${config.ETC_DIR}/${name}\n`);
	}

	// Networks that were switched off or removed leave nothing behind:
	// the file holds a password.
	for (let name in fs.lsdir(config.ETC_DIR) ?? [])
		if (match(name, /^net\..*\.toml(\.tmp)?$/) && !keep[name])
			fs.unlink(`${config.ETC_DIR}/${name}`);

	for (let name in fs.lsdir(config.STATUS_DIR) ?? []) {
		let m = match(name, /^(.*)\.json(\.tmp)?$/);

		if (m && !keep[`net.${m[1]}.toml`])
			fs.unlink(`${config.STATUS_DIR}/${name}`);
	}
}

// The netifd interfaces the service derives devices from. A change of one
// of them (PPPoE coming up as pppoe-wan, a device being renamed) has to
// regenerate the configuration; the init script turns these into reload
// triggers.
function cmd_interfaces() {
	let conf = config.load();
	let names = {};

	for (let net in conf.networks)
		if (config.flag(net.enabled, false) && (net.device ?? '') == '' && config.valid_iface(net.interface ?? 'wan'))
			names[net.interface ?? 'wan'] = true;

	if (config.protect_mode(conf.protect) != 'disabled')
		for (let name in [ ...config.as_list(conf.protect.wan), ...config.as_list(conf.protect.lan) ])
			if (config.valid_iface(name))
				names[name] = true;

	for (let name in sort(keys(names)))
		print(name, '\n');
}

function cmd_protect_check() {
	// `check` writes the files it tests; give it a scratch directory so
	// the live ruleset, DNS fragment and sysctl file stay as they are.
	let dir = `${config.RUN_DIR}/check`;
	let want = protect.desired();
	let conf = `${dir}/protect.toml`;

	config.ensure_dirs();
	fs.mkdir(dir, 0o700);
	fs.mkdir(`${dir}/dnsmasq.d`, 0o700);
	config.write_private(conf, want.toml);

	let lines = [];

	for (let p in want.problems)
		push(lines, `注意：${p}`);

	if (want.mode == 'disabled')
		push(lines, '当前模式是 disabled：下面按 observe 模式检查，只是为了看规则能否通过，不会安装。');

	let argv = [
		config.BIN, 'protect', 'check', '-c', conf,
		'--nft-file', `${dir}/protect.nft`,
		'--sysctl-file', `${dir}/protect.sysctl`,
		'--dnsmasq-conf-dir', want.dns_dir ? `${dir}/dnsmasq.d` : ''
	];

	if (want.mode == 'disabled')
		push(argv, '--mode', 'observe');

	let r = util.capture(argv, 'merge');

	for (let name in [ 'protect.nft', 'protect.sysctl', 'protect.toml', 'dnsmasq.d/gswifi-protect.conf' ])
		fs.unlink(`${dir}/${name}`);

	fs.rmdir(`${dir}/dnsmasq.d`);
	fs.rmdir(dir);

	print(join('\n', lines), length(lines) ? '\n' : '', r.out);

	return r.code;
}

function cmd_protect_show() {
	let want = protect.desired();
	let conf = `${config.RUN_DIR}/show.toml`;

	config.ensure_dirs();
	config.write_private(conf, want.toml);

	let argv = [ config.BIN, 'protect', 'show', '-c', conf ];

	if (want.mode == 'disabled')
		push(argv, '--mode', 'observe');

	let r = util.capture(argv, 'merge');

	fs.unlink(conf);

	if (want.mode == 'disabled')
		print('当前模式是 disabled：下面是改为 observe 后会安装的规则。\n');

	print(r.out);

	return r.code;
}

function cmd_restart(id) {
	if (id != null && !config.valid_id(id)) {
		warn('无效的网络名称\n');

		return 1;
	}

	// Only the sessions are restarted; the protect rules stay loaded.
	// `stop <id>` returns once that session has logged off and exited, so
	// the new one does not start while the old logoff is still going out.
	let ids = (id != null) ? [ id ] : keys(connect()?.call('service', 'list', { name: 'gswifi' })?.gswifi?.instances ?? {});

	for (let name in ids)
		if (name != 'proxy' && config.valid_id(name))
			system([ INIT, 'stop', name ]);

	return system([ INIT, 'start' ]);
}

function cmd_enable(id, value) {
	if (!config.valid_id(id) || !(value in [ '0', '1' ])) {
		warn('usage: ctl enable <id> <0|1>\n');

		return 1;
	}

	let cur = cursor();

	if (cur.get('gswifi', id) != 'network') {
		warn(`没有名为 ${id} 的网络\n`);

		return 1;
	}

	cur.set('gswifi', id, 'enabled', value);
	cur.commit('gswifi');

	return system([ INIT, 'reload' ]);
}

function cmd_pppoe(version, username, offset) {
	let v = int(version ?? '', 10);

	if (type(v) != 'int' || v < 1 || v > 255 || type(username) != 'string' || username == '') {
		out_json({ error: '需要 nk_version 和账号' });

		return 1;
	}

	let argv = [ config.BIN, 'pppoe-username', '--format', 'json', '-v', `${v}`, '-u', username ];

	if (match(offset ?? '', /^-?[0-9]{1,9}$/))
		push(argv, '--time-offset', offset);

	let r = util.capture(argv, 'merge');
	let parsed = null;

	// With stderr merged the JSON is one of several lines.
	for (let l in split(r.out, '\n'))
		if (substr(l, 0, 1) == '{')
			parsed = util.parse_json(l);

	if (r.code != 0 || type(parsed) != 'object') {
		// "[2026-... ERROR] message" -> "message"
		let m = match(trim(r.out), /\] ([^\n]*)$/);

		out_json({ error: m ? m[1] : (trim(r.out) || '计算失败') });

		return 1;
	}

	out_json(parsed);

	return 0;
}

function cmd_log(lines) {
	let n = int(lines ?? '', 10);

	if (type(n) != 'int' || n < 1)
		n = 300;

	if (n > 5000)
		n = 5000;

	// procd tags the sessions "gswifi-auth[pid]" and the proxy
	// "gswifi-proxy[pid]" (after the wrappers it starts); the scripts
	// log as "gswifi".
	let r = util.capture([ '/sbin/logread', '-e', 'gswifi' ]);
	let all = filter(split(r.out, '\n'), l => match(l, / gswifi(-auth|-proxy)?(\[[0-9]+\])?: /));

	print(join('\n', slice(all, max(0, length(all) - n))), length(all) ? '\n' : '');

	return 0;
}

function mask(text) {
	return replace(text, /(\.password=)[^\n]*/g, "$1'********'");
}

function cmd_diag() {
	let section = (title) => print(`\n## ${title}\n`);
	let run = (argv) => print(util.capture(argv, 'merge').out);

	print(`===== gswifi 诊断信息 ${trim(util.capture([ '/bin/date', '+%Y-%m-%d %H:%M:%S %z' ]).out)} =====\n`);

	section('系统');
	for (let l in split(fs.readfile('/etc/openwrt_release') ?? '', '\n'))
		if (match(l, /^DISTRIB_(DESCRIPTION|TARGET|ARCH)=/))
			print(l, '\n');
	print(`kernel: ${util.read_trim('/proc/sys/kernel/osrelease')}\n`);
	print(`gswifi: ${trim(util.capture([ config.BIN, '--version' ]).out) || '未安装'}\n`);

	section('配置（密码已隐藏）');
	print(mask(util.capture([ '/sbin/uci', '-q', 'show', 'gswifi' ]).out));

	section('会话状态');
	out_json(status.snapshot());

	section('防共享检测');
	out_json(protect.status());
	run([ '/usr/sbin/nft', 'list', 'table', 'inet', 'gswifi' ]);

	section('认证方式');
	run([ config.BIN, 'drivers' ]);

	section('网卡');
	run([ '/sbin/ip', 'addr' ]);

	section('路由');
	run([ '/sbin/ip', 'route' ]);

	section('最近日志');
	cmd_log('300');

	return 0;
}

function main() {
	let cmd = ARGV[0];

	switch (cmd) {
	case 'networks':
		cmd_networks();
		return 0;

	case 'interfaces':
		cmd_interfaces();
		return 0;

	case 'status':
		out_json(status.snapshot());
		return 0;

	case 'drivers': {
		let r = util.capture([ config.BIN, 'drivers', '--json' ]);

		print(r.code == 0 ? r.out : '[]\n');
		return r.code;
	}

	case 'protect':
		out_json(protect.status());
		return 0;

	case 'protect-apply': {
		let state = protect.apply(ARGV[1] == 'force');

		if (!state.ok)
			warn(`${state.error}\n`);

		return state.ok ? 0 : 1;
	}

	case 'protect-remove':
		return protect.remove() ? 0 : 1;

	case 'protect-check':
		return cmd_protect_check();

	case 'protect-show':
		return cmd_protect_show();

	case 'restart':
		return cmd_restart(ARGV[1]);

	case 'enable':
		return cmd_enable(ARGV[1], ARGV[2]);

	case 'pppoe':
		return cmd_pppoe(ARGV[1], ARGV[2], ARGV[3]);

	case 'log':
		return cmd_log(ARGV[1]);

	case 'diag':
		return cmd_diag();
	}

	warn('usage: ctl networks|status|drivers|protect|protect-check|protect-show|restart [id]|enable <id> <0|1>|pppoe <ver> <user> [offset]|log [lines]|diag\n');

	return 1;
}

exit(main());
