// SPDX-License-Identifier: MIT
//
// Applies the `[protect]` plan on OpenWrt: `gswifi protect install` does
// the checking and loading, this module supplies what only the platform
// knows and tidies up what the program leaves to it.
//
//  * The generated ruleset is written to /var/run/gswifi/protect.nft, which
//    fw4 includes at top level through
//    /usr/share/nftables.d/ruleset-post/90-gswifi.nft. It must never go
//    into /etc/nftables.d: fw4 includes that directory *inside*
//    `table inet fw4 { }`, where a `table inet gswifi` statement is a
//    syntax error that takes the whole firewall down on its next restart.
//  * Nothing is kept on flash. After a reboot, or with the service
//    disabled, there is no ruleset, no sysctl file and no DNS fragment
//    until the service installs them again from UCI.
//  * The kernel parameters the plan changes are saved first and put back
//    when the plan no longer sets them (the program only removes its
//    file).
//  * dnsmasq reads its conf-dir at start only, so a changed fragment needs
//    a restart, not the reload the program asks for.
//  * After a load the complete firewall is checked with `fw4 check`; if
//    that fails the rules are taken out again.

'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import * as config from 'gswifi.config';
import * as util from 'gswifi.util';

export const NFT_FILE = '/var/run/gswifi/protect.nft';
export const SYSCTL_FILE = '/var/run/gswifi/protect.sysctl';
export const STATE_FILE = '/var/run/gswifi/protect.json';
export const SAVED_SYSCTL = '/var/run/gswifi/sysctl.saved.json';
export const PROXY_READY = '/var/run/gswifi/proxy.ready';
export const PROXY_STATS = '/var/run/gswifi/proxy.stats';
export const TOML_FILE = '/var/etc/gswifi/protect.toml';

const DNS_FRAGMENT = 'gswifi-protect.conf';
const NFT = '/usr/sbin/nft';
const FW4 = '/sbin/fw4';

// The conf-dir of the running dnsmasq (24.10+: /tmp/dnsmasq.cfgXXXX.d,
// before: /tmp/dnsmasq.d), read from its generated configuration. null:
// no dnsmasq, so the DNS features cannot be provided.
export function dnsmasq_conf_dir() {
	for (let path in fs.glob('/var/etc/dnsmasq.conf.*') ?? []) {
		for (let line in split(fs.readfile(path) ?? '', '\n')) {
			let m = match(line, /^conf-dir=([A-Za-z0-9_.\/-]+)/);

			if (m && fs.stat(m[1])?.type == 'directory')
				return m[1];
		}
	}

	return null;
};

// Whether `gswifi proxy` is accepting connections: its wrapper writes the
// pid once the listener is up and removes it when the program is gone.
export function proxy_pid() {
	let pid = int(util.read_trim(PROXY_READY) ?? '', 10);

	return util.pid_runs(pid, config.BIN) ? pid : null;
};

export function table_installed() {
	return system([ '/bin/sh', '-c', `${NFT} list table inet gswifi >/dev/null 2>&1` ]) == 0;
};

function sysctl_path(key) {
	return match(key, /^[a-z0-9_.]+$/) ? '/proc/sys/' + replace(key, /\./g, '/') : null;
}

// Remembers the current value of every key the plan is about to change,
// once: the first value seen is the one to go back to.
function save_sysctls(plan_keys) {
	let saved = util.read_json(SAVED_SYSCTL) ?? {};
	let changed = false;

	for (let key in plan_keys) {
		let path = sysctl_path(key);

		if (path == null || saved[key] != null)
			continue;

		let value = util.read_trim(path);

		if (value != null) {
			saved[key] = value;
			changed = true;
		}
	}

	if (changed)
		util.write_file(SAVED_SYSCTL, sprintf('%J\n', saved));
}

// Puts back every saved key the plan no longer sets.
function restore_sysctls(plan_keys) {
	let saved = util.read_json(SAVED_SYSCTL);

	if (type(saved) != 'object')
		return [];

	let restored = [];

	for (let key in keys(saved)) {
		if (key in plan_keys)
			continue;

		let path = sysctl_path(key);

		if (path != null && fs.writefile(path, `${saved[key]}\n`) != null)
			push(restored, key);

		delete saved[key];
	}

	if (length(keys(saved)))
		util.write_file(SAVED_SYSCTL, sprintf('%J\n', saved));
	else
		fs.unlink(SAVED_SYSCTL);

	return restored;
}

function install_argv(dns_dir, mode, listening) {
	let argv = [
		config.BIN, 'protect', 'install', '--json',
		'-c', TOML_FILE,
		'--nft-file', NFT_FILE,
		'--sysctl-file', SYSCTL_FILE,
		'--dnsmasq-conf-dir', dns_dir ?? ''
	];

	if (mode != null)
		push(argv, '--mode', mode);

	if (listening)
		push(argv, '--proxy-listening');

	return argv;
}

function fragment(dns_dir) {
	return dns_dir ? fs.readfile(`${dns_dir}/${DNS_FRAGMENT}`) : null;
}

function restart_dnsmasq() {
	system([ '/bin/sh', '-c', '/etc/init.d/dnsmasq restart >/dev/null 2>&1' ]);
}

// What the firewall configuration says about flow offloading: offloaded
// connections bypass nftables after their first packets, so most of the
// plan does not apply to them (README "已知限制").
export function offloading(cur) {
	let soft = false, hard = false;

	cur.load('firewall');
	cur.foreach('firewall', 'defaults', (s) => {
		soft ||= config.flag(s.flow_offloading, false);
		hard ||= config.flag(s.flow_offloading_hw, false);
	});

	return { software: soft, hardware: soft && hard };
};

// Everything `apply` derives from UCI and the running system.
export function desired(cur, conn) {
	cur ??= cursor();
	conn ??= connect();
	cur.load('network');

	let p = config.load(cur).protect;
	let mode = config.protect_mode(p);
	let wan = config.resolve_devices(conn, cur, p.wan, p.wan_device);
	let lan = config.resolve_devices(conn, cur, p.lan, p.lan_device);
	let dns_dir = dnsmasq_conf_dir();
	let listening = config.flag(p.proxy, false) && proxy_pid() != null;
	let problems = [];

	for (let name in wan.missing)
		push(problems, `上行接口 ${name} 没有对应的网卡`);

	for (let name in lan.missing)
		push(problems, `局域网接口 ${name} 没有对应的网卡`);

	let wants_dns = config.flag(p.dns_filter_aaaa, false) || config.flag(p.dns_local_arpa, false) ||
		length(config.as_list(p.dns_blocked_domain)) > 0;

	if (mode != 'disabled' && wants_dns && dns_dir == null)
		push(problems, '没有找到正在运行的 dnsmasq，DNS 设置不会生效');

	return {
		mode,
		wan: wan.devices,
		lan: lan.devices,
		dns_dir,
		listening,
		problems,
		proxy: config.flag(p.proxy, false),
		toml: config.protect_toml(p, wan.devices, lan.devices)
	};
};

function write_state(state) {
	state.at = time();
	state.at_up = util.uptime();
	util.write_file(STATE_FILE, sprintf('%J\n', state));
	fs.chmod(STATE_FILE, 0o600);

	return state;
}

function fw4_check() {
	return system([ '/bin/sh', '-c', `${FW4} -q check >/dev/null 2>&1` ]) == 0;
}

// Removes the rules, the DNS fragment and the changed kernel parameters.
function uninstall(dns_dir) {
	let before = fragment(dns_dir);
	let r = { code: 0, out: '' };

	if (table_installed() || fs.access(NFT_FILE) || before != null || fs.access(SYSCTL_FILE)) {
		// `install --mode disabled` deletes the table and withdraws the
		// files; it only needs a configuration file to exist.
		if (!fs.access(TOML_FILE)) {
			config.ensure_dirs();
			config.write_private(TOML_FILE, '[protect]\nmode = "disabled"\n');
		}

		r = util.capture(install_argv(dns_dir, 'disabled', false));
	}

	restore_sysctls([]);

	if (before != null && fragment(dns_dir) == null)
		restart_dnsmasq();

	// The file now only says "delete the table"; without it fw4 has one
	// include less to read.
	if (r.code == 0)
		fs.unlink(NFT_FILE);

	return r.code == 0;
}

// Brings the system in line with UCI. Returns the state that is also
// written to STATE_FILE for `ctl protect` and the LuCI app.
//   force: reinstall even when nothing changed (resets the counters)
export function apply(force) {
	config.ensure_dirs();

	let want = desired();
	let signature = `${want.toml}\nlistening=${want.listening}\ndns=${want.dns_dir}\n`;
	let old = util.read_json(STATE_FILE);

	config.write_private(TOML_FILE, want.toml);

	let state = {
		mode: want.mode,
		ok: true,
		error: null,
		wan: want.wan,
		lan: want.lan,
		problems: want.problems,
		proxy_listening: want.listening,
		dns_dir: want.dns_dir,
		plan: null,
		signature
	};

	if (want.mode == 'disabled') {
		if (!uninstall(want.dns_dir)) {
			state.ok = false;
			state.error = '撤销规则失败，详见系统日志';
		}

		return write_state(state);
	}

	if (!fs.access(NFT) || !fs.access(FW4)) {
		state.ok = false;
		state.error = '需要 firewall4（nftables）。这台路由器没有 nft 或 fw4，无法安装规则';
		uninstall(want.dns_dir);

		return write_state(state);
	}

	if (!length(want.wan)) {
		// Nothing to match on yet (the uplink may simply not be up).
		// Leave no half-configured rules behind; an interface trigger
		// runs this again once the device exists.
		state.ok = false;
		state.error = '没有可用的上行网卡，规则未安装';
		uninstall(want.dns_dir);

		return write_state(state);
	}

	if (!force && old?.ok && old?.signature == signature && old?.plan && table_installed())
		return old;

	// The keys the plan will write, so their current values can be saved.
	let preview = util.parse_json(util.capture([ config.BIN, 'protect', 'show', '--json', '-c', TOML_FILE ]).out);
	let plan_keys = map(preview?.sysctl ?? [], s => s.key);

	save_sysctls(plan_keys);

	let before = fragment(want.dns_dir);
	let r = util.capture(install_argv(want.dns_dir, null, want.listening));
	let plan = util.parse_json(r.out);

	if (r.code != 0 || type(plan) != 'object' || plan.error != null) {
		// The program keeps the previous state when a check fails; say
		// what is in effect now rather than what was asked for.
		state.ok = false;
		state.error = plan?.error ?? '安装规则失败，详见系统日志';
		state.plan = old?.plan;
		state.stale = true;
		restore_sysctls(table_installed() ? map(old?.plan?.sysctl ?? [], s => s.key) : []);
		util.logger('err', `防共享检测规则未安装：${state.error}`);

		return write_state(state);
	}

	restore_sysctls(plan_keys);

	if (fragment(want.dns_dir) != before)
		restart_dnsmasq();

	// The file is now part of every firewall (re)start. Make sure the
	// firewall as a whole still loads with it; if it does not, find out
	// whether these rules are the reason before taking them out.
	if (!fw4_check()) {
		fs.rename(NFT_FILE, `${NFT_FILE}.hold`);

		let without = fw4_check();

		fs.rename(`${NFT_FILE}.hold`, NFT_FILE);

		if (without) {
			uninstall(want.dns_dir);
			state.ok = false;
			state.error = '加上这些规则后防火墙检查（fw4 check）未通过，已撤销';
			util.logger('err', `防共享检测：${state.error}`);

			return write_state(state);
		}

		push(state.problems, '防火墙自身的配置没有通过 fw4 check（与这些规则无关），请检查防火墙设置');
	}

	delete plan.ruleset;
	state.plan = plan;
	util.logger('notice', `防共享检测：${plan.summary}（上行 ${join(' ', want.wan)}）`);

	return write_state(state);
};

// Service stop and package removal: take everything out, whatever UCI says.
export function remove() {
	let ok = uninstall(dnsmasq_conf_dir());

	fs.unlink(STATE_FILE);
	fs.unlink(NFT_FILE);
	fs.unlink(SYSCTL_FILE);
	fs.unlink(TOML_FILE);

	return ok;
};

// Live view for the status page: the last applied state, the counters of
// the table that is loaded right now, and the proxy.
export function status() {
	let cur = cursor();
	let state = util.read_json(STATE_FILE);
	let counters = util.parse_json(util.capture([ config.BIN, 'protect', 'status', '--json' ]).out);
	let p = config.load(cur).protect;
	let pid = proxy_pid();
	let up = util.uptime();
	let applied_at = null;

	if (state?.at_up != null && up != null)
		applied_at = time() - (up - state.at_up);

	return {
		now: time(),
		tz: trim(util.capture([ '/bin/date', '+%z' ]).out),
		mode: config.protect_mode(p),
		persona: (p.persona in [ 'pc', 'phone' ]) ? p.persona : 'pc',
		available: fs.access(NFT) && fs.access(FW4) ? true : false,
		installed: counters?.installed ? true : false,
		counters: counters?.counters ?? [],
		applied: state ? {
			mode: state.mode,
			ok: state.ok,
			error: state.error,
			stale: state.stale ? true : false,
			at: applied_at,
			wan: state.wan,
			lan: state.lan,
			problems: state.problems,
			proxy_listening: state.proxy_listening,
			plan: state.plan
		} : null,
		proxy: {
			enabled: config.flag(p.proxy, false),
			listening: pid != null,
			pid,
			port: int(p.proxy_port ?? '1080', 10),
			stats: (pid != null) ? util.read_json(PROXY_STATS) : null
		},
		offloading: offloading(cur),
		kernel: util.read_trim('/proc/sys/kernel/osrelease')
	};
};
