// SPDX-License-Identifier: MIT
//
// One JSON snapshot of the service for `ctl status` and the LuCI app: per
// network what UCI asks for, what procd runs, and what the session itself
// reports in its status file (written by `gswifi run --status-dir`). No
// log text is parsed here, and no password leaves this module.

'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import * as config from 'gswifi.config';
import * as util from 'gswifi.util';

function sysget(dev, name) {
	return util.read_trim(`/sys/class/net/${dev}/${name}`);
}

// Link state and addresses of one kernel device.
export function device_info(dev) {
	if (!config.valid_device(dev) || !fs.access(`/sys/class/net/${dev}`))
		return { name: dev, present: false };

	let info = {
		name: dev,
		present: true,
		mac: sysget(dev, 'address'),
		operstate: sysget(dev, 'operstate'),
		// Reading `carrier` fails while the device is administratively down.
		carrier: sysget(dev, 'carrier') == '1',
		speed: int(sysget(dev, 'speed') ?? '', 10),
		// Counters can exceed what a JSON number holds exactly.
		rx_bytes: sysget(dev, 'statistics/rx_bytes'),
		tx_bytes: sysget(dev, 'statistics/tx_bytes'),
		ipv4: [],
		ipv6: [],
		gateway: null
	};

	if (type(info.speed) != 'int' || info.speed <= 0)
		info.speed = null;

	for (let line in split(util.capture([ '/sbin/ip', '-o', 'addr', 'show', 'dev', dev ]).out, '\n')) {
		let m = match(line, /[ \t]inet(6?) ([0-9A-Fa-f.:]+\/[0-9]+)/);

		if (m)
			push(m[1] == '6' ? info.ipv6 : info.ipv4, m[2]);
	}

	let route = match(util.capture([ '/sbin/ip', '-4', 'route', 'show', 'default', 'dev', dev ]).out, /default via ([0-9.]+)/);

	if (route)
		info.gateway = route[1];

	return info;
};

// A time from the status file as wall-clock seconds. The `_up` value
// (seconds since boot) is authoritative: the wall clock of a router
// without a battery jumps when NTP first answers, which is after login.
function stamp(sess, key, now, up) {
	let since_boot = sess[`${key}_up`];

	if (type(since_boot) == 'int' && since_boot > 0 && up != null)
		return now - (up - since_boot);

	return (type(sess[key]) == 'int' && sess[key] > 0) ? sess[key] : null;
}

function line(sess, key, now, up) {
	let l = sess[key];

	if (type(l) != 'object')
		return null;

	return { level: l.level, text: l.text, at: stamp(l, 'at', now, up) };
}

function session(id, now, up) {
	let sess = util.read_json(`${config.STATUS_DIR}/${id}.json`);

	if (type(sess) != 'object' || type(sess.state) != 'string')
		return null;

	return {
		pid: sess.pid,
		state: sess.state,
		state_since: stamp(sess, 'state_since', now, up),
		started: stamp(sess, 'started', now, up),
		online_since: stamp(sess, 'online_since', now, up),
		last_online: stamp(sess, 'last_online', now, up),
		updated: stamp(sess, 'updated', now, up),
		interface: sess.interface,
		mac: sess.mac,
		ipv4: sess.ipv4,
		gateway: sess.gateway,
		dns: sess.dns,
		attempts: sess.attempts,
		successes: sess.successes,
		waiting_for_change: sess.waiting_for_change ? true : false,
		exit_code: sess.exit_code,
		reject_stage: sess.reject_stage,
		reason: sess.reason,
		last_log: line(sess, 'last_log', now, up),
		last_issue: line(sess, 'last_issue', now, up),
		server_message: line(sess, 'server_message', now, up)
	};
}

// The device a network authenticates on: the one named in UCI, else the
// one behind its netifd interface.
export function network_device(conn, cur, net, info) {
	if (type(net.device) == 'string' && net.device != '')
		return config.valid_device(net.device) ? net.device : null;

	return config.resolve_device(conn, cur, net.interface ?? 'wan', info?.transport ?? 'eapol');
};

// The single state shown for a network. The order matters: what stops a
// session from being started at all comes first, then what procd says,
// then what the session says about itself.
function view_state(n) {
	if (!n.enabled)
		return 'disabled';

	if (!n.driver_known || !n.runnable)
		return 'unsupported';

	if (!n.configured)
		return 'unconfigured';

	if (n.needs_experimental)
		return 'needs-experimental';

	if (n.device == null)
		return 'nodev';

	if (!n.instance)
		return 'not-started';

	if (!n.instance.running)
		return (n.session?.state == 'fatal') ? 'fatal' : 'exited';

	// Running. Until the device is there and has a link the instance is
	// still the wrapper that waits for it, and no session has started.
	if (n.session && n.session.pid == n.instance.pid)
		return n.session.state;

	if (!n.dev.present)
		return 'nodev';

	if (!n.dev.carrier)
		return 'nolink';

	return 'starting';
}

export function snapshot() {
	let cur = cursor();
	let conn = connect();

	cur.load('network');

	let conf = config.load(cur);
	let drivers = config.load_drivers();
	let now = time();
	let up = util.uptime();
	let service = conn?.call('service', 'list', { name: 'gswifi' })?.gswifi;
	let instances = service?.instances ?? {};
	let networks = [];

	for (let net in conf.networks) {
		let id = net['.name'];
		let driver = net.driver ?? 'ruijie';
		let info = drivers?.[driver];
		let device = network_device(conn, cur, net, info);
		let generated = config.network_toml(net, device, info);
		let inst = instances[id];
		let n = {
			id,
			enabled: config.flag(net.enabled, false),
			driver,
			driver_known: info != null,
			driver_title: info?.title ?? driver,
			support: info?.support ?? null,
			transport: info?.transport ?? null,
			runnable: info ? info.runnable !== false : false,
			unavailable: info?.unavailable ?? null,
			experimental: config.flag(net.experimental, false),
			needs_experimental: (info?.experimental ? true : false) && !config.flag(net.experimental, false),
			username: net.username ?? '',
			configured: (net.username ?? '') != '' && (net.password ?? '') != '',
			interface: net.interface ?? 'wan',
			device,
			device_manual: (net.device ?? '') != '',
			dev: device_info(device),
			// Settings that were dropped, or why no session can be started.
			problems: generated.problems,
			instance: inst ? {
				running: inst.running ? true : false,
				pid: inst.pid ?? null,
				exit_code: inst.exit_code ?? null
			} : null,
			session: session(id, now, up)
		};

		n.state = view_state(n);
		push(networks, n);
	}

	let version = util.capture([ config.BIN, '--version' ]);

	return {
		now,
		// UTC offset of the router, so times can be shown in its zone.
		tz: trim(util.capture([ '/bin/date', '+%z' ]).out),
		binary: fs.access(config.BIN) ? true : false,
		version: (version.code == 0) ? trim(version.out) : null,
		drivers_known: drivers != null,
		boot_enabled: length(fs.glob('/etc/rc.d/S??gswifi') ?? []) > 0,
		service_running: service != null,
		networks
	};
};
