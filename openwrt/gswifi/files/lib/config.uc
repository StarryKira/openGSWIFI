// SPDX-License-Identifier: MIT
//
// /etc/config/gswifi -> the TOML files `gswifi run` and `gswifi protect`
// read. UCI is the source of truth; the TOML is regenerated on every
// service start and reload and lives under /var (0600).
//
// Nothing here pastes a UCI value into a shell command or into the TOML
// text: each value is typed by the driver's schema below and encoded by
// toml.uc, or dropped with a note in `problems`.

'use strict';

import * as fs from 'fs';
import { cursor } from 'uci';
import * as toml from 'gswifi.toml';
import { ubus_call } from 'gswifi.util';

export const BIN = '/usr/bin/gswifi';
export const RUN_DIR = '/var/run/gswifi';
export const ETC_DIR = '/var/etc/gswifi';
export const STATUS_DIR = '/var/run/gswifi/status';

const U16 = { t: 'int', min: 1, max: 65535 };
const U8 = { t: 'int', min: 0, max: 255 };
const U32 = { t: 'int', min: 0, max: 4294967295 };
const SECS = { t: 'int', min: 0, max: 86400 };
const STR = { t: 'str' };
const BOOL = { t: 'bool' };
const IPV4 = { t: 'ipv4' };

// Settings every 802.1X driver shares (gswifi-eapol `Options`).
const EAPOL = {
	timeout: { t: 'int', min: 1, max: 3600 },
	echo_interval: SECS,
	restart_wait: SECS,
	max_retries: { t: 'int', min: -1, max: 1000000 },
	dhcp_mode: { t: 'int', min: 0, max: 3 },
	gateway: IPV4,
	dns: IPV4
};

// iNode version material; a flat part of the `inode` driver's options and
// the `[inode]` sub-table of `h3c-portal`.
const INODE = {
	vif: STR,
	version: STR,
	version_cache: STR,
	key: STR,
	nonce: U32,
	upload_ver: BOOL,
	upload_ip: BOOL,
	data_file: STR
};

function nested(table, fields) {
	let out = {};

	for (let k, v in fields)
		out[k] = { ...v, table };

	return out;
}

// UCI option -> TOML key of the same name, per driver. An option that is
// not listed for the selected driver is not written (it may be a leftover
// of another driver); use `list option 'key=value'` for anything else.
export const SCHEMA = {
	'ruijie': {
		...EAPOL,
		start_mode: { t: 'int', min: 0, max: 3 },
		pkt_type: { t: 'int', min: 0, max: 1 },
		ext_format: { t: 'enum', of: [ 'modern', 'classic', 'none' ] },
		client_version: STR,
		check_version: STR,
		data_file: STR,
		udp_heartbeat: BOOL
	},
	'saier': { ...EAPOL },
	'eap-md5': {
		...EAPOL,
		start_mode: { t: 'enum-int', of: [ 0, 1, 3 ] },
		pkt_type: { t: 'int', min: 0, max: 1 }
	},
	'inode': {
		...EAPOL,
		...INODE,
		start_mode: { t: 'enum-int', of: [ 0, 3 ] }
	},
	'h3c-portal': {
		portal_ip: IPV4,
		server_port: U16,
		plain_password: BOOL,
		serial: { t: 'int', min: 0, max: 65535 },
		heartbeat_interval: { t: 'int', min: 1, max: 3600 },
		stamp: U32,
		timeout: { t: 'int', min: 1, max: 3600 },
		restart_wait: SECS,
		max_fail: { t: 'int', min: 0, max: 1000000 },
		stop_on_reject: BOOL,
		logoff_session_quirk: BOOL,
		zero_timer_stops_heartbeat: BOOL,
		verify_authenticator: BOOL,
		...nested('inode', INODE)
	},
	'anlang': {
		server: STR,
		service: STR,
		discovery_server: IPV4,
		discovery_port: U16,
		server_port: U16,
		local_port: { t: 'int', min: 0, max: 65535 },
		timeout_secs: { t: 'int', min: 1, max: 86400 },
		heartbeat_secs: { t: 'int', min: 1, max: 86400 },
		heartbeat_retry_secs: { t: 'int', min: 1, max: 86400 },
		heartbeat_failures: { t: 'int', min: 1, max: 1000 },
		login_attempts: { t: 'int', min: 1, max: 1000 },
		login_retry_secs: { t: 'int', min: 1, max: 86400 },
		retry_secs: { t: 'int', min: 1, max: 86400 },
		max_backoff_secs: { t: 'int', min: 1, max: 86400 },
		max_rounds: { t: 'int', min: 0, max: 1000000 },
		dhcp_every_rounds: { t: 'int', min: 0, max: 1000000 },
		response_check: { t: 'enum', of: [ 'strict', 'firmware' ] },
		accept_any_source: BOOL,
		retry_on_reject: BOOL
	},
	'drcom': {
		mode: { t: 'enum', of: [ 'dhcp', 'pppoe' ] },
		variant: { t: 'enum', of: [ 'dogcom', 'gs-d', 'gs-x', 'gs-p', 'gs-pt' ] },
		dr_mode: { t: 'int', min: 0, max: 5 },
		server: IPV4,
		server_port: U16,
		mac: STR,
		host_name: STR,
		host_os: STR,
		host_os_hex: STR,
		primary_dns: IPV4,
		dhcp_server: IPV4,
		os_info_size: U32,
		os_major: U32,
		os_minor: U32,
		os_build: U32,
		os_platform_id: U32,
		auth_version: STR,
		keep_alive_version: STR,
		control_check_status: U8,
		adapter_num: U8,
		ip_dog: U8,
		ror_version: BOOL,
		keepalive1_mod: BOOL,
		pppoe_flag: U8,
		timeout_secs: { t: 'int', min: 1, max: 3600 },
		keepalive_interval_secs: { t: 'int', min: 1, max: 86400 },
		max_retries: { t: 'int', min: 1, max: 1000000 },
		keepalive_max_fail: { t: 'int', min: 1, max: 1000 },
		eternal: BOOL,
		backoff_secs: { t: 'int', min: 1, max: 86400 }
	},
	'portal-hubei-old-mac': {
		probe_url: STR,
		portal_host: STR,
		allowed_hosts: { t: 'list' },
		utc_offset_minutes: { t: 'int', min: -1440, max: 1440 },
		use_server_date: BOOL,
		server_time_offset_secs: { t: 'int', min: -34560000, max: 34560000 },
		timeout_secs: { t: 'int', min: 1, max: 86400 },
		check_secs: SECS,
		retry_secs: { t: 'int', min: 1, max: 86400 },
		max_backoff_secs: { t: 'int', min: 1, max: 86400 },
		max_rounds: { t: 'int', min: 0, max: 1000000 },
		max_redirects: { t: 'int', min: 0, max: 20 },
		stop_on_reject: BOOL,
		user_agent: STR
	}
};

// What the service sets when UCI does not: a router daemon keeps looking
// for a silent server instead of giving up after three rounds (no
// credentials are sent while nobody answers). A *refusal* is different and
// is never retried on the same address; see README "被拒绝之后".
const SERVICE_DEFAULTS = {
	'ruijie': { max_retries: '-1' },
	'saier': { max_retries: '-1' },
	'eap-md5': { max_retries: '-1' },
	'inode': { max_retries: '-1' },
	'h3c-portal': { max_fail: '0' }
};

// Keys the runtime reads itself. They are generated from dedicated UCI
// options and cannot be set through `list option`: `exit_on_reject` in
// particular would turn a wrong password into a procd respawn loop.
const RESERVED = [
	'name', 'interface', 'driver', 'username', 'password', 'password_file',
	'dhcp_script', 'experimental', 'trace', 'exit_on_reject'
];

const PPP_PROTOS = [ 'pppoe', 'pppoa', 'pptp', 'l2tp', 'ppp' ];

export function valid_device(name) {
	return type(name) == 'string' && match(name, /^[A-Za-z0-9._@-]{1,15}$/) != null;
};

export function valid_iface(name) {
	return type(name) == 'string' && match(name, /^[A-Za-z0-9_]{1,32}$/) != null;
};

// Section ids become file names and procd instance names.
export function valid_id(name) {
	return type(name) == 'string' && match(name, /^[A-Za-z0-9_]{1,32}$/) != null;
};

export function as_list(value) {
	if (value == null)
		return [];

	return filter(type(value) == 'array' ? value : [ value ], v => v != null && trim(`${v}`) != '');
};

export function flag(value, fallback) {
	return toml.parse_bool(value) ?? fallback;
};

// Reads /etc/config/gswifi. Networks keep their UCI order.
export function load(cur) {
	cur ??= cursor();
	cur.load('gswifi');

	let all = cur.get_all('gswifi') ?? {};
	let conf = { main: {}, protect: {}, networks: [] };

	for (let name, s in all) {
		if (s['.type'] == 'gswifi' && name == 'main')
			conf.main = s;
		else if (s['.type'] == 'protect' && name == 'protect')
			conf.protect = s;
		else if (s['.type'] == 'network')
			push(conf.networks, s);
	}

	sort(conf.networks, (a, b) => a['.index'] - b['.index']);

	return conf;
};

// `gswifi drivers --json`, keyed by name. null when the binary is missing
// or too old to know `--json`.
export function load_drivers() {
	let p = fs.popen(`${BIN} drivers --json 2>/dev/null`, 'r');

	if (!p)
		return null;

	let text = p.read('all');

	p.close();

	let list;

	try { list = json(text); } catch (e) { list = null; }

	if (type(list) != 'array')
		return null;

	let out = {};

	for (let d in list)
		if (type(d) == 'object' && type(d.name) == 'string')
			out[d.name] = d;

	return out;
};

function uci_device(cur, iface, depth) {
	let dev = cur.get('network', iface, 'device') ?? cur.get('network', iface, 'ifname');

	if (type(dev) == 'array')
		dev = dev[0];

	// `option device '@wan'` (the usual wan6) is an alias for another interface.
	if (type(dev) == 'string' && substr(dev, 0, 1) == '@')
		return (depth < 4) ? uci_device(cur, substr(dev, 1), depth + 1) : null;

	// `option ifname 'eth0 eth1'` of old bridge sections: not one device.
	if (type(dev) == 'string' && index(dev, ' ') >= 0)
		return null;

	return dev;
}

// The kernel device behind a netifd interface.
//
// 802.1X (transport "eapol") needs the Ethernet device the frames leave
// on, which for a PPPoE interface is the device underneath it. Everything
// else (UDP, HTTP, the firewall rules) wants the layer 3 device: for
// PPPoE that is pppoe-<name>, which only exists while the link is up, so
// it is predicted from the protocol when netifd does not report it yet.
export function resolve_device(conn, cur, iface, transport) {
	if (!valid_iface(iface))
		return null;

	let st = ubus_call(conn, `network.interface.${iface}`, 'status');
	let proto = st?.proto ?? cur.get('network', iface, 'proto');
	let dev;

	if (transport == 'eapol')
		dev = st?.device ?? uci_device(cur, iface, 0);
	else if (st?.l3_device)
		dev = st.l3_device;
	else if (proto in PPP_PROTOS)
		dev = `${proto}-${iface}`;
	else
		dev = st?.device ?? uci_device(cur, iface, 0);

	return valid_device(dev) ? dev : null;
};

function encode(spec, raw) {
	switch (spec.t) {
	case 'bool': {
		let b = toml.parse_bool(type(raw) == 'array' ? raw[0] : raw);

		return (b == null) ? null : toml.bool(b);
	}

	case 'int': {
		let n = toml.parse_int(raw, spec.min, spec.max);

		return (n == null) ? null : `${n}`;
	}

	case 'enum-int': {
		let n = toml.parse_int(raw, -1000000, 1000000);

		return (n == null || !(n in spec.of)) ? null : `${n}`;
	}

	case 'enum':
		return (raw in spec.of) ? toml.str(raw) : null;

	case 'ipv4': {
		let a = toml.parse_ipv4(raw);

		return (a == null) ? null : toml.str(a);
	}

	case 'list':
		return toml.array(as_list(raw));

	case 'str':
		return (type(raw) == 'string') ? toml.str(raw) : null;
	}

	return null;
}

// `key=value` of the advanced list, typed like the program's `-o`:
// integers and true/false keep their type, everything else is a string.
// `key="123"` forces a string; `table.key=value` sets a key of a sub-table.
function parse_advanced(pair) {
	let m = match(`${pair}`, /^[ \t]*([A-Za-z0-9_-]+)(\.([A-Za-z0-9_-]+))?[ \t]*=(.*)$/);

	if (!m)
		return null;

	let value = trim(m[4]);
	let enc;

	if (value == 'true' || value == 'false')
		enc = value;
	else if (match(value, /^-?[0-9]{1,15}$/))
		enc = `${int(value, 10)}`;
	else if (length(value) >= 2 && substr(value, 0, 1) == '"' && substr(value, -1) == '"')
		enc = toml.str(substr(value, 1, length(value) - 2));
	else
		enc = toml.str(value);

	return m[3] ? { table: m[1], key: m[3], enc } : { table: null, key: m[1], enc };
}

// The DHCP command for one network: an explicit `dhcp_script`, else (unless
// `dhcp_renew` is off) a netifd renew of the configured interface.
function dhcp_script(net) {
	if (type(net.dhcp_script) == 'string' && trim(net.dhcp_script) != '')
		return net.dhcp_script;

	if (flag(net.dhcp_renew, true) && valid_iface(net.interface))
		return `ubus call network.interface.${net.interface} renew`;

	return null;
}

// The TOML of one network section, or the reasons it cannot run.
//   net      UCI section
//   device   resolved kernel device
//   info     entry of `gswifi drivers --json` (null: unknown driver)
// Returns { toml, problems }: `toml` is null when a problem is fatal;
// other problems are settings that were dropped.
export function network_toml(net, device, info) {
	let problems = [];
	let fatal = (msg) => { push(problems, msg); return { toml: null, problems }; };
	let id = net['.name'];
	let driver = net.driver ?? 'ruijie';

	if (!valid_id(id))
		return fatal(`配置节名称 ${id} 无效（只能用字母、数字和下划线）`);

	if (!info)
		return fatal(`不支持的认证方式 ${driver}`);

	if (info.runnable === false)
		return fatal(info.unavailable ?? `认证方式 ${driver} 不能运行会话`);

	if (type(net.username) != 'string' || net.username == '' || type(net.password) != 'string' || net.password == '')
		return fatal('没有填写用户名或密码');

	if (!valid_device(device))
		return fatal('找不到认证用的网卡');

	let experimental = flag(net.experimental, false);

	if (info.experimental && !experimental)
		return fatal(`${info.title} 的验证程度是 ${info.support}，需要先勾选“允许使用实验性认证方式”`);

	let top = [];      // [ key, encoded ] in output order
	let tables = {};   // name -> [ [ key, encoded ] ]
	let put = (table, k, enc) => {
		let list = top;

		if (table != null)
			list = (tables[table] ??= []);

		for (let pair in list) {
			if (pair[0] == k) {
				pair[1] = enc;
				return;
			}
		}

		push(list, [ k, enc ]);
	};

	put(null, 'name', toml.str(id));
	put(null, 'interface', toml.str(device));
	put(null, 'driver', toml.str(driver));
	put(null, 'username', toml.str(net.username));
	put(null, 'password', toml.str(net.password));

	if (experimental)
		put(null, 'experimental', 'true');

	if (flag(net.trace, false))
		put(null, 'trace', 'true');

	let script = dhcp_script(net);

	if (script != null)
		put(null, 'dhcp_script', toml.str(script));

	let schema = SCHEMA[driver] ?? {};
	let defaults = SERVICE_DEFAULTS[driver] ?? {};

	for (let k in sort(keys(schema))) {
		let raw = net[k] ?? defaults[k];

		if (raw == null || raw === '')
			continue;

		let enc = encode(schema[k], raw);
		let shown = (type(raw) == 'array') ? join(' ', raw) : raw;

		if (enc == null && defaults[k] != null && raw !== defaults[k]) {
			enc = encode(schema[k], defaults[k]);
			push(problems, `配置项 ${k} 的值 ${shown} 无效，改用默认值 ${defaults[k]}`);
		}
		else if (enc == null) {
			push(problems, `配置项 ${k} 的值 ${shown} 无效，已忽略`);
		}

		if (enc != null)
			put(schema[k].table, k, enc);
	}

	for (let pair in as_list(net.option)) {
		let adv = parse_advanced(pair);

		if (!adv)
			push(problems, `高级选项 ${pair} 不是 key=value 的形式，已忽略`);
		else if (adv.table == null && adv.key in RESERVED)
			push(problems, `高级选项不能设置 ${adv.key}，已忽略`);
		else
			put(adv.table, adv.key, adv.enc);
	}

	let out = '# 由 /etc/config/gswifi 生成，服务每次启动时覆盖，请勿手工编辑。\n[[networks]]\n';

	for (let pair in top)
		out += `${pair[0]} = ${pair[1]}\n`;

	for (let name in sort(keys(tables)))
		out += `${name} = ${toml.inline_table(tables[name])}\n`;

	return { toml: out, problems };
};

// Devices for a list of netifd interfaces plus explicitly named devices,
// without duplicates. `missing` lists what could not be resolved.
export function resolve_devices(conn, cur, ifaces, devices) {
	let out = [], missing = [];

	for (let iface in as_list(ifaces)) {
		let dev = resolve_device(conn, cur, iface, 'l3');

		if (dev == null)
			push(missing, iface);
		else if (!(dev in out))
			push(out, dev);
	}

	for (let dev in as_list(devices)) {
		if (!valid_device(dev))
			push(missing, dev);
		else if (!(dev in out))
			push(out, dev);
	}

	return { devices: out, missing };
};

export function protect_mode(p) {
	return (p?.mode in [ 'observe', 'enforce' ]) ? p.mode : 'disabled';
};

// The `[protect]` TOML. `wan` and `lan` are the resolved device lists.
export function protect_toml(p, wan, lan) {
	let persona = (p.persona in [ 'pc', 'phone' ]) ? p.persona : 'pc';
	let ipv6 = (p.ipv6 in [ 'forward', 'normalise', 'block' ]) ? p.ipv6 : 'forward';
	let failure = (p.failure_policy in [ 'bypass', 'block' ]) ? p.failure_policy : 'bypass';
	let port = toml.parse_int(p.proxy_port, 1, 65535) ?? 1080;
	let out = '# 由 /etc/config/gswifi 生成，请勿手工编辑。\n[protect]\n';

	out += `mode = ${toml.str(protect_mode(p))}\n`;
	out += `persona = ${toml.str(persona)}\n`;
	out += `wan = ${toml.array(wan)}\n`;
	out += `lan = ${toml.array(lan)}\n`;

	for (let k in [ 'ttl', 'preserve_traceroute', 'ipid', 'tcp_timestamps', 'dscp_ecn', 'icmp', 'source_ports' ])
		out += `${k} = ${toml.bool(flag(p[k], true))}\n`;

	out += `ipv6 = ${toml.str(ipv6)}\n`;
	out += `ntp = ${toml.bool(flag(p.ntp, false))}\n`;
	out += `failure_policy = ${toml.str(failure)}\n`;

	out += '\n[protect.dns]\n';
	out += `take_over = ${toml.bool(flag(p.dns_take_over, false))}\n`;
	out += `blocked_domains = ${toml.array(as_list(p.dns_blocked_domain))}\n`;
	out += `local_arpa = ${toml.bool(flag(p.dns_local_arpa, false))}\n`;
	out += `filter_aaaa = ${toml.bool(flag(p.dns_filter_aaaa, false))}\n`;

	out += '\n[protect.proxy]\n';
	out += `enabled = ${toml.bool(flag(p.proxy, false))}\n`;
	out += `port = ${port}\n`;
	out += `http_only = ${toml.bool(flag(p.proxy_http_only, true))}\n`;

	return out;
};

// Writes `content` to `path` with mode 0600, atomically, only when it
// differs (so procd's file watch does not see a change that is none).
export function write_private(path, content) {
	if (fs.readfile(path) === content)
		return false;

	let tmp = `${path}.tmp`;
	let f = fs.open(tmp, 'w', 0o600);

	if (!f)
		die(`cannot write ${tmp}: ${fs.error()}\n`);

	f.write(content);
	f.close();
	fs.chmod(tmp, 0o600);

	if (!fs.rename(tmp, path))
		die(`cannot rename ${tmp}: ${fs.error()}\n`);

	return true;
};

// `mkdir -p`; the parents get the usual 0755, only `dir` itself `mode`.
function mkdir_p(dir, mode) {
	let path = '';

	for (let part in split(dir, '/')) {
		if (part == '')
			continue;

		path += '/' + part;

		if (fs.stat(path)?.type != 'directory')
			fs.mkdir(path, (path == dir) ? mode : 0o755);
	}

	fs.chmod(dir, mode);
}

export function ensure_dirs() {
	for (let dir in [ RUN_DIR, ETC_DIR, STATUS_DIR ])
		mkdir_p(dir, 0o700);
};
