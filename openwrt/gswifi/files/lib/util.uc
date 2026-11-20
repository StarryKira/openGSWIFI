// SPDX-License-Identifier: MIT
//
// Small helpers shared by the gswifi service scripts.

'use strict';

import * as fs from 'fs';

// One argument for /bin/sh, single-quoted. Every command these scripts
// run is built from arguments quoted here, never by pasting text.
export function shellquote(s) {
	return "'" + replace(`${s}`, /'/g, "'\\''") + "'";
};

// Runs a command (argv array, no shell interpretation of the arguments)
// and returns { code, out }. `stderr`: 'merge' adds it to the output,
// anything else drops it.
export function capture(argv, stderr) {
	let cmd = join(' ', map(argv, shellquote)) + ((stderr == 'merge') ? ' 2>&1' : ' 2>/dev/null');
	let p = fs.popen(cmd, 'r');

	if (!p)
		return { code: 127, out: '' };

	let out = p.read('all') ?? '';
	let code = p.close();

	return { code: code ?? 127, out };
};

export function read_json(path) {
	let text = fs.readfile(path);

	if (text == null)
		return null;

	try {
		return json(text);
	}
	catch (e) {
		return null;
	}
};

export function parse_json(text) {
	try {
		return json(text);
	}
	catch (e) {
		return null;
	}
};

export function write_file(path, content) {
	let tmp = `${path}.tmp`;

	if (fs.writefile(tmp, content) == null)
		return false;

	return fs.rename(tmp, path) ? true : false;
};

export function read_trim(path) {
	let text = fs.readfile(path);

	return (text == null) ? null : trim(text);
};

// Whole seconds since boot.
export function uptime() {
	let m = match(fs.readfile('/proc/uptime') ?? '', /^([0-9]+)/);

	return m ? int(m[1], 10) : null;
};

// Whether `pid` is a running process whose executable is `exe`. After a
// package upgrade replaced the file, the kernel reports the old one as
// "<path> (deleted)" until the process is restarted.
export function pid_runs(pid, exe) {
	if (type(pid) != 'int' || pid <= 0)
		return false;

	let link = fs.readlink(`/proc/${pid}/exe`);

	return link == exe || link == `${exe} (deleted)`;
};

// A ubus call that yields null when there is no ubus (a container without
// init) instead of failing. Written out because ucode before 2025 does not
// short-circuit `conn?.call(...)` when conn is null.
export function ubus_call(conn, object, method, args) {
	if (conn == null)
		return null;

	return conn.call(object, method, args ?? {});
};

export function logger(level, message) {
	system([ '/usr/bin/logger', '-t', 'gswifi', '-p', `daemon.${level}`, '--', `${message}` ]);
};
