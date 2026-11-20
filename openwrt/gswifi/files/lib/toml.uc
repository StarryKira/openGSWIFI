// SPDX-License-Identifier: MIT
//
// The small part of TOML that the generated gswifi configuration needs:
// typed scalars, string arrays, and correct string escaping. Values from
// UCI are never pasted into the output; every one goes through one of
// these functions.

'use strict';

// A TOML basic string. ucode strings are byte strings, so this walks bytes:
// multi-byte UTF-8 sequences (>= 0x80) pass through unchanged, quotes,
// backslashes and every control character are escaped. A password such as
//   p"a\ss#word<newline>密码
// therefore arrives in the program exactly as it was typed.
export function str(value) {
	let s = `${value ?? ''}`;
	let out = '"';
	let from = 0;

	for (let i = 0; i < length(s); i++) {
		let b = ord(s, i);
		let esc = null;

		if (b == 0x22)
			esc = '\\"';
		else if (b == 0x5c)
			esc = '\\\\';
		else if (b == 0x0a)
			esc = '\\n';
		else if (b == 0x0d)
			esc = '\\r';
		else if (b == 0x09)
			esc = '\\t';
		else if (b < 0x20 || b == 0x7f)
			esc = sprintf('\\u%04X', b);

		if (esc != null) {
			out += substr(s, from, i - from) + esc;
			from = i + 1;
		}
	}

	return out + substr(s, from) + '"';
};

// UCI booleans, strictly: the string "0" is false (it is truthy in ucode),
// and anything that is not a known spelling is `null` so the caller can
// fall back to the default instead of guessing.
export function parse_bool(value) {
	if (type(value) == 'bool')
		return value;

	switch (lc(trim(`${value ?? ''}`))) {
	case '1': case 'true': case 'yes': case 'on': case 'enabled':
		return true;

	case '0': case 'false': case 'no': case 'off': case 'disabled':
		return false;
	}

	return null;
};

// A decimal integer within [min, max], or null. Leading zeros, signs where
// none is allowed, hex and trailing text are all rejected: int("12abc")
// would otherwise quietly be 12.
export function parse_int(value, min, max) {
	let s = trim(`${value ?? ''}`);

	if (!match(s, /^-?[0-9]{1,15}$/))
		return null;

	let n = int(s, 10);

	if (n < min || n > max)
		return null;

	return n;
};

export function parse_ipv4(value) {
	let m = match(trim(`${value ?? ''}`), /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);

	if (!m)
		return null;

	for (let i = 1; i <= 4; i++)
		if (int(m[i], 10) > 255)
			return null;

	return `${int(m[1], 10)}.${int(m[2], 10)}.${int(m[3], 10)}.${int(m[4], 10)}`;
};

// A bare TOML key, or null when the name would need quoting. Keys come
// from a fixed schema or from the "advanced options" list; the latter is
// user input, so anything unusual is refused rather than quoted.
export function key(name) {
	return match(`${name ?? ''}`, /^[A-Za-z0-9_-]{1,64}$/) ? name : null;
};

export function bool(value) {
	return value ? 'true' : 'false';
};

export function array(values) {
	return '[' + join(', ', map(values, v => str(v))) + ']';
};

// An inline table from [ key, encoded value ] pairs.
export function inline_table(pairs) {
	return '{ ' + join(', ', map(pairs, p => `${p[0]} = ${p[1]}`)) + ' }';
};
