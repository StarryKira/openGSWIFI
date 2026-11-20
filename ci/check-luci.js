// Syntax check for the LuCI app: every view/module must parse and every JSON
// file must be valid. LuCI modules are function bodies (they end in a
// top-level `return`), so they are compiled with `new Function`.
//
// The rpcd backend and the service's ucode files are not JavaScript; they
// are checked on a router by ci/openwrt-test.sh, which runs them.
//
//   node ci/check-luci.js <dir>...

'use strict';

const fs = require('fs');
const path = require('path');

function* walk(dir) {
	for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, e.name);
		if (e.isDirectory())
			yield* walk(p);
		else
			yield p;
	}
}

let checked = 0, failed = 0;

for (const dir of process.argv.slice(2)) {
	for (const file of walk(dir)) {
		const src = fs.readFileSync(file, 'utf8');

		try {
			if (file.endsWith('.js')) {
				new Function(src);

				// Every view and module starts by declaring strict mode and
				// its dependencies; a missing 'require' only fails in the
				// browser, as a ReferenceError at render time.
				if (!/^'use strict';/.test(src))
					throw new Error("does not start with 'use strict';");

				// Comments may mention a module without using it.
				const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

				for (const m of code.matchAll(/\b(form|uci|ui|dom|poll|rpc|widgets|api|view|baseclass)\.[A-Za-z_]/g)) {
					const name = m[1];
					const required = new RegExp(`^'require [\\w.]*\\b${name}';$|^'require [\\w.]+ as ${name}';$`, 'm');

					if (!required.test(src))
						throw new Error(`uses ${name}.* without 'require ${name}'`);
				}
			}
			else if (file.endsWith('.json')) {
				JSON.parse(src);
			}
			else {
				continue;
			}
			checked++;
		}
		catch (e) {
			console.error(`${file}: ${e.message}`);
			failed++;
		}
	}
}

console.log(`${checked} files ok, ${failed} failed`);
process.exit(failed || !checked ? 1 : 0);
