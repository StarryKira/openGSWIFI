'use strict';
'require baseclass';
'require rpc';

/*
 * Shared by every view of luci-app-gswifi: the RPC calls, what the states
 * and verification levels mean, and the few custom widgets.
 *
 * THEMES. Nothing here assumes a light or a dark page. Text keeps the
 * colour it inherits from the theme; lines and tinted surfaces are derived
 * from that same colour (currentColor) with color-mix(), so they are faint
 * dark lines on a light theme and faint light lines on a dark one without
 * knowing which theme is active or how it marks dark mode (bootstrap and
 * aurora set data-darkmode on <html>, argon sets data-argon-mode, and all
 * of them may just follow the system). The four state colours are only
 * ever used mixed with the inherited text colour or as a translucent
 * tint, which keeps them readable on both. Everything else is a standard
 * LuCI class (cbi-section, table/tr/td with data-title, btn cbi-button,
 * alert-message) that each theme styles itself.
 *
 * TEXT. E() and dom.content() assign a lone string child as innerHTML.
 * Text that comes from the router or from an authentication server is
 * always passed inside an array, so it ends up as a text node.
 */

var callStatus = rpc.declare({ object: 'luci.gswifi', method: 'status', expect: { '': {} } });
var callDrivers = rpc.declare({ object: 'luci.gswifi', method: 'drivers', expect: { drivers: [] } });
var callProtect = rpc.declare({ object: 'luci.gswifi', method: 'protect', expect: { '': {} } });
var callLog = rpc.declare({ object: 'luci.gswifi', method: 'log', params: [ 'lines' ], expect: { '': {} } });
var callControl = rpc.declare({ object: 'luci.gswifi', method: 'control', params: [ 'action', 'id' ], expect: { '': {} } });
var callPppoe = rpc.declare({ object: 'luci.gswifi', method: 'pppoe', params: [ 'version', 'username', 'offset' ], expect: { '': {} } });
var callProtectCheck = rpc.declare({ object: 'luci.gswifi', method: 'protect_check', expect: { '': {} } });
var callProtectShow = rpc.declare({ object: 'luci.gswifi', method: 'protect_show', expect: { '': {} } });
var callProtectApply = rpc.declare({ object: 'luci.gswifi', method: 'protect_apply', expect: { '': {} } });
var callDiag = rpc.declare({ object: 'luci.gswifi', method: 'diag', expect: { '': {} } });

/* tone: ok | busy | warn | bad | idle */
var STATES = {
	'disabled':           { label: _('未启用'),               tone: 'idle', glyph: '–' },
	'unsupported':        { label: _('认证方式不可用'),       tone: 'bad',  glyph: '✕' },
	'unconfigured':       { label: _('尚未填写账号'),         tone: 'warn', glyph: '!' },
	'needs-experimental': { label: _('等待确认实验性认证方式'), tone: 'warn', glyph: '!' },
	'nodev':              { label: _('找不到认证网卡'),       tone: 'bad',  glyph: '✕' },
	'nolink':             { label: _('网线未接通'),           tone: 'warn', glyph: '!' },
	'not-started':        { label: _('未运行'),               tone: 'idle', glyph: '–' },
	'exited':             { label: _('认证程序已退出'),       tone: 'bad',  glyph: '✕' },
	'fatal':              { label: _('无法开始认证'),         tone: 'bad',  glyph: '✕' },
	'starting':           { label: _('正在启动'),             tone: 'busy', glyph: '…' },
	'idle':               { label: _('正在启动'),             tone: 'busy', glyph: '…' },
	'waiting-ip':         { label: _('等待获取 IP 地址'),     tone: 'busy', glyph: '…' },
	'discovering':        { label: _('正在寻找认证服务器'),   tone: 'busy', glyph: '…' },
	'authenticating':     { label: _('正在认证'),             tone: 'busy', glyph: '…' },
	'online':             { label: _('已认证'),               tone: 'ok',   glyph: '✓' },
	'backoff':            { label: _('等待下一次尝试'),       tone: 'warn', glyph: '!' },
	'rejected':           { label: _('认证被拒绝'),           tone: 'bad',  glyph: '✕' },
	'gave-up':            { label: _('认证服务器没有应答'),   tone: 'warn', glyph: '!' },
	'server-not-found':   { label: _('没有找到认证服务器'),   tone: 'warn', glyph: '!' },
	'stopped':            { label: _('已下线'),               tone: 'idle', glyph: '–' }
};

/*
 * The verification levels of `gswifi drivers` (research doc 09.9). The
 * wording must not claim more than the level says: only field-tested means
 * somebody logged in to a real campus network with it.
 */
var SUPPORT = {
	'field-tested':   { label: _('实网验证'),   tone: 'ok',
		text: _('已在真实校园网使用。') },
	'lab-tested':     { label: _('实验室验证'), tone: 'busy',
		text: _('在模拟或实验室服务器上跑通过完整流程，没有真实校园网的报告。') },
	'offline-tested': { label: _('仅离线测试'), tone: 'warn',
		text: _('报文编解码和状态机与研究文档的样本一致，但从未连接过真实的认证服务器。能否认证成功未知。') },
	'documented':     { label: _('仅按文档实现'), tone: 'bad',
		text: _('按研究文档编写，连完整的离线样本都没有，从未连接过真实的认证服务器。能否认证成功未知。') }
};

/*
 * What is known about staying online after a login, per driver. Shown
 * next to an online session so that "已认证" is not read as "will stay
 * online" where that has not been verified.
 */
var KEEPALIVE = {
	'ruijie':  { known: true,  text: _('EAPOL 心跳，沿用 mentorust 在实网使用的实现') },
	'eap-md5': { known: true,  text: _('标准 802.1X，由服务器发起重认证') },
	'saier':   { known: false, text: _('未验证：保活报文按文档实现，没有实网报告') },
	'inode':   { known: false, text: _('未知（未验证）：H3C iNode 的在线保活报文尚未还原，程序不发送保活。认证成功后能在线多久未知') },
	'h3c-portal': { known: false, text: _('未验证：心跳按离线回放的会话实现，没有实网报告') },
	'anlang':  { known: false, text: _('未验证：心跳按离线样本实现，服务器是否接受未知') },
	'drcom':   { known: false, text: _('未验证：keepalive 按文档实现，没有任何实验室或实网会话') },
	'portal-hubei-old-mac': { known: false, text: _('未实现厂商心跳：改为定时探测是否仍在线，这是本程序自己的做法，未验证') }
};

var CSS = [
	/* palette: fixed hues, never used as a plain foreground or background */
	'.gsw{--gsw-ok:#1a8f4c;--gsw-warn:#b06a00;--gsw-bad:#d03d33;--gsw-busy:#2a73d0;--gsw-idle:#6b7482;',
	'--gsw-line:rgba(128,128,128,.34);--gsw-soft:rgba(128,128,128,.1)}',
	'.gsw-t-ok{--gsw-tone:var(--gsw-ok);--gsw-tint:rgba(26,143,76,.13);--gsw-edge:rgba(26,143,76,.55)}',
	'.gsw-t-warn{--gsw-tone:var(--gsw-warn);--gsw-tint:rgba(176,106,0,.13);--gsw-edge:rgba(176,106,0,.6)}',
	'.gsw-t-bad{--gsw-tone:var(--gsw-bad);--gsw-tint:rgba(208,61,51,.12);--gsw-edge:rgba(208,61,51,.55)}',
	'.gsw-t-busy{--gsw-tone:var(--gsw-busy);--gsw-tint:rgba(42,115,208,.12);--gsw-edge:rgba(42,115,208,.55)}',
	'.gsw-t-idle{--gsw-tone:var(--gsw-idle);--gsw-tint:rgba(107,116,130,.13);--gsw-edge:rgba(107,116,130,.55)}',
	/* a state colour as text: pulled towards the theme's own text colour */
	'.gsw-tone{color:var(--gsw-tone)}',
	'@supports (color:color-mix(in srgb,red 50%,blue)){',
	'.gsw{--gsw-line:color-mix(in srgb,currentColor 18%,transparent);--gsw-soft:color-mix(in srgb,currentColor 6%,transparent)}',
	'.gsw-tone{color:color-mix(in srgb,var(--gsw-tone) 50%,currentColor)}',
	'.gsw-badge .gsw-tone{color:color-mix(in srgb,var(--gsw-tone) 34%,currentColor)}',
	'}',

	/* status header of a network */
	'.gsw-hero{display:flex;flex-wrap:wrap;align-items:center;gap:14px 18px;padding:14px 16px;',
	'border:1px solid var(--gsw-line);border-left:4px solid var(--gsw-tone);border-radius:8px;background:var(--gsw-tint)}',
	'.gsw-orb{flex:none;width:44px;height:44px;border-radius:50%;display:flex;align-items:center;justify-content:center;',
	'font-size:22px;font-weight:700;line-height:1;border:2px solid var(--gsw-edge);background:var(--gsw-tint)}',
	'.gsw-t-busy .gsw-orb{animation:gsw-pulse 1.6s ease-in-out infinite}',
	'@keyframes gsw-pulse{0%{box-shadow:0 0 0 0 var(--gsw-edge)}70%,100%{box-shadow:0 0 0 9px rgba(0,0,0,0)}}',
	'@media (prefers-reduced-motion:reduce){.gsw-t-busy .gsw-orb{animation:none}}',
	'.gsw-hero-main{flex:1 1 260px;min-width:0}',
	'.gsw-hero-title{font-size:1.35em;font-weight:600;line-height:1.3}',
	'.gsw-hero-hint{margin-top:4px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}',
	'.gsw-hero-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center}',

	/* small labelled things */
	'.gsw-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}',
	'.gsw-chip{display:inline-flex;align-items:center;gap:5px;max-width:100%;padding:2px 10px;border:1px solid var(--gsw-line);',
	'border-radius:12px;font-size:.88em;line-height:1.5;overflow-wrap:anywhere}',
	'.gsw-chip b{font-weight:600}',
	'.gsw-badge{display:inline-block;padding:1px 9px;border-radius:10px;font-size:.86em;line-height:1.5;white-space:nowrap;',
	'border:1px solid var(--gsw-edge);background:var(--gsw-tint)}',
	'.gsw-dot{display:inline-block;width:.62em;height:.62em;border-radius:50%;background:var(--gsw-tone);margin-right:.45em;vertical-align:baseline}',
	'.gsw-muted{opacity:.8}',
	'.gsw-small{font-size:.9em}',
	'.gsw-mono{font-family:monospace}',
	'.gsw-wrap{overflow-wrap:anywhere;word-break:break-word}',

	/* label / value pairs */
	'.gsw-kvs{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:0 28px;margin-top:12px}',
	'.gsw-kv-wide{grid-column:1/-1}',
	'.gsw-kv-wide .gsw-v{flex:1 1 auto;text-align:left}',
	'.gsw-kv{display:flex;justify-content:space-between;gap:14px;padding:7px 0;border-bottom:1px dashed var(--gsw-line);min-width:0}',
	'.gsw-k{flex:none;opacity:.8}',
	'.gsw-v{min-width:0;text-align:right;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}',
	'.gsw-lines{margin-top:12px;display:grid;gap:8px}',
	'.gsw-line{padding:8px 12px;border:1px solid var(--gsw-line);border-left:3px solid var(--gsw-tone,var(--gsw-line));',
	'border-radius:6px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}',
	'.gsw-line-head{display:block;font-size:.86em;opacity:.8;margin-bottom:2px}',
	/* a remark in a state colour: what is unverified, skipped or needs attention */
	'.gsw-note{margin-top:10px;padding:9px 12px;border:1px solid var(--gsw-edge);border-left-width:3px;border-radius:6px;',
	'background:var(--gsw-tint);line-height:1.6;overflow-wrap:anywhere}',
	'.gsw-note strong{font-weight:600}',

	/* numbers that tick */
	'.gsw-num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}',
	'.gsw-meter{height:6px;border-radius:3px;background:var(--gsw-soft);overflow:hidden;min-width:60px}',
	'.gsw-meter>span{display:block;height:100%;border-radius:3px;background:var(--gsw-tone);opacity:.75}',

	/* log and command output */
	'.gsw-log{font-family:monospace;font-size:12.5px;line-height:1.6;padding:10px 12px;overflow:auto;',
	'border:1px solid var(--gsw-line);border-radius:6px;background:var(--gsw-soft);white-space:pre-wrap;overflow-wrap:anywhere}',
	'.gsw-log-time{opacity:.8}',
	'.gsw-log-tag{opacity:.88}',
	'.gsw-log .gsw-tone .gsw-log-time,.gsw-log .gsw-tone .gsw-log-tag{opacity:1}',
	'.gsw-log-cont{padding-left:1.5em}',
	'.gsw-log mark{background:rgba(255,200,0,.4);color:inherit;padding:0 1px;border-radius:2px}',
	'.gsw-pre{font-family:monospace;font-size:12.5px;line-height:1.55;margin:10px 0 0;padding:10px 12px;overflow:auto;max-height:460px;',
	'border:1px solid var(--gsw-line);border-radius:6px;background:var(--gsw-soft);color:inherit;white-space:pre-wrap;overflow-wrap:anywhere}',

	/* body of a section; its side padding is copied from the theme's heading, see fit() */
	'.gsw-body{min-width:0}',
	'.gsw-body>:first-child{margin-top:0}',

	/* rows of controls */
	'.gsw-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;margin-bottom:10px}',
	'.gsw-toolbar label{display:inline-flex;align-items:center;gap:6px;margin:0;white-space:nowrap}',
	'.gsw-toolbar select,.gsw-toolbar input[type=text],.gsw-toolbar input[type=number]{margin:0;width:auto;min-width:0;max-width:100%}',
	'.gsw-spacer{flex:1 1 0}',
	'.gsw-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}',
	'.gsw-gap{margin-top:12px}',
	'.gsw-result{margin-top:12px;padding:12px 14px;border:1px solid var(--gsw-line);border-radius:6px;background:var(--gsw-soft)}',
	'.gsw-result code{font-size:1.15em;overflow-wrap:anywhere;background:none;color:inherit;padding:0}',

	'@media (max-width:640px){',
	'.gsw-hero{padding:12px}',
	'.gsw-hero-actions{width:100%}',
	'.gsw-kvs{grid-template-columns:1fr}',
	'.gsw-kv{flex-wrap:wrap}',
	'.gsw-v{flex:1 1 auto}',
	'}'
].join('');

function pad2(n) {
	return (n < 10 ? '0' : '') + n;
}

return baseclass.extend({
	STATES: STATES,
	SUPPORT: SUPPORT,
	KEEPALIVE: KEEPALIVE,

	status: function() { return L.resolveDefault(callStatus(), {}); },
	drivers: function() { return L.resolveDefault(callDrivers(), []); },
	protect: function() { return L.resolveDefault(callProtect(), {}); },
	/* Resolves to the log text, or to null when it could not be fetched. */
	log: function(lines) {
		return L.resolveDefault(callLog(lines), null).then(function(res) {
			return res ? (res.log || '') : null;
		});
	},
	control: function(action, id) { return callControl(action, id || ''); },
	pppoe: function(version, username, offset) { return callPppoe(version, username, offset || 0); },
	protectCheck: function() { return callProtectCheck(); },
	protectShow: function() { return callProtectShow(); },
	protectApply: function() { return callProtectApply(); },
	diag: function() { return callDiag(); },

	injectCSS: function() {
		if (document.getElementById('gsw-style'))
			return;

		document.head.appendChild(E('style', { 'id': 'gsw-style', 'type': 'text/css' }, CSS));
	},

	state: function(name) {
		return STATES[name] || { label: name || '?', tone: 'idle', glyph: '?' };
	},

	support: function(level) {
		return SUPPORT[level] || { label: level || _('未知'), tone: 'idle', text: '' };
	},

	/* "实网验证 field-tested" as a pill in the level's colour. */
	supportBadge: function(level) {
		var s = this.support(level);

		return E('span', { 'class': 'gsw-badge gsw-t-' + s.tone, 'title': s.text }, [
			E('span', { 'class': 'gsw-tone' }, [ s.label ]), level ? ' · ' + level : ''
		]);
	},

	/* A remark box; `head` is put in front in the tone's colour. */
	note: function(tone, head, children) {
		return E('div', { 'class': 'gsw-note gsw-t-' + (tone || 'warn') }, [
			head ? E('strong', { 'class': 'gsw-tone' }, [ head ]) : ''
		].concat(children || []));
	},

	/* A button that goes to another page (themes style <a class="btn"> as links). */
	linkButton: function(label, path, variant) {
		return E('button', {
			'class': 'btn cbi-button ' + (variant || 'cbi-button-neutral'),
			'click': function(ev) {
				ev.preventDefault();
				window.location.href = L.url(path);
			}
		}, [ label ]);
	},

	badge: function(text, tone) {
		return E('span', { 'class': 'gsw-badge gsw-t-' + (tone || 'idle') }, [
			E('span', { 'class': 'gsw-tone' }, [ text ])
		]);
	},

	/* A label/value row; returns the row and the node to put the value in. */
	kv: function(label, mono, wide) {
		var v = E('div', { 'class': 'gsw-v' + (mono ? ' gsw-mono' : '') }, '-');

		return {
			row: E('div', { 'class': 'gsw-kv' + (wide ? ' gsw-kv-wide' : '') }, [ E('div', { 'class': 'gsw-k' }, [ label ]), v ]),
			v: v
		};
	},

	/*
	 * A standard LuCI section (the theme draws it: a plain block in
	 * bootstrap, a card in argon and aurora) with our content in a body
	 * element below the heading.
	 */
	section: function(title, children, attrs) {
		var a = { 'class': 'cbi-section' };

		for (var k in (attrs || {}))
			a[k] = attrs[k];

		return E('div', a, [
			E('h3', {}, title),
			E('div', { 'class': 'gsw-body' }, children)
		]);
	},

	/*
	 * Themes that draw sections as cards give the heading and the form
	 * rows a side padding but leave the section itself without one, so
	 * content of our own would touch the edge of the card. Rather than
	 * guess a number per theme, give each body the padding the theme gave
	 * the heading right above it (nothing in bootstrap, 20px in argon).
	 */
	fit: function(root) {
		var apply = function() {
			(root || document).querySelectorAll('.gsw-body').forEach(function(body) {
				var head = body.previousElementSibling;

				if (!head || !/^H[2-4]$/.test(head.tagName))
					return;

				var cs = window.getComputedStyle(head),
				    l = parseFloat(cs.paddingLeft) || 0,
				    r = parseFloat(cs.paddingRight) || 0;

				body.style.paddingLeft = l + 'px';
				body.style.paddingRight = r + 'px';
				body.style.paddingBottom = (l > 0 ? Math.max(parseFloat(cs.paddingTop) || 0, 12) : 0) + 'px';
			});
		};

		/* now if already in the document, and again once it is laid out */
		apply();
		window.requestAnimationFrame(apply);
		window.setTimeout(apply, 300);

		if (!this.fitBound) {
			this.fitBound = true;
			window.addEventListener('resize', function() { apply(); });
		}
	},

	fmtDuration: function(sec) {
		sec = Math.max(0, Math.floor(sec || 0));

		var d = Math.floor(sec / 86400),
		    h = Math.floor(sec % 86400 / 3600),
		    m = Math.floor(sec % 3600 / 60),
		    s = sec % 60;

		if (d > 0) return d + ' 天 ' + h + ' 小时';
		if (h > 0) return h + ' 小时 ' + m + ' 分';
		if (m > 0) return m + ' 分 ' + s + ' 秒';
		return s + ' 秒';
	},

	/*
	 * Times are shown in the router's time zone, the one its log uses, not
	 * the browser's. tz is the "+0800" style offset from `date +%z`.
	 */
	tzOffset: null,

	setTz: function(tz) {
		var m = /^([+-])(\d\d)(\d\d)$/.exec(tz || '');

		this.tzOffset = m ? (m[1] == '-' ? -1 : 1) * (Number(m[2]) * 3600 + Number(m[3]) * 60) : null;
	},

	fmtTime: function(epoch) {
		if (!epoch)
			return '-';

		if (this.tzOffset == null) {
			var l = new Date(epoch * 1000);

			return pad2(l.getMonth() + 1) + '-' + pad2(l.getDate()) + ' ' +
				pad2(l.getHours()) + ':' + pad2(l.getMinutes()) + ':' + pad2(l.getSeconds());
		}

		var d = new Date((epoch + this.tzOffset) * 1000);

		return pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate()) + ' ' +
			pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
	},

	fmtBytes: function(n) {
		n = Number(n);

		if (!isFinite(n) || n < 0)
			return '-';

		var units = [ 'B', 'KB', 'MB', 'GB', 'TB' ], i = 0;

		while (n >= 1024 && i < units.length - 1) {
			n /= 1024;
			i++;
		}

		return (i == 0 ? n : n.toFixed(n >= 100 ? 0 : (n >= 10 ? 1 : 2))) + ' ' + units[i];
	},

	fmtCount: function(n) {
		n = Number(n);

		if (!isFinite(n) || n < 0)
			return '-';

		if (n >= 1e9) return (n / 1e9).toFixed(2) + ' G';
		if (n >= 1e6) return (n / 1e6).toFixed(2) + ' M';
		if (n >= 1e4) return (n / 1e3).toFixed(1) + ' k';
		return String(n);
	},

	/*
	 * Lines of `logread`:
	 *   Fri Nov 20 12:58:12 2026 daemon.err gswifi-auth[3602]: [2026-11-20T12:58:12Z INFO] message
	 * A session's own lines carry "[time LEVEL]" or "[time LEVEL network]";
	 * a line of the same process without it continues the message above
	 * (a server announcement with several lines). Lines of the scripts
	 * ("gswifi:") take their level from the syslog priority.
	 */
	parseLog: function(text) {
		var out = [], last = null;
		var outer = /^\w{3} (\w{3} +\d+ [\d:]{8}) \d{4} \w+\.(\w+) (gswifi[\w-]*)(?:\[(\d+)\])?: (.*)$/;
		var inner = /^\[\S+ +(ERROR|WARN|INFO|DEBUG|TRACE)(?: +([^\]]+))?\] (.*)$/;
		var prio = { 'emerg': 'ERROR', 'alert': 'ERROR', 'crit': 'ERROR', 'err': 'ERROR', 'warn': 'WARN', 'warning': 'WARN' };

		(text || '').split('\n').forEach(function(raw) {
			if (raw === '')
				return;

			var o = outer.exec(raw);
			var e = { raw: raw, time: '', tag: '', pid: '', level: 'INFO', net: '', msg: raw, cont: false };

			if (o) {
				e.time = o[1];
				e.tag = o[3];
				e.pid = o[4] || '';
				e.msg = o[5];

				var i = inner.exec(o[5]);

				if (i) {
					e.level = i[1];
					e.net = i[2] || '';
					e.msg = i[3];
				}
				else if (e.tag == 'gswifi') {
					e.level = prio[o[2]] || 'INFO';
				}
				else if (last && last.pid == e.pid) {
					e.cont = true;
					e.level = last.level;
					e.net = last.net;
				}
			}

			if (!e.cont)
				last = e;

			out.push(e);
		});

		return out;
	},

	logTone: function(entry) {
		if (entry.level == 'ERROR') return 'bad';
		if (entry.level == 'WARN') return 'warn';
		return '';
	},

	/* names: { pid: label } for the processes that are running now */
	renderLogLine: function(entry, keyword, names) {
		var body;

		if (keyword) {
			var parts = [], rest = entry.msg, lower = rest.toLowerCase(), kw = keyword.toLowerCase(), i;

			while ((i = lower.indexOf(kw)) > -1) {
				if (i > 0)
					parts.push(rest.substring(0, i));

				parts.push(E('mark', {}, [ rest.substring(i, i + kw.length) ]));
				rest = rest.substring(i + kw.length);
				lower = rest.toLowerCase();
			}

			parts.push(rest);
			body = parts;
		}
		else {
			body = [ entry.msg ];
		}

		var tone = this.logTone(entry);
		var cls = (tone ? 'gsw-t-' + tone + ' gsw-tone' : '') + (entry.cont ? ' gsw-log-cont' : '');

		if (entry.cont)
			return E('div', { 'class': cls }, body);

		var who = entry.net || (names && names[entry.pid]) || '';

		if (!who && entry.tag == 'gswifi-proxy') who = _('代理');
		if (!who && entry.tag == 'gswifi') who = _('服务');
		if (!who && entry.pid) who = '#' + entry.pid;

		return E('div', { 'class': cls }, [
			E('span', { 'class': 'gsw-log-time' }, [ entry.time ? entry.time + '  ' : '' ]),
			who ? E('span', { 'class': 'gsw-log-tag' }, [ '[' + who + '] ' ]) : '',
			(entry.level == 'ERROR' || entry.level == 'WARN') ? entry.level + ' ' : ''
		].concat(body));
	},

	/* { pid: network id } from a status snapshot, to label log lines */
	pidNames: function(st) {
		var names = {};

		((st && st.networks) || []).forEach(function(n) {
			if (n.instance && n.instance.pid)
				names[n.instance.pid] = n.id;
		});

		return names;
	},

	copyText: function(text) {
		if (navigator.clipboard && window.isSecureContext)
			return navigator.clipboard.writeText(text).then(function() { return true; });

		/* The router is usually reached over plain http, where the clipboard API is unavailable. */
		var ta = E('textarea', { 'style': 'position:fixed;top:0;left:0;opacity:0' });
		var ok = false;

		/* .value, not child text: E() would parse a string child as HTML. */
		ta.value = text;

		document.body.appendChild(ta);
		ta.select();

		try { ok = document.execCommand('copy'); } catch (e) { ok = false; }

		document.body.removeChild(ta);

		return Promise.resolve(ok);
	},

	download: function(filename, text) {
		var url = URL.createObjectURL(new Blob([ text ], { type: 'text/plain;charset=utf-8' }));
		var a = E('a', { 'href': url, 'download': filename, 'style': 'display:none' });

		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		window.setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
	},

	stamp: function() {
		var d = new Date();

		return d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) + '-' +
			pad2(d.getHours()) + pad2(d.getMinutes()) + pad2(d.getSeconds());
	}
});
