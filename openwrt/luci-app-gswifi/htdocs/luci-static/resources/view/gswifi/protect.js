'use strict';
'require view';
'require form';
'require poll';
'require ui';
'require dom';
'require uci';
'require tools.widgets as widgets';
'require gswifi.api as api';

/*
 * Wording on this page is bound by the project's honesty rules: the
 * feature unifies some fields of outgoing packets and nothing has been
 * measured against any campus network's detection. It must never read as
 * "passes detection", and it steers towards observe mode before enforce.
 */

var FEATURE_NAMES = {
	'ttl': _('TTL / Hop Limit'),
	'ipid': _('IP ID'),
	'tcp-timestamps': _('TCP 时间戳'),
	'dscp-ecn': _('DSCP / ECN'),
	'inet-nat': _('端口接管（DNS / NTP / 代理）')
};

function validDevice(section_id, value) {
	return (!value || /^[A-Za-z0-9._@-]{1,15}$/.test(value)) ? true : _('网卡名最长 15 个字符，只能包含字母、数字和 . _ @ -');
}

function cell(title, cls, children) {
	return E('td', { 'class': 'td' + (cls ? ' ' + cls : ''), 'data-title': title }, children);
}

return view.extend({
	load: function() {
		return Promise.all([ api.protect(), uci.load('gswifi') ]);
	},

	render: function(data) {
		var n = this.n = {}, self = this, m, s, o;

		api.injectCSS();

		this.prev = null;

		/* ---- live status ---- */

		n.orb = E('span', { 'class': 'gsw-tone' }, '–');
		n.title = E('div', { 'class': 'gsw-hero-title gsw-tone' }, '');
		n.hint = E('div', { 'class': 'gsw-hero-hint' }, '');
		n.chips = E('div', { 'class': 'gsw-chips' });
		n.reapply = E('button', {
			'class': 'btn cbi-button cbi-button-neutral',
			'click': ui.createHandlerFn(this, 'handleReapply')
		}, _('重新安装规则（计数清零）'));
		n.hero = E('div', { 'class': 'gsw-hero gsw-t-idle' }, [
			E('div', { 'class': 'gsw-orb' }, [ n.orb ]),
			E('div', { 'class': 'gsw-hero-main' }, [ n.title, n.hint, n.chips ]),
			E('div', { 'class': 'gsw-hero-actions' }, [ n.reapply ])
		]);
		n.notes = E('div', {});
		n.counters = E('div', {});
		n.sysctl = E('div', {});

		var statusNode = E('div', { 'class': 'gsw' }, [
			api.section(_('当前状态'), [ n.hero, n.notes ]),
			api.section(_('规则与命中计数'), [ n.counters, n.sysctl ])
		]);

		/* ---- settings ---- */

		m = this.map = new form.Map('gswifi', _('校园网认证 - 防共享检测'), [
			_('校园网可以从每台设备都会泄露的报文特征（初始 TTL、IP ID 序列、TCP 时间戳、DSCP、临时端口范围、HTTP User-Agent、DNS 查询）推断路由器后面接了几台机器。这里用标准的 nftables、sysctl 和 dnsmasq 把上行接口发出去的报文统一成一台主机的样子。'),
			' ',
			_('没有在任何真实校园网上验证过效果：只能说“这些字段被统一了”，不能说“不会被判定为共享”。HTTPS / QUIC 的内容和 TLS 握手特征不受影响，仍然来自各台设备。')
		].join(''));

		s = m.section(form.NamedSection, 'protect', 'protect', _('设置'));
		s.addremove = false;

		s.tab('mode', _('模式与接口'));
		s.tab('features', _('报文特征'));
		s.tab('dns', _('DNS 与 NTP'));
		s.tab('proxy', _('User-Agent 代理'));

		o = s.taboption('mode', form.ListValue, 'mode', _('模式'),
			_('请先用“观察”：它装上同样的匹配条件，但只计数，不修改报文、不接管端口、不改系统参数。在上面的计数表里确认上行接口选对了、哪些规则真的有命中，再改成“启用”。'));
		o.value('disabled', _('关闭'));
		o.value('observe', _('观察：只统计，不修改任何报文（建议先用这个）'));
		o.value('enforce', _('启用：修改出口报文'));
		o.default = 'disabled';
		o.rmempty = false;

		o = s.taboption('mode', form.ListValue, 'persona', _('伪装成'),
			_('只是选一组前后一致的取值，并不会让路由器真的变成那种设备。'));
		o.value('pc', _('电脑（TTL 128，Windows 的临时端口范围）'));
		o.value('phone', _('手机（TTL 64，Android 的临时端口范围）'));
		o.default = 'pc';
		o.rmempty = false;

		o = s.taboption('mode', widgets.NetworkSelect, 'wan', _('上行接口'),
			_('通往校园网的接口。规则作用在它的三层设备上（PPPoE 时是 pppoe-wan），接口重新连接后自动跟随。'));
		o.multiple = true;
		o.nocreate = true;
		o.default = 'wan';
		o.rmempty = true;

		o = s.taboption('mode', widgets.NetworkSelect, 'lan', _('局域网接口'),
			_('客户端所在的接口。接管 DNS / NTP、User-Agent 代理和阻断 IPv6 需要它。不能与上行接口重复。'));
		o.multiple = true;
		o.nocreate = true;
		o.default = 'lan';
		o.rmempty = true;

		o = s.taboption('mode', form.DynamicList, 'wan_device', _('额外的上行网卡'),
			_('不归 netifd 管理的上行网卡，直接写内核设备名。一般留空。'));
		o.rmempty = true;
		o.optional = true;
		o.validate = validDevice;

		o = s.taboption('mode', form.DynamicList, 'lan_device', _('额外的局域网网卡'),
			_('不归 netifd 管理的局域网网卡。一般留空。'));
		o.rmempty = true;
		o.optional = true;
		o.validate = validDevice;

		o = s.taboption('mode', form.ListValue, 'failure_policy', _('某一部分无法运行时'),
			_('目前只影响 User-Agent 代理：代理没有在运行时，重定向规则不会安装。“放行”让这部分流量照常直连；“阻断”则拒绝本来要交给代理的连接，而不是让它们未经处理地出去。'));
		o.value('bypass', _('放行（默认）'));
		o.value('block', _('阻断'));
		o.default = 'bypass';
		o.rmempty = false;

		/* ---- per-signal switches ---- */

		o = s.taboption('features', form.Flag, 'ttl', _('统一 TTL / Hop Limit'),
			_('出口报文的 TTL 一律改成伪装类型的初始值，路由器自身发出的报文也一样。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.Flag, 'preserve_traceroute', _('保留 traceroute 探测'),
			_('TTL ≤ 32 和 250~255 的报文不动：前者是 traceroute 探测，后者是邻居发现、VRRP 一类的本地协议。'));
		o.default = '1';
		o.rmempty = false;
		o.depends('ttl', '1');
		o.retain = true;

		o = s.taboption('features', form.Flag, 'ipid', _('统一 IP ID 序列'),
			_('出口 IPv4 报文改用同一个递增计数；分片不动，以免破坏重组。需要内核 5.5 以上，不支持时会跳过并在上面说明。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.Flag, 'tcp_timestamps', _('去掉 TCP 时间戳'),
			_('删除出口 SYN 里的时间戳选项，并关闭路由器自身连接的时间戳。需要内核 5.18 以上，不支持时会跳过并在上面说明。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.Flag, 'dscp_ecn', _('清零 DSCP / ECN'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.Flag, 'icmp', _('不向上行发 ICMP 差错'),
			_('丢弃发往上行的“目的不可达”和“重定向”。“需要分片”保留，否则路径 MTU 发现会坏。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.Flag, 'source_ports', _('统一源端口范围'),
			_('路由器自身发起的连接改用伪装类型的临时端口范围（只影响路由器自己，转发的连接由 NAT 决定）。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('features', form.ListValue, 'ipv6', _('IPv6'),
			_('IPv6 下通常每台设备各有一个地址，统一 Hop Limit 并不能隐藏设备数量。'));
		o.value('forward', _('照常转发，不处理'));
		o.value('normalise', _('一并统一 Hop Limit'));
		o.value('block', _('拒绝局域网经上行走 IPv6（应用会退回 IPv4）'));
		o.default = 'forward';
		o.rmempty = false;

		/* ---- DNS / NTP ---- */

		o = s.taboption('dns', form.Flag, 'dns_take_over', _('接管局域网的 DNS'),
			_('把局域网发往任何地址的 53 端口查询都交给路由器自己的解析器。DoH / DoT 不走 53 端口，不受影响。'));
		o.default = '0';
		o.rmempty = false;

		o = s.taboption('dns', form.Flag, 'dns_filter_aaaa', _('过滤 AAAA 记录'),
			_('让客户端留在 IPv4。这不等于阻断 IPv6。需要 dnsmasq 2.87 以上；配置通不过 dnsmasq 的检查时整套设置不会生效。'));
		o.default = '0';
		o.rmempty = false;

		o = s.taboption('dns', form.Flag, 'dns_local_arpa', _('反向解析只在本机回答'),
			_('in-addr.arpa、ip6.arpa 和 ipv4only.arpa 的查询不上送。'));
		o.default = '0';
		o.rmempty = false;

		o = s.taboption('dns', form.DynamicList, 'dns_blocked_domain', _('屏蔽的域名'),
			_('这些域名一律回答 0.0.0.0。列表完全由你自己填写，本程序不内置任何列表：一份过期的列表会悄悄弄坏联网检测。修改 DNS 设置会重启 dnsmasq。'));
		o.datatype = 'hostname';
		o.placeholder = 'telemetry.example.com';
		o.rmempty = true;

		o = s.taboption('dns', form.Flag, 'ntp', _('接管局域网的 NTP'),
			_('把局域网发往任何地址的 123 端口都交给路由器。需要在“系统 → 系统 → 时间同步”里打开“作为 NTP 服务器提供服务”，否则客户端对时会失败。'));
		o.default = '0';
		o.rmempty = false;

		/* ---- proxy ---- */

		o = s.taboption('proxy', form.Flag, 'proxy', _('启用 User-Agent 代理'),
			_('把局域网的 TCP 连接重定向到路由器上的透明代理（gswifi proxy）：对上行来说连接由路由器自己发起，明文 HTTP 请求的 User-Agent 被换成下面的值。重定向只在代理确实在监听时才安装。HTTPS 的内容是加密的，User-Agent 既看不到也改不了。'));
		o.default = '0';
		o.rmempty = false;

		o = s.taboption('proxy', form.Value, 'proxy_ua', _('统一的 User-Agent'),
			_('留空则不改写，只代理连接。'));
		o.placeholder = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
		o.rmempty = true;
		o.depends('proxy', '1');
		o.retain = true;

		o = s.taboption('proxy', form.Flag, 'proxy_http_only', _('只代理明文 HTTP'),
			_('只重定向 80 和 8080 端口。关闭后所有 TCP 都经过代理，路由器的负担会明显增加。'));
		o.default = '1';
		o.rmempty = false;
		o.depends('proxy', '1');
		o.retain = true;

		o = s.taboption('proxy', form.Value, 'proxy_port', _('代理监听端口'));
		o.datatype = 'port';
		o.default = '1080';
		o.rmempty = false;
		o.depends('proxy', '1');
		o.retain = true;

		o = s.taboption('proxy', form.DynamicList, 'proxy_strip_header', _('删除的请求头'),
			_('从明文 HTTP 请求里删掉这些请求头，例如 X-Requested-With。'));
		o.rmempty = true;
		o.depends('proxy', '1');
		o.retain = true;
		o.validate = function(section_id, value) {
			return (!value || /^[A-Za-z0-9-]+$/.test(value)) ? true : _('请求头名称只能包含字母、数字和连字符');
		};

		return m.render().then(function(mapNode) {
			/* The live status goes between the description and the form. */
			var first = mapNode.querySelector('.cbi-section, .cbi-tabmenu');

			if (first && first.parentNode == mapNode)
				mapNode.insertBefore(statusNode, first);
			else
				mapNode.appendChild(statusNode);

			self.update(data[0]);
			api.fit(mapNode);
			poll.add(L.bind(self.refresh, self), 3);

			return mapNode;
		});
	},

	refresh: function() {
		return api.protect().then(L.bind(this.update, this));
	},

	update: function(pr) {
		var n = this.n;

		if (!pr || pr.mode == null) {
			n.hero.className = 'gsw-hero gsw-t-bad';
			n.orb.textContent = '?';
			n.title.textContent = _('无法获取状态');
			n.hint.textContent = _('请确认已安装 gswifi 软件包。');
			return;
		}

		this.pr = pr;
		api.setTz(pr.tz);

		var applied = pr.applied || {}, plan = applied.plan || {},
		    tone = 'idle', glyph = '–', title, text;

		if (!pr.available) {
			tone = 'bad'; glyph = '✕';
			title = _('这台路由器不能使用');
			text = _('需要 firewall4（nftables）。没有找到 nft 或 fw4。');
		}
		else if (pr.mode == 'disabled') {
			title = _('未启用');
			text = pr.installed
				? _('配置是关闭的，但防火墙里还有 inet gswifi 表。保存一次设置即可清除。')
				: _('出口流量没有做任何处理，防火墙里没有本程序的规则。');
		}
		else if (applied.ok === false) {
			tone = 'bad'; glyph = '✕';
			title = _('规则没有安装');
			text = (applied.error || _('原因见日志。')) +
				(applied.stale && pr.installed ? '\n' + _('防火墙里仍是上一次成功安装的规则。') : '');
		}
		else if (!pr.installed) {
			tone = 'warn'; glyph = '!';
			title = _('规则当前不在防火墙里');
			text = _('没有找到 inet gswifi 表。点击“重新安装规则”，或重启 gswifi 服务。');
		}
		else if (applied.mode == 'observe') {
			tone = 'busy'; glyph = '◎';
			title = _('观察模式：只统计，不修改报文');
			text = _('下面的计数说明每条规则会命中多少报文。上行接口的计数一直是 0，通常说明接口选错了。确认无误后把模式改为“启用”。');
		}
		else {
			tone = 'ok'; glyph = '✓';
			title = _('已启用：出口报文的特征被统一');
			text = _('规则正在修改出口报文。这不代表不会被判定为共享：没有任何学校的实测数据。网络出现异常时把模式改回“观察”或“关闭”即可撤销。');
		}

		n.hero.className = 'gsw-hero gsw-t-' + tone;
		n.orb.textContent = glyph;
		n.title.textContent = title;
		n.hint.textContent = text;
		n.reapply.disabled = (pr.mode == 'disabled' || !pr.available);

		var chips = [];

		if (applied.mode && applied.mode != 'disabled') {
			if ((applied.wan || []).length)
				chips.push(E('span', { 'class': 'gsw-chip' }, [ _('上行网卡 '), E('b', {}, [ applied.wan.join(' ') ]) ]));

			if ((applied.lan || []).length)
				chips.push(E('span', { 'class': 'gsw-chip' }, [ _('局域网网卡 '), E('b', {}, [ applied.lan.join(' ') ]) ]));

			chips.push(E('span', { 'class': 'gsw-chip' }, [ _('伪装成 '), E('b', {}, [ pr.persona == 'phone' ? _('手机') : _('电脑') ]) ]));

			if (applied.at)
				chips.push(E('span', { 'class': 'gsw-chip' }, [ _('安装于 '), E('b', {}, [ api.fmtTime(applied.at) ]) ]));
		}

		if (pr.kernel)
			chips.push(E('span', { 'class': 'gsw-chip' }, [ _('内核 '), E('b', {}, [ pr.kernel ]) ]));

		dom.content(n.chips, chips);

		/* what was left out, and what limits the rest */
		var notes = [];

		(applied.problems || []).forEach(function(p) {
			notes.push(api.note('warn', null, [ p ]));
		});

		if (applied.mode != 'disabled')
			(plan.skipped || []).forEach(function(sk) {
				notes.push(api.note('warn', _('已跳过 %s：').format(FEATURE_NAMES[sk.feature] || sk.feature), [
					sk.why, _('。这一项没有生效。')
				]));
			});

		if (pr.mode != 'disabled' && pr.offloading && pr.offloading.software)
			notes.push(api.note('warn', _('防火墙开着流量分载：'), [
				pr.offloading.hardware
					? _('被硬件分载的连接只有开头几个报文经过这些规则，之后的报文不会被改写。')
					: _('被软件分载的连接只有开头几个报文经过这些规则，之后的报文不会被改写。'),
				_('要让规则对整条连接生效，需要在“网络 → 防火墙”里关闭流量分载。')
			]));

		if (pr.proxy && pr.proxy.enabled && pr.mode != 'disabled') {
			if (pr.proxy.listening) {
				var st = pr.proxy.stats || {};

				notes.push(api.note('busy', _('User-Agent 代理在监听 %d 端口：').format(pr.proxy.port), [
					_('当前 %d 个连接，累计 %d 个；改写了 %d / %d 个 HTTP 请求，失败 %d，拒绝 %d。')
						.format(st.active || 0, st.total || 0, st.rewritten || 0, st.requests || 0, st.failed || 0, st.refused || 0)
				]));
			}
			else {
				notes.push(api.note('warn', _('User-Agent 代理没有在运行：'), [
					_('重定向规则没有安装，这部分流量按“某一部分无法运行时”的设置处理。原因见日志。')
				]));
			}
		}

		dom.content(n.notes, notes);

		this.updateCounters(pr, applied, plan);
	},

	updateCounters: function(pr, applied, plan) {
		var n = this.n, self = this;

		if (!pr.installed || !(pr.counters || []).length) {
			dom.content(n.counters, E('div', { 'class': 'gsw-muted' },
				pr.mode == 'disabled'
					? _('模式为“关闭”时没有规则。选“观察”并保存后，这里会列出每条规则和它命中的报文数。')
					: _('防火墙里没有本程序的规则。')));
			dom.content(n.sysctl, '');
			this.prev = null;
			return;
		}

		var what = {}, max = 0, rates = {}, prev = this.prev;

		(plan.rules || []).forEach(function(r) { what[r.id] = r.what; });

		pr.counters.forEach(function(c) {
			max = Math.max(max, Number(c.packets) || 0);

			if (prev && prev.at < pr.now && prev.packets[c.name] != null && Number(c.packets) >= prev.packets[c.name])
				rates[c.name] = (Number(c.packets) - prev.packets[c.name]) / (pr.now - prev.at);
		});

		/* A reload resets the counters; start the rates over then. */
		if (!prev || prev.at < pr.now) {
			var packets = {};

			pr.counters.forEach(function(c) { packets[c.name] = Number(c.packets) || 0; });
			this.prev = { at: pr.now, packets: packets };
		}

		var observe = (applied.mode == 'observe');

		var rows = pr.counters.map(function(c) {
			var p = Number(c.packets) || 0,
			    rate = rates[c.name];

			return E('tr', { 'class': 'tr' }, [
				cell(_('规则'), 'left gsw-mono', [ c.name ]),
				cell(_('作用'), 'left gsw-wrap', [ what[c.name] || _('（上一次安装的规则）') ]),
				cell(_('命中报文'), 'right gsw-num', [ api.fmtCount(p) ]),
				cell(_('字节'), 'right gsw-num', [ api.fmtBytes(c.bytes) ]),
				cell(_('速率'), 'right gsw-num', [ rate != null ? (rate >= 10 ? rate.toFixed(0) : rate.toFixed(1)) + ' /s' : '-' ]),
				cell(_('占比'), '', [
					E('div', { 'class': 'gsw-meter gsw-t-' + (observe ? 'busy' : 'ok') }, [
						E('span', { 'style': 'width:' + (max > 0 ? Math.round(p * 100 / max) : 0) + '%' })
					])
				])
			]);
		});

		dom.content(n.counters, [
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th left' }, _('规则')),
					E('th', { 'class': 'th left' }, _('作用')),
					E('th', { 'class': 'th right' }, _('命中报文')),
					E('th', { 'class': 'th right' }, _('字节')),
					E('th', { 'class': 'th right' }, _('速率')),
					E('th', { 'class': 'th' }, _('占比'))
				])
			].concat(rows)),
			E('div', { 'class': 'gsw-muted gsw-small gsw-gap' }, [
				observe
					? _('观察模式：以上规则只计数，没有修改任何报文。')
					: _('以上规则正在修改命中的报文。'),
				' ',
				_('计数在规则每次重新加载后从零开始（保存设置、防火墙重载、接口重连都会重新加载）。')
			])
		]);

		var sysctl = plan.sysctl || [];

		dom.content(n.sysctl, sysctl.length ? E('div', { 'class': 'gsw-gap' }, [
			E('div', { 'class': 'gsw-muted gsw-small' }, _('同时改动的系统参数（只影响路由器自身发出的连接；关闭或停止服务时恢复原值）：')),
			E('div', { 'class': 'gsw-chips' }, sysctl.map(function(x) {
				return E('span', { 'class': 'gsw-chip gsw-mono' }, [ x.key + ' = ' + x.value ]);
			}))
		]) : '');
	},

	handleReapply: function() {
		var self = this;

		return api.protectApply().then(function(res) {
			if (res && res.code)
				ui.addNotification(null, E('p', {}, [ _('安装规则失败：'), String(res.output || res.code) ]), 'error');

			self.prev = null;

			return self.refresh();
		});
	},

	/* Going straight from "off" to "enforce" skips the step that shows whether the rules fit. */
	confirmEnforce: function(proceed) {
		var opt = this.map.lookupOption('mode', 'protect'),
		    el = opt ? opt[0].getUIElement('protect') : null,
		    want = el ? el.getValue() : null,
		    saved = uci.get('gswifi', 'protect', 'mode') || 'disabled';

		/* The base "save & apply" calls handleSave itself; ask once. */
		if (this.confirmed || want != 'enforce' || saved != 'disabled')
			return proceed();

		var self = this;
		var go = function() {
			self.confirmed = true;

			return Promise.resolve(proceed()).then(
				function(r) { self.confirmed = false; return r; },
				function(e) { self.confirmed = false; throw e; });
		};

		return new Promise(function(resolve) {
			ui.showModal(_('直接启用？'), [
				E('p', {}, _('现在的模式是“关闭”。建议先用“观察”运行一段时间：它不修改任何报文，只在计数表里显示每条规则会命中多少流量，可以先确认上行接口选对了、内核支持哪些规则。')),
				E('p', {}, _('“启用”会立刻开始修改出口报文。')),
				E('div', { 'class': 'right' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-neutral',
						'click': function() { ui.hideModal(); resolve(null); }
					}, _('取消')),
					' ',
					E('button', {
						'class': 'btn cbi-button cbi-button-negative',
						'click': function() { ui.hideModal(); resolve(go()); }
					}, _('仍然直接启用')),
					' ',
					E('button', {
						'class': 'btn cbi-button cbi-button-positive important',
						'click': function() { ui.hideModal(); el.setValue('observe'); resolve(go()); }
					}, _('改用观察模式'))
				])
			]);
		});
	},

	handleSave: function(ev) {
		var self = this, args = arguments;

		return this.confirmEnforce(function() { return view.prototype.handleSave.apply(self, args); });
	},

	handleSaveApply: function(ev, mode) {
		var self = this, args = arguments;

		return this.confirmEnforce(function() { return view.prototype.handleSaveApply.apply(self, args); });
	}
});
