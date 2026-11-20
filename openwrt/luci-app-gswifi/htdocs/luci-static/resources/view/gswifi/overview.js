'use strict';
'require view';
'require poll';
'require ui';
'require dom';
'require gswifi.api as api';

function notifyError(prefix, detail) {
	ui.addNotification(null, E('p', {}, [ prefix, String(detail) ]), 'error');
}

function pause(ms) {
	return new Promise(function(resolve) { window.setTimeout(resolve, ms); });
}

/* What to tell the user about a network in its current state. */
function hint(n) {
	var dev = n.device || '?',
	    s = n.session || {},
	    sup = api.support(n.support);

	switch (n.state) {
	case 'disabled':
		return _('这个网络已关闭。点击“启用”开始认证。');

	case 'unsupported':
		return n.unavailable || _('程序不认识认证方式 %s。').format(n.driver);

	case 'unconfigured':
		return _('还没有填写用户名或密码，请到“认证设置”补全。');

	case 'needs-experimental':
		return _('%s 的验证程度是“%s”：%s确认要用，请到“认证设置”勾选“允许使用实验性认证方式”。')
			.format(n.driver_title, sup.label, sup.text);

	case 'nodev':
		return n.device
			? _('网卡 %s 不存在。它出现后会自动开始认证。').format(dev)
			: _('接口 %s 没有对应的网卡。请到“认证设置”检查认证接口，或直接指定网卡。').format(n['interface']);

	case 'nolink':
		return _('网卡 %s 没有检测到链路。接好网线后会自动开始认证。').format(dev);

	case 'not-started':
		return _('已启用，但服务没有在运行这个网络。点击“重新认证”启动它。');

	case 'exited':
		return _('认证程序退出了（退出码 %s）。系统会在 30 秒后重新启动它，连续 5 次失败后不再重启；原因见下面的日志。')
			.format(n.instance && n.instance.exit_code != null ? n.instance.exit_code : '?');

	case 'fatal':
		return (s.reason ? s.reason + '\n' : '') +
			_('这是配置或环境的问题，不是服务器拒绝了账号。修正后保存设置，或点击“重新认证”。');

	case 'starting':
	case 'idle':
		return _('正在启动认证程序…');

	case 'waiting-ip':
		return _('这种认证方式要先有 IPv4 地址，正在等待网卡 %s 获取地址。').format(dev);

	case 'discovering':
		return _('已经发出寻找认证服务器的报文，正在等待应答。一直没有应答时程序会持续重试，这期间不会发送账号密码。');

	case 'authenticating':
		return _('认证服务器已应答，正在提交账号并等待校验…');

	case 'online':
		return _('认证已通过。');

	case 'backoff':
		return _('上一轮没有成功，程序会在等待之后自动重试。');

	case 'rejected':
		var what = (s.reject_stage == 'identity')
			? _('服务器拒绝了用户名，或没有通过客户端校验。')
			: (s.reject_stage == 'password')
				? _('服务器拒绝了密码；也可能是 MAC 绑定不符或账号状态异常。')
				: _('服务器拒绝了这次登录。');

		return what + (s.reason ? '\n' + _('服务器的说明：') + s.reason : '') + '\n' +
			_('为了不让账号被锁定，程序不会在同一个地址上重试。修正设置后保存，或点击“重新认证”再试一次；网卡拿到新地址时也会自动再试。');

	case 'gave-up':
		return _('认证服务器一直没有应答（%s），程序已经停止尝试。网卡地址变化后会再试，也可以点击“重新认证”。')
			.format(s.reason || '-');

	case 'server-not-found':
		return _('没有任何认证服务器应答。请确认网线接在校园网端口上、认证方式选对了。网卡地址变化后会再试，也可以点击“重新认证”。');

	case 'stopped':
		return _('会话已经下线。');
	}

	return '';
}

/* One network: its nodes are built once and filled in on every poll. */
function NetworkCard(view, id) {
	var c = this;

	c.id = id;
	c.orb = E('span', { 'class': 'gsw-tone' }, '–');
	c.title = E('div', { 'class': 'gsw-hero-title gsw-tone' }, '');
	c.hint = E('div', { 'class': 'gsw-hero-hint' }, '');
	c.chips = E('div', { 'class': 'gsw-chips' });
	c.restart = E('button', {
		'class': 'btn cbi-button cbi-button-action',
		'click': ui.createHandlerFn(view, 'handleRestart', id)
	}, _('重新认证'));
	c.toggle = E('button', {
		'class': 'btn cbi-button cbi-button-positive',
		'click': ui.createHandlerFn(view, 'handleToggle', id)
	}, _('启用'));
	c.hero = E('div', { 'class': 'gsw-hero gsw-t-idle' }, [
		E('div', { 'class': 'gsw-orb' }, [ c.orb ]),
		E('div', { 'class': 'gsw-hero-main' }, [ c.title, c.hint, c.chips ]),
		E('div', { 'class': 'gsw-hero-actions' }, [
			c.restart,
			c.toggle,
			api.linkButton(_('设置'), 'admin/services/gswifi/settings')
		])
	]);

	c.notes = E('div', {});

	c.kDriver = api.kv(_('认证方式'));
	c.kUser = api.kv(_('账号'));
	c.kDev = api.kv(_('认证网卡'));
	c.kLink = api.kv(_('链路'));
	c.kIp = api.kv(_('IPv4 地址'), true);
	c.kGw = api.kv(_('网关'), true);
	c.kMac = api.kv(_('MAC 地址'), true);
	c.kSince = api.kv(_('当前状态已持续'));
	c.kOnline = api.kv(_('本次在线时长'));
	c.kCount = api.kv(_('登录成功 / 尝试'));
	c.kAlive = api.kv(_('在线保活'), false, true);
	c.kProc = api.kv(_('进程'));

	c.lines = E('div', { 'class': 'gsw-lines' });

	c.node = api.section([ _('网络 '), id ], [
		c.hero,
		c.notes,
		E('div', { 'class': 'gsw-kvs' }, [
			c.kDriver.row, c.kUser.row, c.kDev.row, c.kLink.row, c.kIp.row, c.kGw.row,
			c.kMac.row, c.kSince.row, c.kOnline.row, c.kCount.row, c.kProc.row, c.kAlive.row
		]),
		c.lines
	], { 'data-network': id });
}

NetworkCard.prototype.update = function(n) {
	var c = this,
	    def = api.state(n.state),
	    s = n.session || {},
	    dev = n.dev || {},
	    live = n.instance && n.instance.running && s.pid == n.instance.pid;

	c.n = n;
	c.live = live;

	c.hero.className = 'gsw-hero gsw-t-' + def.tone;
	c.orb.textContent = def.glyph;
	c.title.textContent = def.label;
	c.hint.textContent = hint(n);

	c.toggle.textContent = n.enabled ? _('停用') : _('启用');
	c.toggle.className = 'btn cbi-button ' + (n.enabled ? 'cbi-button-negative' : 'cbi-button-positive');
	c.restart.disabled = !n.enabled || [ 'unconfigured', 'unsupported', 'needs-experimental' ].indexOf(n.state) > -1;
	c.restart.textContent = (n.state == 'online') ? _('重新认证') : _('立即重新认证');

	var chips = [
		E('span', { 'class': 'gsw-chip' }, [ n.driver_title ]),
		api.supportBadge(n.support)
	];

	if (n.username)
		chips.push(E('span', { 'class': 'gsw-chip' }, [ _('账号 '), E('b', {}, [ n.username ]) ]));

	chips.push(E('span', { 'class': 'gsw-chip' }, [
		_('接口 '),
		E('b', {}, [ n.device_manual ? (n.device || '?') : n['interface'] + (n.device && n.device != n['interface'] ? ' → ' + n.device : '') ])
	]));

	dom.content(c.chips, chips);

	/* Honesty first: say what is not verified about the driver in use. */
	var notes = [], sup = api.support(n.support);

	if (n.enabled && n.experimental && n.support != 'field-tested' && n.support != 'lab-tested')
		notes.push(api.note('warn', _('实验性认证方式：'), [
			_('%s 的验证程度是“%s”。').format(n.driver_title, sup.label), ' ', sup.text
		]));

	(n.problems || []).forEach(function(p) {
		/* The states above already explain what keeps a session from starting. */
		if (n.enabled && n.state != 'unconfigured' && n.state != 'needs-experimental' && n.state != 'unsupported' && n.state != 'nodev')
			notes.push(api.note('warn', _('设置有问题：'), [ p ]));
	});

	dom.content(c.notes, notes);

	dom.content(c.kDriver.v, [ n.driver_title + ' (' + n.driver + ')' ]);
	c.kUser.v.textContent = n.username || _('未填写');
	dom.content(c.kDev.v, n.device
		? [ n.device, ' ', n.device_manual ? api.badge(_('手动指定'), 'idle') : '' ]
		: [ api.badge(_('未找到'), 'bad') ]);

	if (!dev.present) {
		dom.content(c.kLink.v, n.device ? [ api.badge(_('网卡不存在'), 'bad') ] : '-');
		c.kMac.v.textContent = '-';
	}
	else {
		var link = dev.carrier ? _('已连接') : _('未连接');

		if (dev.carrier && dev.speed)
			link += ' · ' + (dev.speed >= 1000 ? (dev.speed / 1000) + ' Gbps' : dev.speed + ' Mbps');

		dom.content(c.kLink.v, [ api.badge(link, dev.carrier ? 'ok' : 'warn') ]);
		c.kMac.v.textContent = (dev.mac || '-').toUpperCase();
	}

	dom.content(c.kIp.v, (dev.ipv4 && dev.ipv4.length)
		? dev.ipv4.map(function(a) { return E('div', {}, [ a ]); })
		: (live && s.ipv4 ? [ s.ipv4 ] : _('未获取')));
	c.kGw.v.textContent = dev.gateway || (live && s.gateway) || '-';

	c.kCount.v.textContent = live ? (s.successes || 0) + ' / ' + (s.attempts || 0) : '-';

	var ka = api.KEEPALIVE[n.driver];

	dom.content(c.kAlive.v, ka
		? [ ka.known ? '' : api.badge(_('未验证'), 'warn'), ka.known ? '' : ' ', ka.text ]
		: [ api.badge(_('未知'), 'warn') ]);

	var procs = [];

	if (n.instance && n.instance.running)
		procs.push('PID ' + n.instance.pid);
	else if (n.instance && n.instance.exit_code != null)
		procs.push(_('已退出，退出码 ') + n.instance.exit_code);

	c.kProc.v.textContent = procs.length ? procs.join('，') : _('未运行');

	/* what the server and the program last said */
	var lines = [];

	if (s.server_message && s.server_message.text)
		lines.push(E('div', { 'class': 'gsw-line gsw-t-busy' }, [
			E('span', { 'class': 'gsw-line-head' }, [ _('服务器消息 · '), api.fmtTime(s.server_message.at) ]),
			s.server_message.text
		]));

	if (s.last_issue && s.last_issue.text && n.state != 'online')
		lines.push(E('div', { 'class': 'gsw-line gsw-t-' + (s.last_issue.level == 'ERROR' ? 'bad' : 'warn') }, [
			E('span', { 'class': 'gsw-line-head' }, [
				(s.last_issue.level == 'ERROR' ? _('最近的错误 · ') : _('最近的警告 · ')), api.fmtTime(s.last_issue.at)
			]),
			s.last_issue.text
		]));

	if (live && s.last_log && s.last_log.text && (!s.last_issue || s.last_log.text != s.last_issue.text || n.state == 'online'))
		lines.push(E('div', { 'class': 'gsw-line' }, [
			E('span', { 'class': 'gsw-line-head' }, [ _('最近一条日志 · '), api.fmtTime(s.last_log.at) ]),
			s.last_log.text
		]));

	dom.content(c.lines, lines);
};

/* The parts that count seconds, between polls. */
NetworkCard.prototype.tick = function(now) {
	var c = this, n = c.n, s = (n && n.session) || {};

	if (!n)
		return;

	c.kSince.v.textContent = (c.live && s.state_since) ? api.fmtDuration(now - s.state_since) : '-';

	if (c.live && n.state == 'online' && s.online_since)
		c.kOnline.v.textContent = api.fmtDuration(now - s.online_since) + _('（自 %s）').format(api.fmtTime(s.online_since));
	else if (c.live && s.last_online)
		c.kOnline.v.textContent = _('不在线，上次在线 ') + api.fmtTime(s.last_online);
	else
		c.kOnline.v.textContent = '-';
};

return view.extend({
	load: function() {
		return Promise.all([ api.status(), api.protect(), api.log(12) ]);
	},

	render: function(data) {
		var n = this.n = {};

		api.injectCSS();

		this.cards = {};
		this.order = '';

		/* shown while the status cannot be fetched */
		n.stale = E('div', { 'class': 'alert-message error', 'style': 'display:none' });
		n.banner = E('div', {});
		n.networks = E('div', {});

		/* protect summary */
		n.pOrb = E('span', { 'class': 'gsw-tone' }, '–');
		n.pTitle = E('div', { 'class': 'gsw-hero-title gsw-tone' }, '');
		n.pHint = E('div', { 'class': 'gsw-hero-hint' }, '');
		n.pChips = E('div', { 'class': 'gsw-chips' });
		n.pHero = E('div', { 'class': 'gsw-hero gsw-t-idle' }, [
			E('div', { 'class': 'gsw-orb' }, [ n.pOrb ]),
			E('div', { 'class': 'gsw-hero-main' }, [ n.pTitle, n.pHint, n.pChips ]),
			E('div', { 'class': 'gsw-hero-actions' }, [
				api.linkButton(_('规则与计数'), 'admin/services/gswifi/protect')
			])
		]);

		n.log = E('div', { 'class': 'gsw-log', 'style': 'max-height:280px' });
		/* the theme already tones the description down; no extra dimming */
		n.version = E('span', {}, '');

		var root = E('div', { 'class': 'gsw' }, [
			E('h2', {}, _('校园网认证')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Open GSWIFI：多协议校园网认证客户端，每个网络对应一个接口上的一个认证会话。'), ' ', n.version
			]),
			n.stale,
			n.banner,
			n.networks,
			api.section(_('防共享检测'), [ n.pHero ]),
			api.section(_('最近日志'), [
				n.log,
				E('div', { 'class': 'gsw-gap' }, [
					E('a', { 'href': L.url('admin/services/gswifi/log') }, _('查看全部日志 »'))
				])
			])
		]);

		this.root = root;
		this.update(data[0], data[1], data[2]);
		api.fit(root);

		poll.add(L.bind(this.refresh, this), 3);
		window.setInterval(L.bind(this.tick, this), 1000);

		return root;
	},

	refresh: function() {
		return Promise.all([ api.status(), api.protect(), api.log(12) ]).then(L.bind(function(res) {
			this.update(res[0], res[1], res[2]);
		}, this));
	},

	/* Seconds since the epoch on the router, extrapolated from the last poll. */
	now: function() {
		if (!this.st)
			return 0;

		return this.st.now + (Date.now() - this.fetchedAt) / 1000;
	},

	tick: function() {
		if (!this.st || this.isStale)
			return;

		var now = this.now(), cards = this.cards;

		Object.keys(cards).forEach(function(id) { cards[id].tick(now); });
	},

	update: function(st, pr, logText) {
		var n = this.n, self = this;

		if (!st || !Array.isArray(st.networks)) {
			this.isStale = true;
			n.stale.style.display = '';
			n.stale.textContent = this.st
				? _('无法从路由器获取状态，下面显示的是 %s 的数据。').format(api.fmtTime(this.st.now))
				: _('无法从路由器获取状态。请确认已安装 gswifi 软件包，并且 rpcd 已经重新加载。');
			return;
		}

		this.isStale = false;
		n.stale.style.display = 'none';
		this.st = st;
		this.fetchedAt = Date.now();
		api.setTz(st.tz);

		n.version.textContent = st.version ? '（' + st.version + '）' : '';

		var banner = [];

		if (!st.binary)
			banner.push(E('div', { 'class': 'alert-message error' }, _('没有找到 /usr/bin/gswifi，认证程序没有安装。')));
		else if (!st.drivers_known)
			banner.push(E('div', { 'class': 'alert-message error' }, _('认证程序太旧，无法列出认证方式（需要支持 gswifi drivers --json 的版本）。')));

		if (st.binary && !st.boot_enabled)
			banner.push(E('div', { 'class': 'alert-message warning' },
				_('服务没有设置为开机启动：重启路由器后不会自动认证。可以在“系统 → 启动项”里启用 gswifi。')));

		if (!st.networks.length)
			banner.push(E('div', { 'class': 'alert-message' }, [
				_('还没有配置任何网络。'), ' ',
				E('a', { 'href': L.url('admin/services/gswifi/settings') }, _('去添加一个'))
			]));

		dom.content(n.banner, banner);

		/* cards are rebuilt only when the set of networks changes */
		var order = st.networks.map(function(x) { return x.id; }).join('\n');

		if (order != this.order) {
			this.order = order;
			this.cards = {};
			dom.content(n.networks, st.networks.map(function(x) {
				return (self.cards[x.id] = new NetworkCard(self, x.id)).node;
			}));
			api.fit(this.root);
		}

		st.networks.forEach(function(x) { self.cards[x.id].update(x); });

		this.updateProtect(pr);

		/* recent log; null means it could not be fetched, keep what is shown */
		if (logText != null) {
			var entries = api.parseLog(logText), names = api.pidNames(st),
			    atBottom = (n.log.scrollHeight - n.log.scrollTop - n.log.clientHeight) < 30;

			dom.content(n.log, entries.length
				? entries.map(function(e) { return api.renderLogLine(e, null, names); })
				: E('div', { 'class': 'gsw-muted' }, _('还没有日志。')));

			if (atBottom)
				n.log.scrollTop = n.log.scrollHeight;
		}

		this.tick();
	},

	updateProtect: function(pr) {
		var n = this.n;

		if (!pr || pr.mode == null)
			return;

		var applied = pr.applied || {}, plan = applied.plan || {},
		    tone = 'idle', glyph = '–', title, text;

		if (pr.mode == 'disabled') {
			title = _('未启用');
			text = _('出口流量没有做任何处理。想用的话先选“观察模式”：它只统计哪些规则会命中，不修改任何报文。');
		}
		else if (applied.ok === false) {
			tone = 'bad'; glyph = '✕';
			title = _('规则没有安装');
			text = applied.error || _('原因见日志。');
		}
		else if (!pr.installed) {
			tone = 'warn'; glyph = '!';
			title = _('规则当前不在防火墙里');
			text = _('配置的模式是 %s，但没有找到 inet gswifi 表。保存一次设置，或重启 gswifi 服务。').format(pr.mode);
		}
		else if (pr.mode == 'observe') {
			tone = 'busy'; glyph = '◎';
			title = _('观察模式：只统计，不修改报文');
			text = _('确认上行接口选对了、规则确实有命中之后，再改为启用。');
		}
		else {
			tone = 'ok'; glyph = '✓';
			title = _('已启用：出口报文的特征被统一');
			text = _('这只是把若干报文特征统一成一台设备的样子，没有在任何真实校园网验证过效果，不代表不会被判定为共享。');
		}

		n.pHero.className = 'gsw-hero gsw-t-' + tone;
		n.pOrb.textContent = glyph;
		n.pTitle.textContent = title;
		n.pHint.textContent = text;

		var chips = [];

		if (pr.mode != 'disabled' && pr.installed) {
			var hits = 0;

			(pr.counters || []).forEach(function(c) { hits += Number(c.packets) || 0; });

			chips.push(E('span', { 'class': 'gsw-chip' }, [ _('规则 '), E('b', {}, [ String((plan.rules || []).length) ]), _(' 条') ]));
			chips.push(E('span', { 'class': 'gsw-chip' }, [ _('命中 '), E('b', {}, [ api.fmtCount(hits) ]), _(' 个报文') ]));

			if ((plan.skipped || []).length)
				chips.push(E('span', { 'class': 'gsw-chip' }, [ _('跳过 '), E('b', {}, [ String(plan.skipped.length) ]), _(' 项（内核不支持）') ]));

			if ((applied.wan || []).length)
				chips.push(E('span', { 'class': 'gsw-chip' }, [ _('上行 '), E('b', {}, [ applied.wan.join(' ') ]) ]));
		}

		dom.content(n.pChips, chips);
	},

	handleRestart: function(id) {
		var self = this;

		return api.control('restart', id).then(function(res) {
			if (res && res.code)
				notifyError(_('重新认证失败：'), res.output || res.code);

			return pause(800);
		}).catch(function(err) {
			notifyError(_('重新认证失败：'), err);
		}).then(function() {
			return self.refresh();
		});
	},

	handleToggle: function(id) {
		var self = this, card = this.cards[id];
		var want = !(card && card.n && card.n.enabled);

		return api.control(want ? 'enable' : 'disable', id).then(function(res) {
			if (res && res.code)
				notifyError(_('操作失败：'), res.output || res.code);

			return pause(800);
		}).catch(function(err) {
			notifyError(_('操作失败：'), err);
		}).then(function() {
			return self.refresh();
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
