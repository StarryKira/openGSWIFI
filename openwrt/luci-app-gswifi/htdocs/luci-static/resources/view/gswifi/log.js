'use strict';
'require view';
'require poll';
'require ui';
'require dom';
'require gswifi.api as api';

return view.extend({
	load: function() {
		return Promise.all([ api.log(500), api.status() ]);
	},

	render: function(data) {
		var n = this.n = {}, self = this;

		api.injectCSS();

		this.text = data[0];
		this.names = api.pidNames(data[1]);
		this.auto = true;

		var redraw = function() { self.draw(); };

		n.lines = E('select', { 'change': function() { self.refresh(); } }, [
			E('option', { 'value': '200' }, '200'),
			E('option', { 'value': '500', 'selected': 'selected' }, '500'),
			E('option', { 'value': '2000' }, '2000'),
			E('option', { 'value': '5000' }, '5000')
		]);
		n.level = E('select', { 'change': redraw }, [
			E('option', { 'value': '' }, _('全部')),
			E('option', { 'value': 'warn' }, _('警告和错误')),
			E('option', { 'value': 'error' }, _('只看错误'))
		]);
		n.who = E('select', { 'change': redraw }, [ E('option', { 'value': '' }, _('全部')) ]);
		n.keyword = E('input', { 'type': 'text', 'placeholder': _('关键字'), 'style': 'width:10em', 'input': redraw });
		n.auto = E('input', { 'type': 'checkbox', 'checked': 'checked', 'change': function(ev) { self.auto = ev.currentTarget.checked; } });
		n.count = E('span', { 'class': 'gsw-muted gsw-small' }, '');
		n.log = E('div', { 'class': 'gsw-log', 'style': 'height:62vh;min-height:260px' });

		var root = E('div', { 'class': 'gsw' }, [
			E('h2', {}, _('校园网认证 - 日志')),
			E('div', { 'class': 'cbi-map-descr' },
				_('认证会话、代理和服务脚本写进系统日志的内容。日志在内存里，路由器重启后清空；系统日志写满后最早的会被覆盖。')),
			api.section(_('系统日志里的 gswifi'), [
				E('div', { 'class': 'gsw-toolbar' }, [
					E('label', {}, [ _('最近'), n.lines, _('行') ]),
					E('label', {}, [ _('级别'), n.level ]),
					E('label', {}, [ _('来源'), n.who ]),
					n.keyword,
					E('label', {}, [ n.auto, _('自动刷新') ]),
					E('span', { 'class': 'gsw-spacer' }),
					n.count,
					E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, 'handleCopy') }, _('复制')),
					E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, 'handleDownload') }, _('下载'))
				]),
				n.log
			])
		]);

		this.draw(true);
		api.fit(root);

		poll.add(function() {
			return self.auto ? self.refresh() : Promise.resolve();
		}, 3);

		return root;
	},

	refresh: function() {
		var self = this;

		return Promise.all([ api.log(Number(this.n.lines.value) || 500), api.status() ]).then(function(res) {
			/* null: the log could not be fetched; keep what is shown */
			if (res[0] != null) {
				self.text = res[0];
				self.names = api.pidNames(res[1]);
				self.draw();
			}
		});
	},

	/* Who wrote a line: a network (by name or by the pid running now), the proxy, or the scripts. */
	source: function(e) {
		if (e.net) return e.net;
		if (this.names[e.pid]) return this.names[e.pid];
		if (e.tag == 'gswifi-proxy') return _('代理');
		if (e.tag == 'gswifi') return _('服务');
		return e.pid ? '#' + e.pid : '';
	},

	shown: function() {
		var self = this,
		    level = this.n.level.value,
		    who = this.n.who.value,
		    kw = this.n.keyword.value.trim().toLowerCase();

		return this.entries.filter(function(e) {
			if (level == 'error' && e.level != 'ERROR') return false;
			if (level == 'warn' && e.level != 'ERROR' && e.level != 'WARN') return false;
			if (who && self.source(e) != who) return false;
			if (kw && e.msg.toLowerCase().indexOf(kw) < 0) return false;
			return true;
		});
	},

	draw: function(first) {
		var n = this.n, self = this;

		this.entries = api.parseLog(this.text || '');

		/* sources present in the log, keeping the selection */
		var seen = {}, sel = n.who.value, opts = [ E('option', { 'value': '' }, _('全部')) ];

		this.entries.forEach(function(e) {
			var s = self.source(e);

			if (s && !seen[s]) {
				seen[s] = true;
				opts.push(E('option', { 'value': s }, [ s ]));
			}
		});

		dom.content(n.who, opts);
		n.who.value = seen[sel] ? sel : '';

		var list = this.shown(),
		    kw = n.keyword.value.trim(),
		    atBottom = first || (n.log.scrollHeight - n.log.scrollTop - n.log.clientHeight) < 40;

		dom.content(n.log, list.length
			? list.map(function(e) { return api.renderLogLine(e, kw, self.names); })
			: E('div', { 'class': 'gsw-muted' }, this.text == null
				? _('无法读取日志。')
				: (this.entries.length ? _('没有符合条件的日志。') : _('还没有日志。启用一个网络后，认证过程会记录在这里。'))));

		n.count.textContent = _('%d / %d 行').format(list.length, this.entries.length);

		if (atBottom)
			n.log.scrollTop = n.log.scrollHeight;
	},

	plain: function() {
		return this.shown().map(function(e) { return e.raw; }).join('\n') + '\n';
	},

	handleCopy: function() {
		return api.copyText(this.plain()).then(function(ok) {
			ui.addNotification(null, E('p', {}, ok ? _('已复制到剪贴板。') : _('复制失败，请手动选择文字复制。')), ok ? 'info' : 'warning');
		});
	},

	handleDownload: function() {
		api.download('gswifi-log-' + api.stamp() + '.txt', this.plain());
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
