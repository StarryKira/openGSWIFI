'use strict';
'require view';
'require ui';
'require dom';
'require gswifi.api as api';

var TRANSPORT = {
	'eapol': _('802.1X（以太网帧）'),
	'udp': 'UDP',
	'http': _('HTTP Portal'),
	'pppoe': _('PPPoE（只派生拨号账号）')
};

/* A card with a button that runs something on the router and shows its text output. */
function runner(title, descr, label, call, filename) {
	var out = E('pre', { 'class': 'gsw-pre', 'style': 'display:none' }),
	    tools = E('span', { 'class': 'gsw-row', 'style': 'display:none' }),
	    text = '';

	var run = function() {
		return call().then(function(res) {
			text = (res && res.output != null) ? String(res.output) : '';

			if (!text)
				text = _('（没有输出）');

			out.textContent = text;
			out.style.display = '';
			tools.style.display = '';

			if (res && res.code)
				ui.addNotification(null, E('p', {}, _('命令返回了错误码 %d，输出见下。').format(res.code)), 'warning');
		}).catch(function(err) {
			ui.addNotification(null, E('p', {}, [ _('执行失败：'), String(err) ]), 'error');
		});
	};

	dom.content(tools, [
		E('button', {
			'class': 'btn cbi-button cbi-button-neutral',
			'click': function() {
				return api.copyText(text).then(function(ok) {
					ui.addNotification(null, E('p', {}, ok ? _('已复制到剪贴板。') : _('复制失败，请手动选择文字复制。')), ok ? 'info' : 'warning');
				});
			}
		}, _('复制')),
		E('button', {
			'class': 'btn cbi-button cbi-button-neutral',
			'click': function() { api.download(filename + '-' + api.stamp() + '.txt', text); }
		}, _('下载'))
	]);

	return api.section(title, [
		E('p', {}, descr),
		E('div', { 'class': 'gsw-row' }, [
			E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': ui.createHandlerFn({ run: run }, 'run') }, label),
			tools
		]),
		out
	]);
}

return view.extend({
	load: function() {
		return api.drivers();
	},

	render: function(drivers) {
		var n = this.n = {}, self = this;

		api.injectCSS();

		drivers = Array.isArray(drivers) ? drivers : [];

		/* ---- NetKeeper ---- */

		/* type=text: not every theme draws a box around number inputs */
		n.nkVersion = E('input', { 'type': 'text', 'inputmode': 'numeric', 'value': '4', 'style': 'width:5em' });
		n.nkUser = E('input', { 'type': 'text', 'placeholder': _('宽带账号'), 'style': 'width:16em' });
		n.nkOffset = E('input', { 'type': 'text', 'inputmode': 'numeric', 'value': '0', 'style': 'width:6em' });
		n.nkOut = E('div', {});

		var netkeeper = api.section(_('NetKeeper / 闪讯 拨号账号'), [
			E('p', {}, [
				_('NetKeeper 把宽带账号变换成一个随时间变化的 PPPoE 用户名（经典算法每 5 秒变一次），拨号时用它代替原账号。'),
				' ',
				E('strong', {}, _('这里只是计算器：')),
				_('本软件包没有接入 netifd / pppd，不会替你拨号。算出的用户名要在有效期内交给 pppd 才有用，所以实际使用需要自己在拨号脚本里调用 gswifi pppoe-username。算法只有离线样本，没有在真实线路上验证过。')
			]),
			E('div', { 'class': 'gsw-toolbar' }, [
				E('label', {}, [ _('nk_version'), n.nkVersion ]),
				E('label', {}, [ _('账号'), n.nkUser ]),
				E('label', {}, [ _('时间校正（秒）'), n.nkOffset ]),
				E('button', {
					'class': 'btn cbi-button cbi-button-action',
					'click': ui.createHandlerFn(this, 'handleNetkeeper')
				}, _('计算'))
			]),
			E('div', { 'class': 'gsw-muted gsw-small' },
				_('nk_version 1~13 是经典 getPIN 的各省版本，14 是海南。15（重庆 4.x）、99、SRun、四川、江苏没有还原，会报不支持。')),
			n.nkOut
		]);

		/* ---- drivers ---- */

		var rows = drivers.map(function(d) {
			var sup = api.support(d.support);

			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left gsw-mono', 'data-title': _('名称') }, [ d.name ]),
				E('td', { 'class': 'td left gsw-wrap', 'data-title': _('认证方式') }, [ d.title ]),
				E('td', { 'class': 'td left', 'data-title': _('传输') }, [ TRANSPORT[d.transport] || d.transport ]),
				E('td', { 'class': 'td left', 'data-title': _('验证程度') }, [ api.supportBadge(d.support) ]),
				E('td', { 'class': 'td left gsw-wrap', 'data-title': _('说明') }, [
					(d.runnable === false)
						? E('span', {}, [ api.badge(_('不能运行'), 'bad'), ' ', d.unavailable || '' ])
						: E('span', {}, [
							sup.text,
							d.experimental ? ' ' + _('使用前需要勾选“允许使用实验性认证方式”。') : ''
						])
				])
			]);
		});

		var driverTable = api.section(_('认证方式'), [
			E('p', {},
				_('这张表直接来自认证程序（gswifi drivers）。验证程度从低到高：仅按文档实现 → 仅离线测试 → 实验室验证 → 实网验证。低于“实验室验证”的方式默认不能启用。')),
			drivers.length
				? E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th left' }, _('名称')),
						E('th', { 'class': 'th left' }, _('认证方式')),
						E('th', { 'class': 'th left' }, _('传输')),
						E('th', { 'class': 'th left' }, _('验证程度')),
						E('th', { 'class': 'th left' }, _('说明'))
					])
				].concat(rows))
				: E('div', { 'class': 'alert-message warning' }, _('无法从认证程序读取列表。请确认已安装 gswifi 软件包。'))
		]);

		var root = E('div', { 'class': 'gsw' }, [
			E('h2', {}, _('校园网认证 - 工具')),
			netkeeper,
			driverTable,
			runner(_('检查防共享检测规则'),
				_('按当前保存的设置生成规则，交给 nft -c 和 dnsmasq --test 检查，并列出内核不支持而被跳过的功能。只检查，不安装，也不改动正在使用的规则。'),
				_('运行 gswifi protect check'), function() { return api.protectCheck(); }, 'gswifi-protect-check'),
			runner(_('查看将要安装的规则'),
				_('打印按当前保存的设置会安装的完整 nftables 规则。'),
				_('运行 gswifi protect show'), function() { return api.protectShow(); }, 'gswifi-protect-show'),
			runner(_('诊断信息'),
				_('汇总系统信息、配置（密码已隐藏）、会话状态、防火墙规则、网卡、路由和最近的日志，报告问题时附上。内容里有用户名、MAC 和 IP 地址，贴到公开场合前请自行检查。'),
				_('生成诊断信息'), function() { return api.diag(); }, 'gswifi-diag')
		]);

		api.fit(root);

		return root;
	},

	handleNetkeeper: function() {
		var n = this.n, self = this,
		    version = parseInt(n.nkVersion.value, 10),
		    user = n.nkUser.value,
		    offset = parseInt(n.nkOffset.value, 10) || 0;

		if (this.timer) {
			window.clearInterval(this.timer);
			this.timer = null;
		}

		if (!user) {
			dom.content(n.nkOut, E('div', { 'class': 'alert-message warning' }, _('请填写账号。')));
			return Promise.resolve();
		}

		if (!(version >= 1 && version <= 255)) {
			dom.content(n.nkOut, E('div', { 'class': 'alert-message warning' }, _('nk_version 应为数字，例如 4。')));
			return Promise.resolve();
		}

		return api.pppoe(version, user, offset).then(function(res) {
			if (!res || res.error || !res.escaped) {
				dom.content(n.nkOut, E('div', { 'class': 'alert-message warning' }, [ (res && res.error) || _('计算失败。') ]));
				return;
			}

			var left = Number(res.remaining) || 0,
			    remain = E('span', {}, [ String(left) ]);

			dom.content(n.nkOut, E('div', { 'class': 'gsw-result' }, [
				E('div', { 'class': 'gsw-muted gsw-small' }, _('拨号用户名（C 字符串转义，可以写进 pppd 的 user "..."）')),
				E('div', {}, [ E('code', {}, [ res.escaped ]) ]),
				E('div', { 'class': 'gsw-muted gsw-small gsw-gap' }, _('十六进制')),
				E('div', { 'class': 'gsw-mono gsw-wrap' }, [ res.hex ]),
				E('div', { 'class': 'gsw-gap gsw-row' }, [
					E('span', {}, [ _('还有 '), remain, _(' 秒有效') ]),
					E('button', {
						'class': 'btn cbi-button cbi-button-neutral',
						'click': function() {
							return api.copyText(res.escaped).then(function(ok) {
								ui.addNotification(null, E('p', {}, ok ? _('已复制到剪贴板。') : _('复制失败，请手动选择文字复制。')), ok ? 'info' : 'warning');
							});
						}
					}, _('复制用户名'))
				])
			]));

			self.timer = window.setInterval(function() {
				left--;

				if (left <= 0) {
					window.clearInterval(self.timer);
					self.timer = null;
					dom.content(remain.parentNode, [ api.badge(_('已过期'), 'warn'), ' ', _('需要重新计算。') ]);
				}
				else {
					remain.textContent = String(left);
				}
			}, 1000);
		}).catch(function(err) {
			dom.content(n.nkOut, E('div', { 'class': 'alert-message error' }, [ _('计算失败：'), String(err) ]));
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
