'use strict';
'require view';
'require form';
'require uci';
'require tools.widgets as widgets';
'require gswifi.api as api';

/*
 * UCI option names are the program's own option names: what is saved here
 * as `option start_mode '1'` reaches the driver as `start_mode = 1`. Some
 * names mean something different per driver (start_mode, service,
 * max_retries, data_file, server), so each gets one widget per meaning,
 * all writing the same UCI option (`ucioption`) and only the one of the
 * selected driver being shown. Those widgets set `retain`: LuCI would
 * otherwise let a hidden widget delete the value a visible one just wrote.
 */

var EAPOL = [ 'ruijie', 'saier', 'eap-md5', 'inode' ];

function byteLength(s) {
	return new TextEncoder().encode(s || '').length;
}

return view.extend({
	load: function() {
		return Promise.all([ api.drivers(), uci.load('gswifi') ]);
	},

	render: function(data) {
		var drivers = Array.isArray(data[0]) ? data[0] : [],
		    byName = {},
		    experimental = [],
		    m, s, o, net;

		api.injectCSS();

		drivers.forEach(function(d) {
			byName[d.name] = d;

			if (d.experimental && d.runnable !== false)
				experimental.push(d.name);
		});

		/* Re-checks the fields whose validity depends on other fields. */
		function revalidate(section_id) {
			[ 'username', 'password', 'experimental' ].forEach(function(name) {
				var el = net.getUIElement(section_id, name);

				if (el && el.triggerValidation)
					el.triggerValidation();
			});
		}

		function requiredWhenEnabled(section_id, value) {
			if (this.section.formvalue(section_id, 'enabled') == '1' && (value == null || value === ''))
				return _('启用这个网络时必须填写');

			return true;
		}

		/*
		 * A rule that involves another field has to hold when the form is
		 * saved, not only when this field was last touched (ticking
		 * "enabled" does not re-validate the user name, and LuCI's
		 * checkbox widget has no validation at all). `check` returns an
		 * error text or null; a failing check stops the save with it.
		 */
		function checkOnSave(option, check) {
			var parse = option.parse;

			option.parse = function(section_id) {
				if (this.isActive(section_id)) {
					var error = check.call(this, section_id, this.formvalue(section_id));

					if (error)
						return Promise.reject(new TypeError(_('网络 %s：%s').format(section_id, error)));
				}

				return parse.apply(this, arguments);
			};
		}

		function enabled(option, section_id) {
			return option.section.formvalue(section_id, 'enabled') == '1';
		}

		/* An option shown for some drivers only. `uciname`: see the note at the top. */
		function opt(tab, type, name, only, title, descr, uciname) {
			var w = s.taboption(tab, type, uciname ? '_' + only[0].replace(/-/g, '_') + '_' + uciname : name, title, descr);

			if (uciname) {
				w.ucioption = uciname;
				w.retain = true;
			}

			only.forEach(function(d) { w.depends('driver', d); });

			return w;
		}

		m = new form.Map('gswifi', _('校园网认证 - 认证设置'),
			_('每个“网络”是一个接口上的一个认证会话。保存并应用后，只有改动过的网络会重新认证。'));

		s = m.section(form.TypedSection, 'network', _('网络'),
			_('服务器明确拒绝登录（密码错误、MAC 绑定不符等）之后，程序不会在同一个地址上反复重试，以免账号被锁定；修正设置后保存，或在“概览”里点“重新认证”。服务器没有应答时会一直重试，这期间不发送账号密码。'));
		s.anonymous = false;
		s.addremove = true;
		s.addbtntitle = _('添加网络');
		net = s;

		s.tab('general', _('账号与接口'));
		s.tab('proto', _('协议参数'));
		s.tab('advanced', _('高级'));

		/* ---- account and interface ---- */

		o = s.taboption('general', form.Flag, 'enabled', _('启用'),
			_('开启后随路由器启动自动认证并保持在线。'));
		o.default = '1';
		o.rmempty = false;
		o.onchange = function(ev, section_id) { revalidate(section_id); };

		o = s.taboption('general', form.ListValue, 'driver', _('认证方式'),
			_('括号里是这种方式的验证程度，来自认证程序本身（gswifi drivers）。只有“实网验证”表示有人用它在真实校园网登录成功过。'));
		o.default = 'ruijie';
		o.rmempty = false;
		o.onchange = function(ev, section_id) { revalidate(section_id); };

		drivers.forEach(function(d) {
			if (d.runnable !== false)
				o.value(d.name, '%s（%s）'.format(d.title, api.support(d.support).label));
		});

		if (!drivers.length) {
			/* The program could not be asked; keep what is configured selectable. */
			var seen = { 'ruijie': true };

			o.value('ruijie', 'ruijie');
			uci.sections('gswifi', 'network', function(sec) {
				if (sec.driver && !seen[sec.driver]) {
					seen[sec.driver] = true;
					o.value(sec.driver, sec.driver);
				}
			});
		}

		/* What the selected driver's level means, one note per driver. */
		drivers.forEach(function(d) {
			if (d.runnable === false)
				return;

			var note = s.taboption('general', form.DummyValue, '_level_' + d.name.replace(/-/g, '_'), _('验证程度'));

			note.depends('driver', d.name);
			note.renderWidget = function() {
				var sup = api.support(d.support), ka = api.KEEPALIVE[d.name];

				return E('div', { 'class': 'gsw' }, [
					E('div', {}, [ api.supportBadge(d.support), ' ', sup.text ]),
					ka ? E('div', { 'class': 'gsw-small gsw-muted', 'style': 'margin-top:4px' }, [ _('在线保活：'), ka.text ]) : ''
				]);
			};
		});

		o = s.taboption('general', form.Flag, 'experimental', _('允许使用实验性认证方式'),
			_('这种认证方式没有达到“实验室验证”：它可能根本登录不上，也可能登录后很快掉线。勾选表示你了解这一点并愿意试用；不勾选时程序拒绝启动它。'));
		o.default = '0';
		experimental.forEach(function(d) { o.depends('driver', d); });
		checkOnSave(o, function(section_id, value) {
			return (enabled(this, section_id) && value != '1')
				? _('所选的认证方式尚未在真实校园网验证。要启用这个网络，必须先勾选“允许使用实验性认证方式”；否则请先取消“启用”。')
				: null;
		});

		o = s.taboption('general', form.Value, 'username', _('用户名'),
			_('校园网账号，通常是学号或工号。'));
		o.rmempty = true;
		o.validate = requiredWhenEnabled;
		checkOnSave(o, function(section_id, value) {
			return (enabled(this, section_id) && !value) ? _('启用时必须填写用户名。') : null;
		});

		o = s.taboption('general', form.Value, 'password', _('密码'),
			_('密码以明文保存在路由器的 /etc/config/gswifi 中（仅 root 可读），运行时写入 /var 下权限为 0600 的文件，不会出现在进程列表或日志里。'));
		o.password = true;
		o.rmempty = true;
		o.validate = requiredWhenEnabled;
		checkOnSave(o, function(section_id, value) {
			return (enabled(this, section_id) && !value) ? _('启用时必须填写密码。') : null;
		});

		o = s.taboption('general', widgets.NetworkSelect, 'interface', _('认证接口'),
			_('接校园网的那个接口，一般是 WAN。802.1X 的认证报文从它底层的网卡发出；其余方式使用它的三层设备（PPPoE 时是 pppoe-wan）。'));
		o.nocreate = true;
		o.default = 'wan';
		o.rmempty = false;

		o = s.taboption('general', widgets.DeviceSelect, 'device', _('指定网卡（可选）'),
			_('留空时自动使用上面接口对应的网卡。只有自动识别的不对时才需要指定。'));
		o.noaliases = true;
		o.optional = true;
		o.rmempty = true;

		/* ---- 802.1X family ---- */

		o = opt('proto', form.ListValue, 'dhcp_mode', EAPOL, _('DHCP 模式'),
			_('学校要求的认证与获取地址的先后顺序，与 MentoHUST 的 DhcpMode 相同。静态地址或“先有地址再认证”的学校选 0。'));
		o.value('0', _('0 - 不处理（地址由路由器自己管理）'));
		o.value('1', _('1 - 二次认证：认证 → 获取地址 → 再认证'));
		o.value('2', _('2 - 认证后获取地址'));
		o.value('3', _('3 - 认证前获取地址'));
		o.default = '0';
		o.rmempty = false;

		o = opt('proto', form.ListValue, null, [ 'ruijie' ], _('扩展数据格式'),
			_('modern：新版锐捷客户端的格式，mentorust 一直使用的那种（实网验证）。classic：MentoHUST 的 1000 字节模板，遇到非锐捷认证器时自动切换 V4 扩展；实网报告较少。none：不带厂商扩展。'), 'ext_format');
		o.value('modern', 'modern');
		o.value('classic', 'classic');
		o.value('none', 'none');
		o.default = 'modern';
		o.rmempty = false;

		o = opt('proto', form.ListValue, null, [ 'ruijie' ], _('寻找服务器方式'),
			_('发出第一个 Start 报文的目的地址（MentoHUST 的 StartMode）。'), 'start_mode');
		o.value('', _('自动（DHCP 模式 1 用锐捷组播，其余用标准组播）'));
		o.value('0', _('0 - 标准组播 01:80:C2:00:00:03'));
		o.value('1', _('1 - 锐捷组播 01:D0:F8:00:00:03'));
		o.value('2', _('2 - 赛尔'));
		o.value('3', _('3 - 广播'));
		o.optional = true;

		o = opt('proto', form.ListValue, null, [ 'eap-md5' ], _('寻找服务器方式'),
			_('第一个 Start 报文的目的地址；没有应答时会依次尝试其余的。'), 'start_mode');
		o.value('0', _('0 - 标准组播 01:80:C2:00:00:03'));
		o.value('1', _('1 - 锐捷组播 01:D0:F8:00:00:03'));
		o.value('3', _('3 - 广播'));
		o.default = '0';

		o = opt('proto', form.ListValue, null, [ 'inode' ], _('寻找服务器方式'),
			_('iNode 只支持标准组播和广播。'), 'start_mode');
		o.value('0', _('0 - 标准组播 01:80:C2:00:00:03'));
		o.value('3', _('3 - 广播'));
		o.default = '0';

		o = opt('proto', form.ListValue, 'pkt_type', [ 'ruijie', 'eap-md5' ], _('报文发送方式'),
			_('用户名、密码和心跳报文发给谁（MentoHUST 的 PktType）。'));
		o.value('0', _('0 - 发给认证服务器'));
		o.value('1', _('1 - 发给标准组播地址'));
		o.default = '0';

		o = opt('proto', form.Flag, 'eapol_dhcp', [ 'ruijie' ], _('向服务器声明使用 DHCP'),
			_('modern 格式里的一个字段（环境变量 EAPOL_ENABLE_DHCP）。WAN 口用 DHCP 获取地址时开启；学校分配静态 IP 时关闭。'));
		o.default = '1';
		o.rmempty = false;

		o = opt('proto', form.Value, null, [ 'ruijie' ], _('服务类型'),
			_('modern 格式里的服务名（EAPOL_SERVICE）。留空使用默认的“互联网”。官方客户端里需要选择“服务”的学校，在这里填对应的名称；最长 32 字节，按 UTF-8 原样发送。'), 'service');
		o.placeholder = _('互联网（默认）');
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (byteLength(value) > 32) ? _('不能超过 32 字节（一个汉字占 3 字节）') : true;
		};

		o = opt('proto', form.Value, 'hdd_ser', [ 'ruijie' ], _('硬盘序列号'),
			_('modern 格式里的硬盘序列号（EAPOL_HDD_SER），个别学校会校验。留空使用内置的默认值；最长 64 字节。'));
		o.placeholder = 'Static:AB45A862';
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (byteLength(value) > 64) ? _('不能超过 64 字节') : true;
		};

		o = opt('proto', form.Value, 'client_version', [ 'ruijie' ], _('客户端版本号'),
			_('写进 classic 格式的客户端版本，例如 4.10。留空时从“客户端文件目录”里的 8021x.exe 读取。'));
		o.placeholder = '4.10';
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (!value || /^\d{1,3}\.\d{1,3}$/.test(value)) ? true : _('应形如 4.10');
		};

		o = opt('proto', form.Value, 'check_version', [ 'ruijie' ], _('校验算法版本'),
			_('客户端校验算法的版本；留空时跟随客户端版本号。'));
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (!value || /^\d{1,3}\.\d{1,3}$/.test(value)) ? true : _('应形如 4.10');
		};

		o = opt('proto', form.Value, null, [ 'ruijie' ], _('客户端文件目录'),
			_('存放官方客户端的 8021x.exe、W32N55.dll、SuConfig.dat 的目录，用来计算客户端校验（V2/V3）。本软件包不附带这些文件，需要自己从学校的客户端里取。留空则不做校验。'), 'data_file');
		o.placeholder = '/etc/gswifi/ruijie';
		o.rmempty = true;

		o = opt('proto', form.Flag, 'udp_heartbeat', [ 'ruijie' ], _('UDP 心跳（实验性）'),
			_('服务器要求时发送锐捷 UDP 心跳。这部分没有在真实校园网验证过。'));
		o.default = '0';

		/* ---- iNode material: the 802.1X driver and the H3C Portal share it ---- */

		o = opt('proto', form.Value, 'vif', [ 'inode', 'h3c-portal' ], _('iNode.vif 路径'),
			_('从官方 iNode 客户端取得的版本文件，用来算出上传给服务器的客户端版本。留空时尝试 /etc/mentohust/iNode.vif，找不到就不上传版本。'));
		o.placeholder = '/etc/mentohust/iNode.vif';
		o.rmempty = true;

		o = opt('proto', form.Value, 'version', [ 'inode', 'h3c-portal' ], _('iNode 版本号'),
			_('直接给出版本号（例如 V5.20-0001C），优先于 vif 文件。'));
		o.rmempty = true;

		o = opt('proto', form.Value, null, [ 'inode', 'h3c-portal' ], _('inode-gs.dat 路径'),
			_('H3C 挑战校验用的数据文件。留空时尝试 /etc/mentohust/inode-gs.dat，找不到就不用。'), 'data_file');
		o.placeholder = '/etc/mentohust/inode-gs.dat';
		o.rmempty = true;

		o = opt('proto', form.Flag, 'upload_ver', [ 'inode', 'h3c-portal' ], _('上传客户端版本'));
		o.default = '1';
		o.rmempty = false;

		o = opt('proto', form.Flag, 'upload_ip', [ 'inode', 'h3c-portal' ], _('上传 IP 地址'));
		o.default = '1';
		o.rmempty = false;

		/* ---- H3C Portal ---- */

		o = opt('proto', form.Value, 'portal_ip', [ 'h3c-portal' ], _('Portal 服务器地址'),
			_('留空（0.0.0.0）时使用接口的 DNS 服务器地址，与原固件的做法一致。'));
		o.datatype = 'ip4addr("nomask")';
		o.placeholder = '0.0.0.0';
		o.rmempty = true;

		o = opt('proto', form.Value, 'server_port', [ 'h3c-portal' ], _('服务器端口'));
		o.datatype = 'port';
		o.placeholder = '50200';
		o.rmempty = true;

		o = opt('proto', form.Flag, 'plain_password', [ 'h3c-portal' ], _('明文发送密码'),
			_('不做密码块变换（原固件的 UsePlainTextPass）。'));
		o.default = '0';

		o = opt('proto', form.Value, 'heartbeat_interval', [ 'h3c-portal' ], _('心跳间隔（秒）'));
		o.datatype = 'range(1,3600)';
		o.placeholder = '10';
		o.rmempty = true;

		o = opt('proto', form.Value, 'max_fail', [ 'h3c-portal' ], _('连续失败多少轮后放弃'),
			_('0 表示一直重试。服务默认填 0：登录应答里没有错误码，分不清是密码错还是服务器忙，所以失败只按“一轮失败”计。'));
		o.datatype = 'uinteger';
		o.default = '0';
		o.rmempty = false;

		/* ---- 安朗 ---- */

		o = opt('proto', form.Value, null, [ 'anlang' ], _('认证服务器地址'),
			_('留空时向 1.1.1.8 发现服务器（原客户端的做法）。'), 'server');
		o.datatype = 'ip4addr("nomask")';
		o.rmempty = true;

		o = opt('proto', form.Value, null, [ 'anlang' ], _('服务名'),
			_('登录用的服务（原客户端的 stype）。留空时向服务器查询。'), 'service');
		o.rmempty = true;

		o = opt('proto', form.ListValue, 'response_check', [ 'anlang' ], _('应答校验'),
			_('strict：丢弃摘要或长度不对的应答（参考实现的做法）。firmware：像原固件那样照单全收。服务器实际怎么做没有抓包确认。'));
		o.value('strict', 'strict');
		o.value('firmware', 'firmware');
		o.default = 'strict';

		o = opt('proto', form.Flag, 'retry_on_reject', [ 'anlang' ], _('登录被拒后继续重试'),
			_('安朗的拒绝应答不带原因，“密码错误”和“已经在线”看起来一样。开启（默认，原客户端的行为）时按超时处理、退避后重试；关闭则第一次被拒就停止。密码确实填错时，开启会让路由器每隔一会儿重试一次。'));
		o.default = '1';
		o.rmempty = false;

		/* ---- Dr.com ---- */

		o = opt('proto', form.ListValue, 'mode', [ 'drcom' ], _('工作模式'),
			_('dhcp：接口已经有地址，通过 UDP 登录并保活。pppoe：由 pppd 完成拨号认证，这里只跑 Dr.com 的 UDP 辅助心跳，认证接口要选 PPPoE 接口。'));
		o.value('dhcp', 'dhcp (D)');
		o.value('pppoe', 'pppoe (P)');
		o.default = 'dhcp';
		o.rmempty = false;

		o = opt('proto', form.Value, null, [ 'drcom' ], _('Dr.com 服务器地址'), null, 'server');
		o.datatype = 'ip4addr("nomask")';
		o.rmempty = false;

		o = opt('proto', form.Value, 'auth_version', [ 'drcom' ], _('AUTH_VERSION'),
			_('两个字节的十六进制，例如 2700。来自学校的配置（通常是对官方客户端抓包得到），dhcp 模式必填。'));
		o.placeholder = '2700';
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (!value || /^(0x)?[0-9a-fA-F]{2}[ :-]?[0-9a-fA-F]{2}$/.test(value)) ? true : _('应为两个字节的十六进制，例如 2700');
		};

		o = opt('proto', form.Value, 'keep_alive_version', [ 'drcom' ], _('KEEP_ALIVE_VERSION'),
			_('两个字节的十六进制，例如 dc02。dhcp 模式必填；pppoe 模式由服务器的应答给出。'));
		o.placeholder = 'dc02';
		o.rmempty = true;
		o.validate = function(section_id, value) {
			return (!value || /^(0x)?[0-9a-fA-F]{2}[ :-]?[0-9a-fA-F]{2}$/.test(value)) ? true : _('应为两个字节的十六进制，例如 dc02');
		};

		o = s.taboption('proto', form.Value, 'pppoe_flag', _('pppoe_flag'),
			_('pppoe 模式必填，0 到 255。'));
		o.datatype = 'range(0,255)';
		o.depends({ driver: 'drcom', mode: 'pppoe' });
		o.rmempty = true;

		o = opt('proto', form.Value, 'host_name', [ 'drcom' ], _('主机名'),
			_('写进登录报文的主机名，最长 32 字节。'));
		o.placeholder = 'OpenWrt';
		o.rmempty = true;

		o = opt('proto', form.Flag, 'ror_version', [ 'drcom' ], _('ror_version'),
			_('在登录报文里附加 ROL 密码扩展（学校配置里的 ror_version）。'));
		o.default = '0';

		o = opt('proto', form.Flag, 'keepalive1_mod', [ 'drcom' ], _('keepalive1_mod'),
			_('使用 keepalive1 的 mod 格式。'));
		o.default = '0';

		/* ---- 湖北 Portal ---- */

		o = opt('proto', form.Value, 'portal_host', [ 'portal-hubei-old-mac' ], _('Portal 主机'),
			_('主机[:端口]。留空时使用探测请求被重定向到的主机。账号密码只会发给这个主机和下面的“允许的主机”。'));
		o.rmempty = true;

		o = opt('proto', form.DynamicList, 'allowed_hosts', [ 'portal-hubei-old-mac' ], _('允许的主机'),
			_('除 Portal 主机之外，还允许接收登录/下线请求的主机。'));
		o.rmempty = true;

		o = opt('proto', form.Value, 'probe_url', [ 'portal-hubei-old-mac' ], _('探测地址'),
			_('用来触发 Portal 重定向的明文 HTTP 地址。'));
		o.placeholder = 'http://www.baidu.com/';
		o.rmempty = true;

		o = opt('proto', form.Value, 'check_secs', [ 'portal-hubei-old-mac' ], _('在线探测间隔（秒）'),
			_('在线后每隔这么久探测一次是否还在线；0 关闭。厂商心跳没有还原，这是代替它的做法。'));
		o.datatype = 'range(0,86400)';
		o.placeholder = '60';
		o.rmempty = true;

		/* ---- shared timing ---- */

		o = opt('proto', form.Value, 'timeout', EAPOL.concat([ 'h3c-portal' ]), _('等待应答的超时（秒）'));
		o.datatype = 'range(1,3600)';
		o.placeholder = '8';
		o.rmempty = true;

		o = opt('proto', form.Value, 'restart_wait', EAPOL.concat([ 'h3c-portal' ]), _('失败后等待多久再试（秒）'));
		o.datatype = 'range(0,86400)';
		o.placeholder = '15';
		o.rmempty = true;

		o = opt('proto', form.Value, null, EAPOL, _('服务器无应答时的重试轮数'),
			_('连续这么多轮收不到任何应答就放弃，直到网卡换了地址或手动重新认证。-1 表示一直重试（服务的默认值：没人应答时只发寻找服务器的报文，不发送账号密码）。'), 'max_retries');
		o.datatype = 'and(integer,min(-1))';
		o.default = '-1';
		o.rmempty = false;

		o = opt('proto', form.Value, 'echo_interval', EAPOL, _('心跳间隔（秒）'),
			_('0 表示使用服务器下发的间隔。'));
		o.datatype = 'range(0,86400)';
		o.placeholder = '0';
		o.rmempty = true;

		o = opt('proto', form.Value, 'gateway', EAPOL, _('上报的网关地址'),
			_('留空时使用路由表里的默认网关。'));
		o.datatype = 'ip4addr("nomask")';
		o.rmempty = true;

		o = opt('proto', form.Value, 'dns', EAPOL, _('上报的 DNS 地址'),
			_('留空时使用系统的上游 DNS。'));
		o.datatype = 'ip4addr("nomask")';
		o.rmempty = true;

		o = opt('proto', form.Value, 'max_rounds', [ 'anlang', 'portal-hubei-old-mac' ], _('失败多少轮后放弃'),
			_('0 表示一直重试（默认）。'));
		o.datatype = 'uinteger';
		o.placeholder = '0';
		o.rmempty = true;

		o = opt('proto', form.Flag, 'stop_on_reject', [ 'h3c-portal', 'portal-hubei-old-mac' ], _('第一次被拒就停止'),
			_('默认关闭：这两种方式的拒绝应答不带可靠的原因，被拒只按“一轮失败”计、退避后重试。确认是账号问题时可以开启，避免反复提交。'));
		o.default = '0';

		/* ---- advanced ---- */

		o = s.taboption('advanced', form.Flag, 'dhcp_renew', _('需要地址时让接口续租'),
			_('认证流程要求获取或更新地址时（DHCP 模式 1~3、安朗的定期重拨），执行 ubus call network.interface.<接口> renew。'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'dhcp_script', _('自定义获取地址的命令'),
			_('填写后代替上面的续租，由 sh -c 执行。'));
		o.rmempty = true;

		o = s.taboption('advanced', form.Flag, 'trace', _('记录每个报文'),
			_('在日志里打印收发的每个报文的前 64 字节，排查问题时使用。日志里会出现用户名，不会出现明文密码。'));
		o.default = '0';

		o = s.taboption('advanced', form.DynamicList, 'option', _('其他配置项'),
			_('上面没有列出的认证方式配置项，写成 key=value，原样交给认证程序（整数和 true/false 保持类型，其余按字符串；key="123" 强制为字符串；子表写成 inode.key=value）。配置项的名称见各认证方式的文档；拼错的名称会在日志里有警告。'));
		o.placeholder = 'key=value';
		o.rmempty = true;
		o.validate = function(section_id, value) {
			if (!value)
				return true;

			var m = /^\s*([A-Za-z0-9_-]+)(\.[A-Za-z0-9_-]+)?\s*=/.exec(value);

			if (!m)
				return _('应写成 key=value');

			if (!m[2] && [ 'name', 'interface', 'driver', 'username', 'password', 'password_file', 'dhcp_script',
			               'experimental', 'trace', 'exit_on_reject' ].indexOf(m[1]) > -1)
				return _('%s 不能在这里设置').format(m[1]);

			return true;
		};

		/* ---- service ---- */

		s = m.section(form.NamedSection, 'main', 'gswifi', _('服务'));
		s.addremove = false;

		o = s.option(form.ListValue, 'log_level', _('日志级别'),
			_('日志写入系统日志，可在“日志”页查看。'));
		o.value('error', 'error');
		o.value('warn', 'warn');
		o.value('info', _('info（默认）'));
		o.value('debug', 'debug');
		o.default = 'info';
		o.rmempty = false;

		return m.render();
	}
});
