# OpenWrt 软件包

两个包：

| 包 | 内容 |
|---|---|
| `gswifi` | 认证程序 `/usr/bin/gswifi`（静态链接）、procd 服务、UCI 配置 `/etc/config/gswifi`、生成配置和管理防共享检测规则的脚本 |
| `luci-app-gswifi` | 网页界面（服务 → 校园网认证）：概览、认证设置、防共享检测、日志、工具 |

发布用的 ipk/apk 由 `ci/package.sh` 用 CI 编好的静态程序打包（每个 CPU 家族一个 `gswifi` 包，装到别的家族的路由器上会被拒绝）；`gswifi/Makefile`、`luci-app-gswifi/Makefile` 供 OpenWrt SDK / buildroot 从源码编译，装的文件和位置与 `package.sh` 相同。

## 安装后有哪些文件

```
/usr/bin/gswifi
/etc/config/gswifi                          UCI 配置（唯一的配置来源，0600）
/etc/init.d/gswifi                          procd 服务
/usr/libexec/gswifi/ctl                     ucode：生成配置、状态 JSON、诊断（LuCI 后端也调用它）
/usr/libexec/gswifi/gswifi-auth             等网卡出现且有链路后 exec gswifi run
/usr/libexec/gswifi/gswifi-proxy            运行 gswifi proxy，监听后/退出时重新应用规则
/usr/libexec/gswifi/protect                 apply [force] | remove（加锁后调用 ctl）
/usr/share/ucode/gswifi/*.uc                上面几个脚本共用的 ucode 模块
/usr/share/nftables.d/ruleset-post/90-gswifi.nft    fw4 的顶层 include
/usr/libexec/rpcd/luci.gswifi               rpcd 插件（ubus 对象 luci.gswifi）

运行时（tmpfs，不写闪存）：
/var/etc/gswifi/net.<id>.toml               每个网络生成的 TOML，含密码，0600，目录 0700
/var/etc/gswifi/protect.toml                [protect] 段
/var/run/gswifi/status/<id>.json            会话状态（gswifi run --status-dir 写入，不含密码）
/var/run/gswifi/protect.nft / protect.json  生成的规则、最近一次应用的结果
```

## UCI

```
config gswifi 'main'
	option log_level 'info'            # error | warn | info | debug

config network 'campus'                # 节名就是网络名：字母、数字、下划线
	option enabled '1'
	option driver 'ruijie'             # gswifi drivers 列出的名字
	option interface 'wan'             # netifd 接口；802.1X 用它底层的网卡，其余用三层设备（pppoe-wan）
	option device ''                   # 直接指定内核网卡，优先于 interface
	option username '…'
	option password '…'
	option experimental '0'            # 低于 lab-tested 的认证方式必须为 1
	option trace '0'
	option dhcp_renew '1'              # 需要地址时 ubus call network.interface.<interface> renew
	option dhcp_script ''              # 自定义获取地址的命令，代替上一项
	list option 'key=value'            # 界面没有列出的认证方式配置项（整数/true/false 保持类型）
	# 其余选项与程序的配置项同名，按所选 driver 的类型写进 TOML，
	# 例如 ruijie 的 ext_format、start_mode、client_version、data_file，
	# 802.1X 共用的 dhcp_mode、timeout、restart_wait、max_retries，
	# anlang 的 server、service、retry_on_reject，drcom 的 server、mode、auth_version…
	# 锐捷 modern 格式的三项走环境变量：service、hdd_ser、eapol_dhcp。

config protect 'protect'
	option mode 'disabled'             # disabled | observe | enforce
	option persona 'pc'                # pc | phone
	list wan 'wan'                     # netifd 接口，解析成三层设备
	list lan 'lan'
	list wan_device ''                 # 不归 netifd 管的网卡（可选）
	list lan_device ''
	option ttl '1'
	option preserve_traceroute '1'
	option ipid '1'
	option tcp_timestamps '1'
	option dscp_ecn '1'
	option icmp '1'
	option source_ports '1'
	option ipv6 'forward'              # forward | normalise | block
	option ntp '0'
	option failure_policy 'bypass'     # bypass | block
	option dns_take_over '0'
	option dns_filter_aaaa '0'
	option dns_local_arpa '0'
	list dns_blocked_domain ''         # 由你自己填，不内置任何列表
	option proxy '0'
	option proxy_port '1080'
	option proxy_http_only '1'
	option proxy_ua ''
	list proxy_strip_header ''
```

## 服务怎么工作

- 每个 `enabled` 且填了账号的网络是一个 procd 实例（实例名 = 节名），另有可选的 `proxy` 实例。`start`/`reload` 时 `ctl networks` 用 ucode 读 UCI、按认证方式的类型表把每个值编码成 TOML（字符串统一转义，布尔值严格解析，`"0"` 是假），写到 `/var/etc/gswifi/net.<id>.toml`（0600）。值从不拼进 shell 命令；密码只在这个文件里，不出现在进程列表、procd 参数或日志中。
- procd 按文件内容判断实例要不要重启：改一个网络或防共享检测页，不会让其他网络掉线。接口事件（例如 PPPoE 拨上后出现 `pppoe-wan`）会触发 reload。
- **被拒绝之后**：`gswifi run` 在服务器明确拒绝（密码错误、MAC 绑定不符）后不会退出，而是等网卡地址或 MAC 变化再试一次，所以错误的密码每个地址只发一次。procd 只在配置错误或崩溃时看到进程退出，最多重启 5 次、间隔 30 秒（`respawn 3600 30 5`）。服务从不设置 `exit_on_reject`（`list option` 也不能设置它），因为那会把一次拒绝变成 procd 的重启循环。服务器一直没有应答时 802.1X 默认无限重试（`max_retries -1`），这期间只发寻找服务器的报文，不发账号密码。在 LuCI 里点“重新认证”只重启那一个实例。
- 状态不从日志里猜：`gswifi run --status-dir` 在每次状态变化时原子地写 `/var/run/gswifi/status/<id>.json`（状态、认证方式和验证程度、网卡、地址、尝试/成功次数、拒绝阶段和原因、最近的日志/警告/服务器消息，时间同时记录开机秒数，不受 NTP 跳变影响）。`ctl status` 把它和 procd 的实例信息、UCI 合成一份 JSON。

## 防共享检测与 firewall4

`gswifi protect install` 生成的规则文件以 `table inet gswifi` 开头。fw4 把 `/etc/nftables.d/*.nft` 包含在 `table inet fw4 { }` **里面**，放进去会让整个防火墙在下次重启时加载失败，所以这里用 fw4 的 `ruleset-post` 位置：`/usr/share/nftables.d/ruleset-post/90-gswifi.nft` 只有一行 `include "/var/run/gswifi/protect.nf[t]"`（方括号让路径成为通配，文件不存在时 nft 不报错）。

- 服务每次 start/reload 都按 UCI 重新应用（`protect apply`，加锁）；没有变化时不重装，计数不清零。规则文件和 sysctl 片段都在 `/var` 下，开机或停用服务后不残留。
- 加载前由程序做 `nft -c`、`dnsmasq --test`；加载后再对整个防火墙跑 `fw4 check`，不通过且确认是这些规则造成的就撤回。dnsmasq 的 conf-dir 从它生成的配置里读取（24.10 起是 `/tmp/dnsmasq.cfgXXXX.d`），片段变化时重启 dnsmasq。
- enforce 改动的内核参数先记下原值，模式改回或服务停止时恢复。
- User-Agent 代理的重定向只在 `gswifi proxy` 真的在监听时安装：`gswifi-proxy` 在程序回调“已监听”后重新应用规则，程序退出（任何原因）后先撤掉重定向再交给 procd 重启。
- 停止服务、卸载软件包都会删除 `inet gswifi` 表、DNS 片段并恢复内核参数；include 文件随包删除。`restart` 和关机不撤规则。

在 OpenWrt 24.10.8（aarch64 容器，带 procd/fw4）里验证过：observe/enforce/disabled 切换，`fw4 check`、`fw4 restart`、`fw4 reload`、`/etc/init.d/firewall restart` 后 fw4 和 `inet gswifi` 两张表都在，代理被杀后重定向消失、重启后恢复，DNS 片段生效（`nslookup` 得到 0.0.0.0）后又被撤回，sysctl 恢复原值。

## LuCI

视图都是客户端 JS（`form.Map` 等），后端是 ucode 写的 rpcd 插件，只调用 `ctl`，参数在 `ctl` 里校验，不经 shell 解释。

- **认证方式的验证程度来自程序本身**（`gswifi drivers --json`）。低于 lab-tested 的方式要勾选“允许使用实验性认证方式”才能保存为启用，概览页一直显示警告；不能运行会话的（NetKeeper、未闭合的 Portal）不出现在选择里。“在线保活”对未验证的方式显示“未验证”/“未知（未验证）”（iNode）。
- **防共享检测默认关闭**，页面引导先用观察模式（从关闭直接改启用时会弹窗建议改用观察），显示每条规则的实时命中计数、被内核跳过的功能及原因、流量分载的影响，任何地方都不说“能过检测”。
- **NetKeeper/闪讯** 没有接入 netifd/pppd：工具页只是用户名计算器（显示有效期倒计时），要实际拨号需要自己在拨号脚本里调用 `gswifi pppoe-username`。
- **主题**：只用标准的 LuCI 类（`cbi-section`、`table`/`td[data-title]`、`btn cbi-button-*`）和少量自带样式。自带样式不写死前景/背景色：线条和底色由继承的文字颜色（`currentColor`）经 `color-mix()` 得出，状态色只以半透明底色或与文字颜色混合的方式出现，所以不依赖主题怎样标记暗色模式（bootstrap/aurora 用 `data-darkmode`，argon 用 `data-argon-mode`）。卡片式主题给标题加了内边距而不给区块加，自带内容的左右内边距在运行时取自同一区块标题的计算样式。

## 本地测试

```sh
# 打包（ipk 需要 GNU tar；apk 需要 apk-tools 3 的 apk mkpkg，在 Alpine 里跑）
version=$(sh ci/version.sh | sed -n 's/^version=//p')
sh ci/package.sh ipk "$version" bin packages
docker run --rm -v "$PWD:/src" -w /src alpine:3.24 sh ci/package.sh apk "$version" bin packages

# 在 OpenWrt rootfs 里安装并测试（CI 的做法，没有 init；不能用 netlink 时跳过规则的实装）
docker run --rm -v "$PWD/packages:/pkgs:ro" -v "$PWD/ci:/ci:ro" \
    "$(sh ci/openwrt-rootfs.sh 24.10.8)" sh /ci/openwrt-test.sh ipk /pkgs
# 加 --cap-add NET_ADMIN 会真正安装规则：fw4 check、fw4 restart 后表还在、卸载后表被删；
# 加 --privileged 还会检查 enforce 写入并恢复的 sysctl。

node ci/check-luci.js openwrt/luci-app-gswifi
sh ci/lint-shell.sh
```

要看网页和真正的 procd 服务，用带 init 的容器：

```sh
docker run -d --name gswifi-dev --privileged -p 127.0.0.1:18080:80 openwrt-arm:24.10.8 /sbin/init
docker cp packages/gswifi_*_aarch64.ipk gswifi-dev:/tmp/ && docker cp packages/luci-app-gswifi_*_all.ipk gswifi-dev:/tmp/
docker exec gswifi-dev sh -c 'opkg install /tmp/*.ipk && passwd root'
# 浏览器打开 http://127.0.0.1:18080/ → 服务 → 校园网认证
```

容器里没有校园网，会话只会停在“正在寻找认证服务器”。完整的 802.1X 状态流转（在线、被拒绝后不再重试、换地址后重试一次）是用 veth 对上的一个测试用认证器验证的，它不在仓库里。

## 与 mentorust 打包的不同

- mentorust 只有锐捷一个协议、一个账号，由一个 shell 守护进程（supervisor）解析程序的日志文字来判断状态、决定重试。这里每个网络一个 procd 实例，重试策略在程序里，状态由程序写成 JSON，shell 不再解析日志。
- 密码不再通过命令行参数传给程序（mentorust 的 `--password=` 会出现在 `ps` 里），而是写进 0600 的 TOML；配置由 ucode 生成并做类型检查。
- 日志进系统日志（logread），不再自己维护 `/var/log/*.log` 和截断。
- 新增防共享检测（fw4 顶层 include、观察模式、计数、代理联动）。
- rpcd 插件和 ctl 用 ucode 写（mentorust 用 sh + jshn）。
- 包文件名不带 `-r<release>`（`gswifi_<version>_<family>.ipk`），与发布说明一致；版本字段里仍是 `<version>-r1`。

## 没有验证的

- `gswifi/Makefile`、`luci-app-gswifi/Makefile` 没有在 OpenWrt SDK 里实际编译过（发布包不走它们）。
- 只在容器里跑过，没有在真实路由器、真实校园网上跑过；MIPS 没有包。
- 防共享检测对任何学校的检测是否有效，没有任何验证。
