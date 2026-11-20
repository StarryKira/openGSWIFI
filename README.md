# Open GSWIFI

开源的多协议校园网认证客户端。目标是用可维护、可离线测试的独立实现，覆盖 GSWIFI 路由器固件里出现的各种校园网认证方式；每种认证方式是一个单独的 crate。

- 锐捷、赛尔、标准 802.1X 和 User-Agent 透明代理移植自 [fuqiuluo](https://github.com/fuqiuluo) 的 [mentorust](https://github.com/fuqiuluo/mentorust) 及其 OpenWrt 版本 [mentorust-for-OPENWRT](https://github.com/StarryKira/mentorust-for-OPENWRT)，行为与 mentorust 一致；
- 其余协议按 `campus-auth-research` 研究文档（文中“doc NN”即第 NN 篇）和按提供商重组的 cleanroom 规格（“cleanroom/NN”）净室实现，用其中的黄金向量做单元测试。

> **验证程度**：每个认证方式都标注 `documented` / `offline-tested` / `lab-tested` / `field-tested`（doc 09.9）。离线测试通过不代表能在真实校园网认证成功。低于 `lab-tested` 的方式需要在配置里写 `experimental = true` 才会启用。

## 认证方式

| `driver` | crate | 认证方式 | 传输 | 验证程度 | 说明 |
|---|---|---|---|---|---|
| `ruijie` | `gswifi-ruijie` | 锐捷 802.1X | EAPOL | field-tested | 来自 mentorust：modern/classic/V4 扩展、`data_file` 客户端校验（V2/V3）、带密钥的 EAPOL 心跳、实验性 UDP 心跳；StartMode 0 遇到“User name”自动切换赛尔 |
| `saier` | `gswifi-saier` | 赛尔 802.1X | EAPOL | offline-tested | 加盐 MD5、固定 Identity 格式、type 6 保活（doc 21.2、25.3） |
| `eap-md5` | `gswifi-eap-md5` | 标准 802.1X | EAPOL | field-tested | RFC 3748 EAP-MD5，无厂商扩展（mentorust `--ext-format none`） |
| `inode` | `gswifi-inode` | H3C iNode 802.1X（MentoHUST AuthType 1） | EAPOL | documented | 版本混淆、VIF 解码、上传 IP/版本、在线查询原地应答；在线保活内容未知 |
| `h3c-portal` | `gswifi-h3c-portal` | H3C Portal（AuthType 2） | UDP | offline-tested | 发现→登录→挑战→在线→下线，五类 130→131 校验，TEA 类密码块变换；整条 doc 29 会话逐字节回放 |
| `anlang` | `gswifi-anlang` | 安朗 UDP（atclient） | UDP | offline-tested | 位重排+MD5 封包、发现/服务/登录/计数心跳；另有安朗 802.1X 用户名格式函数 `eap_username` |
| `drcom` | `gswifi-drcom` | Dr.com 城市热点（Dogcom D/P） | UDP 61440 | documented | `mode = "dhcp"`/`"pppoe"`；GS 的 D/X/P/Pt 变体和 DrMode≠0 会在启动时报不支持，不会静默换协议 |
| `netkeeper` | `gswifi-netkeeper` | NetKeeper/闪讯 PPPoE 拨号账号 | PPPoE | offline-tested | nk_version 1–13 经典 getPIN、14 海南；用 `gswifi pppoe-username` 计算后交给 pppd。15（重庆 4.x）、99（桌面导入）、SRun、四川、江苏会报不支持 |
<!-- PORTAL-ROWS -->

以下 GSWIFI 固件里有、但这里**还没有实现**：Portal Relay 与网页插件（doc 06）、Dr.com X/Pt 与 GS 专有分支、安朗 802.1X 的完整会话、NetKeeper 15/99 与 SRun/四川/江苏拨号、私有内核模块（doc 16）。每个协议还缺哪些研究材料见 [`docs/gaps.md`](docs/gaps.md)。

## 架构

```
crates/
  gswifi-core        Driver 接口：driver 是纯状态机，只返回 Action，不碰 socket/时钟/命令
  gswifi-eapol       802.1X 帧 + 通用会话状态机（Start→Identity→MD5→Success→心跳，重发/重连/DHCP 模式）
  gswifi-ruijie      锐捷 Dialect（modern/classic/V4 扩展、V2/V3 客户端校验、EAPOL/UDP 心跳）
  gswifi-saier       赛尔 Dialect
  gswifi-eap-md5     标准 EAP-MD5 Dialect
  gswifi-inode       iNode Dialect 与版本/VIF/密码原语
  gswifi-h3c-portal  H3C Portal driver 与编解码
  gswifi-anlang      安朗 UDP driver 与编解码
  gswifi-drcom       Dr.com driver、原语与 GS 控制包
  gswifi-netkeeper   NetKeeper/闪讯 拨号账号派生
  gswifi-portal      湖北/云南网页 Portal
  gswifi-link        运行时：网卡信息、pcap 收发 802.1X、UDP socket、HTTP、DHCP 脚本、事件循环
  gswifi-protect     防共享检测：生成 nftables/sysctl/DNS 计划（纯函数，不碰系统）
  gswifi-proxy       透明代理，统一 HTTP User-Agent（防检测，来自 mentorust）
  gswifi             命令行程序
vendor/pcap          mentorust 修改过的 libpcap 绑定（32 位 musl 的 pcap_pkthdr 布局）
openwrt/             OpenWrt 包：gswifi（procd/UCI/fw4）与 luci-app-gswifi
ci/  .github/        打包、安装测试与 GitHub Actions
linux/               deb/rpm 用的 systemd 单元与示例配置
```

Driver API 按 doc 09.3 设计：

```rust
pub trait Driver: Send {
    fn requirements(&self) -> Requirements;          // 需要的 EtherType / UDP 端口 / 是否先要 IPv4
    fn start(&mut self, now: Instant) -> Vec<Action>;
    fn on_frame(&mut self, frame: &[u8], now: Instant) -> Vec<Action>;
    fn on_datagram(&mut self, d: Datagram, now: Instant) -> Vec<Action>;
    fn on_timer(&mut self, now: Instant) -> Vec<Action>;
    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action>;
    fn next_deadline(&self) -> Option<Instant>;
    fn logoff(&mut self, now: Instant) -> Vec<Action>;
    fn state(&self) -> AuthState;
}
// Action = SendFrame | SendUdp | Http | RequestDhcp | Stop(Finished | ServerNotFound | Rejected | GaveUp | Fatal)
```

802.1X 家族共用 `gswifi_eapol::Supplicant<D: Dialect>`，各厂商只实现 `Dialect`（Start/Identity/MD5 应答怎么构造、Success 里取什么、心跳和下线帧）。因此协议代码都能用合成报文离线测试，换 OpenWrt ubus/netifd 也不用动协议。

## 使用

```sh
cargo build --release -p gswifi

gswifi drivers                                   # 列出认证方式和验证程度
gswifi auth -d ruijie -i eth0 -u 学号 -p 密码      # 单网卡
gswifi auth -d ruijie -i eth0 -u 学号 -o ext_format=classic -o start_mode=1   # 密码可放在 GSWIFI_PASSWORD
gswifi example-config > /etc/gswifi/config.toml
gswifi run -c /etc/gswifi/config.toml            # 多网卡，每个 [[networks]] 一个线程
gswifi proxy --port 1080 --ua 'Mozilla/5.0 ...'  # 透明代理（Linux）
gswifi pppoe-username -v 4 -u 账号               # NetKeeper/闪讯 拨号账号（C 字符串，可写进 pppd 的 user "..."）

# 防共享检测（先观察，再启用）
gswifi protect show      -c /etc/gswifi/config.toml   # 只打印将要安装的规则
gswifi protect check     -c /etc/gswifi/config.toml   # 用 nft -c 校验但不加载
gswifi protect install   -c /etc/gswifi/config.toml --mode observe
gswifi protect status                                 # 每条规则的命中计数
gswifi protect uninstall                              # 撤销全部改动
```

低于 `lab-tested` 的方式要加 `experimental = true`（命令行 `--experimental`）。UDP 类方式的配置项见各 crate 的 `Options` 文档，例如安朗的 `server`(`sip`)、`service`(`stype`)，Dr.com 的 `server`、`mode`、`auth_version`、`keep_alive_version`，H3C Portal 的 `portal_ip`、`plain_password` 和 `[inode]` 子表。

配置文件里 `name`、`interface`、`driver`、`username`、`password`/`password_file`、`dhcp_script`、`experimental`、`trace` 由运行时读取，其余键交给认证方式（拼错的键会有警告）。802.1X 共用的键：`timeout`、`echo_interval`、`restart_wait`、`max_retries`、`dhcp_mode`、`gateway`、`dns`；锐捷另有 `start_mode`、`pkt_type`、`ext_format`、`client_version`、`check_version`、`data_file`、`udp_heartbeat`，含义与 mentorust 的同名参数相同。

被明确拒绝（802.1X 的 EAP-Failure、Dr.com 写明账号问题的错误码）时不会在同一地址上反复重试，以免账号被锁；原因不明的拒绝（安朗、H3C Portal、Dr.com 的“已在别处登录”等）按可重试处理，退避有上限（cleanroom gaps.md 的约定）。会话被拒绝或放弃后，`gswifi` 会等网卡地址或 MAC 变化再重新认证；要像 mentorust 那样直接退出，设 `exit_on_reject = true`（命令行 `--exit-on-reject`），退出码：0 正常下线，2 用户名/扩展校验被拒，3 密码/MAC 绑定被拒，4 重试次数用完，255 找不到认证服务器，1 配置或运行错误。

环境变量：`RUST_LOG`（日志级别，默认 info）；锐捷 modern 格式沿用 mentorust 的 `EAPOL_SERVICE`、`EAPOL_HDD_SER`、`EAPOL_ENABLE_DHCP`。

## 防共享检测

校园网会从每台设备都会泄露的特征推断你后面接了几台机器：初始 TTL、IP ID 序列、TCP 时间戳时钟、DSCP/ECN、临时端口范围、HTTP User-Agent、DNS 查询。NAT 不会改这些，所以三台笔记本看起来还是三台。`gswifi-protect` 把上行接口发出去的报文统一成一台主机的样子。

它只用标准 Linux 机制（nftables、sysctl、dnsmasq）处理你自己路由器上的流量。固件里的私有内核模块（`xt_ob` 改包注入、`dpimark` 流分类）**没有移植**：它们依赖私有内核 ABI、不能在别的内核上加载，语义也没有还原完（doc 27.6、cleanroom/10）。

`gswifi-protect` 是纯函数：配置 + 内核能力 → 计划（nftables 规则文本、sysctl、dnsmasq 片段），自己不碰系统；由 `gswifi-link::protect` 负责落盘和加载。所以规则生成全部可以离线测试，集成测试还会把生成的 16 种规则变体交给真正的 `nft -c` 解析。

| 特征 | 做法 | 要求 |
|---|---|---|
| TTL / Hop Limit | 出口统一为 128（`persona = "pc"`）或 64（`"phone"`）；默认保留 TTL ≤ 32 的 traceroute 探测和 250..255（邻居发现、VRRP） | |
| IP ID | 出口 IPv4 改用一个从随机值开始的递增计数；分片不动，避免破坏重组 | 内核 5.5 |
| TCP 时间戳 | 去掉出口 SYN 里的时间戳选项；路由器自身连接关 `tcp_timestamps` | 内核 5.18 |
| DSCP / ECN | 出口清零 | |
| ICMP | 不向上行发目的不可达（**保留“需要分片”**，否则 PMTU 会坏）和重定向 | |
| 源端口 | 路由器自身连接用 Windows 或 Android 的临时端口范围 | |
| IPv6 | `forward` 照常转发 / `normalise` 一并统一 Hop Limit / `block` 拒绝局域网经上行走 IPv6 | |
| DNS | 可选接管局域网 53；可选 `filter-aaaa`、反向解析只在本机回答；**屏蔽域名列表由你自己填，本程序不内置** | |
| NTP | 可选接管局域网 123 | 路由器开 NTP 服务 |
| User-Agent | 可选，把局域网 TCP 重定向到 `gswifi proxy` | |

几条设计上的硬规矩：

- **先用 `mode = "observe"`**。观察模式装上同样的匹配，但只计数：不改报文、不接管端口、不写 sysctl、不建 nat 链。`gswifi protect status` 会按规则列出命中数，确认上行接口选对了、哪些规则真会用上，再改 `enforce`。规则每次重新加载后计数从零开始。
- 所有规则都在单独的 `inet gswifi` 表里**整表原子替换**，不动 fw4 的任何东西；卸载只删这张表，绝不 `flush ruleset`。
- 加载前先过 `nft -c`，dnsmasq 片段先过 `dnsmasq --test`；任何一步不过就保留原状，片段会被撤回。
- 内核不支持的功能（IP ID、去时间戳选项）会被**跳过并说明原因**，不会装上去再假装成功。
- 透明代理的重定向只在代理真的在监听时才装（`--proxy-listening`），否则连接不会被送进没人监听的端口；`failure_policy = "block"` 时改为拒绝这部分流量而不是让它裸奔。

已知限制：防火墙开启软/硬件流量分载时，被分载的连接只有开头几个报文经过这些规则；路由器开 GRO 时合并报文在出口重新分段，各段 IPID 由内核依次加一，可能与下一个报文重叠；HTTPS/HTTP-2/QUIC 的内容是加密的，User-Agent 既看不到也改不了，TLS 握手特征仍来自各设备。这些在 doc 26.5、26.9 里都有说明。

## OpenWrt

两个包：`gswifi`（认证程序、procd 服务、UCI 配置 `/etc/config/gswifi`，按 CPU 家族分 x86_64 / aarch64 / armv7）和 `luci-app-gswifi`（网页界面：服务 → 校园网认证，所有架构通用）。在发布页下载与路由器架构对应的 gswifi 包和 luci-app-gswifi：

```sh
# OpenWrt 23.05 / 24.10
opkg update
opkg install /tmp/gswifi_<版本>_<家族>.ipk /tmp/luci-app-gswifi_<版本>_all.ipk
# OpenWrt 25.12 及以后
apk update
apk add --allow-untrusted /tmp/gswifi_<版本>_<家族>.apk /tmp/luci-app-gswifi_<版本>_all.apk
```

每个网络是一个 procd 实例；密码只写进 `/var` 下权限 0600 的配置文件，不出现在进程列表和日志里；服务器明确拒绝后不会反复重试。防共享检测默认关闭，规则作为 firewall4 的顶层 include 安装，防火墙重启后仍然生效，卸载时连同内核参数一起撤销。NetKeeper/闪讯只提供拨号用户名计算器，没有接入 pppd。详见 [`openwrt/README.md`](openwrt/README.md)。

网页界面在 OpenWrt 24.10 上用 luci-theme-bootstrap（亮/暗）、luci-theme-argon 3.1.4（亮/暗）和 luci-theme-aurora 1.4.0（亮/暗）检查过桌面和手机宽度（390 px）的显示。安装包在 OpenWrt 23.05、24.10（ipk）和 25.12（apk）的官方 rootfs 里做过安装测试；没有在真实路由器和真实校园网上验证。

## 持续集成与发布

每次推送到 `main`、每个 PR 和每个 `v*` 标签都会运行 `.github/workflows/ci.yml`：检查脚本与 LuCI、`cargo fmt`/clippy、单元测试，用 OpenWrt 23.05/24.10/25.12 自带的 `nft -c` 校验生成的全部 nftables 规则，然后用 cross 构建 x86_64、aarch64、armv7 三种全静态（musl + 静态 libpcap）可执行文件，打成 ipk/apk（在官方 OpenWrt rootfs 里安装测试）和 deb/rpm（在 Debian、Ubuntu、Fedora、Rocky 里安装测试）。mipsel（MT7621）是实验性构建，失败不影响其余任务。每个阶段都能在本机用 Docker 复现，见 [`ci/README.md`](ci/README.md)。

构建产物在 Actions 运行页面的 Artifacts 里：`build-<架构>`（可执行文件和 tar.gz）、`packages-ipk`、`packages-apk`、`packages-linux`；可执行文件的大小写在对应 build 任务的摘要里。

发布新版本：

1. 修改 `Cargo.toml` 里 `[workspace.package]` 的 `version`，运行一次 `cargo build` 让 `Cargo.lock` 跟上，提交并推送到 `main`，等 CI 通过；
2. 打标签并推送：`git tag v0.1.0 && git push origin v0.1.0`。标签必须是 `v` 加 Cargo 版本号，否则 CI 在构建之前就会失败。

标签的 CI 全部通过后会自动创建 GitHub Release，附带三种架构的 tar.gz、ipk、apk、deb、rpm、`SHA256SUMS` 和安装说明（哪个 OpenWrt 版本和架构用哪个包）。带连字符的版本（如 `v0.2.0-rc1`）会发布为预发布版本。

## 开发

```sh
cargo fmt --check                    # rustfmt.toml：120 列
cargo test --workspace
cargo clippy --workspace
cargo check --target x86_64-unknown-linux-musl -p gswifi   # OpenWrt 目标的类型检查

# 把生成的 nftables 规则交给真正的 nft 校验（没有 nft 时只导出文件）
GSWIFI_NFT_DUMP=/tmp/nft cargo test -p gswifi-protect --test nft_syntax
docker run --rm --cap-add NET_ADMIN -v /tmp/nft:/w:ro openwrt \
    sh -c 'for f in /w/*.nft; do nft -c -f "$f" || echo "FAIL $f"; done'
```

真正链接 OpenWrt 目标需要对应架构的静态 libpcap，可沿用 mentorust 的 `Cross.toml` 和 `ci/build-libpcap.sh`。

## 参与贡献

欢迎提交代码、文档、bug 报告，以及"某种认证方式在你那里能不能用"的兼容性反馈。约定和流程见 [CONTRIBUTING.md](CONTRIBUTING.md)；提问前可以先看看 [`docs/gaps.md`](docs/gaps.md) 里是否已经记录。

## 许可

MIT。锐捷/赛尔/EAP-MD5/代理代码来自 [fuqiuluo](https://github.com/fuqiuluo) 的 [mentorust](https://github.com/fuqiuluo/mentorust)（MIT），保留原版权声明，见 [LICENSE](LICENSE)。Dr.com 部分没有复制 AGPLv3 的 Dogcom 代码，按研究文档的报文布局独立实现。仓库不包含学校客户端文件、账号或厂商规则；锐捷校验的测试材料是研究包里的合成文件。
