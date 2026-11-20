# 参与贡献

欢迎提交代码、文档、bug 报告和兼容性反馈。下面是这个项目的约定，提交前请读一遍。

## 先说隐私

- **不要在 Issue、PR 或讨论里贴出账号、密码、学号、手机号、MAC 地址等个人信息。** 贴配置和日志前先把它们删掉或换成 `***`。
- `--trace` 的输出包含完整的认证报文，里面有用户名和由密码算出的摘要，**不要公开贴出**。普通日志（不加 `--trace`）一般就够定位问题。
- 仓库不收录学校的客户端程序、账号或厂商规则，请不要在 Issue 或 PR 里附带这类文件。

## 开发环境

- Rust 1.96.1（和 CI 一致）。
- 提交前在仓库根目录跑：

  ```sh
  cargo fmt --check                                        # rustfmt.toml：120 列
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```

- OpenWrt 打包、在容器里安装测试、nftables 规则校验的本地复现方法见 [`ci/README.md`](ci/README.md) 和 [`openwrt/README.md`](openwrt/README.md)。

## 代码约定

- **每种认证方式一个 crate。** driver 是不碰 I/O 的状态机：只根据收到的报文、定时器和地址变化返回动作（发帧、发 UDP、HTTP 请求、要求 DHCP、结束），不自己开 socket、不读时钟、不执行命令。接口在 [`crates/gswifi-core`](crates/gswifi-core)。
- **802.1X 类的方式**只需实现 `gswifi_eapol::Dialect`，共用 `Supplicant` 状态机；其他方式实现 `gswifi_core::Driver`。
- 新的认证方式要在 [`crates/gswifi/src/registry.rs`](crates/gswifi/src/registry.rs) 注册，并带上测试：编解码的单元测试，加一个用脚本化的假服务器驱动整个会话的测试。
- 解析外部输入（报文、配置、文件）遇到畸形数据要返回错误，**不能 panic**。
- 密码用 `gswifi_core::Secret`，派生出来的凭据也不进日志。
- 面向用户的日志用中文，代码注释用英文。
- 依赖优先用工作区里已有的；路由器存储小，新增依赖请说明理由。

## 验证程度

每种认证方式都标注一个验证程度，由 `DriverInfo::support` 给出：

| 等级 | 含义 |
|---|---|
| `documented` | 按协议资料实现，没有覆盖整个会话的测试数据 |
| `offline-tested` | 编解码和状态机通过了已知正确的测试数据 |
| `lab-tested` | 对模拟或实验室服务器跑通过完整会话 |
| `field-tested` | 在真实校园网上成功使用过 |

- 只有拿得出证据才能提升等级；改到 `field-tested` 需要真实校园网的成功反馈（见下面的兼容性反馈）。
- 低于 `lab-tested` 的方式要求用户显式设置 `experimental = true`，不要绕过这个限制。
- 协议里不确定的字段**不要猜一个值填进去**：让 driver 返回明确的错误或报"不支持"，并把缺口记进 [`docs/gaps.md`](docs/gaps.md)。

## 许可与来源

- 项目采用 MIT 许可。提交贡献即表示你同意以 MIT 许可发布这些代码。
- 不要把 GPL/AGPL 代码（例如 Dogcom）复制进 MIT 的 crate。参考了公开资料的地方，在注释里注明出处。
- 移植自 [mentorust](https://github.com/fuqiuluo/mentorust) 的代码保留原作者的版权声明。

## 提交 PR

- 一个 PR 只做一件事，描述里写清楚改了什么、为什么改、怎么验证的。
- fmt、clippy、test 全部通过；行为有变化时，同步更新 README、`docs/gaps.md` 或 `openwrt/README.md`。
- CI 全绿后才会合并。

## 报告问题

- **Bug**：用"Bug 报告"模板，写清楚版本、平台、复现步骤和（脱敏后的）日志。
- **兼容性反馈**：某种认证方式在你那里能不能用，用"兼容性反馈"模板告诉我们。哪怕只是"能用"，也能帮助把它的验证程度往上提。
