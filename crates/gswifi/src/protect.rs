//! `gswifi protect`: builds the traffic-normalisation plan and applies it.

use std::path::PathBuf;

use clap::Subcommand;
use gswifi_link::json::{self, Object};
use gswifi_link::protect::{self, Applied, Paths};
use gswifi_protect::{Capabilities, Config, Mode, Plan};
use log::{error, info, warn};

#[derive(Subcommand)]
pub enum Action {
    /// 打印将要安装的规则（不改动系统）
    Show {
        #[command(flatten)]
        config: Args,
        /// 输出 JSON（规则说明、被跳过的功能及原因、系统参数、规则文本）
        #[arg(long)]
        json: bool,
    },
    /// 检查配置和内核支持，并用 nft -c 校验规则，但不加载
    Check {
        #[command(flatten)]
        config: Args,
    },
    /// 安装规则（建议先用 --mode observe 观察一段时间）
    Install {
        #[command(flatten)]
        config: Args,
        /// 代理正在监听（才安装重定向规则）
        #[arg(long)]
        proxy_listening: bool,
        /// 标准输出改为 JSON：实际装上的计划，或 {"error": "..."}
        #[arg(long)]
        json: bool,
    },
    /// 撤销本程序安装的全部规则、系统参数和 DNS 片段
    Uninstall,
    /// 显示当前状态与每条规则的命中计数
    Status {
        /// 输出 JSON：{"installed": bool, "counters": [{name, packets, bytes}]}
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args)]
pub struct Args {
    /// 配置文件里的 [protect] 段
    #[arg(short, long, default_value = "/etc/gswifi/config.toml")]
    config: String,
    /// 覆盖模式：disabled、observe 或 enforce
    #[arg(long)]
    mode: Option<String>,
    /// nftables 规则文件路径（不要放进 /etc/nftables.d：fw4 会把那里的文件包含在自己的表内部）
    #[arg(long, default_value = "/etc/gswifi/protect.nft")]
    nft_file: PathBuf,
    /// dnsmasq 的 conf-dir；留空则不接管 DNS
    #[arg(long, default_value = "/tmp/dnsmasq.d")]
    dnsmasq_conf_dir: String,
    /// 系统参数文件路径（默认 /etc/sysctl.d/30-gswifi-protect.conf，开机时由系统加载；
    /// 由服务脚本自己在启动时安装的场合可以指向 /var 下的文件，避免停用后残留）
    #[arg(long)]
    sysctl_file: Option<PathBuf>,
}

impl Args {
    fn load(&self) -> Result<Config, String> {
        let text = std::fs::read_to_string(&self.config)
            .map_err(|e| format!("无法读取配置文件 {}: {}", self.config, e))?;
        let mut config = crate::config::parse_protect(&text)?;
        if let Some(mode) = &self.mode {
            config.mode = match mode.as_str() {
                "disabled" => Mode::Disabled,
                "observe" => Mode::Observe,
                "enforce" => Mode::Enforce,
                other => return Err(format!("模式 {:?} 无效，只能是 disabled、observe 或 enforce", other)),
            };
        }
        config.validate()?;
        Ok(config)
    }

    fn paths(&self) -> Paths {
        let defaults = Paths::default();
        Paths {
            nft_file: self.nft_file.clone(),
            dnsmasq_conf_dir: (!self.dnsmasq_conf_dir.is_empty()).then(|| PathBuf::from(&self.dnsmasq_conf_dir)),
            sysctl_file: self.sysctl_file.clone().unwrap_or(defaults.sysctl_file.clone()),
            ..defaults
        }
    }
}

/// A fixed starting point for the IP ID counter per install, so it does not
/// restart at zero on every reload (doc 26.5).
fn ipid_offset() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let pid = std::process::id();
    (nanos ^ pid.rotate_left(13)) as u16
}

fn build(args: &Args, proxy_listening: bool) -> Result<(Plan, Capabilities), String> {
    let config = args.load()?;
    let caps = protect::detect_capabilities();
    let plan = gswifi_protect::compile(&config, &caps, ipid_offset(), proxy_listening)?;
    Ok((plan, caps))
}

/// Whether the capabilities were read from this kernel; elsewhere they are
/// the conservative defaults.
fn kernel_detected() -> bool {
    std::path::Path::new("/proc/sys/kernel/osrelease").exists()
}

/// The plan as JSON, for front ends: every rule with what it does (the
/// rule id is also the name of its counter in `status --json`), what was
/// left out and why, and the files' contents. `applied` is what an install
/// committed.
fn plan_json(plan: &Plan, caps: &Capabilities, applied: Option<&Applied>) -> String {
    let rules = plan.rules.iter().map(|r| Object::new().str("id", r.id).str("what", &r.what).finish());
    let skipped =
        plan.skipped.iter().map(|s| Object::new().str("feature", s.feature.as_str()).str("why", &s.why).finish());
    let sysctl = plan.sysctl.iter().map(|s| Object::new().str("key", &s.key).str("value", &s.value).finish());
    let dns = match &plan.dns {
        Some(d) => Object::new().str("file", &d.file).str("content", &d.content).finish(),
        None => "null".into(),
    };
    let mut o = Object::new()
        .str("mode", plan.mode.as_str())
        .str("summary", &plan.summary())
        .str("kernel", &format!("{}.{}", caps.kernel.0, caps.kernel.1))
        .bool("kernel_detected", kernel_detected())
        .bool("ipv6", caps.ipv6)
        .raw("rules", &json::array(rules))
        .raw("skipped", &json::array(skipped))
        .raw("sysctl", &json::array(sysctl))
        .raw("dns", &dns)
        .str("ruleset", &plan.ruleset);
    if let Some(a) = applied {
        let inner = Object::new()
            .bool("ruleset", a.ruleset)
            .raw("sysctl", &json::array(a.sysctl.iter().map(|k| json::string(k))))
            .bool("dns", a.dns)
            .finish();
        o = o.raw("applied", &inner);
    }
    o.finish()
}

fn counters_json(counters: Option<&[protect::Counter]>) -> String {
    let list = counters.unwrap_or_default().iter().map(|c| {
        // Counters are 64 bit; a JSON number that large loses digits in
        // JavaScript, so they travel as strings.
        Object::new()
            .str("name", &c.name)
            .str("packets", &c.packets.to_string())
            .str("bytes", &c.bytes.to_string())
            .finish()
    });
    Object::new().bool("installed", counters.is_some()).raw("counters", &json::array(list)).finish()
}

fn report(plan: &Plan, caps: &Capabilities) {
    // Say so when the values are the conservative defaults rather than this
    // machine's: generating a plan on a laptop is useful, pretending to have
    // probed its kernel is not.
    let detected = kernel_detected();
    println!(
        "内核 {}.{}，IPv6 {}{}",
        caps.kernel.0,
        caps.kernel.1,
        if caps.ipv6 { "可用" } else { "不可用" },
        if detected { "" } else { "（本机不是 Linux，以上为保守默认值，请在路由器上运行）" }
    );
    println!("{}", plan.summary());
    if plan.mode == Mode::Observe {
        println!("观察模式：只统计命中，不修改任何报文；确认规则和接口无误后再改 enforce。");
    }
    for rule in &plan.rules {
        println!("  {:<18} {}", rule.id, rule.what);
    }
    for skipped in &plan.skipped {
        println!("  跳过 {:<13} {}", skipped.feature.as_str(), skipped.why);
    }
    if !plan.sysctl.is_empty() {
        println!("系统参数（只影响路由器自身的连接）:");
        for s in &plan.sysctl {
            println!("  {} = {}", s.key, s.value);
        }
    }
    if let Some(dns) = &plan.dns {
        println!("DNS 片段 {}（{} 行）", dns.file, dns.content.lines().count());
    }
}

pub fn run(action: Action) -> i32 {
    match action {
        Action::Show { config, json: true } => match build(&config, true) {
            Ok((plan, caps)) => {
                println!("{}", plan_json(&plan, &caps, None));
                0
            }
            Err(e) => fail_json(e),
        },
        Action::Show { config, json: false } => match build(&config, true) {
            Ok((plan, caps)) => {
                report(&plan, &caps);
                println!("\n{}", plan.ruleset);
                0
            }
            Err(e) => fail(e),
        },
        Action::Check { config } => match build(&config, true) {
            Ok((plan, caps)) => {
                report(&plan, &caps);
                match protect::apply(&plan, &config.paths(), true) {
                    Ok(_) => {
                        println!("规则检查通过（未加载）。");
                        0
                    }
                    Err(e) => fail(e),
                }
            }
            Err(e) => fail(e),
        },
        Action::Install { config, proxy_listening, json } => {
            let fail = if json { fail_json } else { fail };
            match build(&config, proxy_listening) {
                Ok((plan, caps)) => {
                    if !json {
                        report(&plan, &caps);
                    }
                    if plan.mode == Mode::Enforce {
                        warn!("enforce 模式会修改出口报文；如果学校网络出现异常，用 gswifi protect uninstall 撤销");
                    }
                    match protect::apply(&plan, &config.paths(), false) {
                        Ok(applied) => {
                            info!("已安装：规则 {}，系统参数 {} 项，DNS {}", applied.ruleset, applied.sysctl.len(), applied.dns);
                            if json {
                                println!("{}", plan_json(&plan, &caps, Some(&applied)));
                            }
                            0
                        }
                        Err(e) => fail(e),
                    }
                }
                Err(e) => fail(e),
            }
        }
        Action::Uninstall => {
            let caps = protect::detect_capabilities();
            let plan = match gswifi_protect::compile(&Config::default(), &caps, 0, false) {
                Ok(p) => p,
                Err(e) => return fail(e),
            };
            match protect::apply(&plan, &Paths::default(), false) {
                Ok(_) => {
                    info!("已撤销全部规则、系统参数和 DNS 片段");
                    0
                }
                Err(e) => fail(e),
            }
        }
        Action::Status { json: true } => {
            let counters = protect::counters(&Paths::default().nft_program).ok();
            println!("{}", counters_json(counters.as_deref()));
            if counters.is_some() {
                0
            } else {
                1
            }
        }
        Action::Status { json: false } => match protect::counters(&Paths::default().nft_program) {
            Ok(counters) if counters.is_empty() => {
                println!("已安装，但没有任何规则。");
                0
            }
            Ok(counters) => {
                println!("{:<18} {:>12} {:>14}", "规则", "命中报文", "字节");
                for c in &counters {
                    println!("{:<18} {:>12} {:>14}", c.name, c.packets, c.bytes);
                }
                println!("\n注：计数在每次重新加载规则后清零。");
                0
            }
            Err(_) => {
                println!("未安装（没有 inet gswifi 表）。");
                1
            }
        },
    }
}

fn fail(e: String) -> i32 {
    error!("{}", e);
    1
}

/// Like [`fail`], and also says so on standard output where a `--json`
/// caller is reading.
fn fail_json(e: String) -> i32 {
    println!("{}", Object::new().str("error", &e).finish());
    fail(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gswifi_protect::Config;

    fn plan(mode: Mode, kernel: (u32, u32)) -> (Plan, Capabilities) {
        let config = Config { mode, wan: vec!["wan".into()], lan: vec!["br-lan".into()], ..Config::default() };
        let caps = Capabilities { kernel, ipv6: true };
        (gswifi_protect::compile(&config, &caps, 7, false).unwrap(), caps)
    }

    #[test]
    fn plan_json_names_rules_and_skipped_features() {
        let (p, caps) = plan(Mode::Enforce, (5, 4));
        let text = plan_json(&p, &caps, None);
        assert!(text.starts_with(r#"{"mode":"enforce","summary":""#), "{}", text);
        assert!(text.contains(r#""kernel":"5.4""#));
        assert!(text.contains(r#"{"id":"ttl4","what":"出口 IPv4 的 TTL 统一为 128"}"#), "{}", text);
        // Kernel 5.4 has neither: both must be listed with the reason, not dropped.
        assert!(text.contains(r#"{"feature":"ipid","why":"当前内核 5.4 不支持，需要 5.5 以上"}"#), "{}", text);
        assert!(text.contains(r#""feature":"tcp-timestamps""#));
        assert!(text.contains(r#"{"key":"net.ipv4.ip_default_ttl","value":"128"}"#));
        assert!(text.contains(r#""dns":null"#));
        // The ruleset is one string: its quotes, tabs and newlines are escaped.
        assert!(text.contains(r#"table inet gswifi {\n\tcounter ttl4 { }\n"#), "{}", text);
        assert!(text.contains(r#"oifname \"wan\""#));
        assert!(!text.contains('\n') && !text.contains('\t'));
        assert!(!text.contains(r#""applied""#));

        let applied = Applied { ruleset: true, sysctl: vec!["net.ipv4.ip_default_ttl".into()], dns: false };
        let text = plan_json(&p, &caps, Some(&applied));
        assert!(text.ends_with(r#","applied":{"ruleset":true,"sysctl":["net.ipv4.ip_default_ttl"],"dns":false}}"#), "{}", text);
    }

    #[test]
    fn observe_and_disabled_plans() {
        let (p, caps) = plan(Mode::Observe, (6, 6));
        let text = plan_json(&p, &caps, None);
        assert!(text.contains(r#""mode":"observe""#) && text.contains(r#""sysctl":[]"#) && text.contains(r#""skipped":[]"#));
        let (p, caps) = plan(Mode::Disabled, (6, 6));
        let text = plan_json(&p, &caps, None);
        assert!(text.contains(r#""mode":"disabled""#) && text.contains(r#""rules":[]"#), "{}", text);
    }

    #[test]
    fn counters_json_shape() {
        assert_eq!(counters_json(None), r#"{"installed":false,"counters":[]}"#);
        assert_eq!(counters_json(Some(&[])), r#"{"installed":true,"counters":[]}"#);
        let c = [protect::Counter { name: "ttl4".into(), packets: u64::MAX, bytes: 98765 }];
        assert_eq!(
            counters_json(Some(&c)),
            r#"{"installed":true,"counters":[{"name":"ttl4","packets":"18446744073709551615","bytes":"98765"}]}"#
        );
    }
}
