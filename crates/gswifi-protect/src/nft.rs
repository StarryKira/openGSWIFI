//! Generates the nftables ruleset.
//!
//! Everything lives in one table, `inet gswifi`, that is replaced
//! atomically; fw4's own tables are never touched (doc 27.5). Every rule
//! carries a named counter so `nft list counters table inet gswifi` says
//! how often it fired — in observe mode that is all it does.

use crate::caps::{Capabilities, Feature};
use crate::config::{Config, FailurePolicy, Ipv6Policy, Mode};
use crate::plan::{RuleInfo, Skipped};

/// Name of the table this crate owns, as written in a ruleset.
pub const TABLE: &str = "inet gswifi";
/// Address family of that table, for `nft` command lines.
pub const TABLE_FAMILY: &str = "inet";
/// Bare table name, for `nft` command lines.
pub const TABLE_NAME: &str = "gswifi";

/// `"wan"` or `{ "wan", "wan2" }`.
fn iface_set(names: &[String]) -> String {
    match names {
        [one] => format!("\"{}\"", one),
        many => format!("{{ {} }}", many.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(", ")),
    }
}

/// Collects rules per chain together with their counters.
#[derive(Default)]
struct Builder {
    counters: Vec<&'static str>,
    postrouting: Vec<String>,
    forward: Vec<String>,
    prerouting: Vec<String>,
    rules: Vec<RuleInfo>,
    skipped: Vec<Skipped>,
}

/// Which chain a rule goes into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Chain {
    Postrouting,
    Forward,
    Prerouting,
}

impl Builder {
    /// Adds a rule. `matches` is the match part, `action` what enforce mode
    /// appends after the counter (empty: the rule only counts anyway).
    fn rule(
        &mut self,
        chain: Chain,
        id: &'static str,
        what: impl Into<String>,
        matches: &str,
        action: &str,
        mode: Mode,
    ) {
        self.counters.push(id);
        let mut line = format!("\t\t{} counter name \"{}\"", matches, id);
        if mode == Mode::Enforce && !action.is_empty() {
            line.push(' ');
            line.push_str(action);
        }
        line.push_str(&format!(" comment \"{}\"", id));
        match chain {
            Chain::Postrouting => self.postrouting.push(line),
            Chain::Forward => self.forward.push(line),
            Chain::Prerouting => self.prerouting.push(line),
        }
        self.rules.push(RuleInfo { id, what: what.into() });
    }

    fn skip(&mut self, feature: Feature, why: impl Into<String>) {
        self.skipped.push(Skipped { feature, why: why.into() });
    }

    /// Checks a capability, recording why a feature was left out.
    fn gate(&mut self, caps: &Capabilities, feature: Feature) -> bool {
        if caps.supports(feature) {
            return true;
        }
        let (major, minor) = feature.min_kernel();
        self.skip(
            feature,
            format!("当前内核 {}.{} 不支持，需要 {}.{} 以上", caps.kernel.0, caps.kernel.1, major, minor),
        );
        false
    }
}

/// Builds the ruleset and the rule list. `ipid_offset` is where the IP ID
/// counter starts (random per install, so it does not restart at 0).
pub(crate) fn build(
    config: &Config,
    caps: &Capabilities,
    ipid_offset: u16,
    proxy_listening: bool,
) -> (String, Vec<RuleInfo>, Vec<Skipped>) {
    let mut b = Builder::default();
    let mode = config.mode;
    let wan = iface_set(&config.wan);
    let lan = (!config.lan.is_empty()).then(|| iface_set(&config.lan));
    let out = format!("oifname {}", wan);

    // ---- outgoing packet normalisation ----

    if config.ttl && b.gate(caps, Feature::Ttl) {
        let ttl = config.persona.ttl();
        // Keep low TTLs (traceroute probes) and the 250..255 range
        // (neighbour discovery, VRRP) as they are (doc 26.4).
        let range = if config.preserve_traceroute { "ip ttl > 32 ip ttl < 250" } else { "ip ttl > 32" };
        b.rule(
            Chain::Postrouting,
            "ttl4",
            format!("出口 IPv4 的 TTL 统一为 {}", ttl),
            &format!("{} {}", out, range),
            &format!("ip ttl set {}", ttl),
            mode,
        );
        if config.ipv6 == Ipv6Policy::Normalise && caps.ipv6 {
            let range6 =
                if config.preserve_traceroute { "ip6 hoplimit > 32 ip6 hoplimit < 250" } else { "ip6 hoplimit > 32" };
            b.rule(
                Chain::Postrouting,
                "ttl6",
                format!("出口 IPv6 的 Hop Limit 统一为 {}", ttl),
                &format!("{} {}", out, range6),
                &format!("ip6 hoplimit set {}", ttl),
                mode,
            );
        }
    }

    if config.ipid && b.gate(caps, Feature::Ipid) {
        // Only whole datagrams: rewriting a fragment's ID breaks reassembly
        // (doc 26.5).
        b.rule(
            Chain::Postrouting,
            "ipid",
            "出口 IPv4 的 IP ID 改用一个递增计数（不动分片）",
            &format!("{} ip frag-off & 0x3fff == 0", out),
            &format!("ip id set numgen inc mod 65536 offset {}", ipid_offset),
            mode,
        );
    }

    if config.tcp_timestamps && b.gate(caps, Feature::TcpOptionReset) {
        // Only the SYN: the option is negotiated there, and a timestamp
        // clock is one of the clearest per-device signals.
        b.rule(
            Chain::Postrouting,
            "tsopt",
            "去掉出口 TCP SYN 里的时间戳选项",
            &format!("{} meta l4proto tcp tcp flags & (syn|ack) == syn", out),
            "reset tcp option timestamp",
            mode,
        );
    }

    if config.dscp_ecn && b.gate(caps, Feature::DscpEcn) {
        b.rule(
            Chain::Postrouting,
            "dscp4",
            "清零出口 IPv4 的 DSCP",
            &format!("{} meta nfproto ipv4", out),
            "ip dscp set cs0",
            mode,
        );
        b.rule(
            Chain::Postrouting,
            "ecn4",
            "清零出口 IPv4 的 ECN",
            &format!("{} meta nfproto ipv4", out),
            "ip ecn set not-ect",
            mode,
        );
        if caps.ipv6 {
            b.rule(
                Chain::Postrouting,
                "dscp6",
                "清零出口 IPv6 的 DSCP",
                &format!("{} meta nfproto ipv6", out),
                "ip6 dscp set cs0",
                mode,
            );
        }
    }

    if config.icmp {
        // "Fragmentation needed" must survive or PMTU discovery breaks
        // (doc 27.7 business integrity).
        b.rule(
            Chain::Postrouting,
            "icmp_unreach",
            "不向上行发送 ICMP 目的不可达（保留“需要分片”）",
            &format!("{} icmp type destination-unreachable icmp code != frag-needed", out),
            "drop",
            mode,
        );
        b.rule(
            Chain::Postrouting,
            "icmp_redirect",
            "不向上行发送 ICMP 重定向",
            &format!("{} icmp type redirect", out),
            "drop",
            mode,
        );
    }

    // ---- forwarding policy ----

    if config.ipv6 == Ipv6Policy::Block {
        if let Some(lan) = &lan {
            b.rule(
                Chain::Forward,
                "ipv6_block",
                "拒绝局域网经上行访问 IPv6（应用退回 IPv4）",
                &format!("iifname {} {} meta nfproto ipv6", lan, out),
                "reject with icmpv6 type admin-prohibited",
                mode,
            );
        }
    }

    // ---- redirects ----
    //
    // Observe mode never installs a nat chain: a redirect changes the path
    // even when nothing is rewritten (doc 27.5). The rules are counted in a
    // plain filter chain instead.
    let redirect_chain = if mode == Mode::Enforce { Chain::Prerouting } else { Chain::Postrouting };
    let nat_ok = mode != Mode::Enforce || b.gate(caps, Feature::InetNat);

    if let Some(lan) = &lan {
        if config.dns.take_over && nat_ok {
            b.rule(
                redirect_chain,
                "dns53",
                "接管局域网 53 端口（交给路由器自己的解析器）",
                &format!("iifname {} udp dport 53", lan),
                "redirect to :53",
                mode,
            );
        }
        if config.ntp && nat_ok {
            b.rule(
                redirect_chain,
                "ntp123",
                "接管局域网 123 端口（需要路由器开启 NTP 服务）",
                &format!("iifname {} udp dport 123", lan),
                "redirect to :123",
                mode,
            );
        }
        // The redirect only goes in while the proxy is listening, so a
        // connection is never sent to a dead port (mentorust does the same).
        if config.proxy.enabled && proxy_listening && nat_ok {
            let ports = if config.proxy.http_only { " tcp dport { 80, 8080 }" } else { "" };
            b.rule(
                redirect_chain,
                "proxy_tcp",
                format!(
                    "把局域网{} TCP 重定向到 {} 端口的 User-Agent 代理",
                    if config.proxy.http_only { " HTTP(80/8080)" } else { "全部" },
                    config.proxy.port
                ),
                &format!("iifname {} meta l4proto tcp{}", lan, ports),
                &format!("redirect to :{}", config.proxy.port),
                mode,
            );
        } else if config.proxy.enabled && !proxy_listening && config.failure_policy == FailurePolicy::Block {
            // failure_policy = block: rather than let the traffic this
            // policy owns leave unnormalised, refuse it (doc 27.5).
            let ports = if config.proxy.http_only { " tcp dport { 80, 8080 }" } else { "" };
            b.rule(
                Chain::Forward,
                "proxy_down_block",
                "代理未运行：按 failure_policy = block 阻断本策略拥有的 TCP",
                &format!("iifname {} {} meta l4proto tcp{}", lan, out, ports),
                "reject with tcp reset",
                mode,
            );
        }
    }

    (render(&b, mode, config), b.rules.clone(), b.skipped.clone())
}

fn render(b: &Builder, mode: Mode, config: &Config) -> String {
    let mut s = String::new();
    s.push_str("# Open GSWIFI 流量归一化规则，自动生成，请勿手工编辑。\n");
    s.push_str(&format!("# 模式 {}，伪装类型 {}。\n", mode.as_str(), config.persona.as_str()));
    s.push_str("# 整张表原子替换，不改动 fw4 的其他表。\n");
    if mode == Mode::Observe {
        s.push_str("# 观察模式：只统计命中，不修改报文、不接管端口、不改系统参数。\n");
    }
    // Declare then delete, so the replacement is one transaction whether or
    // not the table already exists.
    s.push_str(&format!("table {}\n", TABLE));
    s.push_str(&format!("delete table {}\n", TABLE));
    s.push_str(&format!("table inet {} {{\n", TABLE_NAME));
    for c in &b.counters {
        s.push_str(&format!("\tcounter {} {{ }}\n", c));
    }
    let chains: [(&str, &str, &Vec<String>); 3] = [
        ("postrouting", "type filter hook postrouting priority mangle; policy accept;", &b.postrouting),
        ("forward", "type filter hook forward priority filter; policy accept;", &b.forward),
        ("prerouting", "type nat hook prerouting priority dstnat; policy accept;", &b.prerouting),
    ];
    for (name, header, rules) in chains {
        if rules.is_empty() {
            continue;
        }
        s.push_str(&format!("\tchain {} {{\n\t\t{}\n", name, header));
        for r in rules {
            s.push_str(r);
            s.push('\n');
        }
        s.push_str("\t}\n");
    }
    s.push_str("}\n");
    s
}

/// The file that removes everything this crate installed.
pub fn uninstall_ruleset() -> String {
    format!("# Open GSWIFI：移除流量归一化规则\ntable {}\ndelete table {}\n", TABLE, TABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_sets() {
        assert_eq!(iface_set(&["wan".into()]), "\"wan\"");
        assert_eq!(iface_set(&["wan".into(), "wan2".into()]), "{ \"wan\", \"wan2\" }");
    }

    #[test]
    fn uninstall_is_atomic_and_scoped() {
        let text = uninstall_ruleset();
        assert!(text.contains("delete table inet gswifi"));
        // Never flush anything global.
        assert!(!text.contains("flush ruleset"));
    }
}
