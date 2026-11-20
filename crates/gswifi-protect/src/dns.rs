//! dnsmasq configuration fragment.
//!
//! This crate ships **no** built-in domain list. The firmware's list is a
//! snapshot of telemetry and connectivity-check endpoints that goes stale
//! and silently breaks captive-portal detection (doc 26.9 warns it is not
//! an application database). Give your own domains in
//! [`DnsConfig::blocked_domains`](crate::DnsConfig::blocked_domains).
//!
//! The fragment goes into dnsmasq's `conf-dir`, so the user's own
//! configuration is kept; check it with `dnsmasq --test` before reloading
//! (doc 27.5).

use crate::config::{Config, Mode};
use crate::plan::DnsFragment;

/// File name inside dnsmasq's conf-dir.
pub const FILE: &str = "gswifi-protect.conf";

/// `None` unless the mode is enforce and something is configured.
pub(crate) fn build(config: &Config) -> Option<DnsFragment> {
    let dns = &config.dns;
    if config.mode != Mode::Enforce || (!dns.filter_aaaa && !dns.local_arpa && dns.blocked_domains.is_empty()) {
        return None;
    }
    let mut s = String::from("# Open GSWIFI 流量归一化，自动生成，请勿手工编辑。\n");
    if dns.filter_aaaa {
        s.push_str("# 过滤 AAAA 记录：让客户端留在 IPv4。这不等于阻断 IPv6（doc 26.9）。\n");
        // Upstream spelling since dnsmasq 2.87 (OpenWrt 23.05+). The older
        // OpenWrt-only patch spelled it `filter-aaaa`; such a dnsmasq
        // rejects this line in `--test` and the fragment is withdrawn.
        s.push_str("filter-AAAA\n");
    }
    if dns.local_arpa {
        s.push_str("# 反向解析和 ipv4only.arpa 只在本机回答，不上送。\n");
        for zone in ["in-addr.arpa", "ip6.arpa", "ipv4only.arpa"] {
            s.push_str(&format!("server=/{}/\n", zone));
        }
    }
    if !dns.blocked_domains.is_empty() {
        s.push_str("# 配置里指定的域名，回答 0.0.0.0。\n");
        for domain in &dns.blocked_domains {
            s.push_str(&format!("address=/{}/0.0.0.0\n", domain));
        }
    }
    Some(DnsFragment { file: FILE.into(), content: s })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsConfig;

    fn config(dns: DnsConfig, mode: Mode) -> Config {
        Config { mode, wan: vec!["wan".into()], lan: vec!["br-lan".into()], dns, ..Config::default() }
    }

    #[test]
    fn nothing_configured_means_no_fragment() {
        assert!(build(&config(DnsConfig::default(), Mode::Enforce)).is_none());
    }

    #[test]
    fn observe_writes_nothing() {
        let dns = DnsConfig { filter_aaaa: true, ..DnsConfig::default() };
        assert!(build(&config(dns, Mode::Observe)).is_none());
    }

    #[test]
    fn fragment_contents() {
        let dns = DnsConfig {
            take_over: true,
            filter_aaaa: true,
            local_arpa: true,
            blocked_domains: vec!["telemetry.example".into(), "a.b.example".into()],
        };
        let f = build(&config(dns, Mode::Enforce)).unwrap();
        assert_eq!(f.file, "gswifi-protect.conf");
        assert!(f.content.contains("filter-AAAA\n"));
        assert!(f.content.contains("server=/ipv4only.arpa/\n"));
        assert!(f.content.contains("address=/telemetry.example/0.0.0.0\n"));
        assert!(f.content.contains("address=/a.b.example/0.0.0.0\n"));
        // No list of our own.
        assert_eq!(f.content.matches("address=/").count(), 2);
    }
}
