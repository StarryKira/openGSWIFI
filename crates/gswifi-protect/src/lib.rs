//! Traffic normalisation against campus sharing detection (research docs
//! 07, 26, 27).
//!
//! Campus networks infer how many devices sit behind a router from signals
//! that leak per device: the initial TTL, the IP ID sequence, the TCP
//! timestamp clock, DSCP/ECN, ephemeral port ranges, the HTTP User-Agent
//! and DNS lookups. A NAT router passes those through unchanged, so the
//! traffic of three laptops still looks like three laptops. This crate
//! makes what leaves the upstream interface look like it came from one
//! host.
//!
//! It only normalises your own traffic on your own router, with standard
//! Linux mechanisms (nftables, sysctl, dnsmasq). It is **not** a port of
//! the firmware's private kernel modules: the packet-injection and
//! classification modules (`xt_ob`, `dpimark`) are deliberately left out —
//! they depend on a private kernel ABI, cannot be loaded on another
//! kernel, and their semantics are not recovered (doc 27.6, cleanroom/10).
//!
//! # Shape
//!
//! [`compile`] is a pure function: configuration plus the system's
//! [`Capabilities`] give a [`Plan`] holding an nftables ruleset, sysctl
//! settings and a dnsmasq fragment. Nothing here touches the system — the
//! binary applies the plan (doc 27.4). So the whole generator is testable
//! offline, and the generated ruleset is checked against a real `nft` in
//! the integration test.
//!
//! # Start in observe mode
//!
//! [`Mode::Observe`] installs the same matches with counters only: no
//! packet is changed, no port is taken over, no sysctl is written. Run it
//! first to see that the upstream interface is right and which rules fire
//! (doc 27.6 stage B).

mod caps;
mod config;
pub mod dns;
pub mod nft;
mod plan;
pub mod sysctl;

pub use caps::{Capabilities, Feature};
pub use config::{Config, DnsConfig, FailurePolicy, Ipv6Policy, Mode, Persona, ProxyConfig};
pub use plan::{DnsFragment, Plan, RuleInfo, Skipped, Sysctl};

/// Builds the plan.
///
/// `ipid_offset` is where the IP ID counter starts; pass a random value per
/// install so it does not restart at zero after every reload.
/// `proxy_listening` says whether the User-Agent proxy is accepting
/// connections: the redirect is only installed while it is, so a connection
/// is never sent to a port nobody listens on.
pub fn compile(config: &Config, caps: &Capabilities, ipid_offset: u16, proxy_listening: bool) -> Result<Plan, String> {
    config.validate()?;
    if config.mode == Mode::Disabled {
        return Ok(Plan {
            mode: Mode::Disabled,
            ruleset: nft::uninstall_ruleset(),
            sysctl: Vec::new(),
            dns: None,
            rules: Vec::new(),
            skipped: Vec::new(),
        });
    }
    let (ruleset, rules, skipped) = nft::build(config, caps, ipid_offset, proxy_listening);
    Ok(Plan { mode: config.mode, ruleset, sysctl: sysctl::build(config), dns: dns::build(config), rules, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: Mode) -> Config {
        Config { mode, wan: vec!["wan".into()], lan: vec!["br-lan".into()], ..Config::default() }
    }

    fn plan(config: &Config) -> Plan {
        compile(config, &Capabilities { kernel: (6, 6), ipv6: true }, 0x1234, true).unwrap()
    }

    #[test]
    fn enforce_normalises_the_documented_signals() {
        let p = plan(&config(Mode::Enforce));
        for id in ["ttl4", "ipid", "tsopt", "dscp4", "ecn4", "icmp_unreach", "icmp_redirect"] {
            assert!(p.rule(id).is_some(), "{} missing", id);
        }
        assert!(p.ruleset.contains("ip ttl set 128"));
        assert!(p.ruleset.contains("ip id set numgen inc mod 65536 offset 4660"));
        assert!(p.ruleset.contains("reset tcp option timestamp"));
        // Low TTL and the 250..255 range stay untouched.
        assert!(p.ruleset.contains("ip ttl > 32 ip ttl < 250"));
        // Fragments keep their ID.
        assert!(p.ruleset.contains("ip frag-off & 0x3fff == 0"));
        // "Fragmentation needed" survives.
        assert!(p.ruleset.contains("icmp code != frag-needed"));
        assert_eq!(p.sysctl.len(), 3);
    }

    /// Observe must change nothing at all (doc 27.5).
    #[test]
    fn observe_only_counts() {
        let c = Config {
            dns: DnsConfig { take_over: true, filter_aaaa: true, ..DnsConfig::default() },
            ntp: true,
            proxy: ProxyConfig { enabled: true, port: 1080, http_only: false },
            ..config(Mode::Observe)
        };
        let p = plan(&c);
        assert!(p.sysctl.is_empty());
        assert!(p.dns.is_none());
        // Same matches are present, so the counters are meaningful...
        assert!(p.rule("ttl4").is_some());
        assert!(p.rule("dns53").is_some());
        assert!(p.ruleset.contains("counter name \"ttl4\""));
        // ...but nothing follows the counter on any rule line, so no packet
        // is touched, and there is no nat chain to change a path.
        for line in p.ruleset.lines().filter(|l| l.contains("counter name")) {
            let (before_comment, _) = line.rsplit_once(" comment \"").expect("rule has a comment");
            let id = before_comment.rsplit("counter name \"").next().unwrap().trim_end_matches('"');
            assert!(
                before_comment.ends_with(&format!("counter name \"{}\"", id)),
                "observe mode attached an action: {:?}",
                line
            );
        }
        assert!(!p.ruleset.contains("type nat"));
    }

    #[test]
    fn disabled_removes_everything() {
        let p = plan(&config(Mode::Disabled));
        assert!(p.ruleset.contains("delete table inet gswifi"));
        assert!(p.rules.is_empty());
        assert!(p.sysctl.is_empty());
    }

    #[test]
    fn old_kernels_skip_features_and_say_so() {
        let caps = Capabilities { kernel: (5, 4), ipv6: true };
        let p = compile(&config(Mode::Enforce), &caps, 0, true).unwrap();
        assert!(p.rule("ttl4").is_some(), "TTL works on old kernels");
        assert!(p.rule("ipid").is_none());
        assert!(p.rule("tsopt").is_none());
        let skipped: Vec<_> = p.skipped.iter().map(|s| s.feature).collect();
        assert_eq!(skipped, vec![Feature::Ipid, Feature::TcpOptionReset]);
        assert!(p.skipped[0].why.contains("5.5"));
        assert!(p.summary().contains("跳过 2 项"));
    }

    #[test]
    fn proxy_redirect_only_while_listening() {
        let c = Config { proxy: ProxyConfig { enabled: true, port: 1080, http_only: true }, ..config(Mode::Enforce) };
        let caps = Capabilities::default();
        let up = compile(&c, &caps, 0, true).unwrap();
        assert!(up.ruleset.contains("redirect to :1080"));
        assert!(up.ruleset.contains("tcp dport { 80, 8080 }"));
        // Proxy down with the default bypass policy: traffic flows normally.
        let down = compile(&c, &caps, 0, false).unwrap();
        assert!(!down.ruleset.contains("redirect to :1080"));
        assert!(down.rule("proxy_down_block").is_none());
        // failure_policy = block refuses it instead.
        let blocking = Config { failure_policy: FailurePolicy::Block, ..c };
        let down = compile(&blocking, &caps, 0, false).unwrap();
        assert!(down.rule("proxy_down_block").is_some());
        assert!(down.ruleset.contains("reject with tcp reset"));
    }

    #[test]
    fn ipv6_policies() {
        let forward = plan(&config(Mode::Enforce));
        assert!(forward.rule("ttl6").is_none());
        assert!(forward.rule("ipv6_block").is_none());
        let normalise = plan(&Config { ipv6: Ipv6Policy::Normalise, ..config(Mode::Enforce) });
        assert!(normalise.ruleset.contains("ip6 hoplimit set 128"));
        let block = plan(&Config { ipv6: Ipv6Policy::Block, ..config(Mode::Enforce) });
        assert!(block.ruleset.contains("reject with icmpv6 type admin-prohibited"));
    }

    #[test]
    fn phone_persona() {
        let p = plan(&Config { persona: Persona::Phone, ..config(Mode::Enforce) });
        assert!(p.ruleset.contains("ip ttl set 64"));
        assert!(p.sysctl.iter().any(|s| s.value == "32768 60999"));
    }

    #[test]
    fn several_upstream_interfaces() {
        let c = Config { wan: vec!["wan".into(), "wwan".into()], ..config(Mode::Enforce) };
        assert!(plan(&c).ruleset.contains("oifname { \"wan\", \"wwan\" }"));
    }

    #[test]
    fn invalid_configuration_is_refused() {
        let c = Config { wan: vec![], ..config(Mode::Enforce) };
        assert!(compile(&c, &Capabilities::default(), 0, true).is_err());
    }
}
