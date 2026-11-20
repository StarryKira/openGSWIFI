//! Generates every interesting ruleset variant and, when an `nft` binary
//! is available, has it parse them (`nft -c -f`).
//!
//! On a machine without nftables (macOS, a build host) the variants are
//! still written out, so they can be checked elsewhere:
//!
//! ```sh
//! GSWIFI_NFT_DUMP=/tmp/nft cargo test -p gswifi-protect --test nft_syntax
//! docker run --rm --cap-add NET_ADMIN -v /tmp/nft:/w:ro openwrt \
//!     sh -c 'for f in /w/*.nft; do nft -c -f $f || echo "FAIL $f"; done'
//! ```

use std::path::PathBuf;
use std::process::Command;

use gswifi_protect::*;

/// Every variant worth parsing, as (name, config).
fn variants() -> Vec<(&'static str, Config)> {
    let base = Config {
        mode: Mode::Enforce,
        wan: vec!["wan".into()],
        lan: vec!["br-lan".into()],
        ..Config::default()
    };
    let full_dns = DnsConfig {
        take_over: true,
        blocked_domains: vec!["telemetry.example".into()],
        local_arpa: true,
        filter_aaaa: true,
    };
    vec![
        ("disabled", Config { mode: Mode::Disabled, ..base.clone() }),
        ("observe", Config { mode: Mode::Observe, ..base.clone() }),
        ("enforce-defaults", base.clone()),
        ("enforce-phone", Config { persona: Persona::Phone, ..base.clone() }),
        ("enforce-no-traceroute", Config { preserve_traceroute: false, ..base.clone() }),
        ("enforce-multi-wan", Config { wan: vec!["wan".into(), "wwan".into()], ..base.clone() }),
        ("enforce-ipv6-normalise", Config { ipv6: Ipv6Policy::Normalise, ..base.clone() }),
        ("enforce-ipv6-block", Config { ipv6: Ipv6Policy::Block, ..base.clone() }),
        ("enforce-dns-ntp", Config { dns: full_dns.clone(), ntp: true, ..base.clone() }),
        (
            "enforce-proxy-all",
            Config { proxy: ProxyConfig { enabled: true, port: 1080, http_only: false }, ..base.clone() },
        ),
        (
            "enforce-proxy-http",
            Config { proxy: ProxyConfig { enabled: true, port: 1080, http_only: true }, ..base.clone() },
        ),
        (
            "enforce-everything",
            Config {
                ipv6: Ipv6Policy::Block,
                dns: full_dns,
                ntp: true,
                proxy: ProxyConfig { enabled: true, port: 1080, http_only: false },
                failure_policy: FailurePolicy::Block,
                ..base.clone()
            },
        ),
        ("observe-everything", Config { mode: Mode::Observe, ntp: true, ..base }),
    ]
}

fn nft_binary() -> Option<PathBuf> {
    ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"].iter().map(PathBuf::from).find(|p| p.exists())
}

#[test]
fn every_variant_is_valid_nftables() {
    let caps = Capabilities { kernel: (6, 6), ipv6: true };
    let dump = std::env::var_os("GSWIFI_NFT_DUMP").map(PathBuf::from);
    if let Some(dir) = &dump {
        std::fs::create_dir_all(dir).expect("create dump directory");
    }
    let nft = nft_binary();
    let mut checked = 0;

    for (name, config) in variants() {
        // Both proxy states, so the failure-policy variant is covered too.
        for (suffix, listening) in [("", true), ("-proxy-down", false)] {
            if !suffix.is_empty() && !config.proxy.enabled {
                continue;
            }
            let plan = compile(&config, &caps, 0x4321, listening).expect(name);
            let file = format!("{}{}.nft", name, suffix);

            // Invariants that hold for every variant.
            assert!(plan.ruleset.contains("delete table inet gswifi"), "{}: not an atomic replace", file);
            assert!(!plan.ruleset.contains("flush ruleset"), "{}: would wipe other tables", file);
            assert_eq!(plan.ruleset.matches("table inet gswifi {").count(), usize::from(config.mode != Mode::Disabled));

            if let Some(dir) = &dump {
                std::fs::write(dir.join(&file), &plan.ruleset).expect("write variant");
            }
            if let Some(nft) = &nft {
                let mut tmp = std::env::temp_dir();
                tmp.push(format!("gswifi-{}", file));
                std::fs::write(&tmp, &plan.ruleset).expect("write temp ruleset");
                let out = Command::new(nft).arg("-c").arg("-f").arg(&tmp).output().expect("run nft");
                let _ = std::fs::remove_file(&tmp);
                assert!(
                    out.status.success(),
                    "{} rejected by nft:\n{}\n--- ruleset ---\n{}",
                    file,
                    String::from_utf8_lossy(&out.stderr),
                    plan.ruleset
                );
                checked += 1;
            }
        }
    }
    if nft.is_none() {
        eprintln!("note: no nft binary here, only generated the variants (set GSWIFI_NFT_DUMP to keep them)");
    } else {
        assert!(checked >= 14);
    }
}
