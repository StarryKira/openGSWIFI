//! Tests the platform layer with a stub `nft`/`dnsmasq` on PATH, so the
//! order of operations is checked without touching a real firewall:
//! the ruleset must be validated before it is committed, and a rejected
//! DNS fragment must be taken back out.

use std::fs;
use std::path::{Path, PathBuf};

use gswifi_link::protect::{self, Paths};
use gswifi_protect::{Capabilities, Config, DnsConfig, Mode};

struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    /// Creates a temp directory holding stub `nft` and `dnsmasq` programs
    /// that log their arguments. Nothing global is touched, so the tests
    /// still run in parallel.
    fn new(name: &str, nft_script: &str, dnsmasq_script: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("gswifi-apply-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        let log = dir.join("calls.log");
        for (program, body) in [("nft", nft_script), ("dnsmasq", dnsmasq_script)] {
            let path = dir.join("bin").join(program);
            let script = format!("#!/bin/sh\necho \"{} $*\" >> '{}'\n{}\n", program, log.display(), body);
            fs::write(&path, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        Sandbox { dir }
    }

    fn paths(&self) -> Paths {
        Paths {
            nft_file: self.dir.join("rules.nft"),
            sysctl_file: self.dir.join("sysctl.conf"),
            dnsmasq_conf_dir: Some(self.dir.join("dnsmasq.d")),
            // Never run an init script from a test.
            dnsmasq_reload: None,
            nft_program: self.dir.join("bin/nft"),
            dnsmasq_program: self.dir.join("bin/dnsmasq"),
        }
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
    }

    fn dns_fragment(&self) -> PathBuf {
        self.dir.join("dnsmasq.d").join(gswifi_protect::dns::FILE)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn plan(mode: Mode, dns: DnsConfig) -> gswifi_protect::Plan {
    let config = Config { mode, wan: vec!["wan".into()], lan: vec!["br-lan".into()], dns, ..Config::default() };
    gswifi_protect::compile(&config, &Capabilities { kernel: (6, 6), ipv6: true }, 1, false).unwrap()
}

#[test]
fn checks_the_ruleset_before_committing_it() {
    let s = Sandbox::new("ok", "exit 0", "exit 0");
    let plan = plan(Mode::Enforce, DnsConfig::default());
    let applied = protect::apply(&plan, &s.paths(), false).expect("apply");
    assert!(applied.ruleset);
    let calls = s.calls();
    let check = calls.find("nft -c -f").expect("ruleset was checked");
    let commit = calls.find("nft -f").expect("ruleset was committed");
    assert!(check < commit, "committed before checking:\n{}", calls);
    assert!(Path::new(&s.paths().nft_file).exists());
}

#[test]
fn a_rejected_ruleset_is_never_committed() {
    // Fail only the check (`-c`), succeed otherwise.
    let s = Sandbox::new("bad", "case \"$1\" in -c) echo 'bad rule' >&2; exit 1;; esac\nexit 0", "exit 0");
    let err = protect::apply(&plan(Mode::Enforce, DnsConfig::default()), &s.paths(), false).unwrap_err();
    assert!(err.contains("规则检查未通过"), "{}", err);
    assert!(!s.calls().contains("nft -f"), "committed anyway:\n{}", s.calls());
}

#[test]
fn dry_run_checks_but_changes_nothing() {
    let s = Sandbox::new("dry", "exit 0", "exit 0");
    let applied = protect::apply(&plan(Mode::Enforce, DnsConfig::default()), &s.paths(), true).unwrap();
    assert!(!applied.ruleset);
    assert!(s.calls().contains("nft -c -f"));
    assert!(!s.calls().lines().any(|l| l.starts_with("nft -f")), "{}", s.calls());
}

/// Found on a real OpenWrt 24.10: dnsmasq refused the fragment after the
/// ruleset was already loaded. Nothing may be committed in that case.
#[test]
fn a_rejected_dns_fragment_commits_nothing() {
    let s = Sandbox::new("dns", "exit 0", "echo 'bad option' >&2; exit 1");
    let dns =
        DnsConfig { filter_aaaa: true, blocked_domains: vec!["telemetry.example".into()], ..DnsConfig::default() };
    let err = protect::apply(&plan(Mode::Enforce, dns), &s.paths(), false).unwrap_err();
    assert!(err.contains("dnsmasq"), "{}", err);
    assert!(!s.dns_fragment().exists(), "the bad fragment was left behind");
    assert!(!s.calls().lines().any(|l| l.starts_with("nft -f")), "ruleset committed anyway:\n{}", s.calls());
    assert!(!s.paths().nft_file.exists(), "the unloaded ruleset file was left for fw4 to include");
}

/// A failed check restores the files of the plan that is in effect.
#[test]
fn a_failed_check_restores_the_previous_files() {
    let s = Sandbox::new("restore", "exit 0", "exit 0");
    let dns = DnsConfig { filter_aaaa: true, ..DnsConfig::default() };
    protect::apply(&plan(Mode::Enforce, dns.clone()), &s.paths(), false).unwrap();
    let rules = fs::read_to_string(s.paths().nft_file).unwrap();
    let fragment = fs::read_to_string(s.dns_fragment()).unwrap();

    // Same sandbox paths, but now dnsmasq rejects the new fragment.
    fs::write(s.dir.join("bin/dnsmasq"), "#!/bin/sh\nexit 1\n").unwrap();
    let changed = DnsConfig { blocked_domains: vec!["new.example".into()], ..dns };
    let other = Config {
        mode: Mode::Enforce,
        wan: vec!["wan9".into()],
        lan: vec!["br-lan".into()],
        dns: changed,
        ..Config::default()
    };
    let other = gswifi_protect::compile(&other, &Capabilities { kernel: (6, 6), ipv6: true }, 1, false).unwrap();
    assert!(protect::apply(&other, &s.paths(), false).is_err());
    assert_eq!(fs::read_to_string(s.paths().nft_file).unwrap(), rules);
    assert_eq!(fs::read_to_string(s.dns_fragment()).unwrap(), fragment);
}

#[test]
fn observe_writes_no_sysctl_or_dns() {
    let s = Sandbox::new("observe", "exit 0", "exit 0");
    let dns = DnsConfig { filter_aaaa: true, ..DnsConfig::default() };
    let applied = protect::apply(&plan(Mode::Observe, dns), &s.paths(), false).unwrap();
    assert!(applied.sysctl.is_empty());
    assert!(!applied.dns);
    assert!(!s.paths().sysctl_file.exists());
    assert!(!s.dns_fragment().exists());
}

#[test]
fn uninstall_removes_the_files_it_wrote() {
    let s = Sandbox::new("uninstall", "exit 0", "exit 0");
    let dns = DnsConfig { filter_aaaa: true, ..DnsConfig::default() };
    protect::apply(&plan(Mode::Enforce, dns), &s.paths(), false).unwrap();
    assert!(s.paths().sysctl_file.exists());
    assert!(s.dns_fragment().exists());

    let off = plan(Mode::Disabled, DnsConfig::default());
    protect::apply(&off, &s.paths(), false).unwrap();
    assert!(!s.paths().sysctl_file.exists(), "sysctl fragment left behind");
    assert!(!s.dns_fragment().exists(), "dns fragment left behind");
    assert!(s.calls().contains("nft -f"), "the delete-table ruleset was not loaded");
}
