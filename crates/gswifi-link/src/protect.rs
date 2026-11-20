//! Applies a [`gswifi_protect::Plan`]: the platform half of the traffic
//! normalisation (research doc 27.4 — the core only produces a plan, this
//! layer makes the privileged changes).
//!
//! Each step is checked before it is committed: the ruleset goes through
//! `nft -c -f` first, the dnsmasq fragment through `dnsmasq --test`. A
//! failed step leaves the previous state alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use gswifi_protect::{Capabilities, Plan, Sysctl};
use log::{debug, info, warn};

/// Where the generated files go.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The generated nftables file.
    pub nft_file: PathBuf,
    /// Dropped into `/etc/sysctl.d` style directories.
    pub sysctl_file: PathBuf,
    /// dnsmasq's `conf-dir`; `None` leaves DNS alone.
    pub dnsmasq_conf_dir: Option<PathBuf>,
    /// Command that reloads dnsmasq after the fragment changed.
    pub dnsmasq_reload: Option<String>,
    /// The `nft` binary. Services started by procd do not always have
    /// `/usr/sbin` on PATH.
    pub nft_program: PathBuf,
    /// The `dnsmasq` binary, used for `--test`.
    pub dnsmasq_program: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            // NOT /etc/nftables.d: fw4 includes that directory *inside*
            // `table inet fw4 { }`, where a top-level `table` statement is a
            // syntax error that breaks the whole firewall on its next
            // restart. The OpenWrt package registers this file as a
            // `ruleset-post` firewall include instead, so the table comes
            // back after `service firewall restart`.
            nft_file: PathBuf::from("/etc/gswifi/protect.nft"),
            sysctl_file: PathBuf::from("/etc/sysctl.d/30-gswifi-protect.conf"),
            dnsmasq_conf_dir: Some(PathBuf::from("/tmp/dnsmasq.d")),
            dnsmasq_reload: Some("/etc/init.d/dnsmasq reload".into()),
            nft_program: which("nft", "/usr/sbin/nft"),
            dnsmasq_program: which("dnsmasq", "/usr/sbin/dnsmasq"),
        }
    }
}

/// What [`apply`] changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub ruleset: bool,
    pub sysctl: Vec<String>,
    pub dns: bool,
}

/// The usual absolute location if it exists, else the bare name so PATH
/// still applies.
fn which(name: &str, usual: &str) -> PathBuf {
    let usual = PathBuf::from(usual);
    if usual.exists() {
        usual
    } else {
        PathBuf::from(name)
    }
}

fn run(program: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {}: {}", program.display(), e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(format!("{} 失败: {}", program.display(), stderr.trim().lines().next().unwrap_or("未知错误")))
}

/// Reads what this kernel can do (doc 27.5: report what is missing).
pub fn detect_capabilities() -> Capabilities {
    let mut caps = Capabilities::default();
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        if let Some(kernel) = Capabilities::parse_kernel(release.trim()) {
            caps.kernel = kernel;
        }
    }
    caps.ipv6 = Path::new("/proc/net/if_inet6").exists();
    caps
}

fn write_if_changed(path: &Path, content: &str) -> Result<bool, String> {
    if fs::read_to_string(path).is_ok_and(|old| old == content) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("无法创建目录 {}: {}", dir.display(), e))?;
    }
    fs::write(path, content).map_err(|e| format!("无法写入 {}: {}", path.display(), e))?;
    Ok(true)
}

/// Writes the plan and loads it. With `dry_run` the files are written and
/// checked but nothing is committed to the kernel.
///
/// Two phases, so a bad DNS fragment cannot leave half a plan in effect:
/// first everything is written and checked (`nft -c`, `dnsmasq --test`),
/// and only when all checks pass is anything committed.
pub fn apply(plan: &Plan, paths: &Paths, dry_run: bool) -> Result<Applied, String> {
    let mut applied = Applied::default();

    // ---- phase 1: write and check ----

    let nft_before = fs::read_to_string(&paths.nft_file).ok();
    write_if_changed(&paths.nft_file, &plan.ruleset)?;
    let file = paths.nft_file.display().to_string();
    if let Err(e) = run(&paths.nft_program, &["-c", "-f", &file]) {
        // Put the previous file back: fw4 includes this directory on its
        // next restart and must not find a ruleset that does not load.
        restore(&paths.nft_file, nft_before.as_deref());
        return Err(format!("规则检查未通过，没有改动防火墙：{}", e));
    }

    let mut dns_changed = false;
    if let Some(dir) = &paths.dnsmasq_conf_dir {
        let target = dir.join(gswifi_protect::dns::FILE);
        let dns_before = fs::read_to_string(&target).ok();
        dns_changed = match &plan.dns {
            Some(fragment) => write_if_changed(&target, &fragment.content)?,
            None => fs::remove_file(&target).is_ok(),
        };
        if dns_changed && plan.dns.is_some() {
            if let Err(e) = run(&paths.dnsmasq_program, &["--test", "--conf-dir", &dir.display().to_string()]) {
                restore(&target, dns_before.as_deref());
                restore(&paths.nft_file, nft_before.as_deref());
                return Err(format!("dnsmasq 配置检查未通过，没有改动任何设置：{}", e));
            }
        }
    }

    if plan.sysctl.is_empty() {
        let _ = fs::remove_file(&paths.sysctl_file);
    } else {
        write_if_changed(&paths.sysctl_file, &gswifi_protect::sysctl::fragment(&plan.sysctl))?;
    }

    // ---- phase 2: commit ----

    if !dry_run {
        run(&paths.nft_program, &["-f", &file])?;
        applied.ruleset = true;
        debug!("已加载 {}", file);

        for Sysctl { key, value } in &plan.sysctl {
            match write_sysctl(key, value) {
                Ok(()) => applied.sysctl.push(key.clone()),
                // A missing knob is reported, never silently "succeeded".
                Err(e) => warn!("系统参数 {} 未生效：{}", key, e),
            }
        }

        if dns_changed {
            match &paths.dnsmasq_reload {
                Some(cmd) => match Command::new("sh").arg("-c").arg(cmd).status() {
                    Ok(s) if s.success() => applied.dns = true,
                    Ok(s) => warn!("重载 dnsmasq 返回 {:?}", s.code()),
                    Err(e) => warn!("无法重载 dnsmasq: {}", e),
                },
                None => applied.dns = true,
            }
        }
    }

    for skipped in &plan.skipped {
        warn!("未启用 {}：{}", skipped.feature.as_str(), skipped.why);
    }
    info!("{}", plan.summary());
    Ok(applied)
}

/// Puts a file back to what it was before this run (or removes it).
fn restore(path: &Path, before: Option<&str>) {
    let _ = match before {
        Some(content) => fs::write(path, content),
        None => fs::remove_file(path),
    };
}

fn write_sysctl(key: &str, value: &str) -> Result<(), String> {
    let path = PathBuf::from("/proc/sys").join(key.replace('.', "/"));
    if !path.exists() {
        return Err(format!("内核没有 {}", key));
    }
    fs::write(&path, format!("{}\n", value)).map_err(|e| e.to_string())
}

/// Packets and bytes each rule matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counter {
    pub name: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Parses `nft list counters table inet gswifi`.
pub fn parse_counters(text: &str) -> Vec<Counter> {
    let mut out = Vec::new();
    let mut name = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("counter ") {
            name = rest.split_whitespace().next().map(str::to_string);
        } else if let (Some(current), Some(rest)) = (&name, line.strip_prefix("packets ")) {
            let mut parts = rest.split_whitespace();
            let packets = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let bytes = parts.nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            out.push(Counter { name: current.clone(), packets, bytes });
            name = None;
        }
    }
    out
}

/// Current counters, or an error when the table is not loaded.
pub fn counters(nft_program: &Path) -> Result<Vec<Counter>, String> {
    let text = run(
        nft_program,
        &["list", "counters", "table", gswifi_protect::nft::TABLE_FAMILY, gswifi_protect::nft::TABLE_NAME],
    )?;
    Ok(parse_counters(&text))
}

/// Whether the table is currently loaded.
pub fn is_installed(nft_program: &Path) -> bool {
    counters(nft_program).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real output of nft 1.1.1 on OpenWrt 24.10.
    const LISTING: &str = "table inet gswifi {
	counter ttl4 {
		packets 1234 bytes 98765
	}
	counter ipid {
		packets 0 bytes 0
	}
	counter icmp_unreach {
		packets 7 bytes 588
	}
}";

    #[test]
    fn counter_parsing() {
        let c = parse_counters(LISTING);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0], Counter { name: "ttl4".into(), packets: 1234, bytes: 98765 });
        assert_eq!(c[1].packets, 0);
        assert_eq!(c[2], Counter { name: "icmp_unreach".into(), packets: 7, bytes: 588 });
        assert!(parse_counters("").is_empty());
        assert!(parse_counters("garbage\npackets x bytes y").is_empty());
    }

    #[test]
    fn capabilities_are_read_not_guessed() {
        let caps = detect_capabilities();
        // Whatever this machine is, the version has to be plausible.
        assert!(caps.kernel.0 >= 3, "{:?}", caps.kernel);
    }

    #[test]
    fn write_if_changed_is_idempotent() {
        let mut path = std::env::temp_dir();
        path.push(format!("gswifi-protect-test-{}.conf", std::process::id()));
        let _ = fs::remove_file(&path);
        assert!(write_if_changed(&path, "a").unwrap());
        assert!(!write_if_changed(&path, "a").unwrap());
        assert!(write_if_changed(&path, "b").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "b");
        let _ = fs::remove_file(&path);
    }
}
