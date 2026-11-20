//! The compiled plan: what would be installed, and what was left out.

use crate::caps::Feature;
use crate::config::Mode;

/// One installed rule, so a status page can name what a counter counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    /// Stable identifier, also the nftables counter name.
    pub id: &'static str,
    /// What it does, in the user's language.
    pub what: String,
}

/// A part of the configuration that is not in the plan, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub feature: Feature,
    pub why: String,
}

/// A `key = value` for `/etc/sysctl.d`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sysctl {
    pub key: String,
    pub value: String,
}

/// A dnsmasq configuration fragment, written into its `conf-dir`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsFragment {
    /// File name inside the conf-dir (not a full path).
    pub file: String,
    pub content: String,
}

/// Everything the platform layer has to apply. Pure data: this crate never
/// writes a file or runs a command (doc 27.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub mode: Mode,
    /// Complete nftables file that atomically replaces the table.
    pub ruleset: String,
    /// Empty in observe mode.
    pub sysctl: Vec<Sysctl>,
    /// `None` in observe mode or when DNS is not configured.
    pub dns: Option<DnsFragment>,
    pub rules: Vec<RuleInfo>,
    pub skipped: Vec<Skipped>,
}

impl Plan {
    /// A short human summary for the CLI and the log.
    pub fn summary(&self) -> String {
        let mut out = format!("模式 {}，{} 条规则", self.mode.as_str(), self.rules.len());
        if !self.sysctl.is_empty() {
            out.push_str(&format!("，{} 项系统参数", self.sysctl.len()));
        }
        if self.dns.is_some() {
            out.push_str("，DNS 片段");
        }
        if !self.skipped.is_empty() {
            out.push_str(&format!("；跳过 {} 项（内核不支持或未启用）", self.skipped.len()));
        }
        out
    }

    pub fn rule(&self, id: &str) -> Option<&RuleInfo> {
        self.rules.iter().find(|r| r.id == id)
    }
}
