//! What the running kernel can do (doc 27.5: report missing capabilities,
//! never write a rule and then claim it worked).

use serde::Deserialize;

/// A part of the plan that the kernel has to support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    /// Rewriting TTL / hop limit in the mangle hook.
    Ttl,
    /// `ip id set numgen …`.
    Ipid,
    /// `reset tcp option timestamp`.
    TcpOptionReset,
    /// `ip dscp set` / `ip ecn set`.
    DscpEcn,
    /// nat chains in an inet table (DNS/NTP/proxy redirects).
    InetNat,
}

impl Feature {
    /// Lowest kernel that has it. The nftables expressions were added in
    /// these releases; OpenWrt 22.03 ships 5.10, 23.05 ships 5.15,
    /// 24.10 ships 6.6.
    pub fn min_kernel(self) -> (u32, u32) {
        match self {
            Feature::Ttl => (3, 13),
            Feature::DscpEcn => (3, 13),
            // nat in inet tables.
            Feature::InetNat => (4, 18),
            // `numgen` plus a writable IP id.
            Feature::Ipid => (5, 5),
            // Removing a TCP option on the fly.
            Feature::TcpOptionReset => (5, 18),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Feature::Ttl => "ttl",
            Feature::Ipid => "ipid",
            Feature::TcpOptionReset => "tcp-timestamps",
            Feature::DscpEcn => "dscp-ecn",
            Feature::InetNat => "inet-nat",
        }
    }
}

/// Capabilities of the system the plan will run on.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default)]
pub struct Capabilities {
    /// Kernel version, major and minor.
    pub kernel: (u32, u32),
    /// IPv6 is available at all.
    pub ipv6: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        // OpenWrt 22.03, the oldest release with firewall4/nftables.
        Capabilities { kernel: (5, 10), ipv6: true }
    }
}

impl Capabilities {
    pub fn supports(&self, feature: Feature) -> bool {
        self.kernel >= feature.min_kernel()
    }

    /// Parses `uname -r` output (`6.6.73`, `5.15.167-1-foo`).
    pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
        let mut parts = release.split(['.', '-', '+']);
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some((major, minor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_parsing() {
        assert_eq!(Capabilities::parse_kernel("6.6.73"), Some((6, 6)));
        assert_eq!(Capabilities::parse_kernel("5.15.167-1-ab"), Some((5, 15)));
        assert_eq!(Capabilities::parse_kernel("5.10"), Some((5, 10)));
        assert_eq!(Capabilities::parse_kernel("linux"), None);
        assert_eq!(Capabilities::parse_kernel(""), None);
    }

    #[test]
    fn gates() {
        let old = Capabilities { kernel: (5, 4), ipv6: true };
        assert!(old.supports(Feature::Ttl));
        assert!(!old.supports(Feature::Ipid));
        assert!(!old.supports(Feature::TcpOptionReset));
        let new = Capabilities { kernel: (6, 6), ipv6: true };
        assert!(Feature::Ipid.min_kernel() < Feature::TcpOptionReset.min_kernel());
        assert!(new.supports(Feature::TcpOptionReset));
    }
}
