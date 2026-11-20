//! Configuration of the traffic normalisation (research doc 27.5).

use serde::Deserialize;

/// How much of the plan is applied (doc 27.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Nothing is installed.
    #[default]
    Disabled,
    /// The same matches are installed, but they only count: no packet is
    /// changed, no port is taken over, no sysctl is written. Use this first
    /// to see which rules would fire.
    Observe,
    /// Packets are normalised.
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Disabled => "disabled",
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
        }
    }
}

/// Which kind of device the upstream should see (doc 4 persona matrix).
/// This only picks consistent values; it does not make the router *be* that
/// device, and nothing here touches TLS or application level fingerprints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Persona {
    /// TTL 128, Windows ephemeral port range.
    #[default]
    Pc,
    /// TTL 64, Android/Linux ephemeral port range.
    Phone,
}

impl Persona {
    /// Initial TTL / hop limit this persona claims.
    pub fn ttl(self) -> u8 {
        match self {
            Persona::Pc => 128,
            Persona::Phone => 64,
        }
    }

    /// Ephemeral source port range of the router's own connections.
    pub fn port_range(self) -> (u16, u16) {
        match self {
            Persona::Pc => (49152, 65534),
            Persona::Phone => (32768, 60999),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Persona::Pc => "pc",
            Persona::Phone => "phone",
        }
    }
}

/// What LAN clients may do over IPv6 (doc 26.9: an IPv4 policy does not
/// cover IPv6, and filtering AAAA is not the same as blocking IPv6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Policy {
    /// Forward IPv6 unchanged; the normalisation below does not cover it.
    #[default]
    Forward,
    /// Normalise the hop limit like IPv4's TTL.
    Normalise,
    /// Refuse LAN → upstream IPv6, so applications fall back to IPv4.
    Block,
}

/// What happens when a part of the plan cannot run (doc 27.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailurePolicy {
    /// Traffic keeps flowing on the normal path.
    #[default]
    Bypass,
    /// Traffic this policy owns is dropped instead of leaving unnormalised.
    Block,
}

/// Optional DNS handling. The domain lists are yours: this crate ships no
/// built-in blocklist (doc 26.9 warns the firmware's list is not a complete
/// application database, and a stale list breaks connectivity checks).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Redirect LAN port 53 to the router's own resolver.
    pub take_over: bool,
    /// Answer these domains with 0.0.0.0 (telemetry, VoWiFi gateways, …).
    pub blocked_domains: Vec<String>,
    /// Answer reverse lookups and `ipv4only.arpa` locally instead of
    /// forwarding them upstream.
    pub local_arpa: bool,
    /// Drop AAAA answers so clients stay on IPv4. Not a substitute for
    /// [`Ipv6Policy::Block`] (doc 26.9).
    pub filter_aaaa: bool,
}

/// The optional User-Agent proxy (`gswifi proxy`, the crate `gswifi-proxy`).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Redirect LAN TCP to the proxy. The rules are only installed while
    /// the proxy is listening (`gswifi protect proxy-up`).
    pub enabled: bool,
    /// Port the proxy listens on.
    pub port: u16,
    /// Only redirect plain HTTP (80, 8080) instead of all TCP.
    pub http_only: bool,
}

/// Everything the plan is built from.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: Mode,
    pub persona: Persona,
    /// Upstream interfaces the normalisation applies to.
    pub wan: Vec<String>,
    /// LAN interfaces clients arrive on (DNS/NTP/proxy redirects).
    pub lan: Vec<String>,
    /// Give every outgoing packet this persona's TTL / hop limit.
    pub ttl: bool,
    /// Keep TTL ≤ 32 and ≥ 250 as they are, so traceroute still works and
    /// neighbour discovery / VRRP are untouched (doc 26.4).
    pub preserve_traceroute: bool,
    /// Give outgoing IPv4 packets one shared, increasing IP ID.
    pub ipid: bool,
    /// Remove the TCP timestamp option from outgoing SYNs.
    pub tcp_timestamps: bool,
    /// Clear DSCP and ECN on the way out.
    pub dscp_ecn: bool,
    /// Do not send ICMP destination-unreachable (except "fragmentation
    /// needed") or redirects upstream.
    pub icmp: bool,
    /// Use the persona's ephemeral port range for the router's own
    /// connections.
    pub source_ports: bool,
    pub ipv6: Ipv6Policy,
    pub dns: DnsConfig,
    /// Redirect LAN port 123 to the router's own NTP server.
    pub ntp: bool,
    pub proxy: ProxyConfig,
    pub failure_policy: FailurePolicy,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Disabled,
            persona: Persona::Pc,
            wan: Vec::new(),
            lan: Vec::new(),
            ttl: true,
            preserve_traceroute: true,
            ipid: true,
            tcp_timestamps: true,
            dscp_ecn: true,
            icmp: true,
            source_ports: true,
            ipv6: Ipv6Policy::Forward,
            dns: DnsConfig::default(),
            ntp: false,
            proxy: ProxyConfig::default(),
            failure_policy: FailurePolicy::Bypass,
        }
    }
}

/// An interface name safe to put in a quoted nftables string.
fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15 && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
}

/// A domain safe to put in a dnsmasq fragment.
pub(crate) fn valid_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && name.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

impl Config {
    /// Rejects what cannot be compiled into a safe plan. Interface names
    /// and domains are checked because they end up in generated files
    /// (doc 27.4: never paste user configuration into a shell).
    pub fn validate(&self) -> Result<(), String> {
        if self.mode == Mode::Disabled {
            return Ok(());
        }
        if self.wan.is_empty() {
            return Err("需要至少一个上行接口（wan）".into());
        }
        for name in self.wan.iter().chain(&self.lan) {
            if !valid_interface(name) {
                return Err(format!("接口名 {:?} 无效", name));
            }
        }
        if let Some(both) = self.wan.iter().find(|w| self.lan.contains(w)) {
            return Err(format!("接口 {:?} 不能既是上行又是局域网", both));
        }
        let needs_lan = self.dns.take_over || self.ntp || self.proxy.enabled || self.ipv6 == Ipv6Policy::Block;
        if needs_lan && self.lan.is_empty() {
            return Err("DNS/NTP/代理接管和阻断 IPv6 需要指定局域网接口（lan）".into());
        }
        for d in &self.dns.blocked_domains {
            if !valid_domain(d) {
                return Err(format!("域名 {:?} 无效", d));
            }
        }
        if self.proxy.enabled && self.proxy.port == 0 {
            return Err("代理端口不能为 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcing() -> Config {
        Config { mode: Mode::Enforce, wan: vec!["wan".into()], lan: vec!["br-lan".into()], ..Config::default() }
    }

    #[test]
    fn personas_are_consistent() {
        assert_eq!((Persona::Pc.ttl(), Persona::Pc.port_range()), (128, (49152, 65534)));
        assert_eq!((Persona::Phone.ttl(), Persona::Phone.port_range()), (64, (32768, 60999)));
    }

    #[test]
    fn validation() {
        assert!(enforcing().validate().is_ok());
        // Disabled is always fine, even empty.
        assert!(Config::default().validate().is_ok());
        assert!(Config { wan: vec![], ..enforcing() }.validate().is_err());
        assert!(Config { wan: vec!["wan; rm -rf /".into()], ..enforcing() }.validate().is_err());
        assert!(Config { wan: vec!["wan\"".into()], ..enforcing() }.validate().is_err());
        assert!(Config { wan: vec!["averyveryverylonginterface".into()], ..enforcing() }.validate().is_err());
        assert!(Config { lan: vec!["wan".into()], ..enforcing() }.validate().is_err());
        // Take-over without a LAN interface has nothing to match on.
        let dns = DnsConfig { take_over: true, ..DnsConfig::default() };
        assert!(Config { lan: vec![], dns: dns.clone(), ..enforcing() }.validate().is_err());
        let bad = DnsConfig { blocked_domains: vec!["no good".into()], ..dns };
        assert!(Config { dns: bad, ..enforcing() }.validate().is_err());
        let proxy = ProxyConfig { enabled: true, port: 0, http_only: false };
        assert!(Config { proxy, ..enforcing() }.validate().is_err());
    }

    #[test]
    fn domains() {
        assert!(valid_domain("a.example.com"));
        assert!(valid_domain("ipv4only.arpa"));
        assert!(!valid_domain(""));
        assert!(!valid_domain(".example.com"));
        assert!(!valid_domain("a..b"));
        assert!(!valid_domain("a b.com"));
        assert!(!valid_domain("a/b.com"));
    }
}
