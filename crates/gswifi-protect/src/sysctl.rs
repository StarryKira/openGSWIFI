//! Kernel parameters of the router's *own* connections (doc 4 persona
//! matrix). They do not affect forwarded packets, which the nftables rules
//! handle.

use crate::config::{Config, Mode};
use crate::plan::Sysctl;

/// Settings for the persona. Empty unless the mode is enforce: observe
/// must not change anything (doc 27.5).
pub(crate) fn build(config: &Config) -> Vec<Sysctl> {
    let mut out = Vec::new();
    if config.mode != Mode::Enforce {
        return out;
    }
    let mut set = |key: &str, value: String| out.push(Sysctl { key: key.into(), value });
    if config.ttl {
        set("net.ipv4.ip_default_ttl", config.persona.ttl().to_string());
    }
    if config.tcp_timestamps {
        // The router's own timestamp clock is as identifying as a client's.
        set("net.ipv4.tcp_timestamps", "0".into());
    }
    if config.source_ports {
        let (low, high) = config.persona.port_range();
        set("net.ipv4.ip_local_port_range", format!("{} {}", low, high));
    }
    out
}

/// `/etc/sysctl.d` style file contents.
pub fn fragment(settings: &[Sysctl]) -> String {
    let mut s = String::from("# Open GSWIFI 流量归一化，自动生成，请勿手工编辑。\n");
    for Sysctl { key, value } in settings {
        s.push_str(&format!("{}={}\n", key, value));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Persona;

    fn config(mode: Mode, persona: Persona) -> Config {
        Config { mode, persona, wan: vec!["wan".into()], ..Config::default() }
    }

    #[test]
    fn persona_settings() {
        let pc = build(&config(Mode::Enforce, Persona::Pc));
        let find = |s: &[Sysctl], k: &str| s.iter().find(|x| x.key == k).map(|x| x.value.clone());
        assert_eq!(find(&pc, "net.ipv4.ip_default_ttl"), Some("128".into()));
        assert_eq!(find(&pc, "net.ipv4.ip_local_port_range"), Some("49152 65534".into()));
        assert_eq!(find(&pc, "net.ipv4.tcp_timestamps"), Some("0".into()));
        let phone = build(&config(Mode::Enforce, Persona::Phone));
        assert_eq!(find(&phone, "net.ipv4.ip_default_ttl"), Some("64".into()));
        assert_eq!(find(&phone, "net.ipv4.ip_local_port_range"), Some("32768 60999".into()));
    }

    #[test]
    fn observe_changes_nothing() {
        assert!(build(&config(Mode::Observe, Persona::Pc)).is_empty());
        assert!(build(&config(Mode::Disabled, Persona::Pc)).is_empty());
    }

    #[test]
    fn disabled_features_are_absent() {
        let c = Config { ttl: false, source_ports: false, ..config(Mode::Enforce, Persona::Pc) };
        let keys: Vec<_> = build(&c).into_iter().map(|s| s.key).collect();
        assert_eq!(keys, vec!["net.ipv4.tcp_timestamps"]);
        assert!(fragment(&build(&c)).contains("net.ipv4.tcp_timestamps=0"));
    }
}
