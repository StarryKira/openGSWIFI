//! Every driver the binary knows, by its `driver = "..."` name.

use gswifi_core::{Credentials, Driver, DriverInfo, Env};
use log::warn;
use std::fmt::Debug;

use serde::de::DeserializeOwned;

/// Static descriptions of all drivers, for `gswifi drivers`.
pub fn all() -> Vec<&'static DriverInfo> {
    vec![&gswifi_ruijie::INFO, &gswifi_saier::INFO, &gswifi_eap_md5::INFO, &gswifi_inode::INFO, &gswifi_anlang::INFO, &gswifi_drcom::INFO, &gswifi_h3c_portal::INFO, &gswifi_netkeeper::INFO, &gswifi_portal::INFO_HUBEI_OLD_MAC, &gswifi_portal::INFO_HUBEI_NEW_MAC, &gswifi_portal::INFO_HUBEI_ANDROID, &gswifi_portal::INFO_YUNNAN_WEB, &gswifi_portal::INFO_YUNNAN_PPPOE]
}

pub fn info(name: &str) -> Option<&'static DriverInfo> {
    all().into_iter().find(|i| i.name == name)
}

/// Why a listed driver cannot run a session whatever its options are:
/// NetKeeper only derives a dial-up name, and some Portal profiles are
/// listed so they can be named but are not closed. `None`: it can run.
pub fn unavailable(name: &str) -> Option<&'static str> {
    match name {
        "netkeeper" => Some(NETKEEPER_ONLY_DERIVES),
        "portal-hubei-new-mac" => Some(gswifi_portal::HUBEI_NEW_MAC_MISSING),
        "portal-hubei-android" => Some(gswifi_portal::HUBEI_ANDROID_MISSING),
        "portal-yunnan-web" => Some(gswifi_portal::YUNNAN_WEB_MISSING),
        "portal-yunnan-pppoe" => Some(gswifi_portal::YUNNAN_PPPOE_MISSING),
        _ => None,
    }
}

const NETKEEPER_ONLY_DERIVES: &str = "netkeeper 只派生 PPPoE 拨号账号，由 pppd 拨号；请用 gswifi pppoe-username";

/// Deserializes driver options from the remaining keys of a network
/// section, warning about keys no field uses (typos).
fn options<T: DeserializeOwned + Debug>(driver: &str, table: toml::Table) -> Result<T, String> {
    let parsed: T = toml::Value::Table(table.clone()).try_into().map_err(|e| format!("{} 的配置有误: {}", driver, e))?;
    for key in unknown_keys::<T>(&table, &parsed) {
        warn!("{} 不认识配置项 {}，已忽略", driver, key);
    }
    Ok(parsed)
}

/// Keys whose value does not influence the parsed options. Driver options
/// use `#[serde(flatten)]` for the shared settings, which makes serde drop
/// unknown keys silently; so change each value and see whether the result
/// changes (or fails to parse, which also means some field reads it).
fn unknown_keys<T: DeserializeOwned + Debug>(table: &toml::Table, parsed: &T) -> Vec<String> {
    let baseline = format!("{:?}", parsed);
    let mut unknown = Vec::new();
    for (key, value) in table {
        let changed = match value {
            toml::Value::String(s) => toml::Value::String(format!("{}\u{1}", s)),
            toml::Value::Integer(i) => toml::Value::Integer(i.wrapping_add(1)),
            toml::Value::Boolean(b) => toml::Value::Boolean(!b),
            toml::Value::Float(f) => toml::Value::Float(f + 1.0),
            // Arrays, tables, dates: assume a field reads them.
            _ => continue,
        };
        let mut probe = table.clone();
        probe.insert(key.clone(), changed);
        match toml::Value::Table(probe).try_into::<T>() {
            Ok(other) if format!("{:?}", other) == baseline => unknown.push(key.clone()),
            _ => {}
        }
    }
    unknown
}

/// Builds the session of `driver` from its options.
pub fn build(driver: &str, env: Env, credentials: Credentials, table: toml::Table) -> Result<Box<dyn Driver>, String> {
    Ok(match driver {
        "ruijie" => Box::new(gswifi_ruijie::driver(env, credentials, options(driver, table)?)?),
        "saier" => Box::new(gswifi_saier::driver(env, credentials, options(driver, table)?)?),
        "eap-md5" => Box::new(gswifi_eap_md5::driver(env, credentials, options(driver, table)?)?),
        "inode" => Box::new(gswifi_inode::driver(env, credentials, options(driver, table)?)?),
        "h3c-portal" => Box::new(gswifi_h3c_portal::H3cPortalDriver::new(env, credentials, options(driver, table)?)?),
        "anlang" => Box::new(gswifi_anlang::AnlangDriver::new(env, credentials, options(driver, table)?)?),
        "drcom" => Box::new(gswifi_drcom::DrcomDriver::new(env, credentials, options(driver, table)?)?),
        "portal-hubei-old-mac" => Box::new(gswifi_portal::HubeiOldMacDriver::new(env, credentials, options(driver, table)?)?),
        "portal-hubei-new-mac" => Box::new(gswifi_portal::HubeiNewMacDriver::new(env, credentials, options(driver, table)?)?),
        "portal-hubei-android" => Box::new(gswifi_portal::HubeiAndroidDriver::new(env, credentials, options(driver, table)?)?),
        "portal-yunnan-web" => Box::new(gswifi_portal::YunnanWebDriver::new(env, credentials, options(driver, table)?)?),
        "portal-yunnan-pppoe" => Box::new(gswifi_portal::YunnanPppoeDriver::new(env, credentials, options(driver, table)?)?),
        "netkeeper" => return Err(NETKEEPER_ONLY_DERIVES.into()),
        _ => {
            let names: Vec<_> = all().iter().map(|i| i.name).collect();
            return Err(format!("不支持的认证方式 {:?}，可选: {}", driver, names.join(", ")));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_driver_builds_with_defaults() {
        for info in all() {
            let env = Env { interface: "eth0".into(), mac: [2, 0, 0, 0, 0, 1], ..Default::default() };
            let mut table = toml::Table::new();
            // UDP drivers need a server address; 802.1X ones ignore it.
            table.insert("server".into(), "192.0.2.1".into());
            match build(info.name, env, Credentials::new("u", "p"), table) {
                Ok(d) => assert_eq!(d.info().name, info.name),
                // A driver may refuse missing mandatory settings, but must say so.
                Err(e) => assert!(!e.is_empty(), "{}", info.name),
            }
        }
        assert!(build("nope", Env::default(), Credentials::default(), toml::Table::new()).is_err());
    }

    /// `drivers --json` tells front ends which drivers cannot run at all;
    /// that list has to agree with what `build` really refuses.
    #[test]
    fn unavailable_drivers_never_build() {
        for info in all() {
            let Some(reason) = unavailable(info.name) else { continue };
            assert!(!reason.is_empty());
            let env = Env { interface: "eth0".into(), mac: [2, 0, 0, 0, 0, 1], ..Default::default() };
            let mut table = toml::Table::new();
            table.insert("server".into(), "192.0.2.1".into());
            match build(info.name, env, Credentials::new("u", "p"), table) {
                Ok(_) => panic!("{} is marked unavailable but builds", info.name),
                Err(e) => assert_eq!(e, reason, "{}", info.name),
            }
        }
        assert!(unavailable("ruijie").is_none());
        assert_eq!(all().iter().filter(|i| unavailable(i.name).is_some()).count(), 5);
    }

    #[test]
    fn options_are_typed() {
        let table: toml::Table = toml::from_str("ext_format = 'classic'\nstart_mode = 1\ntimeout = 3").unwrap();
        let o: gswifi_ruijie::Options = options("ruijie", table).unwrap();
        assert_eq!((o.ext_format.as_str(), o.start_mode, o.eapol.timeout), ("classic", Some(1), 3));
        // Typos are found although the shared keys are flattened.
        let table: toml::Table = toml::from_str("ext_fromat = 'classic'\ntimeout = 3\nstart_mode = 255\nudp_heartbeat = false").unwrap();
        let o: gswifi_ruijie::Options = toml::Value::Table(table.clone()).try_into().unwrap();
        assert_eq!(unknown_keys(&table, &o), vec!["ext_fromat".to_string()]);
        let bad: toml::Table = toml::from_str("start_mode = 'x'").unwrap();
        assert!(options::<gswifi_ruijie::Options>("ruijie", bad).is_err());
    }
}

