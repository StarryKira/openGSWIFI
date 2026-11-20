//! `/etc/gswifi/config.toml`: one `[[networks]]` section per interface.
//!
//! The keys below are read by the runtime; every other key of a section
//! belongs to the driver (see `gswifi drivers` and the crate docs).

use std::fs;

use gswifi_core::{Credentials, Secret};

/// Keys the runtime consumes; the rest goes to the driver.
const RUNTIME_KEYS: [&str; 10] = [
    "name",
    "interface",
    "driver",
    "username",
    "password",
    "password_file",
    "dhcp_script",
    "experimental",
    "trace",
    "exit_on_reject",
];

#[derive(Clone, Debug)]
pub struct Network {
    /// Shown in log lines; defaults to the interface.
    pub name: String,
    pub interface: String,
    pub driver: String,
    pub credentials: Credentials,
    pub dhcp_script: Option<String>,
    /// Allows drivers below lab-tested.
    pub experimental: bool,
    pub trace: bool,
    /// Exit with the rejection's code instead of waiting for an address
    /// change (for supervisors that expect mentorust's exit codes).
    pub exit_on_reject: bool,
    /// Driver specific options.
    pub options: toml::Table,
}

pub const EXAMPLE: &str = r#"# Open GSWIFI configuration. One [[networks]] section per interface.
# Keys besides the common ones are passed to the driver.

[[networks]]
name = "campus"
interface = "eth0.2"
driver = "ruijie"          # gswifi drivers: ruijie, saier, eap-md5, ...
username = "20260001"
# Prefer a root-only file over a password in this file.
password_file = "/etc/gswifi/campus.pass"
# Command for DHCP modes 1..3 (renews the address); optional.
# dhcp_script = "ifup wan"

# Shared 802.1X settings.
dhcp_mode = 0              # 0 none, 1 twice, 2 after, 3 before authentication
timeout = 8
restart_wait = 15
max_retries = 3            # -1: never give up

# Ruijie settings.
ext_format = "modern"      # modern | classic | none
start_mode = 0             # 0 standard, 1 Ruijie group, 2 Saier, 3 broadcast
# client_version = "4.10"
# data_file = "/etc/gswifi/ruijie"   # 8021x.exe, W32N55.dll, SuConfig.dat

# 防共享检测：统一出口流量特征。先用 observe 观察，再改 enforce。
[protect]
mode = "disabled"          # disabled | observe | enforce
persona = "pc"             # pc（TTL 128）| phone（TTL 64）
wan = ["wan"]              # 上行接口
lan = ["br-lan"]           # 局域网接口（DNS/NTP/代理接管时需要）
ttl = true
preserve_traceroute = true # 保留 TTL<=32 的 traceroute 探测和 250..255
ipid = true                # 需要内核 5.5+
tcp_timestamps = true      # 去掉 SYN 时间戳选项，需要内核 5.18+
dscp_ecn = true
icmp = true
source_ports = true
ipv6 = "forward"           # forward | normalise | block
# [protect.dns] 的域名列表由你自己填，本程序不内置任何列表
# [protect.proxy] enabled/port/http_only 配合 gswifi proxy 使用
"#;

fn string(table: &toml::Table, key: &str) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) => Ok(Some(s.clone())),
        Some(v) => Err(format!("{} 应为字符串，而不是 {}", key, v.type_str())),
    }
}

fn boolean(table: &toml::Table, key: &str) -> Result<bool, String> {
    match table.get(key) {
        None => Ok(false),
        Some(toml::Value::Boolean(b)) => Ok(*b),
        Some(v) => Err(format!("{} 应为 true/false，而不是 {}", key, v.type_str())),
    }
}

impl Network {
    pub fn from_table(mut table: toml::Table) -> Result<Self, String> {
        let interface = string(&table, "interface")?.unwrap_or_default();
        let driver = string(&table, "driver")?.unwrap_or_else(|| "ruijie".into());
        let username = string(&table, "username")?.ok_or("缺少 username")?;
        let password = match (string(&table, "password")?, string(&table, "password_file")?) {
            (Some(p), None) => p,
            (None, Some(path)) => fs::read_to_string(&path)
                .map_err(|e| format!("无法读取密码文件 {}: {}", path, e))?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
            (Some(_), Some(_)) => return Err("password 和 password_file 只能设置一个".into()),
            (None, None) => return Err("缺少 password 或 password_file".into()),
        };
        let network = Network {
            name: string(&table, "name")?.unwrap_or_else(|| {
                if interface.is_empty() {
                    driver.clone()
                } else {
                    interface.clone()
                }
            }),
            credentials: Credentials { username, password: Secret::new(password) },
            dhcp_script: string(&table, "dhcp_script")?.filter(|s| !s.trim().is_empty()),
            experimental: boolean(&table, "experimental")?,
            trace: boolean(&table, "trace")?,
            exit_on_reject: boolean(&table, "exit_on_reject")?,
            interface,
            driver,
            options: toml::Table::new(),
        };
        for key in RUNTIME_KEYS {
            table.remove(key);
        }
        Ok(Network { options: table, ..network })
    }
}

/// Parses the optional `[protect]` section (traffic normalisation).
/// A file without one means "disabled".
pub fn parse_protect(text: &str) -> Result<gswifi_protect::Config, String> {
    let mut root: toml::Table = toml::from_str(text).map_err(|e| format!("配置文件格式错误: {}", e))?;
    match root.remove("protect") {
        None => Ok(gswifi_protect::Config::default()),
        Some(value) => value.try_into().map_err(|e| format!("[protect] 配置有误: {}", e)),
    }
}

/// Parses a whole configuration file.
pub fn parse(text: &str) -> Result<Vec<Network>, String> {
    let mut root: toml::Table = toml::from_str(text).map_err(|e| format!("配置文件格式错误: {}", e))?;
    let networks = match root.remove("networks") {
        Some(toml::Value::Array(list)) => list,
        Some(_) => return Err("networks 应为 [[networks]] 数组".into()),
        None => return Err("配置文件里没有 [[networks]]".into()),
    };
    if networks.is_empty() {
        return Err("配置文件里没有 [[networks]]".into());
    }
    networks
        .into_iter()
        .enumerate()
        .map(|(i, v)| match v {
            toml::Value::Table(t) => Network::from_table(t).map_err(|e| format!("第 {} 个 [[networks]]: {}", i + 1, e)),
            _ => Err(format!("第 {} 个 networks 不是表", i + 1)),
        })
        .collect()
}

/// `key=value` from the command line: integers and booleans keep their
/// type, everything else is a string (so `4.10` stays `"4.10"`).
pub fn cli_option(pair: &str) -> Result<(String, toml::Value), String> {
    let (key, value) = pair.split_once('=').ok_or_else(|| format!("-o 需要 key=value，而不是 {:?}", pair))?;
    let value = if let Ok(i) = value.parse::<i64>() {
        toml::Value::Integer(i)
    } else if let Ok(b) = value.parse::<bool>() {
        toml::Value::Boolean(b)
    } else {
        toml::Value::String(value.to_string())
    };
    Ok((key.trim().to_string(), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_has_a_disabled_protect_section() {
        let c = parse_protect(EXAMPLE).unwrap();
        assert_eq!(c.mode, gswifi_protect::Mode::Disabled);
        assert_eq!(c.wan, vec!["wan".to_string()]);
        assert!(c.validate().is_ok());
        // A file without the section is simply disabled.
        assert_eq!(parse_protect("").unwrap().mode, gswifi_protect::Mode::Disabled);
        assert!(parse_protect("[protect]\nmode = 'nope'").is_err());
    }

    #[test]
    fn example_parses() {
        // The example names a password file that does not exist here.
        let text = EXAMPLE.replace("password_file = \"/etc/gswifi/campus.pass\"", "password = \"x\"");
        let nets = parse(&text).unwrap();
        assert_eq!(nets.len(), 1);
        let n = &nets[0];
        assert_eq!((n.name.as_str(), n.interface.as_str(), n.driver.as_str()), ("campus", "eth0.2", "ruijie"));
        assert_eq!(n.credentials.password.expose(), "x");
        assert!(n.options.contains_key("ext_format"));
        assert!(!n.options.contains_key("username"));
        assert!(!n.options.contains_key("password"));
    }

    #[test]
    fn errors_are_specific() {
        assert!(parse("").unwrap_err().contains("networks"));
        assert!(parse("[[networks]]\nusername='u'").unwrap_err().contains("password"));
        assert!(parse("[[networks]]\nusername='u'\npassword='p'\npassword_file='f'").is_err());
        assert!(parse("[[networks]]\nusername='u'\npassword='p'\nexperimental='yes'").is_err());
    }

    #[test]
    fn cli_values() {
        assert_eq!(cli_option("start_mode=1").unwrap(), ("start_mode".into(), toml::Value::Integer(1)));
        assert_eq!(cli_option("udp_heartbeat=true").unwrap().1, toml::Value::Boolean(true));
        assert_eq!(cli_option("client_version=4.10").unwrap().1, toml::Value::String("4.10".into()));
        assert!(cli_option("novalue").is_err());
    }
}
