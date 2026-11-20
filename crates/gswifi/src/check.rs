//! `gswifi run --check`: reads a configuration file the way `run` does and
//! reports, as JSON, what every network section turned into, without
//! touching an interface or sending anything.
//!
//! Front ends that generate the file (the OpenWrt package does, from UCI)
//! use it to see that their output means what they intended. The password
//! is never printed, only its length in bytes.

use gswifi_core::Env;
use gswifi_link::json::{self, Object};

use crate::config::{self, Network};
use crate::registry;

/// A TOML value as JSON. Dates become strings; non-finite floats `null`.
pub fn value_json(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => json::string(s),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) if f.is_finite() => f.to_string(),
        toml::Value::Float(_) => "null".into(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => json::string(&d.to_string()),
        toml::Value::Array(list) => json::array(list.iter().map(value_json)),
        toml::Value::Table(table) => table_json(table),
    }
}

fn table_json(table: &toml::Table) -> String {
    table.iter().fold(Object::new(), |o, (k, v)| o.raw(k, &value_json(v))).finish()
}

/// Why this network could not run, before any packet is sent.
fn problem(n: &Network) -> Option<String> {
    let Some(info) = registry::info(&n.driver) else {
        return Some(format!("不支持的认证方式 {:?}", n.driver));
    };
    if let Some(why) = registry::unavailable(info.name) {
        return Some(why.to_string());
    }
    if info.support.is_experimental() && !n.experimental {
        return Some(format!("{} 的验证程度是 {}，需要 experimental = true", info.name, info.support));
    }
    // The options are only checked by building the session; a placeholder
    // MAC stands in for the interface, which need not exist here.
    let env = Env { interface: n.interface.clone(), mac: [0x02, 0, 0, 0, 0, 0x01], ..Env::default() };
    registry::build(&n.driver, env, n.credentials.clone(), n.options.clone()).err()
}

fn network_json(n: &Network) -> (String, bool) {
    let problem = problem(n);
    let ok = problem.is_none();
    let text = Object::new()
        .str("name", &n.name)
        .str("interface", &n.interface)
        .str("driver", &n.driver)
        .str("username", &n.credentials.username)
        .num("password_bytes", n.credentials.password.as_bytes().len())
        .bool("experimental", n.experimental)
        .bool("trace", n.trace)
        .bool("exit_on_reject", n.exit_on_reject)
        .opt_str("dhcp_script", n.dhcp_script.as_deref())
        .raw("options", &table_json(&n.options))
        .opt_str("error", problem.as_deref())
        .finish();
    (text, ok)
}

/// The report for a whole file, and whether every network can run.
pub fn report(text: &str) -> (String, bool) {
    match config::parse(text) {
        Ok(networks) => {
            let mut all_ok = true;
            let items: Vec<String> = networks
                .iter()
                .map(|n| {
                    let (json, ok) = network_json(n);
                    all_ok &= ok;
                    json
                })
                .collect();
            (Object::new().bool("ok", all_ok).raw("networks", &json::array(items)).finish(), all_ok)
        }
        Err(e) => (Object::new().bool("ok", false).str("error", &e).raw("networks", "[]").finish(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the OpenWrt package generates for a password and user name
    /// full of characters that need escaping.
    const GENERATED: &str = r#"# generated
[[networks]]
name = "campus"
interface = "eth0"
driver = "ruijie"
username = "u\"s\\er #1\n学号"
password = "p\"a\\ss#w 密码'x"
dhcp_script = "ubus call network.interface.wan renew"
max_retries = -1
ext_format = "classic"
client_version = "4.10"
"#;

    #[test]
    fn generated_values_survive() {
        let (text, ok) = report(GENERATED);
        assert!(ok, "{}", text);
        assert!(
            text.starts_with(r#"{"ok":true,"networks":[{"name":"campus","interface":"eth0","driver":"ruijie""#),
            "{}",
            text
        );
        // The user name comes back byte for byte.
        assert!(text.contains(r#""username":"u\"s\\er #1\n学号""#), "{}", text);
        // The password does not come back at all, only its length.
        let password = "p\"a\\ss#w 密码'x";
        assert!(text.contains(&format!(r#""password_bytes":{}"#, password.len())), "{}", text);
        assert!(!text.contains("ss#w"));
        assert!(
            text.contains(r#""options":{"client_version":"4.10","ext_format":"classic","max_retries":-1}"#),
            "{}",
            text
        );
        assert!(text.contains(r#""exit_on_reject":false"#) && text.contains(r#""error":null"#));
    }

    #[test]
    fn problems_are_reported_per_network() {
        let text = "[[networks]]\ninterface='eth0'\ndriver='inode'\nusername='u'\npassword='p'\n\
                    [[networks]]\ninterface='eth1'\ndriver='netkeeper'\nusername='u'\npassword='p'\n\
                    [[networks]]\ninterface='eth2'\ndriver='ruijie'\nusername='u'\npassword='p'\next_format='nope'\n";
        let (json, ok) = report(text);
        assert!(!ok);
        assert!(json.contains("需要 experimental = true"), "{}", json);
        assert!(json.contains("只派生 PPPoE 拨号账号"), "{}", json);
        assert!(json.contains("扩展数据格式"), "{}", json);
        let (json, ok) = report("not toml [");
        assert!(!ok && json.starts_with(r#"{"ok":false,"error":"#), "{}", json);
    }

    #[test]
    fn values_as_json() {
        let v: toml::Table = toml::from_str("a = [1, 'x']\nb = { c = true }\nd = 1.5").unwrap();
        assert_eq!(table_json(&v), r#"{"a":[1,"x"],"b":{"c":true},"d":1.5}"#);
    }
}
