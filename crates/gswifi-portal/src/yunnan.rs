//! 云南 NetKeeper-family Portal: the parts cleanroom/07 specifies.
//!
//! Closed (grade F): the request headers and form templates of the Web
//! client (§4), the heartbeat text format (§4), the discovery parameters and
//! entry URL ([`crate::discovery::YunnanDiscovery`], §1), and the existence
//! of the PPPoE account prefix `!^B6EA` (§3).
//!
//! Not closed, so not offered (gaps.md "湖北 / 云南 网页 Portal"): which of
//! the two login forms is used and whether `Password` is derived (§4); the
//! account derivation after `!^B6EA` and the `@xyw` condition (§3); the
//! heartbeat URL and interval, which come from the encrypted NkConfig (§5).

use std::fmt;
use std::net::Ipv4Addr;

use crate::url::form_encode_pairs;

/// `ClientVersion` header of the Web client (cleanroom/07 §4).
pub const CLIENT_VERSION: &str = "B6EA";
/// `User-Agent` of the Web client; may change per stage (§4).
pub const USER_AGENT: &str = "CDMA+WLAN(win64)";
/// Account prefix of both the PPPoE call (`switch_pppoe %s !^B6EA%s %s`)
/// and the prefixed Web form. Only the prefix is known (§3).
pub const ACCOUNT_PREFIX: &str = "!^B6EA";
/// Account suffix seen in a conditional PPPoE branch; condition unknown.
pub const PPPOE_SUFFIX: &str = "@xyw";
/// `OriginatingServer` form field (§4).
pub const ORIGINATING_SERVER: &str = "http://www.baidu.com/";
/// Heartbeat `nkcversion` / `winversion` (§4).
pub const NKC_VERSION: &str = "1.1.3815";
pub const WIN_VERSION: &str = "10.0";
/// Heartbeat `type` of the Yunnan client (§4).
pub const HEARTBEAT_TYPE: u32 = 2;

/// The two login form templates (§4). Which one the client uses, and for
/// which accounts, is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormVariant {
    /// `UserName=!^B6EA<value>`.
    Prefixed,
    /// `UserName=<value>`.
    Plain,
}

/// Builds a Yunnan login body from values the caller already has. The
/// `Password` value is a placeholder in the evidence ("是否派生取决于调用链"):
/// this function does not decide it, and no driver uses it until the
/// derivation is closed.
pub fn login_form(variant: FormVariant, username_value: &str, password_value: &str) -> String {
    let user = match variant {
        FormVariant::Prefixed => format!("{}{}", ACCOUNT_PREFIX, username_value),
        FormVariant::Plain => username_value.to_string(),
    };
    form_encode_pairs(&[
        ("button", "Login"),
        ("UserName", &user),
        ("Password", password_value),
        ("FNAME", "0"),
        ("OriginatingServer", ORIGINATING_SERVER),
    ])
}

/// Inputs of one heartbeat (§4).
#[derive(Clone, Debug)]
pub struct Heartbeat<'a> {
    pub ipv4: Ipv4Addr,
    /// Client UUID (`/etc/hbhttp.uuid` in the firmware, cleanroom/07 §2).
    pub nkcguid: &'a str,
    pub username: &'a str,
    /// `time=<unsigned>`.
    pub time: u32,
    pub wlanacname: &'a str,
}

/// A heartbeat field contains a separator; the format has no escaping that
/// the evidence shows, so such a value cannot be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError(pub &'static str);

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "心跳字段 {} 含有 ';'、'=' 或控制字符，格式未定义转义方式", self.0)
    }
}

impl std::error::Error for FieldError {}

/// Heartbeat text, separators and the trailing `;` included (§4):
///
/// ```text
/// magic=0x214B544E;type=2;proxyid=0;ipv4=<ip>;nkcguid=<uuid>;nkcversion=1.1.3815;
/// winversion=10.0;username=<user>;time=<unsigned>;wlanacname=<ac>;
/// ```
///
/// Transport, URL, interval and Content-Type are not known.
pub fn heartbeat_payload(hb: &Heartbeat<'_>) -> Result<String, FieldError> {
    for (name, value) in [("nkcguid", hb.nkcguid), ("username", hb.username), ("wlanacname", hb.wlanacname)] {
        if value.contains([';', '=']) || value.chars().any(char::is_control) {
            return Err(FieldError(name));
        }
    }
    Ok(format!(
        "magic={};type={};proxyid=0;ipv4={};nkcguid={};nkcversion={};winversion={};username={};time={};wlanacname={};",
        crate::hubei::HEARTBEAT_MAGIC,
        HEARTBEAT_TYPE,
        hb.ipv4,
        hb.nkcguid,
        NKC_VERSION,
        WIN_VERSION,
        hb.username,
        hb.time,
        hb.wlanacname
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_format() {
        let hb = Heartbeat {
            ipv4: Ipv4Addr::new(10, 0, 0, 9),
            nkcguid: "6f1c0c3e-0000-4000-8000-000000000001",
            username: "13800000000",
            time: 4_000_000_000,
            wlanacname: "YN-AC",
        };
        assert_eq!(
            heartbeat_payload(&hb).unwrap(),
            "magic=0x214B544E;type=2;proxyid=0;ipv4=10.0.0.9;nkcguid=6f1c0c3e-0000-4000-8000-000000000001;\
             nkcversion=1.1.3815;winversion=10.0;username=13800000000;time=4000000000;wlanacname=YN-AC;"
        );
        assert_eq!(heartbeat_payload(&Heartbeat { username: "a;b", ..hb.clone() }), Err(FieldError("username")));
        assert_eq!(heartbeat_payload(&Heartbeat { wlanacname: "a\n", ..hb }), Err(FieldError("wlanacname")));
    }

    #[test]
    fn form_templates() {
        assert_eq!(
            login_form(FormVariant::Prefixed, "u", "p"),
            "button=Login&UserName=%21%5EB6EAu&Password=p&FNAME=0&OriginatingServer=http%3A%2F%2Fwww.baidu.com%2F"
        );
        assert!(login_form(FormVariant::Plain, "u", "p").starts_with("button=Login&UserName=u&Password=p&"));
    }
}
