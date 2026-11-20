//! NetKeeper / 闪讯 PPPoE usernames of the customised pppd (research doc
//! 12, cleanroom/06).
//!
//! PPPoE, PAP/CHAP and IPCP stay pppd's job; these profiles only change the
//! username pppd dials with. The derived name depends on the time (5 second
//! slots for the classic PIN, seconds for 海南), so it must be computed
//! right before dialing with a correct clock.
//!
//! Implemented: classic getPIN (nk_version 1–13) and 海南 new_calc_pin (14),
//! both D-verified against the original functions. Refused with a reason:
//! 重庆 4.x getPIN_sx4 (15), the NK4.X/SX5.X desktop import (99), and the
//! SRun2K/SRun3K, 四川掌大 and 江苏天翼 dial types.

pub mod transform;

use std::fmt;

use gswifi_core::{DriverInfo, SupportLevel, Transport};
use serde::Deserialize;

pub use transform::{get_pin, hainan_pin, hash_key};

pub static INFO: DriverInfo = DriverInfo {
    name: "netkeeper",
    title: "NetKeeper/闪讯 PPPoE 拨号账号",
    transport: Transport::Pppoe,
    // getPIN and new_calc_pin match the original functions (24 vectors);
    // no real dial-up has been checked.
    support: SupportLevel::OfflineTested,
    docs: &[12],
};

/// How a profile derives the username.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// getPIN with a built-in protocol constant (not a user secret).
    Classic { material: &'static str },
    /// new_calc_pin (海南).
    Hainan,
    /// Not usable; the reason is shown to the user.
    Unsupported { reason: &'static str },
}

/// One `nk_version` of the firmware UI (cleanroom/06 §1). Region names
/// that disagree with their constants are kept as in the firmware.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub version: u8,
    pub name: &'static str,
    pub method: Method,
}

const fn classic(version: u8, name: &'static str, material: &'static str) -> Profile {
    Profile { version, name, method: Method::Classic { material } }
}

pub static PROFILES: &[Profile] = &[
    classic(1, "ChongQing 2.5.0094", "xianxinli1radius"),
    classic(2, "ChongQing 2.5 old", "cqxinliradius002"),
    classic(3, "HuBei ShanXun", "hubtxinli01"),
    classic(4, "Zhejiang ShanXun", "singlenet01"),
    classic(5, "XinJiang sx", "xinjiang@0724"),
    classic(6, "QingHai sx", "shd@xiaoyuan0002"),
    classic(7, "Shandong mobile old", "shandongmobile13"),
    Profile {
        version: 8,
        name: "Shandong mobile 4.9",
        method: Method::Unsupported {
            reason: "固件里这个版本的协议常量是空串（cleanroom/06 §1），真实值未知；如果知道，请用 material 配置",
        },
    },
    classic(9, "HeBei sx", "hebeicncxinli002"),
    classic(10, "ShanXi yixun", "sh_xi@xiaoyuan01"),
    classic(11, "GanSu sx", "xiaoyuanyixun001"),
    classic(12, "NingXia sx", "n_x@xiaoyuanwang"),
    classic(13, "Zhejiang qiye", "zjxinlisx02"),
    Profile { version: 14, name: "HaiNan sx", method: Method::Hainan },
    Profile {
        version: 15,
        name: "ChongQing 4.x",
        method: Method::Unsupported {
            reason: "getPIN_sx4 的三源交错顺序和账号游标初值尚未还原（cleanroom/06 §6）",
        },
    },
    Profile {
        version: 99,
        name: "NK4.X / SX5.X",
        method: Method::Unsupported {
            reason: "这是桌面客户端辅助导入（路由器上开 pppoe-server 接收电脑拨号的真实账号），不是派生算法；材料链路未审计（cleanroom/06 §8）",
        },
    },
];

pub fn profile(version: u8) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.version == version)
}

/// pppd dial types besides NetKeeper (cleanroom/06 §1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DialType {
    #[default]
    Netkeeper,
    Srun3k,
    Srun2k,
    Sichuan,
    Jiangsu,
}

impl DialType {
    fn unsupported(self) -> Option<&'static str> {
        match self {
            DialType::Netkeeper => None,
            DialType::Srun3k => Some("SRun3K 需要的 srun_hb 辅助程序不在固件里（cleanroom/06 §1）"),
            DialType::Srun2k => Some("SRun2K 的附加算法未还原（cleanroom/06 §1）"),
            DialType::Sichuan => Some("四川掌大的 calc_E 变换未还原（cleanroom/06 §1）"),
            DialType::Jiangsu => Some("江苏天翼 1.5.4 的 CHAP 五分支变换未还原（cleanroom/06 §7）"),
        }
    }
}

/// Configuration of the transform.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    /// pppd dial type; only `netkeeper` derives names.
    pub dial_type: DialType,
    /// NetKeeper profile, the firmware's nk_version (1–15, 99).
    pub nk_version: Option<u8>,
    /// Protocol constant for a classic profile whose constant is unknown
    /// or different at your school (getPIN only).
    pub material: Option<String>,
    /// Seconds to add to the system clock (the server's time matters).
    pub time_offset: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Configuration problem.
    Invalid(String),
    /// The profile or dial type is not recovered.
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid(m) => write!(f, "配置错误：{}", m),
            Error::Unsupported(m) => write!(f, "不支持：{}", m),
        }
    }
}

impl std::error::Error for Error {}

/// A username to dial with, and how long it stays valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    /// Raw bytes: the classic PIN starts with CR LF, so it is not printable.
    pub username: Vec<u8>,
    /// Unix time from which a different name is derived.
    pub valid_until: u64,
}

/// Derives the PPPoE username for `unix_time` (already corrected by the
/// caller; [`Options::time_offset`] is applied here).
pub fn derive(options: &Options, username: &str, unix_time: u64) -> Result<Derived, Error> {
    if let Some(reason) = options.dial_type.unsupported() {
        return Err(Error::Unsupported(reason.into()));
    }
    if username.is_empty() || username.contains('\0') {
        return Err(Error::Invalid("用户名为空或含 NUL".into()));
    }
    let version = options.nk_version.ok_or_else(|| Error::Invalid("需要 nk_version（1~15）".into()))?;
    let profile = profile(version).ok_or_else(|| Error::Invalid(format!("未知的 nk_version {}", version)))?;
    let t = unix_time.checked_add_signed(options.time_offset).ok_or_else(|| Error::Invalid("time_offset 超出范围".into()))?;
    let material = options.material.as_deref().filter(|m| !m.is_empty());
    match (profile.method, material) {
        (Method::Classic { material: builtin }, custom) => {
            Ok(Derived { username: get_pin(username, custom.unwrap_or(builtin), t), valid_until: (t / 5 + 1) * 5 })
        }
        // Shandong 4.9: the firmware constant is empty; a configured one works.
        (Method::Unsupported { .. }, Some(custom)) if version == 8 => {
            Ok(Derived { username: get_pin(username, custom, t), valid_until: (t / 5 + 1) * 5 })
        }
        (Method::Hainan, _) => Ok(Derived { username: hainan_pin(username, t).into_bytes(), valid_until: t + 1 }),
        (Method::Unsupported { reason }, _) => Err(Error::Unsupported(format!("nk_version {}（{}）：{}", version, profile.name, reason))),
    }
}

/// Bytes as a C string literal (`\r\n...`), for pppd `user "..."` lines.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(version: u8) -> Options {
        Options { nk_version: Some(version), ..Options::default() }
    }

    #[test]
    fn classic_profiles_use_their_constant() {
        let d = derive(&opts(4), "synthetic", 305419896).unwrap();
        assert_eq!(hex::encode(&d.username), "0d0a4d4939284220656573796e746865746963");
        assert_eq!(d.valid_until, 305419900);
        // A configured material wins.
        let custom = Options { material: Some("xianxinli1radius".into()), ..opts(4) };
        assert_eq!(derive(&custom, "a@b@c", 305419896).unwrap().username, get_pin("a@b@c", "xianxinli1radius", 305419896));
        // Time offset is applied.
        let shifted = Options { time_offset: 5, ..opts(4) };
        assert_eq!(derive(&shifted, "u", 1000).unwrap().username, get_pin("u", "singlenet01", 1005));
    }

    #[test]
    fn hainan_profile() {
        let d = derive(&opts(14), "synthetic", 305419896).unwrap();
        assert_eq!(String::from_utf8(d.username).unwrap(), "~LL_ciJov:kzFlm4_synthetic");
        assert_eq!(d.valid_until, 305419897);
    }

    #[test]
    fn refusals_explain_themselves() {
        assert!(matches!(derive(&opts(15), "u", 0), Err(Error::Unsupported(m)) if m.contains("sx4")));
        assert!(matches!(derive(&opts(99), "u", 0), Err(Error::Unsupported(_))));
        assert!(matches!(derive(&opts(8), "u", 0), Err(Error::Unsupported(_))));
        let shandong = Options { material: Some("secret".into()), ..opts(8) };
        assert!(derive(&shandong, "u", 0).is_ok());
        assert!(matches!(derive(&opts(16), "u", 0), Err(Error::Invalid(_))));
        assert!(matches!(derive(&Options::default(), "u", 0), Err(Error::Invalid(_))));
        assert!(matches!(derive(&opts(4), "", 0), Err(Error::Invalid(_))));
        let srun = Options { dial_type: DialType::Srun3k, ..opts(4) };
        assert!(matches!(derive(&srun, "u", 0), Err(Error::Unsupported(m)) if m.contains("srun_hb")));
    }

    #[test]
    fn every_profile_is_listed_once() {
        let mut versions: Vec<u8> = PROFILES.iter().map(|p| p.version).collect();
        versions.dedup();
        assert_eq!(versions, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99]);
    }

    #[test]
    fn escaping() {
        assert_eq!(escape(b"\r\nA \"b\\\x01"), "\\r\\nA \\\"b\\\\\\x01");
    }

    #[test]
    fn options_parse() {
        let o: Options = serde_json::from_str(r#"{"nk_version": 14, "dial_type": "netkeeper", "time_offset": -3}"#).unwrap();
        assert_eq!((o.nk_version, o.dial_type, o.time_offset), (Some(14), DialType::Netkeeper, -3));
    }
}
