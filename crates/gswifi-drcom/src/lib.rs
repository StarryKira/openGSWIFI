//! Dr.com (城市热点) campus authentication for Open GSWIFI.
//!
//! The GSWIFI AC2100 firmware ships Dr.com twice (doc 01 §1.1, doc 14):
//!
//! * `/usr/bin/dogcom` (doc 03): "DHCP mode" — UDP login and keepalive on
//!   port 61440 once the interface has an address — and "PPPoE mode" — UDP
//!   keepalive after pppd is up. This crate drives both
//!   ([`Variant::Dogcom`]), implemented independently from the byte layouts
//!   of doc 03 (no Dogcom source was used; Dogcom is AGPLv3, doc 09.9).
//! * MentoHUST GS AuthType 3/4/5/6 (D/X/P/Pt) with DrMode school profiles
//!   (doc 30). Their codecs are in [`gs`] and [`packet`] and are verified
//!   against the firmware replays, but the full exchanges are not specified,
//!   so [`DrcomDriver::new`] refuses those variants instead of falling back
//!   to another protocol (doc 09.1).
//!
//! Module map: [`primitives`] (digests, checksums, seed hashes), [`packet`]
//! (challenge/login/keepalive/PPPoE codecs), [`gs`] (GS control packets,
//! receive dispatch, failure texts, DrAuthSvr.dll material), and the
//! sans-IO [`DrcomDriver`].

use std::fmt;
use std::net::Ipv4Addr;

use gswifi_core::{DriverInfo, SupportLevel, Transport};
use serde::Deserialize;

mod driver;
pub mod gs;
pub mod packet;
pub mod primitives;

pub use driver::DrcomDriver;

/// Static description. `Documented`: the primitives and GS codecs match
/// firmware golden vectors, but the Dogcom exchange the driver runs has no
/// golden capture of a whole session (doc 03 is grade U, doc 10 DC-01).
pub const INFO: DriverInfo = DriverInfo {
    name: "drcom",
    title: "Dr.com 城市热点 (Dogcom D/P)",
    transport: Transport::Udp,
    support: SupportLevel::Documented,
    docs: &[3, 14, 23, 30, 2, 1, 9, 10],
};

/// Codec error. Parsers never panic on malformed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The datagram is shorter than the field being read.
    Truncated { what: &'static str, need: usize, got: usize },
    /// Unexpected packet type byte.
    Unexpected { what: &'static str, code: u8 },
    /// Input outside what the protocol allows.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { what, need, got } => write!(f, "{what}: need {need} bytes, got {got}"),
            Error::Unexpected { what, code } => write!(f, "{what}: unexpected type 0x{code:02x}"),
            Error::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

/// Dogcom operating mode (doc 03 §3.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The interface already has an address (DHCP or static); log in over
    /// UDP and keep the session alive (doc 03 §3.2–3.4). Not a DHCP client.
    #[default]
    Dhcp,
    /// pppd has already authenticated; only the Dr.com UDP helper runs
    /// (doc 03 §3.5). It does not replace PAP/CHAP.
    Pppoe,
}

/// Which client implementation to emulate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Variant {
    /// Dogcom 1.6.2 layouts of doc 03. Supported.
    #[default]
    Dogcom,
    /// MentoHUST GS AuthType 3 (D). Refused: online phase graph incomplete.
    GsD,
    /// MentoHUST GS AuthType 4 (X). Refused: needs the 802.1X exchange.
    GsX,
    /// MentoHUST GS AuthType 5 (P). Refused: online tick content unknown.
    GsP,
    /// MentoHUST GS AuthType 6 (Pt). Refused: 244-byte body unspecified.
    GsPt,
}

/// Driver options (`[drcom]` section). Profile fields correspond to the
/// Dogcom configuration keys listed in doc 03 §3.2; they come from the
/// school's profile (usually a capture of the official client), not from
/// this crate. Defaults marked "GS" are the values seen in the doc 30.3
/// replay frames, used only where a neutral value is needed.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Options {
    pub mode: Mode,
    pub variant: Variant,
    /// GS DrMode 0..5 (doc 30.1). Only meaningful for GS variants, which are
    /// refused; must stay 0 for `dogcom`.
    pub dr_mode: u8,
    /// Dr.com server (`server`).
    pub server: Ipv4Addr,
    /// Server UDP port, 61440 (doc 03 §3.1).
    pub server_port: u16,
    /// MAC written into the login (`mac`); default: the interface MAC.
    pub mac: Option<String>,
    /// `host_name`, at most 32 bytes.
    pub host_name: String,
    /// `host_os`, at most 128 bytes of text.
    pub host_os: String,
    /// Raw `host_os` bytes as hex, overriding `host_os` (vendor bytes).
    pub host_os_hex: Option<String>,
    /// `PRIMARY_DNS`; default: the interface DNS.
    pub primary_dns: Option<Ipv4Addr>,
    /// `dhcp_server` written at login offset 146.
    pub dhcp_server: Ipv4Addr,
    /// OSVERSIONINFO (login `[162:182]`); defaults GS (0x94, 6.2.9200, 2).
    pub os_info_size: u32,
    pub os_major: u32,
    pub os_minor: u32,
    pub os_build: u32,
    pub os_platform_id: u32,
    /// `AUTH_VERSION`, 2 bytes hex (e.g. `"2700"`). Required in DHCP mode.
    pub auth_version: Option<String>,
    /// `KEEP_ALIVE_VERSION`, 2 bytes hex. Required in DHCP mode; in PPPoE
    /// mode the server's challenge answer provides it (doc 03 §3.5).
    pub keep_alive_version: Option<String>,
    /// `CONTROLCHECKSTATUS` (default GS 0x20).
    pub control_check_status: u8,
    /// `ADAPTERNUM` (default GS 0x01).
    pub adapter_num: u8,
    /// `IPDOG` (default GS 0x01).
    pub ip_dog: u8,
    /// `ror_version`: append the ROL password extension (password ≤ 16 bytes).
    pub ror_version: bool,
    /// Use the `keepalive1_mod` format (doc 03 §3.3).
    pub keepalive1_mod: bool,
    /// `pppoe_flag`, login96 offset 19. Required in PPPoE mode.
    pub pppoe_flag: Option<u8>,
    /// Receive timeout per request, seconds (doc 03 §3.1: 3).
    pub timeout_secs: u64,
    /// Pause between keepalive rounds, seconds (doc 03: 20 DHCP, ~10 PPPoE).
    pub keepalive_interval_secs: Option<u64>,
    /// Unanswered/failed login rounds before backing off or giving up.
    // doc 03: Dogcom's exact retry count is not specified.
    pub max_retries: u32,
    /// Consecutive keepalive timeouts before logging in again.
    // doc 03 §3.2: failures "accumulate" before re-login; threshold unknown.
    pub keepalive_max_fail: u32,
    /// Keep retrying after `max_retries` (the firmware starts Dogcom with
    /// `-e`, doc 01 §1.3 / doc 03 §3.1). `false`: stop with GaveUp.
    pub eternal: bool,
    /// Wait before a new round after `max_retries` in eternal mode, seconds.
    // doc 03: not specified.
    pub backoff_secs: u64,
}

impl Default for Options {
    fn default() -> Self {
        let os = packet::OsVersion::default();
        Options {
            mode: Mode::Dhcp,
            variant: Variant::Dogcom,
            dr_mode: 0,
            server: Ipv4Addr::UNSPECIFIED,
            server_port: packet::DRCOM_PORT,
            mac: None,
            host_name: "OpenWrt".into(),
            host_os: String::new(),
            host_os_hex: None,
            primary_dns: None,
            dhcp_server: Ipv4Addr::UNSPECIFIED,
            os_info_size: os.info_size,
            os_major: os.major,
            os_minor: os.minor,
            os_build: os.build,
            os_platform_id: os.platform_id,
            auth_version: None,
            keep_alive_version: None,
            control_check_status: 0x20,
            adapter_num: 0x01,
            ip_dog: 0x01,
            ror_version: false,
            keepalive1_mod: false,
            pppoe_flag: None,
            timeout_secs: 3,
            keepalive_interval_secs: None,
            max_retries: 5,
            keepalive_max_fail: 3,
            eternal: true,
            backoff_secs: 30,
        }
    }
}

/// Parses hex such as `"2700"`, `"27 00"`, `"27:00"` or `"0x2700"`.
pub(crate) fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.trim().trim_start_matches("0x").chars().filter(|c| !matches!(c, ' ' | ':' | '-')).collect();
    if clean.len() % 2 != 0 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("“{s}” 不是有效的十六进制字节串"));
    }
    Ok((0..clean.len()).step_by(2).map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_forms() {
        assert_eq!(parse_hex("2700").unwrap(), vec![0x27, 0]);
        assert_eq!(parse_hex("0x0a00").unwrap(), vec![0x0a, 0]);
        assert_eq!(parse_hex("dc:02").unwrap(), vec![0xdc, 2]);
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn info_is_honest() {
        assert_eq!(INFO.name, "drcom");
        assert_eq!(INFO.transport, Transport::Udp);
        assert!(INFO.support.is_experimental());
        assert!(INFO.docs.contains(&3) && INFO.docs.contains(&30));
    }
}
