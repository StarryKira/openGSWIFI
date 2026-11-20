//! Regional web Portals of the GSWIFI firmware: 湖北 Aidc WISPr (old Mac,
//! new Mac, Android) and 云南 NetKeeper WISPr (Web, PPPoE), written from the
//! clean-room specifications cleanroom/08 and cleanroom/07 and the
//! 2026-11-20 gap-closure vectors, without reading firmware.
//!
//! Pure modules:
//! * [`hubei`]: old-Mac FixHBKey and RC4/MD5 password chain (evidence grade
//!   D, every golden vector is a unit test), login form, profile names.
//! * [`discovery`]: probe classification, redirect parameters
//!   (`userip`/`wlanacname`/`nasip`/`usermac`/`aidcauthtype`,
//!   `wlanuserip`) and entry URLs, on a standard URL parser ([`url`]).
//! * [`wispr`]: `WISPAccessGatewayParam` messages over a DTD-free XML
//!   reader ([`xml`]) and login result classification.
//! * [`yunnan`]: the Yunnan constants, form templates and heartbeat format.
//! * [`walltime`]: MMDD in a fixed UTC offset, HTTP `Date` parsing.
//!
//! Drivers: [`HubeiOldMacDriver`] runs; [`HubeiNewMacDriver`],
//! [`HubeiAndroidDriver`], [`YunnanWebDriver`] and [`YunnanPppoeDriver`]
//! always refuse to build, naming what is missing.
//!
//! # Open gaps (see `docs/gaps.md` of the clean-room pack)
//! * Hubei old Mac vendor heartbeat (cleanroom/08 §1.3): `type` value, URL,
//!   interval, method/Content-Type and UUID source unknown, so not sent.
//! * Hubei old Mac password chain when an RC4 output contains 0x00: hashed
//!   at full length like the reference; no vector shows whether the firmware
//!   stops at the NUL ([`hubei::OldMacPassword::rc4_output_had_nul`]).
//! * Which response's `Date` the firmware uses for MMDD, and its tolerance
//!   (docs/05 §5.3, gaps.md).
//! * Aidc `ResponseCode` values and the per-stage header table (whether
//!   `ClientVersion` goes on every request, the User-Agent) are not in the
//!   evidence.
//! * Hubei new Mac, Android and both Yunnan profiles: derivations not closed.
//!
//! Passwords and every derived value are secrets: they are never logged,
//! and their types redact `Debug` (clean-room rule 2).

#![forbid(unsafe_code)]

mod cookies;
pub mod discovery;
mod driver;
pub mod hubei;
#[cfg(test)]
mod testjson;
mod unclosed;
pub mod url;
pub mod walltime;
pub mod wispr;
pub mod xml;
pub mod yunnan;

use gswifi_core::{DriverInfo, SupportLevel, Transport};

pub use driver::{HubeiOldMacDriver, PortalOptions, WallClock};
pub use hubei::HubeiProfile;
pub use unclosed::{
    HubeiAndroidDriver, HubeiNewMacDriver, YunnanPppoeDriver, YunnanWebDriver, HUBEI_ANDROID_MISSING,
    HUBEI_NEW_MAC_MISSING, YUNNAN_PPPOE_MISSING, YUNNAN_WEB_MISSING,
};

/// Research docs every profile follows: 01 (inventory §1.3), 05 (regional
/// portals), 10 (validation gaps HB-01..03, YN-01).
const DOCS: &[u8] = &[1, 5, 10];

/// 湖北 old Mac (`hubei_mac_web_old`, UCI `usecapture=0` per
/// `hubei-service.sh`).
///
/// `Documented`: the credential derivation reproduces the firmware's own
/// golden vectors (grade D) and the state machine passes a scripted fake
/// server, but there are no vectors for the exchange as a whole, the
/// success code comes from the public WISPr BCP rather than firmware
/// evidence, and the vendor heartbeat is not implemented (cleanroom/08
/// §1.3). Not `OfflineTested` until a session sample confirms the exchange.
pub const INFO_HUBEI_OLD_MAC: DriverInfo = DriverInfo {
    name: "portal-hubei-old-mac",
    title: "湖北 Aidc Portal 旧 Mac (hubei_mac_web_old)",
    transport: Transport::Http,
    support: SupportLevel::Documented,
    docs: DOCS,
};

/// 湖北 new Mac (`hubei_mac_web_new`, `usecapture=1`): refuses to build.
pub const INFO_HUBEI_NEW_MAC: DriverInfo = DriverInfo {
    name: "portal-hubei-new-mac",
    title: "湖北 Aidc Portal 新 Mac (hubei_mac_web_new，未闭合，不可用)",
    transport: Transport::Http,
    support: SupportLevel::Documented,
    docs: DOCS,
};

/// 湖北 Android (`hubei_android_web`, `usecapture=2`): refuses to build.
pub const INFO_HUBEI_ANDROID: DriverInfo = DriverInfo {
    name: "portal-hubei-android",
    title: "湖北 Aidc Portal Android (hubei_android_web，未闭合，不可用)",
    transport: Transport::Http,
    support: SupportLevel::Documented,
    docs: DOCS,
};

/// 云南 Web (`adial_yn_web`): refuses to build.
pub const INFO_YUNNAN_WEB: DriverInfo = DriverInfo {
    name: "portal-yunnan-web",
    title: "云南 Portal Web (adial_yn_web，未闭合，不可用)",
    transport: Transport::Http,
    support: SupportLevel::Documented,
    docs: DOCS,
};

/// 云南 PPPoE (`adial_yn_pppoe`): refuses to build.
pub const INFO_YUNNAN_PPPOE: DriverInfo = DriverInfo {
    name: "portal-yunnan-pppoe",
    title: "云南 Portal PPPoE (adial_yn_pppoe，未闭合，不可用)",
    transport: Transport::Pppoe,
    support: SupportLevel::Documented,
    docs: DOCS,
};

/// Every profile of this crate.
pub const ALL_INFO: [&DriverInfo; 5] =
    [&INFO_HUBEI_OLD_MAC, &INFO_HUBEI_NEW_MAC, &INFO_HUBEI_ANDROID, &INFO_YUNNAN_WEB, &INFO_YUNNAN_PPPOE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_explicit() {
        let names: Vec<_> = ALL_INFO.iter().map(|i| i.name).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
        assert!(names.iter().all(|n| n.starts_with("portal-")));
        assert!(ALL_INFO.iter().all(|i| i.support.is_experimental()));
        assert_eq!(INFO_HUBEI_OLD_MAC.transport, Transport::Http);
    }
}
