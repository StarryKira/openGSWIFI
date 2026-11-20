//! 安朗 (Anlang) UDP authentication client: a clean-room reimplementation of
//! the GSWIFI AC2100 firmware's `/bin/atclient` (Version 2.0.0, protocol
//! identifier 4.2.0), written from research doc 04 and the independent
//! Python reference `reference/atcodec.py`.
//!
//! * [`codec`]: byte permutation, digest framing, TLVs, request builders and
//!   response parsers (doc 04.2–04.6), checked against the reference's golden
//!   vectors.
//! * [`AnlangDriver`]: sans-IO session state machine: discovery, service
//!   query, login, heartbeat (doc 04, doc 01.3).
//! * [`eap_username`]: identity format of the separate 安朗 802.1X mode
//!   (MentoHUST AuthType 7, doc 14.5), for the EAPOL engine.
//!
//! The protocol has no confidentiality: the login password is sent as plain
//! bytes under a fixed, keyless bit permutation (doc 04.3). The digest is
//! keyless too: it detects corruption and proves nothing about who sent the
//! packet.

#![forbid(unsafe_code)]

pub mod codec;
mod driver;
mod eap;
#[cfg(test)]
mod testjson;

use gswifi_core::{DriverInfo, SupportLevel, Transport};

pub use codec::ResponseCheck;
pub use driver::{AnlangDriver, Options};
pub use eap::{eap_username, EAP_USERNAME_MAX};

/// Static description of the driver.
///
/// `OfflineTested`: every request matches the reference's golden vectors
/// byte for byte, and the state machine passes a scripted fake server. The
/// vectors are synthetic and the reply layouts are partly unknown (doc
/// 04.5, 04.7, doc 10.2 AT-01): there has been no lab server and no campus
/// login, so this is not `LabTested` (doc 09.9 rates 安朗 offline-tested).
pub const INFO: DriverInfo = DriverInfo {
    name: "anlang",
    title: "安朗 UDP (atclient)",
    transport: Transport::Udp,
    support: SupportLevel::OfflineTested,
    docs: &[1, 4, 9, 10, 14, 22, 25],
};
