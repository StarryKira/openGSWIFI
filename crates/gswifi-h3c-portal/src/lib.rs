//! GS H3C Portal over UDP (MentoHUST 0.3.9-GS AuthType 2).
//!
//! A GS-specific "version 2" Portal with message types 100..123, a 32-byte
//! header, iNode version data in the login and five client check families
//! (research doc 13, 23, 29). It is not the browser Portal and not the
//! standard Huawei/CMCC Portal 1..8.
//!
//! * [`codec`]: header, attributes, authenticator, every client message,
//!   the password block transform, the 130 → 131 checks and the receive
//!   dispatch.
//! * [`H3cPortalDriver`]: the sans-IO session — discovery (110) → login
//!   (100) → challenge response (122) → online keepalive (104) → logoff
//!   (102), with the GS resend schedule (doc 29.4).

pub mod codec;
mod driver;

use gswifi_core::{DriverInfo, SupportLevel, Transport};

pub use driver::{H3cPortalDriver, Options};

/// Driver description for `gswifi drivers`.
///
/// `OfflineTested`: the driver replays the complete doc 29 exchange
/// (110, 100, 122, 104 ×3, 102) byte for byte against the original GS
/// payloads, and every codec piece matches the original functions (doc
/// 29.5 checks, doc 13 builders). The server side of those runs was
/// synthetic, so nothing is known about real servers yet (doc 29.7).
pub const INFO: DriverInfo = DriverInfo {
    name: "h3c-portal",
    title: "H3C Portal UDP (MentoHUST AuthType 2)",
    transport: Transport::Udp,
    support: SupportLevel::OfflineTested,
    docs: &[13, 23, 29],
};
