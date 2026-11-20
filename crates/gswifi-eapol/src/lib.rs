//! IEEE 802.1X for Open GSWIFI.
//!
//! [`frame`] has the EAPOL/EAP constants and builders every 802.1X family
//! shares. [`Supplicant`] is the session state machine of MentoHUST /
//! mentorust (research doc 21): Start → Identity → MD5-Challenge → Success
//! → keepalive, with resends, restart waits, re-authentication and the four
//! DHCP modes. What differs between vendors (frame extensions, addresses,
//! keepalive, server detection) is a [`Dialect`]; the Ruijie, Saier,
//! standard EAP-MD5 and iNode crates each provide one.

mod dialect;
pub mod frame;
mod supplicant;

pub use dialect::{Ctx, Dialect, RequestKind, Stage};
pub use supplicant::{Options, Supplicant};
