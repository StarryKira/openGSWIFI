//! H3C iNode 802.1X extensions of MentoHUST 0.3.9-GS (AuthType 1).
//!
//! iNode authentication is ordinary EAP-MD5 over 802.1X plus a few
//! vendor fields. This crate contains every iNode specific piece the
//! research pack recovered, as pure functions, and an
//! [`InodeDialect`] that plugs them into the generic
//! [`gswifi_eapol::Supplicant`].
//!
//! | Module | Content | Research doc |
//! |---|---|---|
//! | [`mixed`] | two-pass XOR, `mixed20` product version, 32-byte text / 22-byte raw fields | 13.2, 13.3 |
//! | [`vif`] | `DecodeINodeP` block cipher, `iNode.vif` → cached version string | 25.4, 22.5 |
//! | [`password`] | the two password XOR helpers (0x41ba24, 0x40cdd4) | 13.4 |
//! | [`gsdat`] | `inode-gs.dat` records (raw or `GSDAT`/RC4 wrapped) | 29.6 |
//! | [`eap`] | bytes iNode puts into the EAP Identity / MD5 / online responses | 22.3, 22.4 |
//! | [`options`] | [`InodeOptions`] and the loaded [`InodeMaterial`] | 22.3, 25.4 |
//! | [`dialect`] | [`InodeDialect`] for the 802.1X engine | 22, 25.5 |
//!
//! # What an 802.1X engine has to do for iNode
//!
//! Compute once per session (doc 02.2: do not re-randomise between resends):
//! `text = material.version_text(nonce)` — `06 07 | Base64(mixed20) | 20 20`,
//! or `None` when no version is available (doc 22.5: the field is then
//! simply omitted, there is no default version string).
//!
//! * **EAPOL-Start**: standard 18-byte frame (doc 22.3).
//! * **Response/Identity** (EAP type 1): the type data is
//!   [`eap::identity_data`]`(upload_ip.then(ip), upload_ver.then(text), username)`
//!   = `[15 04 IPv4] [06 07 Base64(mixed20)28 20 20] username`; the EAP length
//!   covers all of it.
//! * **Response/MD5-Challenge** (type 4): standard, `16 | MD5(id || password
//!   || challenge) | username` ([`eap::md5_response_data`]); no extension.
//! * **Success**: nothing to parse (doc 25.5: the Ruijie Success parser is
//!   skipped for AuthType 1).
//! * **Online Identity re-query** (type 1 or 20 while online, doc 22.4):
//!   [`eap::online_identity_data`] — IP field and text version, *no*
//!   username, a leading `00` for type 20; the response copies the
//!   request's identifier and type. GS stays online afterwards; see
//!   [`dialect`] for how the current engine differs.
//! * **EAPOL-Logoff**: standard 18-byte frame to the server MAC.

pub mod dialect;
pub mod eap;
mod error;
pub mod gsdat;
pub mod mixed;
pub mod options;
pub mod password;
pub mod vif;

use gswifi_core::{Credentials, DriverInfo, Env, SupportLevel, Transport};
use gswifi_eapol::Supplicant;
use serde::Deserialize;

pub use dialect::InodeDialect;
pub use error::InodeError;
pub use gsdat::GsData;
pub use options::{default_nonce, load_gs_data, InodeMaterial, InodeOptions, DEFAULT_DATA_PATH, DEFAULT_VIF_PATH};

/// Driver description for `gswifi drivers`.
///
/// `Documented`, not `OfflineTested`: every frame the dialect builds
/// matches the original GS builders byte for byte (doc 22.3, 22.4) and the
/// online re-query is answered in place like GS, but the keepalive the
/// shared GS online entry sends for AuthType 1 is unspecified (doc 25.5)
/// and no full iNode exchange was ever replayed (doc 22.4).
pub const INFO: DriverInfo = DriverInfo {
    name: "inode",
    title: "H3C iNode 802.1X (MentoHUST AuthType 1)",
    transport: Transport::Eapol,
    support: SupportLevel::Documented,
    docs: &[13, 22, 25, 29],
};

/// Configuration of the iNode driver: the shared 802.1X settings plus
/// [`InodeOptions`], all in one flat table.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    #[serde(flatten)]
    pub eapol: gswifi_eapol::Options,
    #[serde(flatten)]
    pub inode: InodeOptions,
}

/// An iNode 802.1X session. Reads the VIF / data files the options name.
pub fn driver(env: Env, credentials: Credentials, options: Options) -> Result<Supplicant<InodeDialect>, String> {
    Supplicant::new(InodeDialect::new(options.inode)?, env, credentials, options.eapol)
}
