//! Configuration and loaded material of the iNode branch.

use std::path::{Path, PathBuf};

use log::{info, warn};
use serde::Deserialize;

use crate::gsdat::GsData;
use crate::mixed::{mixed, text_field, version_key};
use crate::vif::{cache_from_plain, decode_vif_file};
use crate::InodeError;

/// Where the GS UI stores `iNode.vif` (doc 02.6, UI constants).
pub const DEFAULT_VIF_PATH: &str = "/etc/mentohust/iNode.vif";
/// Where the GS UI stores `inode-gs.dat`.
pub const DEFAULT_DATA_PATH: &str = "/etc/mentohust/inode-gs.dat";

/// iNode settings, shared by the 802.1X dialect and the H3C Portal driver
/// (`[inode]` table). Every field is optional.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct InodeOptions {
    /// `iNode.vif` to decode the client version from. Unset: the GS
    /// default path is tried and a missing file is tolerated (doc 22.5:
    /// the version field is then omitted). A path set here must be
    /// readable and decodable.
    pub vif: Option<PathBuf>,
    /// Version as it appears decoded from a VIF, e.g. `V5.20-0001C`;
    /// overrides `vif` and goes through the same flag/suffix rules
    /// (doc 25.4).
    pub version: Option<String>,
    /// Exact cached version string used verbatim, e.g. `CH V5.20-0001` (the
    /// research vectors) or `"CH\u0012V5.20-0001"`. Overrides `version`
    /// and `vif`.
    pub version_cache: Option<String>,
    /// Mixing key override. Default: chosen from the cached version
    /// (doc 13.3, [`crate::mixed::version_key`]).
    pub key: Option<String>,
    /// Fixed nonce `q` of the version mixing. The original uses
    /// `low32(time(NULL) * rand())`; drivers do not read the clock, so the
    /// default is [`default_nonce`] of MAC and username.
    pub nonce: Option<u32>,
    /// Send the 32-byte version field in Identity (`UploadVer`, default on).
    pub upload_ver: bool,
    /// Send the 6-byte IP field in Identity (`UploadIP`, default on).
    pub upload_ip: bool,
    /// `inode-gs.dat` (H3C challenge families 4 and 5, doc 29.5). Unset:
    /// the GS default path, missing tolerated.
    pub data_file: Option<PathBuf>,
    /// MentoHUST StartMode, only 0 (standard group address) and 3
    /// (broadcast) are supported for iNode, see [`crate::dialect`].
    pub start_mode: u8,
}

impl Default for InodeOptions {
    fn default() -> Self {
        InodeOptions {
            vif: None,
            version: None,
            version_cache: None,
            key: None,
            nonce: None,
            upload_ver: true,
            upload_ip: true,
            data_file: None,
            start_mode: 0,
        }
    }
}

/// Default mixing nonce: the first four bytes of
/// `MD5("gswifi-inode" || mac || username)`, big endian. Stable per
/// account and device, so resends and re-authentications reuse it
/// (doc 02.2: do not re-randomise material between resends).
pub fn default_nonce(mac: &[u8; 6], username: &[u8]) -> u32 {
    let mut input = b"gswifi-inode".to_vec();
    input.extend_from_slice(mac);
    input.extend_from_slice(username);
    let d = md5::compute(input).0;
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

fn read_file(path: &Path) -> Result<Vec<u8>, InodeError> {
    std::fs::read(path).map_err(|e| InodeError::Io { path: path.display().to_string(), reason: e.to_string() })
}

/// The version material resolved from [`InodeOptions`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeMaterial {
    /// Cached version string (`CH` + flag + version without its last
    /// character), `None` when no version is available.
    pub version_cache: Option<Vec<u8>>,
    /// Key override from the options.
    pub key: Option<Vec<u8>>,
    /// Nonce override from the options.
    pub nonce: Option<u32>,
}

impl InodeMaterial {
    /// Material from an explicit cache, without touching files.
    pub fn from_cache(version_cache: Option<Vec<u8>>) -> Self {
        InodeMaterial { version_cache, key: None, nonce: None }
    }

    /// Resolves the version in the order `version_cache` > `version` >
    /// `vif` > default VIF path (doc 25.4, 22.5). Reads at most one file.
    pub fn load(opts: &InodeOptions) -> Result<Self, InodeError> {
        let version_cache = if let Some(cache) = &opts.version_cache {
            if cache.is_empty() {
                return Err(InodeError::Invalid("version_cache 为空"));
            }
            Some(cache.as_bytes().to_vec())
        } else if let Some(version) = &opts.version {
            Some(cache_from_plain(version.as_bytes())?)
        } else if let Some(path) = &opts.vif {
            Some(decode_vif_file(&read_file(path)?)?)
        } else {
            match std::fs::read(DEFAULT_VIF_PATH) {
                Ok(data) => Some(decode_vif_file(&data)?),
                Err(e) => {
                    warn!("读取 {} 失败({})，不上传 iNode 版本号", DEFAULT_VIF_PATH, e);
                    None
                }
            }
        };
        if let Some(cache) = &version_cache {
            info!("iNode 版本：{}", String::from_utf8_lossy(cache).replace(|c: char| c.is_control(), "?"));
        }
        let key = match &opts.key {
            Some(k) if k.is_empty() => return Err(InodeError::Invalid("版本混合密钥为空")),
            Some(k) => Some(k.as_bytes().to_vec()),
            None => None,
        };
        Ok(InodeMaterial { version_cache, key, nonce: opts.nonce })
    }

    /// Key used for the mixing: the override or the one the cache selects.
    pub fn mixing_key(&self) -> &[u8] {
        match (&self.key, &self.version_cache) {
            (Some(k), _) => k,
            (None, Some(c)) => version_key(c),
            (None, None) => crate::mixed::KEY_OLD,
        }
    }

    /// The nonce to use: the override, else [`default_nonce`].
    pub fn nonce_for(&self, mac: &[u8; 6], username: &[u8]) -> u32 {
        self.nonce.unwrap_or_else(|| default_nonce(mac, username))
    }

    /// `mixed20` for `nonce`, `None` without a version.
    pub fn mixed(&self, nonce: u32) -> Option<[u8; 20]> {
        let cache = self.version_cache.as_ref()?;
        mixed(cache, nonce, self.mixing_key()).ok()
    }

    /// The 32-byte text version field for `nonce`, `None` without a version.
    pub fn version_text(&self, nonce: u32) -> Option<[u8; 32]> {
        self.mixed(nonce).map(|m| text_field(&m))
    }
}

/// Loads `inode-gs.dat` from `opts.data_file` (must exist) or the GS
/// default path (missing tolerated → `None`).
pub fn load_gs_data(opts: &InodeOptions) -> Result<Option<GsData>, InodeError> {
    let data = match &opts.data_file {
        Some(path) => read_file(path)?,
        None => match std::fs::read(DEFAULT_DATA_PATH) {
            Ok(data) => data,
            Err(_) => return Ok(None),
        },
    };
    GsData::parse(&data).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_without_files() {
        let opts = InodeOptions {
            version: Some("V5.20-0001C".into()),
            version_cache: Some("CH V5.20-0001".into()),
            ..InodeOptions::default()
        };
        let m = InodeMaterial::load(&opts).unwrap();
        assert_eq!(m.version_cache.as_deref(), Some(&b"CH V5.20-0001"[..]));
        let opts = InodeOptions { version: Some("V5.20-0001C".into()), ..InodeOptions::default() };
        let m = InodeMaterial::load(&opts).unwrap();
        assert_eq!(m.version_cache.as_deref(), Some(&b"CH\x12V5.20-0001"[..]));
        assert_eq!(m.mixing_key(), crate::mixed::KEY_V3);
    }

    #[test]
    fn explicit_missing_files_are_errors() {
        let opts = InodeOptions { vif: Some("/nonexistent/iNode.vif".into()), ..InodeOptions::default() };
        assert!(matches!(InodeMaterial::load(&opts), Err(InodeError::Io { .. })));
        let opts = InodeOptions { data_file: Some("/nonexistent/inode-gs.dat".into()), ..InodeOptions::default() };
        assert!(matches!(load_gs_data(&opts), Err(InodeError::Io { .. })));
    }

    #[test]
    fn nonce_is_stable() {
        let mac = [2, 0, 0, 0, 0, 1];
        assert_eq!(default_nonce(&mac, b"u"), default_nonce(&mac, b"u"));
        assert_ne!(default_nonce(&mac, b"u"), default_nonce(&mac, b"v"));
    }
}
