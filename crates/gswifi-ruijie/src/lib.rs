//! Ruijie (锐捷) 802.1X, ported from mentorust.
//!
//! The extension after the EAP part comes in three formats
//! ([`packets::ExtFormat`]): `modern` (recent Ruijie clients, what mentorust
//! has always sent), `classic` (MentoHUST's 1000 byte template) and `none`.
//! With `classic`, a non-Ruijie authenticator switches the round to the V4
//! extended format of MentoHUST GS (doc 18.7). Client checks (V2 in 0x17,
//! the mix result in 0x4d/0x60) are computed from the official client files
//! when `data_file` points at them (docs 15, 19, 20, 25). The EAPOL
//! heartbeat uses the key from the Success frame (doc 17); the UDP heartbeat
//! is experimental (doc 20.4).
//!
//! When the server asks for "User name" and StartMode is 0, the session
//! switches to Saier frames (doc 21.2), like MentoHUST.

pub mod check;
pub mod crypt;
mod dialect;
pub mod materials;
pub mod packets;
pub mod udp_heartbeat;
pub mod v2;

use std::path::Path;

use gswifi_core::{Credentials, DriverInfo, Env, SupportLevel, Transport};
use gswifi_eapol::Supplicant;
use log::{info, warn};
use serde::Deserialize;

pub use dialect::RuijieDialect;
use materials::{ClientFiles, Materials};
use packets::{classic, ExtFormat};

pub static INFO: DriverInfo = DriverInfo {
    name: "ruijie",
    title: "锐捷 802.1X",
    transport: Transport::Eapol,
    // The modern format is what mentorust users run on real campuses; the
    // classic/V4 formats and the client checks match the docs' golden
    // vectors but have fewer field reports.
    support: SupportLevel::FieldTested,
    docs: &[15, 17, 18, 19, 20, 21, 25],
};

/// Configuration (MentoHUST names in brackets).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    #[serde(flatten)]
    pub eapol: gswifi_eapol::Options,
    /// 0 standard group `01:80:c2:00:00:03`, 1 Ruijie group
    /// `01:d0:f8:00:00:03`, 2 Saier, 3 broadcast [StartMode]. Default: 1
    /// with DHCP mode 1, otherwise 0.
    pub start_mode: Option<u8>,
    /// 1 sends username/password/heartbeat to the standard group [PktType].
    pub pkt_type: u8,
    /// `modern` (default), `classic` or `none`.
    pub ext_format: String,
    /// Client version written into the classic format, e.g. `3.30`
    /// [Version]. Unset: read from `8021x.exe` next to `data_file`.
    pub client_version: Option<String>,
    /// Client check algorithm version [RjCheckVersion]; default follows the
    /// client version.
    pub check_version: Option<String>,
    /// Directory (or a file in it) of the official client files
    /// `8021x.exe`, `W32N55.dll`, `SuConfig.dat` [DataFile].
    pub data_file: Option<String>,
    /// Send the Ruijie UDP heartbeat when the server asks for it
    /// (experimental, not verified on a real campus).
    pub udp_heartbeat: bool,
}

/// [`Options`] validated and with defaults applied.
#[derive(Clone, Debug)]
pub struct Config {
    pub start_mode: u8,
    pub pkt_type: u8,
    pub ext_format: ExtFormat,
    pub client_version: Option<[u8; 2]>,
    pub check_version: Option<[u8; 2]>,
    pub udp_heartbeat: bool,
}

impl Config {
    pub fn from_options(o: &Options) -> Result<Self, String> {
        o.eapol.validate()?;
        let start_mode = o.start_mode.unwrap_or(if o.eapol.dhcp_mode == 1 { 1 } else { 0 });
        if start_mode > 3 {
            return Err(format!("寻找服务器方式 {} 无效，只能是 0~3", start_mode));
        }
        if o.pkt_type > 1 {
            return Err(format!("报文发送方式 {} 无效，只能是 0 或 1", o.pkt_type));
        }
        let ext_format = ExtFormat::parse(&o.ext_format)
            .ok_or_else(|| format!("扩展数据格式 {:?} 无效，只能是 modern、classic 或 none", o.ext_format))?;
        let version = |v: Option<&str>, what: &str| match v {
            None | Some("") => Ok(None),
            Some(v) => classic::parse_version(v).map(Some).ok_or_else(|| format!("{} {:?} 无效，应形如 4.10", what, v)),
        };
        Ok(Config {
            start_mode,
            pkt_type: o.pkt_type,
            ext_format,
            client_version: version(o.client_version.as_deref(), "客户端版本号")?,
            check_version: version(o.check_version.as_deref(), "校验算法版本")?,
            udp_heartbeat: o.udp_heartbeat,
        })
    }

    /// Algorithm version `major*100+minor` of the client checks and the UDP
    /// material table: `check_version`, else the client version (doc 19.1),
    /// else what the format implies.
    pub fn algo_version(&self) -> u32 {
        let [major, minor] = self.check_version.or(self.client_version).unwrap_or(match self.ext_format {
            ExtFormat::Modern => [6, 41],
            _ => [4, 10],
        });
        major as u32 * 100 + minor as u32
    }

    /// Without a configured client version (or with 0.00) the one of
    /// 8021x.exe is used (doc 19.2); an explicit version, even 0.10, wins.
    /// The check version then follows it unless configured itself.
    pub fn detect_client_version(&mut self, files: &ClientFiles) {
        if self.client_version.is_some_and(|v| v != [0, 0]) || files.exe.is_none() {
            return;
        }
        match files.client_version() {
            Ok(v) => {
                info!("从 8021x.exe 读到客户端版本 {}.{:02}", v[0], v[1]);
                self.client_version = Some(v);
            }
            Err(e) => warn!("无法从 8021x.exe 读取客户端版本（{}），使用默认版本", e),
        }
    }
}

/// Reads the client files, takes the client version from 8021x.exe when
/// none is configured, and builds the materials for the algorithm version.
/// Problems are logged and leave the checks out, as in mentorust.
pub fn load_materials(path: &str, config: &mut Config) -> Option<Materials> {
    if config.ext_format == ExtFormat::None {
        warn!("扩展数据格式为 none，不发送客户端校验，忽略 {}", path);
        return None;
    }
    let files = match ClientFiles::load(Path::new(path)) {
        Ok(files) => files,
        Err(e) => {
            warn!("{}，不计算客户端校验", e);
            return None;
        }
    };
    config.detect_client_version(&files);
    let version = config.algo_version();
    match materials::assemble(&files, version) {
        Ok(m) => {
            info!(
                "已载入客户端校验材料 {}：代码来自{}，算法版本 {}.{:02}，类型 {}，A {} 字节，B {} 字节",
                path,
                m.source,
                version / 100,
                version % 100,
                m.check_type,
                m.a.len(),
                m.b.len()
            );
            Some(m)
        }
        Err(e) => {
            warn!("{}: {}，不计算客户端校验", path, e);
            None
        }
    }
}

/// A Ruijie session. Reads the client files of `data_file`, if any.
pub fn driver(env: Env, credentials: Credentials, options: Options) -> Result<Supplicant<RuijieDialect>, String> {
    let mut config = Config::from_options(&options)?;
    let materials =
        options.data_file.as_deref().filter(|p| !p.trim().is_empty()).and_then(|p| load_materials(p, &mut config));
    info!(
        "认证参数: 寻找服务器方式 {}，报文发送方式 {}，DHCP 模式 {}，扩展格式 {:?}",
        config.start_mode, config.pkt_type, options.eapol.dhcp_mode, config.ext_format
    );
    Supplicant::new(RuijieDialect::new(config, materials), env, credentials, options.eapol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::materials::tests::version_fixture;

    fn config(client: Option<[u8; 2]>, check: Option<[u8; 2]>) -> Config {
        Config {
            start_mode: 0,
            pkt_type: 0,
            ext_format: ExtFormat::Classic,
            client_version: client,
            check_version: check,
            udp_heartbeat: false,
        }
    }

    /// Startup cases of evidence/p0/pe-version.log (0x40b7a0).
    #[test]
    fn client_version_from_8021x_exe() {
        let exe = |ver| ClientFiles { exe: Some(version_fixture(ver, true, true, 0x1200)), ..Default::default() };
        let run = |client, check, files: &ClientFiles| {
            let mut c = config(client, check);
            c.detect_client_version(files);
            (c.client_version, c.algo_version())
        };
        // Nothing configured: version and algorithm from the file.
        assert_eq!(run(None, None, &exe(0x0004_000a)), (Some([4, 10]), 410));
        // An explicit version wins, 0.10 included; 0.00 counts as unset.
        assert_eq!(run(Some([3, 30]), None, &exe(0x0004_000a)), (Some([3, 30]), 330));
        assert_eq!(run(Some([0, 10]), None, &exe(0x0004_000a)), (Some([0, 10]), 10));
        assert_eq!(run(Some([0, 0]), None, &exe(0x0004_000a)), (Some([4, 10]), 410));
        // A configured check version stays.
        assert_eq!(run(None, Some([6, 42]), &exe(0x0004_000a)), (Some([4, 10]), 642));
        // No file or no version resource: unchanged.
        assert_eq!(run(None, None, &ClientFiles::default()), (None, 410));
        let no_version =
            ClientFiles { exe: Some(version_fixture(0x0004_000a, true, false, 0x1200)), ..Default::default() };
        assert_eq!(run(None, None, &no_version), (None, 410));
        // A zero resource value is taken as it is.
        assert_eq!(run(None, None, &exe(0)), (Some([0, 0]), 0));
    }

    #[test]
    fn options_defaults_and_validation() {
        let c = Config::from_options(&Options::default()).unwrap();
        assert_eq!((c.start_mode, c.ext_format), (0, ExtFormat::Modern));
        assert_eq!(c.algo_version(), 641);
        let mut o = Options::default();
        o.eapol.dhcp_mode = 1;
        assert_eq!(Config::from_options(&o).unwrap().start_mode, 1);
        o.start_mode = Some(4);
        assert!(Config::from_options(&o).is_err());
        let o = Options { ext_format: "bogus".into(), ..Options::default() };
        assert!(Config::from_options(&o).is_err());
        let o = Options { client_version: Some("x".into()), ..Options::default() };
        assert!(Config::from_options(&o).is_err());
    }
}
