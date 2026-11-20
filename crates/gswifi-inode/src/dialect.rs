//! iNode as a [`gswifi_eapol::Dialect`] (research doc 22, 25.5).
//!
//! Wrap it as `gswifi_eapol::Supplicant::new(InodeDialect::new(opts)?, env,
//! credentials, common)`. The supplicant owns timing, resends and DHCP;
//! the dialect only builds frames.
//!
//! | Stage | Frame | Evidence |
//! |---|---|---|
//! | Start | 18-byte EAPOL-Start to `01:80:c2:00:00:03` (StartMode 0) or broadcast (3) | doc 21.1, 22.3, golden |
//! | Identity | [`crate::eap::identity_data`] | doc 22.3, golden (four switch combinations, no VIF) |
//! | MD5 | standard `16 ‖ MD5(id‖password‖challenge) ‖ username` | doc 22.3, golden |
//! | Success | nothing parsed, no server interval | doc 25.5 |
//! | Online Identity (type 1/20) | [`crate::eap::online_identity_data`], type copied | doc 22.4, golden builder output |
//! | Keepalive | none, see below | doc 25.5 |
//! | Logoff | 18-byte EAPOL-Logoff to the server MAC | doc 22.3, golden |
//!
//! # Deliberately left out
//!
//! * **Keepalive.** The shared GS online entry (`0x411db4`) sends 45-byte
//!   Ruijie style `BF` frames for AuthType 1 while byte `0x447278` is 0
//!   (doc 25.5). Their content depends on a Ruijie key and echo counter
//!   that the AuthType 1 path never establishes (the Ruijie Success parser
//!   is skipped), so the bytes a real iNode session would send are
//!   unknown. [`Dialect::keepalive`] returns `None`. // doc 25.5: unknown
//! * **Online Identity.** The original answers an Identity (type 1) or
//!   type 20 request while online with the special response and stays
//!   online (doc 22.4); this dialect classifies those requests as
//!   [`RequestKind::Answer`], so the session stays online too. Whether the
//!   server follows such a query with a challenge is not documented.
//! * **Raw version response** (`0x41007c`, [`crate::eap::raw_version_data`]): the
//!   request type that triggers it in a real session is not documented
//!   (doc 22.4), so Notification requests are only logged.
//! * **StartMode 1/2.** Mode 1 adds the Ruijie 1000-byte Start extension
//!   and mode 2 switches AuthType 1 to Saier frames (doc 21.1, research
//!   vector `auth-1-2`); neither is iNode. The Start destination rotation
//!   is only measured for mode 1 (doc 21.3), so mode 0/3 keep one address.
//! * **Automatic Saier switch** on a request starting with `User name`
//!   (doc 21.2) is not verified for AuthType 1 and not implemented.

use gswifi_core::DriverInfo;
use gswifi_eapol::frame::{
    control_frame, eapol_header, identity_response, md5_response, CODE_RESPONSE, EAP_TYPE_IDENTITY,
    EAP_TYPE_MD5_CHALLENGE, EAP_TYPE_NOTIFICATION, MAC_BROADCAST, MAC_STANDARD, TYPE_EAPOL_LOGOFF, TYPE_EAPOL_START,
    TYPE_EAP_PACKET,
};
use gswifi_eapol::{Ctx, Dialect, RequestKind};
use log::{info, warn};

use crate::eap::{identity_data, md5_value, online_identity_data, EAP_TYPE_INODE_ONLINE};
use crate::{InodeMaterial, InodeOptions, INFO};

/// Builds a complete EAP-Response frame of `typ` carrying `data`.
pub fn eap_response(dest: &[u8; 6], src: &[u8; 6], id: u8, typ: u8, data: &[u8]) -> Vec<u8> {
    let eap_len = (data.len() + 5) as u16;
    let mut frame = eapol_header(dest, src, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(typ);
    frame.extend_from_slice(data);
    frame
}

/// The iNode 802.1X dialect.
pub struct InodeDialect {
    material: InodeMaterial,
    upload_ver: bool,
    upload_ip: bool,
    start_dest: [u8; 6],
    /// Text version field, computed once per session on first use.
    text: Option<Option<[u8; 32]>>,
    /// Authenticated (between `on_online` and `on_offline`).
    online: bool,
}

impl InodeDialect {
    /// Loads the version material (VIF file etc.) and builds the dialect.
    pub fn new(options: InodeOptions) -> Result<Self, String> {
        let material = InodeMaterial::load(&options).map_err(|e| e.to_string())?;
        Self::with_material(material, &options)
    }

    /// Builds the dialect from already resolved material (no file access).
    pub fn with_material(material: InodeMaterial, options: &InodeOptions) -> Result<Self, String> {
        let start_dest = match options.start_mode {
            0 => MAC_STANDARD,
            3 => MAC_BROADCAST,
            m => {
                return Err(format!(
                    "iNode 只支持 StartMode 0(标准组播) 或 3(广播)，不支持 {}：模式 1 附带锐捷扩展，模式 2 会改发赛尔报文",
                    m
                ))
            }
        };
        if options.upload_ver && material.version_cache.is_none() {
            warn!("没有可用的 iNode 版本(iNode.vif)，Identity 将省略版本字段");
        }
        Ok(InodeDialect {
            material,
            upload_ver: options.upload_ver,
            upload_ip: options.upload_ip,
            start_dest,
            text: None,
            online: false,
        })
    }

    pub fn material(&self) -> &InodeMaterial {
        &self.material
    }

    /// The 32-byte text version field of this session (`None` without a
    /// version). The nonce is fixed on first use.
    pub fn version_text(&mut self, mac: &[u8; 6], username: &[u8]) -> Option<[u8; 32]> {
        if self.text.is_none() {
            let nonce = self.material.nonce_for(mac, username);
            self.text = Some(self.material.version_text(nonce));
        }
        self.text.flatten()
    }
}

impl Dialect for InodeDialect {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    fn start(&mut self, ctx: &Ctx, _attempt: u32) -> Vec<u8> {
        control_frame(&self.start_dest, &ctx.mac, TYPE_EAPOL_START)
    }

    fn classify(&mut self, _ctx: &Ctx, _src: &[u8; 6], kind: u8, _data: &[u8]) -> RequestKind {
        match kind {
            EAP_TYPE_IDENTITY if self.online => {
                info!("服务器在线查询身份，按 iNode 在线格式回复(IP + 版本，不含用户名)");
                RequestKind::Answer
            }
            EAP_TYPE_IDENTITY => RequestKind::Identity,
            EAP_TYPE_INODE_ONLINE if self.online => {
                info!("服务器发送 iNode 在线请求(type 20)，回复 IP + 版本");
                RequestKind::Answer
            }
            EAP_TYPE_MD5_CHALLENGE => RequestKind::Challenge,
            EAP_TYPE_NOTIFICATION => RequestKind::Notification,
            _ => RequestKind::Unsupported,
        }
    }

    fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, _data: &[u8]) -> Vec<u8> {
        let username = ctx.credentials.username.as_bytes();
        let text = self.version_text(&ctx.mac, username);
        let ip = self.upload_ip.then_some(ctx.net.ip);
        let text = if self.upload_ver { text } else { None };
        identity_response(src, &ctx.mac, id, &identity_data(ip, text.as_ref(), username))
    }

    /// Online Identity (type 1) or type 20 request: IP + version, no
    /// username, request type and id copied; the session stays online
    /// (doc 22.4).
    fn answer(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, kind: u8, _data: &[u8]) -> Option<Vec<u8>> {
        let text = self.version_text(&ctx.mac, ctx.credentials.username.as_bytes());
        let data = online_identity_data(kind, ctx.net.ip, text.as_ref());
        Some(eap_response(src, &ctx.mac, id, kind, &data))
    }

    fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], _frame: &[u8]) -> Vec<u8> {
        let digest = md5_value(id, ctx.credentials.password.as_bytes(), seed, 0);
        md5_response(src, &ctx.mac, id, &digest, ctx.credentials.username.as_bytes())
    }

    fn success(&mut self, _ctx: &Ctx, _frame: &[u8]) -> u32 {
        0
    }

    fn keepalive(&mut self, _ctx: &Ctx) -> Option<Vec<u8>> {
        None
    }

    fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        let dest = ctx.server.unwrap_or(self.start_dest);
        Some(control_frame(&dest, &ctx.mac, TYPE_EAPOL_LOGOFF))
    }

    fn on_online(&mut self, _ctx: &Ctx, _now: std::time::Instant) -> Vec<gswifi_core::Action> {
        self.online = true;
        // cleanroom/docs/gaps.md P0-2: say so instead of pretending.
        warn!("在线保活：未知（未验证）。iNode 认证成功后的保活报文尚未还原，不发送保活；服务器在线查询会照常应答，掉线后重新认证");
        Vec::new()
    }

    fn on_offline(&mut self) {
        self.online = false;
    }
}
