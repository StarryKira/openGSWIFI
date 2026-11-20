//! Saier (赛尔) 802.1X, MentoHUST StartMode 2 (research doc 21.2).
//!
//! Saier is plain EAP-MD5 with a salted digest, a fixed Identity layout and
//! an EAPOL type 6 keepalive, everything sent to the standard group
//! address. The Ruijie driver switches to these frames on its own when a
//! server asks for "User name"; this driver speaks Saier from the start.

pub mod frames;

use gswifi_core::{Credentials, DriverInfo, Env, SupportLevel, Transport};
use gswifi_eapol::frame::{EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE, EAP_TYPE_NOTIFICATION, TYPE_EAPOL_LOGOFF, TYPE_EAPOL_START};
use gswifi_eapol::{Ctx, Dialect, RequestKind, Supplicant};
use serde::Deserialize;

pub static INFO: DriverInfo = DriverInfo {
    name: "saier",
    title: "赛尔 802.1X",
    transport: Transport::Eapol,
    // Frames match the doc 21/25 vectors; mentorust's Saier path has not
    // been reported working on a real campus yet.
    support: SupportLevel::OfflineTested,
    docs: &[21, 25],
};

/// Configuration of the Saier driver: only the shared 802.1X settings.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    #[serde(flatten)]
    pub eapol: gswifi_eapol::Options,
}

/// The Saier dialect.
#[derive(Clone, Debug, Default)]
pub struct SaierDialect;

impl Dialect for SaierDialect {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    fn start(&mut self, ctx: &Ctx, _attempt: u32) -> Vec<u8> {
        frames::build_control_packet(TYPE_EAPOL_START, &ctx.mac)
    }

    fn classify(&mut self, _ctx: &Ctx, _src: &[u8; 6], kind: u8, data: &[u8]) -> RequestKind {
        match kind {
            EAP_TYPE_IDENTITY => RequestKind::Identity,
            frames::EAP_TYPE_IDENTITY_20 if frames::is_saier_identity(data) => RequestKind::Identity,
            EAP_TYPE_MD5_CHALLENGE => RequestKind::Challenge,
            EAP_TYPE_NOTIFICATION | frames::EAP_TYPE_MESSAGE => RequestKind::Notification,
            _ => RequestKind::Unsupported,
        }
    }

    fn identity(&mut self, ctx: &Ctx, _src: &[u8; 6], id: u8, _data: &[u8]) -> Vec<u8> {
        frames::build_identity_packet(&ctx.mac, ctx.net, ctx.credentials.username.as_bytes(), id)
    }

    fn challenge(&mut self, ctx: &Ctx, _src: &[u8; 6], id: u8, seed: &[u8], _frame: &[u8]) -> Vec<u8> {
        let c = ctx.credentials;
        frames::build_password_packet(&ctx.mac, c.username.as_bytes(), c.password.as_bytes(), seed, id)
    }

    fn success(&mut self, _ctx: &Ctx, _frame: &[u8]) -> u32 {
        0
    }

    fn keepalive(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        Some(frames::build_control_packet(frames::TYPE_KEEPALIVE, &ctx.mac))
    }

    fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        Some(frames::build_control_packet(TYPE_EAPOL_LOGOFF, &ctx.mac))
    }
}

/// A Saier session.
pub fn driver(env: Env, credentials: Credentials, options: Options) -> Result<Supplicant<SaierDialect>, String> {
    Supplicant::new(SaierDialect, env, credentials, options.eapol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gswifi_core::{Action, AuthState, Driver, NetInfo};
    use gswifi_eapol::frame::*;
    use std::time::{Duration, Instant};

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn request(id: u8, kind: u8, data: &[u8]) -> Vec<u8> {
        let len = 5 + data.len() as u16;
        let mut f = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, len);
        f.extend_from_slice(&[CODE_REQUEST, id]);
        f.extend_from_slice(&len.to_be_bytes());
        f.push(kind);
        f.extend_from_slice(data);
        f
    }

    fn sent(actions: &[Action]) -> Vec<Vec<u8>> {
        actions.iter().filter_map(|a| if let Action::SendFrame(f) = a { Some(f.clone()) } else { None }).collect()
    }

    #[test]
    fn saier_session() {
        let net = NetInfo { ip: [192, 0, 2, 10], mask: [255, 255, 255, 0], gateway: [192, 0, 2, 1], ..Default::default() };
        let env = Env { interface: "eth0".into(), mac: LOCAL, net };
        let mut d = driver(env, Credentials::new("synthetic", "pw"), Options::default()).unwrap();
        let t = Instant::now();
        assert_eq!(sent(&d.start(t)), vec![frames::build_control_packet(TYPE_EAPOL_START, &LOCAL)]);
        let a = d.on_frame(&request(7, frames::EAP_TYPE_IDENTITY_20, b"User name"), t);
        assert_eq!(sent(&a), vec![frames::build_identity_packet(&LOCAL, &net, b"synthetic", 7)]);
        let mut challenge = vec![16];
        challenge.extend(0..16u8);
        let a = d.on_frame(&request(8, EAP_TYPE_MD5_CHALLENGE, &challenge), t);
        assert_eq!(sent(&a), vec![frames::build_password_packet(&LOCAL, b"synthetic", b"pw", &challenge[1..], 8)]);
        let mut success = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 4);
        success.extend_from_slice(&[CODE_SUCCESS, 8, 0, 4]);
        d.on_frame(&success, t);
        assert_eq!(d.state(), AuthState::Online);
        let a = d.on_timer(t + Duration::from_secs(30));
        assert_eq!(sent(&a), vec![frames::build_control_packet(frames::TYPE_KEEPALIVE, &LOCAL)]);
        let a = d.logoff(t + Duration::from_secs(31));
        assert_eq!(sent(&a), vec![frames::build_control_packet(TYPE_EAPOL_LOGOFF, &LOCAL)]);
    }
}
