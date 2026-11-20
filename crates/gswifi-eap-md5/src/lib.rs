//! Standard IEEE 802.1X with EAP-MD5 (RFC 3748), no vendor data: what
//! mentorust sends with `--ext-format none` and what most non-Ruijie
//! authenticators accept. MentoHUST's StartMode/PktType addressing is kept
//! because some switches only answer one group address.

use gswifi_core::{Credentials, DriverInfo, Env, SupportLevel, Transport};
use gswifi_eapol::frame::{
    control_frame, identity_response, logoff_dest, md5_digest, md5_response, response_dest, rotating_start_dest,
    EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE, EAP_TYPE_NOTIFICATION, TYPE_EAPOL_LOGOFF, TYPE_EAPOL_START,
};
use gswifi_eapol::{Ctx, Dialect, RequestKind, Supplicant};
use serde::Deserialize;

pub static INFO: DriverInfo = DriverInfo {
    name: "eap-md5",
    title: "标准 802.1X (EAP-MD5)",
    transport: Transport::Eapol,
    // RFC 3748 behaviour, unchanged from mentorust's `none` format which
    // users run on real networks.
    support: SupportLevel::FieldTested,
    docs: &[2, 21],
};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Options {
    #[serde(flatten)]
    pub eapol: gswifi_eapol::Options,
    /// First Start destination: 0 standard group, 1 Ruijie group,
    /// 3 broadcast [StartMode]. The others follow if nobody answers.
    pub start_mode: u8,
    /// 1 sends responses to the standard group instead of the server [PktType].
    pub pkt_type: u8,
}

impl Options {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.start_mode, 0 | 1 | 3) {
            return Err(format!("寻找服务器方式 {} 无效，只能是 0、1 或 3（赛尔请用 saier）", self.start_mode));
        }
        if self.pkt_type > 1 {
            return Err(format!("报文发送方式 {} 无效，只能是 0 或 1", self.pkt_type));
        }
        self.eapol.validate()
    }
}

#[derive(Clone, Debug)]
pub struct EapMd5Dialect {
    start_mode: u8,
    pkt_type: u8,
}

impl Dialect for EapMd5Dialect {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    fn start(&mut self, ctx: &Ctx, attempt: u32) -> Vec<u8> {
        control_frame(&rotating_start_dest(self.start_mode, attempt), &ctx.mac, TYPE_EAPOL_START)
    }

    fn classify(&mut self, _ctx: &Ctx, _src: &[u8; 6], kind: u8, _data: &[u8]) -> RequestKind {
        match kind {
            EAP_TYPE_IDENTITY => RequestKind::Identity,
            EAP_TYPE_MD5_CHALLENGE => RequestKind::Challenge,
            EAP_TYPE_NOTIFICATION => RequestKind::Notification,
            _ => RequestKind::Unsupported,
        }
    }

    fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, _data: &[u8]) -> Vec<u8> {
        let dest = response_dest(self.start_mode, self.pkt_type, src);
        identity_response(&dest, &ctx.mac, id, ctx.credentials.username.as_bytes())
    }

    fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], _frame: &[u8]) -> Vec<u8> {
        let dest = response_dest(self.start_mode, self.pkt_type, src);
        let digest = md5_digest(id, ctx.credentials.password.as_bytes(), b"", seed);
        md5_response(&dest, &ctx.mac, id, &digest, ctx.credentials.username.as_bytes())
    }

    fn success(&mut self, _ctx: &Ctx, _frame: &[u8]) -> u32 {
        0
    }

    /// Plain 802.1X has no keepalive; the authenticator re-authenticates
    /// with Identity requests when it wants to.
    fn keepalive(&mut self, _ctx: &Ctx) -> Option<Vec<u8>> {
        None
    }

    fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        let server = ctx.server?;
        Some(control_frame(&logoff_dest(self.start_mode, self.pkt_type, &server), &ctx.mac, TYPE_EAPOL_LOGOFF))
    }
}

/// A standard EAP-MD5 session.
pub fn driver(env: Env, credentials: Credentials, options: Options) -> Result<Supplicant<EapMd5Dialect>, String> {
    options.validate()?;
    let dialect = EapMd5Dialect { start_mode: options.start_mode, pkt_type: options.pkt_type };
    Supplicant::new(dialect, env, credentials, options.eapol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gswifi_core::{Action, AuthState, Driver, NetInfo, Stop};
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

    fn new(opts: Options) -> Supplicant<EapMd5Dialect> {
        let env = Env { interface: "eth0".into(), mac: LOCAL, net: NetInfo::default() };
        driver(env, Credentials::new("user", "pass"), opts).unwrap()
    }

    #[test]
    fn standard_exchange() {
        let mut d = new(Options::default());
        let t = Instant::now();
        assert_eq!(sent(&d.start(t)), vec![control_frame(&MAC_STANDARD, &LOCAL, TYPE_EAPOL_START)]);
        // Unanswered Starts rotate the destination.
        assert_eq!(sent(&d.on_timer(t + Duration::from_secs(8)))[0][..6], MAC_RUIJIE);
        let a = d.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        assert_eq!(sent(&a), vec![identity_response(&SERVER, &LOCAL, 1, b"user")]);
        let mut c = vec![16];
        c.extend_from_slice(&[7; 16]);
        let a = d.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &c), t);
        let digest = md5_digest(2, b"pass", b"", &[7; 16]);
        assert_eq!(sent(&a), vec![md5_response(&SERVER, &LOCAL, 2, &digest, b"user")]);
        let mut ok = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 4);
        ok.extend_from_slice(&[CODE_SUCCESS, 2, 0, 4]);
        d.on_frame(&ok, t);
        assert_eq!(d.state(), AuthState::Online);
        // No keepalive frames.
        assert!(sent(&d.on_timer(t + Duration::from_secs(30))).is_empty());
        let a = d.logoff(t);
        assert_eq!(sent(&a), vec![control_frame(&SERVER, &LOCAL, TYPE_EAPOL_LOGOFF)]);
        assert_eq!(a.last(), Some(&Action::Stop(Stop::Finished)));
    }

    #[test]
    fn group_responses_with_pkt_type_1() {
        let mut d = new(Options { pkt_type: 1, ..Options::default() });
        let t = Instant::now();
        d.start(t);
        assert_eq!(sent(&d.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t))[0][..6], MAC_STANDARD);
    }

    #[test]
    fn rejects_saier_start_mode() {
        let env = Env::default();
        assert!(driver(env, Credentials::default(), Options { start_mode: 2, ..Options::default() }).is_err());
    }
}
