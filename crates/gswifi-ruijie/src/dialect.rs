//! The Ruijie side of mentorust's session (research docs 17–21, 25), as a
//! [`Dialect`] of the shared 802.1X state machine.

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use gswifi_core::text::gbk;
use gswifi_core::{mac_str, Action, DriverInfo};
use gswifi_eapol::frame::{
    logoff_dest, md5_digest, response_dest, rotating_start_dest, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE,
    EAP_TYPE_NOTIFICATION, MAC_STANDARD, TYPE_EAPOL_LOGOFF, TYPE_EAPOL_START,
};
use gswifi_eapol::{Ctx, Dialect, RequestKind, Stage};
use gswifi_saier::frames as saier;
use log::{debug, info, warn};

use crate::check::mix;
use crate::materials::Materials;
use crate::packets::{self, classic, echo, v4, Checks, ExtFormat, ExtParams};
use crate::udp_heartbeat::{self, UdpHeartbeat, UdpParams};
use crate::{v2, Config, INFO};

/// Heartbeat after Success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Echo {
    /// Ruijie 0xbf frame with the key from the Success frame.
    Keyed(u32),
    /// Success carried no key: the fixed frame mentorust 1.0 sent.
    Legacy,
    /// Saier keepalive (EAPOL type 6).
    Saier,
    /// Plain 802.1X needs none.
    None,
}

pub struct RuijieDialect {
    config: Config,
    /// StartMode in effect (0..3); becomes 2 when a Saier server is detected.
    start_mode: u8,
    /// Client materials for the 0x17/0x4d checks of the MD5 response.
    materials: Option<Materials>,
    /// Classic format switched to V4 because the authenticator is not a
    /// Ruijie switch; decided per round, kept for the next Start (doc 18.7).
    v4: bool,
    echo: Echo,
    echo_seq: u32,
    /// UDP heartbeat parameters from this round's challenge or Success.
    udp_params: Option<UdpParams>,
    /// Last MD5 challenge (UDP heartbeat material row, V4 password seed).
    challenge: Option<[u8; 16]>,
    udp: Option<UdpHeartbeat>,
    udp_deadline: Option<Instant>,
}

impl RuijieDialect {
    pub fn new(config: Config, materials: Option<Materials>) -> Self {
        RuijieDialect {
            start_mode: config.start_mode,
            config,
            materials,
            v4: false,
            echo: Echo::None,
            echo_seq: echo::FIRST_SEQUENCE,
            udp_params: None,
            challenge: None,
            udp: None,
            udp_deadline: None,
        }
    }

    /// The session switched to (or was configured for) Saier.
    pub fn is_saier(&self) -> bool {
        self.start_mode == 2
    }

    /// The current round uses the V4 extended format.
    pub fn is_v4(&self) -> bool {
        self.v4
    }

    fn ext_params<'a>(&self, ctx: &Ctx<'a>) -> ExtParams<'a> {
        ExtParams {
            format: if self.v4 { ExtFormat::V4 } else { self.config.ext_format },
            mac: ctx.mac,
            net: ctx.net,
            dhcp_mode: ctx.dhcp_mode,
            version: self.config.client_version,
        }
    }

    /// Attribute 0x17 for frames that do not answer a challenge.
    fn placeholder(&self) -> Option<[u8; 32]> {
        (!self.v4 && self.config.ext_format == ExtFormat::Classic).then(classic::random_placeholder)
    }

    /// V4 password attribute 0x2f. Start and Logoff have no challenge of
    /// their own; the original then reuses the last one it saw.
    fn password_attribute(&self, ctx: &Ctx, seed: Option<&[u8]>) -> Option<[u8; 16]> {
        if !self.v4 {
            return None;
        }
        let seed: [u8; 16] = match seed {
            Some(seed) => seed.try_into().ok()?,
            None => self.challenge.unwrap_or_default(),
        };
        let c = ctx.credentials;
        v4::password_attribute(c.username.as_bytes(), c.password.as_bytes(), &seed)
    }

    /// Start or Logoff with the extension the format and StartMode call for.
    fn control_packet(&self, ctx: &Ctx, typ: u8, dest: &[u8; 6]) -> Vec<u8> {
        let placeholder = self.placeholder();
        let password = self.password_attribute(ctx, None);
        let p = self.ext_params(ctx);
        let checks = Checks { field17: placeholder.as_ref(), field2f: password.as_ref(), ..Default::default() };
        let ext = packets::control_has_ext(p.format, self.start_mode).then_some((&p, checks));
        packets::build_control_packet(typ, dest, ext, &ctx.mac)
    }

    /// Destination of Identity and MD5 responses; V4 always uses the
    /// standard group address.
    fn reply_dest(&self, server: &[u8; 6]) -> [u8; 6] {
        if self.v4 {
            MAC_STANDARD
        } else {
            response_dest(self.start_mode, self.config.pkt_type, server)
        }
    }

    /// Saier servers ask "User name" (doc 21.2); only switch when StartMode
    /// 0 was configured.
    fn detect_saier(&self, data: &[u8]) -> bool {
        self.config.start_mode == 0 && saier::is_saier_identity(data)
    }

    fn switch_to_saier(&mut self, data: &[u8]) {
        if self.start_mode == 0 && self.detect_saier(data) {
            info!("认证服务器是赛尔，切换到赛尔认证方式");
            self.start_mode = 2;
        }
    }

    /// With the classic format, the first request of a round decides whether
    /// the round uses V4: like MentoHUST GS, when the authenticator's OUI is
    /// not one of Ruijie's (doc 18.7).
    fn choose_format(&mut self, stage: Stage, src: &[u8; 6]) {
        if stage != Stage::Start || self.config.ext_format != ExtFormat::Classic {
            return;
        }
        let v4 = v4::wanted_by(src);
        if v4 && !self.v4 {
            info!("认证服务器 {} 不是锐捷交换机，改用标准算法（V4 扩展格式）认证", mac_str(src));
        } else if !v4 && self.v4 {
            info!("认证服务器 {} 是锐捷交换机，改回 classic 格式", mac_str(src));
        }
        self.v4 = v4;
    }

    /// Both the challenge and the Success may carry the UDP parameters, each
    /// in its own layout (doc 25.2). A complete set replaces the earlier one;
    /// a frame without one leaves it alone.
    fn note_udp_params(&mut self, frame: &[u8], source: udp_heartbeat::Source) {
        if self.is_saier() {
            return;
        }
        match udp_heartbeat::parse_frame(frame, source) {
            Ok(Some(params)) => self.udp_params = Some(params),
            Ok(None) => {}
            Err(e) => debug!("{:?} 报文中的 UDP 心跳参数无法解析: {}", source, e),
        }
    }

    /// V2 for 0x17 and, unless the materials are V2 only, the mix result
    /// for 0x4d (doc 20.2). V4 has no 0x17 and puts the mix result in 0x60 too.
    fn client_checks(&self, seed: &[u8]) -> (Option<[u8; 32]>, Option<[u8; 128]>) {
        let Some(m) = self.materials.as_ref() else { return (None, None) };
        let Ok(seed) = <&[u8; 16]>::try_from(seed) else {
            warn!("MD5 挑战长度为 {}，不是 16，不计算客户端校验", seed.len());
            return (None, None);
        };
        let field4d = (m.check_type != 2).then(|| mix::family_result(self.config.algo_version(), &m.a, &m.b, seed));
        let field17 = (!self.v4).then(|| v2::v2_check(seed, &m.v2_code));
        (field17, field4d)
    }

    /// Announcement after the 28 byte header, the server message and a fixed
    /// block; preceded by its length + 2.
    fn print_notice(frame: &[u8]) {
        let Some(m) = frame.get(27).map(|&b| b as usize) else { return };
        let offset = 28 + m + 0x69 + 39;
        let (Some(&len), true) = (frame.get(offset - 1), offset < frame.len()) else { return };
        let len = (len as usize).saturating_sub(2).min(frame.len() - offset);
        let msg = gbk(&frame[offset..offset + len]);
        if msg.is_empty() {
            return;
        }
        if msg.starts_with('\n') || msg.starts_with('\r') {
            info!("系统公告：{}", msg)
        } else {
            info!("系统公告：\n{}", msg)
        }
    }

    fn udp_action(&mut self, now: Instant) -> Option<Action> {
        let udp = self.udp.as_mut()?;
        self.udp_deadline = Some(now + Duration::from_secs(udp.interval() as u64));
        let payload = udp.next_payload()?;
        Some(Action::SendUdp { local_port: udp.src_port(), to: udp.server(), payload })
    }
}

impl Dialect for RuijieDialect {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    /// Start goes to the configured address first, then alternates
    /// Ruijie group → broadcast → standard group (doc 21.3).
    fn start(&mut self, ctx: &Ctx, attempt: u32) -> Vec<u8> {
        if self.is_saier() {
            saier::build_control_packet(TYPE_EAPOL_START, &ctx.mac)
        } else {
            self.control_packet(ctx, TYPE_EAPOL_START, &rotating_start_dest(self.start_mode, attempt))
        }
    }

    fn classify(&mut self, ctx: &Ctx, src: &[u8; 6], kind: u8, data: &[u8]) -> RequestKind {
        if matches!(kind, EAP_TYPE_IDENTITY | EAP_TYPE_NOTIFICATION | saier::EAP_TYPE_IDENTITY_20)
            && !self.is_saier()
            && !self.detect_saier(data)
        {
            self.choose_format(ctx.stage, src);
        }
        match kind {
            EAP_TYPE_IDENTITY => {
                self.switch_to_saier(data);
                RequestKind::Identity
            }
            saier::EAP_TYPE_IDENTITY_20 if self.detect_saier(data) => {
                self.switch_to_saier(data);
                RequestKind::Identity
            }
            EAP_TYPE_MD5_CHALLENGE => RequestKind::Challenge,
            EAP_TYPE_NOTIFICATION | saier::EAP_TYPE_MESSAGE => RequestKind::Notification,
            _ => RequestKind::Unsupported,
        }
    }

    fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, _data: &[u8]) -> Vec<u8> {
        let username = ctx.credentials.username.as_bytes();
        if self.is_saier() {
            return saier::build_identity_packet(&ctx.mac, ctx.net, username, id);
        }
        let dest = self.reply_dest(src);
        let placeholder = self.placeholder();
        packets::build_identity_packet(&dest, &self.ext_params(ctx), placeholder.as_ref(), username, id)
    }

    fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], frame: &[u8]) -> Vec<u8> {
        self.note_udp_params(frame, udp_heartbeat::Source::Challenge);
        self.echo_seq = echo::FIRST_SEQUENCE;
        self.challenge = seed.get(..16).map(|c| c.try_into().unwrap());
        let c = ctx.credentials;
        if self.is_saier() {
            return saier::build_password_packet(&ctx.mac, c.username.as_bytes(), c.password.as_bytes(), seed, id);
        }
        let dest = self.reply_dest(src);
        let digest = md5_digest(id, c.password.as_bytes(), b"", seed);
        let (field17, field4d) = self.client_checks(seed);
        let password = self.password_attribute(ctx, Some(seed));
        let checks = Checks { field17: field17.as_ref(), field4d: field4d.as_ref(), field2f: password.as_ref() };
        packets::build_password_packet(&dest, &self.ext_params(ctx), checks, c.username.as_bytes(), &digest, id)
    }

    fn success(&mut self, _ctx: &Ctx, frame: &[u8]) -> u32 {
        self.note_udp_params(frame, udp_heartbeat::Source::Success);
        Self::print_notice(frame);
        let (echo, interval) = if self.is_saier() {
            (Echo::Saier, 0)
        } else if self.config.ext_format == ExtFormat::None {
            (Echo::None, 0)
        } else {
            match echo::parse_success(frame, 0) {
                Some(info) => {
                    debug!("心跳参数: key = {:08x}, 间隔 = {}s, flag = {}", info.key, info.interval, info.flag);
                    (Echo::Keyed(info.key), info.interval)
                }
                None => (Echo::Legacy, 0),
            }
        };
        self.echo = echo;
        interval
    }

    fn keepalive(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        let server = ctx.server?;
        let dest = response_dest(self.start_mode, self.config.pkt_type, &server);
        match self.echo {
            Echo::Keyed(key) => {
                let frame = echo::build_echo_packet(&dest, &ctx.mac, key, self.echo_seq);
                self.echo_seq = self.echo_seq.wrapping_add(1);
                Some(frame)
            }
            Echo::Legacy => Some(packets::build_legacy_heartbeat_packet(&dest, &ctx.mac)),
            Echo::Saier => Some(saier::build_control_packet(saier::TYPE_KEEPALIVE, &ctx.mac)),
            Echo::None => None,
        }
    }

    fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
        let server = ctx.server?;
        Some(if self.is_saier() {
            saier::build_control_packet(TYPE_EAPOL_LOGOFF, &ctx.mac)
        } else if self.v4 {
            self.control_packet(ctx, TYPE_EAPOL_LOGOFF, &MAC_STANDARD)
        } else {
            let dest = logoff_dest(self.start_mode, self.config.pkt_type, &server);
            self.control_packet(ctx, TYPE_EAPOL_LOGOFF, &dest)
        })
    }

    /// The heartbeat socket of the original client uses TTL 128 (mentorust).
    fn udp_ttl(&self) -> Option<u32> {
        Some(128)
    }

    fn on_online(&mut self, ctx: &Ctx, now: Instant) -> Vec<Action> {
        if self.udp.is_some() || self.is_saier() {
            return Vec::new();
        }
        let Some(params) = self.udp_params.clone() else { return Vec::new() };
        if !self.config.udp_heartbeat {
            info!(
                "服务器要求 UDP 心跳 ({}，间隔 {}s)；若认证后过一段时间掉线，可尝试开启 udp_heartbeat（实验性）",
                params.server, params.interval
            );
            return Vec::new();
        }
        let Some(challenge) = self.challenge else { return Vec::new() };
        let interval = params.interval;
        let server: SocketAddrV4 = params.server;
        let udp = UdpHeartbeat::new(
            params,
            ctx.credentials.username.as_bytes(),
            ctx.net.ip,
            ctx.mac,
            self.config.algo_version(),
            challenge,
        );
        info!("开始发送 UDP 心跳到 {}，间隔 {}s（实验性）", server, interval);
        self.udp = Some(udp);
        self.udp_deadline = Some(now + Duration::from_secs(interval as u64));
        Vec::new()
    }

    fn deadline(&self) -> Option<Instant> {
        self.udp.as_ref().and(self.udp_deadline)
    }

    fn on_timer(&mut self, _ctx: &Ctx, now: Instant) -> Vec<Action> {
        self.udp_action(now).into_iter().collect()
    }

    fn on_offline(&mut self) {
        self.echo = Echo::None;
        self.udp_params = None;
        self.udp = None;
        self.udp_deadline = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{driver, Options};
    use gswifi_core::{AuthState, Credentials, Driver, Env, NetInfo};
    use gswifi_eapol::frame::*;

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    /// evidence/p0/success-three-echo.json (same vectors as packets::echo).
    const SUCCESS: &str = "020000000001020000000002888e0100009c030700040000000000044f4b0d0a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f7fbf3fdffffff870000000000";
    const ECHOES: [&str; 3] = [
        "020000000002020000000001888e01bf001effff37777f9ff7fbfd29ffff37777f9ffffff72bffff37777f3fff",
        "020000000002020000000001888e01bf001effff37777f9ff7fbfdc9ffff37777f9ffffff7cbffff37777f3fff",
        "020000000002020000000001888e01bf001effff37777f9ff7fbfd49ffff37777f9ffffff74bffff37777f3fff",
    ];

    fn request(src: [u8; 6], id: u8, kind: u8, data: &[u8]) -> Vec<u8> {
        let len = 5 + data.len() as u16;
        let mut f = eapol_header(&LOCAL, &src, TYPE_EAP_PACKET, len);
        f.extend_from_slice(&[CODE_REQUEST, id]);
        f.extend_from_slice(&len.to_be_bytes());
        f.push(kind);
        f.extend_from_slice(data);
        f
    }

    fn sent(actions: &[Action]) -> Vec<Vec<u8>> {
        actions.iter().filter_map(|a| if let Action::SendFrame(f) = a { Some(f.clone()) } else { None }).collect()
    }

    fn env() -> Env {
        let net =
            NetInfo { ip: [192, 0, 2, 10], mask: [255, 255, 255, 0], gateway: [192, 0, 2, 1], ..Default::default() };
        Env { interface: "eth0".into(), mac: LOCAL, net }
    }

    fn challenge() -> Vec<u8> {
        let mut c = vec![16];
        c.extend(0..16u8);
        c
    }

    /// Modern format: Success key → the three golden heartbeats, on the
    /// interval the server gave (30 s).
    #[test]
    fn modern_session_heartbeats() {
        let mut d = driver(env(), Credentials::new("synthetic", "pw"), Options::default()).unwrap();
        let t = Instant::now();
        let start = sent(&d.start(t));
        assert_eq!(start[0][..6], MAC_STANDARD);
        assert_eq!(start[0].len(), 18, "modern Start carries no extension");
        let id = sent(&d.on_frame(&request(SERVER, 1, EAP_TYPE_IDENTITY, &[]), t));
        assert_eq!(id[0][..6], SERVER);
        assert!(id[0].len() > 18 + 5 + 9, "modern Identity carries the extension");
        let md5 = sent(&d.on_frame(&request(SERVER, 2, EAP_TYPE_MD5_CHALLENGE, &challenge()), t));
        assert_eq!(&md5[0][24..40], &md5_digest(2, b"pw", b"", &challenge()[1..]));
        d.on_frame(&hex_decode(SUCCESS), t);
        assert_eq!(d.state(), AuthState::Online);
        for (i, want) in ECHOES.iter().enumerate() {
            let at = t + Duration::from_secs(30 * (i as u64 + 1));
            assert_eq!(d.next_deadline(), Some(at));
            assert_eq!(sent(&d.on_timer(at)), vec![hex_decode(want)]);
        }
    }

    /// StartMode 0 + "User name": the session continues in Saier frames.
    #[test]
    fn switches_to_saier() {
        let mut d = driver(env(), Credentials::new("synthetic", "pw"), Options::default()).unwrap();
        let t = Instant::now();
        d.start(t);
        let id = sent(&d.on_frame(&request(SERVER, 7, saier::EAP_TYPE_IDENTITY_20, b"User name"), t));
        assert_eq!(id, vec![saier::build_identity_packet(&LOCAL, &env().net, b"synthetic", 7)]);
        assert!(d.dialect().is_saier());
        let md5 = sent(&d.on_frame(&request(SERVER, 8, EAP_TYPE_MD5_CHALLENGE, &challenge()), t));
        assert_eq!(md5, vec![saier::build_password_packet(&LOCAL, b"synthetic", b"pw", &challenge()[1..], 8)]);
    }

    /// Classic format against a non-Ruijie authenticator switches the round
    /// to V4 (doc 18.7): Identity without extension, to the group address.
    #[test]
    fn classic_switches_to_v4_on_foreign_switch() {
        let opts = Options { ext_format: "classic".into(), ..Options::default() };
        let mut d = driver(env(), Credentials::new("synthetic", "pw"), opts).unwrap();
        let t = Instant::now();
        d.start(t);
        let foreign = [0x02, 0x11, 0x22, 0x00, 0x00, 0x02];
        assert!(v4::wanted_by(&foreign));
        let id = sent(&d.on_frame(&request(foreign, 1, EAP_TYPE_IDENTITY, &[]), t));
        assert!(d.dialect().is_v4());
        assert_eq!(id, vec![identity_response(&MAC_STANDARD, &LOCAL, 1, b"synthetic")]);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
}
