//! The 802.1X session state machine of mentorust (research doc 21), with
//! the I/O taken out: every input returns the actions to perform.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use gswifi_core::text::gbk;
use gswifi_core::{
    mac_str, Action, AuthState, Credentials, Driver, DriverInfo, Env, NetInfo, RejectStage, Requirements, Stop,
};
use log::{debug, error, info, warn};
use serde::Deserialize;

use crate::dialect::{Ctx, Dialect, RequestKind, Stage};
use crate::frame::{self, Received, ETH_P_PAE};

/// Sends per stage: the first one and four repeats (doc 21.3).
const SENDS_PER_STAGE: u32 = 5;
/// Keepalive interval when neither the configuration nor the server sets one.
const DEFAULT_ECHO_INTERVAL: u32 = 30;

/// Settings every 802.1X driver shares (MentoHUST names in brackets).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Seconds to wait for an answer in each stage [Timeout].
    pub timeout: u64,
    /// Keepalive interval; 0 uses the server's value [EchoInterval].
    pub echo_interval: u32,
    /// Seconds to wait after no answer or a drop [RestartWait].
    pub restart_wait: u64,
    /// Rounds without any answer before giving up; -1 never gives up.
    pub max_retries: i32,
    /// 0 none; 1 authenticate, DHCP, authenticate again; 2 DHCP after
    /// authentication; 3 DHCP before authentication [DhcpMode].
    pub dhcp_mode: u8,
    /// Gateway reported to the server instead of the routing table's.
    pub gateway: Option<Ipv4Addr>,
    /// DNS server reported to the server instead of the system's.
    pub dns: Option<Ipv4Addr>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            timeout: 8,
            echo_interval: 0,
            restart_wait: 15,
            max_retries: 3,
            dhcp_mode: 0,
            gateway: None,
            dns: None,
        }
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), String> {
        if self.dhcp_mode > 3 {
            return Err(format!("DHCP 模式 {} 无效，只能是 0~3", self.dhcp_mode));
        }
        Ok(())
    }
}

/// Session context built from disjoint field borrows, so the dialect can
/// be borrowed mutably at the same time.
macro_rules! ctx {
    ($s:expr) => {
        Ctx {
            mac: $s.mac,
            net: &$s.net,
            credentials: &$s.credentials,
            stage: $s.stage,
            dhcp_mode: $s.dhcp_mode,
            server: $s.server,
        }
    };
}

/// What to do once a requested DHCP finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterDhcp {
    /// DhcpMode 3: start the round.
    Start,
    /// DhcpMode 1: log off and authenticate again with the new address.
    Reauthenticate,
    /// DhcpMode 2: go online.
    Online,
}

/// An 802.1X session speaking one [`Dialect`].
pub struct Supplicant<D: Dialect> {
    dialect: D,
    opts: Options,
    credentials: Credentials,
    mac: [u8; 6],
    net: NetInfo,
    dhcp_mode: u8,
    server: Option<[u8; 6]>,
    stage: Stage,
    started: bool,
    stopped: bool,
    pending_dhcp: Option<AfterDhcp>,
    sends: u32,
    last_frame: Vec<u8>,
    deadline: Option<Instant>,
    no_response: u32,
    echo_interval: u32,
    /// The current round was started by the server while online.
    reauth: bool,
    /// Logoff sent or session dropped: a Failure while searching is expected.
    ignore_start_failure: bool,
}

impl<D: Dialect> Supplicant<D> {
    pub fn new(dialect: D, env: Env, credentials: Credentials, opts: Options) -> Result<Self, String> {
        opts.validate()?;
        let mut s = Supplicant {
            dialect,
            dhcp_mode: opts.dhcp_mode,
            echo_interval: opts.echo_interval,
            opts,
            credentials,
            mac: env.mac,
            net: NetInfo::default(),
            server: None,
            stage: Stage::Waiting,
            started: false,
            stopped: false,
            pending_dhcp: None,
            sends: 0,
            last_frame: Vec::new(),
            deadline: None,
            no_response: 0,
            reauth: false,
            ignore_start_failure: false,
        };
        s.set_net(env.net);
        Ok(s)
    }

    pub fn dialect(&self) -> &D {
        &self.dialect
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    fn set_net(&mut self, mut net: NetInfo) {
        if let Some(gw) = self.opts.gateway {
            net.gateway = gw.octets();
        }
        if let Some(dns) = self.opts.dns {
            net.dns = dns.octets();
        }
        self.net = net;
    }

    fn arm(&mut self, now: Instant, secs: u64) {
        self.deadline = Some(now + Duration::from_secs(secs));
    }

    fn stop(&mut self, out: &mut Vec<Action>, stop: Stop) {
        self.stopped = true;
        self.deadline = None;
        self.dialect.on_offline();
        out.push(Action::Stop(stop));
    }

    fn request_dhcp(&mut self, out: &mut Vec<Action>, then: AfterDhcp) {
        info!("DHCP 模式 {}：开始获取 IP 地址", self.dhcp_mode);
        self.dhcp_mode += 3;
        self.pending_dhcp = Some(then);
        self.deadline = None;
        out.push(Action::RequestDhcp);
    }

    // ---- rounds and timer ----

    /// Starts an authentication round from EAPOL-Start (doc 21.4 for DHCP).
    fn begin_round(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.dhcp_mode > 3 {
            self.dhcp_mode -= 3;
        }
        self.stage = Stage::Start;
        self.sends = 0;
        self.server = None;
        self.reauth = false;
        self.dialect.on_offline();
        if self.dhcp_mode == 3 {
            self.request_dhcp(out, AfterDhcp::Start);
            return;
        }
        self.send_start(now, out);
    }

    /// Start goes out up to five times per round; the dialect rotates the
    /// destination (doc 21.3).
    fn send_start(&mut self, now: Instant, out: &mut Vec<Action>) {
        let attempt = self.sends;
        let frame = { self.dialect.start(&ctx!(self), attempt) };
        info!("寻找认证服务器...");
        out.push(Action::SendFrame(frame));
        self.sends += 1;
        self.arm(now, self.opts.timeout.max(1));
    }

    /// Sends the answer of a new stage; the timer repeats it.
    fn enter_stage(&mut self, stage: Stage, frame: Vec<u8>, now: Instant, out: &mut Vec<Action>) {
        self.stage = stage;
        out.push(Action::SendFrame(frame.clone()));
        self.last_frame = frame;
        self.sends = 1;
        self.arm(now, self.opts.timeout.max(1));
    }

    fn no_response(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.no_response += 1;
        let max = self.opts.max_retries;
        if max >= 0 && self.no_response > max as u32 {
            error!("认证失败，重试次数已达上限({})！", max);
            self.stop(out, Stop::GaveUp { rounds: self.no_response });
            return;
        }
        warn!(
            "第{}次认证服务器无响应，{}s后重新认证，直到达到最大{}次限制...",
            self.no_response, self.opts.restart_wait, max
        );
        self.stage = Stage::Waiting;
        self.arm(now, self.opts.restart_wait);
    }

    /// Dropped while online: start over after `restart_wait`.
    fn reconnect(&mut self, now: Instant) {
        warn!("{}s后重新认证...", self.opts.restart_wait);
        self.dialect.on_offline();
        self.ignore_start_failure = true;
        self.stage = Stage::Waiting;
        self.arm(now, self.opts.restart_wait);
    }

    fn go_online(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.stage = Stage::Online;
        self.arm(now, self.echo_interval as u64);
        let actions = self.dialect.on_online(&ctx!(self), now);
        out.extend(actions);
    }

    // ---- received frames ----

    #[allow(clippy::too_many_arguments)]
    fn on_request(
        &mut self,
        src: [u8; 6],
        id: u8,
        kind: u8,
        data: &[u8],
        whole: &[u8],
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let class = { self.dialect.classify(&ctx!(self), &src, kind, data) };
        match class {
            RequestKind::Identity => {
                if self.stage == Stage::Online {
                    info!("认证服务器要求重新认证");
                    self.reauth = true;
                }
                self.server = Some(src);
                let frame = { self.dialect.identity(&ctx!(self), &src, id, data) };
                info!("发送用户名到认证服务器(mac = {}, id = {})...", mac_str(&src), id);
                self.enter_stage(Stage::Identity, frame, now, out);
            }
            RequestKind::Challenge => {
                let Some(&size) = data.first() else { return };
                let Some(seed) = data.get(1..1 + size as usize) else {
                    warn!("MD5 挑战报文不完整，忽略");
                    return;
                };
                if self.stage == Stage::Online {
                    self.reauth = true;
                }
                self.server = Some(src);
                let frame = { self.dialect.challenge(&ctx!(self), &src, id, seed, whole) };
                info!("发送密码到认证服务器(mac = {}, id = {}, seed_len = {})...", mac_str(&src), id, seed.len());
                self.enter_stage(Stage::Md5, frame, now, out);
            }
            RequestKind::Notification => {
                if !data.is_empty() {
                    info!("系统提示：{}", gbk(data));
                }
            }
            RequestKind::Answer => {
                let frame = self.dialect.answer(&ctx!(self), &src, id, kind, data);
                if let Some(frame) = frame {
                    debug!("回复服务器查询(type = {}, id = {})", kind, id);
                    out.push(Action::SendFrame(frame));
                }
            }
            RequestKind::Unsupported => warn!("收到不支持的 EAP 请求类型 {}，忽略", kind),
        }
    }

    fn on_success(&mut self, frame: &[u8], now: Instant, out: &mut Vec<Action>) {
        if self.stage == Stage::Waiting {
            return;
        }
        let first = self.stage != Stage::Online && !self.reauth;
        let server_interval = { self.dialect.success(&ctx!(self), frame) };
        let mut interval = if self.opts.echo_interval != 0 { self.opts.echo_interval } else { server_interval };
        if interval == 0 || interval > 3600 {
            if interval != 0 {
                warn!("服务器给出的心跳间隔 {}s 不合理，改用 {}s", interval, DEFAULT_ECHO_INTERVAL);
            }
            interval = DEFAULT_ECHO_INTERVAL;
        }
        self.echo_interval = interval;

        if first {
            info!("认证成功...欢迎来到互联网世界！");
        } else {
            info!("重新认证成功");
        }
        self.no_response = 0;
        self.reauth = false;
        self.ignore_start_failure = false;

        match self.dhcp_mode {
            1 => self.request_dhcp(out, AfterDhcp::Reauthenticate),
            2 => self.request_dhcp(out, AfterDhcp::Online),
            _ => self.go_online(now, out),
        }
    }

    fn on_failure(&mut self, frame: &[u8], now: Instant, out: &mut Vec<Action>) {
        let message = self.dialect.failure_message(frame).map(|m| gbk(&m)).filter(|m| !m.is_empty());
        if let Some(m) = &message {
            error!("系统提示：{}", m);
        }
        match self.stage {
            Stage::Waiting => {}
            Stage::Online => {
                warn!("报错预测：网络掉线或被踢下线...正在尝试重新连接...");
                self.reconnect(now);
            }
            Stage::Start if self.ignore_start_failure => debug!("忽略寻找服务器阶段的 EAP-Failure"),
            Stage::Identity | Stage::Md5 if self.reauth => {
                warn!("报错预测：网络掉线或被踢下线...正在尝试重新连接...");
                self.reconnect(now);
            }
            Stage::Start => {
                error!("报错预测：寻找认证服务器失败...");
                self.stop(out, Stop::ServerNotFound);
            }
            Stage::Identity => {
                error!("报错预测：\n1，私有扩展数据校验不通过！\n2，用户名错误，请检查用户名是否正确！");
                self.stop(out, Stop::Rejected { stage: RejectStage::Identity, message });
            }
            Stage::Md5 => {
                error!(
                    "报错预测：\n1，账号密码错误，请检查密码是否正确！\n2，MAC地址绑定错误，请解绑已绑定的MAC地址！"
                );
                self.stop(out, Stop::Rejected { stage: RejectStage::Password, message });
            }
        }
    }

    fn send_keepalive(&mut self, out: &mut Vec<Action>) {
        if self.server.is_none() {
            return;
        }
        let frame = { self.dialect.keepalive(&ctx!(self)) };
        if let Some(frame) = frame {
            debug!("发送心跳包");
            out.push(Action::SendFrame(frame));
        }
    }
}

impl<D: Dialect> Driver for Supplicant<D> {
    fn info(&self) -> &'static DriverInfo {
        self.dialect.info()
    }

    fn requirements(&self) -> Requirements {
        Requirements {
            ethertype: Some(ETH_P_PAE),
            udp_ports: self.dialect.udp_ports(),
            needs_ipv4: false,
            udp_ttl: self.dialect.udp_ttl(),
        }
    }

    fn start(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.started {
            return out;
        }
        self.started = true;
        self.begin_round(now, &mut out);
        out
    }

    fn on_frame(&mut self, frame: &[u8], now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if !self.started || self.stopped || self.pending_dhcp.is_some() {
            return out;
        }
        match frame::parse(frame) {
            None => {}
            Some(Received::Other { typ }) => debug!("收到 EAPOL 类型 {} 的报文", typ),
            Some(Received::Request { src, id, kind, data }) => {
                self.on_request(src, id, kind, data, frame, now, &mut out)
            }
            Some(Received::Success { .. }) => self.on_success(frame, now, &mut out),
            Some(Received::Failure { .. }) => self.on_failure(frame, now, &mut out),
        }
        out
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if !self.started || self.stopped || self.pending_dhcp.is_some() {
            return out;
        }
        if self.deadline.is_some_and(|d| now >= d) {
            match self.stage {
                Stage::Start if self.sends < SENDS_PER_STAGE => self.send_start(now, &mut out),
                Stage::Identity | Stage::Md5 if self.sends < SENDS_PER_STAGE => {
                    out.push(Action::SendFrame(self.last_frame.clone()));
                    self.sends += 1;
                    self.arm(now, self.opts.timeout.max(1));
                }
                Stage::Start | Stage::Identity | Stage::Md5 => self.no_response(now, &mut out),
                Stage::Online => {
                    self.send_keepalive(&mut out);
                    self.arm(now, self.echo_interval as u64);
                }
                Stage::Waiting => self.begin_round(now, &mut out),
            }
        }
        if self.stage == Stage::Online && !self.stopped && self.dialect.deadline().is_some_and(|d| now >= d) {
            let actions = self.dialect.on_timer(&ctx!(self), now);
            out.extend(actions);
        }
        out
    }

    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        self.set_net(net);
        if self.stopped {
            return out;
        }
        match self.pending_dhcp.take() {
            Some(AfterDhcp::Start) => {
                self.stage = Stage::Start;
                self.sends = 0;
                self.send_start(now, &mut out);
            }
            Some(AfterDhcp::Reauthenticate) => {
                // Secondary authentication: log in again with the new address.
                if let Some(frame) = self.dialect.logoff(&ctx!(self)) {
                    info!("发送下线请求...");
                    out.push(Action::SendFrame(frame));
                }
                self.ignore_start_failure = true;
                self.stage = Stage::Start;
                self.sends = 0;
                self.server = None;
                self.send_start(now, &mut out);
            }
            Some(AfterDhcp::Online) => self.go_online(now, &mut out),
            None => {}
        }
        out
    }

    fn next_deadline(&self) -> Option<Instant> {
        if self.stopped || self.pending_dhcp.is_some() {
            return None;
        }
        match (self.deadline, self.dialect.deadline().filter(|_| self.stage == Stage::Online)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.server.is_some() && !self.stopped {
            if let Some(frame) = self.dialect.logoff(&ctx!(self)) {
                info!("发送下线请求...");
                out.push(Action::SendFrame(frame));
            }
        }
        if !self.stopped {
            self.stop(&mut out, Stop::Finished);
        }
        out
    }

    fn state(&self) -> AuthState {
        if self.stopped {
            return AuthState::Stopped;
        }
        if !self.started {
            return AuthState::Idle;
        }
        if self.pending_dhcp.is_some() {
            return AuthState::WaitingIp;
        }
        match self.stage {
            Stage::Start => AuthState::Discovering,
            Stage::Identity | Stage::Md5 => AuthState::Authenticating,
            Stage::Online => AuthState::Online,
            Stage::Waiting => AuthState::Backoff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::*;
    use gswifi_core::{SupportLevel, Transport};

    static INFO: DriverInfo = DriverInfo {
        name: "test",
        title: "test",
        transport: Transport::Eapol,
        support: SupportLevel::Documented,
        docs: &[21],
    };

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    /// Plain EAP-MD5 with a fixed keepalive frame, for the engine tests.
    struct Plain;

    impl Dialect for Plain {
        fn info(&self) -> &'static DriverInfo {
            &INFO
        }
        fn start(&mut self, ctx: &Ctx, _attempt: u32) -> Vec<u8> {
            control_frame(&MAC_STANDARD, &ctx.mac, TYPE_EAPOL_START)
        }
        fn classify(&mut self, _: &Ctx, _: &[u8; 6], kind: u8, _: &[u8]) -> RequestKind {
            match kind {
                EAP_TYPE_IDENTITY => RequestKind::Identity,
                EAP_TYPE_MD5_CHALLENGE => RequestKind::Challenge,
                EAP_TYPE_NOTIFICATION => RequestKind::Notification,
                _ => RequestKind::Unsupported,
            }
        }
        fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, _: &[u8]) -> Vec<u8> {
            identity_response(src, &ctx.mac, id, ctx.credentials.username.as_bytes())
        }
        fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], _: &[u8]) -> Vec<u8> {
            let d = md5_digest(id, ctx.credentials.password.as_bytes(), b"", seed);
            md5_response(src, &ctx.mac, id, &d, ctx.credentials.username.as_bytes())
        }
        fn success(&mut self, _: &Ctx, _: &[u8]) -> u32 {
            0
        }
        fn keepalive(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
            Some(control_frame(&MAC_STANDARD, &ctx.mac, 0xbf))
        }
        fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
            Some(control_frame(&MAC_STANDARD, &ctx.mac, TYPE_EAPOL_LOGOFF))
        }
    }

    /// Plain, but answers type 20 in place while online.
    struct Answering(Plain);

    impl Dialect for Answering {
        fn info(&self) -> &'static DriverInfo {
            &INFO
        }
        fn start(&mut self, ctx: &Ctx, a: u32) -> Vec<u8> {
            self.0.start(ctx, a)
        }
        fn classify(&mut self, ctx: &Ctx, src: &[u8; 6], kind: u8, data: &[u8]) -> RequestKind {
            if kind == 20 && ctx.stage == Stage::Online {
                return RequestKind::Answer;
            }
            self.0.classify(ctx, src, kind, data)
        }
        fn answer(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, _kind: u8, _data: &[u8]) -> Option<Vec<u8>> {
            Some(identity_response(src, &ctx.mac, id, b"online"))
        }
        fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, d: &[u8]) -> Vec<u8> {
            self.0.identity(ctx, src, id, d)
        }
        fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], f: &[u8]) -> Vec<u8> {
            self.0.challenge(ctx, src, id, seed, f)
        }
        fn success(&mut self, ctx: &Ctx, f: &[u8]) -> u32 {
            self.0.success(ctx, f)
        }
        fn keepalive(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
            self.0.keepalive(ctx)
        }
        fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>> {
            self.0.logoff(ctx)
        }
    }

    #[test]
    fn answer_keeps_the_session_online() {
        let env = Env { interface: "eth0".into(), mac: LOCAL, net: NetInfo::default() };
        let mut s =
            Supplicant::new(Answering(Plain), env, Credentials::new("user", "pass"), Options::default()).unwrap();
        let t = Instant::now();
        s.start(t);
        s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        s.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t);
        s.on_frame(&code(CODE_SUCCESS, 2), t);
        let deadline = s.next_deadline();
        let a = s.on_frame(&request(9, 20, &[]), t + Duration::from_secs(1));
        assert_eq!(frames(&a), vec![identity_response(&SERVER, &LOCAL, 9, b"online")]);
        assert_eq!(s.state(), AuthState::Online);
        assert_eq!(s.next_deadline(), deadline, "keepalive timer untouched");
        // Before Success the same request is not answered.
        let mut s = Supplicant::new(
            Answering(Plain),
            Env { mac: LOCAL, ..Env::default() },
            Credentials::new("u", "p"),
            Options::default(),
        )
        .unwrap();
        s.start(t);
        assert!(frames(&s.on_frame(&request(9, 20, &[]), t)).is_empty());
    }

    fn supplicant(opts: Options) -> Supplicant<Plain> {
        let env = Env { interface: "eth0".into(), mac: LOCAL, net: NetInfo::default() };
        Supplicant::new(Plain, env, Credentials::new("user", "pass"), opts).unwrap()
    }

    fn request(id: u8, kind: u8, data: &[u8]) -> Vec<u8> {
        let len = 5 + data.len() as u16;
        let mut f = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, len);
        f.extend_from_slice(&[CODE_REQUEST, id]);
        f.extend_from_slice(&len.to_be_bytes());
        f.push(kind);
        f.extend_from_slice(data);
        f
    }

    fn code(code: u8, id: u8) -> Vec<u8> {
        let mut f = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 4);
        f.extend_from_slice(&[code, id, 0, 4]);
        f.resize(60, 0);
        f
    }

    fn frames(actions: &[Action]) -> Vec<Vec<u8>> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendFrame(f) => Some(f.clone()),
                _ => None,
            })
            .collect()
    }

    fn challenge_data() -> Vec<u8> {
        let mut d = vec![16];
        d.extend_from_slice(&[0x5a; 16]);
        d
    }

    /// Logs in and returns the time Success arrived.
    fn login(s: &mut Supplicant<Plain>, t0: Instant) -> Instant {
        let a = s.start(t0);
        assert_eq!(frames(&a), vec![control_frame(&MAC_STANDARD, &LOCAL, TYPE_EAPOL_START)]);
        let a = s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t0);
        assert_eq!(frames(&a), vec![identity_response(&SERVER, &LOCAL, 1, b"user")]);
        assert_eq!(s.state(), AuthState::Authenticating);
        let a = s.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t0);
        let d = md5_digest(2, b"pass", b"", &[0x5a; 16]);
        assert_eq!(frames(&a), vec![md5_response(&SERVER, &LOCAL, 2, &d, b"user")]);
        let a = s.on_frame(&code(CODE_SUCCESS, 2), t0);
        assert!(a.is_empty());
        assert_eq!(s.state(), AuthState::Online);
        t0
    }

    #[test]
    fn login_keepalive_logoff() {
        let mut s = supplicant(Options::default());
        let t0 = Instant::now();
        login(&mut s, t0);
        // Default interval 30 s when neither side sets one.
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_secs(30)));
        let a = s.on_timer(t0 + Duration::from_secs(30));
        assert_eq!(frames(&a), vec![control_frame(&MAC_STANDARD, &LOCAL, 0xbf)]);
        let a = s.logoff(t0 + Duration::from_secs(31));
        assert_eq!(frames(&a), vec![control_frame(&MAC_STANDARD, &LOCAL, TYPE_EAPOL_LOGOFF)]);
        assert_eq!(a.last(), Some(&Action::Stop(Stop::Finished)));
        assert_eq!(s.state(), AuthState::Stopped);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn resend_then_wait_then_give_up() {
        let mut s = supplicant(Options { max_retries: 1, ..Options::default() });
        let mut t = Instant::now();
        assert_eq!(frames(&s.start(t)).len(), 1);
        for _ in 0..4 {
            t += Duration::from_secs(8);
            assert_eq!(frames(&s.on_timer(t)).len(), 1);
        }
        t += Duration::from_secs(8);
        assert!(s.on_timer(t).is_empty());
        assert_eq!(s.state(), AuthState::Backoff);
        assert_eq!(s.next_deadline(), Some(t + Duration::from_secs(15)));
        // Second round: five Starts again, then the limit is reached.
        t += Duration::from_secs(15);
        assert_eq!(frames(&s.on_timer(t)).len(), 1);
        for _ in 0..4 {
            t += Duration::from_secs(8);
            s.on_timer(t);
        }
        t += Duration::from_secs(8);
        assert_eq!(s.on_timer(t), vec![Action::Stop(Stop::GaveUp { rounds: 2 })]);
    }

    #[test]
    fn identity_resent_until_answered() {
        let mut s = supplicant(Options::default());
        let t = Instant::now();
        s.start(t);
        let first = frames(&s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t));
        let again = frames(&s.on_timer(t + Duration::from_secs(8)));
        assert_eq!(first, again);
    }

    #[test]
    fn rejections_stop_with_stage() {
        let mut s = supplicant(Options::default());
        let t = Instant::now();
        s.start(t);
        s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        let a = s.on_frame(&code(CODE_FAILURE, 1), t);
        assert_eq!(a, vec![Action::Stop(Stop::Rejected { stage: RejectStage::Identity, message: None })]);

        let mut s = supplicant(Options::default());
        s.start(t);
        s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        s.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t);
        let a = s.on_frame(&code(CODE_FAILURE, 2), t);
        assert!(matches!(&a[..], [Action::Stop(Stop::Rejected { stage: RejectStage::Password, .. })]));
        // Nothing happens after the stop.
        assert!(s.on_frame(&request(3, EAP_TYPE_IDENTITY, &[]), t).is_empty());

        let mut s = supplicant(Options::default());
        s.start(t);
        assert_eq!(s.on_frame(&code(CODE_FAILURE, 0), t), vec![Action::Stop(Stop::ServerNotFound)]);
    }

    #[test]
    fn dropped_while_online_reconnects() {
        let mut s = supplicant(Options::default());
        let t = login(&mut s, Instant::now());
        assert!(s.on_frame(&code(CODE_FAILURE, 3), t).is_empty());
        assert_eq!(s.state(), AuthState::Backoff);
        let t = t + Duration::from_secs(15);
        assert_eq!(frames(&s.on_timer(t)).len(), 1);
        assert_eq!(s.state(), AuthState::Discovering);
        // The Failure that answers our new Start is expected and ignored.
        assert!(s.on_frame(&code(CODE_FAILURE, 3), t).is_empty());
        assert_eq!(s.state(), AuthState::Discovering);
    }

    #[test]
    fn server_reauthentication_while_online() {
        let mut s = supplicant(Options::default());
        let t = login(&mut s, Instant::now());
        assert_eq!(frames(&s.on_frame(&request(9, EAP_TYPE_IDENTITY, &[]), t)).len(), 1);
        // A Failure during re-authentication reconnects instead of stopping.
        assert!(s.on_frame(&code(CODE_FAILURE, 9), t).is_empty());
        assert_eq!(s.state(), AuthState::Backoff);
    }

    #[test]
    fn dhcp_modes() {
        let t = Instant::now();
        let net = NetInfo { ip: [10, 0, 0, 2], ..Default::default() };

        // Mode 3: DHCP first, Start once the address is there.
        let mut s = supplicant(Options { dhcp_mode: 3, ..Options::default() });
        assert_eq!(s.start(t), vec![Action::RequestDhcp]);
        assert_eq!(s.state(), AuthState::WaitingIp);
        assert_eq!(s.next_deadline(), None);
        assert_eq!(frames(&s.on_net_change(net, t)).len(), 1);
        assert_eq!(s.dhcp_mode, 6);

        // Mode 2: DHCP after Success, then online.
        let mut s = supplicant(Options { dhcp_mode: 2, ..Options::default() });
        s.start(t);
        s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        s.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t);
        assert_eq!(s.on_frame(&code(CODE_SUCCESS, 2), t), vec![Action::RequestDhcp]);
        assert!(s.on_net_change(net, t).is_empty());
        assert_eq!(s.state(), AuthState::Online);

        // Mode 1: DHCP after Success, Logoff, authenticate again.
        let mut s = supplicant(Options { dhcp_mode: 1, ..Options::default() });
        s.start(t);
        s.on_frame(&request(1, EAP_TYPE_IDENTITY, &[]), t);
        s.on_frame(&request(2, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t);
        assert_eq!(s.on_frame(&code(CODE_SUCCESS, 2), t), vec![Action::RequestDhcp]);
        let a = frames(&s.on_net_change(net, t));
        assert_eq!(a.len(), 2);
        assert_eq!(a[0][15], TYPE_EAPOL_LOGOFF);
        assert_eq!(a[1][15], TYPE_EAPOL_START);
        s.on_frame(&request(3, EAP_TYPE_IDENTITY, &[]), t);
        s.on_frame(&request(4, EAP_TYPE_MD5_CHALLENGE, &challenge_data()), t);
        assert!(s.on_frame(&code(CODE_SUCCESS, 4), t).is_empty());
        assert_eq!(s.state(), AuthState::Online);
    }

    #[test]
    fn overrides_apply_to_new_addresses() {
        let opts = Options {
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns: Some(Ipv4Addr::new(10, 0, 0, 53)),
            ..Options::default()
        };
        let mut s = supplicant(opts);
        s.on_net_change(NetInfo { ip: [10, 0, 0, 2], gateway: [1, 1, 1, 1], ..Default::default() }, Instant::now());
        assert_eq!(s.net.gateway, [10, 0, 0, 1]);
        assert_eq!(s.net.dns, [10, 0, 0, 53]);
        assert_eq!(s.net.ip, [10, 0, 0, 2]);
    }

    #[test]
    fn options_validate() {
        assert!(Options { dhcp_mode: 4, ..Options::default() }.validate().is_err());
    }
}
