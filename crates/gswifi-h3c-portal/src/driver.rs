//! The H3C Portal session (research doc 29.2, 29.4).
//!
//! ```text
//! Discovery --TX110, RX111 or 2nd timeout--> Identity --TX100, RX121--> Challenge
//! Challenge --TX122, RX101 with 100--> Online --timer: TX104--> Online
//! Online --RX105: next timer / new challenge--> Online
//! Online --RX101 without 100--> Discovery          (re-authentication)
//! Identity/Challenge --RX101 without 100--> Backoff (restart_wait), or
//!                                           Stop::Rejected with stop_on_reject
//! any --logoff--> TX102, Stop::Finished
//! ```
//!
//! Resends (doc 29.4): discovery sends 110 twice, 8 s apart, then moves to
//! the login even without an answer; the login is sent five times; the
//! challenge response is built once and resent four times; after that the
//! round waits `restart_wait` (15 s) and starts over. `max_fail` failed
//! rounds stop the session.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use gswifi_core::text::gbk;
use gswifi_core::{
    Action, AuthState, Credentials, Datagram, Driver, DriverInfo, Env, NetInfo, RejectStage, Requirements, Stop,
};
use gswifi_inode::{load_gs_data, GsData, InodeMaterial, InodeOptions};
use log::{debug, error, info, warn};
use serde::Deserialize;

use crate::codec::check::check_result;
use crate::codec::{self, Message, Online};
use crate::INFO;

/// Seconds between `104` messages when the server does not say otherwise
/// (doc 29.4: every 104 sets the timer to 10).
const DEFAULT_HEARTBEAT: u64 = 10;
/// Upper bound for a server supplied timer.
const MAX_SERVER_TIMER: u64 = 3600;
/// Sends per stage: first + four repeats (doc 29.4).
const SENDS_PER_STAGE: u32 = 5;

/// H3C Portal settings (MentoHUST names in parentheses).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Portal server (MentoHUST `PortalIP`). `0.0.0.0`: the interface's DNS server, as
    /// the GS init does (doc 23.1; global 0x447254 starts as the DNS
    /// global 0x447f74).
    pub portal_ip: Ipv4Addr,
    /// Server UDP port; GS sets 50200 for AuthType 2 (doc 23.1, 29.1).
    pub server_port: u16,
    /// Send the password in clear instead of the block transform
    /// (`UsePlainTextPass`) (doc 13.7).
    pub plain_password: bool,
    /// Header serial as a big-endian number of the two wire bytes
    /// (`0x1234` → `12 34`). GS draws it with `htons(rand())` at start;
    /// unset here: derived from the MAC so it is stable.
    pub serial: Option<u16>,
    /// Local ports for 110/102, 100/122 and 104. Unset: `56000 + s`,
    /// `58000 + s`, `60000 + s` with `s` = serial bytes read as a
    /// little-endian u16 (MIPSel host order) `& 1023` (doc 29.1).
    pub local_ports: Option<[u16; 3]>,
    /// Seconds between keepalives (doc 29.4: 10).
    pub heartbeat_interval: u64,
    /// Attribute 113 value in login and keepalive (both read global
    /// 0x44726c, `htonl`'d at 0x40dab0 / 0x40defe). Every research harness
    /// forced it to 30, which doc 13.7 calls the heartbeat parameter, but
    /// the GS init stores `time(NULL)` there (0x40b84e → 0x40b856), so real
    /// clients probably send their start time. Drivers do not read the
    /// clock: a runtime that wants the GS value sets this from the wall
    /// clock. Default 30 = the vectors. // doc 29.3: meaning unknown
    pub stamp: u32,
    /// Seconds to wait for an answer (`Timeout`).
    pub timeout: u64,
    /// Seconds to wait before a new round (`RestartWait`).
    pub restart_wait: u64,
    /// Failed rounds before giving up; 0 never gives up (`MaxFail`).
    pub max_fail: u32,
    /// Stop at the first refusal during login. Off by default: 101 carries
    /// only a display text (115), no error code, so a refusal is not known to
    /// be a credential error (cleanroom/docs/gaps.md); it counts as a failed
    /// round instead.
    pub stop_on_reject: bool,
    /// Reproduce the GS logoff length defect (two zero bytes after the
    /// session value, doc 29.3). Off: send the value as received.
    pub logoff_session_quirk: bool,
    /// A 105 without (or with zero) attribute 109 makes GS stop its timer,
    /// i.e. stop the keepalive (doc 29.2). Off: keep the current schedule;
    /// what servers mean by it is not documented.
    pub zero_timer_stops_heartbeat: bool,
    /// Drop server messages whose authenticator is not the `hello` MD5.
    /// GS does not check it (doc 29.1).
    pub verify_authenticator: bool,
    /// iNode version material (`iNode.vif`, `inode-gs.dat`, ...).
    pub inode: InodeOptions,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            portal_ip: Ipv4Addr::UNSPECIFIED,
            server_port: 50200,
            plain_password: false,
            serial: None,
            local_ports: None,
            heartbeat_interval: DEFAULT_HEARTBEAT,
            stamp: 30,
            timeout: 8,
            restart_wait: 15,
            max_fail: 8,
            stop_on_reject: false,
            logoff_session_quirk: false,
            zero_timer_stops_heartbeat: false,
            verify_authenticator: false,
            inode: InodeOptions::default(),
        }
    }
}

/// Serial when none is configured: `MD5("gswifi-h3c" || mac)[..2]`.
fn default_serial(mac: &[u8; 6]) -> [u8; 2] {
    let mut input = b"gswifi-h3c".to_vec();
    input.extend_from_slice(mac);
    let d = md5::compute(input).0;
    [d[0], d[1]]
}

/// GS local ports for a serial (doc 29.1).
pub(crate) fn serial_ports(serial: [u8; 2]) -> [u16; 3] {
    let s = u16::from_le_bytes(serial) & 1023;
    [56000 + s, 58000 + s, 60000 + s]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    WaitingIp,
    Discovery,
    Identity,
    Challenge,
    Online,
    Backoff,
    Stopped,
}

/// One H3C Portal session.
pub struct H3cPortalDriver {
    opts: Options,
    credentials: Credentials,
    mac: [u8; 6],
    net: NetInfo,
    serial: [u8; 2],
    ports: [u16; 3],
    mixed: [u8; 20],
    gs_data: Option<GsData>,
    phase: Phase,
    /// Sends/timeouts in the current stage.
    count: u32,
    deadline: Option<Instant>,
    server: Option<SocketAddrV4>,
    /// Last message of the current stage, resent by the timer.
    last: Vec<u8>,
    check: Option<[u8; 32]>,
    session: Option<Vec<u8>>,
    auth_blob: Option<Vec<u8>>,
    failures: u32,
    heard_server: bool,
}

impl H3cPortalDriver {
    pub fn new(env: Env, credentials: Credentials, options: Options) -> Result<Self, String> {
        if options.timeout == 0 || options.heartbeat_interval == 0 {
            return Err("timeout 和 heartbeat_interval 必须大于 0".into());
        }
        if options.server_port == 0 {
            return Err("server_port 不能为 0".into());
        }
        let user = credentials.username.as_bytes();
        if user.is_empty() || user.len() > codec::MAX_VALUE - 32 {
            return Err(format!("用户名长度必须在 1~{} 字节之间", codec::MAX_VALUE - 32));
        }
        if credentials.password.as_bytes().len() > 31 {
            return Err("密码超过 31 字节，H3C Portal 登录报文放不下".into());
        }
        let material = InodeMaterial::load(&options.inode).map_err(|e| e.to_string())?;
        let nonce = material.nonce_for(&env.mac, user);
        let mixed =
            material.mixed(nonce).ok_or("H3C Portal 登录需要 iNode 版本：请提供 iNode.vif 或设置 inode.version")?;
        let gs_data = load_gs_data(&options.inode).map_err(|e| e.to_string())?;
        let serial = options.serial.map(u16::to_be_bytes).unwrap_or_else(|| default_serial(&env.mac));
        let ports = options.local_ports.unwrap_or_else(|| serial_ports(serial));
        if ports.contains(&0) || ports[0] == ports[1] || ports[1] == ports[2] || ports[0] == ports[2] {
            return Err("local_ports 必须是三个不同的非零端口".into());
        }
        Ok(H3cPortalDriver {
            opts: options,
            credentials,
            mac: env.mac,
            net: env.net,
            serial,
            ports,
            mixed,
            gs_data,
            phase: Phase::Idle,
            count: 0,
            deadline: None,
            server: None,
            last: Vec::new(),
            check: None,
            session: None,
            auth_blob: None,
            failures: 0,
            heard_server: false,
        })
    }

    /// Local ports used for (110/102, 100/122, 104).
    pub fn ports(&self) -> [u16; 3] {
        self.ports
    }

    fn arm(&mut self, now: Instant, secs: u64) {
        self.deadline = Some(now + Duration::from_secs(secs));
    }

    fn send(&self, out: &mut Vec<Action>, port_index: usize, payload: Vec<u8>) {
        if let Some(to) = self.server {
            out.push(Action::SendUdp { local_port: self.ports[port_index], to, payload });
        }
    }

    fn build(&self, result: Result<Vec<u8>, codec::CodecError>, out: &mut Vec<Action>) -> Option<Vec<u8>> {
        match result {
            Ok(p) => Some(p),
            Err(e) => {
                // Inputs are validated in new(); this is a bug guard, not a protocol path.
                error!("构造 H3C Portal 报文失败：{}", e);
                out.push(Action::Stop(Stop::Fatal(e.to_string())));
                None
            }
        }
    }

    fn stop(&mut self, out: &mut Vec<Action>, stop: Stop) {
        self.phase = Phase::Stopped;
        self.deadline = None;
        out.push(Action::Stop(stop));
    }

    fn clear_session(&mut self) {
        self.check = None;
        self.session = None;
        self.auth_blob = None;
        self.last.clear();
    }

    // ---- stages ----

    fn begin_discovery(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.clear_session();
        if !self.net.has_ipv4() {
            info!("等待获取 IPv4 地址...");
            self.phase = Phase::WaitingIp;
            self.deadline = None;
            return;
        }
        let ip = if self.opts.portal_ip.is_unspecified() { Ipv4Addr::from(self.net.dns) } else { self.opts.portal_ip };
        if ip.is_unspecified() {
            error!("未配置 portal_ip，也没有可用作默认值的 DNS 服务器地址");
            self.stop(out, Stop::Fatal("未配置 portal_ip".into()));
            return;
        }
        self.server = Some(SocketAddrV4::new(ip, self.opts.server_port));
        info!("寻找服务器 {}:{}...", ip, self.opts.server_port);
        let Some(p) = self.build(codec::discovery(self.net.ip, self.serial), out) else { return };
        self.phase = Phase::Discovery;
        self.count = 0;
        self.last = p.clone();
        self.send(out, 0, p);
        self.arm(now, self.opts.timeout);
    }

    fn login_payload(&self, out: &mut Vec<Action>) -> Option<Vec<u8>> {
        let login = codec::Login {
            user_ip: self.net.ip,
            serial: self.serial,
            mac: self.mac,
            username: self.credentials.username.as_bytes(),
            password: self.credentials.password.as_bytes(),
            mixed_version: &self.mixed,
            stamp: self.opts.stamp,
            plain_password: self.opts.plain_password,
        };
        self.build(codec::login(&login), out)
    }

    fn enter_identity(&mut self, now: Instant, out: &mut Vec<Action>) {
        info!("发送用户名...");
        let Some(p) = self.login_payload(out) else { return };
        self.phase = Phase::Identity;
        self.count = 0;
        self.send(out, 1, p);
        self.arm(now, self.opts.timeout);
    }

    fn compute_check(&self, challenge: Option<&[u8]>) -> Option<[u8; 32]> {
        let c = challenge?;
        match check_result(c, self.gs_data.as_ref()) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("无法计算客户端校验(属性131)：{}，本次不附带", e);
                None
            }
        }
    }

    fn enter_challenge(&mut self, challenge: Option<&[u8]>, now: Instant, out: &mut Vec<Action>) {
        info!("发送密码...");
        self.check = self.compute_check(challenge);
        let Some(p) = self.build(codec::challenge_response(self.net.ip, self.serial, self.check.as_ref()), out) else {
            return;
        };
        self.phase = Phase::Challenge;
        self.count = 0;
        self.last = p.clone();
        self.send(out, 1, p);
        self.arm(now, self.opts.timeout);
    }

    fn online_payload(&self, out: &mut Vec<Action>) -> Option<Vec<u8>> {
        let o = Online {
            auth_blob: self.auth_blob.as_deref(),
            session: self.session.as_deref(),
            stamp: self.opts.stamp,
            check: self.check.as_ref(),
        };
        self.build(codec::online(self.net.ip, self.serial, &o), out)
    }

    fn go_online(&mut self, session: &[u8], blob: Option<&[u8]>, now: Instant, out: &mut Vec<Action>) {
        if self.phase != Phase::Online {
            info!("认证成功！");
        }
        self.phase = Phase::Online;
        self.failures = 0;
        self.session = Some(session.to_vec());
        self.auth_blob = blob.and_then(|b| {
            let v = codec::auth_blob_value(b);
            if v.is_none() {
                warn!("服务器属性114过长，心跳包中省略");
            }
            v
        });
        info!("发送心跳包以保持在线...");
        self.heartbeat(now, out);
    }

    fn heartbeat(&mut self, now: Instant, out: &mut Vec<Action>) {
        let Some(p) = self.online_payload(out) else { return };
        debug!("发送心跳包");
        self.send(out, 2, p);
        self.arm(now, self.opts.heartbeat_interval);
    }

    fn round_failed(&mut self, what: &str, now: Instant, out: &mut Vec<Action>) {
        self.failures += 1;
        let max = self.opts.max_fail;
        if max != 0 && self.failures >= max {
            if self.heard_server {
                error!("{}，失败次数已达上限({})", what, max);
                self.stop(out, Stop::GaveUp { rounds: self.failures });
            } else {
                error!("{}，始终没有收到服务器应答", what);
                self.stop(out, Stop::ServerNotFound);
            }
            return;
        }
        warn!("{}，{}s 后重启认证({}/{})", what, self.opts.restart_wait, self.failures, max);
        self.phase = Phase::Backoff;
        self.clear_session();
        self.arm(now, self.opts.restart_wait);
    }

    fn on_message(&mut self, r: codec::Received<'_>, now: Instant, out: &mut Vec<Action>) {
        let text = r.text.map(gbk).filter(|t| !t.is_empty());
        let phase = self.phase;
        match r.message {
            Message::DiscoveryAck if matches!(phase, Phase::Discovery | Phase::Identity) => {
                if let Some(t) = &text {
                    info!("服务器提示：{}", t);
                }
                self.enter_identity(now, out);
            }
            Message::Challenge { challenge }
                if matches!(phase, Phase::Discovery | Phase::Identity | Phase::Challenge) =>
            {
                if let Some(t) = &text {
                    info!("服务器提示：{}", t);
                }
                self.enter_challenge(challenge, now, out);
            }
            Message::Success { session, auth_blob }
                if matches!(phase, Phase::Identity | Phase::Challenge | Phase::Online) =>
            {
                if let Some(t) = &text {
                    info!("服务器提示：{}", t);
                }
                self.go_online(session, auth_blob, now, out);
            }
            Message::Failure if phase == Phase::Online => {
                warn!(
                    "服务器结束了在线会话{}，重新认证",
                    text.as_deref().map(|t| format!("({})", t)).unwrap_or_default()
                );
                self.begin_discovery(now, out);
            }
            Message::Failure if matches!(phase, Phase::Identity | Phase::Challenge) => {
                let stage = if phase == Phase::Identity { RejectStage::Identity } else { RejectStage::Password };
                if self.opts.stop_on_reject {
                    match &text {
                        Some(t) => error!("认证失败，服务器提示：{}", t),
                        None => error!("认证失败：服务器拒绝了用户名或密码"),
                    }
                    self.stop(out, Stop::Rejected { stage, message: text });
                } else {
                    let what = match &text {
                        Some(t) => format!("服务器拒绝认证（{}）", t),
                        None => "服务器拒绝认证".to_string(),
                    };
                    self.round_failed(&what, now, out);
                }
            }
            Message::OnlineAck { challenge, timer_ms } if phase == Phase::Online => {
                if let Some(t) = &text {
                    info!("服务器提示：{}", t);
                }
                if challenge.is_some() {
                    self.check = self.compute_check(challenge);
                }
                let secs = timer_ms.unwrap_or(0) / 1000;
                if secs > 0 {
                    if secs > MAX_SERVER_TIMER {
                        warn!("服务器给出的心跳间隔 {}s 过长，改用 {}s", secs, MAX_SERVER_TIMER);
                    }
                    self.arm(now, secs.min(MAX_SERVER_TIMER));
                } else if self.opts.zero_timer_stops_heartbeat {
                    info!("服务器表示不需要发送心跳包");
                    self.deadline = None;
                } else {
                    debug!("105 未指定下次心跳时间，保持原计划");
                }
            }
            Message::Unknown { kind } => {
                warn!("收到未识别的 H3C Portal 报文(type {})，忽略", kind);
            }
            other => debug!("当前阶段({:?})忽略报文 {:?}", phase, other),
        }
    }
}

impl Driver for H3cPortalDriver {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    fn requirements(&self) -> Requirements {
        Requirements { ethertype: None, udp_ports: self.ports.to_vec(), needs_ipv4: true, udp_ttl: None }
    }

    fn start(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.phase == Phase::Idle {
            self.begin_discovery(now, &mut out);
        }
        out
    }

    fn on_datagram(&mut self, datagram: Datagram<'_>, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if !matches!(self.phase, Phase::Discovery | Phase::Identity | Phase::Challenge | Phase::Online) {
            return out;
        }
        if !self.ports.contains(&datagram.local_port) || Some(datagram.from) != self.server {
            debug!("忽略来自 {} 的报文(本地端口 {})", datagram.from, datagram.local_port);
            return out;
        }
        let r = match codec::parse_message(datagram.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!("收到无法解析的 H3C Portal 报文：{}", e);
                return out;
            }
        };
        if self.opts.verify_authenticator && !codec::verify(datagram.payload) {
            warn!("H3C Portal 报文认证字段不符，忽略");
            return out;
        }
        self.heard_server = true;
        self.on_message(r, now, &mut out);
        out
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if !self.deadline.is_some_and(|d| now >= d) {
            return out;
        }
        match self.phase {
            Phase::Discovery => {
                self.count += 1;
                if self.count == 1 {
                    self.send(&mut out, 0, self.last.clone());
                    self.arm(now, self.opts.timeout);
                } else {
                    debug!("寻找服务器无应答，直接发送用户名");
                    self.enter_identity(now, &mut out);
                }
            }
            Phase::Identity => {
                self.count += 1;
                if self.count < SENDS_PER_STAGE {
                    if let Some(p) = self.login_payload(&mut out) {
                        self.send(&mut out, 1, p);
                        self.arm(now, self.opts.timeout);
                    }
                } else {
                    self.round_failed("发送用户名超时", now, &mut out);
                }
            }
            Phase::Challenge => {
                self.count += 1;
                if self.count < SENDS_PER_STAGE {
                    self.send(&mut out, 1, self.last.clone());
                    self.arm(now, self.opts.timeout);
                } else {
                    self.round_failed("发送密码超时", now, &mut out);
                }
            }
            Phase::Online => self.heartbeat(now, &mut out),
            Phase::Backoff => self.begin_discovery(now, &mut out),
            Phase::Idle | Phase::WaitingIp | Phase::Stopped => self.deadline = None,
        }
        out
    }

    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let old = std::mem::replace(&mut self.net, net);
        match self.phase {
            Phase::Idle | Phase::Stopped => {}
            Phase::WaitingIp => {
                if net.has_ipv4() {
                    self.begin_discovery(now, &mut out);
                }
            }
            _ if !net.has_ipv4() => {
                warn!("接口失去 IPv4 地址，等待重新获取");
                self.clear_session();
                self.phase = Phase::WaitingIp;
                self.deadline = None;
            }
            _ if net.ip != old.ip => {
                warn!("IP 地址由 {} 变为 {}，重新认证", old.ipv4(), net.ipv4());
                self.begin_discovery(now, &mut out);
            }
            _ => {}
        }
        out
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.phase == Phase::Stopped {
            return out;
        }
        if matches!(self.phase, Phase::Identity | Phase::Challenge | Phase::Online) {
            let session =
                self.session.as_deref().map(|s| codec::logoff_session_value(s, self.opts.logoff_session_quirk));
            if let Some(p) = self.build(codec::logoff(self.net.ip, self.serial, session.as_deref()), &mut out) {
                info!("发送下线请求...");
                self.send(&mut out, 0, p);
            }
        }
        self.stop(&mut out, Stop::Finished);
        out
    }

    fn state(&self) -> AuthState {
        match self.phase {
            Phase::Idle => AuthState::Idle,
            Phase::WaitingIp => AuthState::WaitingIp,
            Phase::Discovery => AuthState::Discovering,
            Phase::Identity | Phase::Challenge => AuthState::Authenticating,
            Phase::Online => AuthState::Online,
            Phase::Backoff => AuthState::Backoff,
            Phase::Stopped => AuthState::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc29_ports() {
        assert_eq!(serial_ports([0x12, 0x34]), [56018, 58018, 60018]);
    }

    #[test]
    fn options_defaults() {
        let o = Options::default();
        assert_eq!((o.server_port, o.timeout, o.restart_wait, o.max_fail, o.heartbeat_interval), (50200, 8, 15, 8, 10));
        assert!(o.inode.upload_ver && o.inode.upload_ip);
    }
}
