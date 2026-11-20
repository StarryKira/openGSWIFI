//! Sans-IO session driver for the 安朗 UDP protocol (doc 04, doc 01.3).
//!
//! The original client (`/bin/atclient`, main at VA `0x400900`) runs once
//! per process and its init script restarts it in a loop:
//!
//! 1. Discovery: op 12 to `1.1.1.8:3850`, skipped when a server is
//!    configured (`-i`/UCI `sip`). One try, 10 s receive timeout; a timeout
//!    or bad size exits the process (VA `0x400c44`).
//! 2. Service query: op 7 to `server:3848`, skipped when a service is
//!    configured (`-s`/UCI `stype`). One try, 10 s; a reply without the
//!    service field exits or asks for manual input (VA `0x401232`,
//!    `0x401252`).
//! 3. Login: op 1. Up to 3 tries 5 s apart (VA `0x40108a`, `0x40125e`), each
//!    with a 10 s timeout.
//! 4. Heartbeat: op 3, sent right after login and then 20 s after every
//!    accepted heartbeat (VA `0x401334`). A timeout or refusal waits 1 s and
//!    resends the same counter (VA `0x401202`); the third failure ends the
//!    process.
//!
//! After an exit, `atclient-service.sh` sleeps 5 s and starts again from
//! discovery; every 10 rounds it runs `ifup` (doc 01.3).
//!
//! This driver keeps the timers, ports and retry counts above as defaults
//! ([`Options`]). It differs from the original in these ways (each is noted
//! where it happens):
//! * A login refusal is retried like a timeout, as in the original, but
//!   the rounds back off. The reply has no reason code, so "already online"
//!   cannot be told from a wrong password (cleanroom/docs/gaps.md P0-1:
//!   unconfirmed refusals are transient). `retry_on_reject = false` stops
//!   at the first refusal instead.
//! * Rounds back off exponentially, starting at the 5 s restart delay.
//! * `ifup` becomes [`Action::RequestDhcp`].
//! * Heartbeat failures count consecutively. The original never resets its
//!   count, so three isolated losses over days end a healthy session.
//! * Replies are checked with the reference's strictness unless
//!   [`ResponseCheck::Firmware`] is chosen.
//! * Undecodable datagrams are ignored rather than ending the step.
//! * After discovery, replies must come from the server address.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use gswifi_core::text::gbk;
use gswifi_core::{
    Action, AuthState, Credentials, Datagram, Driver, DriverInfo, Env, NetInfo, RejectStage, Requirements, Stop,
};
use log::{debug, error, info, warn};
use serde::Deserialize;

use crate::codec::{self, CodecError, LoginReply, ResponseCheck};

/// Longest accepted setting for any interval, so deadline arithmetic cannot
/// overflow.
const MAX_INTERVAL_SECS: u64 = 86_400;

/// Driver configuration. Defaults are the original client's values.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Authentication server IPv4 (atclient `-i`, UCI `sip`). Empty:
    /// discover it via [`Options::discovery_server`] (doc 04.1).
    #[serde(alias = "sip")]
    pub server: String,
    /// Service name (atclient `-s`, UCI `stype`). Empty: ask the server with
    /// a service query (doc 04.4).
    #[serde(alias = "stype")]
    pub service: String,
    /// Discovery destination, `1.1.1.8` in the firmware (doc 04.1).
    pub discovery_server: Ipv4Addr,
    /// Discovery port, 3850 (doc 04.1).
    pub discovery_port: u16,
    /// Server port for service query, login and heartbeat, 3848 (doc 04.1).
    pub server_port: u16,
    /// Local UDP port; 0 is one ephemeral socket, as the original never binds.
    pub local_port: u16,
    /// Reply timeout per request, 10 s (`SO_RCVTIMEO`, doc 04.1).
    pub timeout_secs: u64,
    /// Delay after an accepted heartbeat, 20 s (doc 04.6).
    pub heartbeat_secs: u64,
    /// Delay before resending a failed heartbeat, 1 s (VA `0x401204`).
    pub heartbeat_retry_secs: u64,
    /// Consecutive heartbeat failures that end the session, 3 (VA `0x401210`).
    pub heartbeat_failures: u32,
    /// Login tries per round, 3 (VA `0x40108a`).
    pub login_attempts: u32,
    /// Delay between login tries, 5 s (VA `0x40125e`).
    pub login_retry_secs: u64,
    /// First delay between failed rounds; doubles up to
    /// [`Options::max_backoff_secs`]. 5 s is the init script's restart delay
    /// (doc 01.3).
    pub retry_secs: u64,
    /// Ceiling of the round backoff.
    pub max_backoff_secs: u64,
    /// Failed rounds before giving up; 0 retries forever, like the firmware.
    pub max_rounds: u32,
    /// Ask for a new address every this many failed rounds (the script runs
    /// `ifup` every 10, doc 01.3); 0 never asks.
    pub dhcp_every_rounds: u32,
    /// Reply checking: `strict` (reference, default) or `firmware`.
    pub response_check: ResponseCheck,
    /// Accept service/login/heartbeat replies from any source address, like
    /// the original (it never checks `recvfrom`'s address).
    pub accept_any_source: bool,
    /// Treat a login refusal like a timeout (the original's behaviour,
    /// default). The refusal carries no reason, so a wrong password and
    /// "already online" look the same (gaps.md P0-1); `false` stops at the
    /// first refusal with [`Stop::Rejected`].
    pub retry_on_reject: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            server: String::new(),
            service: String::new(),
            discovery_server: codec::DISCOVERY_SERVER,
            discovery_port: codec::DISCOVERY_PORT,
            server_port: codec::SERVER_PORT,
            local_port: 0,
            timeout_secs: 10,
            heartbeat_secs: 20,
            heartbeat_retry_secs: 1,
            heartbeat_failures: 3,
            login_attempts: 3,
            login_retry_secs: 5,
            retry_secs: 5,
            max_backoff_secs: 60,
            max_rounds: 0,
            dhcp_every_rounds: 10,
            response_check: ResponseCheck::Strict,
            accept_any_source: false,
            retry_on_reject: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not started.
    Idle,
    /// No IPv4 address: the requests carry the address text.
    WaitingIp,
    /// Discovery sent, waiting for the server address.
    Discovering {
        deadline: Instant,
    },
    /// Service query sent.
    QueryingService {
        deadline: Instant,
    },
    /// Login sent.
    LoggingIn {
        deadline: Instant,
    },
    /// Between login tries.
    LoginPause {
        until: Instant,
    },
    /// Authenticated; next heartbeat due at `next`.
    Online {
        next: Instant,
    },
    /// Heartbeat sent.
    Heartbeat {
        deadline: Instant,
    },
    /// Between a failed heartbeat and its resend.
    HeartbeatPause {
        until: Instant,
    },
    /// Between rounds.
    Backoff {
        until: Instant,
    },
    Stopped,
}

/// One 安朗 UDP session on one interface.
pub struct AnlangDriver {
    opts: Options,
    interface: String,
    mac: [u8; 6],
    net: NetInfo,
    credentials: Credentials,
    /// Configured server, if any; otherwise each round discovers one.
    fixed_server: Option<Ipv4Addr>,
    /// Configured service, if any; otherwise each round queries it.
    fixed_service: Option<Vec<u8>>,
    server: Option<Ipv4Addr>,
    service: Option<Vec<u8>>,
    /// Session from the login reply, cut at the first NUL like the original.
    session: Option<Vec<u8>>,
    counter: u32,
    phase: Phase,
    started: bool,
    login_attempt: u32,
    heartbeat_failures: u32,
    /// Failed rounds since the last successful login.
    rounds: u32,
    /// Some server answered at some point (decides `ServerNotFound` vs `GaveUp`).
    server_seen: bool,
    backoff: Duration,
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn parse_server(text: &str) -> Result<Option<Ipv4Addr>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let ip: Ipv4Addr = text.parse().map_err(|_| format!("安朗: 认证服务器地址 `{}` 不是有效的IPv4地址", text))?;
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        return Err(format!("安朗: 认证服务器地址 `{}` 不可用", ip));
    }
    Ok(Some(ip))
}

impl AnlangDriver {
    /// Validates the configuration. Fails on empty or NUL-containing
    /// credentials, a malformed server address, zero or huge intervals, and
    /// credentials too long for the 127-byte login packet (doc 04.2, 04.4).
    pub fn new(env: Env, credentials: Credentials, options: Options) -> Result<Self, String> {
        let username = credentials.username.as_bytes();
        let password = credentials.password.as_bytes();
        if username.is_empty() {
            return Err("安朗: 用户名不能为空".into());
        }
        if password.is_empty() {
            return Err("安朗: 密码不能为空".into());
        }
        // The original takes both from argv as C strings.
        if username.contains(&0) || password.contains(&0) {
            return Err("安朗: 用户名和密码不能包含NUL字符".into());
        }
        let fixed_server = parse_server(&options.server)?;
        let fixed_service = if options.service.is_empty() {
            None
        } else if options.service.as_bytes().contains(&0) {
            return Err("安朗: 认证服务不能包含NUL字符".into());
        } else {
            Some(options.service.as_bytes().to_vec())
        };
        // Worst case address text is 15 bytes; a discovered service adds more
        // and is checked again when the login is built.
        let worst = codec::LOGIN_OVERHEAD
            + username.len()
            + password.len()
            + codec::MAX_IPV4_TEXT
            + fixed_service.as_ref().map_or(0, Vec::len);
        if worst > codec::MAX_PACKET_LEN {
            return Err(format!(
                "安朗: 用户名、密码与认证服务过长，登录报文可能达到{}字节，原客户端上限为{}字节",
                worst,
                codec::MAX_PACKET_LEN
            ));
        }
        let intervals = [
            ("timeout_secs", options.timeout_secs),
            ("heartbeat_secs", options.heartbeat_secs),
            ("retry_secs", options.retry_secs),
            ("max_backoff_secs", options.max_backoff_secs),
            ("heartbeat_retry_secs", options.heartbeat_retry_secs),
            ("login_retry_secs", options.login_retry_secs),
        ];
        for (name, value) in intervals {
            let positive_required = matches!(name, "timeout_secs" | "heartbeat_secs" | "retry_secs");
            if (positive_required && value == 0) || value > MAX_INTERVAL_SECS {
                return Err(format!("安朗: {} = {} 超出范围（1..={}）", name, value, MAX_INTERVAL_SECS));
            }
        }
        if env.mac == [0; 6] {
            warn!("接口 {} 的MAC地址为全零，登录和心跳报文将携带该地址", env.interface);
        }
        let backoff = secs(options.retry_secs);
        Ok(AnlangDriver {
            interface: env.interface,
            mac: env.mac,
            net: env.net,
            credentials,
            fixed_server,
            fixed_service,
            server: None,
            service: None,
            session: None,
            counter: codec::INITIAL_COUNTER,
            phase: Phase::Idle,
            started: false,
            login_attempt: 0,
            heartbeat_failures: 0,
            rounds: 0,
            server_seen: false,
            backoff,
            opts: options,
        })
    }

    /// Server of the current round (configured or discovered).
    pub fn server(&self) -> Option<Ipv4Addr> {
        self.server
    }

    /// Service of the current round (configured or queried).
    pub fn service(&self) -> Option<&[u8]> {
        self.service.as_deref()
    }

    /// Counter the next heartbeat will carry.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    fn timeout(&self) -> Duration {
        secs(self.opts.timeout_secs)
    }

    fn max_backoff(&self) -> Duration {
        secs(self.opts.max_backoff_secs.max(self.opts.retry_secs))
    }

    fn ip_text(&self) -> String {
        self.net.ipv4().to_string()
    }

    fn udp(&self, to: SocketAddrV4, payload: Vec<u8>) -> Action {
        Action::SendUdp { local_port: self.opts.local_port, to, payload }
    }

    fn server_addr(&self) -> Option<SocketAddrV4> {
        self.server.map(|ip| SocketAddrV4::new(ip, self.opts.server_port))
    }

    fn stop(&mut self, out: &mut Vec<Action>, stop: Stop) {
        self.phase = Phase::Stopped;
        self.session = None;
        out.push(Action::Stop(stop));
    }

    fn fatal(&mut self, out: &mut Vec<Action>, message: String) {
        error!("{}", message);
        self.stop(out, Stop::Fatal(message));
    }

    /// Starts from the first step this configuration needs, like a fresh
    /// atclient process.
    fn begin_round(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.session = None;
        self.counter = codec::INITIAL_COUNTER;
        self.heartbeat_failures = 0;
        self.login_attempt = 0;
        self.server = self.fixed_server;
        self.service = self.fixed_service.clone();
        if !self.net.has_ipv4() {
            info!("等待接口 {} 获取IPv4地址...", self.interface);
            self.phase = Phase::WaitingIp;
            return;
        }
        if self.server.is_some() {
            self.after_server(now, out);
        } else {
            self.send_discovery(now, out);
        }
    }

    fn send_discovery(&mut self, now: Instant, out: &mut Vec<Action>) {
        match codec::discovery(self.ip_text().as_bytes(), &self.mac) {
            Ok(packet) => {
                info!("搜索认证服务器ip中...");
                let to = SocketAddrV4::new(self.opts.discovery_server, self.opts.discovery_port);
                out.push(self.udp(to, packet));
                self.phase = Phase::Discovering { deadline: now + self.timeout() };
            }
            Err(e) => self.fatal(out, format!("无法构造发现报文: {}", e)),
        }
    }

    fn after_server(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.service.is_some() {
            self.send_login(now, out);
        } else {
            self.send_service_query(now, out);
        }
    }

    fn send_service_query(&mut self, now: Instant, out: &mut Vec<Action>) {
        let built = match self.server_addr() {
            Some(to) => codec::service_query(&self.mac).map(|p| (to, p)).map_err(|e| e.to_string()),
            None => Err("缺少认证服务器地址".to_string()),
        };
        match built {
            Ok((to, packet)) => {
                info!("搜索认证服务中...");
                out.push(self.udp(to, packet));
                self.phase = Phase::QueryingService { deadline: now + self.timeout() };
            }
            Err(e) => self.fatal(out, format!("无法构造服务查询报文: {}", e)),
        }
    }

    fn send_login(&mut self, now: Instant, out: &mut Vec<Action>) {
        let built = match (self.server_addr(), self.service.as_deref()) {
            (Some(to), Some(service)) => codec::login(
                self.credentials.username.as_bytes(),
                self.credentials.password.as_bytes(),
                self.ip_text().as_bytes(),
                service,
                &self.mac,
            )
            .map(|p| (to, p))
            .map_err(|e| match e {
                CodecError::PacketLength(n) => {
                    format!(
                        "登录报文{}字节，超过原客户端上限{}字节（用户名、密码或认证服务过长）",
                        n,
                        codec::MAX_PACKET_LEN
                    )
                }
                other => other.to_string(),
            }),
            _ => Err("缺少认证服务器或认证服务".to_string()),
        };
        match built {
            Ok((to, packet)) => {
                self.login_attempt += 1;
                info!("登录中...（第{}/{}次）", self.login_attempt, self.opts.login_attempts.max(1));
                // The packet carries the password; never log its bytes.
                out.push(self.udp(to, packet));
                self.phase = Phase::LoggingIn { deadline: now + self.timeout() };
            }
            Err(e) => self.fatal(out, format!("无法构造登录报文: {}", e)),
        }
    }

    fn send_heartbeat(&mut self, now: Instant, out: &mut Vec<Action>) {
        let built = match (self.server_addr(), self.session.as_deref()) {
            (Some(to), Some(session)) => codec::heartbeat(session, self.ip_text().as_bytes(), &self.mac, self.counter)
                .map(|p| (to, p))
                .map_err(|e| e.to_string()),
            _ => Err("缺少认证服务器或会话".to_string()),
        };
        match built {
            Ok((to, packet)) => {
                debug!("发送心跳，计数器 {:#010x}", self.counter);
                out.push(self.udp(to, packet));
                self.phase = Phase::Heartbeat { deadline: now + self.timeout() };
            }
            Err(e) => self.fatal(out, format!("无法构造心跳报文: {}", e)),
        }
    }

    fn go_online(&mut self, now: Instant, session: Vec<u8>, out: &mut Vec<Action>) {
        info!("认证成功");
        info!("登录成功，正在发送心跳以保活");
        self.session = Some(session);
        self.counter = codec::INITIAL_COUNTER;
        self.heartbeat_failures = 0;
        self.rounds = 0;
        self.backoff = secs(self.opts.retry_secs);
        // The original sends the first heartbeat right away (VA 0x401094).
        self.send_heartbeat(now, out);
    }

    fn login_failed(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.login_attempt < self.opts.login_attempts.max(1) {
            self.phase = Phase::LoginPause { until: now + secs(self.opts.login_retry_secs) };
        } else {
            warn!("登录{}次均未成功", self.login_attempt);
            self.round_failed(now, out);
        }
    }

    fn heartbeat_failed(&mut self, now: Instant) {
        // The original never resets this count after a success (VA 0x401202
        // vs 0x401326). Counting consecutive failures keeps a healthy session
        // alive across isolated losses.
        self.heartbeat_failures += 1;
        let limit = self.opts.heartbeat_failures.max(1);
        if self.heartbeat_failures >= limit {
            warn!("心跳连续失败{}次，会话已失效，{}秒后重新认证", self.heartbeat_failures, self.opts.retry_secs);
            // doc 04.7: no logoff message is known, so the old session is
            // simply abandoned, as when the original process exits.
            self.session = None;
            self.phase = Phase::Backoff { until: now + secs(self.opts.retry_secs) };
        } else {
            warn!("心跳失败（{}/{}），重试中...", self.heartbeat_failures, limit);
            self.phase = Phase::HeartbeatPause { until: now + secs(self.opts.heartbeat_retry_secs) };
        }
    }

    fn round_failed(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.rounds += 1;
        if self.opts.max_rounds > 0 && self.rounds >= self.opts.max_rounds {
            error!("认证失败，已尝试{}轮，放弃", self.rounds);
            let stop = if self.server_seen { Stop::GaveUp { rounds: self.rounds } } else { Stop::ServerNotFound };
            self.stop(out, stop);
            return;
        }
        if self.opts.dhcp_every_rounds > 0 && self.rounds % self.opts.dhcp_every_rounds == 0 {
            info!("已连续{}轮认证失败，请求重新获取地址", self.rounds);
            out.push(Action::RequestDhcp);
        }
        let wait = self.backoff;
        self.backoff = self.backoff.saturating_mul(2).min(self.max_backoff());
        info!("{}秒后重试", wait.as_secs());
        self.phase = Phase::Backoff { until: now + wait };
    }

    /// Decodes a reply, or `None` when it must be ignored.
    fn open(&self, datagram: &Datagram<'_>, firmware_max: usize, from_server_only: bool) -> Option<Vec<u8>> {
        if from_server_only && !self.opts.accept_any_source && Some(*datagram.from.ip()) != self.server {
            debug!("忽略来自 {} 的报文（不是认证服务器）", datagram.from);
            return None;
        }
        match codec::open_response(datagram.payload, self.opts.response_check, firmware_max) {
            Ok(plain) => Some(plain),
            Err(CodecError::BadDigest) => {
                // doc 04.5: whether servers produce this digest is unconfirmed.
                warn!(
                    "来自 {} 的响应摘要校验失败，已忽略（若服务器不生成摘要，可设置 response_check = \"firmware\"）",
                    datagram.from
                );
                None
            }
            Err(e) => {
                warn!("忽略来自 {} 的无法解析的响应: {}", datagram.from, e);
                None
            }
        }
    }

    fn on_discovery_reply(&mut self, datagram: Datagram<'_>, now: Instant, out: &mut Vec<Action>) {
        // Any source: the reply to 1.1.1.8 may come from the real server or a
        // gateway, and the original accepts anything (doc 04.1).
        let Some(plain) = self.open(&datagram, codec::FIRMWARE_DISCOVERY_MAX, false) else {
            return;
        };
        match codec::server_from_discovery(&plain) {
            Ok(ip) => {
                self.server_seen = true;
                info!("已获得认证服务器ip: {}", ip);
                self.server = Some(ip);
                self.after_server(now, out);
            }
            Err(e) => warn!("发现响应中没有可用的认证服务器地址（{}），继续等待", e),
        }
    }

    fn on_service_reply(&mut self, datagram: Datagram<'_>, now: Instant, out: &mut Vec<Action>) {
        let Some(plain) = self.open(&datagram, codec::FIRMWARE_REPLY_MAX, true) else {
            return;
        };
        self.server_seen = true;
        let service = codec::service_from_plain(&plain).map(|s| codec::c_string(s).to_vec());
        match service {
            Ok(service) if !service.is_empty() => {
                info!("已获取到认证服务: {}", gbk(&service));
                self.service = Some(service);
                self.login_attempt = 0;
                self.send_login(now, out);
            }
            // The original asks for manual input here ("认证服务搜索失败1/2，请手动
            // 输入认证服务", VA 0x401232/0x401252): a configuration problem, not
            // something a retry fixes.
            Ok(_) => self.fatal(out, "认证服务搜索失败：服务器返回空的认证服务，请在配置中手动填写 service".into()),
            Err(e) => self.fatal(out, format!("认证服务搜索失败（{}），请在配置中手动填写 service", e)),
        }
    }

    fn on_login_reply(&mut self, datagram: Datagram<'_>, now: Instant, out: &mut Vec<Action>, waiting: bool) {
        let Some(plain) = self.open(&datagram, codec::FIRMWARE_REPLY_MAX, true) else {
            return;
        };
        self.server_seen = true;
        match codec::login_reply(&plain) {
            Ok(LoginReply::Session(raw)) => {
                let session = codec::c_string(raw).to_vec();
                if session.len() > codec::MAX_HEARTBEAT_SESSION {
                    // The original would send a heartbeat over 127 bytes, which
                    // its signed length reads cannot handle (doc 04.2).
                    self.fatal(
                        out,
                        format!(
                            "服务器返回的会话长{}字节，心跳报文最多容纳{}字节，无法保活",
                            session.len(),
                            codec::MAX_HEARTBEAT_SESSION
                        ),
                    );
                } else if session.is_empty() {
                    if waiting {
                        warn!("登录成功但会话为空，重试中...");
                        self.login_failed(now, out);
                    }
                } else {
                    self.go_online(now, session, out);
                }
            }
            Ok(LoginReply::Rejected) if self.opts.retry_on_reject => {
                if waiting {
                    warn!("服务器拒绝登录，按配置继续重试...");
                    self.login_failed(now, out);
                }
            }
            Ok(LoginReply::Rejected) => {
                // doc 04.5: no error-code table is known, so the reason cannot
                // be told apart. The original retries; we stop so that a wrong
                // password is not retried until the account locks (doc 09.4).
                let message = "服务器拒绝登录（账号、密码、认证服务或账号状态有误），不再自动重试".to_string();
                error!("{}", message);
                self.stop(out, Stop::Rejected { stage: RejectStage::Password, message: Some(message) });
            }
            Ok(LoginReply::NoSession) => {
                if waiting {
                    warn!("登录成功但未获得会话，重试中...");
                    self.login_failed(now, out);
                }
            }
            Err(e) => {
                if waiting {
                    warn!("登录响应无效（{}），重试中...", e);
                    self.login_failed(now, out);
                }
            }
        }
    }

    fn on_heartbeat_reply(&mut self, datagram: Datagram<'_>, now: Instant, waiting: bool) {
        let Some(plain) = self.open(&datagram, codec::FIRMWARE_REPLY_MAX, true) else {
            return;
        };
        if codec::heartbeat_accepted(&plain) {
            self.counter = codec::next_counter(self.counter);
            if self.heartbeat_failures > 0 {
                info!("心跳恢复正常");
            }
            self.heartbeat_failures = 0;
            debug!("心跳成功");
            self.phase = Phase::Online { next: now + secs(self.opts.heartbeat_secs) };
        } else if waiting {
            warn!("心跳被服务器拒绝");
            self.heartbeat_failed(now);
        } else {
            debug!("忽略迟到的心跳拒绝响应");
        }
    }
}

impl Driver for AnlangDriver {
    fn info(&self) -> &'static DriverInfo {
        &crate::INFO
    }

    fn requirements(&self) -> Requirements {
        Requirements { ethertype: None, udp_ports: vec![self.opts.local_port], needs_ipv4: true, udp_ttl: None }
    }

    fn start(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.started {
            return out;
        }
        self.started = true;
        info!("安朗认证启动，接口 {}", self.interface);
        self.begin_round(now, &mut out);
        out
    }

    fn on_datagram(&mut self, datagram: Datagram<'_>, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match self.phase {
            Phase::Discovering { .. } => self.on_discovery_reply(datagram, now, &mut out),
            Phase::QueryingService { .. } => self.on_service_reply(datagram, now, &mut out),
            // A reply that arrives after its timeout still counts if it carries
            // a session or a refusal; other late replies are ignored.
            Phase::LoggingIn { .. } => self.on_login_reply(datagram, now, &mut out, true),
            Phase::LoginPause { .. } => self.on_login_reply(datagram, now, &mut out, false),
            Phase::Heartbeat { .. } => self.on_heartbeat_reply(datagram, now, true),
            Phase::HeartbeatPause { .. } => self.on_heartbeat_reply(datagram, now, false),
            _ => debug!("忽略来自 {} 的报文（当前不等待响应）", datagram.from),
        }
        out
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match self.next_deadline() {
            Some(deadline) if now >= deadline => {}
            _ => return out,
        }
        match self.phase {
            Phase::Discovering { .. } => {
                warn!("搜索认证服务器超时");
                self.round_failed(now, &mut out);
            }
            Phase::QueryingService { .. } => {
                warn!("搜索认证服务超时");
                self.round_failed(now, &mut out);
            }
            Phase::LoggingIn { .. } => {
                warn!("登录超时");
                self.login_failed(now, &mut out);
            }
            Phase::LoginPause { .. } => self.send_login(now, &mut out),
            Phase::Online { .. } | Phase::HeartbeatPause { .. } => self.send_heartbeat(now, &mut out),
            Phase::Heartbeat { .. } => {
                warn!("心跳超时");
                self.heartbeat_failed(now);
            }
            Phase::Backoff { .. } => self.begin_round(now, &mut out),
            Phase::Idle | Phase::WaitingIp | Phase::Stopped => {}
        }
        out
    }

    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let old = self.net;
        self.net = net;
        if !self.started || self.phase == Phase::Stopped {
            return out;
        }
        if !net.has_ipv4() {
            if self.phase != Phase::WaitingIp {
                warn!("接口 {} 失去IPv4地址，暂停认证", self.interface);
                self.session = None;
                self.phase = Phase::WaitingIp;
            }
            return out;
        }
        match self.phase {
            Phase::WaitingIp => {
                info!("接口已获得IPv4地址 {}", net.ipv4());
                self.begin_round(now, &mut out);
            }
            // The next round picks up the new address.
            Phase::Backoff { .. } => {}
            // Every request carries the address text; a session bound to the
            // old address is stale (doc 09.3).
            _ if old.ip != net.ip => {
                info!("接口地址由 {} 变为 {}，重新认证", old.ipv4(), net.ipv4());
                self.begin_round(now, &mut out);
            }
            _ => {}
        }
        out
    }

    fn next_deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Discovering { deadline }
            | Phase::QueryingService { deadline }
            | Phase::LoggingIn { deadline }
            | Phase::Heartbeat { deadline } => Some(deadline),
            Phase::LoginPause { until } | Phase::HeartbeatPause { until } | Phase::Backoff { until } => Some(until),
            Phase::Online { next } => Some(next),
            Phase::Idle | Phase::WaitingIp | Phase::Stopped => None,
        }
    }

    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.phase == Phase::Stopped {
            return out;
        }
        if self.session.is_some() {
            // doc 04.7 / doc 10.2 AT-01: no logoff message was recovered from
            // atclient. The original is just killed (init.d `killall
            // atclient`), and the server session expires once heartbeats stop.
            info!("安朗协议没有已知的下线报文，服务器端会话将在心跳停止后自行失效");
        }
        self.stop(&mut out, Stop::Finished);
        out
    }

    fn state(&self) -> AuthState {
        match self.phase {
            Phase::Idle => AuthState::Idle,
            Phase::WaitingIp => AuthState::WaitingIp,
            // Finding the server and the service both count as discovery
            // (doc 09.4: "找到服务器/服务" leads to authenticating).
            Phase::Discovering { .. } | Phase::QueryingService { .. } => AuthState::Discovering,
            Phase::LoggingIn { .. } | Phase::LoginPause { .. } => AuthState::Authenticating,
            Phase::Online { .. } | Phase::Heartbeat { .. } | Phase::HeartbeatPause { .. } => AuthState::Online,
            Phase::Backoff { .. } => AuthState::Backoff,
            Phase::Stopped => AuthState::Stopped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{op, unseal, Packet};
    use crate::testjson::Json;
    use serde::de::value::{Error as DeError, MapDeserializer};

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const LOCAL: [u8; 4] = [192, 0, 2, 10];
    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

    fn env() -> Env {
        Env { interface: "wan".into(), mac: MAC, net: NetInfo { ip: LOCAL, ..NetInfo::default() } }
    }

    fn driver(opts: Options) -> AnlangDriver {
        AnlangDriver::new(env(), Credentials::new("alice", "synthetic"), opts).unwrap()
    }

    fn server_addr() -> SocketAddrV4 {
        SocketAddrV4::new(SERVER, 3848)
    }

    fn discovery_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 8), 3850)
    }

    /// Scripted fake server. Reply op codes are synthetic: the real ones are
    /// unknown (doc 04.5). Only the offsets the original reads are filled.
    mod fake {
        use super::*;
        use crate::codec::{seal, tlv};

        pub fn discovery(ip: Ipv4Addr) -> Vec<u8> {
            seal(13, &tlv(12, &ip.octets()).unwrap()).unwrap()
        }
        pub fn service(name: &[u8]) -> Vec<u8> {
            seal(8, &tlv(10, name).unwrap()).unwrap()
        }
        pub fn login_ok(session: &[u8]) -> Vec<u8> {
            let mut payload = vec![0, 0, 1, 8, session.len() as u8];
            payload.extend_from_slice(session);
            seal(2, &payload).unwrap()
        }
        pub fn login_rejected() -> Vec<u8> {
            seal(2, &[0, 0, 0]).unwrap()
        }
        pub fn login_no_session() -> Vec<u8> {
            seal(2, &[0, 0, 1, 0]).unwrap()
        }
        pub fn heartbeat_ok() -> Vec<u8> {
            seal(4, &[0, 0, 1]).unwrap()
        }
        pub fn heartbeat_rejected() -> Vec<u8> {
            seal(4, &[0, 0, 0]).unwrap()
        }
    }

    fn dg(from: SocketAddrV4, payload: &[u8]) -> Datagram<'_> {
        Datagram { local_port: 0, from, payload }
    }

    fn sends(actions: &[Action]) -> Vec<(SocketAddrV4, Vec<u8>)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendUdp { local_port, to, payload } => {
                    assert_eq!(*local_port, 0);
                    Some((*to, payload.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// The one request in `actions`, decoded.
    fn request(actions: &[Action]) -> (SocketAddrV4, Packet) {
        let sent = sends(actions);
        assert_eq!(sent.len(), 1, "{:?}", actions);
        let (to, payload) = sent.into_iter().next().unwrap();
        let packet = unseal(&payload).unwrap();
        assert!(packet.digest_valid);
        (to, packet)
    }

    fn field(packet: &Packet, kind: u8) -> Vec<u8> {
        codec::parse_tlvs(packet.payload())
            .unwrap()
            .into_iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| v.to_vec())
            .unwrap_or_else(|| panic!("no TLV {}", kind))
    }

    fn stop_of(actions: &[Action]) -> Option<Stop> {
        actions.iter().find_map(|a| match a {
            Action::Stop(s) => Some(s.clone()),
            _ => None,
        })
    }

    /// Drives a default session to the first heartbeat; returns the time.
    fn online(d: &mut AnlangDriver, t0: Instant) -> Instant {
        d.start(t0);
        d.on_datagram(dg(discovery_addr(), &fake::discovery(SERVER)), t0);
        d.on_datagram(dg(server_addr(), &fake::service(b"campus")), t0);
        let a = d.on_datagram(dg(server_addr(), &fake::login_ok(b"session")), t0);
        let (_, hb) = request(&a);
        assert_eq!(hb.kind, op::HEARTBEAT);
        assert_eq!(d.state(), AuthState::Online);
        t0
    }

    #[test]
    fn info_and_requirements() {
        let d = driver(Options::default());
        assert_eq!(d.info().name, "anlang");
        assert_eq!(d.info().support, gswifi_core::SupportLevel::OfflineTested);
        assert_eq!(d.requirements(), Requirements { ethertype: None, udp_ports: vec![0], needs_ipv4: true, udp_ttl: None });
        assert_eq!(d.state(), AuthState::Idle);
        assert_eq!(d.next_deadline(), None);
    }

    #[test]
    fn full_exchange_discovery_to_heartbeats() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());

        let a = d.start(t0);
        let (to, p) = request(&a);
        assert_eq!(to, discovery_addr());
        assert_eq!(p.kind, op::DISCOVERY);
        assert_eq!(p.plain.len(), 51);
        assert_eq!(field(&p, 9), b"192.0.2.10\0\0\0\0\0\0");
        assert_eq!(d.state(), AuthState::Discovering);
        assert_eq!(d.next_deadline(), Some(t0 + secs(10)));
        assert!(d.start(t0).is_empty(), "start is idempotent");

        // Reply comes from the real server rather than 1.1.1.8: accepted.
        let t1 = t0 + secs(1);
        let a = d.on_datagram(dg(SocketAddrV4::new(Ipv4Addr::new(10, 9, 9, 9), 3850), &fake::discovery(SERVER)), t1);
        let (to, p) = request(&a);
        assert_eq!(d.server(), Some(SERVER));
        assert_eq!(to, server_addr());
        assert_eq!(p.kind, op::SERVICE_QUERY);
        assert_eq!(d.state(), AuthState::Discovering);

        let a = d.on_datagram(dg(server_addr(), &fake::service(b"campus")), t1);
        let (to, p) = request(&a);
        assert_eq!(to, server_addr());
        assert_eq!(p.kind, op::LOGIN);
        assert_eq!(d.service(), Some(&b"campus"[..]));
        assert_eq!(
            codec::parse_tlvs(p.payload()).unwrap(),
            vec![
                (7, &MAC[..]),
                (1, &b"alice"[..]),
                (2, &b"synthetic"[..]),
                (9, &b"192.0.2.10"[..]),
                (10, &b"campus"[..]),
                (14, &b"\0"[..]),
                (31, &b"4.2.0"[..]),
            ]
        );
        assert_eq!(d.state(), AuthState::Authenticating);

        let a = d.on_datagram(dg(server_addr(), &fake::login_ok(b"S3SS10N")), t1);
        let (to, p) = request(&a);
        assert_eq!(to, server_addr());
        assert_eq!(p.kind, op::HEARTBEAT);
        assert_eq!(field(&p, 8), b"S3SS10N");
        assert_eq!(field(&p, 20), [1, 0, 0, 0]);
        assert_eq!(d.state(), AuthState::Online);
        assert_eq!(d.next_deadline(), Some(t1 + secs(10)));

        let a = d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t1);
        assert!(a.is_empty());
        assert_eq!(d.next_deadline(), Some(t1 + secs(20)));
        assert!(d.on_timer(t1 + secs(19)).is_empty(), "early timer does nothing");

        let t2 = t1 + secs(20);
        let (_, p) = request(&d.on_timer(t2));
        assert_eq!(field(&p, 20), [1, 0, 0, 3]);
        d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t2);
        let (_, p) = request(&d.on_timer(t2 + secs(20)));
        assert_eq!(field(&p, 20), [1, 0, 0, 6]);
        assert_eq!(d.counter(), 0x0100_0006);
    }

    #[test]
    fn driver_requests_match_golden_vectors() {
        let doc = Json::parse(include_str!("../testdata/vectors.json")).unwrap();
        let wire = |name: &str| {
            let r = doc.get("requests").arr().iter().find(|r| r.get("name").str() == name).unwrap();
            hex::decode(r.get("wire_hex").str()).unwrap()
        };
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let a = d.start(t0);
        assert_eq!(sends(&a)[0].1, wire("discovery"));
        let a = d.on_datagram(dg(discovery_addr(), &fake::discovery(SERVER)), t0);
        assert_eq!(sends(&a)[0].1, wire("service_query"));
        let a = d.on_datagram(dg(server_addr(), &fake::service(b"campus")), t0);
        assert_eq!(sends(&a)[0].1, wire("login"));
        let a = d.on_datagram(dg(server_addr(), &fake::login_ok(b"session")), t0);
        assert_eq!(sends(&a)[0].1, wire("heartbeat"));
    }

    #[test]
    fn configured_server_and_service_skip_discovery() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() });
        let (to, p) = request(&d.start(t0));
        assert_eq!(to, server_addr());
        assert_eq!(p.kind, op::LOGIN);
        assert_eq!(field(&p, 10), b"campus");

        let mut d = driver(Options { server: " 10.0.0.5 ".into(), ..Options::default() });
        let (to, p) = request(&d.start(t0));
        assert_eq!(to, server_addr());
        assert_eq!(p.kind, op::SERVICE_QUERY);

        // Service only: discovery still runs, then login directly.
        let mut d = driver(Options { service: "campus".into(), ..Options::default() });
        let (_, p) = request(&d.start(t0));
        assert_eq!(p.kind, op::DISCOVERY);
        let (_, p) = request(&d.on_datagram(dg(discovery_addr(), &fake::discovery(SERVER)), t0));
        assert_eq!(p.kind, op::LOGIN);
    }

    #[test]
    fn login_rejection_stops_when_configured() {
        let t0 = Instant::now();
        let mut d = driver(Options {
            server: "10.0.0.5".into(),
            service: "campus".into(),
            retry_on_reject: false,
            ..Options::default()
        });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &fake::login_rejected()), t0);
        assert!(sends(&a).is_empty());
        let stop = stop_of(&a).unwrap();
        assert!(matches!(stop, Stop::Rejected { stage: RejectStage::Password, message: Some(_) }));
        assert_eq!(stop.exit_code(), 3);
        assert_eq!(d.state(), AuthState::Stopped);
        assert_eq!(d.next_deadline(), None);
        assert!(d.on_timer(t0 + secs(100)).is_empty());
        assert!(d.on_datagram(dg(server_addr(), &fake::login_ok(b"x")), t0).is_empty());
        assert!(d.logoff(t0).is_empty());
    }

    #[test]
    fn rejection_is_retried_by_default() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &fake::login_rejected()), t0);
        assert!(a.is_empty());
        assert_eq!(d.next_deadline(), Some(t0 + secs(5)));
        let (_, p) = request(&d.on_timer(t0 + secs(5)));
        assert_eq!(p.kind, op::LOGIN);
    }

    #[test]
    fn login_timeouts_then_backoff_round() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() });
        d.start(t0);
        let mut t = t0;
        for attempt in 1..=3 {
            t += secs(10);
            let a = d.on_timer(t);
            assert!(a.is_empty(), "attempt {}", attempt);
            if attempt < 3 {
                assert_eq!(d.state(), AuthState::Authenticating);
                t += secs(5);
                let (_, p) = request(&d.on_timer(t));
                assert_eq!(p.kind, op::LOGIN);
            }
        }
        assert_eq!(d.state(), AuthState::Backoff);
        assert_eq!(d.next_deadline(), Some(t + secs(5)));
        // A new round starts from the first needed step (login here).
        t += secs(5);
        let (_, p) = request(&d.on_timer(t));
        assert_eq!(p.kind, op::LOGIN);
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let t0 = Instant::now();
        let mut d = driver(Options { max_backoff_secs: 20, dhcp_every_rounds: 0, ..Options::default() });
        d.start(t0);
        let mut t = t0;
        let mut waits = Vec::new();
        for _ in 0..5 {
            t += secs(10);
            assert!(d.on_timer(t).is_empty());
            let until = d.next_deadline().unwrap();
            waits.push((until - t).as_secs());
            t = until;
            let (to, p) = request(&d.on_timer(t));
            assert_eq!(to, discovery_addr());
            assert_eq!(p.kind, op::DISCOVERY);
        }
        assert_eq!(waits, [5, 10, 20, 20, 20]);
    }

    #[test]
    fn server_not_found_after_max_rounds() {
        let t0 = Instant::now();
        let mut d = driver(Options { max_rounds: 2, ..Options::default() });
        d.start(t0);
        assert!(d.on_timer(t0 + secs(10)).is_empty());
        d.on_timer(t0 + secs(15));
        let a = d.on_timer(t0 + secs(25));
        assert_eq!(stop_of(&a), Some(Stop::ServerNotFound));
        assert_eq!(Stop::ServerNotFound.exit_code(), 255);
        assert_eq!(d.state(), AuthState::Stopped);
    }

    #[test]
    fn gave_up_when_server_answered() {
        let t0 = Instant::now();
        let mut d = driver(Options { max_rounds: 1, login_attempts: 1, ..Options::default() });
        d.start(t0);
        d.on_datagram(dg(discovery_addr(), &fake::discovery(SERVER)), t0);
        d.on_datagram(dg(server_addr(), &fake::service(b"campus")), t0);
        let a = d.on_timer(t0 + secs(10));
        assert_eq!(stop_of(&a), Some(Stop::GaveUp { rounds: 1 }));
    }

    #[test]
    fn dhcp_requested_every_n_failed_rounds() {
        let t0 = Instant::now();
        let mut d = driver(Options { dhcp_every_rounds: 2, ..Options::default() });
        d.start(t0);
        let a = d.on_timer(t0 + secs(10));
        assert!(!a.contains(&Action::RequestDhcp));
        let t = d.next_deadline().unwrap();
        d.on_timer(t);
        let a = d.on_timer(t + secs(10));
        assert_eq!(a, vec![Action::RequestDhcp]);
        assert_eq!(d.state(), AuthState::Backoff);
    }

    #[test]
    fn heartbeat_failures_resend_same_counter_then_relogin() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let t = online(&mut d, t0);
        // One success, so the counter is past its initial value.
        d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t);
        let mut t = t + secs(20);
        let (_, p) = request(&d.on_timer(t));
        assert_eq!(field(&p, 20), [1, 0, 0, 3]);

        // Timeout -> 1 s pause -> same counter.
        t += secs(10);
        assert!(d.on_timer(t).is_empty());
        assert_eq!(d.state(), AuthState::Online);
        t += secs(1);
        let (_, p) = request(&d.on_timer(t));
        assert_eq!(field(&p, 20), [1, 0, 0, 3]);

        // Refusal counts as the second failure.
        assert!(d.on_datagram(dg(server_addr(), &fake::heartbeat_rejected()), t).is_empty());
        t += secs(1);
        let (_, p) = request(&d.on_timer(t));
        assert_eq!(field(&p, 20), [1, 0, 0, 3]);

        // Third failure: session lost, new round after 5 s with a fresh counter.
        t += secs(10);
        assert!(d.on_timer(t).is_empty());
        assert_eq!(d.state(), AuthState::Backoff);
        assert_eq!(d.next_deadline(), Some(t + secs(5)));
        t += secs(5);
        let (to, p) = request(&d.on_timer(t));
        assert_eq!((to, p.kind), (discovery_addr(), op::DISCOVERY));
        assert_eq!(d.counter(), codec::INITIAL_COUNTER);
        assert_eq!(d.server(), None);
    }

    #[test]
    fn heartbeat_failures_are_consecutive() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let mut t = online(&mut d, t0);
        // Fail, recover, fail, recover... never three in a row.
        for _ in 0..5 {
            t += secs(10);
            d.on_timer(t);
            t += secs(1);
            request(&d.on_timer(t));
            d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t);
            assert_eq!(d.state(), AuthState::Online);
            t += secs(20);
            request(&d.on_timer(t));
        }
        assert_eq!(d.state(), AuthState::Online);
    }

    #[test]
    fn late_replies_during_pauses() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() });
        d.start(t0);
        d.on_timer(t0 + secs(10));
        assert_eq!(d.next_deadline(), Some(t0 + secs(15)));
        // A late "no session" during the pause does not count twice.
        assert!(d.on_datagram(dg(server_addr(), &fake::login_no_session()), t0 + secs(11)).is_empty());
        assert_eq!(d.next_deadline(), Some(t0 + secs(15)));
        // A late session is taken.
        let (_, p) = request(&d.on_datagram(dg(server_addr(), &fake::login_ok(b"late")), t0 + secs(12)));
        assert_eq!(field(&p, 8), b"late");
        // Late heartbeat success during the resend pause restores the schedule.
        let t = t0 + secs(22);
        d.on_timer(t);
        assert!(d.on_datagram(dg(server_addr(), &fake::heartbeat_rejected()), t).is_empty());
        assert_eq!(d.next_deadline(), Some(t + secs(1)));
        d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t);
        assert_eq!(d.next_deadline(), Some(t + secs(20)));
        assert_eq!(d.counter(), 0x0100_0003);
    }

    #[test]
    fn no_session_and_empty_session_are_retried() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() });
        d.start(t0);
        assert!(d.on_datagram(dg(server_addr(), &fake::login_no_session()), t0).is_empty());
        assert_eq!(d.state(), AuthState::Authenticating);
        request(&d.on_timer(t0 + secs(5)));
        // Session that is all NUL is empty as a C string.
        assert!(d.on_datagram(dg(server_addr(), &fake::login_ok(b"\0abc")), t0 + secs(5)).is_empty());
        assert_eq!(d.next_deadline(), Some(t0 + secs(10)));
        // Session with an inner NUL is cut, like the original's strlen.
        request(&d.on_timer(t0 + secs(10)));
        let (_, p) = request(&d.on_datagram(dg(server_addr(), &fake::login_ok(b"ab\0cd")), t0 + secs(10)));
        assert_eq!(field(&p, 8), b"ab");
    }

    #[test]
    fn oversized_session_is_fatal() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), service: "s".into(), ..Options::default() });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &fake::login_ok(&[b's'; 40])), t0);
        assert!(matches!(stop_of(&a), Some(Stop::Fatal(_))));
    }

    #[test]
    fn malformed_datagrams_are_ignored() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        d.start(t0);
        let deadline = d.next_deadline();
        let good = fake::discovery(SERVER);
        let mut bad_digest = good.clone();
        bad_digest[4] ^= 0x01;
        let samples: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xff],
            good[..good.len() - 1].to_vec(),
            bad_digest,
            vec![0x55; 200],
            codec::seal(13, b"\x03\x04ab").unwrap(),
        ];
        for sample in &samples {
            assert!(d.on_datagram(dg(discovery_addr(), sample), t0).is_empty());
            assert_eq!(d.state(), AuthState::Discovering);
            assert_eq!(d.next_deadline(), deadline);
        }
        // Still usable afterwards.
        let (_, p) = request(&d.on_datagram(dg(discovery_addr(), &good), t0));
        assert_eq!(p.kind, op::SERVICE_QUERY);
    }

    #[test]
    fn source_address_is_checked_after_discovery() {
        let t0 = Instant::now();
        let stranger = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 66), 3848);
        let mut d = driver(Options { server: "10.0.0.5".into(), ..Options::default() });
        d.start(t0);
        assert!(d.on_datagram(dg(stranger, &fake::service(b"campus")), t0).is_empty());
        assert_eq!(d.service(), None);
        // Source port is not checked.
        let (_, p) = request(&d.on_datagram(dg(SocketAddrV4::new(SERVER, 40000), &fake::service(b"campus")), t0));
        assert_eq!(p.kind, op::LOGIN);

        let mut d = driver(Options { server: "10.0.0.5".into(), accept_any_source: true, ..Options::default() });
        d.start(t0);
        let (_, p) = request(&d.on_datagram(dg(stranger, &fake::service(b"campus")), t0));
        assert_eq!(p.kind, op::LOGIN);
    }

    #[test]
    fn firmware_response_check_accepts_bad_digest() {
        let t0 = Instant::now();
        let mut reply = fake::login_ok(b"sess");
        reply[3] ^= 0x01; // digest byte
        let opts = Options { server: "10.0.0.5".into(), service: "campus".into(), ..Options::default() };
        let mut strict = driver(opts.clone());
        strict.start(t0);
        assert!(strict.on_datagram(dg(server_addr(), &reply), t0).is_empty());
        assert_eq!(strict.state(), AuthState::Authenticating);

        let mut lenient = driver(Options { response_check: ResponseCheck::Firmware, ..opts });
        lenient.start(t0);
        let (_, p) = request(&lenient.on_datagram(dg(server_addr(), &reply), t0));
        assert_eq!(field(&p, 8), b"sess");
    }

    #[test]
    fn bad_service_reply_is_fatal() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), ..Options::default() });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &codec::seal(8, b"\x0b\x04ab").unwrap()), t0);
        assert!(matches!(stop_of(&a), Some(Stop::Fatal(_))));
        assert_eq!(stop_of(&a).unwrap().exit_code(), 1);

        let mut d = driver(Options { server: "10.0.0.5".into(), ..Options::default() });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &fake::service(b"")), t0);
        assert!(matches!(stop_of(&a), Some(Stop::Fatal(_))));
    }

    #[test]
    fn discovered_service_too_long_for_login_is_fatal() {
        let t0 = Instant::now();
        let mut d = driver(Options { server: "10.0.0.5".into(), ..Options::default() });
        d.start(t0);
        let a = d.on_datagram(dg(server_addr(), &fake::service(&[b'x'; 80])), t0);
        assert!(matches!(stop_of(&a), Some(Stop::Fatal(_))));
    }

    #[test]
    fn address_change_and_loss() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let t = online(&mut d, t0);
        let same = env().net;
        assert!(d.on_net_change(same, t).is_empty());
        assert_eq!(d.state(), AuthState::Online);

        // New address while online: start over with the new address text.
        let new = NetInfo { ip: [192, 0, 2, 77], ..NetInfo::default() };
        let (to, p) = request(&d.on_net_change(new, t));
        assert_eq!((to, p.kind), (discovery_addr(), op::DISCOVERY));
        assert_eq!(field(&p, 9), b"192.0.2.77\0\0\0\0\0\0");

        // Address lost: wait without deadline, then resume.
        assert!(d.on_net_change(NetInfo::default(), t).is_empty());
        assert_eq!(d.state(), AuthState::WaitingIp);
        assert_eq!(d.next_deadline(), None);
        let (_, p) = request(&d.on_net_change(same, t));
        assert_eq!(p.kind, op::DISCOVERY);
        assert_eq!(field(&p, 9), b"192.0.2.10\0\0\0\0\0\0");
    }

    #[test]
    fn start_without_address_waits() {
        let t0 = Instant::now();
        let mut e = env();
        e.net = NetInfo::default();
        let mut d = AnlangDriver::new(e, Credentials::new("alice", "synthetic"), Options::default()).unwrap();
        // Before start, address changes are only recorded.
        assert!(d.on_net_change(NetInfo::default(), t0).is_empty());
        assert!(d.start(t0).is_empty());
        assert_eq!(d.state(), AuthState::WaitingIp);
        let (_, p) = request(&d.on_net_change(env().net, t0));
        assert_eq!(p.kind, op::DISCOVERY);
    }

    #[test]
    fn logoff_has_no_protocol_message() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let t = online(&mut d, t0);
        let a = d.logoff(t);
        assert_eq!(a, vec![Action::Stop(Stop::Finished)]);
        assert_eq!(d.state(), AuthState::Stopped);
        assert!(d.logoff(t).is_empty());
        assert!(d.on_net_change(NetInfo::default(), t).is_empty());
    }

    #[test]
    fn unexpected_datagrams_while_online_are_ignored() {
        let t0 = Instant::now();
        let mut d = driver(Options::default());
        let t = online(&mut d, t0);
        d.on_datagram(dg(server_addr(), &fake::heartbeat_ok()), t);
        let deadline = d.next_deadline();
        assert!(d.on_datagram(dg(server_addr(), &fake::login_rejected()), t).is_empty());
        assert_eq!(d.next_deadline(), deadline);
        assert_eq!(d.state(), AuthState::Online);
    }

    #[test]
    fn random_datagrams_in_every_phase_never_panic() {
        let mut seed = 0x1234_5678_u64;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };
        let t0 = Instant::now();
        for phase_steps in 0..5 {
            let mut d = driver(Options::default());
            d.start(t0);
            let script =
                [fake::discovery(SERVER), fake::service(b"campus"), fake::login_ok(b"session"), fake::heartbeat_ok()];
            let from = |i: usize| if i == 0 { discovery_addr() } else { server_addr() };
            for (i, reply) in script.iter().take(phase_steps).enumerate() {
                d.on_datagram(dg(from(i), reply), t0);
            }
            for _ in 0..500 {
                let len = next() as usize % 140;
                let mut data: Vec<u8> = (0..len).map(|_| next()).collect();
                if (18..=codec::MAX_PACKET_LEN).contains(&len) && len % 3 == 0 {
                    data = codec::seal(next(), &data[18..]).unwrap();
                }
                d.on_datagram(dg(server_addr(), &data), t0);
                d.on_datagram(dg(discovery_addr(), &data), t0);
            }
        }
    }

    #[test]
    fn new_validates_configuration() {
        let make = |user: &str, pass: &str, opts: Options| AnlangDriver::new(env(), Credentials::new(user, pass), opts);
        assert!(make("", "p", Options::default()).is_err());
        assert!(make("u", "", Options::default()).is_err());
        assert!(make("u\0x", "p", Options::default()).is_err());
        assert!(make("u", "p", Options { server: "10.0.0".into(), ..Options::default() }).is_err());
        assert!(make("u", "p", Options { server: "0.0.0.0".into(), ..Options::default() }).is_err());
        assert!(make("u", "p", Options { server: "255.255.255.255".into(), ..Options::default() }).is_err());
        assert!(make("u", "p", Options { service: "a\0".into(), ..Options::default() }).is_err());
        assert!(make("u", "p", Options { timeout_secs: 0, ..Options::default() }).is_err());
        assert!(make("u", "p", Options { heartbeat_secs: 0, ..Options::default() }).is_err());
        assert!(make("u", "p", Options { heartbeat_secs: u64::MAX, ..Options::default() }).is_err());
        assert!(make("u", "p", Options { login_retry_secs: 0, heartbeat_retry_secs: 0, ..Options::default() }).is_ok());
        // 44 + U + P + 15 + S <= 127.
        let user = "u".repeat(60);
        assert!(make(&user, "pppppppp", Options::default()).is_ok());
        assert!(make(&user, "ppppppppp", Options::default()).is_err());
        assert!(make(&user, "pppp", Options { service: "campus".into(), ..Options::default() }).is_err());
    }

    #[test]
    fn options_deserialize_with_uci_aliases() {
        let opts = Options::deserialize(MapDeserializer::<_, DeError>::new(
            vec![
                ("sip", "10.0.0.5"),
                ("stype", "campus"),
                ("discovery_server", "1.1.1.9"),
                ("response_check", "firmware"),
            ]
            .into_iter(),
        ))
        .unwrap();
        assert_eq!(opts.server, "10.0.0.5");
        assert_eq!(opts.service, "campus");
        assert_eq!(opts.discovery_server, Ipv4Addr::new(1, 1, 1, 9));
        assert_eq!(opts.response_check, ResponseCheck::Firmware);
        assert_eq!(opts.timeout_secs, 10, "missing fields keep firmware defaults");
        assert_eq!(opts.server_port, 3848);
    }
}
