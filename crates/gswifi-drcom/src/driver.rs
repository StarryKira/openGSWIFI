//! Sans-IO Dogcom-style session (doc 03 §3.2–3.5).
//!
//! DHCP mode (doc 03 §3.2):
//! challenge → 200 ms → login → keepalive1 → 200 ms → keepalive2 (file
//! handshake once, then type 1 / type 3) → 20 s → keepalive1 …
//!
//! PPPoE mode (doc 03 §3.5): challenge(8) → login96 → keepalive2 rounds
//! every ~10 s.
//!
//! Every request waits `timeout_secs` (doc 03 §3.1: 3 s receive timeout).
//! Explicit refusals stop the session without retrying (doc 09.4); "server
//! busy" (code 2) is retried. Lost keepalives lead to a new login.

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use gswifi_core::{
    Action, AuthState, Credentials, Datagram, Driver, DriverInfo, Env, NetInfo, RejectStage, Requirements, Stop,
};
use log::{debug, error, info, warn};

use crate::gs::error_text;
use crate::packet::{
    challenge_request, keepalive1, keepalive1_mod, keepalive1_mod_request, login, parse_challenge_response,
    parse_keepalive1_mod_seed, parse_keepalive2_tail, parse_keepalive_reply, parse_login_reply, parse_pppoe_challenge,
    pppoe_challenge, pppoe_login, Keepalive2, KeepaliveReply, LoginLayout, LoginParams, LoginReply, OsVersion,
    PppoeChallenge, CHALLENGE_DOGCOM_LOGIN, DRCOM_PORT, KEEPALIVE1_DOGCOM_LEN, MAX_HOST_NAME, MAX_HOST_OS,
    MAX_PASSWORD, MAX_USERNAME,
};
use crate::{parse_hex, Mode, Options, Variant, INFO};

/// Delay between challenge and login, keepalive1 and keepalive2 (doc 03 §3.2).
const STEP_DELAY: Duration = Duration::from_millis(200);
/// Wait after "server busy" (doc 03 §3.2: failures retry after about 3 s).
const BUSY_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    WaitingIp,
    Challenge,
    PreLogin,
    Login,
    PreKa1,
    Ka1ModSeed,
    Ka1,
    PreKa2,
    Ka2File,
    Ka2Type1,
    Ka2Type3,
    Sleep,
    PppChallenge,
    PppLogin,
    Backoff,
    Stopped,
}

impl Phase {
    fn awaiting_auth(self) -> bool {
        matches!(self, Phase::Challenge | Phase::Login | Phase::PppChallenge | Phase::PppLogin)
    }

    fn awaiting_keepalive(self) -> bool {
        matches!(self, Phase::Ka1ModSeed | Phase::Ka1 | Phase::Ka2File | Phase::Ka2Type1 | Phase::Ka2Type3)
    }
}

/// Validated profile.
#[derive(Clone, Debug)]
struct Profile {
    mode: Mode,
    server: SocketAddrV4,
    mac: [u8; 6],
    host_name: Vec<u8>,
    host_os: Vec<u8>,
    primary_dns: Option<[u8; 4]>,
    dhcp_server: [u8; 4],
    os: OsVersion,
    auth_version: [u8; 2],
    keep_alive_version: [u8; 2],
    control_check_status: u8,
    adapter_num: u8,
    ip_dog: u8,
    ror: bool,
    keepalive1_mod: bool,
    pppoe_flag: u8,
    timeout: Duration,
    interval: Duration,
    max_retries: u32,
    keepalive_max_fail: u32,
    eternal: bool,
    backoff: Duration,
}

/// Dr.com session driver (see the crate docs for supported variants).
pub struct DrcomDriver {
    p: Profile,
    creds: Credentials,
    net: NetInfo,
    phase: Phase,
    state: AuthState,
    deadline: Option<Instant>,
    /// Last request, resent on timeout.
    last: Vec<u8>,
    /// Consecutive failed login rounds.
    attempts: u32,
    /// Consecutive keepalive timeouts.
    ka_fail: u32,
    /// The server answered at least once during this run.
    answered: bool,
    rng: u64,
    seed: [u8; 4],
    md5a: [u8; 16],
    auth_info: [u8; 16],
    ka1_counter: u8,
    ka2_counter: u32,
    tail: [u8; 4],
    file_done: bool,
    ppp: Option<PppoeChallenge>,
    ppp_counter: u8,
    ppp_logged_in_once: bool,
}

fn two(name: &str, value: &Option<String>) -> Result<Option<[u8; 2]>, String> {
    match value {
        None => Ok(None),
        Some(s) => {
            let b = parse_hex(s)?;
            if b.len() != 2 {
                return Err(format!("{name} 必须是 2 字节十六进制（如 \"2700\"），实际 {} 字节", b.len()));
            }
            Ok(Some([b[0], b[1]]))
        }
    }
}

impl DrcomDriver {
    /// Validates the options and prepares a session. GS variants, DrMode
    /// profiles and inconsistent profiles are refused with an explanation.
    pub fn new(env: Env, credentials: Credentials, options: Options) -> Result<Self, String> {
        match options.variant {
            Variant::Dogcom => {}
            Variant::GsD => {
                return Err("Dr.com GS D版（MentoHUST AuthType3）暂不支持：登录体、keepalive1 与控制包已按第30.3节回放逐字节验证（见 gs 模块），\
                    但在线阶段图、重发调度与首次失败后的隐藏回退标志尚未完整（第30.3/30.7/30.8节）。不会改用其他协议代发；\
                    如学校使用 Dogcom 布局，请显式设置 variant = \"dogcom\"（第03篇）。"
                    .into())
            }
            Variant::GsX => {
                return Err("Dr.com GS X版（AuthType4）暂不支持：需要 802.1X EAP 交换，研究只有统一 UDP 合成输入，没有真实 EAP 交换（第30节、第30.8节）。".into())
            }
            Variant::GsP => {
                return Err("Dr.com GS P版（AuthType5）暂不支持：在线 tick 的 38 字节报文（MD5A 位置为测试夹具）与周期性重新挑战未确定（第30.3节）。\
                    PPPoE 辅助保活请使用 variant = \"dogcom\"、mode = \"pppoe\"（第03.5节）。"
                    .into())
            }
            Variant::GsPt => {
                return Err("Dr.com GS Pt版（AuthType6）暂不支持：244 字节登录体没有独立编码规格，注销走 EAPOL（第30.3/30.8节）。".into())
            }
        }
        if options.dr_mode != 0 {
            return Err(format!(
                "dr_mode = {} 属于 GS MentoHUST 学校 profile（第30.1节），dogcom 变体不能使用；DrMode4 另需 TCP 9002 辅助请求（第30.6节），DrMode5 的另一发送路径未知。",
                options.dr_mode
            ));
        }
        if options.server.is_unspecified() {
            return Err("必须设置 Dr.com 认证服务器地址 server".into());
        }
        let mode = options.mode;
        let mac = match &options.mac {
            Some(s) => gswifi_core::parse_mac(s).ok_or_else(|| format!("无效的 MAC 地址：{s}"))?,
            None => env.mac,
        };
        let auth_version = two("auth_version", &options.auth_version)?;
        let keep_alive_version = two("keep_alive_version", &options.keep_alive_version)?;
        let host_os = match &options.host_os_hex {
            Some(h) => parse_hex(h)?,
            None => options.host_os.as_bytes().to_vec(),
        };
        if options.host_name.len() > MAX_HOST_NAME {
            return Err(format!("host_name 超过 {MAX_HOST_NAME} 字节（第03.2节：会覆盖后续固定字段）"));
        }
        if host_os.len() > MAX_HOST_OS {
            return Err(format!("host_os 超过 {MAX_HOST_OS} 字节"));
        }
        if options.timeout_secs == 0 || options.max_retries == 0 || options.keepalive_max_fail == 0 {
            return Err("timeout_secs、max_retries 与 keepalive_max_fail 必须大于 0".into());
        }
        let (auth_version, keep_alive_version, pppoe_flag) = match mode {
            Mode::Dhcp => {
                let user = credentials.username.as_bytes();
                if user.is_empty() || user.len() > MAX_USERNAME {
                    return Err(format!(
                        "用户名必须为 1..={MAX_USERNAME} 字节（第03.2节：用户名区域在 offset 56 之前结束）"
                    ));
                }
                let pw = credentials.password.as_bytes().len();
                if pw > MAX_PASSWORD || (options.ror_version && pw > 16) {
                    return Err("密码过长：ror_version 时最多 16 字节（第03.2节），否则最多 79 字节".into());
                }
                if mac == [0; 6] {
                    return Err("未知接口 MAC，无法构造登录包；请设置 mac".into());
                }
                let a =
                    auth_version.ok_or("DHCP 模式必须设置 auth_version（学校 profile 的 AUTH_VERSION，第03.2节）")?;
                let k = keep_alive_version
                    .ok_or("DHCP 模式必须设置 keep_alive_version（学校 profile 的 KEEP_ALIVE_VERSION，第03.4节）")?;
                (a, k, options.pppoe_flag.unwrap_or(0))
            }
            Mode::Pppoe => {
                let flag = options.pppoe_flag.ok_or("PPPoE 模式必须设置 pppoe_flag（login96 offset 19，第03.5节）")?;
                (auth_version.unwrap_or([0; 2]), keep_alive_version.unwrap_or([0; 2]), flag)
            }
        };
        let interval = options.keepalive_interval_secs.unwrap_or(match mode {
            Mode::Dhcp => 20,
            Mode::Pppoe => 10,
        });
        let p = Profile {
            mode,
            server: SocketAddrV4::new(options.server, options.server_port),
            mac,
            host_name: options.host_name.into_bytes(),
            host_os,
            primary_dns: options.primary_dns.map(|d| d.octets()),
            dhcp_server: options.dhcp_server.octets(),
            os: OsVersion {
                info_size: options.os_info_size,
                major: options.os_major,
                minor: options.os_minor,
                build: options.os_build,
                platform_id: options.os_platform_id,
            },
            auth_version,
            keep_alive_version,
            control_check_status: options.control_check_status,
            adapter_num: options.adapter_num,
            ip_dog: options.ip_dog,
            ror: options.ror_version,
            keepalive1_mod: options.keepalive1_mod,
            pppoe_flag,
            timeout: Duration::from_secs(options.timeout_secs),
            interval: Duration::from_secs(interval),
            max_retries: options.max_retries,
            keepalive_max_fail: options.keepalive_max_fail,
            eternal: options.eternal,
            backoff: Duration::from_secs(options.backoff_secs),
        };
        if mode == Mode::Dhcp && p.primary_dns.is_none() && env.net.dns == [0; 4] {
            warn!("未配置 primary_dns，接口也没有 DNS，登录包 DNS 字段将为 0.0.0.0");
        }
        if mode == Mode::Dhcp && p.dhcp_server == [0; 4] {
            warn!("未配置 dhcp_server，登录包 offset 146 将为 0.0.0.0");
        }
        let digest = md5::compute([&mac[..], credentials.username.as_bytes()].concat()).0;
        let rng = u64::from_le_bytes(digest[..8].try_into().unwrap_or([1; 8])) | 1;
        Ok(DrcomDriver {
            p,
            creds: credentials,
            net: env.net,
            phase: Phase::Idle,
            state: AuthState::Idle,
            deadline: None,
            last: Vec::new(),
            attempts: 0,
            ka_fail: 0,
            answered: false,
            rng,
            seed: [0; 4],
            md5a: [0; 16],
            auth_info: [0; 16],
            ka1_counter: 0,
            ka2_counter: 0,
            tail: [0; 4],
            file_done: false,
            ppp: None,
            ppp_counter: 0,
            ppp_logged_in_once: false,
        })
    }

    /// Two "random" bytes. Drivers may not read clocks or OS randomness, so
    /// this is an xorshift seeded from MAC and username; the fields are
    /// nonces, not secrets (doc 03 §3.2/3.3 call them random).
    fn random2(&mut self) -> [u8; 2] {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let v = (self.rng >> 24) as u16;
        v.to_le_bytes()
    }

    fn send(&mut self, payload: Vec<u8>, phase: Phase, now: Instant) -> Vec<Action> {
        self.last = payload.clone();
        self.phase = phase;
        self.deadline = Some(now + self.p.timeout);
        vec![Action::SendUdp { local_port: DRCOM_PORT, to: self.p.server, payload }]
    }

    fn resend(&mut self, now: Instant) -> Vec<Action> {
        self.deadline = Some(now + self.p.timeout);
        vec![Action::SendUdp { local_port: DRCOM_PORT, to: self.p.server, payload: self.last.clone() }]
    }

    fn wait(&mut self, phase: Phase, delay: Duration, now: Instant) -> Vec<Action> {
        self.phase = phase;
        self.deadline = Some(now + delay);
        Vec::new()
    }

    fn stop(&mut self, stop: Stop) -> Vec<Action> {
        self.phase = Phase::Stopped;
        self.state = AuthState::Stopped;
        self.deadline = None;
        vec![Action::Stop(stop)]
    }

    fn wait_for_ip(&mut self) -> Vec<Action> {
        self.phase = Phase::WaitingIp;
        self.state = AuthState::WaitingIp;
        self.deadline = None;
        match self.p.mode {
            Mode::Dhcp => vec![Action::RequestDhcp],
            // pppd owns the address in PPPoE mode.
            Mode::Pppoe => Vec::new(),
        }
    }

    fn reset_session(&mut self) {
        self.seed = [0; 4];
        self.md5a = [0; 16];
        self.auth_info = [0; 16];
        self.ka1_counter = 0;
        self.ka2_counter = 0;
        self.tail = [0; 4];
        self.file_done = false;
        self.ppp = None;
        self.ka_fail = 0;
    }

    /// Starts (or restarts) a login round.
    fn start_auth(&mut self, now: Instant) -> Vec<Action> {
        if !self.net.has_ipv4() {
            info!("等待接口获得 IPv4 地址");
            return self.wait_for_ip();
        }
        self.reset_session();
        self.state = if self.answered { AuthState::Authenticating } else { AuthState::Discovering };
        match self.p.mode {
            Mode::Dhcp => {
                debug!("发送 Dr.com challenge");
                let random = self.random2();
                let pkt = challenge_request(CHALLENGE_DOGCOM_LOGIN, random, self.p.auth_version[0]);
                self.send(pkt.to_vec(), Phase::Challenge, now)
            }
            Mode::Pppoe => {
                debug!("发送 Dr.com PPPoE challenge");
                self.ppp_counter = self.ppp_counter.wrapping_add(1) % 0xff;
                let pkt = pppoe_challenge(self.ppp_counter);
                self.send(pkt.to_vec(), Phase::PppChallenge, now)
            }
        }
    }

    fn relogin(&mut self, now: Instant) -> Vec<Action> {
        self.attempts = 0;
        self.start_auth(now)
    }

    /// Login rounds exhausted.
    fn exhausted(&mut self, now: Instant) -> Vec<Action> {
        let rounds = self.attempts;
        if self.p.eternal {
            warn!("连续 {rounds} 次认证未成功，{} 秒后重试", self.p.backoff.as_secs());
            self.attempts = 0;
            self.state = AuthState::Backoff;
            return self.wait(Phase::Backoff, self.p.backoff, now);
        }
        if self.answered {
            error!("连续 {rounds} 次认证未成功，放弃");
            self.stop(Stop::GaveUp { rounds })
        } else {
            error!("Dr.com 服务器 {} 无响应", self.p.server);
            self.stop(Stop::ServerNotFound)
        }
    }

    fn auth_timeout(&mut self, now: Instant) -> Vec<Action> {
        self.attempts += 1;
        if self.attempts >= self.p.max_retries {
            return self.exhausted(now);
        }
        warn!("等待服务器响应超时，重试（{}/{}）", self.attempts, self.p.max_retries);
        match self.phase {
            // The login depends on the seed: ask for a fresh one.
            Phase::Login | Phase::PppLogin => self.start_auth(now),
            _ => self.resend(now),
        }
    }

    fn keepalive_timeout(&mut self, now: Instant) -> Vec<Action> {
        self.ka_fail += 1;
        if self.ka_fail >= self.p.keepalive_max_fail {
            warn!("保活连续 {} 次无响应，重新登录", self.ka_fail);
            return self.relogin(now);
        }
        debug!("保活超时，重发（{}/{}）", self.ka_fail, self.p.keepalive_max_fail);
        self.resend(now)
    }

    /// Failure code from a login answer (doc 30.7 texts). Only codes whose
    /// text names an account or configuration problem stop the session;
    /// "already logged in elsewhere" (1), busy (2), too many users (20) and
    /// codes without a known meaning are retried with back-off
    /// (cleanroom/docs/gaps.md: unconfirmed failures are transient).
    fn login_failed(&mut self, code: u8, now: Instant) -> Vec<Action> {
        let text = error_text(code).trim_end();
        let stage = match code {
            3 | 4 | 5 | 7 | 11 | 22 => Some(RejectStage::Password),
            // 21: client check failed (material); 23: static IP refused.
            21 | 23 => Some(RejectStage::Other),
            _ => None,
        };
        let Some(stage) = stage else {
            self.attempts += 1;
            if self.attempts >= self.p.max_retries {
                return self.exhausted(now);
            }
            let wait = if code == 2 { BUSY_WAIT } else { self.p.backoff };
            warn!("{text}（代码 {code}），{}s 后重试", wait.as_secs());
            self.state = AuthState::Backoff;
            return self.wait(Phase::Backoff, wait, now);
        };
        // doc 30.7: code 21 is followed by a server text whose offset is not
        // documented; it is not decoded.
        error!("认证失败：{text}（代码 {code}）");
        self.stop(Stop::Rejected { stage, message: Some(format!("{text}（代码 {code}）")) })
    }

    fn login_succeeded(&mut self) {
        info!("认证成功");
        self.answered = true;
        self.attempts = 0;
        self.ka_fail = 0;
        self.state = AuthState::Online;
    }

    // ---- DHCP mode ------------------------------------------------------

    fn send_login(&mut self, seed: [u8; 4], now: Instant) -> Vec<Action> {
        let dns = self.p.primary_dns.unwrap_or(self.net.dns);
        let params = LoginParams {
            username: self.creds.username.as_bytes(),
            password: self.creds.password.as_bytes(),
            seed,
            mac: self.p.mac,
            host_ip: self.net.ip,
            control_check_status: self.p.control_check_status,
            adapter_num: self.p.adapter_num,
            ip_dog: self.p.ip_dog,
            host_name: &self.p.host_name,
            primary_dns: dns,
            dhcp_server: self.p.dhcp_server,
            os: self.p.os,
            host_os: &self.p.host_os,
            auth_version: self.p.auth_version,
            ror: self.p.ror,
        };
        match login(&params, LoginLayout::Dogcom) {
            Ok(l) => {
                self.md5a = l.md5a;
                debug!("发送登录包（{} 字节）", l.body.len());
                self.send(l.body, Phase::Login, now)
            }
            // Field limits were validated in new(); keep a safe exit anyway.
            Err(e) => self.stop(Stop::Fatal(format!("无法构造登录包：{e}"))),
        }
    }

    fn start_keepalive1(&mut self, now: Instant) -> Vec<Action> {
        if self.p.keepalive1_mod {
            self.ka1_counter = self.ka1_counter.wrapping_add(1);
            let pkt = keepalive1_mod_request(self.ka1_counter);
            return self.send(pkt.to_vec(), Phase::Ka1ModSeed, now);
        }
        let random = self.random2();
        match keepalive1(&self.md5a, &self.auth_info, random, KEEPALIVE1_DOGCOM_LEN) {
            Ok(pkt) => self.send(pkt, Phase::Ka1, now),
            Err(e) => self.stop(Stop::Fatal(e.to_string())),
        }
    }

    fn keepalive2(&mut self, ka_type: u8, file_handshake: bool) -> Vec<u8> {
        let (version, host_ip, pppoe_crc_type) = match self.p.mode {
            Mode::Dhcp => (self.p.keep_alive_version, Some(self.net.ip), None),
            Mode::Pppoe => {
                let ch = self.ppp.unwrap_or(PppoeChallenge {
                    seed: [0; 4],
                    sip: [0; 4],
                    keepalive_version: [0; 2],
                    derive_enabled: false,
                });
                (ch.keepalive_version, None, Some(ch.encrypt_type()))
            }
        };
        let pkt = Keepalive2 {
            counter: self.ka2_counter,
            ka_type,
            file_handshake,
            version,
            tail: self.tail,
            host_ip,
            pppoe_crc_type,
        }
        .build();
        self.ka2_counter = self.ka2_counter.wrapping_add(1);
        pkt.to_vec()
    }

    fn start_keepalive2(&mut self, now: Instant) -> Vec<Action> {
        if self.file_done {
            let pkt = self.keepalive2(1, false);
            self.send(pkt, Phase::Ka2Type1, now)
        } else {
            let pkt = self.keepalive2(1, true);
            self.send(pkt, Phase::Ka2File, now)
        }
    }

    /// `05` while online: the server ended the session (doc 30.2: GS goes
    /// back to state 1 and logs in again).
    fn kicked(&mut self, body: &[u8], now: Instant) -> Vec<Action> {
        let code = body.get(4).copied().unwrap_or(0);
        warn!("服务器通知下线：{}（代码 {code}），重新登录", error_text(code).trim_end());
        self.relogin(now)
    }

    fn on_keepalive_datagram(&mut self, body: &[u8], now: Instant) -> Vec<Action> {
        if body.first() == Some(&0x05) && body.len() >= 5 {
            return self.kicked(body, now);
        }
        if body.first() == Some(&0x4d) {
            // doc 03 §3.3: notice, not a failure; keep waiting.
            info!("收到服务器通知（0x4d），继续等待");
            return Vec::new();
        }
        match self.phase {
            Phase::Ka1ModSeed => match parse_keepalive1_mod_seed(body) {
                Ok(seed) => {
                    let random = self.random2();
                    let pkt = keepalive1_mod(seed, &self.auth_info, random);
                    self.send(pkt.to_vec(), Phase::Ka1, now)
                }
                Err(e) => self.ignore(e),
            },
            Phase::Ka1 => match parse_keepalive_reply(body) {
                Ok(KeepaliveReply::Ack) => {
                    self.ka_fail = 0;
                    self.wait(Phase::PreKa2, STEP_DELAY, now)
                }
                Ok(KeepaliveReply::Notice) => Vec::new(),
                Err(e) => self.ignore(e),
            },
            Phase::Ka2File => match parse_keepalive_reply(body) {
                Ok(KeepaliveReply::Ack) => {
                    // doc 03 §3.4: the answer's length field may be 0x10 or 0x28.
                    self.file_done = true;
                    self.ka_fail = 0;
                    let pkt = self.keepalive2(1, false);
                    self.send(pkt, Phase::Ka2Type1, now)
                }
                Ok(KeepaliveReply::Notice) => Vec::new(),
                Err(e) => self.ignore(e),
            },
            Phase::Ka2Type1 => match parse_keepalive2_tail(body) {
                Ok(tail) => {
                    self.tail = tail;
                    self.ka_fail = 0;
                    let pkt = self.keepalive2(3, false);
                    self.send(pkt, Phase::Ka2Type3, now)
                }
                Err(e) => self.ignore(e),
            },
            Phase::Ka2Type3 => match parse_keepalive_reply(body) {
                Ok(KeepaliveReply::Ack) => {
                    debug!("保活成功");
                    self.ka_fail = 0;
                    self.wait(Phase::Sleep, self.p.interval, now)
                }
                Ok(KeepaliveReply::Notice) => Vec::new(),
                Err(e) => self.ignore(e),
            },
            _ => Vec::new(),
        }
    }

    // ---- PPPoE mode -----------------------------------------------------

    fn on_ppp_login_reply(&mut self, body: &[u8], now: Instant) -> Vec<Action> {
        // doc 03 §3.5 does not describe the answer to login96. The GS receive
        // dispatch (doc 30.2) treats 04 and 07/sub 4 or 6 as success and 05 as
        // failure; the same classification is used here.
        let success = match body {
            [0x04, ..] => true,
            [0x07, _, _, _, sub, ..] => *sub == 4 || *sub == 6,
            _ => false,
        };
        if success {
            self.login_succeeded();
            self.ppp_logged_in_once = true;
            return self.start_keepalive2(now);
        }
        if let [0x05, _, _, _, code, ..] = body {
            return self.login_failed(*code, now);
        }
        debug!("忽略 PPPoE 登录阶段的未知报文 {}", gswifi_core::text::hex_head(body, 8));
        Vec::new()
    }

    fn ignore(&self, e: crate::Error) -> Vec<Action> {
        debug!("忽略无效报文：{e}");
        Vec::new()
    }
}

impl Driver for DrcomDriver {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }

    fn requirements(&self) -> Requirements {
        Requirements { ethertype: None, udp_ports: vec![DRCOM_PORT], needs_ipv4: true, udp_ttl: None }
    }

    fn start(&mut self, now: Instant) -> Vec<Action> {
        info!(
            "Dr.com 认证开始（{}，服务器 {}）",
            if self.p.mode == Mode::Dhcp { "DHCP 模式" } else { "PPPoE 模式" },
            self.p.server
        );
        self.start_auth(now)
    }

    fn on_datagram(&mut self, d: Datagram<'_>, now: Instant) -> Vec<Action> {
        if d.from != self.p.server || d.local_port != DRCOM_PORT {
            debug!("忽略来自 {} 的报文（本地端口 {}）", d.from, d.local_port);
            return Vec::new();
        }
        let body = d.payload;
        match self.phase {
            Phase::Challenge => match parse_challenge_response(body) {
                Ok(seed) => {
                    self.answered = true;
                    self.state = AuthState::Authenticating;
                    self.seed = seed;
                    self.wait(Phase::PreLogin, STEP_DELAY, now)
                }
                Err(e) => self.ignore(e),
            },
            Phase::Login => match parse_login_reply(body) {
                Ok(LoginReply::Success { auth_info }) => {
                    self.auth_info = auth_info;
                    self.login_succeeded();
                    self.wait(Phase::PreKa1, STEP_DELAY, now)
                }
                Ok(LoginReply::Failure { code }) => {
                    self.answered = true;
                    self.login_failed(code, now)
                }
                Err(e) => self.ignore(e),
            },
            Phase::PppChallenge => match parse_pppoe_challenge(body) {
                Ok(ch) => {
                    self.answered = true;
                    self.state = AuthState::Authenticating;
                    self.ppp = Some(ch);
                    self.ppp_counter = self.ppp_counter.wrapping_add(1) % 0xff;
                    let pkt = pppoe_login(self.ppp_counter, &ch, !self.ppp_logged_in_once, self.p.pppoe_flag);
                    self.send(pkt.to_vec(), Phase::PppLogin, now)
                }
                Err(e) => self.ignore(e),
            },
            Phase::PppLogin => self.on_ppp_login_reply(body, now),
            p if p.awaiting_keepalive() => self.on_keepalive_datagram(body, now),
            _ => Vec::new(),
        }
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        match self.deadline {
            Some(d) if now >= d => {}
            _ => return Vec::new(),
        }
        self.deadline = None;
        match self.phase {
            Phase::PreLogin => self.send_login(self.seed, now),
            Phase::PreKa1 => self.start_keepalive1(now),
            Phase::PreKa2 => self.start_keepalive2(now),
            Phase::Sleep => match self.p.mode {
                Mode::Dhcp => self.start_keepalive1(now),
                Mode::Pppoe => self.start_keepalive2(now),
            },
            Phase::Backoff => self.start_auth(now),
            p if p.awaiting_auth() => self.auth_timeout(now),
            p if p.awaiting_keepalive() => self.keepalive_timeout(now),
            _ => Vec::new(),
        }
    }

    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action> {
        let old = self.net;
        self.net = net;
        match self.phase {
            Phase::Stopped | Phase::Idle => Vec::new(),
            _ if !net.has_ipv4() => {
                if self.phase == Phase::WaitingIp {
                    return Vec::new();
                }
                warn!("接口失去 IPv4 地址，暂停认证");
                self.wait_for_ip()
            }
            Phase::WaitingIp => {
                info!("接口获得地址 {}，开始认证", net.ipv4());
                self.relogin(now)
            }
            _ if old.ip != net.ip => {
                // doc 09.3: never keep signing with an old address.
                info!("IPv4 地址变为 {}，重新认证", net.ipv4());
                self.relogin(now)
            }
            _ => Vec::new(),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        // doc 03: the Dogcom logout packet is not specified (the GS replay of
        // doc 30.3 only shows a logout challenge `01 01 …`, a different
        // client), so nothing is sent; the server session times out.
        info!("Dr.com 会话结束（注销报文未在文档中规定，不发送）");
        self.stop(Stop::Finished)
    }

    fn state(&self) -> AuthState {
        self.state
    }
}

#[cfg(test)]
mod tests;
