//! Sans-IO session driver for the Hubei old-Mac portal
//! (`hubei_mac_web_old`, cleanroom/08 §1, docs/05 §5.2 and §5.6).
//!
//! One round:
//!
//! 1. Probe: `GET http://www.baidu.com/` (cleanroom/07 §1). 2xx means nothing
//!    intercepted the request: the line is already usable and the driver
//!    goes online without logging in. A 3xx is followed (no credentials
//!    involved) until a `Location` carries the portal parameters.
//! 2. Entry: `GET http://<host>/?userip=..&wlanacname=..&nasip=..&usermac=..&aidcauthtype=0`
//!    with `ClientVersion: Mdsc`; the answer must be a WISPr `Redirect`
//!    with a `LoginURL`.
//! 3. Login: `POST LoginURL` with the old-Mac form; the password is derived
//!    from the account, the password and the server-corrected local date
//!    (FixHBKey + RC4/MD5 chain, cleanroom/08 §1.1–1.2).
//! 4. Online: the `AuthenticationReply` `ResponseCode` 50 means success;
//!    `LogoffURL` and the cookies are kept for logoff (cleanroom/08 §1.3).
//!
//! Gaps and the behaviour chosen for them:
//! * **Vendor heartbeat — not sent.** Its `type` value, URL, interval and
//!   UUID handling are not closed (cleanroom/08 §1.3, gaps.md); sending a
//!   guessed one is forbidden (gaps.md convention 3). Instead, while online,
//!   the probe is repeated every [`PortalOptions::check_secs`]; a new portal
//!   redirect means the session was lost and the driver logs in again. This
//!   liveness check is this crate's own (【补充】), not a firmware timer.
//! * **Response codes** follow the public WISPr BCP (see [`crate::wispr`]).
//!   Every failure, including code 100, is retried with capped exponential
//!   backoff unless [`PortalOptions::stop_on_reject`] is set: no Aidc
//!   credential-error code is confirmed (gaps.md convention 1).
//! * **Server time**: MMDD is computed from the injectable wall clock plus
//!   the offset of the last portal `Date` header (cleanroom/07 §2,
//!   docs/05 §5.3), never by changing the system time; which response the
//!   firmware takes its time from, and its tolerance, are open.
//! * **Logoff** is WISPr's `GET LogoffURL` (【补充】); the evidence only says
//!   the URL is saved.
//! * **Redirect safety**: credentials only go to plain-HTTP hosts on the
//!   allow list (entry host or `portal_host`, plus `allowed_hosts`),
//!   cleanroom/07 §1 "跳转目标按 profile 白名单".
//! * An address change discards the session, the failure count and any
//!   terminal state, and starts a new round at once (gaps.md convention 2).

#[cfg(test)]
mod tests;

use std::time::{Duration, Instant, SystemTime};

use gswifi_core::{
    Action, AuthState, Credentials, Driver, DriverInfo, Env, HttpRequest, HttpResponse, NetInfo, RejectStage,
    Requirements, Stop,
};
use log::{debug, error, info, warn};
use serde::Deserialize;

use crate::cookies::CookieJar;
use crate::discovery::{
    classify_probe, entry_authority, is_portal_redirect, HubeiDiscovery, ProbeOutcome, DEFAULT_PROBE_URL,
};
use crate::hubei::{derive_password, fix_hb_key, old_mac, old_mac_login_form};
use crate::url::Url;
use crate::walltime::{local_mmdd, parse_http_date, unix_secs};
use crate::wispr::{self, classify_login, LoginOutcome, Message};

/// Longest accepted interval setting, so deadline arithmetic cannot overflow.
const MAX_INTERVAL_SECS: u64 = 86_400;
/// Largest accepted manual server offset (400 days).
const MAX_SERVER_OFFSET_SECS: i64 = 400 * 86_400;

const NAME: &str = "湖北旧Mac";

/// Options shared by every portal driver of this crate. Unknown keys are
/// ignored by serde (the CLI warns about them).
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct PortalOptions {
    /// Connectivity probe whose interception yields the portal redirect;
    /// `http://www.baidu.com/` in the firmware (cleanroom/07 §1). Must be
    /// plain HTTP.
    pub probe_url: String,
    /// `host[:port]` of the portal. When set, the entry request goes there
    /// instead of the redirect's host, and it is the host credentials may be
    /// sent to (besides `allowed_hosts`).
    pub portal_host: String,
    /// Further hosts allowed to receive `LoginURL`/`LogoffURL` requests.
    /// By default only the portal host (redirect host or `portal_host`).
    pub allowed_hosts: Vec<String>,
    /// Fixed offset of the router's local time from UTC, in minutes; the
    /// firmware uses `localtime`, +480 (China) by default.
    pub utc_offset_minutes: i32,
    /// Correct the wall clock with the portal's `Date` header (the firmware
    /// has `curl_getdate`/`settimeofday`, cleanroom/07 §2). On by default:
    /// before login the router usually cannot reach NTP.
    pub use_server_date: bool,
    /// Seconds added to the wall clock when no server `Date` is available
    /// (or `use_server_date` is off).
    pub server_time_offset_secs: i64,
    /// Request timeout the driver enforces itself.
    pub timeout_secs: u64,
    /// Liveness probe interval while online; 0 disables it. Not a firmware
    /// value (the vendor heartbeat interval is unknown).
    pub check_secs: u64,
    /// First delay after a failed round; doubles up to `max_backoff_secs`.
    /// 5 s is `hubei-service.sh`'s round delay (docs/01 §1.3).
    pub retry_secs: u64,
    pub max_backoff_secs: u64,
    /// Failed rounds before giving up; 0 retries forever.
    pub max_rounds: u32,
    /// Redirects followed by the probe and the entry request.
    pub max_redirects: u32,
    /// Stop on `ResponseCode` 100 instead of retrying. Off by default: its
    /// meaning on Aidc servers is unconfirmed (gaps.md convention 1).
    pub stop_on_reject: bool,
    /// `User-Agent` for every request; empty sends none. The old-Mac
    /// client's User-Agent is not in the evidence.
    pub user_agent: String,
}

impl Default for PortalOptions {
    fn default() -> Self {
        PortalOptions {
            probe_url: DEFAULT_PROBE_URL.to_string(),
            portal_host: String::new(),
            allowed_hosts: Vec::new(),
            utc_offset_minutes: 480,
            use_server_date: true,
            server_time_offset_secs: 0,
            timeout_secs: 15,
            check_secs: 60,
            retry_secs: 5,
            max_backoff_secs: 300,
            max_rounds: 0,
            max_redirects: 5,
            stop_on_reject: false,
            user_agent: String::new(),
        }
    }
}

/// Parses `host[:port]` (no scheme, path or query).
pub(crate) fn parse_host_spec(spec: &str, what: &str) -> Result<Url, String> {
    let spec = spec.trim();
    let bad = || format!("{}: {} = {:?} 应为 主机[:端口]", NAME, what, spec);
    if spec.is_empty() || spec.contains(['/', '?', '#', '@']) {
        return Err(bad());
    }
    Url::parse(&format!("http://{}/", spec)).map_err(|_| bad())
}

/// Wall-clock source for the date derivation; tests inject fixed times.
pub type WallClock = Box<dyn Fn() -> SystemTime + Send>;

#[derive(Clone, Debug)]
enum Step {
    /// Connectivity probe; `check` while online (liveness), else discovery.
    Probe { url: Url, hops: u32, check: bool },
    /// WISPr XML entry.
    Entry { url: Url, hops: u32 },
    /// Login POST.
    Login { url: Url },
}

#[derive(Clone, Debug)]
enum Phase {
    Idle,
    WaitingIp,
    Request { id: u32, deadline: Instant, step: Step },
    Online { next_check: Option<Instant> },
    Backoff { until: Instant },
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopKind {
    Finished,
    Rejected,
    GaveUp,
    Fatal,
}

/// State of one round; dropped whenever a round ends or the address changes.
#[derive(Debug, Default)]
struct Session {
    /// Hosts that may receive credentials this round.
    credential_hosts: Vec<String>,
    cookies: CookieJar,
    /// Server time minus wall clock, from the latest `Date` header.
    server_offset: Option<i64>,
    logoff_url: Option<Url>,
    logged_in: bool,
}

/// Hubei old-Mac portal session on one interface.
pub struct HubeiOldMacDriver {
    opts: PortalOptions,
    probe: Url,
    portal_authority: Option<String>,
    allowed_hosts: Vec<String>,
    interface: String,
    mac: [u8; 6],
    net: NetInfo,
    credentials: Credentials,
    wall_clock: WallClock,
    phase: Phase,
    session: Session,
    next_id: u32,
    started: bool,
    rounds: u32,
    backoff: Duration,
    portal_seen: bool,
    heartbeat_warned: bool,
    stopped: Option<StopKind>,
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

impl HubeiOldMacDriver {
    /// Validates credentials and options. The wall clock defaults to
    /// [`SystemTime::now`]; see [`HubeiOldMacDriver::with_wall_clock`].
    pub fn new(env: Env, credentials: Credentials, options: PortalOptions) -> Result<Self, String> {
        let user = &credentials.username;
        if user.trim().is_empty() {
            return Err(format!("{}: 用户名不能为空", NAME));
        }
        if user.chars().any(char::is_control) {
            return Err(format!("{}: 用户名不能包含控制字符", NAME));
        }
        if credentials.password.is_empty() {
            return Err(format!("{}: 密码不能为空", NAME));
        }
        // The firmware takes the password from argv, a C string.
        if credentials.password.as_bytes().contains(&0) {
            return Err(format!("{}: 密码不能包含NUL字符", NAME));
        }
        let probe = Url::parse(&options.probe_url).map_err(|e| format!("{}: probe_url 无效: {}", NAME, e))?;
        if !probe.is_http() {
            return Err(format!("{}: probe_url 必须是 http:// 地址（运行时不支持 HTTPS）", NAME));
        }
        let portal = if options.portal_host.trim().is_empty() {
            None
        } else {
            Some(parse_host_spec(&options.portal_host, "portal_host")?)
        };
        let mut allowed_hosts = Vec::new();
        for spec in &options.allowed_hosts {
            allowed_hosts.push(parse_host_spec(spec, "allowed_hosts")?.host().to_string());
        }
        if let Some(p) = &portal {
            allowed_hosts.push(p.host().to_string());
        }
        if !(-720..=840).contains(&options.utc_offset_minutes) {
            return Err(format!(
                "{}: utc_offset_minutes = {} 超出范围（-720..=840）",
                NAME, options.utc_offset_minutes
            ));
        }
        if options.server_time_offset_secs.abs() > MAX_SERVER_OFFSET_SECS {
            return Err(format!("{}: server_time_offset_secs 超出 ±{} 秒", NAME, MAX_SERVER_OFFSET_SECS));
        }
        let ranges = [
            ("timeout_secs", options.timeout_secs, 1, 300),
            ("retry_secs", options.retry_secs, 1, MAX_INTERVAL_SECS),
            ("max_backoff_secs", options.max_backoff_secs, options.retry_secs, MAX_INTERVAL_SECS),
            ("check_secs", options.check_secs, 0, MAX_INTERVAL_SECS),
        ];
        for (name, value, min, max) in ranges {
            if value < min || value > max {
                return Err(format!("{}: {} = {} 超出范围（{}..={}）", NAME, name, value, min, max));
            }
        }
        if options.max_redirects > 10 {
            return Err(format!("{}: max_redirects = {} 超出范围（0..=10）", NAME, options.max_redirects));
        }
        if options.user_agent.chars().any(char::is_control) {
            return Err(format!("{}: user_agent 不能包含控制字符", NAME));
        }
        Ok(HubeiOldMacDriver {
            probe,
            portal_authority: portal.map(|p| p.authority()),
            allowed_hosts,
            interface: env.interface,
            mac: env.mac,
            net: env.net,
            credentials,
            wall_clock: Box::new(SystemTime::now),
            phase: Phase::Idle,
            session: Session::default(),
            next_id: 0,
            started: false,
            rounds: 0,
            backoff: secs(options.retry_secs),
            portal_seen: false,
            heartbeat_warned: false,
            stopped: None,
            opts: options,
        })
    }

    /// Replaces the wall clock used for the date derivation (never for
    /// timers).
    pub fn with_wall_clock(mut self, clock: impl Fn() -> SystemTime + Send + 'static) -> Self {
        self.wall_clock = Box::new(clock);
        self
    }

    /// Logged in by this driver in the current round (not merely online).
    pub fn is_authenticated(&self) -> bool {
        self.session.logged_in
    }

    /// The vendor heartbeat is never sent (see the module docs); status
    /// pages must show it as unimplemented, not as healthy.
    pub fn vendor_keepalive_implemented(&self) -> bool {
        false
    }

    fn alloc_id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn max_backoff(&self) -> Duration {
        secs(self.opts.max_backoff_secs.max(self.opts.retry_secs))
    }

    fn next_check(&self, now: Instant) -> Option<Instant> {
        (self.opts.check_secs > 0).then(|| now + secs(self.opts.check_secs))
    }

    /// Up to 10 % of `base`, derived from the MAC and the round so that
    /// routers restarted together do not retry in lockstep (rule 3).
    fn jitter(&self, base: Duration) -> Duration {
        let span = u64::try_from(base.as_millis() / 10).unwrap_or(u64::MAX);
        if span == 0 {
            return Duration::ZERO;
        }
        let fnv = self.mac.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193));
        let seed = u64::from(fnv) ^ u64::from(self.rounds).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        Duration::from_millis(seed % (span + 1))
    }

    /// Server time minus wall clock, if the response has a valid `Date`.
    fn date_offset(&self, response: &HttpResponse) -> Option<i64> {
        let date = parse_http_date(response.header("Date")?)?;
        Some(date - unix_secs((self.wall_clock)()))
    }

    fn base_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if !self.opts.user_agent.is_empty() {
            headers.push(("User-Agent".to_string(), self.opts.user_agent.clone()));
        }
        headers
    }

    /// Headers of requests to the portal: `ClientVersion: Mdsc` (cleanroom/08
    /// §1), the optional User-Agent and the host's cookies.
    fn portal_headers(&self, host: &str) -> Vec<(String, String)> {
        let mut headers = vec![("ClientVersion".to_string(), old_mac::CLIENT_VERSION.to_string())];
        headers.extend(self.base_headers());
        if let Some(cookie) = self.session.cookies.header(host) {
            headers.push(("Cookie".to_string(), cookie));
        }
        headers
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &mut self,
        now: Instant,
        out: &mut Vec<Action>,
        method: &str,
        url: &Url,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        step: Step,
    ) {
        let id = self.alloc_id();
        let request = HttpRequest { method: method.to_string(), url: url.to_string(), headers, body };
        out.push(Action::Http { id, request });
        self.phase = Phase::Request { id, deadline: now + secs(self.opts.timeout_secs), step };
    }

    fn stop(&mut self, out: &mut Vec<Action>, stop: Stop, kind: StopKind) {
        self.phase = Phase::Stopped;
        self.session = Session::default();
        self.stopped = Some(kind);
        out.push(Action::Stop(stop));
    }

    fn fatal(&mut self, out: &mut Vec<Action>, message: String) {
        error!("{}", message);
        self.stop(out, Stop::Fatal(message), StopKind::Fatal);
    }

    fn begin_round(&mut self, now: Instant, out: &mut Vec<Action>) {
        self.session = Session::default();
        if !self.net.has_ipv4() {
            info!("等待接口 {} 获取IPv4地址...", self.interface);
            self.phase = Phase::WaitingIp;
            return;
        }
        debug!("探测 {} 是否被Portal拦截", self.probe);
        self.send_probe(self.probe.clone(), 0, false, now, out);
    }

    fn round_failed(&mut self, now: Instant, out: &mut Vec<Action>, reason: String) {
        warn!("{}", reason);
        self.session = Session::default();
        self.rounds = self.rounds.saturating_add(1);
        if self.opts.max_rounds > 0 && self.rounds >= self.opts.max_rounds {
            error!("连续 {} 轮失败，放弃", self.rounds);
            let stop = if self.portal_seen { Stop::GaveUp { rounds: self.rounds } } else { Stop::ServerNotFound };
            return self.stop(out, stop, StopKind::GaveUp);
        }
        let wait = self.backoff + self.jitter(self.backoff);
        info!("{:.1} 秒后重试（已连续失败 {} 轮）", wait.as_secs_f32(), self.rounds);
        self.phase = Phase::Backoff { until: now + wait };
        self.backoff = (self.backoff * 2).min(self.max_backoff());
    }

    fn reset_failures(&mut self) {
        self.rounds = 0;
        self.backoff = secs(self.opts.retry_secs);
    }

    fn dispatch(&mut self, step: Step, result: Result<HttpResponse, String>, now: Instant, out: &mut Vec<Action>) {
        match step {
            Step::Probe { url, hops, check } => self.on_probe(url, hops, check, result, now, out),
            Step::Entry { url, hops } => self.on_entry(url, hops, result, now, out),
            Step::Login { url } => self.on_login(url, result, now, out),
        }
    }

    fn send_probe(&mut self, url: Url, hops: u32, check: bool, now: Instant, out: &mut Vec<Action>) {
        let headers = self.base_headers();
        self.request(now, out, "GET", &url.clone(), headers, Vec::new(), Step::Probe { url, hops, check });
    }

    fn on_probe(
        &mut self,
        url: Url,
        hops: u32,
        check: bool,
        result: Result<HttpResponse, String>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let response = match result {
            Ok(r) => r,
            Err(e) => return self.probe_failed(check, format!("访问 {} 失败: {}", url, e), now, out),
        };
        let date = self.date_offset(&response);
        match classify_probe(&url, &response) {
            ProbeOutcome::NotIntercepted => self.not_intercepted(check, now),
            ProbeOutcome::Redirect(target) if is_portal_redirect(&target) => {
                if check {
                    info!("检测到再次被重定向到Portal，会话已失效，重新登录");
                }
                self.on_portal_redirect(target, date, now, out);
            }
            ProbeOutcome::Redirect(target) if target.is_http() && hops < self.opts.max_redirects => {
                debug!("探测被跳转到 {}，继续跟随", target);
                self.send_probe(target, hops + 1, check, now, out);
            }
            ProbeOutcome::Redirect(target) => {
                debug!("探测跳转到 {}，不含Portal参数，视为未被拦截", target);
                self.not_intercepted(check, now);
            }
            ProbeOutcome::Failed(reason) => self.probe_failed(check, format!("探测 {}: {}", url, reason), now, out),
        }
    }

    fn not_intercepted(&mut self, check: bool, now: Instant) {
        if check {
            debug!("在线检测正常");
        } else {
            info!("{} 未被Portal拦截，网络已可用（可能已在线），无需登录", self.probe);
            self.reset_failures();
        }
        self.phase = Phase::Online { next_check: self.next_check(now) };
    }

    fn probe_failed(&mut self, check: bool, reason: String, now: Instant, out: &mut Vec<Action>) {
        if check {
            // A network error says nothing about the portal session.
            warn!("在线检测失败（保持当前状态）: {}", reason);
            self.phase = Phase::Online { next_check: self.next_check(now) };
        } else {
            self.round_failed(now, out, reason);
        }
    }

    fn on_portal_redirect(&mut self, target: Url, date: Option<i64>, now: Instant, out: &mut Vec<Action>) {
        self.portal_seen = true;
        self.session = Session::default();
        let discovery = match HubeiDiscovery::from_redirect(&target) {
            Ok(d) => d,
            Err(e) => return self.round_failed(now, out, format!("{}（跳转目标 {}）", e, target.authority())),
        };
        let authority = self.portal_authority.clone().unwrap_or_else(|| entry_authority(&target));
        let entry = match discovery.entry_url(&authority) {
            Ok(u) => u,
            Err(e) => return self.round_failed(now, out, format!("无法构造Portal入口地址: {}", e)),
        };
        let mut hosts = vec![entry.host().to_string()];
        hosts.extend(self.allowed_hosts.iter().cloned());
        self.session = Session { credential_hosts: hosts, server_offset: date, ..Session::default() };
        info!("发现湖北Portal {}（AC {}）", entry.authority(), discovery.wlanacname.value);
        if discovery.userip.value != self.net.ipv4().to_string() {
            debug!("Portal 给出的用户IP {} 与接口地址 {} 不同", discovery.userip.value, self.net.ipv4());
        }
        self.send_entry(entry, 0, now, out);
    }

    fn send_entry(&mut self, url: Url, hops: u32, now: Instant, out: &mut Vec<Action>) {
        let headers = self.portal_headers(url.host());
        self.request(now, out, "GET", &url.clone(), headers, Vec::new(), Step::Entry { url, hops });
    }

    fn on_entry(
        &mut self,
        url: Url,
        hops: u32,
        result: Result<HttpResponse, String>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let response = match result {
            Ok(r) => r,
            Err(e) => return self.round_failed(now, out, format!("访问Portal入口失败: {}", e)),
        };
        self.session.cookies.store(url.host(), &response);
        if let Some(offset) = self.date_offset(&response) {
            self.session.server_offset = Some(offset);
        }
        match response.status {
            200..=299 => {}
            300..=399 => {
                return match classify_probe(&url, &response) {
                    ProbeOutcome::Redirect(target) if target.is_http() && hops < self.opts.max_redirects => {
                        debug!("Portal入口跳转到 {}", target);
                        self.send_entry(target, hops + 1, now, out)
                    }
                    ProbeOutcome::Redirect(target) => self.round_failed(
                        now,
                        out,
                        format!("Portal入口跳转到 {}，无法继续（不是 http:// 或跳转次数过多）", target.authority()),
                    ),
                    ProbeOutcome::Failed(reason) => self.round_failed(now, out, format!("Portal入口: {}", reason)),
                    ProbeOutcome::NotIntercepted => self.round_failed(now, out, "Portal入口响应异常".to_string()),
                };
            }
            status => return self.round_failed(now, out, format!("Portal入口返回 HTTP {}", status)),
        }
        let redirect = match wispr::parse(&response.body) {
            Ok(Message::Redirect(r)) => r,
            Ok(_) => return self.round_failed(now, out, "Portal入口返回的不是 WISPr Redirect 消息".to_string()),
            Err(e) => return self.round_failed(now, out, format!("Portal入口: {}", e)),
        };
        if let Some(config) = &redirect.config_url {
            debug!("忽略 ConfigURL {}：客户端配置的解码未闭合（cleanroom/07 §5）", config);
        }
        let Some(login) = redirect.login_url else {
            return self.round_failed(now, out, "WISPr Redirect 缺少 LoginURL".to_string());
        };
        let login_url = match url.join(&login) {
            Ok(u) => u,
            Err(e) => return self.round_failed(now, out, format!("LoginURL 无效: {}", e)),
        };
        if let Err(message) = self.check_credential_target(&login_url, "LoginURL") {
            return self.fatal(out, message);
        }
        self.send_login(login_url, now, out);
    }

    /// Credentials only go to plain-HTTP hosts on this round's allow list.
    fn check_credential_target(&self, url: &Url, what: &str) -> Result<(), String> {
        if !url.is_http() {
            return Err(format!("{}: {} {} 不是 http:// 地址，运行时不支持 HTTPS", NAME, what, url.authority()));
        }
        if !self.session.credential_hosts.iter().any(|h| h == url.host()) {
            return Err(format!(
                "{}: {} 的主机 {} 不在允许列表（{}）中，拒绝发送凭据；如确为学校Portal，请把它加入 allowed_hosts",
                NAME,
                what,
                url.host(),
                self.session.credential_hosts.join(", ")
            ));
        }
        Ok(())
    }

    fn send_login(&mut self, url: Url, now: Instant, out: &mut Vec<Action>) {
        let wall = unix_secs((self.wall_clock)());
        let (offset, source) = match (self.opts.use_server_date, self.session.server_offset) {
            (true, Some(o)) => (o, "服务器 Date"),
            _ => (self.opts.server_time_offset_secs, "本机时钟"),
        };
        if source == "服务器 Date" && offset.abs() > 300 {
            info!("本机时间与服务器相差 {} 秒，按服务器时间计算日期", offset);
        }
        let mmdd = local_mmdd(wall.saturating_add(offset), self.opts.utc_offset_minutes);
        debug!("派生日期 MMDD={}（{}，UTC{:+}分钟）", mmdd, source, self.opts.utc_offset_minutes);
        let username = self.credentials.username.clone();
        let password = match fix_hb_key(&username, &mmdd) {
            Ok(key) => derive_password(self.credentials.password.as_bytes(), &key),
            Err(e) => return self.fatal(out, format!("{}: 无法派生登录密码: {}", NAME, e)),
        };
        if password.rc4_output_had_nul() {
            warn!(
                "本次密码派生的 RC4 中间值含 0x00 字节，固件对这种情形的长度处理未经向量验证（gaps: HB-01 NUL 边界）；\
                 若登录失败，日期变化后会自动恢复"
            );
        }
        let body = old_mac_login_form(&username, password.expose()).into_bytes();
        let mut headers = self.portal_headers(url.host());
        headers.push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
        info!("正在登录 {}（账号 {}）", url.authority(), username);
        self.request(now, out, "POST", &url.clone(), headers, body, Step::Login { url });
    }

    fn on_login(&mut self, url: Url, result: Result<HttpResponse, String>, now: Instant, out: &mut Vec<Action>) {
        let response = match result {
            Ok(r) => r,
            Err(e) => return self.round_failed(now, out, format!("登录请求失败: {}", e)),
        };
        self.session.cookies.store(url.host(), &response);
        if !(200..=299).contains(&response.status) {
            return self.round_failed(now, out, format!("登录请求返回 HTTP {}", response.status));
        }
        let reply = match wispr::parse(&response.body) {
            Ok(Message::AuthenticationReply(r)) => r,
            Ok(_) => return self.round_failed(now, out, "登录响应不是 WISPr AuthenticationReply".to_string()),
            Err(e) => return self.round_failed(now, out, format!("无法识别的登录响应: {}", e)),
        };
        let suffix = reply.reply_message.as_deref().map(|m| format!("：{}", m)).unwrap_or_default();
        let code = reply.response_code.map_or_else(|| "缺失".to_string(), |c| c.to_string());
        match classify_login(reply.response_code) {
            LoginOutcome::Success => self.logged_in(&url, reply.logoff_url.as_deref(), &suffix, now),
            LoginOutcome::Rejected if self.opts.stop_on_reject => {
                error!("服务器拒绝登录（ResponseCode 100）{}", suffix);
                let stop = Stop::Rejected { stage: RejectStage::Password, message: reply.reply_message };
                self.stop(out, stop, StopKind::Rejected);
            }
            LoginOutcome::Rejected => self.round_failed(
                now,
                out,
                format!(
                    "服务器拒绝登录（ResponseCode 100）{}。湖北服务器拒绝码的含义未经确认（也可能是“已在线”），按可重试处理",
                    suffix
                ),
            ),
            LoginOutcome::Pending => self.round_failed(
                now,
                out,
                format!("服务器返回认证处理中（ResponseCode 201）{}，规格未覆盖结果轮询，稍后重新登录", suffix),
            ),
            LoginOutcome::ServerError => {
                self.round_failed(now, out, format!("认证服务器错误（ResponseCode {}）{}", code, suffix))
            }
            LoginOutcome::Unknown => {
                self.round_failed(now, out, format!("未知的登录结果（ResponseCode {}）{}", code, suffix))
            }
        }
    }

    fn logged_in(&mut self, login_url: &Url, logoff: Option<&str>, suffix: &str, now: Instant) {
        self.session.logoff_url = match logoff.map(|l| login_url.join(l)) {
            None => {
                debug!("登录响应没有 LogoffURL");
                None
            }
            Some(Err(e)) => {
                warn!("LogoffURL 无效（退出时不注销）: {}", e);
                None
            }
            Some(Ok(u)) => match self.check_credential_target(&u, "LogoffURL") {
                Ok(()) => Some(u),
                Err(m) => {
                    warn!("{}；退出时不注销", m);
                    None
                }
            },
        };
        self.session.logged_in = true;
        self.reset_failures();
        info!("认证成功{}", suffix);
        if !self.heartbeat_warned {
            self.heartbeat_warned = true;
            let recovery = if self.opts.check_secs > 0 {
                format!("本程序每 {} 秒探测一次，发现掉线后自动重新登录", self.opts.check_secs)
            } else {
                "在线检测已关闭（check_secs = 0），掉线后不会自动发现".to_string()
            };
            warn!(
                "湖北 Aidc 厂商心跳未实现：心跳的 type 值、URL、间隔与 UUID 来源均未闭合（cleanroom/08 §1.3，gaps.md），\
                 服务器可能因收不到心跳而断开；{}",
                recovery
            );
        }
        self.phase = Phase::Online { next_check: self.next_check(now) };
    }
}

impl Driver for HubeiOldMacDriver {
    fn info(&self) -> &'static DriverInfo {
        &crate::INFO_HUBEI_OLD_MAC
    }

    fn requirements(&self) -> Requirements {
        Requirements { needs_ipv4: true, ..Requirements::default() }
    }

    fn start(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if self.started {
            return out;
        }
        self.started = true;
        info!("湖北 Aidc Portal（旧 Mac）认证开始，接口 {}", self.interface);
        self.begin_round(now, &mut out);
        out
    }

    fn on_http(&mut self, id: u32, response: Result<HttpResponse, String>, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Request { id: pending, step, .. } if pending == id => self.dispatch(step, response, now, &mut out),
            other => {
                self.phase = other;
                debug!("忽略过期的 HTTP 响应 #{}", id);
            }
        }
        out
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Request { deadline, step, .. } if now >= deadline => {
                self.dispatch(step, Err(format!("{} 秒内没有响应", self.opts.timeout_secs)), now, &mut out)
            }
            Phase::Backoff { until } if now >= until => self.begin_round(now, &mut out),
            Phase::Online { next_check: Some(at) } if now >= at => {
                debug!("在线检测");
                self.send_probe(self.probe.clone(), 0, true, now, &mut out);
            }
            other => self.phase = other,
        }
        out
    }

    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let old = self.net;
        self.net = net;
        if !self.started || matches!(self.stopped, Some(StopKind::Finished | StopKind::Fatal)) {
            return out;
        }
        if !net.has_ipv4() {
            if !matches!(self.phase, Phase::WaitingIp) {
                info!("接口 {} 失去IPv4地址，等待新地址", self.interface);
            }
            self.session = Session::default();
            self.phase = Phase::WaitingIp;
            return out;
        }
        let changed = old.ip != net.ip;
        let waiting = matches!(self.phase, Phase::WaitingIp);
        if !changed && !waiting {
            return out;
        }
        if changed && old.has_ipv4() {
            info!("接口地址由 {} 变为 {}，清除会话与失败计数，重新认证", old.ipv4(), net.ipv4());
        }
        // gaps.md convention 2: an address change clears terminal state.
        self.stopped = None;
        self.reset_failures();
        self.begin_round(now, &mut out);
        out
    }

    fn next_deadline(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Request { deadline, .. } => Some(*deadline),
            Phase::Backoff { until } => Some(*until),
            Phase::Online { next_check } => *next_check,
            Phase::Idle | Phase::WaitingIp | Phase::Stopped => None,
        }
    }

    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match (self.session.logged_in, self.session.logoff_url.clone()) {
            (true, Some(url)) => {
                info!("正在注销 {}", url.authority());
                let headers = self.portal_headers(url.host());
                let id = self.alloc_id();
                let request =
                    HttpRequest { method: "GET".to_string(), url: url.to_string(), headers, body: Vec::new() };
                out.push(Action::Http { id, request });
            }
            (true, None) => info!("没有可用的 LogoffURL，直接退出（服务器端会话保留到超时）"),
            (false, _) => {}
        }
        self.session = Session::default();
        self.phase = Phase::Stopped;
        self.stopped = Some(StopKind::Finished);
        out.push(Action::Stop(Stop::Finished));
        out
    }

    fn state(&self) -> AuthState {
        match &self.phase {
            Phase::Idle => AuthState::Idle,
            Phase::WaitingIp => AuthState::WaitingIp,
            Phase::Request { step: Step::Probe { check: true, .. }, .. } => AuthState::Online,
            Phase::Request { step: Step::Probe { .. } | Step::Entry { .. }, .. } => AuthState::Discovering,
            Phase::Request { step: Step::Login { .. }, .. } => AuthState::Authenticating,
            Phase::Online { .. } => AuthState::Online,
            Phase::Backoff { .. } => AuthState::Backoff,
            Phase::Stopped => AuthState::Stopped,
        }
    }
}
