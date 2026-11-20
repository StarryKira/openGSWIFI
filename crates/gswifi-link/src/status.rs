//! Per-network status file for front ends (the LuCI app, scripts).
//!
//! A front end should not have to scrape log text to learn whether a
//! session is online. Each network's thread installs a reporter with
//! [`begin`]; the event loop and the binary then record state changes with
//! [`state`] / [`stopped`], and the logger hands every line to [`log`].
//! Every change rewrites one small JSON file, `<dir>/<name>.json`,
//! atomically (write + rename), so a reader never sees half a file.
//!
//! Times are written twice: as wall-clock seconds (`x`) and as seconds
//! since boot (`x_up`). Routers without a battery-backed clock boot with a
//! clock that is days behind and only correct it once the login succeeded
//! and NTP is reachable, so a duration must be computed from the `_up`
//! value and `/proc/uptime`, never from the wall clock.
//!
//! The file holds no credentials.

use std::cell::RefCell;
use std::fmt::Arguments;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gswifi_core::{mac_str, AuthState, DriverInfo, Env, NetInfo, RejectStage, Stop};

use crate::json::Object;

/// Format version of the file, raised when a field changes meaning.
pub const VERSION: u32 = 1;

/// Longest text kept from one log line; server announcements can be long.
const MAX_TEXT: usize = 2000;

/// Prefixes the drivers use when they print what the server said.
const SERVER_MARKERS: [&str; 3] = ["系统公告：", "系统提示：", "服务器提示："];

/// A moment as wall-clock seconds and as seconds since boot (0 when the
/// platform has no `/proc/uptime`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Stamp {
    unix: u64,
    up: u64,
}

impl Stamp {
    fn now() -> Stamp {
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let up = fs::read_to_string("/proc/uptime").ok().and_then(|t| parse_uptime(&t)).unwrap_or(0);
        Stamp { unix, up }
    }
}

/// Whole seconds from `/proc/uptime` (`"12345.67 12000.00"`).
fn parse_uptime(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.split('.').next()?.parse().ok()
}

/// One captured log line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    level: &'static str,
    text: String,
    at: Stamp,
}

/// Everything the file says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Snapshot {
    name: String,
    pid: u32,
    driver: String,
    title: String,
    support: String,
    interface: String,
    mac: String,
    ipv4: String,
    gateway: String,
    dns: String,
    state: &'static str,
    state_since: Stamp,
    started: Stamp,
    /// Set while the state is `online`.
    online_since: Option<Stamp>,
    /// When the session last became online, kept after it dropped.
    last_online: Option<Stamp>,
    /// Sessions started (the first one included).
    attempts: u32,
    /// Times a session reached `online`.
    successes: u32,
    /// The session ended and the program waits for an address change
    /// before it tries again.
    waiting_for_change: bool,
    exit_code: Option<i32>,
    reject_stage: Option<&'static str>,
    reason: Option<String>,
    last_log: Option<Line>,
    /// Latest line at WARN or ERROR.
    last_issue: Option<Line>,
    /// Latest text the drivers printed as coming from the server.
    server_message: Option<Line>,
}

fn stamp(o: Object, key: &str, s: Stamp) -> Object {
    o.num(key, s.unix).num(&format!("{}_up", key), s.up)
}

fn opt_stamp(o: Object, key: &str, s: Option<Stamp>) -> Object {
    match s {
        Some(s) => stamp(o, key, s),
        None => o.raw(key, "null").raw(&format!("{}_up", key), "null"),
    }
}

fn line(o: Object, key: &str, l: &Option<Line>) -> Object {
    match l {
        Some(l) => {
            let inner = stamp(Object::new().str("level", l.level).str("text", &l.text), "at", l.at).finish();
            o.raw(key, &inner)
        }
        None => o.raw(key, "null"),
    }
}

impl Snapshot {
    fn to_json(&self, updated: Stamp) -> String {
        let mut o = Object::new()
            .num("version", VERSION)
            .str("name", &self.name)
            .num("pid", self.pid)
            .str("driver", &self.driver)
            .str("title", &self.title)
            .str("support", &self.support)
            .str("interface", &self.interface)
            .str("mac", &self.mac)
            .str("ipv4", &self.ipv4)
            .str("gateway", &self.gateway)
            .str("dns", &self.dns)
            .str("state", self.state);
        o = stamp(o, "state_since", self.state_since);
        o = stamp(o, "started", self.started);
        o = opt_stamp(o, "online_since", self.online_since);
        o = opt_stamp(o, "last_online", self.last_online);
        o = o
            .num("attempts", self.attempts)
            .num("successes", self.successes)
            .bool("waiting_for_change", self.waiting_for_change)
            .opt_num("exit_code", self.exit_code)
            .opt_str("reject_stage", self.reject_stage)
            .opt_str("reason", self.reason.as_deref());
        o = line(o, "last_log", &self.last_log);
        o = line(o, "last_issue", &self.last_issue);
        o = line(o, "server_message", &self.server_message);
        stamp(o, "updated", updated).finish()
    }

    fn set_state(&mut self, state: &'static str) {
        if self.state == state {
            return;
        }
        let now = Stamp::now();
        if state == "online" {
            self.successes += 1;
            self.online_since = Some(now);
            self.last_online = Some(now);
        } else {
            self.online_since = None;
        }
        self.state = state;
        self.state_since = now;
    }

    fn set_net(&mut self, net: &NetInfo) {
        let addr = |a: [u8; 4]| if a == [0; 4] { String::new() } else { Ipv4Addr::from(a).to_string() };
        self.ipv4 = addr(net.ip);
        self.gateway = addr(net.gateway);
        self.dns = addr(net.dns);
    }
}

struct Reporter {
    path: PathBuf,
    snapshot: Snapshot,
    /// What the file holds, without the `updated` stamp.
    written: Option<Snapshot>,
}

impl Reporter {
    fn flush(&mut self) {
        if self.written.as_ref() == Some(&self.snapshot) {
            return;
        }
        // Failing to write a status file must never disturb the session.
        if write_atomically(&self.path, &self.snapshot.to_json(Stamp::now())).is_ok() {
            self.written = Some(self.snapshot.clone());
        }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Reporter>> = const { RefCell::new(None) };
}

/// Runs `f` on this thread's reporter, if any, then rewrites the file when
/// something changed.
fn update(f: impl FnOnce(&mut Snapshot)) {
    CURRENT.with(|current| {
        // `try_borrow_mut`: a log line produced while the file is being
        // written must not panic the session.
        if let Ok(mut current) = current.try_borrow_mut() {
            if let Some(reporter) = current.as_mut() {
                f(&mut reporter.snapshot);
                reporter.flush();
            }
        }
    });
}

/// A name that is safe as a file name: `[A-Za-z0-9._-]`, never hidden,
/// never empty.
pub fn file_stem(name: &str) -> String {
    let mut stem: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    if stem.is_empty() {
        stem.push_str("network");
    }
    if stem.starts_with('.') {
        stem.replace_range(0..1, "_");
    }
    stem
}

fn write_atomically(path: &Path, content: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Server messages can name the account: root only.
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.write_all(b"\n")?;
    }
    fs::rename(&tmp, path)
}

/// Starts reporting for the network this thread runs: `<dir>/<name>.json`
/// (see [`file_stem`]). Until this is called every other function here
/// does nothing.
pub fn begin(dir: &Path, name: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("无法创建状态目录 {}: {}", dir.display(), e))?;
    let now = Stamp::now();
    let snapshot = Snapshot {
        name: name.to_string(),
        pid: std::process::id(),
        state: "starting",
        state_since: now,
        started: now,
        ..Snapshot::default()
    };
    let mut reporter = Reporter { path: dir.join(format!("{}.json", file_stem(name))), snapshot, written: None };
    write_atomically(&reporter.path, &reporter.snapshot.to_json(now))
        .map_err(|e| format!("无法写入状态文件 {}: {}", reporter.path.display(), e))?;
    reporter.written = Some(reporter.snapshot.clone());
    CURRENT.with(|current| *current.borrow_mut() = Some(reporter));
    Ok(())
}

/// A new session is about to start.
pub fn attempt() {
    update(|s| {
        s.attempts += 1;
        s.waiting_for_change = false;
        s.exit_code = None;
        s.reject_stage = None;
        s.reason = None;
        s.set_state("starting");
    });
}

/// Which driver runs on which interface.
pub fn describe(info: &DriverInfo, env: &Env) {
    update(|s| {
        s.driver = info.name.to_string();
        s.title = info.title.to_string();
        s.support = info.support.as_str().to_string();
        s.interface = env.interface.clone();
        s.mac = mac_str(&env.mac);
        s.set_net(&env.net);
    });
}

/// Name of a driver state in the file.
pub fn state_name(state: AuthState) -> &'static str {
    match state {
        AuthState::Idle => "idle",
        AuthState::WaitingIp => "waiting-ip",
        AuthState::Discovering => "discovering",
        AuthState::Authenticating => "authenticating",
        AuthState::Online => "online",
        AuthState::Backoff => "backoff",
        AuthState::Stopped => "stopped",
    }
}

/// The driver is in `state`, with these addresses.
pub fn state(state: AuthState, net: &NetInfo) {
    update(|s| {
        s.set_net(net);
        s.set_state(state_name(state));
    });
}

/// The session ended. `waiting_for_change` says the program stays and
/// retries once the interface gets another address.
pub fn stopped(stop: &Stop, waiting_for_change: bool) {
    update(|s| {
        s.exit_code = Some(stop.exit_code());
        s.waiting_for_change = waiting_for_change;
        s.reject_stage = None;
        s.reason = None;
        let state = match stop {
            Stop::Finished => "stopped",
            Stop::ServerNotFound => "server-not-found",
            Stop::Rejected { stage, message } => {
                s.reject_stage = Some(match stage {
                    RejectStage::Identity => "identity",
                    RejectStage::Password => "password",
                    RejectStage::Other => "other",
                });
                s.reason = message.clone();
                "rejected"
            }
            Stop::GaveUp { rounds } => {
                s.reason = Some(format!("{} 轮没有应答", rounds));
                "gave-up"
            }
            Stop::Fatal(message) => {
                s.reason = Some(message.clone());
                "fatal"
            }
        };
        s.set_state(state);
    });
}

fn clip(text: &str) -> String {
    let text = text.trim();
    match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// Hands a log record to this thread's reporter: the latest line, the
/// latest warning or error, and the latest server message are kept.
/// Lines below INFO are ignored.
pub fn log(level: log::Level, args: &Arguments) {
    if level > log::Level::Info {
        return;
    }
    update(|s| {
        let text = clip(&args.to_string());
        let entry = Line { level: level.as_str(), text, at: Stamp::now() };
        if let Some(message) = SERVER_MARKERS.iter().find_map(|m| entry.text.split_once(m).map(|(_, rest)| rest.trim())) {
            if !message.is_empty() {
                s.server_message = Some(Line { text: message.to_string(), ..entry.clone() });
            }
        }
        if level <= log::Level::Warn {
            s.last_issue = Some(entry.clone());
        }
        s.last_log = Some(entry);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use gswifi_core::{SupportLevel, Transport};

    static INFO: DriverInfo = DriverInfo {
        name: "ruijie",
        title: "锐捷 802.1X",
        transport: Transport::Eapol,
        support: SupportLevel::FieldTested,
        docs: &[],
    };

    fn sandbox(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gswifi-status-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(format!("{}.json", name))).unwrap()
    }

    #[test]
    fn uptime_parsing() {
        assert_eq!(parse_uptime("12345.67 12000.00\n"), Some(12345));
        assert_eq!(parse_uptime("7"), Some(7));
        assert_eq!(parse_uptime(""), None);
        assert_eq!(parse_uptime("soon"), None);
    }

    #[test]
    fn file_names_cannot_escape_the_directory() {
        assert_eq!(file_stem("campus"), "campus");
        assert_eq!(file_stem("eth0.2"), "eth0.2");
        assert_eq!(file_stem("../../etc/passwd"), "_._.._etc_passwd");
        assert_eq!(file_stem("校园网 1"), "____1");
        assert_eq!(file_stem(""), "network");
        assert_eq!(file_stem(".hidden"), "_hidden");
    }

    #[test]
    fn nothing_happens_without_begin() {
        // No reporter on this thread: all of these are no-ops.
        attempt();
        state(AuthState::Online, &NetInfo::default());
        stopped(&Stop::Finished, false);
        log(log::Level::Error, &format_args!("x"));
    }

    #[test]
    fn a_session_from_start_to_online() {
        let dir = sandbox("online");
        begin(&dir, "campus").unwrap();
        let text = read(&dir, "campus");
        assert!(text.contains(r#""version":1"#) && text.contains(r#""state":"starting""#), "{}", text);
        assert!(text.contains(&format!(r#""pid":{}"#, std::process::id())));
        assert!(text.ends_with("}\n"));

        attempt();
        let env = Env {
            interface: "eth1".into(),
            mac: [0, 0x1a, 0xa9, 1, 2, 3],
            net: NetInfo { ip: [10, 0, 0, 7], gateway: [10, 0, 0, 1], ..NetInfo::default() },
        };
        describe(&INFO, &env);
        state(AuthState::Discovering, &env.net);
        log(log::Level::Info, &format_args!("寻找认证服务器..."));
        let text = read(&dir, "campus");
        for part in [
            r#""driver":"ruijie""#,
            r#""title":"锐捷 802.1X""#,
            r#""support":"field-tested""#,
            r#""interface":"eth1""#,
            r#""mac":"00:1a:a9:01:02:03""#,
            r#""ipv4":"10.0.0.7""#,
            r#""gateway":"10.0.0.1""#,
            r#""dns":"""#,
            r#""state":"discovering""#,
            r#""attempts":1"#,
            r#""successes":0"#,
            r#""online_since":null"#,
            r#""last_log":{"level":"INFO","text":"寻找认证服务器...""#,
            r#""last_issue":null"#,
        ] {
            assert!(text.contains(part), "{} missing in {}", part, text);
        }

        state(AuthState::Authenticating, &env.net);
        state(AuthState::Online, &env.net);
        // Reporting the same state again does not count a second success.
        state(AuthState::Online, &env.net);
        let text = read(&dir, "campus");
        assert!(text.contains(r#""state":"online""#) && text.contains(r#""successes":1"#), "{}", text);
        assert!(!text.contains(r#""online_since":null"#));

        // Dropped: no longer online, but the last time is remembered.
        state(AuthState::Backoff, &env.net);
        let text = read(&dir, "campus");
        assert!(text.contains(r#""online_since":null"#) && !text.contains(r#""last_online":null"#), "{}", text);
        // No temporary file is left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejections_are_recorded_with_their_reason() {
        let dir = sandbox("rejected");
        begin(&dir, "wan").unwrap();
        attempt();
        log(log::Level::Info, &format_args!("系统公告：\n本月流量已用 \"80%\"\n请勿共享"));
        log(log::Level::Error, &format_args!("系统提示：密码错误 <b>3</b> 次"));
        let stop = Stop::Rejected { stage: RejectStage::Password, message: Some("密码错误".into()) };
        stopped(&stop, true);
        let text = read(&dir, "wan");
        for part in [
            r#""state":"rejected""#,
            r#""exit_code":3"#,
            r#""reject_stage":"password""#,
            r#""reason":"密码错误""#,
            r#""waiting_for_change":true"#,
            r#""last_issue":{"level":"ERROR","text":"系统提示：密码错误 <b>3</b> 次""#,
            r#""server_message":{"level":"ERROR","text":"密码错误 <b>3</b> 次""#,
        ] {
            assert!(text.contains(part), "{} missing in {}", part, text);
        }

        // The next attempt clears the verdict but keeps the messages.
        attempt();
        let text = read(&dir, "wan");
        assert!(text.contains(r#""state":"starting""#) && text.contains(r#""attempts":2"#), "{}", text);
        assert!(text.contains(r#""exit_code":null"#) && text.contains(r#""reason":null"#));
        assert!(text.contains(r#""waiting_for_change":false"#));
        assert!(text.contains("密码错误 <b>3</b> 次"));

        stopped(&Stop::GaveUp { rounds: 3 }, true);
        assert!(read(&dir, "wan").contains(r#""state":"gave-up""#));
        stopped(&Stop::ServerNotFound, true);
        assert!(read(&dir, "wan").contains(r#""exit_code":255"#));
        stopped(&Stop::Fatal("未找到网卡 eth9".into()), false);
        let text = read(&dir, "wan");
        assert!(text.contains(r#""state":"fatal""#) && text.contains(r#""reason":"未找到网卡 eth9""#), "{}", text);
        stopped(&Stop::Finished, false);
        assert!(read(&dir, "wan").contains(r#""state":"stopped""#));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_capture_is_bounded_and_ignores_debug() {
        let dir = sandbox("log");
        begin(&dir, "n").unwrap();
        log(log::Level::Debug, &format_args!("状态: Online"));
        assert!(read(&dir, "n").contains(r#""last_log":null"#));
        let long = "字".repeat(MAX_TEXT + 50);
        log(log::Level::Warn, &format_args!("{}", long));
        let text = read(&dir, "n");
        assert!(text.contains(&format!("{}…", "字".repeat(MAX_TEXT))));
        assert!(!text.contains(&"字".repeat(MAX_TEXT + 1)));
        // An announcement marker with nothing after it is not a message.
        log(log::Level::Info, &format_args!("系统公告："));
        assert!(read(&dir, "n").contains(r#""server_message":null"#));
        let _ = fs::remove_dir_all(&dir);
    }
}
