//! Scripted fake-server tests: every request the driver emits is checked,
//! and the "server" answers through `on_http`/`on_timer`.

use std::time::{Duration, Instant, UNIX_EPOCH};

use gswifi_core::{Action, AuthState, Credentials, Driver, Env, HttpRequest, HttpResponse, NetInfo, RejectStage, Stop};

use super::{HubeiOldMacDriver, PortalOptions};
use crate::hubei::derive_old_mac;
use crate::walltime::days_from_civil;

/// The simulated account of the gap-closure harness (`out_sim.txt`,
/// `out_sim_pw.txt`): on 1120 the firmware derives `0e6124a3cb4dec5a`.
const USER: &str = "2026310488@hubupt";
const PASS: &str = "Xy9#k2Lt";
const DERIVED_1120: &str = "0e6124a3cb4dec5a";
const IP: [u8; 4] = [10, 21, 0, 7];

/// 0x6aff9488, the harness's pinned `time()`: 2026-11-20 08:30 in China.
const SERVER_DATE: &str = "Fri, 20 Nov 2026 00:30:00 GMT";
/// The router's clock before NTP: 2020-01-01, deliberately wrong.
const WRONG_WALL_CLOCK: u64 = 1_577_836_800;

const PROBE: &str = "http://www.baidu.com/";
const REDIRECT: &str = "http://58.53.199.1:8080/portal/index.jsp?userip=10.21.0.7&wlanacname=HB-WH-ME60\
                        &nasip=58.53.1.1&usermac=02-00-00-00-00-01";
const ENTRY: &str = "http://58.53.199.1:8080/?userip=10.21.0.7&wlanacname=HB-WH-ME60&nasip=58.53.1.1\
                     &usermac=02-00-00-00-00-01&aidcauthtype=0";
const LOGIN: &str = "http://58.53.199.1:8080/portal/login.do?ac=HB";
const LOGOFF: &str = "http://58.53.199.1:8080/portal/logoff.do?x=1";

fn env() -> Env {
    Env { interface: "wan".into(), mac: [2, 0, 0, 0, 0, 1], net: NetInfo { ip: IP, ..NetInfo::default() } }
}

fn driver_at(opts: PortalOptions, wall_secs: u64) -> HubeiOldMacDriver {
    HubeiOldMacDriver::new(env(), Credentials::new(USER, PASS), opts)
        .unwrap()
        .with_wall_clock(move || UNIX_EPOCH + Duration::from_secs(wall_secs))
}

fn driver(opts: PortalOptions) -> HubeiOldMacDriver {
    driver_at(opts, WRONG_WALL_CLOCK)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The single action must be an HTTP request.
fn http(actions: &[Action]) -> (u32, HttpRequest) {
    match actions {
        [Action::Http { id, request }] => (*id, request.clone()),
        other => panic!("expected one HTTP request, got {:?}", other),
    }
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Result<HttpResponse, String> {
    Ok(HttpResponse {
        status,
        headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: body.as_bytes().to_vec(),
    })
}

fn wispr_redirect(login: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><WISPAccessGatewayParam><Redirect>\
         <LoginURL>{}</LoginURL><ConfigURL>http://58.53.199.149:8005/aidcclient/settings/AidcConfig_HB.dat</ConfigURL>\
         <MessageType>100</MessageType><ResponseCode>0</ResponseCode></Redirect></WISPAccessGatewayParam>",
        login
    )
}

fn auth_reply(code: u32, message: &str, logoff: Option<&str>) -> String {
    format!(
        "<html><body><!--<WISPAccessGatewayParam><AuthenticationReply><MessageType>120</MessageType>\
         <ResponseCode>{}</ResponseCode><ReplyMessage>{}</ReplyMessage>{}</AuthenticationReply>\
         </WISPAccessGatewayParam>--></body></html>",
        code,
        message,
        logoff.map(|l| format!("<LogoffURL>{}</LogoffURL>", l)).unwrap_or_default()
    )
}

fn expected_body(derived: &str) -> String {
    format!(
        "button=Login&UserName=%21%5EMdsc02026310488%40hubupt&Password={}&FNAME=0\
         &OriginatingServer=http%3A%2F%2Fwww.sina.com.cn%2F",
        derived
    )
}

/// Runs probe → entry → login and returns the login request (unanswered).
fn up_to_login(d: &mut HubeiOldMacDriver, now: Instant, entry_headers: &[(&str, &str)]) -> (u32, HttpRequest) {
    let (id, probe) = http(&d.start(now));
    assert_eq!((probe.method.as_str(), probe.url.as_str()), ("GET", PROBE));
    let (id, entry) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), now));
    assert_eq!(entry.url, ENTRY);
    http(&d.on_http(id, resp(200, entry_headers, &wispr_redirect("/portal/login.do?ac=HB")), now))
}

fn online(d: &mut HubeiOldMacDriver, now: Instant) {
    let (id, login) = up_to_login(d, now, &[("Date", SERVER_DATE)]);
    assert_eq!(login.url, LOGIN);
    assert!(d.on_http(id, resp(200, &[], &auth_reply(50, "ok", Some("/portal/logoff.do?x=1"))), now).is_empty());
    assert_eq!(d.state(), AuthState::Online);
}

/// Deadline of the current backoff, checked against `base` plus at most
/// 10 % jitter.
fn backoff_deadline(d: &HubeiOldMacDriver, now: Instant, base: u64) -> Instant {
    assert_eq!(d.state(), AuthState::Backoff);
    let at = d.next_deadline().unwrap();
    assert!(at >= now + secs(base) && at <= now + secs(base) + Duration::from_millis(base * 100), "{:?}", at - now);
    at
}

#[test]
fn success_flow_uses_server_date_cookies_and_logs_off() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    assert!(d.requirements().needs_ipv4);
    assert_eq!(d.state(), AuthState::Idle);

    let (id, probe) = http(&d.start(t0));
    assert_eq!(probe.url, PROBE);
    assert_eq!(header(&probe, "ClientVersion"), None, "the probe is not a portal request");
    assert_eq!(d.state(), AuthState::Discovering);
    assert!(d.start(t0).is_empty(), "start is idempotent");

    let (id, entry) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    assert_eq!((entry.method.as_str(), entry.url.as_str()), ("GET", ENTRY));
    assert_eq!(header(&entry, "ClientVersion"), Some("Mdsc"));
    assert_eq!(header(&entry, "Cookie"), None);

    let entry_answer = resp(
        200,
        &[("Date", SERVER_DATE), ("Set-Cookie", "JSESSIONID=s1; Path=/; HttpOnly")],
        &wispr_redirect("/portal/login.do?ac=HB"),
    );
    let (id, login) = http(&d.on_http(id, entry_answer, t0));
    assert_eq!((login.method.as_str(), login.url.as_str()), ("POST", LOGIN));
    assert_eq!(header(&login, "Content-Type"), Some("application/x-www-form-urlencoded"));
    assert_eq!(header(&login, "ClientVersion"), Some("Mdsc"));
    assert_eq!(header(&login, "Cookie"), Some("JSESSIONID=s1"));
    // The wall clock says 2020-01-01; the server's Date (1120) wins, and the
    // body carries the firmware's own derived value for that day.
    assert_eq!(String::from_utf8(login.body.clone()).unwrap(), expected_body(DERIVED_1120));
    assert!(!String::from_utf8_lossy(&login.body).contains(PASS));
    assert_eq!(d.state(), AuthState::Authenticating);

    let actions = d.on_http(id, resp(200, &[], &auth_reply(50, "认证成功", Some("/portal/logoff.do?x=1"))), t0);
    assert!(actions.is_empty());
    assert_eq!(d.state(), AuthState::Online);
    assert!(d.is_authenticated());
    assert!(!d.vendor_keepalive_implemented());
    assert_eq!(d.next_deadline(), Some(t0 + secs(60)));

    // Liveness check: not intercepted → still online.
    let t1 = t0 + secs(60);
    assert!(d.on_timer(t1 - secs(1)).is_empty(), "early timer does nothing");
    let (id, check) = http(&d.on_timer(t1));
    assert_eq!(check.url, PROBE);
    assert_eq!(d.state(), AuthState::Online);
    assert!(d.on_http(id, resp(200, &[], "<html>baidu</html>"), t1).is_empty());
    assert_eq!(d.next_deadline(), Some(t1 + secs(60)));
    assert!(d.is_authenticated());

    // Logoff: WISPr GET of the saved LogoffURL with the session cookie.
    let actions = d.logoff(t1);
    match actions.as_slice() {
        [Action::Http { request, .. }, Action::Stop(Stop::Finished)] => {
            assert_eq!((request.method.as_str(), request.url.as_str()), ("GET", LOGOFF));
            assert_eq!(header(request, "Cookie"), Some("JSESSIONID=s1"));
            assert_eq!(header(request, "ClientVersion"), Some("Mdsc"));
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(d.state(), AuthState::Stopped);
    assert_eq!(d.next_deadline(), None);
}

#[test]
fn without_server_date_the_wall_clock_and_utc_offset_decide_the_day() {
    let t0 = Instant::now();
    // 2026-11-19 20:00 UTC = 2026-11-20 04:00 in China.
    let wall = (days_from_civil(2026, 11, 19) * 86_400 + 20 * 3600) as u64;
    let mut d = driver_at(PortalOptions::default(), wall);
    let (_, login) = up_to_login(&mut d, t0, &[]);
    assert_eq!(String::from_utf8(login.body).unwrap(), expected_body(DERIVED_1120));

    // UTC: still the 19th.
    let opts = PortalOptions { utc_offset_minutes: 0, ..PortalOptions::default() };
    let mut d = driver_at(opts, wall);
    let (_, login) = up_to_login(&mut d, t0, &[]);
    let derived_1119 = derive_old_mac(USER, PASS.as_bytes(), "1119").unwrap();
    assert_ne!(derived_1119.expose(), DERIVED_1120);
    assert_eq!(String::from_utf8(login.body).unwrap(), expected_body(derived_1119.expose()));

    // A manual offset applies when there is no Date; with use_server_date
    // off it applies even though the server sent one.
    let opts =
        PortalOptions { use_server_date: false, server_time_offset_secs: -12 * 3600, ..PortalOptions::default() };
    let mut d = driver_at(opts, wall);
    let (_, login) = up_to_login(&mut d, t0, &[("Date", SERVER_DATE)]);
    assert_eq!(String::from_utf8(login.body).unwrap(), expected_body(derived_1119.expose()));
}

#[test]
fn relative_locations_multi_hop_and_header_case() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    let (id, _) = http(&d.start(t0));
    // Hop 1: a redirect without portal parameters is followed.
    let (id, hop) = http(&d.on_http(id, resp(302, &[("location", "http://GW.Local/redirect?step=1")], ""), t0));
    assert_eq!(hop.url, "http://gw.local/redirect?step=1");
    assert_eq!(d.state(), AuthState::Discovering);
    // Hop 2: relative Location, upper-case header, mixed-case parameter name.
    let relative = "/portal/../portal/?UserIP=10.21.0.7&wlanacname=AC%2D1&nasip=1.1.1.1&usermac=02:00:00:00:00:01";
    let (id, entry) = http(&d.on_http(id, resp(307, &[("LOCATION", relative)], ""), t0));
    assert_eq!(
        entry.url,
        "http://gw.local/?userip=10.21.0.7&wlanacname=AC%2D1&nasip=1.1.1.1&usermac=02:00:00:00:00:01&aidcauthtype=0"
    );
    // The entry itself redirects (relative path); the XML then gives a
    // relative LoginURL with an entity.
    let (id, xml_page) = http(&d.on_http(id, resp(302, &[("Location", "login/xml")], ""), t0));
    assert_eq!(xml_page.url, "http://gw.local/login/xml");
    assert_eq!(header(&xml_page, "ClientVersion"), Some("Mdsc"));
    let (_, login) = http(&d.on_http(id, resp(200, &[], &wispr_redirect("../auth?a=1&amp;b=2")), t0));
    assert_eq!((login.method.as_str(), login.url.as_str()), ("POST", "http://gw.local/auth?a=1&b=2"));
}

#[test]
fn server_errors_back_off_exponentially_and_retry() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    let (id, _) = http(&d.start(t0));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    assert!(d.on_http(id, resp(500, &[], "Internal Server Error"), t0).is_empty());
    let t1 = backoff_deadline(&d, t0, 5);

    // Next round from the probe; this time the login answers 102.
    let (id, probe) = http(&d.on_timer(t1));
    assert_eq!(probe.url, PROBE);
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t1));
    let (id, _) = http(&d.on_http(id, resp(200, &[], &wispr_redirect(LOGIN)), t1));
    assert!(d.on_http(id, resp(200, &[], &auth_reply(102, "RADIUS timeout", None)), t1).is_empty());
    let t2 = backoff_deadline(&d, t1, 10);

    // Code 100 is not a confirmed credential error: retried, not stopped.
    let (id, _) = http(&d.on_timer(t2));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t2));
    let (id, _) = http(&d.on_http(id, resp(200, &[], &wispr_redirect(LOGIN)), t2));
    assert!(d.on_http(id, resp(200, &[], &auth_reply(100, "密码错误", None)), t2).is_empty());
    let t3 = backoff_deadline(&d, t2, 20);

    // Non-WISPr answers are failures too, never "success".
    let (id, _) = http(&d.on_timer(t3));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t3));
    assert!(d.on_http(id, resp(200, &[], "<html>success</html>"), t3).is_empty());
    let t4 = backoff_deadline(&d, t3, 40);

    // A success resets the backoff.
    let (id, _) = http(&d.on_timer(t4));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t4));
    let (id, _) = http(&d.on_http(id, resp(200, &[], &wispr_redirect(LOGIN)), t4));
    assert!(d.on_http(id, resp(200, &[], &auth_reply(50, "", None)), t4).is_empty());
    assert_eq!(d.state(), AuthState::Online);
    // ...and without a LogoffURL, logoff only stops.
    assert_eq!(d.logoff(t4), vec![Action::Stop(Stop::Finished)]);
}

#[test]
fn stop_on_reject_stops_with_the_server_message() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { stop_on_reject: true, ..PortalOptions::default() });
    let (id, _) = up_to_login(&mut d, t0, &[]);
    let actions = d.on_http(id, resp(200, &[], &auth_reply(100, "用户名或密码错误", None)), t0);
    assert_eq!(
        actions,
        vec![Action::Stop(Stop::Rejected {
            stage: RejectStage::Password, message: Some("用户名或密码错误".into())
        })]
    );
    assert_eq!(d.state(), AuthState::Stopped);
    // gaps.md convention 2: a new address clears the terminal state.
    let (_, probe) = http(&d.on_net_change(NetInfo { ip: [10, 21, 0, 8], ..NetInfo::default() }, t0));
    assert_eq!(probe.url, PROBE);
}

#[test]
fn timeouts_retry_with_capped_backoff_and_stale_answers_are_ignored() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { max_backoff_secs: 12, ..PortalOptions::default() });
    let (id1, _) = http(&d.start(t0));
    assert_eq!(d.next_deadline(), Some(t0 + secs(15)));
    // The runtime reports a transport timeout.
    assert!(d.on_http(id1, Err("connection timed out".into()), t0).is_empty());
    let t1 = backoff_deadline(&d, t0, 5);

    // The driver's own deadline: no answer at all.
    let (id2, _) = http(&d.on_timer(t1));
    assert_ne!(id1, id2);
    assert_eq!(d.next_deadline(), Some(t1 + secs(15)));
    assert!(d.on_timer(t1 + secs(15)).is_empty());
    let t2 = backoff_deadline(&d, t1 + secs(15), 10);
    // The late answer to the timed-out request changes nothing.
    assert!(d.on_http(id2, resp(302, &[("Location", REDIRECT)], ""), t2).is_empty());
    assert_eq!(d.state(), AuthState::Backoff);

    // Third failure: 20 s capped to 12 s.
    let (id3, _) = http(&d.on_timer(t2));
    assert!(d.on_http(id3, Err("no route to host".into()), t2).is_empty());
    let t3 = backoff_deadline(&d, t2, 12);
    let (id4, _) = http(&d.on_timer(t3));
    assert!(d.on_http(id4, Err("no route to host".into()), t3).is_empty());
    backoff_deadline(&d, t3, 12);
}

#[test]
fn max_rounds_gives_up_distinguishing_server_not_found() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { max_rounds: 2, ..PortalOptions::default() });
    let (id, _) = http(&d.start(t0));
    assert!(d.on_http(id, Err("timeout".into()), t0).is_empty());
    let (id, _) = http(&d.on_timer(d.next_deadline().unwrap()));
    assert_eq!(d.on_http(id, Err("timeout".into()), t0), vec![Action::Stop(Stop::ServerNotFound)]);

    let mut d = driver(PortalOptions { max_rounds: 1, ..PortalOptions::default() });
    let (id, _) = http(&d.start(t0));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    assert_eq!(d.on_http(id, resp(503, &[], ""), t0), vec![Action::Stop(Stop::GaveUp { rounds: 1 })]);
}

#[test]
fn address_change_discards_the_session_and_retries_at_once() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    online(&mut d, t0);
    assert!(d.is_authenticated());

    // Same address (lease renewal): nothing happens.
    assert!(d.on_net_change(NetInfo { ip: IP, ..NetInfo::default() }, t0).is_empty());
    assert_eq!(d.state(), AuthState::Online);

    // New address: session dropped (no stale logoff), new round right away.
    let new_net = NetInfo { ip: [10, 21, 0, 99], ..NetInfo::default() };
    let (id, probe) = http(&d.on_net_change(new_net, t0));
    assert_eq!(probe.url, PROBE);
    assert_eq!(d.state(), AuthState::Discovering);
    assert!(!d.is_authenticated());

    // Fail into backoff, then lose the address: wait for one.
    assert!(d.on_http(id, Err("down".into()), t0).is_empty());
    assert_eq!(d.state(), AuthState::Backoff);
    assert!(d.on_net_change(NetInfo::default(), t0).is_empty());
    assert_eq!(d.state(), AuthState::WaitingIp);
    assert_eq!(d.next_deadline(), None);

    // Address back: immediate probe, backoff reset (next failure waits 5 s).
    let (id, _) = http(&d.on_net_change(new_net, t0));
    assert!(d.on_http(id, Err("down".into()), t0).is_empty());
    backoff_deadline(&d, t0, 5);
    assert_eq!(d.logoff(t0), vec![Action::Stop(Stop::Finished)]);
}

#[test]
fn no_address_at_start_waits() {
    let t0 = Instant::now();
    let env = Env { net: NetInfo::default(), ..env() };
    let mut d = HubeiOldMacDriver::new(env, Credentials::new(USER, PASS), PortalOptions::default()).unwrap();
    assert!(d.start(t0).is_empty());
    assert_eq!(d.state(), AuthState::WaitingIp);
    let (_, probe) = http(&d.on_net_change(NetInfo { ip: IP, ..NetInfo::default() }, t0));
    assert_eq!(probe.url, PROBE);
}

#[test]
fn liveness_check_detects_a_lost_session_and_logs_in_again() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    online(&mut d, t0);
    let t1 = t0 + secs(60);
    let (id, _) = http(&d.on_timer(t1));
    // A network error during the check keeps the session.
    assert!(d.on_http(id, Err("timeout".into()), t1).is_empty());
    assert!(d.is_authenticated());
    let t2 = t1 + secs(60);
    assert_eq!(d.next_deadline(), Some(t2));
    let (id, _) = http(&d.on_timer(t2));
    // Intercepted again: the session is gone, straight to the entry.
    let (_, entry) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t2));
    assert_eq!(entry.url, ENTRY);
    assert!(!d.is_authenticated());
    assert_eq!(d.state(), AuthState::Discovering);
}

#[test]
fn not_intercepted_means_online_without_login() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { check_secs: 0, ..PortalOptions::default() });
    let (id, _) = http(&d.start(t0));
    assert!(d.on_http(id, resp(200, &[], "<html></html>"), t0).is_empty());
    assert_eq!(d.state(), AuthState::Online);
    assert!(!d.is_authenticated());
    assert_eq!(d.next_deadline(), None, "check_secs = 0 disables the liveness probe");
    // A redirect to HTTPS without portal parameters is the real site.
    let mut d = driver(PortalOptions::default());
    let (id, _) = http(&d.start(t0));
    assert!(d.on_http(id, resp(302, &[("Location", "https://www.baidu.com/")], ""), t0).is_empty());
    assert_eq!(d.state(), AuthState::Online);
    assert_eq!(d.logoff(t0), vec![Action::Stop(Stop::Finished)]);
}

#[test]
fn credentials_only_go_to_allowed_plain_http_hosts() {
    let t0 = Instant::now();
    let run = |opts: PortalOptions, login: &str| {
        let mut d = driver(opts);
        let (id, _) = http(&d.start(t0));
        let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
        d.on_http(id, resp(200, &[], &wispr_redirect(login)), t0)
    };
    let actions = run(PortalOptions::default(), "http://evil.example/login");
    assert!(
        matches!(actions.as_slice(), [Action::Stop(Stop::Fatal(m))] if m.contains("evil.example") && m.contains("allowed_hosts"))
    );
    let actions = run(PortalOptions::default(), "https://58.53.199.1/login");
    assert!(matches!(actions.as_slice(), [Action::Stop(Stop::Fatal(m))] if m.contains("HTTPS")));
    // Same host on another port is the same host.
    let (_, login) = http(&run(PortalOptions::default(), "http://58.53.199.1:9090/login"));
    assert_eq!(login.method, "POST");
    // Explicitly allowed.
    let opts = PortalOptions { allowed_hosts: vec!["Evil.Example".into()], ..PortalOptions::default() };
    let (_, login) = http(&run(opts, "http://evil.example/login"));
    assert_eq!(login.url, "http://evil.example/login");
    // A LogoffURL elsewhere is dropped, not used.
    let mut d = driver(PortalOptions::default());
    let (id, _) = up_to_login(&mut d, t0, &[]);
    assert!(d.on_http(id, resp(200, &[], &auth_reply(50, "", Some("http://other/logoff"))), t0).is_empty());
    assert_eq!(d.logoff(t0), vec![Action::Stop(Stop::Finished)]);
}

#[test]
fn portal_host_overrides_the_redirect_host() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { portal_host: "Portal.HB.edu:8088".into(), ..PortalOptions::default() });
    let (id, _) = http(&d.start(t0));
    let (id, entry) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    assert!(entry.url.starts_with("http://portal.hb.edu:8088/?userip=10.21.0.7&"), "{}", entry.url);
    let (_, login) = http(&d.on_http(id, resp(200, &[], &wispr_redirect("/login")), t0));
    assert_eq!(login.url, "http://portal.hb.edu:8088/login");
}

#[test]
fn incomplete_redirect_is_a_retryable_error_not_a_guess() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    let (id, _) = http(&d.start(t0));
    let no_nasip = "http://58.53.199.1/?userip=10.21.0.7&wlanacname=AC&usermac=m";
    assert!(d.on_http(id, resp(302, &[("Location", no_nasip)], ""), t0).is_empty());
    backoff_deadline(&d, t0, 5);
}

#[test]
fn no_secret_reaches_debug_output() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions::default());
    let (id, _) = http(&d.start(t0));
    let (id, _) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    let actions = d.on_http(id, resp(200, &[("Date", SERVER_DATE)], &wispr_redirect(LOGIN)), t0);
    let shown = format!("{:?}", actions);
    assert!(shown.contains("POST") && !shown.contains(PASS) && !shown.contains(DERIVED_1120), "{}", shown);
}

#[test]
fn option_and_credential_validation() {
    let build = |user: &str, pass: &str, opts: PortalOptions| {
        HubeiOldMacDriver::new(env(), Credentials::new(user, pass), opts).err().unwrap_or_default()
    };
    let ok = PortalOptions::default;
    assert!(build(" ", PASS, ok()).contains("用户名"));
    assert!(build("a\nb", PASS, ok()).contains("控制字符"));
    assert!(build(USER, "", ok()).contains("密码"));
    assert!(build(USER, "a\0b", ok()).contains("NUL"));
    assert!(build(USER, PASS, PortalOptions { probe_url: "https://www.baidu.com/".into(), ..ok() }).contains("http://"));
    assert!(build(USER, PASS, PortalOptions { probe_url: "www.baidu.com".into(), ..ok() }).contains("probe_url"));
    assert!(build(USER, PASS, PortalOptions { portal_host: "http://h/".into(), ..ok() }).contains("portal_host"));
    assert!(build(USER, PASS, PortalOptions { allowed_hosts: vec!["a/b".into()], ..ok() }).contains("allowed_hosts"));
    assert!(build(USER, PASS, PortalOptions { utc_offset_minutes: 900, ..ok() }).contains("utc_offset_minutes"));
    assert!(build(USER, PASS, PortalOptions { timeout_secs: 0, ..ok() }).contains("timeout_secs"));
    assert!(
        build(USER, PASS, PortalOptions { retry_secs: 10, max_backoff_secs: 5, ..ok() }).contains("max_backoff_secs")
    );
    assert!(build(USER, PASS, PortalOptions { max_redirects: 11, ..ok() }).contains("max_redirects"));
    assert!(build(USER, PASS, PortalOptions { server_time_offset_secs: i64::MAX, ..ok() })
        .contains("server_time_offset_secs"));
    assert!(build(USER, PASS, PortalOptions { user_agent: "x\r\nEvil: 1".into(), ..ok() }).contains("user_agent"));
    assert_eq!(build(USER, PASS, ok()), "");
    let d = HubeiOldMacDriver::new(env(), Credentials::new(USER, PASS), ok()).unwrap();
    assert_eq!(d.info().name, "portal-hubei-old-mac");
    // Every option shows up in Debug (the CLI's unknown-key check relies on it).
    let shown = format!("{:?}", PortalOptions::default());
    for field in ["probe_url", "portal_host", "allowed_hosts", "utc_offset_minutes", "use_server_date", "check_secs"] {
        assert!(shown.contains(field), "{}", field);
    }
}

#[test]
fn user_agent_is_sent_when_configured() {
    let t0 = Instant::now();
    let mut d = driver(PortalOptions { user_agent: "Mozilla/5.0".into(), ..PortalOptions::default() });
    let (id, probe) = http(&d.start(t0));
    assert_eq!(header(&probe, "User-Agent"), Some("Mozilla/5.0"));
    let (_, entry) = http(&d.on_http(id, resp(302, &[("Location", REDIRECT)], ""), t0));
    assert_eq!(header(&entry, "User-Agent"), Some("Mozilla/5.0"));
}
