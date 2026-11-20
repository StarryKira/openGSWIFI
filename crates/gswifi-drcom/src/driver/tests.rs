//! Driver tests against a scripted fake server: feed datagrams and timer
//! expiries, assert the returned actions.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use gswifi_core::{Action, AuthState, Credentials, Datagram, Driver, Env, NetInfo, RejectStage, Stop};

use super::*;
use crate::primitives::{gen_crc, md5a};

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IP: [u8; 4] = [10, 1, 2, 3];
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SEED: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const AUTH_INFO: [u8; 16] = [0xa5; 16];

fn net(ip: [u8; 4]) -> NetInfo {
    NetInfo { ip, mask: [255, 255, 255, 0], gateway: [10, 1, 2, 1], dns: [10, 0, 0, 53], ipv6: [0; 16] }
}

fn env() -> Env {
    Env { interface: "wan".into(), mac: MAC, net: net(IP) }
}

fn dhcp_opts() -> Options {
    Options {
        server: SERVER,
        auth_version: Some("2700".into()),
        keep_alive_version: Some("dc02".into()),
        dhcp_server: Ipv4Addr::new(10, 1, 2, 1),
        host_name: "router".into(),
        ..Options::default()
    }
}

fn pppoe_opts() -> Options {
    Options { mode: Mode::Pppoe, server: SERVER, pppoe_flag: Some(0x2a), ..Options::default() }
}

fn creds() -> Credentials {
    Credentials::new("student", "secret")
}

fn driver(opts: Options) -> DrcomDriver {
    DrcomDriver::new(env(), creds(), opts).unwrap()
}

/// Payloads of the SendUdp actions; checks ports and destination.
fn sent(actions: &[Action]) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendUdp { local_port, to, payload } => {
                assert_eq!(*local_port, 61440);
                assert_eq!(*to, SocketAddrV4::new(SERVER, 61440));
                Some(payload.clone())
            }
            _ => None,
        })
        .collect()
}

fn one(actions: &[Action]) -> Vec<u8> {
    let s = sent(actions);
    assert_eq!(s.len(), 1, "{actions:?}");
    s.into_iter().next().unwrap()
}

fn stop_of(actions: &[Action]) -> Option<Stop> {
    actions.iter().find_map(|a| if let Action::Stop(s) = a { Some(s.clone()) } else { None })
}

struct Sim {
    d: DrcomDriver,
    now: Instant,
}

impl Sim {
    fn new(opts: Options) -> Sim {
        Sim { d: driver(opts), now: Instant::now() }
    }

    fn start(&mut self) -> Vec<Action> {
        self.d.start(self.now)
    }

    fn rx(&mut self, payload: &[u8]) -> Vec<Action> {
        self.now += Duration::from_millis(5);
        let dg = Datagram { local_port: 61440, from: SocketAddrV4::new(SERVER, 61440), payload };
        self.d.on_datagram(dg, self.now)
    }

    /// Advances to the next deadline and fires it.
    fn fire(&mut self) -> Vec<Action> {
        let deadline = self.d.next_deadline().expect("no deadline armed");
        assert!(deadline >= self.now);
        self.now = deadline;
        self.d.on_timer(self.now)
    }

    fn until_deadline(&self) -> Duration {
        self.d.next_deadline().unwrap() - self.now
    }
}

fn challenge_reply(seed: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = 0x02;
    b[1] = 0x02;
    b[4..8].copy_from_slice(&seed);
    b
}

fn login_ok() -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0] = 0x04;
    b[23..39].copy_from_slice(&AUTH_INFO);
    b
}

fn failure(code: u8) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = 0x05;
    b[4] = code;
    b
}

fn ka_reply(tail: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0u8; 40];
    b[0] = 0x07;
    b[2] = 0x28;
    b[16..20].copy_from_slice(&tail);
    b
}

/// Runs the DHCP flow up to the first keepalive1 and returns it.
fn online(sim: &mut Sim) -> Vec<u8> {
    one(&sim.start());
    assert!(sim.rx(&challenge_reply(SEED)).is_empty());
    one(&sim.fire());
    assert!(sim.rx(&login_ok()).is_empty());
    assert_eq!(sim.d.state(), AuthState::Online);
    one(&sim.fire())
}

#[test]
fn requirements_and_info() {
    let d = driver(dhcp_opts());
    let r = d.requirements();
    assert_eq!(r.udp_ports, vec![61440]);
    assert!(r.needs_ipv4);
    assert_eq!(r.ethertype, None);
    assert_eq!(d.info().name, "drcom");
    assert_eq!(d.state(), AuthState::Idle);
}

#[test]
fn dhcp_full_cycle() {
    let mut sim = Sim::new(dhcp_opts());
    let ch = one(&sim.start());
    assert_eq!(ch.len(), 20);
    assert_eq!((ch[0], ch[1], ch[4]), (0x01, 0x02, 0x27));
    assert_eq!(sim.d.state(), AuthState::Discovering);
    assert_eq!(sim.until_deadline(), Duration::from_secs(3));

    assert!(sim.rx(&challenge_reply(SEED)).is_empty());
    assert_eq!(sim.until_deadline(), Duration::from_millis(200));
    assert_eq!(sim.d.state(), AuthState::Authenticating);

    let login = one(&sim.fire());
    let a = md5a(SEED, b"secret");
    assert_eq!(login.len(), 330);
    assert_eq!(&login[..4], &[0x03, 0x01, 0x00, 7 + 20]);
    assert_eq!(&login[4..20], &a);
    assert_eq!(&login[20..27], b"student");
    assert_eq!(&login[81..85], &IP);
    assert_eq!(&login[110..116], b"router");
    assert_eq!(&login[142..146], &[10, 0, 0, 53], "interface DNS by default");
    assert_eq!(&login[146..150], &[10, 1, 2, 1]);
    assert_eq!(&login[310..312], &[0x27, 0x00]);
    assert_eq!(&login[328..330], &[0xe9, 0x13]);

    assert!(sim.rx(&login_ok()).is_empty());
    assert_eq!(sim.d.state(), AuthState::Online);
    assert_eq!(sim.until_deadline(), Duration::from_millis(200));

    let ka1 = one(&sim.fire());
    assert_eq!(ka1.len(), 42);
    assert_eq!(ka1[0], 0xff);
    assert_eq!(&ka1[1..17], &a);
    assert_eq!(&ka1[20..36], &AUTH_INFO);

    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    let file = one(&sim.fire());
    assert_eq!(&file[..10], &[0x07, 0, 0x28, 0, 0x0b, 1, 0x0f, 0x27, 0x2f, 0x12]);

    let t1 = one(&sim.rx(&ka_reply([9; 4])));
    assert_eq!(&t1[..8], &[0x07, 1, 0x28, 0, 0x0b, 1, 0xdc, 0x02]);
    assert_eq!(&t1[16..20], &[0; 4]);

    let t3 = one(&sim.rx(&ka_reply([0xaa, 0xbb, 0xcc, 0xdd])));
    assert_eq!(&t3[..8], &[0x07, 2, 0x28, 0, 0x0b, 3, 0xdc, 0x02]);
    assert_eq!(&t3[16..20], &[0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(&t3[28..32], &IP);
    assert_eq!(&t3[32..40], &[0; 8]);

    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    assert_eq!(sim.until_deadline(), Duration::from_secs(20));

    // Next round: keepalive1 again, then type 1 without a file handshake.
    let ka1b = one(&sim.fire());
    assert_eq!(&ka1b[1..17], &a);
    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    let t1b = one(&sim.fire());
    assert_eq!((t1b[1], t1b[5], t1b[6]), (3, 1, 0xdc));
    assert_eq!(sim.d.state(), AuthState::Online);
}

#[test]
fn wrong_password_is_not_retried() {
    let mut sim = Sim::new(dhcp_opts());
    one(&sim.start());
    sim.rx(&challenge_reply(SEED));
    one(&sim.fire());
    let actions = sim.rx(&failure(3));
    match stop_of(&actions) {
        Some(Stop::Rejected { stage: RejectStage::Password, message: Some(m) }) => {
            assert!(m.contains("帐号或密码错误"), "{m}");
            assert!(m.contains("代码 3"));
        }
        other => panic!("{other:?}"),
    }
    assert!(sent(&actions).is_empty());
    assert_eq!(sim.d.state(), AuthState::Stopped);
    assert_eq!(sim.d.next_deadline(), None);
    assert!(sim.d.on_timer(sim.now + Duration::from_secs(60)).is_empty());
    assert!(sim.rx(&challenge_reply(SEED)).is_empty());
}

#[test]
fn confirmed_refusals_stop_with_reason() {
    for (code, stage) in [(11, RejectStage::Password), (21, RejectStage::Other), (23, RejectStage::Other)] {
        let mut sim = Sim::new(dhcp_opts());
        one(&sim.start());
        sim.rx(&challenge_reply(SEED));
        one(&sim.fire());
        match stop_of(&sim.rx(&failure(code))) {
            Some(Stop::Rejected { stage: s, message: Some(_) }) => assert_eq!(s, stage, "code {code}"),
            other => panic!("code {code}: {other:?}"),
        }
    }
}

/// Already online elsewhere, too many users and undocumented codes are
/// not credential errors: back off and log in again.
#[test]
fn unconfirmed_refusals_are_retried() {
    for code in [1u8, 6, 20, 99] {
        let mut sim = Sim::new(dhcp_opts());
        one(&sim.start());
        sim.rx(&challenge_reply(SEED));
        one(&sim.fire());
        let actions = sim.rx(&failure(code));
        assert_eq!(stop_of(&actions), None, "code {code}");
        assert_eq!(sim.d.state(), AuthState::Backoff, "code {code}");
        assert!(sim.d.next_deadline().is_some(), "code {code}");
    }
}

#[test]
fn busy_server_is_retried_after_wait() {
    let mut sim = Sim::new(dhcp_opts());
    one(&sim.start());
    sim.rx(&challenge_reply(SEED));
    one(&sim.fire());
    let actions = sim.rx(&failure(2));
    assert!(actions.is_empty());
    assert_eq!(sim.d.state(), AuthState::Backoff);
    assert_eq!(sim.until_deadline(), Duration::from_secs(3));
    let ch = one(&sim.fire());
    assert_eq!(ch[0], 0x01);
}

#[test]
fn silent_server_not_found_without_eternal() {
    let mut sim = Sim::new(Options { eternal: false, max_retries: 3, ..dhcp_opts() });
    let ch = one(&sim.start());
    assert_eq!(one(&sim.fire()), ch, "challenge resent unchanged");
    assert_eq!(one(&sim.fire()), ch);
    let actions = sim.fire();
    assert_eq!(stop_of(&actions), Some(Stop::ServerNotFound));
    assert_eq!(sim.d.state(), AuthState::Stopped);
}

#[test]
fn login_timeout_restarts_with_new_challenge_then_gives_up() {
    let mut sim = Sim::new(Options { eternal: false, max_retries: 2, ..dhcp_opts() });
    one(&sim.start());
    sim.rx(&challenge_reply(SEED));
    let login = one(&sim.fire());
    assert_eq!(login[0], 0x03);
    let again = one(&sim.fire());
    assert_eq!(again.len(), 20, "a timed-out login asks for a fresh seed");
    assert_eq!(stop_of(&sim.fire()), Some(Stop::GaveUp { rounds: 2 }));
}

#[test]
fn eternal_mode_backs_off_and_retries() {
    let mut sim = Sim::new(Options { max_retries: 2, backoff_secs: 30, ..dhcp_opts() });
    one(&sim.start());
    one(&sim.fire());
    assert!(sim.fire().is_empty());
    assert_eq!(sim.d.state(), AuthState::Backoff);
    assert_eq!(sim.until_deadline(), Duration::from_secs(30));
    let ch = one(&sim.fire());
    assert_eq!(ch.len(), 20);
}

#[test]
fn keepalive_loss_triggers_relogin() {
    let mut sim = Sim::new(dhcp_opts());
    let ka1 = online(&mut sim);
    assert_eq!(one(&sim.fire()), ka1);
    assert_eq!(one(&sim.fire()), ka1);
    let ch = one(&sim.fire());
    assert_eq!(ch.len(), 20, "third timeout: log in again");
    assert_eq!(sim.d.state(), AuthState::Authenticating);
    // The new session works again.
    sim.rx(&challenge_reply([1, 2, 3, 4]));
    let login = one(&sim.fire());
    assert_eq!(&login[4..20], &md5a([1, 2, 3, 4], b"secret"));
}

#[test]
fn notice_does_not_count_as_failure() {
    let mut sim = Sim::new(dhcp_opts());
    online(&mut sim);
    let before = sim.d.next_deadline();
    assert!(sim.rx(&[0x4d, 0x3a, 0, 0]).is_empty());
    assert_eq!(sim.d.next_deadline(), before);
    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    assert_eq!(sim.until_deadline(), Duration::from_millis(200));
}

#[test]
fn server_kick_while_online_relogs() {
    let mut sim = Sim::new(dhcp_opts());
    online(&mut sim);
    let ch = one(&sim.rx(&failure(1)));
    assert_eq!(ch.len(), 20);
}

#[test]
fn foreign_datagrams_ignored() {
    let mut sim = Sim::new(dhcp_opts());
    one(&sim.start());
    let reply = challenge_reply(SEED);
    let other =
        Datagram { local_port: 61440, from: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 61440), payload: &reply };
    assert!(sim.d.on_datagram(other, sim.now).is_empty());
    let port = Datagram { local_port: 61440, from: SocketAddrV4::new(SERVER, 61441), payload: &reply };
    assert!(sim.d.on_datagram(port, sim.now).is_empty());
    let local = Datagram { local_port: 5000, from: SocketAddrV4::new(SERVER, 61440), payload: &reply };
    assert!(sim.d.on_datagram(local, sim.now).is_empty());
    assert_eq!(sim.until_deadline(), Duration::from_secs(3), "still waiting for the real answer");
}

/// Drives a driver into each waiting phase, then feeds garbage. Nothing may
/// panic; truncated answers must not advance the session.
#[test]
fn malformed_input_never_panics() {
    let mut rng = 0x1234_5678_9abc_def1u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    type Setup = (&'static str, fn() -> Sim);
    let setups: Vec<Setup> = vec![
        ("challenge", || {
            let mut s = Sim::new(dhcp_opts());
            s.start();
            s
        }),
        ("login", || {
            let mut s = Sim::new(dhcp_opts());
            s.start();
            s.rx(&challenge_reply(SEED));
            s.fire();
            s
        }),
        ("ka1", || {
            let mut s = Sim::new(dhcp_opts());
            online(&mut s);
            s
        }),
        ("ka1mod", || {
            let mut s = Sim::new(Options { keepalive1_mod: true, ..dhcp_opts() });
            online(&mut s);
            s
        }),
        ("ka2", || {
            let mut s = Sim::new(dhcp_opts());
            online(&mut s);
            s.rx(&ka_reply([0; 4]));
            s.fire();
            s
        }),
        ("ppp-challenge", || {
            let mut s = Sim::new(pppoe_opts());
            s.start();
            s
        }),
        ("ppp-login", || {
            let mut s = Sim::new(pppoe_opts());
            s.start();
            s.rx(&ppp_challenge_reply(true));
            s
        }),
    ];
    for (name, setup) in setups {
        for len in 0..48usize {
            for first in [0x02u8, 0x04, 0x05, 0x07, 0x4d, 0xff] {
                let mut s = setup();
                let mut payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
                if let Some(b) = payload.first_mut() {
                    *b = first;
                }
                let actions = s.rx(&payload);
                for a in &actions {
                    if let Action::SendUdp { payload, .. } = a {
                        assert!(!payload.is_empty(), "{name}");
                    }
                }
                // Truncated answers (shorter than any valid one) never advance.
                if len < 4 && !(first == 0x04 && name == "ppp-login") && first != 0x4d {
                    assert!(actions.is_empty(), "{name}: {payload:02x?} -> {actions:?}");
                }
            }
        }
    }
}

#[test]
fn waits_for_address_then_starts() {
    let mut e = env();
    e.net = NetInfo::default();
    let mut d = DrcomDriver::new(e, creds(), dhcp_opts()).unwrap();
    let now = Instant::now();
    assert_eq!(d.start(now), vec![Action::RequestDhcp]);
    assert_eq!(d.state(), AuthState::WaitingIp);
    assert_eq!(d.next_deadline(), None);
    let actions = d.on_net_change(net(IP), now);
    assert_eq!(one(&actions).len(), 20);
}

#[test]
fn address_change_relogs_with_new_address() {
    let mut sim = Sim::new(dhcp_opts());
    online(&mut sim);
    let new_ip = [10, 1, 2, 99];
    let ch = one(&sim.d.on_net_change(net(new_ip), sim.now));
    assert_eq!(ch.len(), 20);
    sim.rx(&challenge_reply(SEED));
    let login = one(&sim.fire());
    assert_eq!(&login[81..85], &new_ip);
    // Same address again: nothing to do.
    assert!(sim.d.on_net_change(net(new_ip), sim.now).is_empty());
    // Address lost: wait and ask for DHCP.
    assert_eq!(sim.d.on_net_change(NetInfo::default(), sim.now), vec![Action::RequestDhcp]);
    assert_eq!(sim.d.state(), AuthState::WaitingIp);
    assert_eq!(sim.d.next_deadline(), None);
}

#[test]
fn logoff_finishes() {
    let mut sim = Sim::new(dhcp_opts());
    online(&mut sim);
    let actions = sim.d.logoff(sim.now);
    assert_eq!(actions, vec![Action::Stop(Stop::Finished)]);
    assert_eq!(sim.d.state(), AuthState::Stopped);
}

#[test]
fn keepalive1_mod_flow() {
    let mut sim = Sim::new(Options { keepalive1_mod: true, ..dhcp_opts() });
    let req = online(&mut sim);
    assert_eq!(req, vec![0x07, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]);
    let mut seed_reply = vec![0u8; 16];
    seed_reply[0] = 0x07;
    let seed = [0x6f, 0x7c, 0x89, 0x96];
    seed_reply[8..12].copy_from_slice(&seed);
    let pkt = one(&sim.rx(&seed_reply));
    assert_eq!(pkt.len(), 38);
    assert_eq!(&pkt[8..12], &seed);
    assert_eq!(&pkt[12..20], &gen_crc(3, seed));
    assert_eq!(&pkt[20..36], &AUTH_INFO);
    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    let file = one(&sim.fire());
    assert_eq!(&file[5..8], &[1, 0x0f, 0x27]);
}

fn ppp_challenge_reply(enabled: bool) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[0] = 0x07;
    b[5] = enabled as u8;
    b[8..12].copy_from_slice(&[0x03, 0x91, 0x22, 0xe3]);
    b[12..16].copy_from_slice(&[10, 9, 9, 9]);
    b[28..30].copy_from_slice(&[0x12, 0x34]);
    b
}

#[test]
fn pppoe_flow() {
    let mut sim = Sim::new(pppoe_opts());
    let ch = one(&sim.start());
    assert_eq!(ch, vec![0x07, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]);

    let login = one(&sim.rx(&ppp_challenge_reply(true)));
    assert_eq!(login.len(), 96);
    assert_eq!(&login[..5], &[0x07, 0x02, 0x60, 0x00, 0x03]);
    assert_eq!(&login[12..16], &[10, 9, 9, 9]);
    assert_eq!((login[17], login[19]), (0x62, 0x2a));
    assert_eq!(&login[20..24], &[0x03, 0x91, 0x22, 0xe3]);
    assert_eq!(&login[24..32], &gen_crc(3, [0x03, 0x91, 0x22, 0xe3]));

    let mut ok = vec![0u8; 16];
    ok[0] = 0x04;
    let file = one(&sim.rx(&ok));
    assert_eq!(sim.d.state(), AuthState::Online);
    assert_eq!(&file[5..8], &[1, 0x0f, 0x27]);
    let t1 = one(&sim.rx(&ka_reply([0; 4])));
    assert_eq!(&t1[5..8], &[1, 0x12, 0x34], "version from the challenge answer");
    let t3 = one(&sim.rx(&ka_reply([5, 6, 7, 8])));
    assert_eq!(t3[5], 3);
    assert_eq!(&t3[16..20], &[5, 6, 7, 8]);
    assert_eq!(&t3[28..32], &[0; 4]);
    assert_eq!(&t3[32..40], &gen_crc(3, [t3[0], t3[1], t3[2], t3[3]]));
    assert!(sim.rx(&ka_reply([0; 4])).is_empty());
    assert_eq!(sim.until_deadline(), Duration::from_secs(10));
    let t1b = one(&sim.fire());
    assert_eq!(t1b[5], 1);

    // Lost keepalives: a new challenge, and the re-login uses marker 63.
    one(&sim.fire());
    one(&sim.fire());
    let ch2 = one(&sim.fire());
    assert_eq!(&ch2[..2], &[0x07, 0x03]);
    let relogin = one(&sim.rx(&ppp_challenge_reply(false)));
    assert_eq!(relogin[17], 0x63);
    assert_eq!(&relogin[28..32], &[0; 4], "type 0: only [24:28] carries check32");
}

#[test]
fn pppoe_refusal_stops() {
    let mut sim = Sim::new(pppoe_opts());
    one(&sim.start());
    one(&sim.rx(&ppp_challenge_reply(true)));
    match stop_of(&sim.rx(&failure(4))) {
        Some(Stop::Rejected { stage: RejectStage::Password, message: Some(m) }) => assert!(m.contains("费用")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn pppoe_waits_for_pppd_address_without_dhcp() {
    let mut e = env();
    e.net = NetInfo::default();
    let mut d = DrcomDriver::new(e, Credentials::default(), pppoe_opts()).unwrap();
    assert!(d.start(Instant::now()).is_empty());
    assert_eq!(d.state(), AuthState::WaitingIp);
}

#[test]
fn unsupported_and_invalid_configurations_are_refused() {
    for v in [Variant::GsD, Variant::GsX, Variant::GsP, Variant::GsPt] {
        let err = DrcomDriver::new(env(), creds(), Options { variant: v, ..dhcp_opts() }).err().unwrap();
        assert!(err.contains("暂不支持"), "{err}");
        assert!(err.contains("第30"), "{err}");
    }
    let err = DrcomDriver::new(env(), creds(), Options { dr_mode: 4, ..dhcp_opts() }).err().unwrap();
    assert!(err.contains("dr_mode"));
    assert!(DrcomDriver::new(env(), creds(), Options { server: Ipv4Addr::UNSPECIFIED, ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { auth_version: None, ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { keep_alive_version: None, ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { auth_version: Some("27".into()), ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { mac: Some("zz".into()), ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { host_name: "h".repeat(33), ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), creds(), Options { max_retries: 0, ..dhcp_opts() }).is_err());
    assert!(DrcomDriver::new(env(), Credentials::new("u".repeat(37), "p"), dhcp_opts()).is_err());
    assert!(DrcomDriver::new(env(), Credentials::new("", "p"), dhcp_opts()).is_err());
    assert!(DrcomDriver::new(
        env(),
        Credentials::new("u", "p".repeat(17)),
        Options { ror_version: true, ..dhcp_opts() }
    )
    .is_err());
    let mut e = env();
    e.mac = [0; 6];
    assert!(DrcomDriver::new(e.clone(), creds(), dhcp_opts()).is_err());
    assert!(DrcomDriver::new(e, creds(), Options { mac: Some("02:00:00:00:00:09".into()), ..dhcp_opts() }).is_ok());
    assert!(DrcomDriver::new(env(), creds(), Options { pppoe_flag: None, ..pppoe_opts() }).is_err());
}

#[test]
fn ror_profile_and_overrides_reach_the_login() {
    let opts = Options {
        ror_version: true,
        primary_dns: Some(Ipv4Addr::new(8, 8, 4, 4)),
        host_os_hex: Some("4472434f4d000f2702".into()),
        mac: Some("02:00:00:00:00:09".into()),
        ..dhcp_opts()
    };
    let mut sim = Sim::new(opts);
    one(&sim.start());
    sim.rx(&challenge_reply(SEED));
    let login = one(&sim.fire());
    assert_eq!(&login[142..146], &[8, 8, 4, 4]);
    assert_eq!(&login[182..191], b"DrCOM\x00\x0f\x27\x02");
    assert_eq!(&login[312..314], &[0x00, 6]);
    let c = 314 + 6;
    assert_eq!(&login[c..c + 2], &[0x02, 0x0c]);
    assert_eq!(&login[c + 8..c + 14], &[2, 0, 0, 0, 0, 9]);
    assert_eq!(login.len(), 338);
}

#[test]
fn options_deserialize_with_defaults() {
    // Serde wiring: a minimal TOML-like map through serde's value
    // deserializer is enough to exercise rename rules and defaults.
    use serde::de::value::{Error as DeError, MapDeserializer};
    use serde::de::IntoDeserializer;
    use serde::Deserialize;
    let map = vec![("mode", "pppoe"), ("variant", "gs-pt"), ("server", "10.0.0.1")];
    let opts = Options::deserialize(MapDeserializer::<_, DeError>::new(
        map.into_iter().map(|(k, v)| (k, v.into_deserializer())),
    ))
    .unwrap();
    assert_eq!(opts.mode, Mode::Pppoe);
    assert_eq!(opts.variant, Variant::GsPt);
    assert_eq!(opts.server, SERVER);
    assert_eq!(opts.server_port, 61440);
    assert_eq!(opts.timeout_secs, 3);
    assert!(opts.eternal);
}
