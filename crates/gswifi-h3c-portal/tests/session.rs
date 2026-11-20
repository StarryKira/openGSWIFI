//! The driver against a scripted server replaying the doc 29 exchange.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use gswifi_core::{Action, AuthState, Credentials, Datagram, Driver, Env, NetInfo, RejectStage, Stop};
use gswifi_h3c_portal::codec::{self, check::check_result};
use gswifi_h3c_portal::{H3cPortalDriver, Options};
use gswifi_inode::mixed::nonce_from_time_rand;
use gswifi_inode::InodeOptions;
use serde_json::Value;

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
const SERVER: SocketAddrV4 = SocketAddrV4::new(SERVER_IP, 50200);
const IP: [u8; 4] = [192, 0, 2, 10];
const SERIAL: [u8; 2] = [0x12, 0x34];
const P56: u16 = 56018;
const P58: u16 = 58018;
const P60: u16 = 60018;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn options() -> Options {
    Options {
        portal_ip: SERVER_IP,
        serial: Some(0x1234),
        logoff_session_quirk: true,
        inode: InodeOptions {
            version_cache: Some("CH V5.20-0001".into()),
            nonce: Some(nonce_from_time_rand(0x12345678, 0x10203)),
            data_file: Some(testdata("inode-gs.dat")),
            ..InodeOptions::default()
        },
        ..Options::default()
    }
}

fn env() -> Env {
    Env {
        interface: "eth0".into(),
        mac: [2, 0, 0, 0, 0, 1],
        net: NetInfo { ip: IP, dns: [198, 51, 100, 53], ..NetInfo::default() },
    }
}

fn driver(opts: Options) -> H3cPortalDriver {
    H3cPortalDriver::new(env(), Credentials::new("synthetic", "synthetic"), opts).unwrap()
}

/// (client source port, UDP payload) of every recorded frame.
fn session_vectors(name: &str) -> Vec<(String, u16, Vec<u8>)> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(testdata(name)).unwrap()).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let f = hex::decode(c["frame_hex"].as_str().unwrap()).unwrap();
            let tag = c["tag"].as_str().unwrap_or("blob").to_string();
            (tag, u16::from_be_bytes([f[34], f[35]]), f[42..].to_vec())
        })
        .collect()
}

fn sent(actions: &[Action]) -> Vec<(u16, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendUdp { local_port, to, payload } => {
                assert_eq!(*to, SERVER);
                Some((*local_port, payload.clone()))
            }
            _ => None,
        })
        .collect()
}

fn rx(d: &mut H3cPortalDriver, port: u16, payload: &[u8], now: Instant) -> Vec<Action> {
    d.on_datagram(Datagram { local_port: port, from: SERVER, payload }, now)
}

/// A server message as the synthetic research server built them.
fn server(kind: u8, attrs: &[(u8, &[u8])]) -> Vec<u8> {
    codec::packet(kind, SERIAL, [0; 4], attrs).unwrap()
}

fn login_to_challenge(d: &mut H3cPortalDriver, t: Instant) {
    d.start(t);
    rx(d, P56, &server(111, &[]), t);
    let mut ch = vec![b'1'];
    ch.extend(0..32u8);
    rx(d, P58, &server(121, &[(130, &ch)]), t);
}

fn login_online(d: &mut H3cPortalDriver, t: Instant) {
    login_to_challenge(d, t);
    let a = rx(d, P58, &server(101, &[(100, &[0x10, 0x20, 0x30, 0x40])]), t);
    assert_eq!(sent(&a).len(), 1);
    assert_eq!(d.state(), AuthState::Online);
}

#[test]
fn replays_doc29_exchange_byte_for_byte() {
    let v = session_vectors("h3c-session-vectors.json");
    let mut d = driver(options());
    assert_eq!(d.requirements().udp_ports, vec![P56, P58, P60]);
    assert!(d.requirements().needs_ipv4);
    let t0 = Instant::now();

    // TX110 discovery.
    assert_eq!(sent(&d.start(t0)), vec![(v[0].1, v[0].2.clone())]);
    assert_eq!(d.state(), AuthState::Discovering);
    assert_eq!(d.next_deadline(), Some(t0 + Duration::from_secs(8)));
    // Our fake server reproduces the recorded server payloads exactly.
    assert_eq!(server(111, &[]), v[1].2);
    // RX111 → TX100.
    assert_eq!(sent(&rx(&mut d, P56, &v[1].2, t0)), vec![(v[2].1, v[2].2.clone())]);
    assert_eq!(d.state(), AuthState::Authenticating);
    // RX121 (130 = '1' + 00..1f) → TX122 with 131.
    assert_eq!(sent(&rx(&mut d, P58, &v[3].2, t0)), vec![(v[4].1, v[4].2.clone())]);
    // RX101 with 100 → online, TX104 immediately.
    assert_eq!(sent(&rx(&mut d, P58, &v[5].2, t0)), vec![(v[6].1, v[6].2.clone())]);
    assert_eq!(d.state(), AuthState::Online);
    assert_eq!(d.next_deadline(), Some(t0 + Duration::from_secs(10)));
    // Timer → TX104.
    let t1 = t0 + Duration::from_secs(10);
    assert!(d.on_timer(t1 - Duration::from_millis(1)).is_empty());
    assert_eq!(sent(&d.on_timer(t1)), vec![(v[7].1, v[7].2.clone())]);
    // RX105 with 109 = 30000 ms: the next keepalive in 30 s, then 10 s again.
    let t2 = t1 + Duration::from_secs(2);
    assert!(rx(&mut d, P60, &v[8].2, t2).is_empty());
    assert_eq!(d.next_deadline(), Some(t2 + Duration::from_secs(30)));
    let t3 = t2 + Duration::from_secs(30);
    assert_eq!(sent(&d.on_timer(t3)), vec![(v[9].1, v[9].2.clone())]);
    assert_eq!(d.next_deadline(), Some(t3 + Duration::from_secs(10)));
    // Logoff → TX102 (with the GS length quirk enabled) and stop.
    let a = d.logoff(t3);
    assert_eq!(sent(&a), vec![(v[10].1, v[10].2.clone())]);
    assert_eq!(a.last(), Some(&Action::Stop(Stop::Finished)));
    assert_eq!(d.state(), AuthState::Stopped);
    assert_eq!(d.next_deadline(), None);
    assert!(d.logoff(t3).is_empty());
}

#[test]
fn echoes_auth_blob_like_gs() {
    let v = session_vectors("h3c-blob-vectors.json");
    let mut d = driver(options());
    let t = Instant::now();
    login_to_challenge(&mut d, t);
    let a = rx(&mut d, P58, &server(101, &[(100, &[0x10, 0x20, 0x30, 0x40]), (114, b"ABC")]), t);
    assert_eq!(sent(&a), vec![(v[0].1, v[0].2.clone())]);
    for (i, step) in [10u64, 20].iter().enumerate() {
        assert_eq!(sent(&d.on_timer(t + Duration::from_secs(*step))), vec![(v[i + 1].1, v[i + 1].2.clone())]);
    }
}

#[test]
fn resend_schedule_matches_doc29_4() {
    let v = session_vectors("h3c-session-vectors.json");
    let mut d = driver(options());
    let t0 = Instant::now();
    let s = |secs: u64| t0 + Duration::from_secs(secs);
    assert_eq!(sent(&d.start(t0)).len(), 1);
    // count 1: the cached 110 again.
    assert_eq!(sent(&d.on_timer(s(8))), vec![(P56, v[0].2.clone())]);
    // count 2: straight to the login even without 111.
    assert_eq!(sent(&d.on_timer(s(16))), vec![(P58, v[2].2.clone())]);
    // Login count 1..4 resend, count 5 restart wait 15 s.
    for i in 1..=4 {
        assert_eq!(sent(&d.on_timer(s(16 + 8 * i))), vec![(P58, v[2].2.clone())]);
    }
    assert!(d.on_timer(s(56)).is_empty());
    assert_eq!(d.state(), AuthState::Backoff);
    assert_eq!(d.next_deadline(), Some(s(71)));
    assert_eq!(sent(&d.on_timer(s(71))), vec![(P56, v[0].2.clone())]);

    // Challenge stage without 130: 122 without 131 (GS state 3 builder),
    // built once and resent four times.
    let t = s(100);
    rx(&mut d, P56, &server(111, &[]), t);
    let a = sent(&rx(&mut d, P58, &server(121, &[]), t));
    assert_eq!(a, vec![(P58, codec::challenge_response(IP, SERIAL, None).unwrap())]);
    for i in 1..=4u64 {
        assert_eq!(sent(&d.on_timer(t + Duration::from_secs(8 * i))), a);
    }
    assert!(d.on_timer(t + Duration::from_secs(40)).is_empty());
    assert_eq!(d.state(), AuthState::Backoff);
}

#[test]
fn refusal_is_a_failed_round_by_default() {
    let mut d = driver(options());
    let t = Instant::now();
    login_to_challenge(&mut d, t);
    let a = rx(&mut d, P58, &server(101, &[(115, b"synthetic-error")]), t);
    assert!(a.is_empty(), "{a:?}");
    assert_eq!(d.state(), AuthState::Backoff);
    assert!(d.next_deadline().is_some());
}

#[test]
fn refusal_stops_when_configured() {
    for (stage_setup, stage) in [(false, RejectStage::Identity), (true, RejectStage::Password)] {
        let mut d = driver(Options { stop_on_reject: true, ..options() });
        let t = Instant::now();
        if stage_setup {
            login_to_challenge(&mut d, t);
        } else {
            d.start(t);
            rx(&mut d, P56, &server(111, &[]), t);
        }
        let a = rx(&mut d, P58, &server(101, &[(115, b"synthetic-error")]), t);
        assert_eq!(a, vec![Action::Stop(Stop::Rejected { stage, message: Some("synthetic-error".into()) })]);
        assert_eq!(d.state(), AuthState::Stopped);
        assert_eq!(d.next_deadline(), None);
        assert!(rx(&mut d, P58, &server(111, &[]), t).is_empty());
        assert!(d.on_timer(t + Duration::from_secs(100)).is_empty());
    }
}

#[test]
fn drop_while_online_rediscovers() {
    let mut d = driver(options());
    let t = Instant::now();
    login_online(&mut d, t);
    let a = rx(&mut d, P60, &server(101, &[]), t);
    assert_eq!(sent(&a), vec![(P56, codec::discovery(IP, SERIAL).unwrap())]);
    assert_eq!(d.state(), AuthState::Discovering);
}

#[test]
fn unknown_wrong_source_and_malformed_are_ignored() {
    let mut d = driver(options());
    let t = Instant::now();
    login_online(&mut d, t);
    let deadline = d.next_deadline();
    for kind in [100u8, 102, 103, 104, 106, 110, 112, 120, 122, 123, 200] {
        assert!(rx(&mut d, P60, &server(kind, &[]), t).is_empty(), "type {}", kind);
    }
    // 111/121 have no meaning online.
    assert!(rx(&mut d, P60, &server(111, &[]), t).is_empty());
    assert!(rx(&mut d, P60, &server(121, &[]), t).is_empty());
    let good = server(101, &[]);
    let other = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 99), 50200);
    assert!(d.on_datagram(Datagram { local_port: P60, from: other, payload: &good }, t).is_empty());
    let port = SocketAddrV4::new(SERVER_IP, 50201);
    assert!(d.on_datagram(Datagram { local_port: P60, from: port, payload: &good }, t).is_empty());
    assert!(rx(&mut d, 12345, &good, t).is_empty());
    let mut v1 = good.clone();
    v1[0] = 1;
    let mut trailing = good.clone();
    trailing.push(0);
    let mut bad_len = server(101, &[(115, b"x")]);
    bad_len[33] = 1;
    for bad in [&good[..31], &v1[..], &trailing[..], &bad_len[..], &[][..]] {
        assert!(rx(&mut d, P60, bad, t).is_empty());
    }
    assert_eq!(d.state(), AuthState::Online);
    assert_eq!(d.next_deadline(), deadline);
}

#[test]
fn give_up_after_max_fail() {
    let mut d = driver(Options { max_fail: 1, ..options() });
    let t0 = Instant::now();
    d.start(t0);
    let mut last = Vec::new();
    for secs in (8..=56).step_by(8) {
        last = d.on_timer(t0 + Duration::from_secs(secs));
    }
    assert_eq!(last, vec![Action::Stop(Stop::ServerNotFound)]);

    let mut d = driver(Options { max_fail: 1, ..options() });
    d.start(t0);
    rx(&mut d, P56, &server(111, &[]), t0);
    rx(&mut d, P58, &server(121, &[]), t0);
    let mut last = Vec::new();
    for secs in (8..=40).step_by(8) {
        last = d.on_timer(t0 + Duration::from_secs(secs));
    }
    assert_eq!(last, vec![Action::Stop(Stop::GaveUp { rounds: 1 })]);
}

#[test]
fn online_ack_timer_and_new_challenge() {
    let mut d = driver(options());
    let t = Instant::now();
    login_online(&mut d, t);
    let before = d.next_deadline();
    // 105 without 109: the schedule stays by default.
    assert!(rx(&mut d, P60, &server(105, &[]), t).is_empty());
    assert_eq!(d.next_deadline(), before);
    // A new 130 (family 3) changes the 131 of the next keepalive.
    let ch: Vec<u8> = std::iter::once(b'3').chain(100..132u8).collect();
    rx(&mut d, P60, &server(105, &[(130, &ch)]), t);
    let a = sent(&d.on_timer(before.unwrap()));
    let attrs = codec::parse_attributes(&a[0].1).unwrap();
    assert_eq!(codec::attribute(&attrs, 131), Some(&check_result(&ch, None).unwrap()[..]));
    // A challenge that cannot be computed drops 131 instead of inventing one.
    rx(&mut d, P60, &server(105, &[(130, &[0x10, 0x20, 0x30, 0x40])]), t);
    let a = sent(&d.on_timer(d.next_deadline().unwrap()));
    assert_eq!(codec::attribute(&codec::parse_attributes(&a[0].1).unwrap(), 131), None);

    // Opt-in GS behaviour: zero timer stops the keepalive.
    let mut d = driver(Options { zero_timer_stops_heartbeat: true, ..options() });
    login_online(&mut d, t);
    rx(&mut d, P60, &server(105, &[(109, &[0; 8])]), t);
    assert_eq!(d.next_deadline(), None);
    assert_eq!(d.state(), AuthState::Online);
}

#[test]
fn address_changes() {
    let mut e = env();
    e.net.ip = [0; 4];
    let mut d = H3cPortalDriver::new(e, Credentials::new("synthetic", "synthetic"), options()).unwrap();
    let t = Instant::now();
    assert!(d.start(t).is_empty());
    assert_eq!(d.state(), AuthState::WaitingIp);
    assert_eq!(d.next_deadline(), None);
    let a = d.on_net_change(env().net, t);
    assert_eq!(sent(&a), vec![(P56, codec::discovery(IP, SERIAL).unwrap())]);

    let mut d = driver(options());
    login_online(&mut d, t);
    let new_ip = [192, 0, 2, 77];
    let a = d.on_net_change(NetInfo { ip: new_ip, ..env().net }, t);
    assert_eq!(sent(&a), vec![(P56, codec::discovery(new_ip, SERIAL).unwrap())]);
    let a = d.on_net_change(NetInfo::default(), t);
    assert!(a.is_empty());
    assert_eq!(d.state(), AuthState::WaitingIp);
}

#[test]
fn portal_ip_defaults_to_dns() {
    let mut d = driver(Options { portal_ip: Ipv4Addr::UNSPECIFIED, ..options() });
    let a = d.start(Instant::now());
    match &a[..] {
        [Action::SendUdp { to, .. }] => assert_eq!(*to, SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 53), 50200)),
        other => panic!("{:?}", other),
    }
    let mut e = env();
    e.net.dns = [0; 4];
    let mut d =
        H3cPortalDriver::new(e, Credentials::new("u", "p"), Options { portal_ip: Ipv4Addr::UNSPECIFIED, ..options() })
            .unwrap();
    assert!(matches!(&d.start(Instant::now())[..], [Action::Stop(Stop::Fatal(_))]));
}

#[test]
fn verify_authenticator_option() {
    let mut d = driver(Options { verify_authenticator: true, ..options() });
    let t = Instant::now();
    d.start(t);
    let mut unsealed = server(111, &[]);
    unsealed[16..32].fill(0);
    assert!(rx(&mut d, P56, &unsealed, t).is_empty());
    assert_eq!(sent(&rx(&mut d, P56, &server(111, &[]), t)).len(), 1);
}

#[test]
fn constructor_validation() {
    let c = || Credentials::new("synthetic", "synthetic");
    let no_version = Options {
        inode: InodeOptions {
            vif: Some("/nonexistent/iNode.vif".into()),
            data_file: Some(testdata("inode-gs.dat")),
            ..InodeOptions::default()
        },
        ..options()
    };
    assert!(H3cPortalDriver::new(env(), c(), no_version).is_err());
    assert!(H3cPortalDriver::new(env(), Credentials::new("u", "p".repeat(32)), options()).is_err());
    assert!(H3cPortalDriver::new(env(), Credentials::new("", "p"), options()).is_err());
    assert!(H3cPortalDriver::new(env(), c(), Options { local_ports: Some([1, 1, 2]), ..options() }).is_err());
    assert!(H3cPortalDriver::new(env(), c(), Options { timeout: 0, ..options() }).is_err());
    let d = H3cPortalDriver::new(env(), c(), Options { serial: None, ..options() }).unwrap();
    assert!(d.ports().iter().all(|p| (56000..61024).contains(p)));
}

#[test]
fn options_deserialize_with_defaults() {
    let o: Options =
        serde_json::from_str(r#"{"portal_ip":"192.0.2.20","plain_password":true,"inode":{"version":"V5.20-0001C"}}"#)
            .unwrap();
    assert_eq!(o.portal_ip, SERVER_IP);
    assert!(o.plain_password);
    assert_eq!(o.server_port, 50200);
    assert_eq!(o.inode.version.as_deref(), Some("V5.20-0001C"));
    assert!(o.inode.upload_ip);
}

/// Pseudo-random garbage must never panic the codec or the driver.
#[test]
fn garbage_never_panics() {
    let mut d = driver(options());
    let t = Instant::now();
    login_online(&mut d, t);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..3000 {
        let len = (next() % 120) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if i % 2 == 0 && buf.len() >= 32 {
            buf[0] = 2;
            buf[1] = [101, 105, 111, 121][i % 4];
            buf[15] = (next() % 4) as u8;
        }
        let _ = codec::parse_message(&buf);
        let _ = check_result(&buf, None);
        let _ = rx(&mut d, [P56, P58, P60][i % 3], &buf, t);
    }
}
