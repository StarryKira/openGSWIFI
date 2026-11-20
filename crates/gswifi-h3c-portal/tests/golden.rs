//! Golden vectors from the research pack (see `testdata/README.md`): outputs
//! of the original GS functions and state builders under QEMU, synthetic
//! input.

use std::path::PathBuf;

use gswifi_h3c_portal::codec::block::block_transform;
use gswifi_h3c_portal::codec::check::check_result;
use gswifi_h3c_portal::codec::{self, parse_attributes, receive, seal, Login, Online, ReceiveAction};
use gswifi_inode::mixed::{mixed, nonce_from_time_rand, KEY_V3};
use gswifi_inode::GsData;
use serde_json::Value;

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn json(name: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path(name)).unwrap()).unwrap();
    v.as_array().unwrap().clone()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{} missing in {}", key, v))
}

const IP: [u8; 4] = [192, 0, 2, 10];
const SERIAL: [u8; 2] = [0x12, 0x34];
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn research_mixed() -> [u8; 20] {
    mixed(b"CH V5.20-0001", nonce_from_time_rand(0x12345678, 0x10203), KEY_V3).unwrap()
}

fn login(password: &[u8], plain: bool) -> Vec<u8> {
    let m = research_mixed();
    codec::login(&Login {
        user_ip: IP,
        serial: SERIAL,
        mac: MAC,
        username: b"synthetic",
        password,
        mixed_version: &m,
        stamp: 30,
        plain_password: plain,
    })
    .unwrap()
}

/// UDP payload of an Ethernet/IPv4 frame (IHL 5) and its ports.
struct Udp {
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

fn udp(frame_hex: &str) -> Option<Udp> {
    let f = hex::decode(frame_hex).unwrap();
    if f.len() < 42 || f[12..14] != [8, 0] {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([f[34], f[35]]),
        dst_port: u16::from_be_bytes([f[36], f[37]]),
        payload: f[42..].to_vec(),
    })
}

fn unsealed(mut body: Vec<u8>) -> Vec<u8> {
    body[16..32].fill(0);
    body
}

#[test]
fn original_builder_functions() {
    let mut checked = 0;
    for c in json("algorithm-comparison-h3c.json") {
        match s(&c, "algorithm") {
            "h3c-info" => {
                let body = codec::discovery(IP, SERIAL).unwrap();
                assert_eq!(hex::encode(unsealed(body.clone())), s(&c, "unsealed_hex"));
                assert_eq!(hex::encode(&body), s(&c, "sealed_hex"));
                let mut again = hex::decode(s(&c, "unsealed_hex")).unwrap();
                seal(&mut again).unwrap();
                assert_eq!(hex::encode(again), s(&c, "sealed_hex"));
            }
            "h3c-block" => {
                let input: Vec<u8> = (0..32).map(|j| (j * 17 + 3) as u8).collect();
                let key = [0x01234567, 0x89abcdef, 0x10213243, 0x54657687];
                let rounds = c["rounds"].as_u64().unwrap() as u32;
                let swap = c["swap_words"].as_bool().unwrap();
                assert_eq!(
                    hex::encode(block_transform(&input, &key, rounds, swap).unwrap()),
                    s(&c, "qemu_hex"),
                    "{}",
                    c
                );
            }
            "h3c-login" => {
                let plain = c["plain_password"].as_bool().unwrap();
                let body = login(b"password123", plain);
                assert_eq!(body.len() as u64, c["returned_length"].as_u64().unwrap());
                // The original vector is taken before sealing.
                assert_eq!(hex::encode(unsealed(body)), s(&c, "qemu_hex"));
            }
            other => panic!("unexpected {}", other),
        }
        checked += 1;
    }
    assert_eq!(checked, 11);
}

#[test]
fn five_check_families() {
    let data = GsData::parse(&std::fs::read(path("inode-gs.dat")).unwrap()).unwrap();
    let cases = json("h3c-check-vectors.json");
    assert_eq!(cases.len(), 45);
    let mut families = std::collections::BTreeSet::new();
    for c in &cases {
        let challenge = hex::decode(s(c, "challenge_hex")).unwrap();
        families.insert(c["family"].as_u64().unwrap());
        assert_eq!(hex::encode(check_result(&challenge, Some(&data)).unwrap()), s(c, "result_hex"), "{}", s(c, "log"));
    }
    assert_eq!(families.len(), 5);
}

#[test]
fn original_receive_dispatch() {
    let cases = json("receive-vectors-h3c.json");
    assert_eq!(cases.len(), 88);
    for c in &cases {
        let frame = hex::decode(s(c, "frame_hex")).unwrap();
        let state = c["state"].as_u64().unwrap() as u8;
        let got = receive(&frame[42..], state).unwrap();
        let want: Vec<ReceiveAction> = c["original_actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| match (a[0].as_str().unwrap(), &a[1]) {
                ("state", n) => ReceiveAction::State(n.as_u64().unwrap() as u8),
                ("timer", n) => ReceiveAction::Timer(n.as_u64().unwrap()),
                ("reconnect", _) => ReceiveAction::Reconnect,
                other => panic!("{:?}", other),
            })
            .collect();
        assert_eq!(got, want, "{}", s(c, "log"));
    }
}

/// The 30 single-state builder runs (6 Dr modes × GS states 0..4, the
/// mode does not affect H3C): 0 logoff, 1 discovery, 2 login,
/// 3 challenge response without 130, 4 keepalive without session.
#[test]
fn original_state_builders() {
    let cases = json("builder-vectors-h3c.json");
    assert_eq!(cases.len(), 30);
    for c in &cases {
        let state = c["state"].as_u64().unwrap();
        let frames: Vec<Udp> = c["frames"].as_array().unwrap().iter().filter_map(|f| udp(s(f, "hex"))).collect();
        assert_eq!(frames.len(), 1, "{}", s(c, "log"));
        let (want_port, body) = match state {
            0 => (56018, codec::logoff(IP, SERIAL, None).unwrap()),
            1 => (56018, codec::discovery(IP, SERIAL).unwrap()),
            2 => (58018, login(b"synthetic", false)),
            3 => (58018, codec::challenge_response(IP, SERIAL, None).unwrap()),
            4 => (60018, codec::online(IP, SERIAL, &Online { stamp: 30, ..Online::default() }).unwrap()),
            _ => unreachable!(),
        };
        assert_eq!(hex::encode(&frames[0].payload), hex::encode(body), "{}", s(c, "log"));
        assert_eq!((frames[0].src_port, frames[0].dst_port), (want_port, 50200));
        let timers: Vec<u64> = c["timers"].as_array().unwrap().iter().map(|t| t.as_u64().unwrap()).collect();
        assert_eq!(timers, vec![[0, 8, 8, 8, 10][state as usize]]);
    }
}

#[test]
fn session_payloads_codec_level() {
    let cases = json("h3c-session-vectors.json");
    let types: Vec<u64> = cases.iter().map(|c| c["type"].as_u64().unwrap()).collect();
    assert_eq!(types, [110, 111, 100, 121, 122, 101, 104, 104, 105, 104, 102]);
    let challenge: Vec<u8> = std::iter::once(b'1').chain(0..32).collect();
    let check = check_result(&challenge, None).unwrap();
    let session = [0x10, 0x20, 0x30, 0x40];
    for c in &cases {
        let u = udp(s(c, "frame_hex")).unwrap();
        let body = u.payload;
        if s(c, "direction") == "server" {
            // Server frames were sealed the same way; parse them strictly.
            assert!(codec::verify(&body));
            codec::parse_message(&body).unwrap();
            continue;
        }
        let want = match c["type"].as_u64().unwrap() {
            110 => codec::discovery(IP, SERIAL).unwrap(),
            100 => login(b"synthetic", false),
            122 => codec::challenge_response(IP, SERIAL, Some(&check)).unwrap(),
            104 => codec::online(
                IP,
                SERIAL,
                &Online { session: Some(&session), stamp: 30, check: Some(&check), ..Online::default() },
            )
            .unwrap(),
            102 => codec::logoff(IP, SERIAL, Some(&codec::logoff_session_value(&session, true))).unwrap(),
            other => panic!("{}", other),
        };
        assert_eq!(hex::encode(&body), hex::encode(want), "{}", s(c, "tag"));
    }
}

#[test]
fn auth_blob_echo() {
    let challenge: Vec<u8> = std::iter::once(b'1').chain(0..32).collect();
    let check = check_result(&challenge, None).unwrap();
    let cases = json("h3c-blob-vectors.json");
    assert_eq!(cases.len(), 3);
    for c in &cases {
        let body = udp(s(c, "frame_hex")).unwrap().payload;
        let attrs = parse_attributes(&body).unwrap();
        assert_eq!(hex::encode(codec::attribute(&attrs, 114).unwrap()), s(c, "expected_auth_blob_hex"));
        let blob = codec::auth_blob_value(b"ABC").unwrap();
        let want = codec::online(
            IP,
            SERIAL,
            &Online {
                auth_blob: Some(&blob),
                session: Some(&[0x10, 0x20, 0x30, 0x40]),
                stamp: 30,
                check: Some(&check),
            },
        )
        .unwrap();
        assert_eq!(hex::encode(body), hex::encode(want));
    }
}
