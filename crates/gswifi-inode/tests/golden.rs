//! Golden vectors from the research pack (see `testdata/README.md`): outputs
//! of the original GS functions run under QEMU on synthetic input.

use std::path::PathBuf;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gswifi_core::{Action, Credentials, Driver, Env, NetInfo};
use gswifi_eapol::frame::{eapol_header, CODE_REQUEST, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE, TYPE_EAP_PACKET};
use gswifi_eapol::Supplicant;
use gswifi_inode::dialect::eap_response;
use gswifi_inode::eap::{md5_value, raw_version_data};
use gswifi_inode::mixed::{double_xor, mixed, nonce_from_time_rand, raw_field, text_field, KEY_OLD, KEY_V3};
use gswifi_inode::password::{md5_challenge_xor, password_xor};
use gswifi_inode::vif::{crypt_block, decode_inode_p, decode_vif_file, decrypt_raw};
use gswifi_inode::{GsData, InodeDialect, InodeError, InodeMaterial, InodeOptions};
use serde_json::Value;

fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn json(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(name)).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{} missing in {}", key, v))
}

fn u(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or_else(|| panic!("{} missing in {}", key, v))
}

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];
const CHALLENGE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[test]
fn original_function_vectors() {
    let cases = json("algorithm-comparison-inode.json");
    let mut checked = 0;
    for c in cases.as_array().unwrap() {
        let alg = s(c, "algorithm");
        let out: Vec<u8> = match alg {
            "inode-xor" => {
                let n = u(&c["input"], "length") as usize;
                let data: Vec<u8> = (0..n).map(|j| (j * 13 + 7) as u8).collect();
                let key = [KEY_V3, KEY_OLD][u(&c["input"], "key") as usize];
                double_xor(&data, key).unwrap()
            }
            "inode-mixed" | "inode-text" | "inode-raw" => {
                let i = &c["input"];
                let q = nonce_from_time_rand(u(i, "time") as u32, u(i, "rand") as u32);
                let m = mixed(s(i, "cached_version").as_bytes(), q, s(i, "key").as_bytes()).unwrap();
                match alg {
                    "inode-mixed" => m.to_vec(),
                    "inode-text" => text_field(&m).to_vec(),
                    _ => raw_field(&m).to_vec(),
                }
            }
            "password" => md5_value(7, b"synthetic", &CHALLENGE, u(c, "mode") as u8).to_vec(),
            "xorpass" => md5_challenge_xor(&CHALLENGE, b"synthetic").to_vec(),
            "inode-pass-xor" => {
                let n = u(c, "password_length") as usize;
                let pw: Vec<u8> = (0..n).map(|j| 97 + (j % 26) as u8).collect();
                if c["passed_prefix_only"].as_bool() == Some(true) {
                    // Original output beyond 16 bytes is uninitialised heap memory.
                    assert!(password_xor(&CHALLENGE, &pw).is_err());
                    assert_eq!(
                        hex::encode(password_xor(&CHALLENGE, &pw[..16]).unwrap()),
                        s(c, "initialized_prefix_hex")
                    );
                    checked += 1;
                    continue;
                }
                password_xor(&CHALLENGE, &pw).unwrap().to_vec()
            }
            other => panic!("unexpected algorithm {}", other),
        };
        assert_eq!(hex::encode(out), s(c, "qemu_hex"), "{}", c);
        checked += 1;
    }
    assert_eq!(checked, 83);
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

fn frames(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendFrame(f) => Some(hex::encode(f)),
            _ => None,
        })
        .collect()
}

fn research_material(with_version: bool) -> InodeMaterial {
    InodeMaterial {
        version_cache: with_version.then(|| b"CH V5.20-0001".to_vec()),
        key: None,
        nonce: Some(nonce_from_time_rand(0x12345678, 0x10203)),
    }
}

fn supplicant(material: InodeMaterial, upload_ip: bool, upload_ver: bool) -> Supplicant<InodeDialect> {
    let opts = InodeOptions { upload_ip, upload_ver, ..InodeOptions::default() };
    let dialect = InodeDialect::with_material(material, &opts).unwrap();
    let net = NetInfo { ip: [192, 0, 2, 10], ..NetInfo::default() };
    let env = Env { interface: "eth0".into(), mac: LOCAL, net };
    Supplicant::new(dialect, env, Credentials::new("synthetic", "synthetic"), Default::default()).unwrap()
}

/// Drives the real 802.1X engine with the iNode dialect and compares every
/// client frame with the frame the original GS builder produced.
#[test]
fn engine_with_dialect_matches_original_frames() {
    let doc = json("frame-vectors-inode.json");
    let mut checked = 0;
    for case in doc["cases"].as_array().unwrap() {
        let id = s(case, "id");
        let (ip, ver, version) = match id {
            "auth-1-0" | "inode-flags-1-1" => (true, true, true),
            "inode-flags-0-0" => (false, false, true),
            "inode-flags-0-1" => (false, true, true),
            "inode-flags-1-0" => (true, false, true),
            "inode-no-vif" => (true, true, false),
            "inode-online" => continue,
            other => panic!("unexpected case {}", other),
        };
        let want = |tag: &str| {
            let f = case["frames"].as_array().unwrap().iter().find(|f| s(f, "tag") == tag).unwrap();
            s(f, "hex").to_string()
        };
        let mut sup = supplicant(research_material(version), ip, ver);
        let t = Instant::now();
        assert_eq!(frames(&sup.start(t)), vec![want("start")], "{}", id);
        assert_eq!(frames(&sup.on_frame(&request(7, EAP_TYPE_IDENTITY, &[]), t)), vec![want("identity")], "{}", id);
        let mut md5 = vec![16u8];
        md5.extend_from_slice(&CHALLENGE);
        assert_eq!(frames(&sup.on_frame(&request(7, EAP_TYPE_MD5_CHALLENGE, &md5), t)), vec![want("md5")], "{}", id);
        let success = hex::decode(want("success")).unwrap();
        assert!(frames(&sup.on_frame(&success, t)).is_empty(), "{}", id);
        assert_eq!(sup.state(), gswifi_core::AuthState::Online);
        // doc 25.5: the BF keepalive of the shared online entry is not reproduced.
        let later = t + std::time::Duration::from_secs(30);
        assert!(frames(&sup.on_timer(later)).is_empty());
        let a = sup.logoff(later);
        assert_eq!(frames(&a), vec![want("logoff")], "{}", id);
        checked += 4;
    }
    assert_eq!(checked, 24);
}

#[test]
fn online_responses_match_original_builders() {
    let doc = json("frame-vectors-inode.json");
    let case = doc["cases"].as_array().unwrap().iter().find(|c| s(c, "id") == "inode-online").unwrap();
    let want = |tag: &str| {
        let f = case["frames"].as_array().unwrap().iter().find(|f| s(f, "tag") == tag).unwrap();
        s(f, "hex").to_string()
    };
    let mut sup = supplicant(research_material(true), true, true);
    let t = Instant::now();
    sup.start(t);
    sup.on_frame(&request(7, EAP_TYPE_IDENTITY, &[]), t);
    let mut md5 = vec![16u8];
    md5.extend_from_slice(&CHALLENGE);
    sup.on_frame(&request(7, EAP_TYPE_MD5_CHALLENGE, &md5), t);
    sup.on_frame(&hex::decode("020000000001020000000002888e0100000403070004").unwrap(), t);
    assert_eq!(sup.state(), gswifi_core::AuthState::Online);
    assert_eq!(frames(&sup.on_frame(&request(7, EAP_TYPE_IDENTITY, &[]), t)), vec![want("online-id1")]);
    assert_eq!(frames(&sup.on_frame(&request(7, 20, &[]), t)), vec![want("online-id20")]);
    let m = research_material(true).mixed(nonce_from_time_rand(0x12345678, 0x10203)).unwrap();
    assert_eq!(hex::encode(eap_response(&SERVER, &LOCAL, 7, 2, &raw_version_data(&m))), want("type2-version"));
}

#[test]
fn vif_raw_blocks() {
    let cases = json("vif-raw-vectors.json");
    assert_eq!(cases.as_array().unwrap().len(), 16);
    for c in cases.as_array().unwrap() {
        let raw = STANDARD.decode(s(c, "input")).unwrap();
        assert_eq!(hex::encode(decrypt_raw(&raw).unwrap()), s(c, "raw_plaintext_hex"));
    }
}

#[test]
fn vif_original_wrapper() {
    let cases = json("vif-valid-vectors.json");
    assert_eq!(cases.as_array().unwrap().len(), 13);
    for c in cases.as_array().unwrap() {
        let mut out = decode_inode_p(s(c, "input").as_bytes()).unwrap();
        out.push(0);
        assert_eq!(hex::encode(&out), s(c, "original_output_with_nul_hex"));
        assert_eq!(out.len() as u64, u(c, "original_n"));
    }
}

#[test]
fn vif_file_to_upload_field() {
    let c = json("vif-file-vector.json");
    let cache = decode_vif_file(&std::fs::read(path("iNode.vif")).unwrap()).unwrap();
    assert_eq!(hex::encode(&cache), s(&c, "cache_hex"));
    let q = nonce_from_time_rand(u(&c, "time") as u32, u(&c, "rand") as u32);
    let m = mixed(&cache, q, s(&c, "key").as_bytes()).unwrap();
    assert_eq!(hex::encode(text_field(&m)), s(&c, "text_hex"));
    // The same through the options loader.
    let opts = InodeOptions { vif: Some(path("iNode.vif")), nonce: Some(q), ..InodeOptions::default() };
    let material = InodeMaterial::load(&opts).unwrap();
    assert_eq!(hex::encode(material.version_text(q).unwrap()), s(&c, "text_hex"));
}

#[test]
fn vif_bad_padding_rejected() {
    let cipher = crypt_block(*b"ABCDEF\x00\x80", true);
    assert_eq!(decode_inode_p(STANDARD.encode(cipher).as_bytes()), Err(InodeError::Padding));
    let cipher = crypt_block(*b"ABCDEF\x01\x02", true);
    assert_eq!(decode_inode_p(STANDARD.encode(cipher).as_bytes()), Err(InodeError::Padding));
    assert!(decode_vif_file(&[0u8; 255]).is_err());
}

#[test]
fn gs_data_original_reader() {
    let cases = json("inode-record-vectors.json");
    assert_eq!(cases.as_array().unwrap().len(), 18);
    for c in cases.as_array().unwrap() {
        let data = GsData::parse(&std::fs::read(path(s(c, "file"))).unwrap()).unwrap();
        let (id, off, len) = (u(c, "identifier") as u32, u(c, "offset") as u8, u(c, "length") as u8);
        if c["ret"].as_i64() == Some(0) {
            assert_eq!(hex::encode(data.read(id, off, len).unwrap()), s(c, "output_hex"), "{}", c);
        } else {
            assert_eq!(data.read(id, off, len), Err(InodeError::MissingRecord(id)));
        }
    }
}

/// Pseudo-random garbage must never panic the decoders or the dialect.
#[test]
fn garbage_never_panics() {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut sup = supplicant(research_material(true), true, true);
    let t = Instant::now();
    sup.start(t);
    for i in 0..3000 {
        let len = (next() % 600) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        let _ = decode_inode_p(&buf);
        let b64 = STANDARD.encode(&buf[..len.min(64)]);
        let _ = decode_inode_p(b64.as_bytes());
        let _ = decode_vif_file(&buf);
        let _ = gswifi_inode::vif::cache_from_plain(&buf);
        let _ = GsData::parse(&buf);
        let _ = mixed(&buf, next() as u32, KEY_OLD);
        if buf.len() >= 23 {
            buf[..6].copy_from_slice(&LOCAL);
            buf[6..12].copy_from_slice(&SERVER);
            buf[12..14].copy_from_slice(&[0x88, 0x8e]);
            buf[15] = (i % 3) as u8;
        }
        let _ = sup.on_frame(&buf, t);
    }
}
