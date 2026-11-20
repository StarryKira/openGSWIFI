//! The credential transforms of the customised pppd (cleanroom/06 §3–5).
//! Pure functions of the username, the built-in material and the time.

/// Part of the username before the first `@` (`strcspn(user, "@")`).
fn local_part(username: &str) -> &[u8] {
    let bytes = username.as_bytes();
    &bytes[..bytes.iter().position(|&b| b == b'@').unwrap_or(bytes.len())]
}

/// Classic NetKeeper / 闪讯 PIN (getPIN, nk_version 1–13; cleanroom/06 §3,
/// D: 12 vectors). Returns the PPP username actually dialed:
/// `0d 0a | 6 time characters | 2 hex chars of MD5 | username` (the whole
/// username, domain included). `unix_time` is the server-corrected time;
/// the result changes every 5 seconds.
pub fn get_pin(username: &str, material: &str, unix_time: u64) -> Vec<u8> {
    let q = (unix_time / 5) as u32;
    let mut input = q.to_be_bytes().to_vec();
    input.extend_from_slice(local_part(username));
    input.extend_from_slice(material.as_bytes());
    let digest = md5::compute(&input).0;
    let hex = format!("{:02x}", digest[0]);

    // Bit transpose: b[j] collects bits j, j+4, …, j+28 of q, MSB first.
    let mut b = [0u8; 4];
    for (j, byte) in b.iter_mut().enumerate() {
        for k in 0..8 {
            *byte |= (((q >> (j + 4 * k)) & 1) as u8) << (7 - k);
        }
    }
    let x = [
        b[0] >> 2,
        ((b[0] << 4) & 48) | (b[1] >> 4),
        ((b[1] << 2) & 60) | (b[2] >> 6),
        b[2] & 63,
        b[3] >> 2,
        (b[3] << 4) & 48,
    ];
    let mut out = b"\r\n".to_vec();
    // Six-bit alphabet from 0x20 that skips '@' (not Base64).
    out.extend(x.iter().map(|&v| if v + 32 < 64 { v + 32 } else { v + 33 }));
    out.extend_from_slice(hex.as_bytes());
    out.extend_from_slice(username.as_bytes());
    out
}

/// Internal checksum helper of pppd (0x40abd0, cleanroom/06 §4): sum of
/// little-endian 16-bit words (an odd tail byte counts as a signed char),
/// folded once when the high half is set, complemented.
pub fn hash_key(buf: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for pair in buf.chunks_exact(2) {
        s = s.wrapping_add(u16::from_le_bytes([pair[0], pair[1]]) as u32);
    }
    if buf.len() % 2 == 1 {
        s = s.wrapping_add(buf[buf.len() - 1] as i8 as i32 as u32);
    }
    if s & 0xffff_0000 != 0 {
        s = (s.wrapping_add(s >> 16)) & 0xffff;
    }
    !(s as u16)
}

const HAINAN_ALPHABET: &[u8; 64] = b"abcdefghijklmnopqrstuvwxyz1234567890ZYXWVUTSRQPONMLKJIHGFEDCBA:_";

/// `strlen()` of the original: stop at the first NUL.
fn c_str(mut buf: Vec<u8>) -> Vec<u8> {
    if let Some(nul) = buf.iter().position(|&b| b == 0) {
        buf.truncate(nul);
    }
    buf
}

/// 海南 PIN (new_calc_pin, nk_version 14; cleanroom/06 §5, D: 12 vectors):
/// `~LL_` + 12 characters + `_` + username. Changes every second.
///
/// Both hash inputs are C strings: phase 1 stops at a zero byte of BE32(t),
/// and phase 2 at a zero byte of BE16(h1). The phase-2 truncation is
/// confirmed by the firmware sample with h1 = 0x5C00 (sim_fw.txt; the
/// "phase-2 变体" of gaps.md); for a zero high byte the input is empty by
/// the same rule, not yet seen in a sample.
pub fn hainan_pin(username: &str, unix_time: u64) -> String {
    let t = unix_time as u32;
    let mut raw = t.to_be_bytes().to_vec();
    raw.extend_from_slice(b"hngx01");
    raw.extend_from_slice(local_part(username));
    let h1 = hash_key(&c_str(raw));
    let mut phase2 = h1.to_be_bytes().to_vec();
    phase2.extend_from_slice(b"000c29270712");
    let h2 = hash_key(&c_str(phase2));
    let [t3, t2, t1, t0] = t.to_be_bytes();
    let [h1l, h1h] = h1.to_le_bytes();
    let [h2l, h2h] = h2.to_le_bytes();
    let buf = [t3, t2, h1l, h1h, t1, t0, h2l, h2h];
    let mut out = String::from("~LL_");
    for pair in buf.chunks_exact(2) {
        let (a, b) = (pair[0], pair[1]);
        for v in [a >> 3, ((a & 7) << 2) | (b >> 6), b & 0x3f] {
            out.push(HAINAN_ALPHABET[v as usize] as char);
        }
    }
    out.push('_');
    out.push_str(username);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!("../testdata/pppd_vectors.json")).unwrap()
    }

    #[test]
    fn get_pin_vectors() {
        let mut n = 0;
        for v in vectors().iter().filter(|v| v.get("pin").is_some()) {
            let got = get_pin(v["user"].as_str().unwrap(), v["material"].as_str().unwrap(), v["t"].as_u64().unwrap());
            assert_eq!(hex::encode(got), v["pin"].as_str().unwrap(), "{}", v);
            n += 1;
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn hainan_vectors() {
        let mut n = 0;
        for v in vectors().iter().filter(|v| v.get("hainan").is_some()) {
            let got = hainan_pin(v["user"].as_str().unwrap(), v["t"].as_u64().unwrap());
            assert_eq!(hex::encode(got), v["hainan"].as_str().unwrap(), "{}", v);
            n += 1;
        }
        assert_eq!(n, 5);
    }

    /// Harness calls of the original functions (sim_fw / sim_h2probe).
    #[test]
    fn firmware_probes() {
        let mut n = 0;
        for line in include_str!("../testdata/firmware-probe.txt").lines() {
            let quoted: Vec<&str> = line.split('\'').collect();
            let t =
                u64::from_str_radix(line.split_whitespace().nth(1).unwrap().trim_start_matches("t=0x"), 16).unwrap();
            let want = hex::decode(line.split_whitespace().last().unwrap()).unwrap();
            let got = if line.starts_with("getpin_t") {
                get_pin(quoted[1], quoted[3], t)
            } else {
                hainan_pin(quoted[1], t).into_bytes()
            };
            assert_eq!(got, want, "{}", line);
            n += 1;
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn get_pin_layout() {
        let pin = get_pin("student@zj", "singlenet01", 305419896);
        assert_eq!(&pin[..2], b"\r\n");
        assert!(pin[2..8].iter().all(|&c| (32..=96).contains(&c) && c != b'@'));
        assert!(pin[8..10].iter().all(u8::is_ascii_hexdigit));
        assert_eq!(&pin[10..], b"student@zj");
        // Same 5 second slot, same name; the next slot differs.
        assert_eq!(get_pin("u", "m", 1000), get_pin("u", "m", 1004));
        assert_ne!(get_pin("u", "m", 1000), get_pin("u", "m", 1005));
    }

    #[test]
    fn hash_key_cases() {
        assert_eq!(hash_key(&[]), 0xffff);
        assert_eq!(hash_key(&[1, 0]), !1);
        // Odd tail byte is a signed char: 0xff adds -1.
        assert_eq!(hash_key(&[2, 0, 0xff]), !1);
        // Carry folded once.
        assert_eq!(hash_key(&[0xff, 0xff, 0x02, 0x00]), !2u16);
    }

    /// The firmware sample whose h1 has a zero low byte (sim_fw.txt).
    #[test]
    fn hainan_phase2_stops_at_nul() {
        let pin = hainan_pin("2026310488@hubupt", 0x6aff9488);
        assert_eq!(pin, "~LL_nl_ab3ssiup__2026310488@hubupt");
        // h1 = 0x5C00, phase 2 hashes only 0x5c.
        assert_eq!(hash_key(&[0x5c]), 0xffa3);
    }
}
