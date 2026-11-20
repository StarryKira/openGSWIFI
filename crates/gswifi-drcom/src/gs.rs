//! Codecs of the GS MentoHUST Dr.com branches (AuthType 3/4/5/6 = D/X/P/Pt,
//! DrMode 0..5), doc 30 (grade D: original functions run under QEMU with
//! synthetic inputs) and doc 23.3.
//!
//! These are pure building blocks. The [`crate::DrcomDriver`] does not run
//! the GS session itself because doc 30.3/30.8 state that its online phase
//! graph, the X EAP exchange and per-DrMode behaviour are not complete; the
//! driver refuses those variants instead (doc 09.1).
//!
//! The GS D login body is [`crate::packet::login`] with
//! [`crate::packet::LoginLayout::Gs`], verified against the doc 30.3 frames.

use crate::primitives::{check32, seedhash, xor16, FALLBACK_CRC};
use crate::Error;

/// MentoHUST `AuthType` values of the Dr.com family (doc 30.1, doc 01 §1.2).
pub const AUTH_D: u8 = 3;
pub const AUTH_X: u8 = 4;
pub const AUTH_P: u8 = 5;
pub const AUTH_PT: u8 = 6;

/// School profile names of `DrMode` 0..5 (doc 01 §1.2, doc 30.1). They are
/// UI labels, not verified school policies.
pub const DR_MODES: [&str; 6] = ["普通", "山东师范大学", "华南理工大学", "韶关学院", "长沙医学院", "星海音乐学院"];

// ---------------------------------------------------------------------------
// Control packets (doc 30.4)
// ---------------------------------------------------------------------------

/// 40-byte control1 (`0x420eec`, doc 30.4): `07 seq 28 00 0b 01`, version at
/// `[6:8]`, `[8]` = 16 if the version is `0f 27` else 19, `[9]` = 57, tail8 at
/// `[16:24]`. Returns the packet and the next sequence number.
pub fn control1(tail: [u8; 8], version: [u8; 2], sequence: u8) -> ([u8; 40], u8) {
    let mut b = [0u8; 40];
    b[..6].copy_from_slice(&[0x07, sequence, 40, 0, 0x0b, 0x01]);
    b[6..8].copy_from_slice(&version);
    b[8] = if version == [0x0f, 0x27] { 0x16 } else { 0x19 };
    b[9] = 0x57;
    b[16..24].copy_from_slice(&tail);
    (b, sequence.wrapping_add(1))
}

/// 40-byte control3 (`0x420fa4`, doc 30.4): header with `[5]` = 03, `[8]` = 19,
/// `[9]` = 57, `[16:24]` = received UDP body `[16:24]` (full frame `[58:66]`),
/// IPv4 at `[28:32]`. With `[24:28]` zero, the 20 LE16 words are XORed, the
/// result times 711 is written as a full LE32 at `[24:28]` (not truncated to
/// 16 bits like [`crate::primitives::check16`]).
pub fn control3(received_tail: [u8; 8], ip: [u8; 4], version: [u8; 2], sequence: u8) -> ([u8; 40], u8) {
    let mut b = [0u8; 40];
    b[..6].copy_from_slice(&[0x07, sequence, 40, 0, 0x0b, 0x03]);
    b[6..8].copy_from_slice(&version);
    b[8] = 0x19;
    b[9] = 0x57;
    b[16..24].copy_from_slice(&received_tail);
    b[28..32].copy_from_slice(&ip);
    let sum = (xor16(&b) as u32).wrapping_mul(711);
    b[24..28].copy_from_slice(&sum.to_le_bytes());
    (b, sequence.wrapping_add(1))
}

/// Default `address_hint` of control96 (doc 30.4).
pub const CONTROL96_ADDRESS_HINT: u32 = 0xffff_ffff;

/// 96-byte control (`0x4210bc`, doc 30.4). `derive_enabled` is received UDP
/// body `[5]` (full frame `[47]`), `seed` is body `[8:12]` (frame `[50:54]`).
///
/// Layout: `07 seq 60 00 03`, IPv4 `[12:16]`, `[17]` = 62, client version
/// `[19]`, seed `[20:24]`, `[39]` = 17, IPv4 `[40:44]`, LE32 address hint
/// `[44:48]`, `[54]` = 01. CRC: direct [`seedhash`] at `[24:32]`; when it does
/// not apply, `[24:32]` = [`FALLBACK_CRC`], [`check32`] of all 96 bytes goes
/// to `[24:28]` and `[28:32]` is cleared. Finally byte `32+i` is rotated left
/// by `i & 7` for i = 0..63 (checksum first, rotation after).
pub fn control96(
    derive_enabled: bool,
    seed: [u8; 4],
    ip: [u8; 4],
    sequence: u8,
    client_version: u8,
    address_hint: u32,
) -> ([u8; 96], u8) {
    let mut b = [0u8; 96];
    b[..5].copy_from_slice(&[0x07, sequence, 96, 0, 0x03]);
    b[12..16].copy_from_slice(&ip);
    b[17] = 0x62;
    b[19] = client_version;
    b[20..24].copy_from_slice(&seed);
    b[39] = 0x17;
    b[40..44].copy_from_slice(&ip);
    b[44..48].copy_from_slice(&address_hint.to_le_bytes());
    b[54] = 0x01;
    match seedhash(derive_enabled, seed) {
        Some(crc) => b[24..32].copy_from_slice(&crc),
        None => {
            b[24..32].copy_from_slice(&FALLBACK_CRC);
            // 96 is a multiple of 4: check32 cannot fail here.
            let sum = check32(&b).unwrap_or([0; 4]);
            b[24..28].copy_from_slice(&sum);
            b[28..32].copy_from_slice(&[0; 4]);
        }
    }
    for i in 0..64 {
        b[32 + i] = b[32 + i].rotate_left((i & 7) as u32);
    }
    (b, sequence.wrapping_add(1))
}

// ---------------------------------------------------------------------------
// Receive dispatch (doc 30.2)
// ---------------------------------------------------------------------------

/// What the GS receive branch does with a datagram (doc 30.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GsAction {
    /// Enter GS state N (1 start, 2 challenge answered, 4 online …).
    State(u8),
    /// Arm the control timer with N seconds.
    Timer(u32),
    /// Authentication-phase failure: failure/reconnect path (MaxFail).
    Reconnect,
}

/// Numeric receive dispatch of the GS Dr.com branches (doc 30.2). `body` is
/// the UDP payload; `state` the current GS state; `auth` 3..6; `mode` the
/// DrMode. Note the two layers: `body[4]` is the subtype of type 7 and only
/// subtype 11 carries the ACK opcode in `body[5]`.
pub fn receive(body: &[u8], state: u8, auth: u8, mode: u8) -> Result<Vec<GsAction>, Error> {
    if !(AUTH_D..=AUTH_PT).contains(&auth) {
        return Err(Error::Invalid(format!("AuthType {auth} is not a Dr.com branch")));
    }
    if body.len() < 6 {
        return Err(Error::Truncated { what: "GS Dr.com datagram", need: 6, got: body.len() });
    }
    use GsAction::*;
    let (typ, sub) = (body[0], body[4]);
    Ok(match typ {
        2 => vec![State(2)],
        4 => vec![State(4)],
        5 if state == 4 || state == 6 => vec![State(1)],
        5 => vec![Reconnect],
        7 => match sub {
            2 => vec![State(if state == 4 { 4 } else { 2 })],
            4 if state != 4 => vec![State(4)],
            4 if auth == AUTH_P => vec![Timer(10)],
            // doc 30.2: other profiles ignore 7/4 while online in this set.
            4 => vec![],
            6 => vec![State(4)],
            11 => match body[5] {
                6 => vec![Timer(1)],
                4 => vec![Timer(match auth {
                    AUTH_P => 10,
                    AUTH_X if mode == 2 => 12,
                    AUTH_X => 8,
                    _ => 20,
                })],
                2 => {
                    if body.len() < 8 {
                        return Err(Error::Truncated { what: "GS control ACK", need: 8, got: body.len() });
                    }
                    if body[6..8] != [0, 0] {
                        vec![State(4)]
                    } else {
                        vec![Timer(20)]
                    }
                }
                _ => vec![],
            },
            _ => vec![],
        },
        // doc 30.2: type 77 (0x4d) has prefix/length conditions that the
        // tested prefix did not trigger; unknown otherwise, ignored here.
        _ => vec![],
    })
}

// ---------------------------------------------------------------------------
// Failure codes (doc 30.7)
// ---------------------------------------------------------------------------

const ERROR_TEXTS: [&str; 23] = [
    "本帐号已在其他地方登录！",
    "服务器繁忙，请稍候重新登录",
    "帐号或密码错误，请检查后重新登录",
    "费用已超支，不能使用需要收费的网络资源",
    "本帐号的期限已到，不能使用",
    "未知的错误代码。",
    "本帐号只能在指定的IP地址使用！",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "本帐号只能在指定MAC地址使用！",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "未知的错误代码。",
    "用户数超过限制",
    "客户端认证失败 : ",
    "本帐号只能在指定的IP，或MAC地址使用！",
    "不能使用静态IP，请改为DHCP动态分配地址并重新登录。",
];

/// GS text of a failure code (doc 30.7, `evidence/session/dr-error-texts.json`).
/// Codes 6, 8–10 and 12–19 are "unknown" in GS too. Code 21 is followed by
/// a variable server text in GS whose offset is not documented.
pub fn error_text(code: u8) -> &'static str {
    match code {
        1..=23 => ERROR_TEXTS[code as usize - 1],
        _ => "未知的错误代码。",
    }
}

// ---------------------------------------------------------------------------
// DrAuthSvr.dll material (doc 30.5)
// ---------------------------------------------------------------------------

/// Whole-file fingerprint of `DrAuthSvr.dll` (`0x4208f4`, doc 30.5): lower hex
/// MD5 of the file followed by `%08x` of the XOR of all LE32 words of the
/// zero-padded file (no multiplier). 40 ASCII bytes, without the NUL.
pub fn dll_fingerprint(data: &[u8]) -> Result<[u8; 40], Error> {
    if data.is_empty() {
        return Err(Error::Invalid("empty DrAuthSvr.dll".into()));
    }
    let acc = data.chunks(4).fold(0u32, |acc, w| {
        let mut word = [0u8; 4];
        word[..w.len()].copy_from_slice(w);
        acc ^ u32::from_le_bytes(word)
    });
    let text = format!("{:x}{:08x}", md5::compute(data), acc);
    let mut out = [0u8; 40];
    out.copy_from_slice(text.as_bytes());
    Ok(out)
}

/// Client version from `DrAuthSvr.dll` (`0x420a54`, doc 30.5). A non-zero
/// `cache[2]` wins. Otherwise the first marker class present is used; within
/// it the last parsable number wins (C `%u`, low 8 bits). A marker without a
/// parsable number keeps 0, like the original "successful" return. Files
/// shorter than 24 bytes are rejected (the original underflows) and a file
/// without any marker is an error.
pub fn dll_version(data: &[u8], cache: [u8; 3]) -> Result<u8, Error> {
    if cache[2] != 0 {
        return Ok(cache[2]);
    }
    if data.len() < 24 {
        return Err(Error::Invalid("DrAuthSvr.dll shorter than 24 bytes".into()));
    }
    const MARKERS: [(&[u8], usize); 3] =
        [(b"%s%s%sBuild(k%d.%s)", 20), (b"%s%s%s(1x)Build(k%d.%s)", 24), (b"%s %s%s Build(k%d.%s)", 23)];
    for (marker, skip) in MARKERS {
        let mut found = false;
        let mut result = 0u8;
        let mut pos = 0;
        while let Some(off) = find(&data[pos..], marker) {
            found = true;
            let start = pos + off;
            let mut p = start + skip;
            if skip == 23 && data.get(p) == Some(&0) {
                p += 1;
            }
            if let Some(v) = parse_c_unsigned_low8(data.get(p..).unwrap_or(&[])) {
                result = v;
            }
            pos = start + marker.len();
        }
        if found {
            return Ok(result);
        }
    }
    Err(Error::Invalid("no GS-recognised client version marker in DrAuthSvr.dll".into()))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `%u` semantics reduced to the low 8 bits: optional whitespace, optional
/// sign, at least one digit.
fn parse_c_unsigned_low8(s: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let negative = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits = s[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let v = s[i..i + digits].iter().fold(0u8, |acc, d| acc.wrapping_mul(10).wrapping_add(d - b'0'));
    Some(if negative { v.wrapping_neg() } else { v })
}

/// DrMode 4 helper request (doc 30.6, VA `0x42f48c`): sent once over TCP to
/// the configured DNS address, port 9002. The driver API has no TCP action,
/// which is one reason DrMode 4 is refused.
pub const MODE4_HTTP_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nAccept-Encoding: identity\r\nConnection: close\r\nUser-Agent: Dr.COM Client\r\n\r\n";
/// TCP port of the DrMode 4 helper (doc 30.6).
pub const MODE4_HTTP_PORT: u16 = 9002;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        challenge_request, keepalive1, keepalive1_mod, keepalive1_mod_request, login, pppoe_challenge, LoginLayout,
        LoginParams, OsVersion, CHALLENGE_GS_LOGIN, CHALLENGE_GS_LOGOFF, KEEPALIVE1_GS_LEN,
    };

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    const IP: [u8; 4] = [192, 0, 2, 10];

    /// 40 original outputs of the three control encoders
    /// (`evidence/session/control-vectors.json`, harness inputs as in
    /// `reference/test_session.py`).
    #[test]
    fn control_packets_match_original_outputs() {
        let text = include_str!("../testdata/control.txt");
        let frame: Vec<u8> = (0..256).map(|i| ((i * 13 + 7) & 255) as u8).collect();
        let mut n = 0;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let num = |i: usize| p[i].parse::<u32>().unwrap();
            let (got, next, want, after) = if p[0] == "CTRL" {
                let (kind, special, seq, after) = (num(1), num(2), num(3), num(4));
                let version = if special == 1 { [15, 39] } else { [4, 10] };
                let seq = if seq == 1 { 255 } else { 0 };
                let (pkt, next) = if kind == 1 {
                    let tail: [u8; 8] = std::array::from_fn(|i| ((i * 17 + 3) & 255) as u8);
                    let (b, n) = control1(tail, version, seq);
                    (b.to_vec(), n)
                } else {
                    let (b, n) = control3(frame[58..66].try_into().unwrap(), IP, version, seq);
                    (b.to_vec(), n)
                };
                (pkt, next, p[5], after)
            } else {
                let (seq, flag, selector, after) = (num(2), num(3), num(4), num(5));
                let seed = [selector as u8, 0x91, 0x22, 0xe3];
                let seq = if seq == 1 { 255 } else { 0 };
                let (b, next) = control96(flag != 0, seed, IP, seq, 0x27, CONTROL96_ADDRESS_HINT);
                (b.to_vec(), next, p[6], after)
            };
            assert_eq!((hex(&got).as_str(), next as u32), (want, after), "{line}");
            n += 1;
        }
        assert_eq!(n, 40);
    }

    fn parse_actions(s: &str) -> Vec<GsAction> {
        if s == "-" {
            return vec![];
        }
        s.split(';')
            .map(|a| match a.split_once('=').unwrap() {
                ("state", v) => GsAction::State(v.parse().unwrap()),
                ("timer", v) => GsAction::Timer(v.parse().unwrap()),
                ("reconnect", _) => GsAction::Reconnect,
                other => panic!("{other:?}"),
            })
            .collect()
    }

    /// 496 original Dr receive dispatches (`receive-vectors.json` minus the
    /// 88 H3C cases): 240 type/subtype/state, 72 ACK, 184 failure codes.
    #[test]
    fn receive_dispatch_matches_original() {
        let text = include_str!("../testdata/receive.txt");
        let mut n = 0;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let (auth, mode, state) = (p[0].parse().unwrap(), p[1].parse().unwrap(), p[2].parse().unwrap());
            let got = receive(&unhex(p[3]), state, auth, mode).unwrap();
            assert_eq!(got, parse_actions(p[4]), "{line}");
            n += 1;
        }
        assert_eq!(n, 496);
    }

    #[test]
    fn receive_rejects_malformed() {
        assert!(receive(&[], 1, 3, 0).is_err());
        assert!(receive(&[7, 0, 0, 0, 11], 4, 3, 0).is_err());
        assert!(receive(&[7, 0, 0, 0, 11, 2], 4, 3, 0).is_err());
        assert!(receive(&[2; 6], 1, 2, 0).is_err());
        assert!(receive(&[2; 6], 1, 7, 0).is_err());
        assert_eq!(receive(&[7, 0, 0, 0, 11, 2, 0, 1], 4, 3, 0).unwrap(), vec![GsAction::State(4)]);
    }

    struct Case {
        auth: u8,
        mode: u8,
        logoff_frames: u32,
        events: Vec<(u8, u8, Vec<u32>, Vec<u8>)>,
        frames: Vec<(String, Vec<u8>)>,
    }

    fn session_cases() -> Vec<Case> {
        let mut cases: Vec<Case> = Vec::new();
        for line in include_str!("../testdata/session.txt").lines().filter(|l| !l.is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            match p[0] {
                "case" => cases.push(Case {
                    auth: p[1].parse().unwrap(),
                    mode: p[2].parse().unwrap(),
                    logoff_frames: p[3].trim_start_matches("logoff_frames=").parse().unwrap(),
                    events: vec![],
                    frames: vec![],
                }),
                "event" => {
                    let timers =
                        if p[3] == "-" { vec![] } else { p[3].split(',').map(|t| t.parse().unwrap()).collect() };
                    cases.last_mut().unwrap().events.push((
                        p[1].parse().unwrap(),
                        p[2].parse().unwrap(),
                        timers,
                        unhex(p[4]),
                    ));
                }
                "frame" => cases.last_mut().unwrap().frames.push((p[1].to_string(), unhex(p[2]))),
                other => panic!("{other}"),
            }
        }
        cases
    }

    /// 24 joined replays (doc 30.3, `dr-session-vectors.json`): the dispatch
    /// reproduces every recorded state change and dispatch-armed timer.
    #[test]
    fn joined_replays_state_traces() {
        let cases = session_cases();
        assert_eq!(cases.len(), 24);
        for c in &cases {
            for (before, after, timers, body) in &c.events {
                let actions = receive(body, *before, c.auth, c.mode).unwrap();
                let states: Vec<u8> =
                    actions.iter().filter_map(|a| if let GsAction::State(s) = a { Some(*s) } else { None }).collect();
                let armed: Vec<u32> =
                    actions.iter().filter_map(|a| if let GsAction::Timer(t) = a { Some(*t) } else { None }).collect();
                assert_eq!(*after, states.last().copied().unwrap_or(*before));
                if !armed.is_empty() {
                    assert_eq!(&armed, timers);
                }
            }
            // P logs off without a frame (doc 30.3).
            assert_eq!(c.logoff_frames, if c.auth == AUTH_P { 0 } else { 1 });
        }
    }

    fn frame<'a>(c: &'a Case, tag: &str) -> &'a [u8] {
        &c.frames.iter().find(|(t, _)| t == tag).unwrap_or_else(|| panic!("{tag}")).1
    }

    fn frames<'a>(c: &'a Case, tag: &str) -> Vec<&'a [u8]> {
        c.frames.iter().filter(|(t, _)| t == tag).map(|(_, b)| b.as_slice()).collect()
    }

    /// Every client datagram of the six D replays is rebuilt independently,
    /// including the 342-byte login body that doc 30.8 lists as lacking an
    /// independent codec. Synthetic configuration of the harness: user and
    /// password "synthetic", MAC 02:00:00:00:00:01, IP 192.0.2.10, client
    /// version 0x27 (client-check fixture), random 0x5678.
    #[test]
    fn gs_d_frames_rebuilt_byte_for_byte() {
        let random = [0x78, 0x56];
        for c in session_cases().iter().filter(|c| c.auth == AUTH_D) {
            let challenge_rx = &c.events[0].3;
            let success_rx = &c.events[1].3;
            let sub2_rx = &c.events[2].3;
            assert_eq!(frame(c, "start"), challenge_request(CHALLENGE_GS_LOGIN, random, 0x27));
            assert_eq!(frame(c, "logoff"), challenge_request(CHALLENGE_GS_LOGOFF, random, 0x27));

            let seed = crate::packet::parse_challenge_response(challenge_rx).unwrap();
            let l = login(
                &LoginParams {
                    username: b"synthetic",
                    password: b"synthetic",
                    seed,
                    mac: [2, 0, 0, 0, 0, 1],
                    host_ip: IP,
                    control_check_status: 0x20,
                    adapter_num: 0x01,
                    ip_dog: 0x01,
                    host_name: b"LAPTOP-PEVCLMV4",
                    primary_dns: [192, 0, 2, 20],
                    dhcp_server: [198, 51, 100, 53],
                    os: OsVersion::default(),
                    host_os: b"DrCOM\x00\x0f\x27\x02",
                    auth_version: [0x27, 0x00],
                    ror: true,
                },
                LoginLayout::Gs,
            )
            .unwrap();
            assert_eq!(hex(frame(c, "challenge")), hex(&l.body), "login body, mode {}", c.mode);
            // The Dogcom layout differs only in checksum1/checksum2/trailer.
            let d = login(
                &LoginParams {
                    username: b"synthetic",
                    password: b"synthetic",
                    seed,
                    mac: [2, 0, 0, 0, 0, 1],
                    host_ip: IP,
                    control_check_status: 0x20,
                    adapter_num: 0x01,
                    ip_dog: 0x01,
                    host_name: b"LAPTOP-PEVCLMV4",
                    primary_dns: [192, 0, 2, 20],
                    dhcp_server: [198, 51, 100, 53],
                    os: OsVersion::default(),
                    host_os: b"DrCOM\x00\x0f\x27\x02",
                    auth_version: [0x27, 0x00],
                    ror: true,
                },
                LoginLayout::Dogcom,
            )
            .unwrap();
            assert_eq!(d.body.len(), l.body.len());
            assert_eq!(&d.body[..97], &l.body[..97]);
            assert_eq!(&d.body[105..325], &l.body[105..325]);
            assert_eq!(&d.body[329..340], &l.body[329..340]);

            let auth_info: [u8; 16] = success_rx[23..39].try_into().unwrap();
            let control1_frame = frame(c, "online-tick3");
            let version = [sub2_rx[28], sub2_rx[29]];
            assert_eq!(control1_frame, control1([0; 8], version, 0).0);
            if c.mode == 4 {
                // DrMode 4 uses keepalive1_mod (doc 30.3 table: 50-byte frame).
                assert_eq!(frames(c, "success"), vec![&keepalive1_mod_request(1)[..]]);
                assert_eq!(frames(c, "online-tick2"), vec![&keepalive1_mod_request(2)[..]]);
                let seed2: [u8; 4] = sub2_rx[8..12].try_into().unwrap();
                assert_eq!(frame(c, "control2"), keepalive1_mod(seed2, &auth_info, random));
            } else {
                let k = keepalive1(&l.md5a, &auth_info, random, KEEPALIVE1_GS_LEN).unwrap();
                assert_eq!(frame(c, "success"), k.as_slice());
                assert_eq!(frame(c, "online-tick1"), k.as_slice());
                let (b, _) =
                    control96(sub2_rx[5] != 0, sub2_rx[8..12].try_into().unwrap(), IP, 1, 0x27, CONTROL96_ADDRESS_HINT);
                assert_eq!(frame(c, "control2"), b);
            }
        }
    }

    /// P and Pt replays: the 8-byte start, the control96 login (P) and the
    /// control1 keepalives are rebuilt. Not rebuilt: the 38-byte online tick
    /// (its MD5A slot holds a harness fixture) and the 244-byte Pt body
    /// (doc 30.8: no independent codec).
    #[test]
    fn gs_p_and_pt_frames_rebuilt() {
        for c in session_cases().iter().filter(|c| c.auth == AUTH_P || c.auth == AUTH_PT) {
            let rx = &c.events[0].3;
            let version = [rx[28], rx[29]];
            assert_eq!(frame(c, "start"), pppoe_challenge(1));
            assert_eq!(frame(c, "success"), control1([0; 8], [0, 0], 0).0);
            let (b, _) = control96(rx[5] != 0, rx[8..12].try_into().unwrap(), IP, 3, 0x27, CONTROL96_ADDRESS_HINT);
            assert_eq!(frame(c, "control2"), b);
            if c.auth == AUTH_P {
                let (b, _) = control96(rx[5] != 0, rx[8..12].try_into().unwrap(), IP, 2, 0x27, CONTROL96_ADDRESS_HINT);
                assert_eq!(frame(c, "challenge"), b);
                assert_eq!(frame(c, "online-tick2"), pppoe_challenge(4));
                assert_eq!(frame(c, "online-tick3"), control1([0; 8], version, 1).0);
            } else {
                assert_eq!(frame(c, "challenge").len(), 244);
                assert_eq!(frame(c, "online-tick2"), control1([0; 8], [0, 0], 1).0);
                assert_eq!(frame(c, "online-tick3"), control1([0; 8], version, 2).0);
            }
        }
    }

    /// 15 DLL fixtures (`dr-dll-vectors.json`): fingerprints and versions.
    #[test]
    fn dll_material_matches_original() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/dll");
        let mut n = 0;
        for line in include_str!("../testdata/dll.txt").lines().filter(|l| !l.is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let data = std::fs::read(dir.join(p[0])).unwrap();
            assert_eq!(std::str::from_utf8(&dll_fingerprint(&data).unwrap()).unwrap(), p[1], "{line}");
            match p[2] {
                "-" => {}
                "err" => assert!(dll_version(&data, [0; 3]).is_err(), "{line}"),
                v => assert_eq!(dll_version(&data, [0; 3]).unwrap(), v.parse::<u8>().unwrap(), "{line}"),
            }
            n += 1;
        }
        assert_eq!(n, 15);
        assert_eq!(dll_version(b"", [0, 0, 0x7f]).unwrap(), 127);
        assert!(dll_version(b"a", [0; 3]).is_err());
        assert!(dll_fingerprint(b"").is_err());
    }

    #[test]
    fn dll_version_edge_cases() {
        let mut f = vec![b'x'; 8];
        f.extend_from_slice(b"%s%s%sBuild(k%d.%s)");
        f.extend_from_slice(b"  ");
        f.extend_from_slice(b"-1 trailing");
        // Marker at 8 (19 bytes), number scan starts at 8+20 = 28: " -1 …".
        // Whitespace and the sign are accepted like %u; -1 wraps to 255.
        let v = dll_version(&f, [0; 3]).unwrap();
        assert_eq!(v, 255);
        // Marker without digits keeps 0 and still succeeds.
        let mut g = vec![b'x'; 8];
        g.extend_from_slice(b"%s%s%sBuild(k%d.%s)xxxxxxxx");
        assert_eq!(dll_version(&g, [0; 3]).unwrap(), 0);
    }

    #[test]
    fn error_texts_match_firmware() {
        let mut n = 0;
        for line in include_str!("../testdata/errors.txt").lines().filter(|l| !l.is_empty()) {
            let (code, text) = line.split_once(' ').unwrap();
            assert_eq!(error_text(code.parse().unwrap()), text);
            n += 1;
        }
        assert_eq!(n, 23);
        // Code 21 keeps its trailing space (a server text follows in GS).
        assert_eq!(error_text(21), "客户端认证失败 : ");
        assert_eq!(error_text(0), "未知的错误代码。");
        assert_eq!(error_text(200), "未知的错误代码。");
    }

    #[test]
    fn mode4_request_constant() {
        assert_eq!(MODE4_HTTP_REQUEST, include_bytes!("../testdata/dr-mode4-http.bin"));
        assert_eq!(MODE4_HTTP_REQUEST.len(), 91);
    }
}
