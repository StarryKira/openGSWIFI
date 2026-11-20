//! Ruijie UDP heartbeat (research doc 20.4–20.6, 25.2). The payload and the
//! parameter parsing are verified against the original functions, but the
//! long-term scheduling has not been seen on a real network, so the feature
//! is off unless asked for.

use super::check::udp;
use gswifi_eapol::frame::{CODE_REQUEST, CODE_SUCCESS, EAP_TYPE_MD5_CHALLENGE};
use log::{debug, warn};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};

const ATTR_INTERVAL: u8 = 0x59;
const ATTR_DST_PORT: u8 = 0x5a;
const ATTR_SERVER: u8 = 0x5b;
const ATTR_KEY: u8 = 0x5c;
const ATTR_IV: u8 = 0x5d;
const ATTR_COUNTER: u8 = 0x5e;
const ATTR_SRC_PORT: u8 = 0x6e;

/// Prefix of every attribute in a Success frame.
const SUCCESS_ATTR_PREFIX: [u8; 4] = [0x00, 0x00, 0x13, 0x11];

/// The server frames that can carry the UDP parameters. Their attribute
/// layouts differ, and neither is the `1a | len` wrapper the client uses in
/// its own extension (doc 25.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// MD5 Request with a 16 byte challenge (parser 0x40c9d4): attributes
    /// `type | len | value` from frame offset 40, `len` excludes the header.
    Challenge,
    /// EAP Success (parser 0x40cb18): attributes
    /// `00 00 13 11 | type | inner_len | value` from `BE16(frame[26..28]) + 166`,
    /// `inner_len` includes its own two bytes.
    Success,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UdpParams {
    pub server: SocketAddrV4,
    pub src_port: u16,
    pub key: [u8; 8],
    pub iv: [u8; 8],
    pub counter: u64,
    pub interval: u32,
}

/// Attributes of one server frame; the first occurrence of a type wins.
/// Every read stays inside the EAPOL body (`18 + BE16(frame[16..18])`); the
/// original parsers did not check this.
fn frame_attributes(frame: &[u8], source: Source) -> Result<BTreeMap<u8, &[u8]>, &'static str> {
    if frame.len() < 40 || frame[12..14] != [0x88, 0x8e] {
        return Err("不是完整的 EAPOL 帧");
    }
    let end = 18 + u16::from_be_bytes([frame[16], frame[17]]) as usize;
    if end > frame.len() {
        return Err("EAPOL 长度超出帧");
    }
    let (mut pos, header) = match source {
        Source::Challenge => {
            if frame[18] != CODE_REQUEST || frame[22..24] != [EAP_TYPE_MD5_CHALLENGE, 16] {
                return Err("不是带 16 字节挑战的 MD5 请求");
            }
            (40, 2)
        }
        Source::Success => {
            if frame[18] != CODE_SUCCESS {
                return Err("不是 EAP-Success");
            }
            (166 + u16::from_be_bytes([frame[26], frame[27]]) as usize, 6)
        }
    };
    let mut attrs = BTreeMap::new();
    while pos < end {
        if pos + header > end {
            return Err("属性头被截断");
        }
        let (typ, len) = match source {
            Source::Challenge => (frame[pos], frame[pos + 1] as usize),
            Source::Success => {
                if frame[pos..pos + 4] != SUCCESS_ATTR_PREFIX {
                    return Err("属性头不是 00 00 13 11");
                }
                let inner = frame[pos + 5] as usize;
                if inner < 2 {
                    return Err("属性长度小于 2");
                }
                (frame[pos + 4], inner - 2)
            }
        };
        let start = pos + header;
        if start + len > end {
            return Err("属性值被截断");
        }
        attrs.entry(typ).or_insert(&frame[start..start + len]);
        pos = start + len;
    }
    Ok(attrs)
}

/// UDP parameters carried by a Challenge or Success frame. `Ok(None)` when
/// any of the six required attributes is missing: the server does not want
/// the UDP heartbeat. The whole set is checked before anything is used.
pub fn parse_frame(frame: &[u8], source: Source) -> Result<Option<UdpParams>, &'static str> {
    const REQUIRED: [(u8, usize); 6] =
        [(ATTR_SERVER, 4), (ATTR_DST_PORT, 4), (ATTR_SRC_PORT, 4), (ATTR_KEY, 8), (ATTR_IV, 8), (ATTR_COUNTER, 8)];
    let attrs = frame_attributes(frame, source)?;
    if REQUIRED.iter().any(|(t, _)| !attrs.contains_key(t)) {
        return Ok(None);
    }
    if REQUIRED.iter().any(|(t, n)| attrs[t].len() != *n) || attrs.get(&ATTR_INTERVAL).is_some_and(|v| v.len() != 4) {
        return Err("属性长度不对");
    }
    let be32 = |t: u8| u32::from_be_bytes(attrs[&t].try_into().unwrap());
    let arr8 = |t: u8| -> [u8; 8] { attrs[&t].try_into().unwrap() };
    let ip = attrs[&ATTR_SERVER];
    // Zero would stop the original timer; fall back to the default instead.
    let interval = match attrs.get(&ATTR_INTERVAL) {
        Some(_) if be32(ATTR_INTERVAL) > 0 => be32(ATTR_INTERVAL),
        _ => udp::DEFAULT_INTERVAL_SECS,
    };
    Ok(Some(UdpParams {
        // Ports are BE32 values of which the low 16 bits are used.
        server: SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), be32(ATTR_DST_PORT) as u16),
        src_port: be32(ATTR_SRC_PORT) as u16,
        key: udp::decrypt_attribute(&arr8(ATTR_KEY)),
        iv: udp::decrypt_attribute(&arr8(ATTR_IV)),
        // Network order 64 bit, confirmed on the original parser.
        counter: u64::from_be_bytes(arr8(ATTR_COUNTER)),
        interval,
    }))
}

/// Payload generator of the UDP heartbeat. The driver owns the timer; the
/// runtime owns the socket (bound to `src_port`, doc 20.5).
pub struct UdpHeartbeat {
    params: UdpParams,
    seq: u32,
    username: Vec<u8>,
    ip: [u8; 4],
    mac: [u8; 6],
    /// Version `major*100+minor` selecting the material table.
    version: u32,
    challenge: [u8; 16],
}

impl UdpHeartbeat {
    pub fn new(
        params: UdpParams,
        username: &[u8],
        ip: [u8; 4],
        mac: [u8; 6],
        version: u32,
        challenge: [u8; 16],
    ) -> Self {
        Self { params, seq: udp::INITIAL_SEQ, username: username.to_vec(), ip, mac, version, challenge }
    }

    pub fn interval(&self) -> u32 {
        self.params.interval
    }

    pub fn server(&self) -> SocketAddrV4 {
        self.params.server
    }

    pub fn src_port(&self) -> u16 {
        self.params.src_port
    }

    /// Payload of the next heartbeat; advances the sequence number and the
    /// counter. `None` when the username does not fit the payload.
    pub fn next_payload(&mut self) -> Option<Vec<u8>> {
        let p = &self.params;
        let Some(payload) = udp::udp_payload(
            &self.username,
            self.ip,
            self.mac,
            self.version,
            self.seq,
            p.counter,
            &self.challenge,
            &p.key,
            &p.iv,
        ) else {
            warn!("用户名过长，无法构造 UDP 心跳");
            return None;
        };
        debug!("UDP 心跳 seq = {}", self.seq);
        self.seq = self.seq.wrapping_add(1);
        self.params.counter = udp::next_counter(p.counter, self.version, p.interval);
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::unhex;

    fn vectors() -> impl Iterator<Item = (Source, Vec<u8>, &'static str)> {
        include_str!("check/testdata/udp-attributes.txt").lines().filter(|l| !l.starts_with('#')).map(|line| {
            let (input, expected) = line.split_once(" | ").unwrap();
            let f: Vec<&str> = input.split(' ').collect();
            let source = match f[0] {
                "challenge" => Source::Challenge,
                "success" => Source::Success,
                k => panic!("kind {}", k),
            };
            (source, unhex(f[3]), expected)
        })
    }

    fn show(p: &UdpParams) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            hex::encode(p.server.ip().octets()),
            p.src_port,
            p.server.port(),
            hex::encode(p.key),
            hex::encode(p.iv),
            p.counter,
            p.interval
        )
    }

    /// 48 calls of the original parsers (doc 25.2): both layouts, message
    /// lengths 0/4/19, each required attribute left out once, 0x59 missing.
    #[test]
    fn original_parser_vectors() {
        let mut n = 0;
        for (source, frame, expected) in vectors() {
            let got = parse_frame(&frame, source).unwrap();
            assert_eq!(
                got.as_ref().map(show).as_deref().unwrap_or("-"),
                expected,
                "{:?} {}",
                source,
                hex::encode(&frame)
            );
            n += 1;
        }
        assert_eq!(n, 48);
    }

    /// Counter `01..08` on the wire is the integer 0x0102030405060708.
    #[test]
    fn counter_is_network_order_u64() {
        let (source, frame, _) = vectors().next().unwrap();
        let p = parse_frame(&frame, source).unwrap().unwrap();
        assert_eq!(p.counter, 0x0102_0304_0506_0708);
    }

    /// A layout is only read where its parser reads it.
    #[test]
    fn layouts_are_not_interchangeable() {
        for (source, frame, expected) in vectors() {
            let other = if source == Source::Challenge { Source::Success } else { Source::Challenge };
            if expected != "-" {
                assert!(!matches!(parse_frame(&frame, other), Ok(Some(_))));
            }
        }
    }

    #[test]
    fn truncated_frames_are_rejected() {
        for (source, frame, expected) in vectors() {
            if expected == "-" {
                continue;
            }
            // EAPOL length one byte short: the last attribute no longer fits.
            let mut short = frame.clone();
            let len = u16::from_be_bytes([short[16], short[17]]) - 1;
            short[16..18].copy_from_slice(&len.to_be_bytes());
            assert!(parse_frame(&short, source).is_err());
            // EAPOL length beyond the captured bytes.
            assert!(parse_frame(&frame[..frame.len() - 1], source).is_err());
        }
    }

    #[test]
    fn zero_interval_falls_back_to_default() {
        let (source, mut frame, _) = vectors().next().unwrap();
        let n = frame.len();
        assert_eq!(frame[n - 6..n - 4], [ATTR_INTERVAL, 4]);
        frame[n - 4..].fill(0);
        assert_eq!(parse_frame(&frame, source).unwrap().unwrap().interval, udp::DEFAULT_INTERVAL_SECS);
    }
}
