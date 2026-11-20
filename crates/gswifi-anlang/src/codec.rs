//! Wire codec of the 安朗 UDP protocol (doc 04.2–04.6).
//!
//! Pure functions only: no sockets, no clock. Request builders are byte-exact
//! ports of the independent reference `reference/atcodec.py` and are checked
//! against its golden vectors (`testdata/vectors.json`). Response parsers read
//! only the offsets the original client is known to read (doc 04.5, 04.6 and
//! the disassembly addresses cited per function); everything else in a
//! response is undocumented and ignored.
//!
//! Packet plain view (doc 04.2):
//!
//! | offset | len | content |
//! |---:|---:|---|
//! | 0 | 1 | op |
//! | 1 | 1 | total plain length |
//! | 2 | 16 | MD5 of the whole plain packet with this field zeroed |
//! | 18 | n | payload (TLVs in requests) |
//!
//! Every byte of the plain view is then bit-permuted (doc 04.3). There is no
//! key: the digest is an integrity check, not a MAC, and the password in the
//! login packet is readable by anyone who captures it (doc 04.3).

use std::fmt;
use std::net::Ipv4Addr;

use serde::Deserialize;

/// Bytes before the payload: op, total length, digest (doc 04.2).
pub const HEADER_LEN: usize = 18;
/// Largest packet the original client handles safely: it reads the length
/// byte with a signed load, so 128..=255 would turn negative (doc 04.2).
pub const MAX_PACKET_LEN: usize = 127;
/// Largest TLV value: the one-byte TLV length counts its 2-byte header.
pub const MAX_TLV_VALUE: usize = 253;
/// Longest dotted-quad IPv4 text.
pub const MAX_IPV4_TEXT: usize = 15;
/// Discovery and heartbeat pad the IPv4 text with NUL to this width
/// (doc 04.4, 04.6). Login does not pad.
pub const IPV4_FIELD_LEN: usize = 16;
/// Login length without the four variable fields: `44 + U + P + I + S`
/// (doc 04.4).
pub const LOGIN_OVERHEAD: usize = 44;
/// Heartbeat length without the session: `88 + session` (doc 04.6).
pub const HEARTBEAT_OVERHEAD: usize = 88;
/// Longest session a heartbeat can carry within [`MAX_PACKET_LEN`].
pub const MAX_HEARTBEAT_SESSION: usize = MAX_PACKET_LEN - HEARTBEAT_OVERHEAD;
/// Initial heartbeat counter: the LE32 literal at atclient VA `0x40139c`,
/// sent big-endian as `01 00 00 00` (doc 04.6). It is not 1.
pub const INITIAL_COUNTER: u32 = 0x0100_0000;
/// Protocol identifier sent in login TLV 31 (doc 04.4). The program version
/// 2.0.0 is a different thing and is never sent.
pub const PROTOCOL_VERSION: &[u8] = b"4.2.0";
/// Built-in discovery address of the original client (doc 04.1). Whether a
/// campus gateway intercepts it is unverified.
pub const DISCOVERY_SERVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 8);
/// Discovery UDP port (doc 04.1, VA `0x400baa`).
pub const DISCOVERY_PORT: u16 = 3850;
/// Server UDP port for service query, login and heartbeat (doc 04.1, VA
/// `0x400ee2`).
pub const SERVER_PORT: u16 = 3848;
/// Value of TLV 8 in discovery and service query requests (doc 04.4).
/// Meaning unknown; sent verbatim.
pub const QUERY_MARKER: [u8; 5] = [0, 1, 2, 3, 4];
/// The original client receives discovery replies into a 256-byte buffer and
/// treats 256 or more bytes as a size error (VA `0x400c50`).
pub const FIRMWARE_DISCOVERY_MAX: usize = 255;
/// Service, login and heartbeat replies go into a 4096-byte buffer; 4096 or
/// more bytes is a size error (VA `0x400ff0`, `0x4018ae`, `0x4012c8`).
pub const FIRMWARE_REPLY_MAX: usize = 4095;

/// Request op codes (doc 04.4, 04.6). Response op codes are unknown
/// (doc 04.5) and never checked.
pub mod op {
    pub const LOGIN: u8 = 1;
    pub const HEARTBEAT: u8 = 3;
    pub const SERVICE_QUERY: u8 = 7;
    pub const DISCOVERY: u8 = 12;
}

/// TLV types seen in requests (doc 04.4, 04.6) and the two response markers
/// the original client looks for.
pub mod tlv_type {
    pub const USERNAME: u8 = 1;
    pub const PASSWORD: u8 = 2;
    pub const MAC: u8 = 7;
    /// Session in heartbeats and login replies; carries [`super::QUERY_MARKER`]
    /// in discovery and service query requests.
    pub const SESSION: u8 = 8;
    pub const IPV4: u8 = 9;
    pub const SERVICE: u8 = 10;
    /// Discovery reply: the client takes the four bytes that start two bytes
    /// after the first byte with this value (VA `0x400cac`).
    pub const SERVER: u8 = 12;
    /// Login: constant one-byte value 0. Meaning unknown (doc 04.4).
    pub const LOGIN_FLAG: u8 = 14;
    pub const COUNTER: u8 = 20;
    pub const VERSION: u8 = 31;
    /// Heartbeat: six 4-byte zero fields with types 42..=47 (doc 04.6).
    /// Meaning unknown.
    pub const HEARTBEAT_ZERO: [u8; 6] = [42, 43, 44, 45, 46, 47];
}

/// Why a packet could not be built or parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Packet length outside `18..=127` (requests, strict replies) or outside
    /// the firmware receive buffer (lenient replies).
    PacketLength(usize),
    /// Length byte at offset 1 differs from the datagram length.
    LengthMismatch { declared: u8, actual: usize },
    /// TLV value longer than [`MAX_TLV_VALUE`].
    TlvTooLong(usize),
    /// Fewer than two bytes left for a TLV header.
    TruncatedTlv { offset: usize },
    /// TLV length below 2 or past the end of the payload.
    InvalidTlvLength { offset: usize, length: u8 },
    /// IPv4 text empty or longer than 15 bytes.
    Ipv4TextLength(usize),
    /// Digest does not match the packet.
    BadDigest,
    /// Service reply without the service field at offset 18.
    MissingService,
    /// Service field length below 2 or past the end of the reply.
    InvalidServiceLength(u8),
    /// Login reply with offset 20 zero (server refused).
    LoginRejected,
    /// Login reply without the session marker at offset 21.
    NoSession,
    /// Session length zero, above 127 or past the end of the reply.
    InvalidSessionLength(u8),
    /// Discovery reply without a server address.
    NoServerAddress,
    /// Discovery reply names an address no server can have.
    InvalidServerAddress(Ipv4Addr),
    /// 802.1X username longer than the original 115-byte buffer allows.
    UsernameTooLong(usize),
    /// 802.1X username contains NUL, which the original C string would cut.
    InvalidUsername,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::PacketLength(n) => write!(f, "packet length {} out of range", n),
            CodecError::LengthMismatch { declared, actual } => {
                write!(f, "declared length {} but datagram has {} bytes", declared, actual)
            }
            CodecError::TlvTooLong(n) => write!(f, "TLV value of {} bytes exceeds 253", n),
            CodecError::TruncatedTlv { offset } => write!(f, "truncated TLV header at offset {}", offset),
            CodecError::InvalidTlvLength { offset, length } => {
                write!(f, "invalid TLV length {} at offset {}", length, offset)
            }
            CodecError::Ipv4TextLength(n) => write!(f, "IPv4 text of {} bytes (need 1..=15)", n),
            CodecError::BadDigest => f.write_str("digest mismatch"),
            CodecError::MissingService => f.write_str("no service field at offset 18"),
            CodecError::InvalidServiceLength(n) => write!(f, "invalid service field length {}", n),
            CodecError::LoginRejected => f.write_str("login rejected"),
            CodecError::NoSession => f.write_str("no session in login reply"),
            CodecError::InvalidSessionLength(n) => write!(f, "invalid session length {}", n),
            CodecError::NoServerAddress => f.write_str("no server address in discovery reply"),
            CodecError::InvalidServerAddress(ip) => write!(f, "unusable server address {}", ip),
            CodecError::UsernameTooLong(n) => write!(f, "formatted username of {} bytes exceeds 114", n),
            CodecError::InvalidUsername => f.write_str("username contains NUL"),
        }
    }
}

impl std::error::Error for CodecError {}

/// How strictly replies are checked before their fields are read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseCheck {
    /// Reference behaviour (doc 04.5, `atcodec.py`): length `18..=127`,
    /// length byte equal to the datagram length, digest must match.
    #[default]
    Strict,
    /// Original client behaviour: any length that fits its receive buffer,
    /// length byte and digest not checked (it copies the digest out and zeroes
    /// it but never compares, doc 04.5). For servers that turn out not to
    /// produce the digest.
    Firmware,
}

/// Bit permutation of one byte: output bits 7..0 come from input bits
/// 0, 4, 3, 2, 5, 6, 7, 1 (doc 04.3, atclient VA `0x4015ac`).
pub const fn encode_byte(x: u8) -> u8 {
    ((x & 1) << 7) | ((x & 2) >> 1) | ((x & 28) << 2) | ((x & 32) >> 2) | ((x & 64) >> 4) | ((x & 128) >> 6)
}

/// Inverse of [`encode_byte`] (doc 04.3, atclient VA `0x401604`).
pub const fn decode_byte(x: u8) -> u8 {
    ((x & 2) << 6) | ((x & 4) << 4) | ((x & 8) << 2) | ((x & 112) >> 2) | ((x & 1) << 1) | ((x & 128) >> 7)
}

/// Applies [`encode_byte`] to every byte.
pub fn encode(plain: &[u8]) -> Vec<u8> {
    plain.iter().map(|&b| encode_byte(b)).collect()
}

/// Applies [`decode_byte`] to every byte.
pub fn decode(wire: &[u8]) -> Vec<u8> {
    wire.iter().map(|&b| decode_byte(b)).collect()
}

/// MD5 over the plain packet with bytes 2..18 taken as zero (doc 04.2,
/// atclient wrapper VA `0x4023f8`). Shorter input is hashed as is.
pub fn digest(plain: &[u8]) -> [u8; 16] {
    let mut buf = plain.to_vec();
    if buf.len() >= HEADER_LEN {
        buf[2..HEADER_LEN].fill(0);
    }
    md5::compute(&buf).0
}

/// One TLV: `type | 2 + len(value) | value` (doc 04.4).
pub fn tlv(kind: u8, value: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(value.len() + 2);
    push_tlv(&mut out, kind, value)?;
    Ok(out)
}

fn push_tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), CodecError> {
    if value.len() > MAX_TLV_VALUE {
        return Err(CodecError::TlvTooLong(value.len()));
    }
    out.push(kind);
    out.push(value.len() as u8 + 2);
    out.extend_from_slice(value);
    Ok(())
}

/// Builds the wire form of a request: header, digest, bit permutation
/// (doc 04.2). Refuses packets longer than [`MAX_PACKET_LEN`].
pub fn seal(kind: u8, payload: &[u8]) -> Result<Vec<u8>, CodecError> {
    let n = HEADER_LEN + payload.len();
    if n > MAX_PACKET_LEN {
        return Err(CodecError::PacketLength(n));
    }
    let mut plain = Vec::with_capacity(n);
    plain.push(kind);
    plain.push(n as u8);
    plain.extend_from_slice(&[0; 16]);
    plain.extend_from_slice(payload);
    let sum = md5::compute(&plain).0;
    plain[2..HEADER_LEN].copy_from_slice(&sum);
    Ok(encode(&plain))
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    pub digest_valid: bool,
    /// The whole plain view, header included.
    pub plain: Vec<u8>,
}

impl Packet {
    /// Bytes after the 18-byte header.
    pub fn payload(&self) -> &[u8] {
        &self.plain[HEADER_LEN..]
    }
}

/// Decodes a datagram with the reference's strict framing (`atcodec.unseal`):
/// length `18..=127` and equal to the length byte. The digest is reported,
/// not enforced.
pub fn unseal(wire: &[u8]) -> Result<Packet, CodecError> {
    if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&wire.len()) {
        return Err(CodecError::PacketLength(wire.len()));
    }
    let plain = decode(wire);
    if plain[1] as usize != plain.len() {
        return Err(CodecError::LengthMismatch { declared: plain[1], actual: plain.len() });
    }
    let digest_valid = digest(&plain)[..] == plain[2..HEADER_LEN];
    Ok(Packet { kind: plain[0], digest_valid, plain })
}

/// Splits a payload into `(type, value)` pairs. Every TLV must be complete.
pub fn parse_tlvs(payload: &[u8]) -> Result<Vec<(u8, &[u8])>, CodecError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        if pos + 2 > payload.len() {
            return Err(CodecError::TruncatedTlv { offset: pos });
        }
        let (kind, length) = (payload[pos], payload[pos + 1]);
        let n = length as usize;
        if n < 2 || pos + n > payload.len() {
            return Err(CodecError::InvalidTlvLength { offset: pos, length });
        }
        out.push((kind, &payload[pos + 2..pos + n]));
        pos += n;
    }
    Ok(out)
}

fn check_ipv4_text(text: &[u8]) -> Result<(), CodecError> {
    if text.is_empty() || text.len() > MAX_IPV4_TEXT {
        return Err(CodecError::Ipv4TextLength(text.len()));
    }
    Ok(())
}

fn padded_ipv4(text: &[u8]) -> Result<[u8; IPV4_FIELD_LEN], CodecError> {
    check_ipv4_text(text)?;
    let mut field = [0u8; IPV4_FIELD_LEN];
    field[..text.len()].copy_from_slice(text);
    Ok(field)
}

/// Discovery request, op 12, 51 bytes, sent to `1.1.1.8:3850` (doc 04.4,
/// VA `0x400acc`): `08 07 00 01 02 03 04 | 09 12 ip16 | 07 08 mac6`.
pub fn discovery(local_ipv4: &[u8], mac: &[u8; 6]) -> Result<Vec<u8>, CodecError> {
    let ip = padded_ipv4(local_ipv4)?;
    let mut payload = Vec::with_capacity(33);
    push_tlv(&mut payload, tlv_type::SESSION, &QUERY_MARKER)?;
    push_tlv(&mut payload, tlv_type::IPV4, &ip)?;
    push_tlv(&mut payload, tlv_type::MAC, mac)?;
    seal(op::DISCOVERY, &payload)
}

/// Service query, op 7, 33 bytes (doc 04.4, VA `0x400f2a`):
/// `08 07 00 01 02 03 04 | 07 08 mac6`.
pub fn service_query(mac: &[u8; 6]) -> Result<Vec<u8>, CodecError> {
    let mut payload = Vec::with_capacity(15);
    push_tlv(&mut payload, tlv_type::SESSION, &QUERY_MARKER)?;
    push_tlv(&mut payload, tlv_type::MAC, mac)?;
    seal(op::SERVICE_QUERY, &payload)
}

/// Login, op 1, `44 + U + P + I + S` bytes (doc 04.4, VA `0x401688`). TLV
/// order is kept as in the original: MAC, username, password, IPv4 text
/// (not padded), service, `0e 03 00`, `1f 07 "4.2.0"`. The password is sent
/// as plain bytes under the reversible permutation (doc 04.3).
pub fn login(
    username: &[u8],
    password: &[u8],
    local_ipv4: &[u8],
    service: &[u8],
    mac: &[u8; 6],
) -> Result<Vec<u8>, CodecError> {
    check_ipv4_text(local_ipv4)?;
    let mut payload = Vec::with_capacity(LOGIN_OVERHEAD + username.len() + password.len() + 15 + service.len());
    push_tlv(&mut payload, tlv_type::MAC, mac)?;
    push_tlv(&mut payload, tlv_type::USERNAME, username)?;
    push_tlv(&mut payload, tlv_type::PASSWORD, password)?;
    push_tlv(&mut payload, tlv_type::IPV4, local_ipv4)?;
    push_tlv(&mut payload, tlv_type::SERVICE, service)?;
    push_tlv(&mut payload, tlv_type::LOGIN_FLAG, &[0])?;
    push_tlv(&mut payload, tlv_type::VERSION, PROTOCOL_VERSION)?;
    seal(op::LOGIN, &payload)
}

/// Heartbeat, op 3, `88 + session` bytes (doc 04.6, VA `0x401094`): session,
/// IPv4 text padded to 16, MAC, counter as BE32, then TLVs 42..=47 with four
/// zero bytes each.
pub fn heartbeat(session: &[u8], local_ipv4: &[u8], mac: &[u8; 6], counter: u32) -> Result<Vec<u8>, CodecError> {
    let ip = padded_ipv4(local_ipv4)?;
    let mut payload = Vec::with_capacity(HEARTBEAT_OVERHEAD - HEADER_LEN + session.len());
    push_tlv(&mut payload, tlv_type::SESSION, session)?;
    push_tlv(&mut payload, tlv_type::IPV4, &ip)?;
    push_tlv(&mut payload, tlv_type::MAC, mac)?;
    push_tlv(&mut payload, tlv_type::COUNTER, &counter.to_be_bytes())?;
    for kind in tlv_type::HEARTBEAT_ZERO {
        push_tlv(&mut payload, kind, &[0; 4])?;
    }
    seal(op::HEARTBEAT, &payload)
}

/// Counter after an accepted heartbeat: plus 3, back to [`INITIAL_COUNTER`]
/// when the result is `0xffffffff` (doc 04.6, VA `0x401326`).
pub const fn next_counter(counter: u32) -> u32 {
    let next = counter.wrapping_add(3);
    if next == u32::MAX {
        INITIAL_COUNTER
    } else {
        next
    }
}

/// Decodes a reply and returns its plain view after the checks of `check`.
/// `firmware_max` is the receive-buffer limit used by
/// [`ResponseCheck::Firmware`] ([`FIRMWARE_DISCOVERY_MAX`] or
/// [`FIRMWARE_REPLY_MAX`]).
pub fn open_response(wire: &[u8], check: ResponseCheck, firmware_max: usize) -> Result<Vec<u8>, CodecError> {
    match check {
        ResponseCheck::Strict => {
            let packet = unseal(wire)?;
            if !packet.digest_valid {
                return Err(CodecError::BadDigest);
            }
            Ok(packet.plain)
        }
        ResponseCheck::Firmware => {
            if wire.len() < HEADER_LEN || wire.len() > firmware_max {
                return Err(CodecError::PacketLength(wire.len()));
            }
            Ok(decode(wire))
        }
    }
}

/// Byte at `index`, zero past the end. The original client reads reply flags
/// from a zero-filled `calloc` buffer, so a missing byte reads as 0.
fn byte_at(plain: &[u8], index: usize) -> u8 {
    plain.get(index).copied().unwrap_or(0)
}

/// Bytes up to the first NUL. The original client keeps service and session
/// as C strings and uses `strlen` afterwards (doc 04.4, 04.6).
pub fn c_string(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// Server address from a decoded discovery reply.
///
/// The original client (VA `0x400cac..0x400cc4`) zeroes the digest, scans
/// the plain packet up to the length byte for the first byte equal to 12 and
/// takes the four bytes starting two positions later. The full reply layout
/// is unknown (doc 04.7, doc 10.2 AT-01). This port scans the payload only:
/// with the digest zeroed the header can only match when the op or length is
/// 12, and then the original would read the zeroed digest as `0.0.0.0`,
/// which can never have worked. Unlike the original, it reads the address
/// bytes directly rather than formatting them as text: atclient's formatter
/// appears to drop a zero tens digit, so 200 becomes "20" (VA
/// `0x400cc6..0x400e82`, static reading only).
pub fn server_from_discovery(plain: &[u8]) -> Result<Ipv4Addr, CodecError> {
    let declared = byte_at(plain, 1) as usize;
    // Signed length byte: 128..=255 is negative and the scan finds nothing.
    let end = if declared <= MAX_PACKET_LEN { declared.min(plain.len()) } else { 0 };
    let pos = plain
        .get(HEADER_LEN..end)
        .and_then(|region| region.iter().position(|&b| b == tlv_type::SERVER))
        .map(|i| i + HEADER_LEN)
        .ok_or(CodecError::NoServerAddress)?;
    let bytes = plain.get(pos + 2..pos + 6).ok_or(CodecError::NoServerAddress)?;
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        return Err(CodecError::InvalidServerAddress(ip));
    }
    Ok(ip)
}

/// Service value from a decoded service reply (doc 04.4): offset 18 must be
/// 10, offset 19 is a length `n` that includes the 2-byte header, the value
/// is `plain[20..18 + n]`. The original copies `n - 2` bytes as a C string;
/// apply [`c_string`] before using the value as it did.
pub fn service_from_plain(plain: &[u8]) -> Result<&[u8], CodecError> {
    if plain.len() < 20 || plain[18] != tlv_type::SERVICE {
        return Err(CodecError::MissingService);
    }
    let n = plain[19] as usize;
    if n < 2 || 18 + n > plain.len() {
        return Err(CodecError::InvalidServiceLength(plain[19]));
    }
    Ok(&plain[20..18 + n])
}

/// Strict service-reply parser of the reference (`service_from_response`):
/// framing and digest checked.
pub fn service_from_response(wire: &[u8]) -> Result<Vec<u8>, CodecError> {
    let plain = open_response(wire, ResponseCheck::Strict, FIRMWARE_REPLY_MAX)?;
    service_from_plain(&plain).map(<[u8]>::to_vec)
}

/// Outcome of a login reply (doc 04.5, VA `0x401902..0x401924`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginReply<'a> {
    /// Offset 20 is zero. The original logs "server rejected" (and retries).
    Rejected,
    /// Offset 21 is not 8. The original logs "success but have't get session".
    NoSession,
    /// The `n` bytes from offset 23, `n` read at offset 22. Here the length
    /// is `n`, not `n - 2` as in the service reply. The original keeps it as a
    /// C string; apply [`c_string`] to match.
    Session(&'a [u8]),
}

/// Reads a decoded login reply. Rejection and missing session are outcomes,
/// not errors; an impossible session length is an error.
pub fn login_reply(plain: &[u8]) -> Result<LoginReply<'_>, CodecError> {
    if byte_at(plain, 20) == 0 {
        return Ok(LoginReply::Rejected);
    }
    if byte_at(plain, 21) != tlv_type::SESSION {
        return Ok(LoginReply::NoSession);
    }
    let length = byte_at(plain, 22);
    let n = length as usize;
    if n == 0 || n > MAX_PACKET_LEN || 23 + n > plain.len() {
        return Err(CodecError::InvalidSessionLength(length));
    }
    Ok(LoginReply::Session(&plain[23..23 + n]))
}

/// Strict login-reply parser of the reference
/// (`session_from_login_response`): framing and digest checked, rejection
/// and missing session are errors.
pub fn session_from_login_response(wire: &[u8]) -> Result<Vec<u8>, CodecError> {
    let plain = open_response(wire, ResponseCheck::Strict, FIRMWARE_REPLY_MAX)?;
    match login_reply(&plain)? {
        LoginReply::Session(session) => Ok(session.to_vec()),
        LoginReply::Rejected => Err(CodecError::LoginRejected),
        LoginReply::NoSession => Err(CodecError::NoSession),
    }
}

/// Whether a decoded heartbeat reply accepts the heartbeat: offset 20
/// non-zero (doc 04.6, VA `0x401314`).
pub fn heartbeat_accepted(plain: &[u8]) -> bool {
    byte_at(plain, 20) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testjson::Json;

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const IP: &[u8] = b"192.0.2.10";

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // --- test_atcodec.py: test_bit_basis_and_inverse (doc 04.3) ---

    #[test]
    fn bit_basis_and_inverse() {
        let basis: Vec<u8> = (0..8).map(|i| encode_byte(1 << i)).collect();
        assert_eq!(basis, [128, 1, 16, 32, 64, 8, 4, 2]);
        for x in 0..=255u8 {
            assert_eq!(decode_byte(encode_byte(x)), x);
            assert_eq!(encode_byte(decode_byte(x)), x);
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)), all);
    }

    // --- vectors.json: every request rebuilt from `inputs` ---

    #[test]
    fn golden_vectors_json() {
        let doc = Json::parse(include_str!("../testdata/vectors.json")).unwrap();
        assert!(doc.get("status").str().contains("synthetic"));
        let inputs = doc.get("inputs");
        let username = inputs.get("username").str().as_bytes();
        let password = inputs.get("password").str().as_bytes();
        let ipv4 = inputs.get("ipv4").str().as_bytes();
        let mac: [u8; 6] = unhex(inputs.get("mac").str()).try_into().unwrap();
        let service = inputs.get("service").str().as_bytes();
        let session = inputs.get("session").str().as_bytes();
        let counter = inputs.get("counter").u64() as u32;
        assert_eq!(counter, INITIAL_COUNTER);

        let requests = doc.get("requests").arr();
        assert_eq!(requests.len(), 4);
        for request in requests {
            let name = request.get("name").str();
            let built = match name {
                "discovery" => discovery(ipv4, &mac),
                "service_query" => service_query(&mac),
                "login" => login(username, password, ipv4, service, &mac),
                "heartbeat" => heartbeat(session, ipv4, &mac, counter),
                other => panic!("unknown vector {}", other),
            }
            .unwrap();
            let wire = unhex(request.get("wire_hex").str());
            let plain = unhex(request.get("plain_hex").str());
            assert_eq!(hex::encode(&built), hex::encode(&wire), "{} wire", name);
            assert_eq!(decode(&wire), plain, "{} plain", name);
            assert_eq!(encode(&plain), wire, "{} encode", name);

            let packet = unseal(&wire).unwrap();
            assert_eq!(packet.kind as u64, request.get("kind").u64(), "{} kind", name);
            assert_eq!(packet.plain.len() as u64, request.get("length").u64(), "{} length", name);
            assert_eq!(packet.digest_valid, request.get("digest_valid").bool(), "{} digest", name);
            assert_eq!(packet.plain, plain);

            let expected: Vec<(u8, Vec<u8>)> = request
                .get("tlvs")
                .arr()
                .iter()
                .map(|t| (t.get("type").u64() as u8, unhex(t.get("value_hex").str())))
                .collect();
            let parsed: Vec<(u8, Vec<u8>)> =
                parse_tlvs(packet.payload()).unwrap().into_iter().map(|(k, v)| (k, v.to_vec())).collect();
            assert_eq!(parsed, expected, "{} tlvs", name);
        }
    }

    // --- test_atcodec.py: test_service_layout (doc 04.4) ---

    #[test]
    fn service_layout() {
        let wire = service_query(&MAC).unwrap();
        let p = unseal(&wire).unwrap();
        assert_eq!(wire.len(), 33);
        assert_eq!(&p.plain[..2], b"\x07\x21");
        assert_eq!(p.payload(), &unhex("080700010203040708020000000001")[..]);
        assert!(p.digest_valid);
    }

    // --- test_atcodec.py: test_login_layout_and_password (doc 04.4) ---

    #[test]
    fn login_layout_and_password() {
        let p = unseal(&login(b"alice", b"synthetic", IP, b"campus", &MAC).unwrap()).unwrap();
        assert!(p.digest_valid);
        assert_eq!(p.kind, 1);
        assert_eq!(p.plain.len(), LOGIN_OVERHEAD + 5 + 9 + 10 + 6);
        assert_eq!(
            parse_tlvs(p.payload()).unwrap(),
            vec![
                (7, &MAC[..]),
                (1, &b"alice"[..]),
                (2, &b"synthetic"[..]),
                (9, IP),
                (10, &b"campus"[..]),
                (14, &b"\0"[..]),
                (31, &b"4.2.0"[..]),
            ]
        );
    }

    // --- test_atcodec.py: test_discovery_and_rejection ---

    #[test]
    fn discovery_and_rejection() {
        let p = unseal(&discovery(IP, &MAC).unwrap()).unwrap();
        assert_eq!(p.plain.len(), 51);
        let fields = parse_tlvs(p.payload()).unwrap();
        let mut padded = IP.to_vec();
        padded.extend_from_slice(&[0; 6]);
        assert_eq!(fields[1], (9, &padded[..]));

        let mut damaged = service_query(&[0; 6]).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(!unseal(&damaged).unwrap().digest_valid);

        assert!(unseal(b"").is_err());
        for bad in [&b"\x01"[..], b"\x01\x00", b"\x01\x05a"] {
            assert!(parse_tlvs(bad).is_err(), "{:?}", bad);
        }
        assert_eq!(login(&[b'x'; 100], b"p", IP, b"s", &[0; 6]), Err(CodecError::PacketLength(156)));
    }

    // --- test_atcodec.py: test_heartbeat_counter_and_padding (doc 04.6) ---

    #[test]
    fn heartbeat_counter_and_padding() {
        let p = unseal(&heartbeat(b"session", IP, &MAC, INITIAL_COUNTER).unwrap()).unwrap();
        assert_eq!(p.plain.len(), 95);
        assert_eq!(p.kind, 3);
        assert!(p.digest_valid);
        let fields = parse_tlvs(p.payload()).unwrap();
        assert_eq!(fields[3], (20, &[1u8, 0, 0, 0][..]));
        let zeros: Vec<(u8, &[u8])> = (42..48).map(|k| (k, &[0u8; 4][..])).collect();
        assert_eq!(&fields[4..], &zeros[..]);
        assert_eq!(next_counter(INITIAL_COUNTER), INITIAL_COUNTER + 3);
        assert_eq!(next_counter(0xffff_fffc), INITIAL_COUNTER);
    }

    // --- test_atcodec.py: test_response_layouts_are_distinct (doc 04.4/04.5) ---

    #[test]
    fn response_layouts_are_distinct() {
        // Ops 8 and 2 are synthetic placeholders, not confirmed server values.
        assert_eq!(service_from_response(&seal(8, &tlv(10, b"campus").unwrap()).unwrap()).unwrap(), b"campus");
        let response = seal(2, b"\0\0\x01\x08\x03abc").unwrap();
        assert_eq!(session_from_login_response(&response).unwrap(), b"abc");
        assert_eq!(
            session_from_login_response(&seal(2, b"\0\0\x01\x08\x08abc").unwrap()),
            Err(CodecError::InvalidSessionLength(8))
        );
        assert_eq!(service_from_response(&seal(8, b"\x0a\x01").unwrap()), Err(CodecError::InvalidServiceLength(1)));
    }

    // --- additional boundaries ---

    #[test]
    fn counter_sequence_and_wrap() {
        let mut c = INITIAL_COUNTER;
        for _ in 0..4 {
            c = next_counter(c);
        }
        assert_eq!(c, 0x0100_000c);
        assert_eq!(next_counter(0xffff_fffb), 0xffff_fffe);
        assert_eq!(next_counter(0xffff_fffd), 0);
        assert_eq!(next_counter(0xffff_fffe), 1);
        let p = unseal(&heartbeat(b"s", IP, &MAC, 0x0102_0304).unwrap()).unwrap();
        assert_eq!(parse_tlvs(p.payload()).unwrap()[3].1, &[1, 2, 3, 4]);
    }

    #[test]
    fn packet_length_limits() {
        assert_eq!(seal(1, &[0; 109]).unwrap().len(), 127);
        assert_eq!(seal(1, &[0; 110]), Err(CodecError::PacketLength(128)));
        assert_eq!(seal(1, &[]).unwrap().len(), 18);
        assert!(unseal(&seal(1, &[]).unwrap()).unwrap().digest_valid);
        assert_eq!(unseal(&[0; 17]), Err(CodecError::PacketLength(17)));
        assert_eq!(unseal(&[0; 128]), Err(CodecError::PacketLength(128)));
        // Login exactly at the limit: 44 + U + P + I + S = 127.
        let user = [b'u'; 48];
        assert_eq!(login(&user, b"pass", b"192.0.2.10", b"campus", &MAC).unwrap().len(), 112);
        let user = [b'u'; 63];
        assert_eq!(login(&user, b"pass", b"192.0.2.10", b"campus", &MAC).unwrap().len(), 127);
        let user = [b'u'; 64];
        assert!(login(&user, b"pass", b"192.0.2.10", b"campus", &MAC).is_err());
        // Heartbeat session limit.
        assert!(heartbeat(&[b's'; MAX_HEARTBEAT_SESSION], IP, &MAC, 0).is_ok());
        assert!(heartbeat(&[b's'; MAX_HEARTBEAT_SESSION + 1], IP, &MAC, 0).is_err());
    }

    #[test]
    fn tlv_limits() {
        assert_eq!(tlv(5, &[7; 253]).unwrap().len(), 255);
        assert_eq!(tlv(5, &[7; 254]), Err(CodecError::TlvTooLong(254)));
        assert_eq!(tlv(5, b"").unwrap(), [5, 2]);
        assert_eq!(parse_tlvs(b"").unwrap(), vec![]);
        assert_eq!(parse_tlvs(b"\x05\x02").unwrap(), vec![(5, &b""[..])]);
        assert_eq!(parse_tlvs(b"\x05\x02\x06"), Err(CodecError::TruncatedTlv { offset: 2 }));
        assert_eq!(parse_tlvs(b"\x05\x00"), Err(CodecError::InvalidTlvLength { offset: 0, length: 0 }));
    }

    #[test]
    fn ipv4_text_limits() {
        assert_eq!(discovery(b"", &MAC), Err(CodecError::Ipv4TextLength(0)));
        assert_eq!(discovery(b"1234567890123456", &MAC), Err(CodecError::Ipv4TextLength(16)));
        assert!(discovery(b"255.255.255.255", &MAC).is_ok());
        assert!(heartbeat(b"s", b"", &MAC, 0).is_err());
        assert!(login(b"u", b"p", b"", b"s", &MAC).is_err());
    }

    #[test]
    fn unseal_reports_length_mismatch() {
        let mut plain = decode(&service_query(&MAC).unwrap());
        plain[1] = 32;
        assert_eq!(unseal(&encode(&plain)), Err(CodecError::LengthMismatch { declared: 32, actual: 33 }));
    }

    #[test]
    fn open_response_modes() {
        let good = seal(4, b"\0\0\x01").unwrap();
        assert!(open_response(&good, ResponseCheck::Strict, FIRMWARE_REPLY_MAX).is_ok());
        let mut bad = good.clone();
        bad[5] ^= 0x10;
        assert_eq!(open_response(&bad, ResponseCheck::Strict, FIRMWARE_REPLY_MAX), Err(CodecError::BadDigest));
        let plain = open_response(&bad, ResponseCheck::Firmware, FIRMWARE_REPLY_MAX).unwrap();
        assert!(heartbeat_accepted(&plain));
        // Firmware mode ignores the length byte but not the buffer size.
        let long = encode(&[1u8; 200]);
        assert!(open_response(&long, ResponseCheck::Strict, FIRMWARE_REPLY_MAX).is_err());
        assert!(open_response(&long, ResponseCheck::Firmware, FIRMWARE_REPLY_MAX).is_ok());
        assert!(open_response(&encode(&[1u8; 256]), ResponseCheck::Firmware, FIRMWARE_DISCOVERY_MAX).is_err());
        assert!(open_response(&[0; 17], ResponseCheck::Firmware, FIRMWARE_REPLY_MAX).is_err());
    }

    fn plain_of(kind: u8, payload: &[u8]) -> Vec<u8> {
        unseal(&seal(kind, payload).unwrap()).unwrap().plain
    }

    #[test]
    fn discovery_reply_server_address() {
        // Synthetic reply op 13; the real op is unknown (doc 04.5).
        let plain = plain_of(13, &tlv(12, &[10, 0, 200, 5]).unwrap());
        assert_eq!(server_from_discovery(&plain), Ok(Ipv4Addr::new(10, 0, 200, 5)));
        // The first 12 wins, as in the original scan, even after another TLV.
        let mut payload = tlv(3, b"ab").unwrap();
        payload.extend(tlv(12, &[172, 16, 0, 1]).unwrap());
        assert_eq!(server_from_discovery(&plain_of(13, &payload)), Ok(Ipv4Addr::new(172, 16, 0, 1)));
        // No 12 at all.
        assert_eq!(server_from_discovery(&plain_of(13, b"\x03\x04ab")), Err(CodecError::NoServerAddress));
        // A 12 too close to the end.
        assert_eq!(server_from_discovery(&plain_of(13, b"\x0c\x06\x0a\x00")), Err(CodecError::NoServerAddress));
        // Op 12 echoed: header is not scanned, payload still is.
        assert_eq!(
            server_from_discovery(&plain_of(12, &tlv(12, &[10, 1, 2, 3]).unwrap())),
            Ok(Ipv4Addr::new(10, 1, 2, 3))
        );
        // Unusable addresses.
        assert!(matches!(
            server_from_discovery(&plain_of(13, &tlv(12, &[0, 0, 0, 0]).unwrap())),
            Err(CodecError::InvalidServerAddress(_))
        ));
        assert!(server_from_discovery(&plain_of(13, &tlv(12, &[255, 255, 255, 255]).unwrap())).is_err());
        assert!(server_from_discovery(&plain_of(13, &tlv(12, &[224, 0, 0, 1]).unwrap())).is_err());
        assert!(server_from_discovery(&[]).is_err());
    }

    #[test]
    fn login_reply_outcomes() {
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x00")), Ok(LoginReply::Rejected));
        // Header only: offset 20 missing reads as zero, like the calloc buffer.
        assert_eq!(login_reply(&plain_of(2, b"")), Ok(LoginReply::Rejected));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x01\x09\x01a")), Ok(LoginReply::NoSession));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x01")), Ok(LoginReply::NoSession));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x01\x08")), Err(CodecError::InvalidSessionLength(0)));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x01\x08\x00")), Err(CodecError::InvalidSessionLength(0)));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x7f\x08\x02ab")), Ok(LoginReply::Session(b"ab")));
        assert_eq!(login_reply(&plain_of(2, b"\0\0\x01\x08\x03a\0b")), Ok(LoginReply::Session(b"a\0b")));
        assert_eq!(session_from_login_response(&seal(2, b"\0\0\0").unwrap()), Err(CodecError::LoginRejected));
        assert_eq!(session_from_login_response(&seal(2, b"\0\0\x01\x07").unwrap()), Err(CodecError::NoSession));
    }

    #[test]
    fn service_reply_cases() {
        assert_eq!(service_from_plain(&plain_of(8, b"\x0a\x02")), Ok(&b""[..]));
        assert_eq!(service_from_plain(&plain_of(8, b"\x0b\x04ab")), Err(CodecError::MissingService));
        assert_eq!(service_from_plain(&plain_of(8, b"\x0a")), Err(CodecError::MissingService));
        assert_eq!(service_from_plain(&plain_of(8, b"\x0a\x05ab")), Err(CodecError::InvalidServiceLength(5)));
        // Trailing bytes after the field are ignored, as in the original.
        assert_eq!(service_from_plain(&plain_of(8, b"\x0a\x04ab\x99")), Ok(&b"ab"[..]));
        assert_eq!(c_string(b"ab\0cd"), b"ab");
        assert_eq!(c_string(b"abc"), b"abc");
        assert_eq!(c_string(b"\0"), b"");
    }

    #[test]
    fn heartbeat_reply_flag() {
        assert!(heartbeat_accepted(&plain_of(4, b"\0\0\x01")));
        assert!(heartbeat_accepted(&plain_of(4, b"\0\0\x80")));
        assert!(!heartbeat_accepted(&plain_of(4, b"\0\0\x00")));
        assert!(!heartbeat_accepted(&plain_of(4, b"")));
    }

    /// Small deterministic generator for the robustness tests.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    fn parse_everything(wire: &[u8]) {
        let _ = unseal(wire);
        for check in [ResponseCheck::Strict, ResponseCheck::Firmware] {
            for max in [FIRMWARE_DISCOVERY_MAX, FIRMWARE_REPLY_MAX] {
                if let Ok(plain) = open_response(wire, check, max) {
                    let _ = server_from_discovery(&plain);
                    let _ = service_from_plain(&plain);
                    let _ = login_reply(&plain);
                    let _ = heartbeat_accepted(&plain);
                    let _ = parse_tlvs(&plain[HEADER_LEN..]);
                }
            }
        }
        let _ = parse_tlvs(wire);
        let _ = service_from_response(wire);
        let _ = session_from_login_response(wire);
        let _ = server_from_discovery(wire);
        let _ = login_reply(wire);
        let _ = service_from_plain(wire);
    }

    #[test]
    fn truncation_never_panics_and_is_rejected() {
        let samples = [
            discovery(IP, &MAC).unwrap(),
            service_query(&MAC).unwrap(),
            login(b"alice", b"synthetic", IP, b"campus", &MAC).unwrap(),
            heartbeat(b"session", IP, &MAC, INITIAL_COUNTER).unwrap(),
            seal(2, b"\0\0\x01\x08\x03abc").unwrap(),
            seal(8, &tlv(10, b"campus").unwrap()).unwrap(),
        ];
        for wire in &samples {
            for cut in 0..wire.len() {
                let prefix = &wire[..cut];
                assert!(unseal(prefix).is_err(), "prefix {} accepted", cut);
                assert!(open_response(prefix, ResponseCheck::Strict, FIRMWARE_REPLY_MAX).is_err());
                parse_everything(prefix);
            }
            let plain = decode(wire);
            for cut in 0..plain.len() - HEADER_LEN {
                let _ = parse_tlvs(&plain[HEADER_LEN..HEADER_LEN + cut]);
            }
        }
    }

    #[test]
    fn bit_flips_break_digest_or_framing() {
        let wire = login(b"alice", b"synthetic", IP, b"campus", &MAC).unwrap();
        for i in 0..wire.len() {
            for bit in 0..8 {
                let mut damaged = wire.clone();
                damaged[i] ^= 1 << bit;
                match unseal(&damaged) {
                    Ok(p) => assert!(!p.digest_valid, "flip {}:{} kept a valid digest", i, bit),
                    Err(CodecError::LengthMismatch { .. }) => assert_eq!(i, 1),
                    Err(e) => panic!("unexpected {:?}", e),
                }
                assert!(open_response(&damaged, ResponseCheck::Strict, FIRMWARE_REPLY_MAX).is_err());
                parse_everything(&damaged);
            }
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut rng = Lcg(0x5eed);
        for round in 0..4000 {
            let len = (rng.next() as usize + rng.next() as usize) % 300;
            let mut data: Vec<u8> = (0..len).map(|_| rng.next()).collect();
            // Half of the inputs get a plausible header so deeper paths run.
            if round % 2 == 0 && (HEADER_LEN..=MAX_PACKET_LEN).contains(&len) {
                let mut plain = decode(&data);
                plain[1] = len as u8;
                let sum = digest(&plain);
                plain[2..HEADER_LEN].copy_from_slice(&sum);
                data = encode(&plain);
                assert!(unseal(&data).unwrap().digest_valid);
            }
            parse_everything(&data);
        }
    }
}
