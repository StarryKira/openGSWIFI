//! Wire format of the GS "version 2" H3C Portal (research doc 13.5–13.8,
//! 29.1–29.3, 29.5).
//!
//! Every message is a UDP payload with a 32-byte header and TLV
//! attributes:
//!
//! | offset | size | field |
//! |---:|---:|---|
//! | 0 | 1 | version = 2 |
//! | 1 | 1 | message type (100..123, *not* standard Portal 1..8) |
//! | 2 | 1 | auth type (0 in every client message) |
//! | 3 | 1 | reserved |
//! | 4 | 2 | serial, two raw bytes |
//! | 6 | 2 | request id (0 in every client message) |
//! | 8 | 4 | user IPv4, network order |
//! | 12 | 2 | port |
//! | 14 | 1 | error |
//! | 15 | 1 | attribute count |
//! | 16 | 16 | authenticator `MD5(header with zero authenticator ‖ attributes ‖ "hello")` |
//!
//! Attributes are `type:u8 | total_length:u8 | value`, the length counting
//! the two header bytes; values are limited to 253 bytes here (the original
//! writes `len + 2` into a byte and overflows at 254/255, doc 13.5).
//! Message and attribute names below describe the role observed in the
//! replayed exchange (doc 29.2, 29.3); they are not standard Portal names.

pub mod block;
pub mod check;

use std::fmt;

/// Protocol version byte.
pub const VERSION: u8 = 2;
/// Header size.
pub const HEADER_LEN: usize = 32;
/// Suffix of the authenticator input (fixed protocol material, doc 13.6).
pub const SEAL_SUFFIX: &[u8] = b"hello";
/// Largest attribute value.
pub const MAX_VALUE: usize = 253;

/// Client → server: identity/login (doc 13.7).
pub const MSG_LOGIN: u8 = 100;
/// Server → client: authentication result; success when it carries
/// attribute 100 (doc 29.2).
pub const MSG_RESULT: u8 = 101;
/// Client → server: logoff (doc 29.3).
pub const MSG_LOGOFF: u8 = 102;
/// Client → server: online keepalive (doc 29.3).
pub const MSG_ONLINE: u8 = 104;
/// Server → client: online answer with timer/challenge (doc 29.2).
pub const MSG_ONLINE_ACK: u8 = 105;
/// Client → server: information/discovery request (doc 13.6).
pub const MSG_DISCOVERY: u8 = 110;
/// Server → client: discovery answer, triggers the login (doc 29.2).
pub const MSG_DISCOVERY_ACK: u8 = 111;
/// Server → client: password/challenge stage (doc 29.2).
pub const MSG_CHALLENGE: u8 = 121;
/// Client → server: challenge response (doc 29.3).
pub const MSG_CHALLENGE_RESPONSE: u8 = 122;

/// Login inner version block: TLV 1 = Base64(mixed20), TLV 255 = MAC text.
pub const ATTR_VERSION_INFO: u8 = 33;
/// Constant `01` in the login (meaning unknown, doc 13.7).
pub const ATTR_LOGIN_FLAG: u8 = 56;
/// Constant `01` at the end of 104 (doc 29.3; doc 23 wrongly said 32).
pub const ATTR_ONLINE_FLAG: u8 = 96;
/// Session value: success marker in 101, echoed in 104 and 102.
pub const ATTR_SESSION: u8 = 100;
/// Login: 32-byte text version field followed by the username.
pub const ATTR_USER: u8 = 101;
/// Login: password (plain or block transformed).
pub const ATTR_PASSWORD: u8 = 102;
/// User IPv4 (first of the two IP attributes in 110).
pub const ATTR_IP_103: u8 = 103;
/// User IPv4 (second).
pub const ATTR_IP_104: u8 = 104;
/// Server → client: next timer in milliseconds, BE64.
pub const ATTR_TIMER_MS: u8 = 109;
/// BE32 stamp (login and 104).
pub const ATTR_STAMP: u8 = 113;
/// Server blob from 101, echoed in 104 with ASCII `0.0.0.0` appended.
pub const ATTR_AUTH_BLOB: u8 = 114;
/// Server text, displayable; not a proven error code enumeration.
pub const ATTR_SERVER_TEXT: u8 = 115;
/// 104 constant `00000001`.
pub const ATTR_ONLINE_120: u8 = 120;
/// 104 constant `00000000`.
pub const ATTR_ONLINE_122: u8 = 122;
/// 104 constant `63`.
pub const ATTR_ONLINE_125: u8 = 125;
/// 104 user IPv4.
pub const ATTR_IP_126: u8 = 126;
/// 104 user IPv4.
pub const ATTR_IP_127: u8 = 127;
/// Server challenge for the client check.
pub const ATTR_CHALLENGE: u8 = 130;
/// Client check result (32 bytes).
pub const ATTR_CHECK: u8 = 131;

/// Malformed input or a value that does not fit the format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Shorter than the header or an attribute runs past the end.
    Truncated,
    /// Version byte is not 2.
    Version(u8),
    /// Attribute length below 2.
    AttributeLength { kind: u8, len: u8 },
    /// Bytes after the announced attributes.
    TrailingBytes(usize),
    /// Attribute value longer than 253 bytes.
    ValueTooLong { kind: u8, len: usize },
    /// More than 255 attributes.
    TooManyAttributes,
    /// Other precondition.
    Invalid(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Truncated => f.write_str("报文被截断"),
            CodecError::Version(v) => write!(f, "协议版本 {} 不是 2", v),
            CodecError::AttributeLength { kind, len } => write!(f, "属性 {} 长度 {} 无效", kind, len),
            CodecError::TrailingBytes(n) => write!(f, "属性之后多出 {} 字节", n),
            CodecError::ValueTooLong { kind, len } => write!(f, "属性 {} 的值长 {} 字节，超过 253", kind, len),
            CodecError::TooManyAttributes => f.write_str("属性超过 255 个"),
            CodecError::Invalid(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for CodecError {}

/// Parsed common header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kind: u8,
    pub auth_type: u8,
    pub reserved: u8,
    pub serial: [u8; 2],
    pub request_id: u16,
    pub user_ip: [u8; 4],
    pub port: u16,
    pub error: u8,
    pub attr_count: u8,
    pub authenticator: [u8; 16],
}

impl Header {
    /// Reads the header; checks the length and the version byte only.
    pub fn parse(body: &[u8]) -> Result<Header, CodecError> {
        if body.len() < HEADER_LEN {
            return Err(CodecError::Truncated);
        }
        if body[0] != VERSION {
            return Err(CodecError::Version(body[0]));
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&body[16..32]);
        Ok(Header {
            version: body[0],
            kind: body[1],
            auth_type: body[2],
            reserved: body[3],
            serial: [body[4], body[5]],
            request_id: u16::from_be_bytes([body[6], body[7]]),
            user_ip: [body[8], body[9], body[10], body[11]],
            port: u16::from_be_bytes([body[12], body[13]]),
            error: body[14],
            attr_count: body[15],
            authenticator,
        })
    }
}

/// Appends one attribute.
pub fn push_attribute(out: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), CodecError> {
    if value.len() > MAX_VALUE {
        return Err(CodecError::ValueTooLong { kind, len: value.len() });
    }
    out.push(kind);
    out.push(value.len() as u8 + 2);
    out.extend_from_slice(value);
    Ok(())
}

/// Parses exactly `attr_count` attributes and requires them to end the
/// body. The original parser (`0x41bc08`) only follows the count; this
/// one also checks every length (doc 13.5).
pub fn parse_attributes(body: &[u8]) -> Result<Vec<(u8, &[u8])>, CodecError> {
    let header = Header::parse(body)?;
    let mut pos = HEADER_LEN;
    let mut attrs = Vec::with_capacity(header.attr_count as usize);
    for _ in 0..header.attr_count {
        let (kind, len) = match body.get(pos..pos + 2) {
            Some(&[k, l]) => (k, l),
            _ => return Err(CodecError::Truncated),
        };
        if len < 2 {
            return Err(CodecError::AttributeLength { kind, len });
        }
        let end = pos + len as usize;
        let value = body.get(pos + 2..end).ok_or(CodecError::Truncated)?;
        attrs.push((kind, value));
        pos = end;
    }
    if pos != body.len() {
        return Err(CodecError::TrailingBytes(body.len() - pos));
    }
    Ok(attrs)
}

/// First value of `kind` (duplicates: the first one wins, like the
/// research reference).
pub fn attribute<'a>(attrs: &[(u8, &'a [u8])], kind: u8) -> Option<&'a [u8]> {
    attrs.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
}

fn authenticator(body: &[u8]) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    ctx.consume(&body[..16]);
    ctx.consume([0u8; 16]);
    ctx.consume(&body[32..]);
    ctx.consume(SEAL_SUFFIX);
    ctx.compute().0
}

/// Writes the authenticator: `MD5(body[..16] ‖ zero16 ‖ body[32..] ‖
/// "hello")` into `body[16..32]` (doc 13.6, 29.1). Any previous value is
/// ignored. Not an HMAC and no protection against an active attacker.
pub fn seal(body: &mut [u8]) -> Result<(), CodecError> {
    if body.len() < HEADER_LEN {
        return Err(CodecError::Truncated);
    }
    let a = authenticator(body);
    body[16..32].copy_from_slice(&a);
    Ok(())
}

/// Whether `body` carries the authenticator [`seal`] would write. The
/// original receive path does not check it (doc 29.1), and whether real
/// servers seal with `hello` is not documented.
pub fn verify(body: &[u8]) -> bool {
    body.len() >= HEADER_LEN && body[16..32] == authenticator(body)
}

/// Builds and seals a client message (auth type, request id, port and
/// error zero, as in every recovered client frame).
pub fn packet(kind: u8, serial: [u8; 2], user_ip: [u8; 4], attrs: &[(u8, &[u8])]) -> Result<Vec<u8>, CodecError> {
    if attrs.len() > 255 {
        return Err(CodecError::TooManyAttributes);
    }
    let mut body = Vec::with_capacity(HEADER_LEN + attrs.iter().map(|(_, v)| v.len() + 2).sum::<usize>());
    body.extend_from_slice(&[VERSION, kind, 0, 0, serial[0], serial[1], 0, 0]);
    body.extend_from_slice(&user_ip);
    body.extend_from_slice(&[0, 0, 0, attrs.len() as u8]);
    body.extend_from_slice(&[0; 16]);
    for (k, v) in attrs {
        push_attribute(&mut body, *k, v)?;
    }
    seal(&mut body)?;
    Ok(body)
}

/// 110 discovery: attributes 103 and 104 with the user IP (doc 13.6).
pub fn discovery(user_ip: [u8; 4], serial: [u8; 2]) -> Result<Vec<u8>, CodecError> {
    packet(MSG_DISCOVERY, serial, user_ip, &[(ATTR_IP_103, &user_ip), (ATTR_IP_104, &user_ip)])
}

/// Inputs of the 100 login.
#[derive(Clone, Copy, Debug)]
pub struct Login<'a> {
    pub user_ip: [u8; 4],
    pub serial: [u8; 2],
    pub mac: [u8; 6],
    pub username: &'a [u8],
    pub password: &'a [u8],
    /// iNode `mixed20` (gswifi-inode).
    pub mixed_version: &'a [u8; 20],
    /// Attribute 113 value.
    pub stamp: u32,
    /// `UsePlainTextPass`.
    pub plain_password: bool,
}

/// Upper-case colon separated MAC, as in the login's inner TLV 255.
pub fn mac_text(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

/// 100 login (doc 13.7), seven attributes in this order:
///
/// | type | value |
/// |---:|---|
/// | 33 | inner TLV 1 = Base64(mixed20), inner TLV 255 = MAC text |
/// | 104 | user IP |
/// | 103 | user IP |
/// | 101 | 32-byte text version field ‖ username |
/// | 102 | password, plain or [`block::password_value`] |
/// | 56 | `01` |
/// | 113 | BE32 stamp |
pub fn login(l: &Login) -> Result<Vec<u8>, CodecError> {
    let mut inner = Vec::with_capacity(51);
    push_attribute(&mut inner, 1, gswifi_inode::mixed::base64_version(l.mixed_version).as_bytes())?;
    push_attribute(&mut inner, 255, mac_text(&l.mac).as_bytes())?;
    let mut user = gswifi_inode::mixed::text_field(l.mixed_version).to_vec();
    user.extend_from_slice(l.username);
    let password = block::password_value(l.password, l.plain_password)?;
    let stamp = l.stamp.to_be_bytes();
    packet(
        MSG_LOGIN,
        l.serial,
        l.user_ip,
        &[
            (ATTR_VERSION_INFO, &inner),
            (ATTR_IP_104, &l.user_ip),
            (ATTR_IP_103, &l.user_ip),
            (ATTR_USER, &user),
            (ATTR_PASSWORD, &password),
            (ATTR_LOGIN_FLAG, &[1]),
            (ATTR_STAMP, &stamp),
        ],
    )
}

/// 122 challenge response: optional 131, then 104 and 103 (doc 29.3).
pub fn challenge_response(user_ip: [u8; 4], serial: [u8; 2], check: Option<&[u8; 32]>) -> Result<Vec<u8>, CodecError> {
    let mut attrs: Vec<(u8, &[u8])> = Vec::with_capacity(3);
    if let Some(c) = check {
        attrs.push((ATTR_CHECK, c));
    }
    attrs.push((ATTR_IP_104, &user_ip));
    attrs.push((ATTR_IP_103, &user_ip));
    packet(MSG_CHALLENGE_RESPONSE, serial, user_ip, &attrs)
}

/// Session values of the 104 keepalive.
#[derive(Clone, Copy, Debug, Default)]
pub struct Online<'a> {
    /// Final 114 value (server blob already followed by `0.0.0.0`).
    pub auth_blob: Option<&'a [u8]>,
    /// Attribute 100 from the success message.
    pub session: Option<&'a [u8]>,
    pub stamp: u32,
    /// Attribute 131 from the cached challenge.
    pub check: Option<&'a [u8; 32]>,
}

/// 104 keepalive (doc 29.3): 127, 126, 104, 103 (user IP), optional 114,
/// optional 100, 113 stamp, 122 `00000000`, 120 `00000001`, 125 `63`,
/// 96 `01`, optional 131.
pub fn online(user_ip: [u8; 4], serial: [u8; 2], o: &Online) -> Result<Vec<u8>, CodecError> {
    let stamp = o.stamp.to_be_bytes();
    let mut attrs: Vec<(u8, &[u8])> =
        vec![(ATTR_IP_127, &user_ip), (ATTR_IP_126, &user_ip), (ATTR_IP_104, &user_ip), (ATTR_IP_103, &user_ip)];
    if let Some(b) = o.auth_blob {
        attrs.push((ATTR_AUTH_BLOB, b));
    }
    if let Some(s) = o.session {
        attrs.push((ATTR_SESSION, s));
    }
    attrs.extend_from_slice(&[
        (ATTR_STAMP, &stamp),
        (ATTR_ONLINE_122, &[0, 0, 0, 0]),
        (ATTR_ONLINE_120, &[0, 0, 0, 1]),
        (ATTR_ONLINE_125, &[0x63]),
        (ATTR_ONLINE_FLAG, &[1]),
    ]);
    if let Some(c) = o.check {
        attrs.push((ATTR_CHECK, c));
    }
    packet(MSG_ONLINE, serial, user_ip, &attrs)
}

/// The 114 value the original sends back: server value ‖ ASCII `0.0.0.0`
/// without NUL (doc 29.3). `None` when it would not fit an attribute.
pub fn auth_blob_value(server_value: &[u8]) -> Option<Vec<u8>> {
    let mut v = server_value.to_vec();
    v.extend_from_slice(b"0.0.0.0");
    (v.len() <= MAX_VALUE).then_some(v)
}

/// 102 logoff: 104, 103 and the optional session value (doc 29.3).
///
/// GS caches the session length *including* the TLV header and uses it
/// as the value length here, so the original sends two extra bytes from
/// the neighbouring cache (zero in the research run). Pass
/// [`logoff_session_value`] output to reproduce the observed bytes.
pub fn logoff(user_ip: [u8; 4], serial: [u8; 2], session: Option<&[u8]>) -> Result<Vec<u8>, CodecError> {
    let mut attrs: Vec<(u8, &[u8])> = vec![(ATTR_IP_104, &user_ip), (ATTR_IP_103, &user_ip)];
    if let Some(s) = session {
        attrs.push((ATTR_SESSION, s));
    }
    packet(MSG_LOGOFF, serial, user_ip, &attrs)
}

/// Session value for [`logoff`]: as received, or with the GS length defect
/// modelled deterministically as two zero bytes (doc 29.3). The real
/// trailing bytes are whatever follows in the original's cache.
pub fn logoff_session_value(session: &[u8], gs_length_quirk: bool) -> Vec<u8> {
    let mut v = session.to_vec();
    if gs_length_quirk && v.len() + 2 <= MAX_VALUE {
        v.extend_from_slice(&[0, 0]);
    }
    v
}

/// What a server message means for the client (doc 29.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    /// 111: go to the login stage.
    DiscoveryAck,
    /// 121: go to the challenge stage; `challenge` is attribute 130.
    Challenge { challenge: Option<&'a [u8]> },
    /// 101 with attribute 100: authenticated.
    Success { session: &'a [u8], auth_blob: Option<&'a [u8]> },
    /// 101 without attribute 100: refused while authenticating, dropped
    /// while online.
    Failure,
    /// 105: optional new challenge (130) and next timer (109, ms; `Some(0)`
    /// when present but zero, `None` when absent).
    OnlineAck { challenge: Option<&'a [u8]>, timer_ms: Option<u64> },
    /// Anything else. GS reacts to no other type; no meaning is invented
    /// for them (doc 29.2, 29.7). 103 in particular is *not* "forced
    /// offline".
    Unknown { kind: u8 },
}

/// A parsed server message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub header: Header,
    pub message: Message<'a>,
    /// Attribute 115, if any.
    pub text: Option<&'a [u8]>,
}

fn timer_value(v: &[u8]) -> Result<u64, CodecError> {
    if v.len() > 8 {
        return Err(CodecError::Invalid("属性 109 超过 8 字节"));
    }
    Ok(v.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
}

/// Parses a server message: header, attributes (strictly), then the
/// meaning. Authenticator, serial and source checks are the caller's.
pub fn parse_message(body: &[u8]) -> Result<Received<'_>, CodecError> {
    let header = Header::parse(body)?;
    let attrs = parse_attributes(body)?;
    let text = attribute(&attrs, ATTR_SERVER_TEXT);
    let message = match header.kind {
        MSG_DISCOVERY_ACK => Message::DiscoveryAck,
        MSG_CHALLENGE => Message::Challenge { challenge: attribute(&attrs, ATTR_CHALLENGE) },
        MSG_RESULT => match attribute(&attrs, ATTR_SESSION) {
            Some(session) => Message::Success { session, auth_blob: attribute(&attrs, ATTR_AUTH_BLOB) },
            None => Message::Failure,
        },
        MSG_ONLINE_ACK => Message::OnlineAck {
            challenge: attribute(&attrs, ATTR_CHALLENGE),
            timer_ms: attribute(&attrs, ATTR_TIMER_MS).map(timer_value).transpose()?,
        },
        kind => Message::Unknown { kind },
    };
    Ok(Received { header, message, text })
}

/// The original receive dispatch as numeric actions (doc 29.2), for
/// comparison with the 88 recorded original reactions. States are the GS
/// ones: 1 discovery, 2 identity, 3 challenge, 4 online, 6 online variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveAction {
    /// Enter this GS state.
    State(u8),
    /// Set the timer to this many seconds (0: no timer).
    Timer(u64),
    /// Authentication failure: the failure/restart path with MaxFail.
    Reconnect,
}

/// GS reaction to `body` in GS `state`: 111 → state 2; 121 → state 3; 101
/// with 100 → state 4, without → state 1 when online (4/6) else
/// reconnect; 105 → timer `109 / 1000` s (0 without 109); others nothing.
pub fn receive(body: &[u8], state: u8) -> Result<Vec<ReceiveAction>, CodecError> {
    let r = parse_message(body)?;
    Ok(match r.message {
        Message::DiscoveryAck => vec![ReceiveAction::State(2)],
        Message::Challenge { .. } => vec![ReceiveAction::State(3)],
        Message::Success { .. } => vec![ReceiveAction::State(4)],
        Message::Failure if state == 4 || state == 6 => vec![ReceiveAction::State(1)],
        Message::Failure => vec![ReceiveAction::Reconnect],
        Message::OnlineAck { timer_ms, .. } => vec![ReceiveAction::Timer(timer_ms.unwrap_or(0) / 1000)],
        Message::Unknown { .. } => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: [u8; 4] = [192, 0, 2, 10];

    #[test]
    fn parser_boundaries() {
        let body = discovery(IP, [0x12, 0x34]).unwrap();
        assert_eq!(parse_attributes(&body).unwrap(), vec![(103, &IP[..]), (104, &IP[..])]);
        assert_eq!(parse_attributes(&body[..31]), Err(CodecError::Truncated));
        assert_eq!(parse_attributes(&body[..body.len() - 1]), Err(CodecError::Truncated));
        let mut bad = body.clone();
        bad[33] = 1;
        assert_eq!(parse_attributes(&bad), Err(CodecError::AttributeLength { kind: 103, len: 1 }));
        let mut long = body.clone();
        long.push(0);
        assert_eq!(parse_attributes(&long), Err(CodecError::TrailingBytes(1)));
        let mut v1 = body.clone();
        v1[0] = 1;
        assert_eq!(parse_attributes(&v1), Err(CodecError::Version(1)));
        let mut out = Vec::new();
        assert!(push_attribute(&mut out, 1, &[0; 254]).is_err());
        assert!(push_attribute(&mut out, 1, &[0; 253]).is_ok());
    }

    #[test]
    fn seal_and_verify() {
        let mut body = discovery(IP, [0x12, 0x34]).unwrap();
        assert!(verify(&body));
        body[20] ^= 1;
        assert!(!verify(&body));
        seal(&mut body).unwrap();
        assert!(verify(&body));
        assert!(seal(&mut [0u8; 31]).is_err());
        assert!(!verify(&[0u8; 31]));
    }

    #[test]
    fn timer_attribute() {
        assert_eq!(timer_value(&[0, 0, 0, 0, 0, 0, 0x75, 0x30]), Ok(30000));
        assert!(timer_value(&[0; 9]).is_err());
    }

    #[test]
    fn logoff_quirk_and_blob() {
        assert_eq!(logoff_session_value(&[1, 2, 3, 4], true), vec![1, 2, 3, 4, 0, 0]);
        assert_eq!(logoff_session_value(&[1, 2, 3, 4], false), vec![1, 2, 3, 4]);
        assert_eq!(auth_blob_value(b"ABC").unwrap(), b"ABC0.0.0.0");
        assert!(auth_blob_value(&[0; 247]).is_none());
    }
}
