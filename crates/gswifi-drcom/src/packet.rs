//! UDP payload codecs of the Dr.com D (DHCP) and P (PPPoE helper) exchanges.
//!
//! Layouts follow doc 03 §3.2–3.5 (Dogcom 1.6.2 as described from the
//! public upstream, grade U) and, where marked, the GS MentoHUST frames of
//! doc 30.3 (`evidence/session/dr-session-*.pcap`, grade D). Offsets are
//! relative to the UDP payload. All builders validate their inputs and all
//! parsers check lengths, so malformed datagrams return [`Error`] instead of
//! panicking (doc 03 §3.7: upstream reads fixed offsets after `recvfrom`).

use crate::primitives::{check16, check32, checksum1968, gen_crc, md5a, md5b, ror_password, FALLBACK_CRC};
use crate::Error;

/// Default UDP port of the Dr.com server; the client binds it too (doc 03 §3.1).
pub const DRCOM_PORT: u16 = 61440;

fn need(what: &'static str, body: &[u8], n: usize) -> Result<(), Error> {
    if body.len() < n {
        Err(Error::Truncated { what, need: n, got: body.len() })
    } else {
        Ok(())
    }
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[..N]);
    out
}

// ---------------------------------------------------------------------------
// Challenge (doc 03 §3.2)
// ---------------------------------------------------------------------------

/// Second byte of the Dogcom login challenge (doc 03 §3.2: offset1 = 02).
pub const CHALLENGE_DOGCOM_LOGIN: u8 = 0x02;
/// Second byte of the GS login challenge (doc 30.3 frames: `01 00 ...`).
pub const CHALLENGE_GS_LOGIN: u8 = 0x00;
/// Second byte of the GS logoff challenge (doc 30.3 frames: `01 01 ...`).
pub const CHALLENGE_GS_LOGOFF: u8 = 0x01;

/// 20-byte challenge request: `01 kind rand2 auth_version[0]`, rest zero
/// (doc 03 §3.2; GS frames in doc 30.3 use the same layout with kind 00/01).
pub fn challenge_request(kind: u8, random: [u8; 2], auth_version0: u8) -> [u8; 20] {
    let mut p = [0u8; 20];
    p[0] = 0x01;
    p[1] = kind;
    p[2..4].copy_from_slice(&random);
    p[4] = auth_version0;
    p
}

/// Parses the challenge response: first byte `02`, seed at `[4:8]`
/// (doc 03 §3.2). Doc 03 asks to check length as well as the first byte.
pub fn parse_challenge_response(body: &[u8]) -> Result<[u8; 4], Error> {
    need("challenge response", body, 8)?;
    if body[0] != 0x02 {
        return Err(Error::Unexpected { what: "challenge response", code: body[0] });
    }
    Ok(arr(&body[4..8]))
}

// ---------------------------------------------------------------------------
// Login (doc 03 §3.2, doc 30.3 frames)
// ---------------------------------------------------------------------------

/// Windows `OSVERSIONINFO` fields written as five LE32 at `[162:182]`
/// (doc 03 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsVersion {
    pub info_size: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
}

impl Default for OsVersion {
    /// Values seen in the GS D frames of doc 30.3 (0x94, 6.2.9200, platform 2).
    fn default() -> Self {
        OsVersion { info_size: 0x94, major: 6, minor: 2, build: 9200, platform_id: 2 }
    }
}

/// Which client produced the login body. The fields at `[0:312]` are the
/// same; the checksums and the trailer differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginLayout {
    /// Doc 03 §3.2 (grade U): checksum1 = `MD5(p[0:97] || 14 00 07 0b)[0:8]`,
    /// checksum2 (1234/1968) written at `c+2`, trailer `e9 13`.
    Dogcom,
    /// GS MentoHUST AuthType 3 as captured in doc 30.3 (grade D, verified
    /// byte for byte by the tests): checksum1 = `MD5(p[0:97])[0:8]`, the six
    /// bytes at `c+2` stay `01 26 07 11 00 00`, and the 2-byte trailer is
    /// [`check16`] of the whole body with the trailer zeroed.
    Gs,
}

/// Inputs of the login body. Field limits follow doc 03 §3.2: the username
/// and host name must not run into the fixed fields that follow them.
#[derive(Clone, Debug)]
pub struct LoginParams<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub seed: [u8; 4],
    pub mac: [u8; 6],
    pub host_ip: [u8; 4],
    /// `CONTROLCHECKSTATUS`, offset 56.
    pub control_check_status: u8,
    /// `ADAPTERNUM`, offset 57.
    pub adapter_num: u8,
    /// `IPDOG`, offset 105.
    pub ip_dog: u8,
    /// Offset 110, at most 32 bytes.
    pub host_name: &'a [u8],
    /// Offset 142.
    pub primary_dns: [u8; 4],
    /// Offset 146.
    pub dhcp_server: [u8; 4],
    pub os: OsVersion,
    /// Offset 182, at most 128 bytes (`host_os` or vendor bytes).
    pub host_os: &'a [u8],
    /// `AUTH_VERSION`, offset 310.
    pub auth_version: [u8; 2],
    /// Append the ROL password extension (Dogcom `ror_version`).
    pub ror: bool,
}

/// Longest username that leaves offset 56 intact (doc 03 §3.2).
pub const MAX_USERNAME: usize = 36;
/// Longest host name that leaves offset 142 intact.
pub const MAX_HOST_NAME: usize = 32;
/// Size of the host_os area `[182:310]`.
pub const MAX_HOST_OS: usize = 128;
/// Longest password accepted without the ror extension (GS keeps an 80-byte
/// C buffer, doc 14.1 tested up to 79).
pub const MAX_PASSWORD: usize = 79;

/// Encoded login body plus the MD5A that keepalive1 reuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub body: Vec<u8>,
    pub md5a: [u8; 16],
}

/// Builds the login body (doc 03 §3.2 table).
///
/// Trailer: after `AUTH_VERSION` comes the optional ror extension
/// (`00`, password length, ROL bytes — layout as in the GS frame of doc
/// 30.3), then at offset `c`: `02 0c`, six bytes at `c+2`, the MAC at
/// `c+8`, zero padding up to the next multiple of 4, and a 2-byte trailer.
/// This yields the 330-byte non-ror length of doc 03 §3.2 and the 342-byte
/// GS frame for a 9-byte password.
// doc 03 §3.2: "ror base 338, plus long-password/JLU padding" is not given
// as a formula; the 4-byte rounding above reproduces 330 and the GS frame
// but is unverified against Dogcom for other password lengths.
pub fn login(p: &LoginParams<'_>, layout: LoginLayout) -> Result<Login, Error> {
    if p.username.len() > MAX_USERNAME {
        return Err(Error::Invalid(format!(
            "username is {} bytes, at most {MAX_USERNAME} fit the login body",
            p.username.len()
        )));
    }
    if p.host_name.len() > MAX_HOST_NAME {
        return Err(Error::Invalid(format!("host name longer than {MAX_HOST_NAME} bytes")));
    }
    if p.host_os.len() > MAX_HOST_OS {
        return Err(Error::Invalid(format!("host_os longer than {MAX_HOST_OS} bytes")));
    }
    if p.password.len() > MAX_PASSWORD {
        return Err(Error::Invalid(format!("password longer than {MAX_PASSWORD} bytes")));
    }
    let a = md5a(p.seed, p.password);
    let ror = if p.ror { Some(ror_password(&a, p.password)?) } else { None };

    let c = 312 + ror.as_ref().map_or(0, |r| 2 + r.len());
    let padded = (c + 14).div_ceil(4) * 4;
    let mut b = vec![0u8; padded + 2];

    b[0..3].copy_from_slice(&[0x03, 0x01, 0x00]);
    b[3] = (p.username.len() + 20) as u8;
    b[4..20].copy_from_slice(&a);
    b[20..20 + p.username.len()].copy_from_slice(p.username);
    b[56] = p.control_check_status;
    b[57] = p.adapter_num;
    for i in 0..6 {
        b[58 + i] = p.mac[i] ^ a[i];
    }
    b[64..80].copy_from_slice(&md5b(p.seed, p.password));
    b[80] = 0x01; // number of IPv4 addresses
    b[81..85].copy_from_slice(&p.host_ip);
    // [85:97] further addresses: zero (doc 03 §3.2 lists only one).
    let mut ctx = md5::Context::new();
    ctx.consume(&b[0..97]);
    if layout == LoginLayout::Dogcom {
        ctx.consume([0x14, 0x00, 0x07, 0x0b]);
    }
    b[97..105].copy_from_slice(&ctx.compute().0[..8]);
    b[105] = p.ip_dog;
    b[110..110 + p.host_name.len()].copy_from_slice(p.host_name);
    b[142..146].copy_from_slice(&p.primary_dns);
    b[146..150].copy_from_slice(&p.dhcp_server);
    // [150:162]: secondary DNS / WINS, zero in doc 03 and in the GS frames.
    let os = [p.os.info_size, p.os.major, p.os.minor, p.os.build, p.os.platform_id];
    for (i, v) in os.iter().enumerate() {
        b[162 + i * 4..166 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    b[182..182 + p.host_os.len()].copy_from_slice(p.host_os);
    b[310..312].copy_from_slice(&p.auth_version);
    if let Some(r) = &ror {
        b[312] = 0x00;
        b[313] = r.len() as u8;
        b[314..314 + r.len()].copy_from_slice(r);
    }
    b[c..c + 2].copy_from_slice(&[0x02, 0x0c]);
    b[c + 2..c + 8].copy_from_slice(&[0x01, 0x26, 0x07, 0x11, 0x00, 0x00]);
    b[c + 8..c + 14].copy_from_slice(&p.mac);
    match layout {
        LoginLayout::Dogcom => {
            let sum = checksum1968(&b[..padded])?;
            b[c + 2..c + 6].copy_from_slice(&sum);
            b[padded..padded + 2].copy_from_slice(&[0xe9, 0x13]);
            // doc 03 §3.2: the JLU trailer `60 a2` belongs to the JLU layout,
            // which the docs do not specify; it is not offered.
        }
        LoginLayout::Gs => {
            let sum = check16(&b)?;
            b[padded..padded + 2].copy_from_slice(&sum);
        }
    }
    Ok(Login { body: b, md5a: a })
}

/// Server answer to the login (doc 03 §3.2 "登录响应").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginReply {
    /// `04`: 16 bytes of auth_information from `[23:39]`.
    Success { auth_info: [u8; 16] },
    /// `05`: reason code at offset 4 (texts: [`crate::gs::error_text`]).
    Failure { code: u8 },
}

/// Parses a login reply; anything but `04`/`05` is [`Error::Unexpected`].
pub fn parse_login_reply(body: &[u8]) -> Result<LoginReply, Error> {
    need("login reply", body, 1)?;
    match body[0] {
        0x04 => {
            need("login success", body, 39)?;
            Ok(LoginReply::Success { auth_info: arr(&body[23..39]) })
        }
        0x05 => {
            need("login failure", body, 5)?;
            Ok(LoginReply::Failure { code: body[4] })
        }
        code => Err(Error::Unexpected { what: "login reply", code }),
    }
}

// ---------------------------------------------------------------------------
// keepalive1 (doc 03 §3.3)
// ---------------------------------------------------------------------------

/// Length of the Dogcom keepalive1 (doc 03 §3.3: "普通模式42字节").
pub const KEEPALIVE1_DOGCOM_LEN: usize = 42;
/// Length of the GS keepalive1 (doc 30.3 frames: 38 bytes).
pub const KEEPALIVE1_GS_LEN: usize = 38;

/// keepalive1: `ff`, MD5A at `[1:17]`, auth_information at `[20:36]`,
/// 2 random bytes at `[36:38]`, rest zero; `len` is 42 (Dogcom) or 38 (GS).
pub fn keepalive1(md5a: &[u8; 16], auth_info: &[u8; 16], random: [u8; 2], len: usize) -> Result<Vec<u8>, Error> {
    if len < 38 {
        return Err(Error::Invalid(format!("keepalive1 needs at least 38 bytes, got {len}")));
    }
    let mut p = vec![0u8; len];
    p[0] = 0xff;
    p[1..17].copy_from_slice(md5a);
    p[20..36].copy_from_slice(auth_info);
    p[36..38].copy_from_slice(&random);
    Ok(p)
}

/// First packet of `keepalive1_mod`: `07 counter 08 00 01 00 00 00`
/// (doc 03 §3.3 shows counter 01; the GS frames of doc 30.3 count 01, 02 …).
pub fn keepalive1_mod_request(counter: u8) -> [u8; 8] {
    [0x07, counter, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00]
}

/// Seed from the `keepalive1_mod` answer, `[8:12]` (doc 03 §3.3).
pub fn parse_keepalive1_mod_seed(body: &[u8]) -> Result<[u8; 4], Error> {
    need("keepalive1_mod seed", body, 12)?;
    if body[0] != 0x07 {
        return Err(Error::Unexpected { what: "keepalive1_mod seed", code: body[0] });
    }
    Ok(arr(&body[8..12]))
}

/// Second `keepalive1_mod` packet (38 bytes): `ff`, seed at `[8:12]`,
/// `gen_crc(seed[0] & 3, seed)` at `[12:20]`, auth_information `[20:36]`,
/// random `[36:38]` (doc 03 §3.3; matches the GS DrMode4 frame of doc 30.3).
pub fn keepalive1_mod(seed: [u8; 4], auth_info: &[u8; 16], random: [u8; 2]) -> [u8; 38] {
    let mut p = [0u8; 38];
    p[0] = 0xff;
    p[8..12].copy_from_slice(&seed);
    p[12..20].copy_from_slice(&gen_crc(seed[0] & 3, seed));
    p[20..36].copy_from_slice(auth_info);
    p[36..38].copy_from_slice(&random);
    p
}

/// Classification of a keepalive answer (doc 03 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveReply {
    /// `07`: this round succeeded.
    Ack,
    /// `4d`: server notice; keep waiting, it is not a failure (doc 03 §3.3).
    Notice,
}

/// A `07` answer must at least carry the `07 counter length 00` header that
/// every type-7 packet has (doc 03 §3.3–3.5, doc 30.4); shorter is refused.
// doc 03: the exact keepalive answer lengths are not specified.
pub fn parse_keepalive_reply(body: &[u8]) -> Result<KeepaliveReply, Error> {
    need("keepalive reply", body, 1)?;
    match body[0] {
        0x07 => {
            need("keepalive reply", body, 4)?;
            Ok(KeepaliveReply::Ack)
        }
        0x4d => Ok(KeepaliveReply::Notice),
        code => Err(Error::Unexpected { what: "keepalive reply", code }),
    }
}

// ---------------------------------------------------------------------------
// keepalive2 (doc 03 §3.4)
// ---------------------------------------------------------------------------

/// `[6:8]` of the first ("file") keepalive2 (doc 03 §3.4).
pub const KEEPALIVE2_FILE_VERSION: [u8; 2] = [0x0f, 0x27];

/// One 40-byte keepalive2 (doc 03 §3.4 table). Unlisted bytes are zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive2 {
    /// Running counter; byte 1 is `counter % 0xff` (modulo 255, doc 03 §3.4).
    pub counter: u32,
    /// 1 for the first/"front" packet of a round, 3 for the second.
    pub ka_type: u8,
    /// First file handshake: `[6:8] = 0f 27` instead of the version.
    pub file_handshake: bool,
    /// `KEEP_ALIVE_VERSION`.
    pub version: [u8; 2],
    /// `[16:20]` for type 3, copied from the previous answer.
    // doc 03 §3.4: only type 3 is said to carry the tail; type 1 keeps the
    // default zero ("默认清零"). Unknown whether Dogcom also sends it in type 1.
    pub tail: [u8; 4],
    /// DHCP mode, type 3: host IPv4 at `[28:32]`.
    pub host_ip: Option<[u8; 4]>,
    /// PPPoE mode, type 3: `gen_crc(type, packet[0:4])` at `[32:40]`. Doc 03
    /// §3.4 stresses the input is the packet's own first 4 bytes, not the seed.
    pub pppoe_crc_type: Option<u8>,
}

impl Keepalive2 {
    pub fn build(&self) -> [u8; 40] {
        let mut p = [0u8; 40];
        p[0] = 0x07;
        p[1] = (self.counter % 0xff) as u8;
        p[2..4].copy_from_slice(&[0x28, 0x00]);
        p[4] = 0x0b;
        p[5] = self.ka_type;
        p[6..8].copy_from_slice(if self.file_handshake { &KEEPALIVE2_FILE_VERSION } else { &self.version });
        p[8..10].copy_from_slice(&[0x2f, 0x12]);
        if self.ka_type == 3 {
            p[16..20].copy_from_slice(&self.tail);
            if let Some(ip) = self.host_ip {
                p[28..32].copy_from_slice(&ip);
            }
            if let Some(t) = self.pppoe_crc_type {
                let crc = gen_crc(t, arr(&p[0..4]));
                p[32..40].copy_from_slice(&crc);
            }
        }
        p
    }
}

/// Tail `[16:20]` of a keepalive2 answer (doc 03 §3.4).
pub fn parse_keepalive2_tail(body: &[u8]) -> Result<[u8; 4], Error> {
    need("keepalive2 reply", body, 20)?;
    if body[0] != 0x07 {
        return Err(Error::Unexpected { what: "keepalive2 reply", code: body[0] });
    }
    Ok(arr(&body[16..20]))
}

// ---------------------------------------------------------------------------
// PPPoE helper (doc 03 §3.5)
// ---------------------------------------------------------------------------

/// PPPoE helper challenge: `07 counter 08 00 01 00 00 00` (doc 03 §3.5).
pub fn pppoe_challenge(counter: u8) -> [u8; 8] {
    keepalive1_mod_request(counter)
}

/// Fields of the PPPoE challenge answer (doc 03 §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PppoeChallenge {
    /// `[8:12]`.
    pub seed: [u8; 4],
    /// `[12:16]`, echoed into the login.
    pub sip: [u8; 4],
    /// `[28:30]`, KEEP_ALIVE_VERSION for keepalive2.
    pub keepalive_version: [u8; 2],
    /// Offset 5 non-zero: the server enabled the derived CRC types.
    pub derive_enabled: bool,
}

impl PppoeChallenge {
    /// `seed[0] & 3`, forced to 0 when the server did not enable it.
    pub fn encrypt_type(&self) -> u8 {
        if self.derive_enabled {
            self.seed[0] & 3
        } else {
            0
        }
    }
}

pub fn parse_pppoe_challenge(body: &[u8]) -> Result<PppoeChallenge, Error> {
    need("PPPoE challenge reply", body, 30)?;
    // doc 03 §3.5 does not state the reply's first byte; 07 is what every
    // other Dr.com misc packet uses (doc 30.2), so anything else is refused.
    if body[0] != 0x07 {
        return Err(Error::Unexpected { what: "PPPoE challenge reply", code: body[0] });
    }
    Ok(PppoeChallenge {
        seed: arr(&body[8..12]),
        sip: arr(&body[12..16]),
        keepalive_version: arr(&body[28..30]),
        derive_enabled: body[5] != 0,
    })
}

/// 96-byte PPPoE login as far as doc 03 §3.5 specifies it: header
/// `07 counter 60 00 03`, sip `[12:16]`, `[17]` = 62 on the first login and
/// 63 afterwards, `[19]` = pppoe_flag, seed `[20:24]`, CRC at `[24:32]`.
/// Type 0: a 32-byte scratch copy with `[24:32]` = [`FALLBACK_CRC`] is fed
/// to [`check32`] and only the result is written to `[24:28]`.
// doc 03 §3.5: bytes [32:96] are not specified and stay zero. The GS body
// (`gs::control96`, doc 30.4) fills them and checksums all 96 bytes; that is
// a different client and is not substituted silently.
pub fn pppoe_login(counter: u8, ch: &PppoeChallenge, first: bool, pppoe_flag: u8) -> [u8; 96] {
    let mut p = [0u8; 96];
    p[0..5].copy_from_slice(&[0x07, counter, 0x60, 0x00, 0x03]);
    p[12..16].copy_from_slice(&ch.sip);
    p[17] = if first { 0x62 } else { 0x63 };
    p[19] = pppoe_flag;
    p[20..24].copy_from_slice(&ch.seed);
    match ch.encrypt_type() {
        0 => {
            let mut scratch = [0u8; 32];
            scratch.copy_from_slice(&p[..32]);
            scratch[24..32].copy_from_slice(&FALLBACK_CRC);
            // 32 is a multiple of 4: check32 cannot fail here.
            let sum = check32(&scratch).unwrap_or([0; 4]);
            p[24..28].copy_from_slice(&sum);
        }
        t => p[24..32].copy_from_slice(&gen_crc(t, ch.seed)),
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_layout() {
        let p = challenge_request(CHALLENGE_DOGCOM_LOGIN, [0xaa, 0xbb], 0x0a);
        assert_eq!(&p[..5], &[0x01, 0x02, 0xaa, 0xbb, 0x0a]);
        assert!(p[5..].iter().all(|&b| b == 0));
        let mut r = [0u8; 8];
        r[0] = 2;
        r[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(parse_challenge_response(&r).unwrap(), [1, 2, 3, 4]);
        assert!(parse_challenge_response(&r[..7]).is_err());
        r[0] = 3;
        assert!(parse_challenge_response(&r).is_err());
    }

    fn params<'a>(pw: &'a [u8], ror: bool) -> LoginParams<'a> {
        LoginParams {
            username: b"synthetic",
            password: pw,
            seed: [0, 0, 0x20, 0],
            mac: [2, 0, 0, 0, 0, 1],
            host_ip: [192, 0, 2, 10],
            control_check_status: 0x20,
            adapter_num: 0x01,
            ip_dog: 0x01,
            host_name: b"LAPTOP-PEVCLMV4",
            primary_dns: [192, 0, 2, 20],
            dhcp_server: [198, 51, 100, 53],
            os: OsVersion::default(),
            host_os: b"DrCOM\x00\x0f\x27\x02",
            auth_version: [0x27, 0x00],
            ror,
        }
    }

    #[test]
    fn dogcom_login_lengths_and_checksums() {
        // Non-ror: 330 bytes (doc 03 §3.2), trailer e9 13 at 328.
        let l = login(&params(b"synthetic", false), LoginLayout::Dogcom).unwrap();
        assert_eq!(l.body.len(), 330);
        assert_eq!(&l.body[312..314], &[0x02, 0x0c]);
        assert_eq!(&l.body[320..326], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(&l.body[328..330], &[0xe9, 0x13]);
        // checksum1 with the 14 00 07 0b suffix.
        let mut ctx = md5::Context::new();
        ctx.consume(&l.body[..97]);
        ctx.consume([0x14, 0x00, 0x07, 0x0b]);
        assert_eq!(&l.body[97..105], &ctx.compute().0[..8]);
        // checksum2 recomputed over the scratch buffer.
        let mut scratch = l.body[..328].to_vec();
        scratch[314..320].copy_from_slice(&[0x01, 0x26, 0x07, 0x11, 0x00, 0x00]);
        assert_eq!(&l.body[314..318], &checksum1968(&scratch).unwrap());
        // ror with an 8-byte password: 338 (the "ror base" of doc 03 §3.2).
        let l = login(&params(b"12345678", true), LoginLayout::Dogcom).unwrap();
        assert_eq!(l.body.len(), 338);
        assert_eq!(&l.body[312..314], &[0x00, 8]);
    }

    #[test]
    fn login_rejects_oversized_fields() {
        let mut p = params(b"pw", false);
        let long = [b'u'; 37];
        p.username = &long;
        assert!(login(&p, LoginLayout::Dogcom).is_err());
        let p = params(&[b'p'; 17], true);
        assert!(login(&p, LoginLayout::Dogcom).is_err());
        let mut p = params(b"pw", false);
        let host = [b'h'; 33];
        p.host_name = &host;
        assert!(login(&p, LoginLayout::Gs).is_err());
        let mut p = params(b"pw", false);
        let os = [b'o'; 129];
        p.host_os = &os;
        assert!(login(&p, LoginLayout::Gs).is_err());
        let username = [b'u'; 36];
        let mut p = params(b"pw", false);
        p.username = &username;
        let l = login(&p, LoginLayout::Gs).unwrap();
        assert_eq!(l.body[3], 56);
        assert_eq!(l.body[56], 0x20);
    }

    #[test]
    fn login_reply_parsing() {
        let mut ok = vec![0u8; 39];
        ok[0] = 4;
        ok[23..39].copy_from_slice(&[9; 16]);
        assert_eq!(parse_login_reply(&ok).unwrap(), LoginReply::Success { auth_info: [9; 16] });
        assert!(parse_login_reply(&ok[..38]).is_err());
        assert_eq!(parse_login_reply(&[5, 0, 0, 0, 3]).unwrap(), LoginReply::Failure { code: 3 });
        assert!(parse_login_reply(&[5, 0, 0, 0]).is_err());
        assert!(parse_login_reply(&[]).is_err());
        assert!(parse_login_reply(&[7; 64]).is_err());
    }

    #[test]
    fn keepalive_layouts() {
        let p = keepalive1(&[1; 16], &[2; 16], [3, 4], KEEPALIVE1_DOGCOM_LEN).unwrap();
        assert_eq!(p.len(), 42);
        assert_eq!(p[0], 0xff);
        assert_eq!(&p[1..17], &[1; 16]);
        assert_eq!(&p[17..20], &[0; 3]);
        assert_eq!(&p[20..36], &[2; 16]);
        assert_eq!(&p[36..38], &[3, 4]);
        assert_eq!(&p[38..], &[0; 4]);
        assert!(keepalive1(&[1; 16], &[2; 16], [3, 4], 37).is_err());

        let k = Keepalive2 {
            counter: 255 + 7,
            ka_type: 3,
            file_handshake: false,
            version: [0xdc, 0x02],
            tail: [1, 2, 3, 4],
            host_ip: Some([10, 0, 0, 1]),
            pppoe_crc_type: None,
        }
        .build();
        assert_eq!(&k[..10], &[0x07, 7, 0x28, 0x00, 0x0b, 3, 0xdc, 0x02, 0x2f, 0x12]);
        assert_eq!(&k[16..20], &[1, 2, 3, 4]);
        assert_eq!(&k[28..32], &[10, 0, 0, 1]);
        assert_eq!(&k[32..40], &[0; 8]);
        let f = Keepalive2 { counter: 0, ka_type: 1, file_handshake: true, tail: [9; 4], ..Keepalive2::from_type3(k) }.build();
        assert_eq!(&f[5..8], &[1, 0x0f, 0x27]);
        assert_eq!(&f[16..20], &[0; 4], "type 1 keeps the tail zero");
        let pp = Keepalive2 { host_ip: None, pppoe_crc_type: Some(2), ..Keepalive2::from_type3(k) }.build();
        assert_eq!(&pp[28..32], &[0; 4]);
        assert_eq!(&pp[32..40], &gen_crc(2, [0x07, 7, 0x28, 0x00]));
        assert_eq!(parse_keepalive2_tail(&k).unwrap(), [1, 2, 3, 4]);
        assert!(parse_keepalive2_tail(&k[..19]).is_err());
        assert_eq!(parse_keepalive_reply(&[0x4d]).unwrap(), KeepaliveReply::Notice);
        assert!(parse_keepalive_reply(&[0x05]).is_err());
    }

    impl Keepalive2 {
        fn from_type3(raw: [u8; 40]) -> Keepalive2 {
            Keepalive2 {
                counter: raw[1] as u32,
                ka_type: raw[5],
                file_handshake: false,
                version: [raw[6], raw[7]],
                tail: [raw[16], raw[17], raw[18], raw[19]],
                host_ip: Some([raw[28], raw[29], raw[30], raw[31]]),
                pppoe_crc_type: None,
            }
        }
    }

    #[test]
    fn pppoe_login_layout() {
        let mut r = [0u8; 30];
        r[0] = 7;
        r[5] = 1;
        r[8..12].copy_from_slice(&[0x02, 0x91, 0x22, 0xe3]);
        r[12..16].copy_from_slice(&[10, 1, 2, 3]);
        r[28..30].copy_from_slice(&[0xdc, 0x02]);
        let ch = parse_pppoe_challenge(&r).unwrap();
        assert_eq!(ch.encrypt_type(), 2);
        let p = pppoe_login(5, &ch, true, 0x2a);
        assert_eq!(&p[..5], &[0x07, 5, 0x60, 0x00, 0x03]);
        assert_eq!(&p[12..16], &[10, 1, 2, 3]);
        assert_eq!((p[17], p[19]), (0x62, 0x2a));
        assert_eq!(&p[24..32], &gen_crc(2, ch.seed));
        assert_eq!(pppoe_login(6, &ch, false, 0x2a)[17], 0x63);
        // Disabled by the server: type 0 with the 32-byte check32.
        r[5] = 0;
        let ch = parse_pppoe_challenge(&r).unwrap();
        assert_eq!(ch.encrypt_type(), 0);
        let p = pppoe_login(5, &ch, true, 0x2a);
        let mut scratch = p[..32].to_vec();
        scratch[24..32].copy_from_slice(&FALLBACK_CRC);
        assert_eq!(&p[24..28], &check32(&scratch).unwrap());
        assert_eq!(&p[28..], &[0u8; 68][..]);
        assert!(parse_pppoe_challenge(&r[..29]).is_err());
        r[0] = 2;
        assert!(parse_pppoe_challenge(&r).is_err());
    }
}
