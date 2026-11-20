//! Hubei old-Mac FixHBKey: the 128-character RC4 key (cleanroom/08 §1.1,
//! evidence grade D: firmware function `0x407dc8` executed under QEMU and
//! compared byte for byte, 9 vectors in
//! `gapclose/vectors/hubei_oldmac_vectors.json` plus the intermediate values
//! of the raw harness logs; independent reference
//! `gapclose/reference/hubei_oldmac.py`).
//!
//! ```text
//! X  = username up to the first '@';  c = 'c' (the caller passes 99)
//! m1 = md5hex(MMDD‖X‖c)   m2 = md5hex(MMDD‖c‖X)
//! m3 = md5hex(X‖c‖MMDD)   m4 = md5hex(c‖X‖MMDD)
//! S1 = m1[16]&1 → ga_src = S1 ? m3 : m4,  gb_src = S1 ? m4 : m3
//! S2 = m1[18]&1 → ga walks outer (0/31) or inner (1/30)
//! S3 = gb_src[20]&1 → gb walks outer or inner
//! ga = md5hex(ga1)‖md5hex(ga2),  gb = md5hex(gb1)‖md5hex(gb2)
//! sga: upper-case odd (gb[22]&1) or even positions of ga; sgb: even of gb
//! key = gb[24]&1 ? zip(sga, sgb) : zip(reverse(sga), reverse(sgb))
//! ```
//!
//! Every selector is the parity of the ASCII code of one hex character.

use std::fmt;

use gswifi_core::Secret;

/// Lower-case MD5 hex digest.
pub(crate) type Hex32 = [u8; 32];

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn md5_hex(data: &[u8]) -> Hex32 {
    let digest = md5::compute(data);
    let mut out = [0u8; 32];
    for (i, b) in digest.0.iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    out
}

/// The salt character FixHBKey is called with (`fn(user, 'c', out129)`).
pub const KEY_SALT: u8 = b'c';

/// Why a key cannot be derived or accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// `mmdd` is not four ASCII digits.
    BadDate,
    /// The username contains NUL; the firmware takes it as a C string.
    Nul,
    /// A supplied key is not exactly 128 ASCII bytes.
    BadKey,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::BadDate => "日期必须是四位数字 MMDD",
            KeyError::Nul => "用户名不能包含NUL字符",
            KeyError::BadKey => "密钥必须是128个ASCII字符",
        })
    }
}

impl std::error::Error for KeyError {}

/// The 128-character FixHBKey. Derived material: `Debug` is redacted and
/// the text is wiped on drop (clean-room rule 2).
#[derive(Clone, PartialEq, Eq)]
pub struct Key128(Secret);

impl Key128 {
    /// Accepts an externally supplied key (the password-chain vectors use a
    /// synthetic one). Must be 128 ASCII bytes, as the firmware copies
    /// exactly 128 bytes into the RC4 key schedule.
    pub fn from_ascii(key: &str) -> Result<Key128, KeyError> {
        if key.len() != 128 || !key.is_ascii() || key.contains('\0') {
            return Err(KeyError::BadKey);
        }
        Ok(Key128(Secret::new(key)))
    }

    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Key128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key128(***)")
    }
}

/// Every intermediate of one derivation, for the golden-vector tests.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct KeyTrace {
    pub m: [Hex32; 4],
    pub ga1: Hex32,
    pub ga2: Hex32,
    pub gb1: Hex32,
    pub gb2: Hex32,
    pub ga: [u8; 64],
    pub gb: [u8; 64],
    pub sga: [u8; 64],
    pub sgb: [u8; 64],
    pub key: [u8; 128],
    /// S1, S2, S3, gb[22]&1, gb[24]&1.
    pub selectors: [u8; 5],
}

/// 16 characters of `s` from `start`, step +2 or −2.
fn walk(s: &Hex32, start: usize, descending: bool) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (k, o) in out.iter_mut().enumerate() {
        *o = if descending { s[start - 2 * k] } else { s[start + 2 * k] };
    }
    out
}

/// Interleaves two walks into a 32-character buffer (even slots from `a`).
fn il(a: [u8; 16], b: [u8; 16]) -> Hex32 {
    let mut out = [0u8; 32];
    for k in 0..16 {
        out[2 * k] = a[k];
        out[2 * k + 1] = b[k];
    }
    out
}

fn concat(a: Hex32, b: Hex32) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&a);
    out[32..].copy_from_slice(&b);
    out
}

fn upper_where(s: &[u8; 64], parity: usize) -> [u8; 64] {
    let mut out = *s;
    for (i, c) in out.iter_mut().enumerate() {
        if i % 2 == parity {
            *c = c.to_ascii_uppercase();
        }
    }
    out
}

fn check_date(mmdd: &str) -> Result<(), KeyError> {
    if mmdd.len() == 4 && mmdd.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(KeyError::BadDate)
    }
}

pub(crate) fn trace(username: &str, mmdd: &str) -> Result<KeyTrace, KeyError> {
    check_date(mmdd)?;
    if username.contains('\0') {
        return Err(KeyError::Nul);
    }
    let x = username.split('@').next().unwrap_or("").as_bytes();
    let d = mmdd.as_bytes();
    let c = &[KEY_SALT][..];
    let md5_of = |parts: [&[u8]; 3]| md5_hex(&parts.concat());
    let m1 = md5_of([d, x, c]);
    let m2 = md5_of([d, c, x]);
    let m3 = md5_of([x, c, d]);
    let m4 = md5_of([c, x, d]);

    let s1 = m1[16] & 1;
    let s2 = m1[18] & 1;
    let (ga_src, gb_src) = if s1 == 0 { (m4, m3) } else { (m3, m4) };
    let s3 = gb_src[20] & 1;

    let (ga1, ga2) = if s2 == 0 {
        (il(walk(&m1, 31, true), walk(&ga_src, 0, false)), il(walk(&m1, 0, false), walk(&ga_src, 31, true)))
    } else {
        (il(walk(&m1, 1, false), walk(&ga_src, 30, true)), il(walk(&m1, 30, true), walk(&ga_src, 1, false)))
    };
    let (gb1, gb2) = if s3 == 0 {
        (il(walk(&m2, 0, false), walk(&gb_src, 0, false)), il(walk(&m2, 31, true), walk(&gb_src, 31, true)))
    } else {
        (il(walk(&m2, 1, false), walk(&gb_src, 1, false)), il(walk(&m2, 30, true), walk(&gb_src, 30, true)))
    };

    let ga = concat(md5_hex(&ga1), md5_hex(&ga2));
    let gb = concat(md5_hex(&gb1), md5_hex(&gb2));
    let g22 = gb[22] & 1;
    let g24 = gb[24] & 1;
    let sga = upper_where(&ga, usize::from(g22));
    let sgb = upper_where(&gb, 0);

    let mut key = [0u8; 128];
    for i in 0..64 {
        // Forward zip, or the reversed zip of block 0x40820a.
        let j = if g24 == 1 { i } else { 63 - i };
        key[2 * i] = sga[j];
        key[2 * i + 1] = sgb[j];
    }
    Ok(KeyTrace { m: [m1, m2, m3, m4], ga1, ga2, gb1, gb2, ga, gb, sga, sgb, key, selectors: [s1, s2, s3, g22, g24] })
}

/// Derives the FixHBKey for `username` on local date `mmdd` (`"0503"`).
/// Only the part before the first `@` enters the key.
pub fn fix_hb_key(username: &str, mmdd: &str) -> Result<Key128, KeyError> {
    let t = trace(username, mmdd)?;
    // The key is 128 ASCII hex characters by construction.
    let text: String = t.key.iter().map(|&b| b as char).collect();
    Ok(Key128(Secret::new(text)))
}
