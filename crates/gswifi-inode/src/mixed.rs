//! iNode product version obfuscation (research doc 13.2, 13.3).
//!
//! The server is sent a 20-byte `mixed20` derived from the cached version
//! string (`CH` + flag byte + version, see [`crate::vif`]), a nonce and a
//! fixed key. The nonce travels inside the field, so the server can undo
//! the mixing; it is not a secret and `mixed20` is not a session key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::InodeError;

/// Key for cached versions whose major digit (offset 4) is at least `'3'`.
pub const KEY_V3: &[u8] = b"Oly5D62FaE94W7";
/// Key for older versions.
pub const KEY_OLD: &[u8] = b"HuaWei3COM1X";

/// Two-pass repeating-key XOR of `0x41b53c` (doc 13.2):
/// `out[i] = in[i] ^ key[i % k] ^ key[(n-1-i) % k]`. Not RC4; applying it
/// twice with the same key restores the input. The original loops require
/// non-empty data and key, so empty input is rejected.
pub fn double_xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, InodeError> {
    if data.is_empty() || key.is_empty() {
        return Err(InodeError::Invalid("双向异或要求数据和密钥非空"));
    }
    let (n, k) = (data.len(), key.len());
    Ok(data.iter().enumerate().map(|(i, &v)| v ^ key[i % k] ^ key[(n - 1 - i) % k]).collect())
}

/// Key the original picks for a cached version: [`KEY_V3`] when byte 4 is
/// `>= '3'`, otherwise [`KEY_OLD`] (doc 13.3). A cache shorter than five
/// bytes reads a NUL there after `strncpy`, hence [`KEY_OLD`].
pub fn version_key(cached_version: &[u8]) -> &'static [u8] {
    if cached_version.get(4).is_some_and(|&c| c >= b'3') {
        KEY_V3
    } else {
        KEY_OLD
    }
}

/// The original nonce `q = low32(time(NULL) * rand())` (doc 13.3), for
/// reproducing the research vectors.
pub fn nonce_from_time_rand(time: u32, rand: u32) -> u32 {
    time.wrapping_mul(rand)
}

/// `mixed20` of `0x41b584` (doc 13.3):
///
/// ```text
/// v16     = strncpy(cached_version, 16)        (stops at NUL, zero padded)
/// stage16 = double_xor(v16, lowercase_hex8(q))
/// mixed20 = double_xor(stage16 || BE32(q), key)
/// ```
pub fn mixed(cached_version: &[u8], nonce: u32, key: &[u8]) -> Result<[u8; 20], InodeError> {
    if key.is_empty() {
        return Err(InodeError::Invalid("版本混合密钥为空"));
    }
    let end = cached_version.iter().position(|&b| b == 0).unwrap_or(cached_version.len());
    let mut v16 = [0u8; 16];
    let n = end.min(16);
    v16[..n].copy_from_slice(&cached_version[..n]);
    let hex = format!("{:08x}", nonce);
    let mut stage = double_xor(&v16, hex.as_bytes())?;
    stage.extend_from_slice(&nonce.to_be_bytes());
    let out = double_xor(&stage, key)?;
    let mut mixed = [0u8; 20];
    mixed.copy_from_slice(&out);
    Ok(mixed)
}

/// 32-byte text version field of `0x41b8b0` (doc 13.3, 22.3):
/// `06 07 | Base64(mixed20) (28 bytes) | 20 20` — two spaces, no NUL.
pub fn text_field(mixed: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = 0x06;
    out[1] = 0x07;
    let b64 = STANDARD.encode(mixed);
    out[2..30].copy_from_slice(b64.as_bytes());
    out[30] = b' ';
    out[31] = b' ';
    out
}

/// 22-byte raw version field of `0x41b9b8` (doc 13.3, 22.4): `01 16 | mixed20`.
pub fn raw_field(mixed: &[u8; 20]) -> [u8; 22] {
    let mut out = [0u8; 22];
    out[0] = 0x01;
    out[1] = 0x16;
    out[2..].copy_from_slice(mixed);
    out
}

/// Base64 of `mixed20` alone (28 ASCII bytes, `0x41b968`), as used inside
/// the H3C Portal login attribute 33 (doc 13.7).
pub fn base64_version(mixed: &[u8; 20]) -> String {
    STANDARD.encode(mixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc13_example() {
        let q = nonce_from_time_rand(0x12345678, 0x10203);
        let m = mixed(b"CH V5.20-0001", q, KEY_V3).unwrap();
        assert_eq!(hex(&m), "64633c4d4a07347f264f1c3277557a76b98ddb11");
        assert_eq!(base64_version(&m), "ZGM8TUoHNH8mTxwyd1V6drmN2xE=");
        assert_eq!(&text_field(&m)[30..], b"  ");
        assert_eq!(raw_field(&m)[..2], [1, 0x16]);
    }

    #[test]
    fn double_xor_is_involution_and_rejects_empty() {
        let d = b"abcdefg".to_vec();
        let once = double_xor(&d, KEY_OLD).unwrap();
        assert_eq!(double_xor(&once, KEY_OLD).unwrap(), d);
        assert!(double_xor(b"", KEY_OLD).is_err());
        assert!(double_xor(b"x", b"").is_err());
    }

    #[test]
    fn key_selection() {
        assert_eq!(version_key(b"CH V5.20"), KEY_V3);
        assert_eq!(version_key(b"CH V3.60"), KEY_V3);
        assert_eq!(version_key(b"CH V2.40"), KEY_OLD);
        assert_eq!(version_key(b"CH"), KEY_OLD);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
