//! Attribute 130 → 131: the five GS H3C client checks (`0x41be54`,
//! research doc 29.5).
//!
//! The first challenge byte is ASCII `'1'`..`'5'` (0x31..0x35), not 1..5.
//! Family 2 carries 40 bytes, the others 32. Every family ends with
//!
//! ```text
//! d = MD5(decoded[..32]);  attribute131 = d || MD5(d)
//! ```
//!
//! AES and 3DES are the standard primitives with fixed firmware keys
//! (doc 29.5 table); the TEA variant is the firmware's own.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use des::TdesEde3;
use gswifi_inode::{GsData, InodeError};

/// AES-128 key, VA 0x42d540.
pub const AES_KEY: [u8; 16] = [
    0xec, 0xd4, 0x4f, 0x7b, 0xc6, 0xdd, 0x7d, 0xde, 0x2b, 0x7b, 0x51, 0xab, 0x4a, 0x6f, 0x5a, 0x22,
];
/// AES-CBC IV, VA 0x42d550 (ASCII `a@4de%#1asdfsd24`).
pub const AES_IV: [u8; 16] = *b"a@4de%#1asdfsd24";
/// 3DES (EDE, three keys) key, VA 0x42d560.
pub const DES3_KEY: [u8; 24] = [
    0x00, 0x88, 0x01, 0x01, 0xd2, 0x42, 0xa4, 0x4a, 0xe0, 0x54, 0xf2, 0xd2, 0x73, 0xda, 0xae, 0x4d, 0x42, 0xf2, 0x18,
    0x20, 0xd3, 0x72, 0x04, 0xbf,
];
/// TEA variant key, VA 0x42d578, read as little-endian words.
pub const TEA_KEY: [u8; 16] = [
    0x24, 0x78, 0x65, 0x56, 0x32, 0x56, 0x74, 0x56, 0x79, 0x98, 0x80, 0x97, 0x78, 0x78, 0x76, 0x65,
];

/// Why no attribute 131 could be computed. The original then omits 131
/// (it returns −1 without writing a result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// First byte is not ASCII `'1'`..`'5'`.
    Family(u8),
    /// Wrong challenge length for the family (33, or 41 for family 2).
    Length { family: u8, len: usize },
    /// Families 4 and 5 need `inode-gs.dat`.
    NeedData,
    /// The data file lacks a record or the slice is invalid.
    Data(InodeError),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Family(b) => write!(f, "未知的客户端校验类型 {:#04x}", b),
            CheckError::Length { family, len } => write!(f, "校验类型 {} 的挑战长度 {} 不正确", family, len),
            CheckError::NeedData => f.write_str("校验类型 4/5 需要 inode-gs.dat"),
            CheckError::Data(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CheckError {}

/// Family 1: decrypt direction of the TEA variant (doc 29.5). Four 8-byte
/// blocks, little-endian words, 16 rounds, `sum` starts at 0xe3779b90,
/// logical right shifts — unlike the password transform's arithmetic ones.
pub fn tea_decode(data: &[u8; 32]) -> [u8; 32] {
    let key: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes([TEA_KEY[4 * i], TEA_KEY[4 * i + 1], TEA_KEY[4 * i + 2], TEA_KEY[4 * i + 3]])
    });
    let mut out = [0u8; 32];
    for (src, dst) in data.chunks_exact(8).zip(out.chunks_exact_mut(8)) {
        let mut x = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        let mut y = u32::from_le_bytes([src[4], src[5], src[6], src[7]]);
        let mut sum = 0xe377_9b90u32;
        for _ in 0..16 {
            y = y.wrapping_sub((sum ^ x).wrapping_add(((x << 4) ^ (x >> 5)).wrapping_add(key[((sum >> 11) & 3) as usize])));
            sum = sum.wrapping_sub(0x9e37_79b9);
            x = x.wrapping_sub((sum ^ y).wrapping_add(((y << 4) ^ (y >> 5)).wrapping_add(key[(sum & 3) as usize])));
        }
        dst[..4].copy_from_slice(&x.to_le_bytes());
        dst[4..].copy_from_slice(&y.to_le_bytes());
    }
    out
}

/// AES-128-CBC decryption without padding of whole blocks.
fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for block in data.chunks_exact_mut(16) {
        let saved: [u8; 16] = block.try_into().unwrap_or([0; 16]);
        let ga = GenericArray::from_mut_slice(block);
        cipher.decrypt_block(ga);
        for (b, p) in block.iter_mut().zip(prev) {
            *b ^= p;
        }
        prev = saved;
    }
}

fn des3_ecb_decrypt(data: &mut [u8]) {
    let cipher = TdesEde3::new(GenericArray::from_slice(&DES3_KEY));
    for block in data.chunks_exact_mut(8) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

/// Copies `src` over the start of `decoded` (at most 32 bytes): a slice
/// shorter than 32 keeps the remaining decrypted bytes (doc 29.5).
fn overlay(decoded: &mut [u8], src: &[u8]) {
    let n = src.len().min(32);
    decoded[..n].copy_from_slice(&src[..n]);
}

fn read(data: Option<&GsData>, id: u32, offset: u8, length: u8) -> Result<Vec<u8>, CheckError> {
    let data = data.ok_or(CheckError::NeedData)?;
    data.read(id, offset, length).map(<[u8]>::to_vec).map_err(CheckError::Data)
}

/// Computes the 32-byte attribute 131 value for an attribute 130 value.
///
/// * `'1'`: [`tea_decode`].
/// * `'2'`: 3DES-ECB decrypt of 40 bytes; `n = 40 - plain[39]`; if `n >= 0`
///   the first `n` plaintext bytes replace the ciphertext prefix (no other
///   padding check, doc 29.5); the first 32 bytes are hashed.
/// * `'3'`: AES-128-CBC decrypt of 32 bytes.
/// * `'4'`: AES, then one record slice: `ID = BE32(d[4..8])`, offset `d[10]`,
///   length `d[17]`, laid over the start.
/// * `'5'`: AES; first slice `BE32(d[0..4])`/`d[4]`/`d[5]`; `d[16..32]` is
///   decrypted again with key `MD5(first)` and the fixed IV; second slice
///   `BE32(d[26..30])`/`d[30]`/`d[31]`; `(first || second)[..32]` laid
///   over the start.
pub fn check_result(challenge: &[u8], data: Option<&GsData>) -> Result<[u8; 32], CheckError> {
    let family = *challenge.first().ok_or(CheckError::Length { family: 0, len: 0 })?;
    if !(b'1'..=b'5').contains(&family) {
        return Err(CheckError::Family(family));
    }
    let n = if family == b'2' { 40 } else { 32 };
    if challenge.len() != n + 1 {
        return Err(CheckError::Length { family: family - b'0', len: challenge.len() });
    }
    let raw = &challenge[1..];
    let mut decoded = raw.to_vec();
    match family {
        b'1' => {
            let block: [u8; 32] = raw.try_into().map_err(|_| CheckError::Length { family: 1, len: raw.len() })?;
            decoded = tea_decode(&block).to_vec();
        }
        b'2' => {
            let mut plain = raw.to_vec();
            des3_ecb_decrypt(&mut plain);
            let keep = 40 - plain[39] as i32;
            if keep >= 0 {
                let keep = keep as usize;
                decoded[..keep].copy_from_slice(&plain[..keep]);
            }
        }
        _ => {
            aes_cbc_decrypt(&AES_KEY, &AES_IV, &mut decoded);
            if family == b'4' {
                let id = u32::from_be_bytes([decoded[4], decoded[5], decoded[6], decoded[7]]);
                let chosen = read(data, id, decoded[10], decoded[17])?;
                overlay(&mut decoded, &chosen);
            } else if family == b'5' {
                let id = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]);
                let first = read(data, id, decoded[4], decoded[5])?;
                let key = md5::compute(&first).0;
                aes_cbc_decrypt(&key, &AES_IV, &mut decoded[16..32]);
                let id = u32::from_be_bytes([decoded[26], decoded[27], decoded[28], decoded[29]]);
                let second = read(data, id, decoded[30], decoded[31])?;
                let joined: Vec<u8> = first.iter().chain(&second).copied().take(32).collect();
                overlay(&mut decoded, &joined);
            }
        }
    }
    let d = md5::compute(&decoded[..32]).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&d);
    out[16..].copy_from_slice(&md5::compute(d).0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_challenges() {
        assert_eq!(check_result(b"", None), Err(CheckError::Length { family: 0, len: 0 }));
        assert_eq!(check_result(&[1; 33], None), Err(CheckError::Family(1)));
        assert!(matches!(check_result(&[b'1'; 32], None), Err(CheckError::Length { .. })));
        assert!(matches!(check_result(&[b'2'; 33], None), Err(CheckError::Length { .. })));
        assert_eq!(check_result(&[b'4'; 33], None), Err(CheckError::NeedData));
        assert_eq!(check_result(&[b'5'; 33], None), Err(CheckError::NeedData));
        assert!(check_result(&[b'3'; 33], None).is_ok());
    }

    #[test]
    fn iv_matches_doc_hex() {
        assert_eq!(
            AES_IV,
            [0x61, 0x40, 0x34, 0x64, 0x65, 0x25, 0x23, 0x31, 0x61, 0x73, 0x64, 0x66, 0x73, 0x64, 0x32, 0x34]
        );
    }
}
