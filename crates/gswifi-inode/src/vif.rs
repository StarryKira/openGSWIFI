//! `iNode.vif` decoding: `DecodeINodeP` (0x41c350) and the version cache
//! built from it (research doc 25.4, 22.5, 13.3).
//!
//! The block function is a DES-shaped Feistel network with the firmware's
//! own cooked subkeys (VA 0x42d590, 128 bytes) and SP tables (VA 0x42d610,
//! 2048 bytes), both in `data/` and read as little-endian words. Input
//! blocks are two big-endian words. It is *not* standard DES with some key
//! (doc 13.9), and not the Ruijie material transform either (doc 25.4).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::InodeError;

const fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    let mut i = 0;
    while i < N {
        out[i] = u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
        i += 1;
    }
    out
}

/// Cooked subkeys, VA 0x42d590 (doc 25.4, data/inode/manifest.json).
static SUBKEYS: [u32; 32] = le_words(include_bytes!("../data/vif-subkeys.bin"));
/// Eight 64-entry SP tables, VA 0x42d610.
static SP: [u32; 512] = le_words(include_bytes!("../data/vif-sp.bin"));

fn sp(table: usize, index: u32) -> u32 {
    SP[table * 64 + (index & 63) as usize]
}

fn round_fn(r: u32, k1: u32, k2: u32) -> u32 {
    let a = r ^ k1;
    let b = r.rotate_left(28) ^ k2;
    sp(3, a >> 24) ^ sp(2, a >> 16) ^ sp(1, a >> 8) ^ sp(0, a) ^ sp(7, b >> 24) ^ sp(6, b >> 16) ^ sp(5, b >> 8) ^ sp(4, b)
}

/// One 8-byte block of the VIF cipher; `encrypt` runs the key schedule in
/// reverse (only needed to build test input).
pub fn crypt_block(block: [u8; 8], encrypt: bool) -> [u8; 8] {
    let mut a0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let mut a3 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

    // Initial permutation, transcribed from the firmware (doc 25.4).
    let mut v1 = ((a3 << 4) & 0xf0f0_f0f0) ^ a0;
    let mut a2 = (v1 >> 4) & 0x0f0f_0f0f;
    a3 ^= a2;
    v1 ^= a3 << 16;
    v1 ^= (a3 << 4) & 0xf0f0_f0f0;
    a3 ^= v1 >> 16;
    let mut a1 = (a3 << 16) ^ v1;
    a2 = ((a1 << 2) & 0xcccc_cccc) ^ a3;
    a1 ^= (a2 >> 2) & 0x3333_3333;
    v1 = ((a1 << 2) & 0xcccc_cccc) ^ ((a1 << 8) & 0xff00_ff00) ^ a2;
    a0 = ((v1 >> 8) & 0x00ff_00ff) ^ a1;
    a2 = ((a0 << 8) & 0xff00_ff00) ^ v1;
    v1 = a2.rotate_left(1) ^ (a0 & 0xaaaa_aaaa);
    a0 ^= v1 & 0xaaaa_aaaa;
    v1 ^= a0 & 0xaaaa_aaaa;
    let mut ra = a0.rotate_left(1);

    let mut pairs = [(0u32, 0u32); 16];
    for (n, pair) in pairs.iter_mut().enumerate() {
        let i = 31 - 2 * n;
        *pair = (SUBKEYS[i], SUBKEYS[i - 1]);
    }
    if encrypt {
        pairs.reverse();
    }
    for i in (0..16).step_by(2) {
        ra ^= round_fn(v1, pairs[i].0, pairs[i].1);
        v1 ^= round_fn(ra, pairs[i + 1].0, pairs[i + 1].1);
    }

    // Final permutation.
    v1 = v1.rotate_left(31);
    v1 ^= ra & 0xaaaa_aaaa;
    a0 = ra ^ (v1 & 0xaaaa_aaaa);
    v1 ^= a0 & 0xaaaa_aaaa;
    a2 = ((v1 << 8) & 0xff00_ff00) ^ a0.rotate_left(31);
    v1 ^= (a2 >> 8) & 0x00ff_00ff;
    a1 = ((v1 << 8) & 0xff00_ff00) ^ ((v1 << 2) & 0xcccc_cccc) ^ a2;
    v1 ^= (a1 >> 2) & 0x3333_3333;
    a2 = ((v1 << 2) & 0xcccc_cccc) ^ a1 ^ (v1 >> 16);
    a3 = (a2 << 16) ^ v1;
    a2 ^= a3 >> 16;
    a0 = ((a3 >> 4) & 0x0f0f_0f0f) ^ a2;
    v1 = ((a0 << 4) & 0xf0f0_f0f0) ^ a3;
    a2 = ((v1 >> 4) & 0x0f0f_0f0f) ^ a0;

    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&v1.to_be_bytes());
    out[4..].copy_from_slice(&a2.to_be_bytes());
    out
}

/// Decrypts whole blocks without any padding handling (`len % 8 == 0`).
pub fn decrypt_raw(data: &[u8]) -> Result<Vec<u8>, InodeError> {
    if data.len() % 8 != 0 {
        return Err(InodeError::Invalid("VIF 密文长度必须是 8 的倍数"));
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        out.extend_from_slice(&crypt_block(chunk.try_into().unwrap_or([0; 8]), false));
    }
    Ok(out)
}

/// Checked `DecodeINodeP` (doc 25.4). Returns the plaintext without the C
/// terminator the original appends.
///
/// Steps: non-empty Base64 text whose length is a multiple of 4 → decode →
/// non-empty ciphertext, multiple of 8 → block decrypt → padding. Padding
/// is *not* PKCS#7: a last byte 1..=7 requires that many equal bytes and
/// removes them; 0 and 8..=127 remove nothing (so "empty + eight 08"
/// decodes to eight 08 bytes). A last byte >= 128 becomes a negative
/// signed length in the original and may read out of bounds; rejected.
pub fn decode_inode_p(text: &[u8]) -> Result<Vec<u8>, InodeError> {
    if text.is_empty() || text.len() % 4 != 0 {
        return Err(InodeError::Invalid("VIF 文本长度必须是 4 的非零倍数"));
    }
    let raw = STANDARD.decode(text).map_err(|_| InodeError::Base64)?;
    if raw.is_empty() || raw.len() % 8 != 0 {
        return Err(InodeError::Invalid("VIF 解码后的密文长度必须是 8 的非零倍数"));
    }
    let mut plain = decrypt_raw(&raw)?;
    let pad = plain[plain.len() - 1];
    if pad >= 128 {
        return Err(InodeError::Padding);
    }
    if (1..8).contains(&pad) {
        let n = pad as usize;
        if plain[plain.len() - n..].iter().any(|&b| b != pad) {
            return Err(InodeError::Padding);
        }
        plain.truncate(plain.len() - n);
    }
    Ok(plain)
}

/// Inverse of [`decode_inode_p`] for tests and tooling: pads with bytes
/// 1..=7 when needed and Base64-encodes. Aligned plaintext is not padded,
/// so one ending in a byte 1..=7 does not round-trip; empty input becomes
/// eight `08` bytes. How the real iNode tool pads is not documented.
pub fn encode_inode_p(plain: &[u8]) -> String {
    let mut data = plain.to_vec();
    let pad = (8 - data.len() % 8) % 8;
    data.extend(std::iter::repeat(pad as u8).take(pad));
    if data.is_empty() {
        data = vec![8; 8];
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        out.extend_from_slice(&crypt_block(chunk.try_into().unwrap_or([0; 8]), true));
    }
    STANDARD.encode(out)
}

/// Turns the decoded VIF plaintext (e.g. `V5.20-0001C`) into the cached
/// version string the mixing uses (doc 25.4, 13.3):
///
/// * `cache = "CH " + plain[..11]` (stopping at a NUL);
/// * major `'3'` with minor (bytes 9..11, decimal) `>= 63`: `cache[2] = 0x10`;
///   otherwise major `>= '5'`: `cache[2]` = `0x12` / `0x13` / `0x11` for a
///   trailing `C` / `T` / anything else;
/// * the last character is removed.
///
/// `V5.20-0001C` becomes `43 48 12 56 35 2e 32 30 2d 30 30 30 31`.
pub fn cache_from_plain(plain: &[u8]) -> Result<Vec<u8>, InodeError> {
    if plain.len() < 11 {
        return Err(InodeError::Invalid("解码后的版本短于 11 字节"));
    }
    let head = &plain[..11];
    let end = head.iter().position(|&b| b == 0).unwrap_or(11);
    let mut cache = b"CH ".to_vec();
    cache.extend_from_slice(&head[..end]);
    if cache.len() < 5 {
        return Err(InodeError::Invalid("版本格式无效"));
    }
    let last = cache[cache.len() - 1];
    let minor = |c: &[u8]| (c[9] as i32 - 48) * 10 + c[10] as i32 - 48;
    if cache[4] == b'3' && cache.len() > 10 && minor(&cache) >= 63 {
        cache[2] = 0x10;
    } else if cache[4] >= b'5' {
        cache[2] = match last {
            b'C' => 0x12,
            b'T' => 0x13,
            _ => 0x11,
        };
    }
    cache.pop();
    Ok(cache)
}

/// Whole `iNode.vif` file → cached version string (`0x41b640`, doc 25.4):
/// the last 256 bytes are cut off, the text ends at the first NUL, goes
/// through [`decode_inode_p`] and [`cache_from_plain`]. The meaning of the
/// 256-byte tail is not documented (doc 13.3); it is ignored.
pub fn decode_vif_file(data: &[u8]) -> Result<Vec<u8>, InodeError> {
    if data.len() < 256 {
        return Err(InodeError::Invalid("iNode.vif 短于 256 字节"));
    }
    let prefix = &data[..data.len() - 256];
    let end = prefix.iter().position(|&b| b == 0).unwrap_or(prefix.len());
    let plain = decode_inode_p(&prefix[..end])?;
    cache_from_plain(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_round_trip() {
        let b = *b"ABCDEFGH";
        assert_eq!(crypt_block(crypt_block(b, true), false), b);
    }

    #[test]
    fn encode_decode_round_trip() {
        for plain in [&b""[..], b"V5.20-0001C", b"12345678", b"1234567"] {
            let text = encode_inode_p(plain);
            let back = decode_inode_p(text.as_bytes()).unwrap();
            if plain.is_empty() {
                assert_eq!(back, vec![8; 8]);
            } else {
                assert_eq!(back, plain);
            }
        }
    }

    #[test]
    fn cache_flags() {
        assert_eq!(cache_from_plain(b"V5.20-0001C").unwrap(), b"CH\x12V5.20-0001");
        assert_eq!(cache_from_plain(b"V5.20-0001T").unwrap(), b"CH\x13V5.20-0001");
        assert_eq!(cache_from_plain(b"V5.20-0001X").unwrap(), b"CH\x11V5.20-0001");
        assert_eq!(cache_from_plain(b"V3.60-6301C").unwrap(), b"CH\x10V3.60-6301");
        assert_eq!(cache_from_plain(b"V3.60-0001C").unwrap(), b"CH V3.60-0001");
        assert!(cache_from_plain(b"short").is_err());
        assert!(cache_from_plain(b"V\0.........").is_err());
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(decode_inode_p(b"").is_err());
        assert!(decode_inode_p(b"abc").is_err());
        assert!(decode_inode_p(b"ab=c").is_err());
        assert!(decode_inode_p(b"AAAA").is_err()); // 3 bytes, not 8-aligned
        assert!(decode_vif_file(&[0u8; 255]).is_err());
        assert!(decode_vif_file(&[0u8; 256]).is_err());
    }
}
