//! The GS H3C password block transform `0x41baf4` (research doc 13.8).
//!
//! TEA-shaped but not TEA or XTEA: an arithmetic right shift and an extra
//! addition replace XTEA's mixing. 8-byte blocks, zero padded to the next
//! multiple of 8 (no extra block when aligned).

use super::CodecError;

/// Key of the Portal password field: the 16 bytes at VA 0x423758
/// (`12 98 46 35 25 90 47 83 86 24 19 23 29 58 61 36`) read as four
/// little-endian words on MIPSel.
pub const PASSWORD_KEY: [u32; 4] = [0x3546_9812, 0x8347_9025, 0x2319_2486, 0x3661_5829];
/// Rounds used for the password field.
pub const PASSWORD_ROUNDS: u32 = 16;
const DELTA: u32 = 0x9e37_79b9;

/// Encrypt direction of the transform. Words are little endian unless
/// `swap_words` (the word order helper at 0x4407b0 set to 1; default 0 on
/// MIPSel). `rounds` is limited to 64.
///
/// ```text
/// x += (sum ^ y) + (((y << 4) ^ (y >>arith 5)) + key[sum & 3])
/// sum += delta
/// y += (sum ^ x) + (((x << 4) ^ (x >>arith 5)) + key[(sum >> 11) & 3])
/// ```
pub fn block_transform(data: &[u8], key: &[u32; 4], rounds: u32, swap_words: bool) -> Result<Vec<u8>, CodecError> {
    if rounds > 64 {
        return Err(CodecError::Invalid("块变换轮数超过 64"));
    }
    let mut padded = data.to_vec();
    padded.resize(data.len().div_ceil(8) * 8, 0);
    let read = |b: &[u8]| {
        let w = [b[0], b[1], b[2], b[3]];
        if swap_words {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        }
    };
    let ashr5 = |v: u32| ((v as i32) >> 5) as u32;
    let mut out = Vec::with_capacity(padded.len());
    for block in padded.chunks_exact(8) {
        let (mut x, mut y) = (read(&block[..4]), read(&block[4..]));
        let mut sum = 0u32;
        for _ in 0..rounds {
            x = x.wrapping_add((sum ^ y).wrapping_add(((y << 4) ^ ashr5(y)).wrapping_add(key[(sum & 3) as usize])));
            sum = sum.wrapping_add(DELTA);
            y = y.wrapping_add(
                (sum ^ x).wrapping_add(((x << 4) ^ ashr5(x)).wrapping_add(key[((sum >> 11) & 3) as usize])),
            );
        }
        for w in [x, y] {
            out.extend_from_slice(&if swap_words { w.to_be_bytes() } else { w.to_le_bytes() });
        }
    }
    Ok(out)
}

/// Value of login attribute 102 (doc 13.7): the password itself
/// (`UsePlainTextPass`) or the 32-byte transform of the password zero
/// padded to 32 bytes. Passwords longer than 31 bytes do not fit the
/// original buffer and are rejected.
pub fn password_value(password: &[u8], plain: bool) -> Result<Vec<u8>, CodecError> {
    if password.len() > 31 {
        return Err(CodecError::Invalid("密码超过 31 字节"));
    }
    if plain {
        return Ok(password.to_vec());
    }
    let mut padded = password.to_vec();
    padded.resize(32, 0);
    block_transform(&padded, &PASSWORD_KEY, PASSWORD_ROUNDS, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_words_match_doc() {
        let bytes = [0x12, 0x98, 0x46, 0x35, 0x25, 0x90, 0x47, 0x83, 0x86, 0x24, 0x19, 0x23, 0x29, 0x58, 0x61, 0x36];
        for (i, w) in PASSWORD_KEY.iter().enumerate() {
            assert_eq!(w.to_le_bytes(), bytes[4 * i..4 * i + 4]);
        }
    }

    #[test]
    fn padding_and_limits() {
        assert_eq!(block_transform(&[1], &PASSWORD_KEY, 16, false).unwrap().len(), 8);
        assert_eq!(block_transform(&[1; 8], &PASSWORD_KEY, 16, false).unwrap().len(), 8);
        assert!(block_transform(&[], &PASSWORD_KEY, 16, false).unwrap().is_empty());
        assert!(block_transform(&[1], &PASSWORD_KEY, 65, false).is_err());
        assert_eq!(password_value(b"pw", false).unwrap().len(), 32);
        assert_eq!(password_value(b"pw", true).unwrap(), b"pw");
        assert!(password_value(&[b'a'; 32], true).is_err());
    }
}
