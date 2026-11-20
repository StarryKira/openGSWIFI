//! The two iNode password helpers (research doc 13.4).
//!
//! Neither appears in the recovered AuthType 1 Identity/MD5 frames (doc
//! 22.3 uses the standard MD5 response), and the docs do not say which
//! exchange sends them. They are exported for completeness and for engines
//! that later find the calling branch; the dialect does not use them.
//! The EAP-MD5 digest itself is in [`crate::eap`].

use crate::InodeError;

/// `0x41ba24`: challenge XOR the first 16 password bytes (zero padded),
/// without hashing.
///
/// The original allocates `max(16, strlen(password))` bytes but only
/// initialises the first 16, then returns the whole length: for passwords
/// longer than 16 bytes the tail is uninitialised heap memory (doc 13.4).
/// That output is not an algorithm, so passwords over 16 bytes are
/// rejected instead of reproduced.
pub fn password_xor(challenge: &[u8; 16], password: &[u8]) -> Result<[u8; 16], InodeError> {
    if password.len() > 16 {
        return Err(InodeError::Invalid("密码超过 16 字节时原程序输出含未初始化内存，不予模拟"));
    }
    let mut out = *challenge;
    for (o, p) in out.iter_mut().zip(password) {
        *o ^= p;
    }
    Ok(out)
}

/// `0x40cdd4`: `MD5(challenge16) XOR password16` (password zero padded or
/// truncated to 16 bytes).
pub fn md5_challenge_xor(challenge: &[u8; 16], password: &[u8]) -> [u8; 16] {
    let mut out = md5::compute(challenge).0;
    for (o, p) in out.iter_mut().zip(password.iter().take(16)) {
        *o ^= p;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_uninitialised_tail() {
        assert!(password_xor(&[0; 16], &[b'a'; 17]).is_err());
        assert_eq!(password_xor(&[0; 16], b"").unwrap(), [0; 16]);
    }
}
