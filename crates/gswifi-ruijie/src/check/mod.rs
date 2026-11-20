//! Ruijie V3/V4 check algorithms: the custom M/S/R/T/W hashes, the 20 mix
//! sub-entries with their 5 version families (0x4d attribute), and the UDP
//! heartbeat helpers.
//!
//! Clean-room implementation written from the campus-auth-research spec pack
//! (docs 15.2, 19, 20; data/ruijie tables; test vectors). Anything the docs
//! left open was inferred against the published vectors; those places are
//! commented where they occur.

pub mod hash;
pub mod mix;
pub mod udp;

/// Lowercase ASCII hex encoding (`X.hex` in doc 19.3).
pub(crate) fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)]);
        out.push(DIGITS[usize::from(b & 15)]);
    }
    out
}

#[cfg(test)]
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}
