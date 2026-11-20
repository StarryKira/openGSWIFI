//! Hubei old-Mac password chain (cleanroom/08 §1.2, evidence grade D:
//! firmware function `0x40827e` under QEMU, vectors
//! `gapclose/vectors/hubei_password_vectors.json` and harness logs
//! `out_pw1.txt`, `out_pw2.txt`, `out_sim_pw.txt`).
//!
//! ```text
//! P1    = md5hex(RC4(key128, password))
//! P2    = P1[8..24]
//! P3    = md5hex(RC4(key128, P2))
//! final = P3[8..24]        → the login form's Password= value
//! ```
//!
//! RC4 is the textbook KSA/PRGA keyed with all 128 bytes of the key.

use std::fmt;

use gswifi_core::Secret;

use super::fixhbkey::{md5_hex, Hex32, Key128};

/// Textbook RC4 (KSA + PRGA). `key` must not be empty.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty(), "RC4 key must not be empty");
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            b ^ s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]
        })
        .collect()
}

/// The 16-character value sent as `Password=`. Derived credential:
/// redacted `Debug`, wiped on drop.
#[derive(Clone)]
pub struct OldMacPassword {
    value: Secret,
    rc4_nul: bool,
}

impl OldMacPassword {
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// One of the two RC4 outputs contained a 0x00 byte. The chain hashes
    /// the full RC4 output, like the reference; whether the firmware
    /// instead stops at the NUL (C string length) is not covered by any
    /// vector (gap, see crate docs). About 1 derivation in 10 is affected.
    pub fn rc4_output_had_nul(&self) -> bool {
        self.rc4_nul
    }
}

impl fmt::Debug for OldMacPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OldMacPassword(***)")
    }
}

/// Every intermediate of one chain, for the golden-vector tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ChainTrace {
    pub p1_rc4: Vec<u8>,
    pub p1_md5: Hex32,
    pub p2: [u8; 16],
    pub p3_rc4: Vec<u8>,
    pub p3_md5: Hex32,
    pub result: [u8; 16],
}

fn middle(h: &Hex32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[8..24]);
    out
}

pub(crate) fn trace(password: &[u8], key: &Key128) -> ChainTrace {
    let k = key.as_bytes();
    let p1_rc4 = rc4(k, password);
    let p1_md5 = md5_hex(&p1_rc4);
    let p2 = middle(&p1_md5);
    let p3_rc4 = rc4(k, &p2);
    let p3_md5 = md5_hex(&p3_rc4);
    let result = middle(&p3_md5);
    ChainTrace { p1_rc4, p1_md5, p2, p3_rc4, p3_md5, result }
}

/// Runs the chain on the raw password bytes with a FixHBKey.
pub fn derive_password(password: &[u8], key: &Key128) -> OldMacPassword {
    let t = trace(password, key);
    let rc4_nul = t.p1_rc4.contains(&0) || t.p3_rc4.contains(&0);
    let value: String = t.result.iter().map(|&b| b as char).collect();
    OldMacPassword { value: Secret::new(value), rc4_nul }
}
