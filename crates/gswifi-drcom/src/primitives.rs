//! Dr.com digests, checksums and seed hashes.
//!
//! Every function here is pure and length-checked. Sources:
//! * `md5a` / `md5b` / byte XOR: doc 14.1 (GS functions `0x420728`,
//!   `0x4207fc`, `0x4207b4`, dynamically compared, grade D) and doc 03 §3.2.
//! * password ROL extension: doc 03 §3.2 ("ror") and doc 14.1 (`0x4208a8`).
//! * `check16` / `check32`: doc 14.2 (`0x420bfc` / `0x420c88`, grade D).
//! * `checksum1968`: doc 03 §3.2 (Dogcom login checksum2, grade U).
//! * `seedhash`: doc 14.3 (`0x420d08`, grade D); `mixed_seedhash`: doc 23.2
//!   (`0x420dd8`, grade D); `gen_crc`: doc 03 §3.5 (grade U).

use sha1::{Digest, Sha1};

use crate::Error;

/// MD5A = MD5(`03 01` || seed4 || password) (doc 14.1, doc 03 §3.2).
///
/// The password is the C string without its NUL; the empty password has a
/// defined digest (doc 14.1).
pub fn md5a(seed: [u8; 4], password: &[u8]) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    ctx.consume([0x03, 0x01]);
    ctx.consume(seed);
    ctx.consume(password);
    ctx.compute().0
}

/// MD5B = MD5(`01` || password || seed4 || `00 00 00 00`) (doc 14.1).
pub fn md5b(seed: [u8; 4], password: &[u8]) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    ctx.consume([0x01]);
    ctx.consume(password);
    ctx.consume(seed);
    ctx.consume([0u8; 4]);
    ctx.compute().0
}

/// Byte-wise XOR of two equally long inputs (doc 14.1, `0x4207b4`).
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    if a.len() != b.len() {
        return Err(Error::Invalid(format!("xor of {} and {} bytes", a.len(), b.len())));
    }
    Ok(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
}

/// Password extension of "ror" profiles: `ROL8(MD5A[i] ^ password[i], 3)`
/// for every password byte (doc 03 §3.2, doc 14.1 `0x4208a8`).
///
/// Doc 03 §3.2/§3.7: the upstream indexes MD5A by password position, so a
/// password longer than 16 bytes would read past the digest. That case is
/// rejected instead of being "supported".
pub fn ror_password(md5a: &[u8; 16], password: &[u8]) -> Result<Vec<u8>, Error> {
    if password.len() > 16 {
        return Err(Error::Invalid(format!(
            "ror profiles support passwords of at most 16 bytes, got {} (doc 03 §3.2)",
            password.len()
        )));
    }
    Ok(md5a.iter().zip(password).map(|(m, p)| (m ^ p).rotate_left(3)).collect())
}

/// 16-bit Dr.com checksum: XOR of all LE16 words, times 711, low 16 bits,
/// serialised LE16 (doc 14.2). Unaligned input is an error and the empty
/// input yields `00 00`, exactly like the original helper.
pub fn check16(data: &[u8]) -> Result<[u8; 2], Error> {
    if data.len() % 2 != 0 {
        return Err(Error::Invalid(format!("check16 needs an even length, got {}", data.len())));
    }
    let acc = data.chunks_exact(2).fold(0u16, |acc, w| acc ^ u16::from_le_bytes([w[0], w[1]]));
    Ok(acc.wrapping_mul(711).to_le_bytes())
}

/// XOR of all LE16 words (helper of [`check16`] and GS control3, doc 30.4).
pub(crate) fn xor16(data: &[u8]) -> u16 {
    data.chunks(2).fold(0u16, |acc, w| acc ^ u16::from_le_bytes([w[0], *w.get(1).unwrap_or(&0)]))
}

/// 32-bit Dr.com checksum: XOR of all LE32 words, times 19680126
/// (`0x012c4b7e`), low 32 bits, serialised LE32 (doc 14.2). This is not the
/// 1968 multiplier of the Dogcom login checksum2 (see [`checksum1968`]).
pub fn check32(data: &[u8]) -> Result<[u8; 4], Error> {
    if data.len() % 4 != 0 {
        return Err(Error::Invalid(format!("check32 needs a multiple of 4 bytes, got {}", data.len())));
    }
    Ok(xor32(data, 0).wrapping_mul(19_680_126).to_le_bytes())
}

fn xor32(data: &[u8], init: u32) -> u32 {
    data.chunks_exact(4).fold(init, |acc, w| acc ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// Dogcom login checksum2 (doc 03 §3.2): start from 1234, XOR every LE32
/// word, multiply by 1968, low 32 bits, LE32. The caller zero-pads the
/// buffer to a multiple of 4 (doc 03 §3.2 asks for an explicit length
/// instead of relying on uninitialised memory).
pub fn checksum1968(data: &[u8]) -> Result<[u8; 4], Error> {
    if data.len() % 4 != 0 {
        return Err(Error::Invalid(format!("checksum2 needs a multiple of 4 bytes, got {}", data.len())));
    }
    Ok(xor32(data, 1234).wrapping_mul(1968).to_le_bytes())
}

/// Standard MD4 (RFC 1320). Only used by the selector-2 seed hash
/// (doc 14.3); implemented here to avoid another dependency.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());

    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    for block in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, w) in block.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        const R1: [u32; 4] = [3, 7, 11, 19];
        const R2: [u32; 4] = [3, 5, 9, 13];
        const R3: [u32; 4] = [3, 9, 11, 15];
        const O3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for i in 0..16 {
            let f = (b & c) | (!b & d);
            let t = a.wrapping_add(f).wrapping_add(x[i]).rotate_left(R1[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        for i in 0..16 {
            let k = (i % 4) * 4 + i / 4;
            let g = (b & c) | (b & d) | (c & d);
            let t = a.wrapping_add(g).wrapping_add(x[k]).wrapping_add(0x5a82_7999).rotate_left(R2[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        for (i, &k) in O3.iter().enumerate() {
            let h = b ^ c ^ d;
            let t = a.wrapping_add(h).wrapping_add(x[k]).wrapping_add(0x6ed9_eba1).rotate_left(R3[i % 4]);
            (a, b, c, d) = (d, t, b, c);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, s) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
    }
    out
}

/// Digest byte indices per selector (doc 14.3, identical in doc 03 §3.5 and
/// doc 23.2).
const PICK: [[usize; 8]; 3] = [
    [2, 3, 8, 9, 5, 6, 13, 14],  // 1: MD5
    [1, 2, 8, 9, 4, 5, 11, 12],  // 2: MD4
    [2, 3, 9, 10, 5, 6, 15, 16], // 3: SHA1
];

fn picked(selector: u8, input: &[u8]) -> [u8; 8] {
    let digest: Vec<u8> = match selector {
        1 => md5::compute(input).0.to_vec(),
        2 => md4(input).to_vec(),
        _ => Sha1::digest(input).to_vec(),
    };
    let mut out = [0u8; 8];
    for (o, &i) in out.iter_mut().zip(PICK[selector as usize - 1].iter()) {
        *o = digest[i];
    }
    out
}

/// Fixed 8 bytes used when no seed hash applies (doc 03 §3.5 type 0,
/// doc 30.4: VA `0x42f458`).
pub const FALLBACK_CRC: [u8; 8] = [0xc7, 0x2f, 0x31, 0x01, 0x7e, 0x00, 0x00, 0x00];

/// Direct 4-byte seed hash `0x420d08` (doc 14.3): `selector = seed[0] & 3`.
/// Returns `None` when disabled or selector 0 (the original returns 1 and
/// leaves its output untouched); otherwise 8 picked digest bytes of
/// MD5/MD4/SHA1(seed4).
pub fn seedhash(enabled: bool, seed: [u8; 4]) -> Option<[u8; 8]> {
    let selector = seed[0] & 3;
    (enabled && selector != 0).then(|| picked(selector, &seed))
}

/// Mixed seed hash `0x420dd8` (doc 23.2): like [`seedhash`] but hashes
/// `seed4 || 6a a2 33 01`. Kept separate on purpose: doc 23.2 / 30.4 say
/// the two must never be interchanged.
pub fn mixed_seedhash(enabled: bool, seed: [u8; 4]) -> Option<[u8; 8]> {
    let selector = seed[0] & 3;
    if !enabled || selector == 0 {
        return None;
    }
    let mut input = [0u8; 8];
    input[..4].copy_from_slice(&seed);
    input[4..].copy_from_slice(&[0x6a, 0xa2, 0x33, 0x01]);
    Some(picked(selector, &input))
}

/// Dogcom `gen_crc` (doc 03 §3.5): type 0 is the fixed [`FALLBACK_CRC`];
/// types 1/2/3 are the MD5/MD4/SHA1 picks of the 4 input bytes. Only the low
/// two bits of `encrypt_type` are used.
pub fn gen_crc(encrypt_type: u8, seed: [u8; 4]) -> [u8; 8] {
    match encrypt_type & 3 {
        0 => FALLBACK_CRC,
        t => picked(t, &seed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|j| ((j * 13 + 7) & 255) as u8).collect()
    }

    /// Golden vectors from `evidence/deep/algorithm-comparison.json` and
    /// `evidence/p0/pure-more.log` (see testdata/README.md).
    #[test]
    fn firmware_golden_vectors() {
        let text = include_str!("../testdata/primitives.txt");
        let mut counts = std::collections::BTreeMap::new();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let p: Vec<&str> = line.split_whitespace().collect();
            *counts.entry(p[0]).or_insert(0) += 1;
            match p[0] {
                "dr-md5a" | "dr-md5b" => {
                    let n: usize = p[1].parse().unwrap();
                    let pw: Vec<u8> = (0..n).map(|j| 97 + (j % 26) as u8).collect();
                    let out = if p[0] == "dr-md5a" { md5a([0, 1, 2, 3], &pw) } else { md5b([0, 1, 2, 3], &pw) };
                    assert_eq!(hex(&out), p[2], "{line}");
                }
                "dr-check16" | "dr-check32" => {
                    let n: usize = p[1].parse().unwrap();
                    let data = pattern(n);
                    let out = if p[0] == "dr-check16" {
                        check16(&data).map(|v| v.to_vec())
                    } else {
                        check32(&data).map(|v| v.to_vec())
                    };
                    if p[2] == "-1" {
                        assert!(out.is_err(), "{line}");
                    } else {
                        assert_eq!(hex(&out.unwrap()), p[3], "{line}");
                    }
                }
                "dr-seedhash" | "dr-mixed" => {
                    // pure-more.log: "DRMIX enabled selector ret out", seed [s,1,2,3];
                    // seedhash: "enabled selector out", seed [s,0x91,0x22,0xe3].
                    let enabled = p[1] == "1";
                    let selector: u8 = p[2].parse().unwrap();
                    let (out, want) = if p[0] == "dr-seedhash" {
                        (seedhash(enabled, [selector, 0x91, 0x22, 0xe3]), p[3])
                    } else {
                        let ret: i32 = p[3].parse().unwrap();
                        let out = mixed_seedhash(enabled, [selector, 1, 2, 3]);
                        assert_eq!(out.is_some(), ret == 0, "{line}");
                        (out, p[4])
                    };
                    // The original leaves its 0xcc sentinel untouched on None.
                    let got = out.map(|o| hex(&o)).unwrap_or_else(|| "cc".repeat(8));
                    assert_eq!(got, want, "{line}");
                }
                "dr-mac-xor" => {
                    let a: Vec<u8> = (0..6).map(|j| (j * 41) as u8).collect();
                    let b: Vec<u8> = (0..6).map(|j| (j * 17) as u8).collect();
                    assert_eq!(hex(&xor_bytes(&a, &b).unwrap()), p[1]);
                }
                other => panic!("unknown vector {other}"),
            }
        }
        assert_eq!(counts["dr-md5a"], 8);
        assert_eq!(counts["dr-md5b"], 8);
        assert_eq!(counts["dr-check16"], 12);
        assert_eq!(counts["dr-check32"], 12);
        assert_eq!(counts["dr-seedhash"], 8);
        assert_eq!(counts["dr-mixed"], 8);
    }

    #[test]
    fn doc_14_named_examples() {
        // doc 14.1: password "abcdefghi", seed 00 01 02 03.
        assert_eq!(hex(&md5a([0, 1, 2, 3], b"abcdefghi")), "56b64401eb3cb5a2cd77dc6c5d815cd7");
        assert_eq!(hex(&md5b([0, 1, 2, 3], b"abcdefghi")), "90dae5ab0776fd17a2f2e5414938034d");
        // doc 14.2: pattern of length 4.
        assert_eq!(hex(&check16(&pattern(4)).unwrap()), "8a7f");
        assert_eq!(hex(&check32(&pattern(4)).unwrap()), "72e859dd");
        // doc 14.3: seed [selector,91,22,e3].
        assert_eq!(hex(&seedhash(true, [1, 0x91, 0x22, 0xe3]).unwrap()), "249982861512a4ca");
        assert_eq!(hex(&seedhash(true, [2, 0x91, 0x22, 0xe3]).unwrap()), "c313a6d64919aa66");
        assert_eq!(hex(&seedhash(true, [3, 0x91, 0x22, 0xe3]).unwrap()), "95163b19233f9e7d");
        assert_eq!(seedhash(true, [4, 0x91, 0x22, 0xe3]), None);
        assert_eq!(seedhash(false, [1, 0x91, 0x22, 0xe3]), None);
    }

    #[test]
    fn md4_rfc1320() {
        assert_eq!(hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(hex(&md4(b"message digest")), "d9130a8164549fe818874806e1c7014b");
        assert_eq!(
            hex(&md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }

    #[test]
    fn gen_crc_matches_seedhash_and_fallback() {
        let seed = [0x6f, 0x7c, 0x89, 0x96];
        assert_eq!(gen_crc(0, seed), FALLBACK_CRC);
        for t in 1..4u8 {
            let mut s = seed;
            s[0] = (s[0] & !3) | t;
            assert_eq!(Some(gen_crc(t, s)), seedhash(true, s));
        }
        assert_eq!(FALLBACK_CRC.to_vec(), include_bytes!("../testdata/dr-control-fallback.bin").to_vec());
    }

    #[test]
    fn ror_and_lengths() {
        let m = md5a([0x00, 0x00, 0x20, 0x00], b"synthetic");
        assert_eq!(hex(&ror_password(&m, b"synthetic").unwrap()), "94b8b7b6389ae63704");
        assert!(ror_password(&m, &[b'a'; 17]).is_err());
        assert!(xor_bytes(&[1], &[1, 2]).is_err());
        assert!(checksum1968(&[0; 3]).is_err());
        assert_eq!(checksum1968(&[]).unwrap(), (1234u32 * 1968).to_le_bytes());
    }
}
