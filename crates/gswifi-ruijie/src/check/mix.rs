//! The 20 mix sub-entries, the 5 version families and their selectors
//! (doc 15.3–15.5, doc 19.2–19.3). Produces the 128-byte 0x4d value.
//!
//! Notation follows doc 19.3: A/B are the caller's full material byte
//! strings, `seed` the 16 raw challenge bytes. Byte additions wrap mod 256.

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, KeyInit};
use des::Des;

use super::hash::{md5c, ripemd128c, sha1c, tigerc, whirlpoolc};
use super::hex_lower;

/// DES key of 0x408a50 / 0x408c34 (doc 19.3).
const DES_KEY_408A50: [u8; 8] = [0x76, 0x2a, 0x24, 0x21, 0x31, 0x64, 0x33, 0x56];
/// DES key of the 409xxx / 40a110 / 40993c entries (doc 19.3); same bytes as
/// data/ruijie/des-fixed-key8.bin (VA 0x42e890), ASCII `?r^3d)5,`. Also the
/// key of the 499..524 client material decryption (doc 25.1).
pub(crate) const DES_KEY_3F72: [u8; 8] = [0x3f, 0x72, 0x5e, 0x33, 0x64, 0x29, 0x35, 0x2c];
/// DES key applied to the Whirlpool output in 0x40908c (doc 19.3).
const DES_KEY_40908C: [u8; 8] = [0x7b, 0x3f, 0x5e, 0x39, 0x2a, 0x7e, 0x21, 0x6f];

/// One of the 20 unique mix sub-entries, named by firmware address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    E4088f4,
    E408a50,
    E408c34,
    E408f08,
    E40908c,
    E409284,
    E409398,
    E409574,
    E4097a4,
    E40993c,
    E409b2c,
    E409cf8,
    E409e08,
    E409f54,
    E40a110,
    E40a2d4,
    E40a404,
    E40a4ac,
    E40a5dc,
    E40a7a4,
}

// Addresses and lists name the test vectors.
#[cfg_attr(not(test), allow(dead_code))]
impl Entry {
    pub const ALL: [Entry; 20] = [
        Entry::E4088f4,
        Entry::E408a50,
        Entry::E408c34,
        Entry::E408f08,
        Entry::E40908c,
        Entry::E409284,
        Entry::E409398,
        Entry::E409574,
        Entry::E4097a4,
        Entry::E40993c,
        Entry::E409b2c,
        Entry::E409cf8,
        Entry::E409e08,
        Entry::E409f54,
        Entry::E40a110,
        Entry::E40a2d4,
        Entry::E40a404,
        Entry::E40a4ac,
        Entry::E40a5dc,
        Entry::E40a7a4,
    ];

    /// Firmware address the entry is named after.
    pub fn address(self) -> u32 {
        match self {
            Entry::E4088f4 => 0x4088f4,
            Entry::E408a50 => 0x408a50,
            Entry::E408c34 => 0x408c34,
            Entry::E408f08 => 0x408f08,
            Entry::E40908c => 0x40908c,
            Entry::E409284 => 0x409284,
            Entry::E409398 => 0x409398,
            Entry::E409574 => 0x409574,
            Entry::E4097a4 => 0x4097a4,
            Entry::E40993c => 0x40993c,
            Entry::E409b2c => 0x409b2c,
            Entry::E409cf8 => 0x409cf8,
            Entry::E409e08 => 0x409e08,
            Entry::E409f54 => 0x409f54,
            Entry::E40a110 => 0x40a110,
            Entry::E40a2d4 => 0x40a2d4,
            Entry::E40a404 => 0x40a404,
            Entry::E40a4ac => 0x40a4ac,
            Entry::E40a5dc => 0x40a5dc,
            Entry::E40a7a4 => 0x40a7a4,
        }
    }

    pub fn from_address(addr: u32) -> Option<Entry> {
        Entry::ALL.into_iter().find(|e| e.address() == addr)
    }
}

/// The five version families (doc 19.2 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// algorithm version < 499
    F40a908,
    /// 499..=524
    F40aba0,
    /// 525..=641
    F40a9a4,
    /// exactly 642
    F40aa40,
    /// >= 643
    F40aafc,
}

// Addresses and lists name the test vectors.
#[cfg_attr(not(test), allow(dead_code))]
impl Family {
    pub const ALL: [Family; 5] = [
        Family::F40a908,
        Family::F40aba0,
        Family::F40a9a4,
        Family::F40aa40,
        Family::F40aafc,
    ];

    /// Family for an algorithm version `major * 100 + minor` (doc 19.2). This
    /// is the algorithm version pair (`RjCheckVersion`), not the header
    /// Version field.
    pub fn for_version(algo_version: u32) -> Family {
        match algo_version {
            0..=498 => Family::F40a908,
            499..=524 => Family::F40aba0,
            525..=641 => Family::F40a9a4,
            642 => Family::F40aa40,
            _ => Family::F40aafc,
        }
    }

    pub fn address(self) -> u32 {
        match self {
            Family::F40a908 => 0x40a908,
            Family::F40aba0 => 0x40aba0,
            Family::F40a9a4 => 0x40a9a4,
            Family::F40aa40 => 0x40aa40,
            Family::F40aafc => 0x40aafc,
        }
    }

    pub fn from_address(addr: u32) -> Option<Family> {
        Family::ALL.into_iter().find(|f| f.address() == addr)
    }

    /// Selector 0..4 to sub-entry mapping (doc 19.2 table).
    pub fn entries(self) -> [Entry; 5] {
        use Entry::*;
        match self {
            Family::F40a908 => [E40a2d4, E40a404, E40a4ac, E40a5dc, E40a7a4],
            Family::F40aba0 => [E409b2c, E409cf8, E409e08, E409f54, E40a110],
            Family::F40a9a4 => [E409284, E409398, E409574, E4097a4, E40993c],
            Family::F40aa40 | Family::F40aafc => [E4088f4, E408a50, E408c34, E408f08, E40908c],
        }
    }

    /// Selector for `seed` (doc 15.4 / 19.2). `None` only for 642 when the
    /// C remainder is negative; that branch outputs 128 zero bytes.
    pub fn selector(self, seed: &[u8; 16]) -> Option<usize> {
        match self {
            Family::F40a908 | Family::F40aba0 | Family::F40a9a4 => {
                Some(usize::from(seed[0].wrapping_add(seed[3])) % 5)
            }
            Family::F40aa40 | Family::F40aafc => {
                let sum = i32::from(seed[1] as i8) + i32::from(seed[4] as i8);
                // Rust `%` truncates toward zero exactly like C.
                let r = sum % 5;
                if r < 0 && self == Family::F40aa40 {
                    None
                } else {
                    // 643+: the (possibly negative) remainder is reinterpreted
                    // as uint32 and reduced again.
                    Some(((r as u32) % 5) as usize)
                }
            }
        }
    }
}

/// Final 0x4d value for an algorithm version (doc 19.2): 128 lowercase ASCII
/// hex characters of the selected entry's raw64, or 128 binary zero bytes in
/// the 642 negative-remainder case.
pub fn family_result(algo_version: u32, a: &[u8], b: &[u8], seed: &[u8; 16]) -> [u8; 128] {
    family_result_for(Family::for_version(algo_version), a, b, seed)
}

/// As [`family_result`] for an explicit family.
pub fn family_result_for(family: Family, a: &[u8], b: &[u8], seed: &[u8; 16]) -> [u8; 128] {
    match family.selector(seed) {
        Some(sel) => hex128(&compute(family.entries()[sel], a, b, seed)),
        None => [0u8; 128],
    }
}

/// Lowercase hex of a raw64 result.
pub fn hex128(raw: &[u8; 64]) -> [u8; 128] {
    let mut out = [0u8; 128];
    out.copy_from_slice(&hex_lower(raw));
    out
}

/// Standard DES-ECB decryption, 8-byte blocks, no padding (doc 19.3 `DESdec`).
/// A trailing partial block is left as it is; callers pass whole blocks.
pub(crate) fn des_dec(data: &[u8], key: &[u8; 8]) -> Vec<u8> {
    let cipher = Des::new(&GenericArray::from(*key));
    let mut out = data.to_vec();
    for block in out.chunks_exact_mut(8) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    out
}

/// `signedhex` (doc 19.3): each byte sign-extended to int32 and printed with
/// C `%02x`, so 0x80 becomes `ffffff80`.
fn signed_hex(bytes: impl IntoIterator<Item = u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for b in bytes {
        let v = b as i8 as i32 as u32;
        out.extend_from_slice(format!("{v:02x}").as_bytes());
    }
    out
}

/// Bytes at indices `start, start-2, ..., start % 2` (e.g. `D0[15,13,...,1]`).
fn every_other_desc(d: &[u8], start: usize) -> impl Iterator<Item = u8> + '_ {
    (0..=start).rev().step_by(2).map(move |i| d[i])
}

/// `reverse(R0).hex[..rlen] || signedhex(D0[first..]) || signedhex(D0[second..])`,
/// truncated to 64 bytes (shared by 408a50, 409398 and 409f54).
fn rhex_dhex_input(r0: &[u8; 16], d0: &[u8], rlen: usize, first: usize, second: usize) -> Vec<u8> {
    let mut rev = *r0;
    rev.reverse();
    let mut m = hex_lower(&rev);
    m.truncate(rlen);
    m.extend(signed_hex(every_other_desc(d0, first)));
    m.extend(signed_hex(every_other_desc(d0, second)));
    m.truncate(64);
    m
}

/// Concatenate byte slices.
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `w[63..0]`.
fn reversed(w: &[u8; 64]) -> [u8; 64] {
    let mut out = *w;
    out.reverse();
    out
}

/// `w[63], w[62], ..., w[64-n]` (each plus `add_base + k` when given)
/// followed by `w[0..64-n]` (408c34, 408f08, 409574, 4097a4, 40993c).
fn reversed_head(w: &[u8], n: usize, add_base: Option<u8>) -> [u8; 64] {
    let mut out = [0u8; 64];
    for k in 0..n {
        let add = add_base.map_or(0, |base| base.wrapping_add(k as u8));
        out[k] = w[63 - k].wrapping_add(add);
    }
    out[n..].copy_from_slice(&w[..64 - n]);
    out
}

/// `w[0..=16] || w[63..=17]` (4088f4, 409284).
fn head17_then_reversed(w: &[u8; 64]) -> [u8; 64] {
    let mut out = *w;
    out[17..].reverse();
    out
}

/// Raw 64-byte result of one sub-entry (doc 19.3). The recipes below are
/// written from doc 19.3 and match mix-layouts.json byte for byte.
pub fn compute(entry: Entry, a: &[u8], b: &[u8], seed: &[u8; 16]) -> [u8; 64] {
    let s = &seed[..];
    match entry {
        Entry::E4088f4 => {
            let s0 = sha1c(a);
            let m = hex_lower(&md5c(s));
            // Character tweaks on M0.hex and S0[1] are part of the recipe.
            let head = [
                m[0],
                m[3].wrapping_add(1),
                m[2],
                m[5].wrapping_sub(3),
                m[4],
                m[5],
                m[6],
                m[11].wrapping_add(5),
                m[8],
                m[9],
                m[10],
                m[13].wrapping_sub(7),
                m[12],
                m[17].wrapping_add(11),
                m[14],
                m[15],
                m[16],
                m[19].wrapping_sub(13),
                m[18],
                m[19],
                s[0],
                s[1],
                s[2],
                s0[1].wrapping_add(17),
                s[4],
                s[5],
            ];
            let w = whirlpoolc(&cat(&[&head, &s0, &s[6..16]]));
            head17_then_reversed(&w)
        }
        Entry::E408a50 | Entry::E409398 => {
            let key = if entry == Entry::E408a50 { &DES_KEY_408A50 } else { &DES_KEY_3F72 };
            let r0 = ripemd128c(a);
            let d0 = des_dec(s, key);
            reversed(&whirlpoolc(&rhex_dhex_input(&r0, &d0, 18, 15, 14)))
        }
        Entry::E408c34 => {
            let r0 = ripemd128c(a);
            let d0 = des_dec(s, &DES_KEY_408A50);
            let w = whirlpoolc(&cat(&[&r0[10..16], &d0, &r0[0..10], s]));
            reversed_head(&w, 32, Some(193))
        }
        Entry::E408f08 => {
            let t1 = tigerc(a);
            let s0 = sha1c(s);
            let w = whirlpoolc(&cat(&[&t1, &s[0..9], &[0x00], &s0, &s[8..14]]));
            reversed_head(&w, 16, Some(193))
        }
        Entry::E40908c => {
            let t1 = tigerc(a);
            let r0 = ripemd128c(s);
            let w = whirlpoolc(&cat(&[&t1[0..16], &s[0..9], &[0x48], &r0, &s[10..16]]));
            let d0 = des_dec(&w, &DES_KEY_40908C);
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&d0[..32]);
            for k in 0..32 {
                // D0[63]+1, D0[62], D0[61]+1, ... D0[32]
                out[32 + k] = d0[63 - k].wrapping_add(u8::from(k % 2 == 0));
            }
            out
        }
        Entry::E409284 | Entry::E409cf8 => {
            let s0 = sha1c(a);
            let m0 = hex_lower(&md5c(s));
            let w = whirlpoolc(&cat(&[&m0[0..20], &s[0..6], &s0, &s[6..16]]));
            if entry == Entry::E409284 {
                head17_then_reversed(&w)
            } else {
                reversed(&w)
            }
        }
        Entry::E409574 => {
            let r0 = ripemd128c(a);
            let d0 = des_dec(s, &DES_KEY_3F72);
            let w = whirlpoolc(&cat(&[&r0[0..10], &d0, &r0[10..16], s]));
            reversed_head(&w, 16, None)
        }
        Entry::E4097a4 => {
            let t1 = tigerc(a);
            let s0 = sha1c(s);
            let w = whirlpoolc(&cat(&[&t1, &s[0..10], &s0, &s[8..14]]));
            reversed_head(&w, 16, None)
        }
        Entry::E40993c | Entry::E409b2c => {
            let t1 = tigerc(a);
            let r0 = ripemd128c(s);
            let w = whirlpoolc(&cat(&[&t1[0..16], &s[0..10], &r0, &s[10..16]]));
            if entry == Entry::E40993c {
                reversed_head(&des_dec(&w, &DES_KEY_3F72), 32, None)
            } else {
                reversed(&w)
            }
        }
        Entry::E409e08 => {
            let t1 = tigerc(a);
            let s0 = sha1c(s);
            reversed(&whirlpoolc(&cat(&[&t1, &s[0..8], &s0, &s[8..16]])))
        }
        Entry::E409f54 => {
            let r0 = ripemd128c(a);
            let d0 = des_dec(s, &DES_KEY_3F72);
            // Full reverse(R0).hex, then even bytes before odd bytes.
            whirlpoolc(&rhex_dhex_input(&r0, &d0, 32, 14, 15))
        }
        Entry::E40a110 => {
            let r0 = ripemd128c(a);
            let d0 = des_dec(s, &DES_KEY_3F72);
            reversed(&whirlpoolc(&cat(&[&d0, &s[0..6], &r0, &s[6..16]])))
        }
        Entry::E40a2d4 => {
            let even = signed_hex(s.iter().copied().step_by(2));
            let odd = signed_hex(s.iter().copied().skip(1).step_by(2));
            let mut m = cat(&[&hex_lower(&md5c(a)), &even, &hex_lower(&md5c(b)), &odd]);
            m.truncate(96);
            whirlpoolc(&m)
        }
        Entry::E40a404 => {
            let s0 = sha1c(a);
            let s1 = sha1c(b);
            whirlpoolc(&cat(&[&s1, &s[0..6], &s0, &s[6..16]]))
        }
        Entry::E40a4ac => {
            let r1 = ripemd128c(a);
            let s0 = sha1c(b);
            whirlpoolc(&cat(&[&s0, &s[0..6], &r1, &s[6..16]]))
        }
        Entry::E40a5dc => {
            let t1 = tigerc(a);
            let r0 = ripemd128c(b);
            whirlpoolc(&cat(&[&t1, &s[0..10], &r0, &s[10..16]]))
        }
        Entry::E40a7a4 => {
            // Doc 19.3: the firmware hand-builds two Whirlpool blocks; for this
            // 60-byte message that equals W(message).
            let t0 = tigerc(b);
            let s0 = sha1c(a);
            whirlpoolc(&cat(&[&t0, &s[0..8], &s0, &s[8..16]]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::unhex;

    fn seed16(hex: &str) -> [u8; 16] {
        unhex(hex).try_into().expect("16-byte seed")
    }

    /// evidence/p0/mix-holdout.log: 240 per-entry cases (12 inputs x 20 entries).
    #[test]
    fn holdout_240() {
        let text = include_str!("testdata/mix-holdout.txt");
        let mut inputs = std::collections::HashMap::new();
        let mut checked = 0;
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let p: Vec<&str> = line.split_whitespace().collect();
            match p[0] {
                "I" => {
                    inputs.insert(p[1], (unhex(p[2]), unhex(p[3]), seed16(p[4])));
                }
                "R" => {
                    let entry = Entry::from_address(u32::from_str_radix(p[1], 16).unwrap()).unwrap();
                    let (a, b, s) = &inputs[p[2]];
                    let got = compute(entry, a, b, s);
                    assert_eq!(hex_lower(&got), p[3].as_bytes(), "{entry:?} case {}", p[2]);
                    checked += 1;
                }
                _ => panic!("bad line {line}"),
            }
        }
        assert_eq!(checked, 240);
    }

    /// evidence/deep/rj-mix-vectors.json (30) + rj-coverage-vectors.json (40).
    #[test]
    fn family_vectors_70() {
        let a: Vec<u8> = (0..64).map(|i| ((i * 3 + 1) & 255) as u8).collect();
        let b: Vec<u8> = (0..96).map(|i| ((i * 7 + 2) & 255) as u8).collect();
        let mut checked = 0;
        for line in include_str!("testdata/family-vectors.txt").lines().filter(|l| !l.starts_with('#')) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let family = Family::from_address(u32::from_str_radix(p[0], 16).unwrap()).unwrap();
            let seed = seed16(p[2]);
            let want_sel = if p[1] == "-" { None } else { Some(p[1].parse::<usize>().unwrap()) };
            assert_eq!(family.selector(&seed), want_sel, "{family:?} {}", p[2]);
            let got = family_result_for(family, &a, &b, &seed);
            if p[3] == "ZERO" {
                assert_eq!(got, [0u8; 128]);
            } else {
                assert_eq!(&got[..], p[3].as_bytes(), "{family:?} {}", p[2]);
            }
            checked += 1;
        }
        assert_eq!(checked, 70);
    }

    #[test]
    fn version_dispatch() {
        assert_eq!(Family::for_version(0), Family::F40a908);
        assert_eq!(Family::for_version(498), Family::F40a908);
        assert_eq!(Family::for_version(499), Family::F40aba0);
        assert_eq!(Family::for_version(524), Family::F40aba0);
        assert_eq!(Family::for_version(525), Family::F40a9a4);
        assert_eq!(Family::for_version(641), Family::F40a9a4);
        assert_eq!(Family::for_version(642), Family::F40aa40);
        assert_eq!(Family::for_version(643), Family::F40aafc);
        assert_eq!(Family::for_version(u32::MAX), Family::F40aafc);
    }

    #[test]
    fn selector_sign_rules() {
        // s8(0x80) + s8(0x80) = -256, C remainder -1.
        let mut seed = [0u8; 16];
        seed[1] = 0x80;
        seed[4] = 0x80;
        assert_eq!(Family::F40aa40.selector(&seed), None);
        // 643+: uint32(-1) % 5 = 0xffffffff % 5 = 0.
        assert_eq!(Family::F40aafc.selector(&seed), Some(0));
        assert_eq!(family_result(642, &[], &[], &seed), [0u8; 128]);
        // -3 -> 0xfffffffd % 5 = 3.
        seed[1] = 0xff;
        seed[4] = 0xfe;
        assert_eq!(Family::F40aafc.selector(&seed), Some(3));
        // Unsigned rule ignores sign: (0xff + 0x03) & 255 = 2.
        let mut seed = [0u8; 16];
        seed[0] = 0xff;
        seed[3] = 0x03;
        assert_eq!(Family::F40a908.selector(&seed), Some(2));
    }

    #[test]
    fn signed_hex_formats_like_c() {
        assert_eq!(signed_hex([0x00, 0x7f, 0x80, 0xff]), b"007fffffff80ffffffff".to_vec());
    }
}
