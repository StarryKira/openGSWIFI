//! Ruijie UDP heartbeat helpers (doc 20.1, 20.4, 20.5): RC4 attribute
//! decryption, the built-in UDP material tables and the payload builder.

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

use super::hash::{md5c, whirlpoolc};
use super::hex_lower;
use super::mix::{compute, hex128, Entry, Family};

/// RC4 key for the 0x5c (key8) and 0x5d (IV8) attributes: ASCII, 14 bytes,
/// no terminator (doc 20.4).
pub const ATTRIBUTE_RC4_KEY: &[u8; 14] = b"com.ruijie.www";

/// Default UDP interval when attribute 0x59 is absent (doc 20.4).
pub const DEFAULT_INTERVAL_SECS: u32 = 300;

/// Initial sequence number; the caller increments it after each payload
/// (doc 20.5).
pub const INITIAL_SEQ: u32 = 1;

/// Rows per UDP material table (doc 20.1).
pub const MATERIAL_ROWS: usize = 53;

/// The four UDP material tables, 53 rows of `A64 || B64` each (doc 20.1).
/// Index = table family from [`table_family`].
static MATERIAL_TABLES: [&[u8; 6784]; 4] = [
    include_bytes!("data/udp-material-pre499.bin"),
    include_bytes!("data/udp-material-499-524.bin"),
    include_bytes!("data/udp-material-525-641.bin"),
    include_bytes!("data/udp-material-642plus.bin"),
];

/// Fixed seed of table family 0 (VA 0x4230dc, doc 20.1).
static UDP_SEED16: &[u8; 16] = include_bytes!("data/udp-seed16.bin");

/// Fixed 128-character result of table family 1 selector 4 (VA 0x423014,
/// doc 20.1).
static UDP_499_SELECTOR4: &[u8; 128] = include_bytes!("data/udp-499-selector4.bin");

/// Standard RC4 (KSA + PRGA) over `data`.
///
/// # Panics
/// If `key` is empty.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(!key.is_empty(), "RC4 key must not be empty");
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
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

/// Decrypts the 8-byte value of attribute 0x5c (key) or 0x5d (IV). Each
/// field uses a freshly initialised RC4 stream (doc 20.4).
pub fn decrypt_attribute(value: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&rc4(ATTRIBUTE_RC4_KEY, value));
    out
}

/// UDP material table family 0..3 for an algorithm version (doc 20.1):
/// <499, 499..524, 525..641, >=642.
pub fn table_family(algo_version: u32) -> usize {
    match algo_version {
        0..=498 => 0,
        499..=524 => 1,
        525..=641 => 2,
        _ => 3,
    }
}

/// Material row index: `(sum of bytes of BE32(seq) || challenge16) * 727 % 53`
/// (doc 20.5). `challenge` is the cached EAP MD5 challenge.
pub fn row_index(seq: u32, challenge: &[u8; 16]) -> usize {
    let sum: u32 = seq.to_be_bytes().iter().chain(challenge).map(|&b| u32::from(b)).sum();
    (sum * 727 % MATERIAL_ROWS as u32) as usize
}

/// Counter value for the next payload (doc 20.5): versions < 480 add the UDP
/// interval, >= 480 add 1.
pub fn next_counter(counter: u64, algo_version: u32, interval_secs: u32) -> u64 {
    if algo_version < 480 {
        counter.wrapping_add(u64::from(interval_secs))
    } else {
        counter.wrapping_add(1)
    }
}

/// 128 ASCII characters of UDP material for `row` of table `family`
/// (doc 20.1).
///
/// Family 0 uses the fixed seed16, the others the first 16 bytes of the
/// row's B. The sub-entry is `row % 5`. Two special cases: family 0
/// selector 0 is the 0x40a2d4 recipe with *unsigned* `%02x` seed bytes, and
/// family 1 selector 4 is a fixed 128-byte string. Family 3 uses its own
/// entry order 408c34/40908c/408f08/4088f4/408a50.
///
/// # Panics
/// If `family > 3` or `row > 52`.
pub fn udp_material(family: usize, row: usize) -> [u8; 128] {
    assert!(family < 4 && row < MATERIAL_ROWS, "UDP material family 0..3, row 0..52");
    let line = &MATERIAL_TABLES[family][row * 128..(row + 1) * 128];
    let (a, b) = line.split_at(64);
    let seed: [u8; 16] = if family == 0 { *UDP_SEED16 } else { b[..16].try_into().expect("16 bytes") };
    let selector = row % 5;
    if family == 0 && selector == 0 {
        // Firmware 0x4087c4: like 40a2d4 but unsigned `%02x` -> exactly 96 bytes.
        let even: Vec<u8> = seed.iter().copied().step_by(2).collect();
        let odd: Vec<u8> = seed.iter().copied().skip(1).step_by(2).collect();
        let msg = [hex_lower(&md5c(a)), hex_lower(&even), hex_lower(&md5c(b)), hex_lower(&odd)].concat();
        return hex128(&whirlpoolc(&msg));
    }
    if family == 1 && selector == 4 {
        return *UDP_499_SELECTOR4;
    }
    let entries = match family {
        0 => Family::F40a908.entries(),
        1 => Family::F40aba0.entries(),
        2 => Family::F40a9a4.entries(),
        _ => [Entry::E408c34, Entry::E40908c, Entry::E408f08, Entry::E4088f4, Entry::E408a50],
    };
    hex128(&compute(entries[selector], a, b, &seed))
}

/// Standard DES-CBC encryption of an 8-byte aligned buffer.
fn des_cbc_encrypt(data: &mut [u8], key: &[u8; 8], iv: &[u8; 8]) {
    let cipher = Des::new(&GenericArray::from(*key));
    let mut prev = *iv;
    for block in data.chunks_exact_mut(8) {
        for (x, p) in block.iter_mut().zip(prev) {
            *x ^= p;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        prev.copy_from_slice(block);
    }
}

/// Full UDP heartbeat payload (doc 20.5), starting at the UDP payload.
///
/// `key`/`iv` are the already RC4-decrypted 0x5c/0x5d values, `counter` the
/// current 64-bit counter, `challenge` the cached EAP MD5 challenge. Returns
/// `None` if `username` is longer than 255 bytes (its length is one byte).
#[allow(clippy::too_many_arguments)]
pub fn udp_payload(
    username: &[u8],
    ipv4: [u8; 4],
    mac: [u8; 6],
    algo_version: u32,
    seq: u32,
    counter: u64,
    challenge: &[u8; 16],
    key: &[u8; 8],
    iv: &[u8; 8],
) -> Option<Vec<u8>> {
    let username_len = u8::try_from(username.len()).ok()?;
    let material = udp_material(table_family(algo_version), row_index(seq, challenge));

    // Plaintext TLVs; lengths are value lengths (doc 20.5).
    let mut inner = Vec::with_capacity(32 + username.len() + 128);
    inner.extend_from_slice(&[0x01, 0x01, 0x02, 0x03, username_len]);
    inner.extend_from_slice(username);
    inner.extend_from_slice(&[0x04, 0x04]);
    inner.extend_from_slice(&ipv4);
    inner.extend_from_slice(&[0x05, 0x06]);
    inner.extend_from_slice(&mac);
    inner.extend_from_slice(&[0x14, 0x80]);
    inner.extend_from_slice(&material);
    // Zero padding to a multiple of 8; nothing added when already aligned.
    inner.resize(inner.len().div_ceil(8) * 8, 0);
    des_cbc_encrypt(&mut inner, key, iv);

    let total = 42 + inner.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x00, 0x01]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0u8; 16]); // MD5 digest, filled below
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&counter.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x01]);
    p.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    p.extend_from_slice(&inner);

    // Digest: standard MD5(payload with zeroed digest || key8 || IV8).
    let mut ctx = md5::Context::new();
    ctx.consume(&p);
    ctx.consume(key);
    ctx.consume(iv);
    p[8..24].copy_from_slice(&ctx.compute().0);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::unhex;

    #[test]
    fn rc4_attribute_vector() {
        // evidence/p0/extra-validation.json kind=RC4.
        assert_eq!(rc4(ATTRIBUTE_RC4_KEY, b"12345678"), unhex("23dacfec97a21e4b"));
        assert_eq!(decrypt_attribute(b"12345678").to_vec(), unhex("23dacfec97a21e4b"));
        // RC4 is symmetric.
        assert_eq!(decrypt_attribute(&[0x23, 0xda, 0xcf, 0xec, 0x97, 0xa2, 0x1e, 0x4b]), *b"12345678");
    }

    /// All 212 rows from evidence/p0/extra-validation.json kind=UDPMAT.
    #[test]
    fn material_212_rows() {
        let mut checked = 0;
        for line in include_str!("testdata/udp-material.txt").lines().filter(|l| !l.starts_with('#')) {
            let p: Vec<&str> = line.split_whitespace().collect();
            let (family, row): (usize, usize) = (p[0].parse().unwrap(), p[1].parse().unwrap());
            assert_eq!(&udp_material(family, row)[..], p[2].as_bytes(), "family {family} row {row}");
            checked += 1;
        }
        assert_eq!(checked, 212);
    }

    #[test]
    fn helpers() {
        assert_eq!(table_family(498), 0);
        assert_eq!(table_family(499), 1);
        assert_eq!(table_family(524), 1);
        assert_eq!(table_family(525), 2);
        assert_eq!(table_family(641), 2);
        assert_eq!(table_family(642), 3);
        assert_eq!(next_counter(10, 479, 30), 40);
        assert_eq!(next_counter(10, 480, 30), 11);
        let challenge: [u8; 16] = std::array::from_fn(|i| i as u8);
        // (0+0+0+1 + 120) * 727 % 53
        assert_eq!(row_index(1, &challenge), 121 * 727 % 53);
    }

    /// evidence/p0/udp-three-frames.json: three synthetic payloads, version
    /// 410, seq 1..3, counter +30 each, challenge 00..0f.
    #[test]
    fn three_frames() {
        const PAYLOADS: [&str; 3] = [
            "02010000000100caa353d2aba7400c7e81f1e02c6a0228ef0000000105060708010203040101000000a01098ad1a3be4a04267b7007c3602f15289e8bbe90db47458ef6df717592c4cbe185dea54ad1f6dbeb5c5cb30b603199c20b9610af7d5d5b55c97d60bb1c80e85bfba6a184b64106ec0088156baf0c865d7c5b821d4aa1ca4f80f6082974f8ad132c3930f0225b6ad184856053be105bd06010a5aea82e39b53a36afb10b71925a4629b73308374bce4f57dedb765e7fc7203bb06ce234e391cb7b73e1d0fb99f",
            "02010000000100caa8ce06216a085a31d5135a2ad348ebb30000000205060708010203220101000000a01098ad1a3be4a04267b7007c3602f15289e8bbe90db47458d52099a31e7fb8e375247b3d1d2af0e9cd941afacdc27839a730b86beb4d5bf9b93c96d21cd4e0d94f3303cf295e5de26d66c45ae5f38b6c2795f24a05fad242aa0351ee7b90d6ead30180d79fa844a7961b2e43447386ac44dfa6cc3a2c073673a61043960adbec5cfab8dbb3962cce749114993e7462e132f8f545b6f88125dc14dec48154ce4e",
            "02010000000100ca5be5b048d306c22b6aff07e28f2c3c010000000305060708010203400101000000a01098ad1a3be4a04267b7007c3602f15289e8bbe90db4745899b1f029a0b33eb26c6127bff717131a7dab679aebaf668413e7d25e05704b1218ad22c8ea6c6aeea3196d4efc4cbbcb35e251e931a9655d45eb5780c95d50a4ef0a9e8e9c1df1ec5767eed0ca4e74000cd5e3d3fb7799a0e60df62e5e4c31028b24ff98898b117071d4ac0190cb45545875867fb68bb6193f4943b4a149826b35c363e909f655e9",
        ];
        let challenge: [u8; 16] = std::array::from_fn(|i| i as u8);
        let mut counter = 0x0506_0708_0102_0304u64;
        for (seq, want) in (INITIAL_SEQ..).zip(PAYLOADS) {
            let got = udp_payload(
                b"synthetic",
                [192, 0, 2, 10],
                [0x02, 0, 0, 0, 0, 0x01],
                410,
                seq,
                counter,
                &challenge,
                b"12345678",
                b"abcdefgh",
            )
            .unwrap();
            assert_eq!(got.len(), 202);
            assert_eq!(got, unhex(want), "seq {seq}");
            counter = next_counter(counter, 410, 30);
        }
    }

    #[test]
    fn rejects_long_username() {
        let name = [b'x'; 256];
        assert!(udp_payload(&name, [0; 4], [0; 6], 410, 1, 0, &[0; 16], &[0; 8], &[0; 8]).is_none());
    }
}
