//! Ruijie custom hash variants, doc letters M/S/R/T/W (doc 15.2, 19.4–19.6).
//!
//! Each function keeps the block structure of the public algorithm it is
//! named after and applies only the documented differences. None of these
//! outputs equal the standard algorithm.

/// Merkle–Damgård padding: `marker`, zeros, then the bit length in the last
/// `length_bytes` bytes of the final 64-byte block (only the low 64 bits are
/// non-zero).
fn pad(data: &[u8], marker: u8, length_bytes: usize, big_endian: bool) -> Vec<u8> {
    let mut m = Vec::with_capacity(data.len() + 64 + length_bytes);
    m.extend_from_slice(data);
    m.push(marker);
    while m.len() % 64 != 64 - length_bytes {
        m.push(0);
    }
    let bits = (data.len() as u64).wrapping_mul(8);
    if big_endian {
        m.resize(m.len() + length_bytes - 8, 0);
        m.extend_from_slice(&bits.to_be_bytes());
    } else {
        m.extend_from_slice(&bits.to_le_bytes());
        m.resize(m.len() + length_bytes - 8, 0);
    }
    m
}

fn le32_words(block: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    w
}

/// Builds `N` u64 values from `N * 8` little-endian bytes at compile time.
const fn le64_table<const N: usize>(bytes: &[u8]) -> [u64; N] {
    assert!(bytes.len() == N * 8);
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        let p = i * 8;
        out[i] = u64::from_le_bytes([
            bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3],
            bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7],
        ]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// M: custom MD5 (doc 15.2)
// ---------------------------------------------------------------------------

/// Custom MD5 IV (doc 15.2).
const MD5C_IV: [u32; 4] = [0x5013_7246, 0x8acf_9dbe, 0xc9ef_aced, 0x2564_7013];

/// Per-step additive constants. Source: `_RJMD5_ROUNDS` in the spec pack's
/// `auth_primitives.py`. Differs from RFC 1321 at steps (0-based)
/// 13, 21, 32, 52, 61, 63; step 43 additionally gets an input-dependent term
/// (see [`md5c_block`]).
const MD5C_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987163, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02442453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3492, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655659c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af335, 0x2ad7d2bb, 0xeb866391,
];

/// Rotation amounts per round (doc 15.2: round 3 uses 5/11/16/23; the
/// `_RJMD5_ROUNDS` table also gives 19 instead of 21 in round 4).
const MD5C_S: [[u32; 4]; 4] = [[7, 12, 17, 22], [5, 9, 14, 20], [5, 11, 16, 23], [6, 10, 15, 19]];

/// Extra term added after `b + rotl(...)`, per round (doc 15.2).
const MD5C_POST: [u32; 4] = [2, 0u32.wrapping_sub(2), 0u32.wrapping_sub(1), 1];

fn md5c_block(state: &mut [u32; 4], block: &[u8]) {
    let x = le32_words(block);
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let round = i / 16;
        let (f, g) = match round {
            0 => ((b & c) | (!b & d), i),
            1 => ((b & d) | (c & !d), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let mut k = MD5C_K[i];
        if i == 43 {
            // Doc 15.2: step 44 (1-based) adds byte 1 of message word 2.
            k = k.wrapping_add((x[2] >> 8) & 0xff);
        }
        let v = a.wrapping_add(f).wrapping_add(x[g]).wrapping_add(k);
        let nb = b
            .wrapping_add(v.rotate_left(MD5C_S[round][i % 4]))
            .wrapping_add(MD5C_POST[round]);
        a = d;
        d = c;
        c = b;
        b = nb;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d]) {
        *s = s.wrapping_add(v);
    }
}

/// Ruijie custom MD5 ("M", firmware 0x41701c; doc 15.2).
pub fn md5c(data: &[u8]) -> [u8; 16] {
    let mut st = MD5C_IV;
    for block in pad(data, 0x80, 8, false).chunks_exact(64) {
        md5c_block(&mut st, block);
    }
    let mut out = [0u8; 16];
    for (o, w) in out.chunks_exact_mut(4).zip(st) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// S: custom SHA-1 (doc 19.4)
// ---------------------------------------------------------------------------

/// Custom SHA-1 IV (doc 19.4).
const SHA1C_IV: [u32; 5] = [0x3207_5416, 0xf8da_e9bc, 0x7354_1260, 0x8acb_9dfe, 0xfd0c_2e1b];

fn sha1c_block(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    // Doc 19.4: second-segment constant includes the first byte of the
    // current (padded) block. Inferred: the byte is zero-extended. A signed
    // reading fails every S vector with a block starting at the 0x80 pad
    // byte (n = 0, 64, 128 ...); the unsigned one passes all 11.
    let k2 = 0x16ae_9debu32.wrapping_add(u32::from(block[0]));
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, wi) in w.iter().enumerate() {
        // Doc 19.4: segments 0..19, 20..39, 40..60 (21 steps), 61..79.
        // Boolean functions are the SHA-1 ones (Ch, Parity, Maj, Parity);
        // inferred from "otherwise identical", confirmed by the S vectors.
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0u32.wrapping_sub(0x5d6a_a4d4)),
            20..=39 => (b ^ c ^ d, k2),
            40..=60 => ((b & c) | (b & d) | (c & d), 0u32.wrapping_sub(0x3403_2e48)),
            _ => (b ^ c ^ d, 0u32.wrapping_sub(0x5cd3_9e93)),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    // Doc 19.4: hash[0] gets an extra +1 in the feed-forward.
    h[0] = h[0].wrapping_add(a).wrapping_add(1);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// Ruijie custom SHA-1 ("S", firmware 0x4174fc; doc 19.4).
pub fn sha1c(data: &[u8]) -> [u8; 20] {
    let mut h = SHA1C_IV;
    for block in pad(data, 0x80, 8, true).chunks_exact(64) {
        sha1c_block(&mut h, block);
    }
    let mut out = [0u8; 20];
    for (o, w) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&w.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// R: custom RIPEMD-128 (doc 19.5, data/ruijie/ripemd-rounds.json)
// ---------------------------------------------------------------------------
//
// Inferred structure (doc 19.5 only summarises the round macros):
//
// * Every one of the 128 statements in ripemd-rounds.json has the form
//   `X[a] = rotl(X[a] + F(X[b], X[c], X[d]) + w[r] + K, s)` with
//   (b, c, d) the cyclic successors of `a` inside its line, exactly like
//   standard RIPEMD-128. Message order `r`/`r'` and rotations `s`/`s'` are
//   the standard RIPEMD-128 tables for all 128 steps (checked statement by
//   statement), so the "rotation differences" in doc 19.5 are already the
//   standard per-step rotations, not changes to them.
// * Round functions follow standard RIPEMD-128: left line F1 xor, F2
//   (x&y)|(!x&z), F3 (x|!y)^z, F4 (x&z)|(y&!z); right line uses them in
//   reverse order (F4, F3, F2, F1). The 20 explicit statements in the JSON
//   use exactly these functions, so the only per-step deviation from a
//   round's (F, K) is the additive constant ([`RMD_K_OVERRIDE`]).
// * The final merge is the standard RIPEMD-128 combination with an extra +1
//   on the new h[2]. Found by testing: without it all single-block vectors
//   were off by exactly 1 in word 2; with it all 11 `R` vectors in
//   evidence/p0/hash-gs.log (and every mix vector using R) match. No other
//   single round-function substitution matches the vectors.

/// Custom RIPEMD-128 IV (doc 19.5).
const RMD_IV: [u32; 4] = [0x1025_7436, 0xa8bd_9cfe, 0x9efc_ad8b, 0x1237_5460];

/// Per-round additive constants R1..R8 (doc 19.5: R1/R8 `+2`, R2 325b99a1,
/// R3 1baed69c, R4 bcdcb1f9, R5 5a82798a, R6 41d42d5d, R7 30ed3f68).
const RMD_K: [u32; 8] = [
    2, 0x325b_99a1, 0x1bae_d69c, 0xbcdc_b1f9, 0x5a82_798a, 0x41d4_2d5d, 0x30ed_3f68, 2,
];

/// Steps (0..63 left line, 64..127 right line, in ripemd-rounds.json order)
/// whose constant is not the round constant. 20 come from the explicit
/// expressions in the JSON; step 53 is the macro call with `w[8] + 2`
/// folded into the constant (addition is mod 2^32, so it is equivalent).
const RMD_K_OVERRIDE: [(usize, u32); 21] = [
    (17, 0x0000_0002),
    (23, 0xbcdc_b1f9),
    (25, 0x0000_0002),
    (31, 0x0000_0002),
    (43, 0x325b_99a1),
    (45, 0xbcdc_b1fa),
    (50, 0x325b_99a1),
    (53, 0xbcdc_b1fb),
    (57, 0x1bae_d69c),
    (59, 0x0000_0002),
    (63, 0xbcdc_b1fc),
    (70, 0x325b_99a1),
    (74, 0xbcdc_b1f9),
    (78, 0xbcdc_b1fc),
    (86, 0xbcdc_b1f9),
    (87, 0xbcdc_b1fd),
    (94, 0x325b_99a1),
    (102, 0xbcdc_b1fe),
    (105, 0x5a82_798a),
    (110, 0x41d4_2d5d),
    (113, 0xbcdc_b1fe),
];

/// Standard RIPEMD-128 message word order, left line then right line.
const RMD_R: [[usize; 16]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
];

/// Standard RIPEMD-128 rotations, left line then right line.
const RMD_S: [[u32; 16]; 8] = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
];

/// Boolean function for macro round `r` (0-based R1..R8).
fn rmd_f(r: usize, x: u32, y: u32, z: u32) -> u32 {
    match r {
        0 | 7 => x ^ y ^ z,
        1 | 6 => (x & y) | (!x & z),
        2 | 5 => (x | !y) ^ z,
        _ => (x & z) | (y & !z),
    }
}

fn ripemd128c_block(h: &mut [u32; 4], block: &[u8]) {
    let w = le32_words(block);
    // wv[0..4]: left line A B C D, wv[4..8]: right line A' B' C' D'.
    let mut wv = [h[0], h[1], h[2], h[3], h[0], h[1], h[2], h[3]];
    for step in 0..128 {
        let round = step / 16;
        let j = step % 16;
        let base = if step < 64 { 0 } else { 4 };
        // Target register cycles A, D, C, B; F takes its three successors.
        let a = base + (4 - j % 4) % 4;
        let b = base + (a - base + 1) % 4;
        let c = base + (a - base + 2) % 4;
        let d = base + (a - base + 3) % 4;
        let k = RMD_K_OVERRIDE
            .iter()
            .find(|(s, _)| *s == step)
            .map_or(RMD_K[round], |&(_, k)| k);
        wv[a] = wv[a]
            .wrapping_add(rmd_f(round, wv[b], wv[c], wv[d]))
            .wrapping_add(w[RMD_R[round][j]])
            .wrapping_add(k)
            .rotate_left(RMD_S[round][j]);
    }
    let [a, b, c, d, a2, b2, c2, d2] = wv;
    let t = h[1].wrapping_add(c).wrapping_add(d2);
    h[1] = h[2].wrapping_add(d).wrapping_add(a2);
    // Inferred extra +1 (see module comment above).
    h[2] = h[3].wrapping_add(a).wrapping_add(b2).wrapping_add(1);
    h[3] = h[0].wrapping_add(b).wrapping_add(c2);
    h[0] = t;
}

/// Ruijie custom RIPEMD-128 ("R"; doc 19.5).
pub fn ripemd128c(data: &[u8]) -> [u8; 16] {
    let mut h = RMD_IV;
    for block in pad(data, 0x80, 8, false).chunks_exact(64) {
        ripemd128c_block(&mut h, block);
    }
    let mut out = [0u8; 16];
    for (o, w) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// T: custom Tiger (doc 19.6)
// ---------------------------------------------------------------------------

/// Tiger S-boxes t1..t4, 4 x 256 u64 (identical to standard Tiger, doc 19.6).
static TIGER_SBOX: [u64; 1024] = le64_table(include_bytes!("data/tiger-sbox-le64.bin"));

/// Custom Tiger IV (doc 19.6).
const TIGER_IV: [u64; 3] = [0x158e_427a_c96b_03df, 0xf025_c13b_8e9d_a784, 0xb690_ab45_c3e2_1b74];

/// First key-schedule constant; standard Tiger uses a5a5a5a5a5a5a5a5 (doc 19.6).
const TIGER_KS1: u64 = 0xa5a5_b5a5_a5a5_a7a5;
const TIGER_KS2: u64 = 0x0123_4567_89ab_cdef;

fn tiger_t(table: usize, byte: u8) -> u64 {
    TIGER_SBOX[table * 256 + usize::from(byte)]
}

fn tiger_round(a: &mut u64, b: &mut u64, c: &mut u64, x: u64, mul: u64) {
    *c ^= x;
    let cb = c.to_le_bytes();
    *a = a.wrapping_sub(tiger_t(0, cb[0]) ^ tiger_t(1, cb[2]) ^ tiger_t(2, cb[4]) ^ tiger_t(3, cb[6]));
    *b = b.wrapping_add(tiger_t(3, cb[1]) ^ tiger_t(2, cb[3]) ^ tiger_t(1, cb[5]) ^ tiger_t(0, cb[7]));
    *b = b.wrapping_mul(mul);
}

fn tiger_pass(a: &mut u64, b: &mut u64, c: &mut u64, x: &[u64; 8], mul: u64) {
    tiger_round(a, b, c, x[0], mul);
    tiger_round(b, c, a, x[1], mul);
    tiger_round(c, a, b, x[2], mul);
    tiger_round(a, b, c, x[3], mul);
    tiger_round(b, c, a, x[4], mul);
    tiger_round(c, a, b, x[5], mul);
    tiger_round(a, b, c, x[6], mul);
    tiger_round(b, c, a, x[7], mul);
}

fn tiger_key_schedule(x: &mut [u64; 8]) {
    x[0] = x[0].wrapping_sub(x[7] ^ TIGER_KS1);
    x[1] ^= x[0];
    x[2] = x[2].wrapping_add(x[1]);
    x[3] = x[3].wrapping_sub(x[2] ^ ((!x[1]) << 19));
    x[4] ^= x[3];
    x[5] = x[5].wrapping_add(x[4]);
    x[6] = x[6].wrapping_sub(x[5] ^ ((!x[4]) >> 23));
    x[7] ^= x[6];
    x[0] = x[0].wrapping_add(x[7]);
    x[1] = x[1].wrapping_sub(x[0] ^ ((!x[7]) << 19));
    x[2] ^= x[1];
    x[3] = x[3].wrapping_add(x[2]);
    x[4] = x[4].wrapping_sub(x[3] ^ ((!x[2]) >> 23));
    x[5] ^= x[4];
    x[6] = x[6].wrapping_add(x[5]);
    x[7] = x[7].wrapping_sub(x[6] ^ TIGER_KS2);
}

fn tiger_block(st: &mut [u64; 3], block: &[u8]) {
    let mut x = [0u64; 8];
    for (i, c) in block.chunks_exact(8).enumerate() {
        x[i] = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    let [mut a, mut b, mut c] = *st;
    for (pass, mul) in [5u64, 7, 9].into_iter().enumerate() {
        if pass != 0 {
            tiger_key_schedule(&mut x);
        }
        tiger_pass(&mut a, &mut b, &mut c, &x, mul);
        // Rotate registers: next pass works on (c, a, b).
        (a, b, c) = (c, a, b);
    }
    st[0] ^= a;
    st[1] = b.wrapping_sub(st[1]);
    st[2] = c.wrapping_add(st[2]);
}

/// Ruijie custom Tiger ("T"; doc 19.6). Tiger-1 `0x01` padding, LE64 output.
pub fn tigerc(data: &[u8]) -> [u8; 24] {
    let mut st = TIGER_IV;
    for block in pad(data, 0x01, 8, false).chunks_exact(64) {
        tiger_block(&mut st, block);
    }
    let mut out = [0u8; 24];
    for (o, w) in out.chunks_exact_mut(8).zip(st) {
        o.copy_from_slice(&w.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// W: custom Whirlpool (doc 19.6)
// ---------------------------------------------------------------------------

/// Custom Whirlpool tables C0..C7 (`[t * 256 + x]`). The firmware file stores
/// them in C7..C0 order (doc 19.6), so file block `7 - t` is `C_t`. They
/// differ from standard Whirlpool in 46 entries (sbox-differences.json), so
/// they are no longer rotations of one table and all 8 are kept.
static WHIRLPOOL_C: [u64; 2048] = whirlpool_tables(include_bytes!("data/whirlpool-sbox-gs-order-le64.bin"));

const fn whirlpool_tables(gs_order: &[u8]) -> [u64; 2048] {
    let file: [u64; 2048] = le64_table(gs_order);
    let mut out = [0u64; 2048];
    let mut t = 0;
    while t < 8 {
        let mut x = 0;
        while x < 256 {
            out[t * 256 + x] = file[(7 - t) * 256 + x];
            x += 1;
        }
        t += 1;
    }
    out
}

/// Whirlpool round constants, unchanged from the standard (doc 19.6).
const WHIRLPOOL_RC: [u64; 10] = [
    0x1823_c6e8_87b8_014f,
    0x36a6_d2f5_796f_9152,
    0x60bc_9b8e_a30c_7b35,
    0x1de0_d7c2_2e4b_fe57,
    0x1577_37e5_9ff0_4ada,
    0x58c9_290a_b1a0_6b85,
    0xbd5d_10f4_cb3e_0567,
    0xe427_418b_a77d_95d8,
    0xfbee_7c66_dd17_479e,
    0xca2d_bf07_ad5a_8333,
];

/// Custom Whirlpool IV (doc 19.6; standard is all zero).
const WHIRLPOOL_IV: [u64; 8] = [0, 3, 5, 2, 1, 7, 4, 6];

/// One Whirlpool round function output word: `XOR_t C_t[byte_t(src[i - t])]`.
fn whirlpool_op(src: &[u64; 8], i: usize) -> u64 {
    (0..8).fold(0, |acc, t| {
        let byte = (src[(i + 8 - t) & 7] >> (56 - 8 * t)) & 0xff;
        acc ^ WHIRLPOOL_C[t * 256 + byte as usize]
    })
}

fn whirlpool_block(hash: &mut [u64; 8], block: &[u8]) {
    let mut k = *hash;
    let mut state = [0u64; 8];
    for (i, c) in block.chunks_exact(8).enumerate() {
        let m = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        state[i] = m ^ hash[i];
    }
    let feed = state;
    for rc in WHIRLPOOL_RC {
        let mut nk = [0u64; 8];
        for (i, v) in nk.iter_mut().enumerate() {
            *v = whirlpool_op(&k, i);
        }
        nk[0] ^= rc;
        let mut ns = [0u64; 8];
        for (i, v) in ns.iter_mut().enumerate() {
            *v = whirlpool_op(&state, i) ^ nk[i];
        }
        // Doc 19.6: state[2], [5], [6] get +1 after the round-key XOR.
        for i in [2, 5, 6] {
            ns[i] = ns[i].wrapping_add(1);
        }
        k = nk;
        state = ns;
    }
    // Miyaguchi–Preneel: H' = H ^ M ^ E(M ^ H).
    for i in 0..8 {
        hash[i] = feed[i] ^ state[i];
    }
}

/// Ruijie custom Whirlpool ("W"; doc 19.6). Standard 256-bit length padding,
/// big-endian output.
pub fn whirlpoolc(data: &[u8]) -> [u8; 64] {
    let mut h = WHIRLPOOL_IV;
    for block in pad(data, 0x80, 32, true).chunks_exact(64) {
        whirlpool_block(&mut h, block);
    }
    let mut out = [0u8; 64];
    for (o, w) in out.chunks_exact_mut(8).zip(h) {
        o.copy_from_slice(&w.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::hex_lower;

    fn hex(b: &[u8]) -> String {
        String::from_utf8(hex_lower(b)).unwrap()
    }

    /// evidence/p0/hash-gs.log: input is `(i*13+7)&255` for i in 0..n.
    const GS_VECTORS: &str = "\
S 0 b772187b3b0675807e77088e9c43fc02309c45a8
R 0 e2cf51ff5f7d08e090a206613d633194
T 0 0b7917e593ef3887dd0e20a952ddf3e4fb11e09e053f350a
W 0 58261111fbe753fb02537c90aaac1a35f4235aae5a2a1e855532ba55b4df6704d2e55ab0bcdc74d56292e2c2d1827b9e88b479aee59242349d234f64d5be300b
S 1 e1591cfc705f4559d8716cef1a5fdbca7dc50e36
R 1 8af564b7c9f48b0788d0a996afa6c5c6
T 1 36c37b89804d4a1b2d805e3258546c21a24917025fa0d3f7
W 1 4f229dde52fa9ee4c6c3bf10075f62d1267e481d911fad6cf6c3d08a898e1dc66cbf30d479f41d4d0b1781eca6c47b0454c41301f2237887e8495b7ba460342f
S 16 b1d1e97319edb3e7cd97f5b09e5e3a06ef9e90c9
R 16 ad393b69ea2f29fd19f3d06aa11a7ad5
T 16 8695c3b18399d9ba5c94b62eab9d1d7c60f2dff6aef31bd0
W 16 d4878160cbaa22e6b8a94df02a9d4ff6ff1662708146b5b5194d47e18caa98770e14f0a51e1e7934db26d1e2b7a16a8732a19165ddf16bda347605b03abbb7f1
S 55 ea2d95c3116b03762c5465ee06b84e219070e215
R 55 26d9a89a8adee191f7cff01188633bf1
T 55 3389b7a95f1b28e83850379149430597537ddb8c0b0dd0fa
W 55 5ccff784bd90253dc913c6fa2f1baf7632bd114c09f2d4e00f5c655c301db1f72d66dc99061b207d3d06f11b0d4163e25838755a6acaa8b8b61d629e21028b88
S 56 eb5431a1b8b3c654fa9cbfc9df6e4e16512d585e
R 56 855f1aae43512ea5f553434dba7b7310
T 56 571678a18641e38ec4a497109553d1f73ba485b1cfa50676
W 56 414d87b65552decf4a63335b961b83ceebd94d1f8f496b95d913ed60d416fd5c89ef89c4c65201cf93f491a7a35db8496852bf42e2fbd55b43e0c91d54e39254
S 63 af6486e91ad28c5945459a5c4ca12a98408b5d2a
R 63 e78d234793719a11c1f8216fdedf7905
T 63 22d49c9a2ba351dd588b2adb6f58f0bfd41ea7133c3be30a
W 63 17d5600888d188c798af3496a9339b0adb104a5b357600e2a0b9b5dfcb91577668a127ffa4a9883963dc2dfe57bdbb5f17ec376b852a726564cef0a67f766dff
S 64 c108756f2e3535130335a25bc53c1eb561134cef
R 64 f639c348ccd8c47e40b6688299ac9ec6
T 64 f4443c88ee487835f16c05be35d9754a3e9281b00e88510d
W 64 68ffcb56a9eacf65d593b9e0495bd2c50cabebc8491b5e860d3f3791d04606b4634497887eb898c0fe6ccf73cdbad7c2ae099b792db1b816daafa4dd0df6cfbe
S 65 48e3c1f72db7d2b2939d9b14da718c03190b2b50
R 65 3a52a147a925c6bf47686a918de44360
T 65 8dc22681626ed9792cc9dacffe870eaacc142e0c22fff5cf
W 65 d9cb1cbb47ba294024663224bbf44f496c9713af249cb699565179960f3f250db4afbdd508c282b60fa0b4af357cbeb5b2d52f21f4a62e1cfc698b00ddb42aa1
S 96 bde969ef77453a36b290146e2340ebc2f1554179
R 96 b21694bc3d3ec6695c5d57c2c5ac0049
T 96 3c191819a9a41e611c06c14826ed73ce379293a6f91b30e4
W 96 d7c2c3f4b4d74ae0a1b348c95fe2e9f80cfea7c01552e74abfc11067050fe21142461ae27d7e9ca37398463b4af0f5a0e9a822295857ed7b22cac2d456303fc5
S 128 0288c20ede12e354a42883535f4b2f0911fb1762
R 128 1331032905c1a30f21e869c7464c5820
T 128 65e30a0f18599c7177ffe2c3cadfdc1ddab4907880c5a777
W 128 d0f9da738a5ab3b9b307f8b23a54284fc58e99ccdb69788ba87f6bf1255cc0f4fd778b5731b54da1dfe01d276651f47bdb0fa5b7e2a6f7046c7258e9f4753456
S 129 e6ed1a256142eef82d470ccc3a4a1d489ee0b915
R 129 93df2ec050d4362f8565cd0b58c83449
T 129 89c3dcf5fa71aee7f30231e88560904b8d661a51e69efa96
W 129 d28cf4c089ee5328cfa08897d1a0a7311c36558cee26ad4f69e5e306391fbe9381c3d9e1eecff025f74bfae875262517341e4070b9e7a83da3b6c311b1699679
";

    /// evidence/deep/rj-hash.log: custom MD5 of `bytes(range(n))` (doc 15.2).
    const MD5C_VECTORS: [(usize, &str); 6] = [
        (0, "2d1a67b2bd1982d14ed10e44dd83b394"),
        (1, "1329d95a8d56719441f5e877603620bb"),
        (16, "e347f74a391d14f1afd942b804914133"),
        (64, "c0078b1c06c62ee05204d16ae791665a"),
        (65, "7272ffc8303d2207192cce24261cebfe"),
        (128, "b347b7fa94aeac1fa2a5b39acca8e134"),
    ];

    fn check_gs(letter: &str, f: fn(&[u8]) -> String) {
        let mut n_checked = 0;
        for line in GS_VECTORS.lines().filter(|l| l.starts_with(letter)) {
            let mut p = line.split_whitespace();
            let (_, n, want) = (p.next(), p.next().unwrap(), p.next().unwrap());
            let n: usize = n.parse().unwrap();
            let input: Vec<u8> = (0..n).map(|i| ((i * 13 + 7) & 255) as u8).collect();
            assert_eq!(f(&input), want, "{letter} n={n}");
            n_checked += 1;
        }
        assert_eq!(n_checked, 11);
    }

    #[test]
    fn sha1c_vectors() {
        check_gs("S", |d| hex(&sha1c(d)));
    }

    #[test]
    fn ripemd128c_vectors() {
        check_gs("R", |d| hex(&ripemd128c(d)));
    }

    #[test]
    fn tigerc_vectors() {
        check_gs("T", |d| hex(&tigerc(d)));
    }

    #[test]
    fn whirlpoolc_vectors() {
        check_gs("W", |d| hex(&whirlpoolc(d)));
    }

    #[test]
    fn md5c_vectors() {
        for (n, want) in MD5C_VECTORS {
            let input: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert_eq!(hex(&md5c(&input)), want, "M n={n}");
        }
    }

    #[test]
    fn tables_match_doc() {
        // Tiger t1[0] is the standard 0x02aab17cf7e90c5e (doc 19.6).
        assert_eq!(TIGER_SBOX[0], 0x02aa_b17c_f7e9_0c5e);
        // Custom C0[0] (sbox-differences.json table 0 entry 0).
        assert_eq!(WHIRLPOOL_C[0], 0x1818_6018_c07a_30d8);
        // Custom C7[129] (table 7 entry 129).
        assert_eq!(WHIRLPOOL_C[7 * 256 + 129], 0x0210_0000_0000_0000);
    }
}
