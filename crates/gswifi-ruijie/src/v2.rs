//! Ruijie "V2" client check (research docs 15.1, 20.2, 20.3): eight MD5s over
//! the code section of the official client, mixed with the MD5 challenge.
//! The result replaces the value of attribute 0x17 in the MD5 response; the
//! code comes from the client materials (`super::materials`).

/// `n = len/8; part[i] = seed[2i] || MD5(seed || code[i*n..(i+1)*n]) || seed[2i+1]`,
/// result is the lowercase hex of `MD5(part[0] || .. || part[7])`. The
/// remainder of the code beyond `8n` bytes is not used.
pub fn v2_check(seed: &[u8; 16], code: &[u8]) -> [u8; 32] {
    let n = code.len() / 8;
    let mut table = Vec::with_capacity(8 * 18);
    for i in 0..8 {
        let mut ctx = md5::Context::new();
        ctx.consume(seed);
        ctx.consume(&code[i * n..(i + 1) * n]);
        table.push(seed[2 * i]);
        table.extend_from_slice(&ctx.compute().0);
        table.push(seed[2 * i + 1]);
    }
    let digest = md5::compute(&table);
    let mut out = [0u8; 32];
    out.copy_from_slice(hex::encode(digest.0).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Code `(i*37+11)&255`, research evidence/deep/v2-comparison.json.
    const VECTORS: [(usize, &str, &str); 24] = [
        (8, "00112233445566778899aabbccddeeff", "f516ffb28e40dd7915c0228692d7a3eb"),
        (8, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "4568d219b217856c84ab7a01f901b379"),
        (8, "7a8b9cadbecfe0f10213243546576879", "1e653969230d1b2c0aac01c565d99294"),
        (8, "b7c8d9eafb0c1d2e3f5061728394a5b6", "23f70838b64041df48ff11cf34a71a7e"),
        (9, "00112233445566778899aabbccddeeff", "f516ffb28e40dd7915c0228692d7a3eb"),
        (9, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "4568d219b217856c84ab7a01f901b379"),
        (9, "7a8b9cadbecfe0f10213243546576879", "1e653969230d1b2c0aac01c565d99294"),
        (9, "b7c8d9eafb0c1d2e3f5061728394a5b6", "23f70838b64041df48ff11cf34a71a7e"),
        (64, "00112233445566778899aabbccddeeff", "3669ba662c8a8fdb412ff9a5f361cc7c"),
        (64, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "96b0e928e2b48af4d7ed87a0ba60905d"),
        (64, "7a8b9cadbecfe0f10213243546576879", "c84a286cc18bb4297b573790365874e3"),
        (64, "b7c8d9eafb0c1d2e3f5061728394a5b6", "0ff9e5f700f1149c3eaceaa1685ebf18"),
        (65, "00112233445566778899aabbccddeeff", "3669ba662c8a8fdb412ff9a5f361cc7c"),
        (65, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "96b0e928e2b48af4d7ed87a0ba60905d"),
        (65, "7a8b9cadbecfe0f10213243546576879", "c84a286cc18bb4297b573790365874e3"),
        (65, "b7c8d9eafb0c1d2e3f5061728394a5b6", "0ff9e5f700f1149c3eaceaa1685ebf18"),
        (513, "00112233445566778899aabbccddeeff", "f5a16b814c6a8b0b410d555cab60748d"),
        (513, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "8a9c7589ee8b1488bad3ee0ccd96e43a"),
        (513, "7a8b9cadbecfe0f10213243546576879", "afcb62c9b78d042632494d20648ad4aa"),
        (513, "b7c8d9eafb0c1d2e3f5061728394a5b6", "d77fd78bc35621f479605e5a9f1cd1d0"),
        (4096, "00112233445566778899aabbccddeeff", "4ae7ca570b4c3709a637fd8c77f7d56f"),
        (4096, "3d4e5f708192a3b4c5d6e7f8091a2b3c", "732e5f628282774efc7be9a8bf2d7f4f"),
        (4096, "7a8b9cadbecfe0f10213243546576879", "a87a94f2574251efe84829b55d401f54"),
        (4096, "b7c8d9eafb0c1d2e3f5061728394a5b6", "dc861a9490c4c04951a145e365dc6c21"),
    ];

    #[test]
    fn v2_vectors() {
        for (len, seed, want) in VECTORS {
            let code: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) & 255) as u8).collect();
            let seed: [u8; 16] = hex::decode(seed).unwrap().try_into().unwrap();
            assert_eq!(std::str::from_utf8(&v2_check(&seed, &code)).unwrap(), want, "len {}", len);
        }
    }
}
