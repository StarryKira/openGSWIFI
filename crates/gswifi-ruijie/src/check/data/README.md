# Binary tables

Copied unchanged from `data/ruijie/` of the campus-auth-research spec pack.
VA, length and SHA-256 are as listed in that pack's `manifest.json`; the
SHA-256 of each copy here was re-checked against it. They are embedded with
`include_bytes!`. Nothing is read at run time.

| File | VA | Length | SHA-256 | Used for |
|---|---|---:|---|---|
| `tiger-sbox-le64.bin` | 0x426120 | 8192 | `364d73427379144b709fb0565ba1536c2c32ef9b02ab6201b1aefc30857372ea` | Tiger t1..t4, 4x256 u64 LE (doc 19.6) |
| `whirlpool-sbox-gs-order-le64.bin` | 0x428178 | 16384 | `39f9dde15920a40e0110ea8e272d9cbaff44fed6d57db7dd7687190933f2e777` | custom Whirlpool C7..C0, 8x256 u64 LE (doc 19.6) |
| `udp-material-pre499.bin` | 0x445750 | 6784 | `6b76a1170ca8fbee54565c3b308988309d27fc6f01bd278377b5432214a94d5b` | UDP material, versions < 499 (doc 20.1) |
| `udp-material-499-524.bin` | 0x443cd0 | 6784 | `de331d98c61f945605c71ce4ca0c50f293c8cc01402fa3c804cb9daedec5aae1` | UDP material, 499..524 |
| `udp-material-525-641.bin` | 0x442250 | 6784 | `743c2dd978cce40cec9269d8d48aa44fbe0ecd9c41ea1e0d7677a4769924028a` | UDP material, 525..641 |
| `udp-material-642plus.bin` | 0x4407d0 | 6784 | `12f69294da2930e052939e072f60d0960eca23263927d4b46afbf0ebf53068b1` | UDP material, >= 642 |
| `udp-seed16.bin` | 0x4230dc | 16 | `5f14799586974143b8f91dba411d85c837eb0bc73f1bbc8ce8e5f8df56367a3e` | fixed seed of UDP table family 0 |
| `udp-499-selector4.bin` | 0x423014 | 128 | `1ef9bfd283213ef44a91db0123a6e0484ee385b38ceb4750bc2ed0cc2ff89496` | fixed 128-char override, 499..524 selector 4 |
| `client-des3-keys.bin` | — | 384 | `96419d212574f26c345842ed2207db918bf4b897e32cdaedc006bbe4bb247888` | 96 LE32 subkeys left by 0x418468 for the key at 0x4230a0 (run-time product, not an ELF table); client material block transform (doc 25.1) |
| `client-des3-sp.bin` | 0x42c200 | 2048 | `a8670c113967e204ff3e4efa3d77c6824945830a226cce99cce9b3b805e6f970` | 8x64 LE32 SP tables of that transform |

Test vectors under `../testdata/` are reformatted extracts of the pack's
`evidence/p0/mix-holdout.log`, `evidence/deep/rj-mix-vectors.json` and
`rj-coverage-vectors.json`, and the UDPMAT rows of
`evidence/p0/extra-validation.json`.

From `evidence/compat/` (doc 25): `materials/` holds the synthetic client
files of `fixtures/` unchanged (not the Windows client);
`material-loader.txt` and `material-integration.txt` reduce
`material-vectors.json` and `integration-*vectors.json` to lengths, MD5
digests and the 0x17/0x4d values; `udp-attributes.txt` is
`udp-attribute-vectors.json`.
