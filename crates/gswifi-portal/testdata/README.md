# gswifi-portal test data

All files are verbatim copies from the 2026-11-20 gap-closure work area
`gapclose/` (README of the clean-room pack,
section "2026-11-20 闭环增补"). They were produced by running the firmware's
own functions of `/usr/sbin/hubei_mac_web_old` under QEMU with
`gapclose/hubei_harness.c` (FixHBKey `0x407dc8`, password chain `0x40827e`,
RC4 `0x407c85`, md5hex `0x407d51`), evidence grade D. The independent
reference is `gapclose/reference/hubei_oldmac.py`
(SHA256 `bb0d070f35d7fc2ae9ee0205221e6aad9a291e1093c042e2bc3028c6c511264d`);
it was re-run against every file below before porting.

| File | Source | SHA256 |
|---|---|---|
| `hubei_oldmac_vectors.json` | `gapclose/vectors/hubei_oldmac_vectors.json` | `8626373d2dcc289e513ccf8b615bb8e5592a6d05d176b94fb5d620fcc61fd143` |
| `hubei_password_vectors.json` | `gapclose/vectors/hubei_password_vectors.json` | `0d6c2f051d8509a9aa97f14148b6d0a4660f48d8b1b376eb0d4c8ff8bd638e52` |
| `logs/out_hb1.txt` | `gapclose/out_hb1.txt` | `765eb6a8dfb20f4d523696fce599a8983063d92d781a91cbb658cc1662ce531f` |
| `logs/out_hb2.txt` | `gapclose/out_hb2.txt` | `97c3533bc27f147a265e9e332eb995eb37e651dd601f742c22536a9d6958c9a2` |
| `logs/out_hb3.txt` | `gapclose/out_hb3.txt` | `a3b089b797509241eab94bbb4f5c25fcb7660e1c755b75973081969fa0a47584` |
| `logs/out_x_aaa.txt` | `gapclose/out_x_aaa.txt` | `842fbc05cc842c2b0e70e5dcfd811b51d58064ff3484eff156ea3d6c5f9b2e0c` |
| `logs/out_x_bb.txt` | `gapclose/out_x_bb.txt` | `0e4e85c300aad89abeca485c6b2fb0003cbc0f52ccb27a0d3a196235c552ba3a` |
| `logs/out_x_longernamedom.txt` | `gapclose/out_x_longernamedom.txt` | `7f9c4fae99ae7f1560f50cf100df8fc0a61352bf86487d68a792532b05a9b68a` |
| `logs/out_x_test123x.txt` | `gapclose/out_x_test123x.txt` | `998e01d58b06b604abecebe890ea25d51ee391a34530bff7b7fbbd8c5cadb093` |
| `logs/out_x_u1.txt` | `gapclose/out_x_u1.txt` | `220454d2702701c84722f1536b70cd00cc12afeeab82a5578efafa44f707b592` |
| `logs/out_x_zzq.txt` | `gapclose/out_x_zzq.txt` | `6b99eba1b92c0bce1b7ca58deaed33b869c2f0484cf1510d890dc8a0fdd52bca` |
| `logs/out_sim.txt` | `gapclose/out_sim.txt` | `c2a6e415b348616544c012c214f489e98c9e746a2021b909b165671ecac595ef` |
| `logs/out_pw1.txt` | `gapclose/out_pw1.txt` | `bf92f1c04fde22fafdff579ddfd5e003748f5480b320b910149ff28f52a508b8` |
| `logs/out_pw2.txt` | `gapclose/out_pw2.txt` | `3bb30a3dcceff4d3dbd8658a2a534c7eb748164e1de81a536685c69aff167d28` |
| `logs/out_sim_pw.txt` | `gapclose/out_sim_pw.txt` | `859db3a5aac6c1334eea714ccc5d536b3f6f03b4287421ca2492cdef7be49ce1` |

## How the tests use them (`src/hubei/mod.rs`)

* `fixhbkey_golden_vectors`: the 9 JSON vectors, checking m1..m4, ga, gb
  and key128, and that together they take both values of every selector
  (S1, S2, S3, gb[22], gb[24]).
* `fixhbkey_matches_every_harness_log`: the 10 key logs. Besides the JSON
  values they hold the MD5 inputs (from which the test recovers MMDD and the
  account), the interleaved 32-character buffers `ga1/ga2/gb1/gb2_tmp`, the
  case-mixed `sga`/`sgb`, and key128 as hex. `out_sim.txt` is a tenth key
  that is not in the JSON: account `2026310488` (the harness passed
  `2026310488@hubupt`), MMDD `1120`. The trailing QEMU `SIGSEGV` lines are
  the harness running past the function and are ignored.
* `password_chain_golden_vector`: the JSON vector (synthetic key
  `0123456789abcdef`×8, password `password123`), every intermediate.
* `password_chain_matches_harness_logs`:
  * `out_pw2.txt` is the same run as the JSON vector, ending with the
    firmware's 33-byte output buffer.
  * `out_pw1.txt` does not name its inputs. Its RC4 output decrypts to
    `password123` under the `student@x`/`0905` key128 and to garbage under
    every other logged key, so it is that pair (final value
    `66cd02c602d032fb`). Only the first pass is used: the repeated
    "Password2/Password3" lines after "stack_chk path taken" come from the
    harness re-entering the function, not from the derivation.
  * `out_sim_pw.txt` is the `out_sim.txt` key with password `Xy9#k2Lt` (the
    credentials of the same simulation in
    `gapclose/mentohust_harness_sim.c`; the RC4 output decrypts to exactly
    that string), final value `0e6124a3cb4dec5a`. The harness pinned
    `time()` to `0x6aff9488` = 2026-11-20 00:30:00 UTC; the driver tests
    replay that date through an HTTP `Date` header.

None of these values comes from a server: there is still no captured
campus session (cleanroom README, "全部提供商:无实网抓包").
