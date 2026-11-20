# Test vectors

Firmware outputs of the custom pppd's credential transforms, recorded by
QEMU-executing the original functions (cleanroom/06, evidence grade D).

| File | Source | SHA-256 of source |
|---|---|---|
| `pppd_vectors.json` | `x20/gapclose/vectors/pppd_vectors.json` (verbatim): 7 getPIN (nk_version 1-13) + 5 Hainan (nk_version 14) | `08d718a4a62f11bc9480168696c70286380cf0b68b1d090ea15c508c31a56ab4` |
| `firmware-probe.txt` | `getpin_t`/`hainan_t` lines of `x20/gapclose/sim_fw.txt` (`4484ec32…`) and `sim_h2probe.txt` (`69851ad2…`): harness call, timestamp, username, returned bytes in hex | see left |

The `2026310488@hubupt` / `0x6aff9488` probe of `sim_fw.txt` is the
Hainan case where h1 = 0x5C00 (gaps.md "hainan phase-2 变体"): decoding the
firmware output gives h2 = 0xffa3 = hash_key(5c), i.e. the phase-2 input is
also cut at the first NUL. No sample has a zero high byte yet.
