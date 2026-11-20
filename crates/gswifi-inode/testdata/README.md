# gswifi-inode test data

Copied from the research pack
`~/Documents/Codex/2026-11-19/x20/outputs/campus-auth-research/` (GS r1161
`usr/sbin/mentohust`, SHA256 `f638fba1…f606`). All inputs are synthetic
(account `synthetic`, IP 192.0.2.10, MAC 02:00:00:00:00:01, time 0x12345678,
rand 0x10203); outputs come from the original functions run under QEMU.
These are offline vectors, not campus server captures.

| File | Source | Content |
|---|---|---|
| `algorithm-comparison-inode.json` | `evidence/deep/algorithm-comparison.json`, cases `inode-xor`, `inode-mixed/text/raw`, `password`, `xorpass`, `inode-pass-xor` (83) | doc 13.2–13.4 |
| `frame-vectors-inode.json` | `evidence/p0/frame-vectors.json`, cases `auth-1-0`, `inode-flags-*`, `inode-no-vif`, `inode-online` (frame fields trimmed) | doc 22.3–22.5 |
| `vif-raw-vectors.json`, `vif-valid-vectors.json`, `vif-file-vector.json` | `evidence/compat/` | doc 25.4 |
| `iNode.vif` | `evidence/compat/fixtures/vif/iNode.vif` (synthetic file) | doc 25.4 |
| `inode-record-vectors.json` | `evidence/session/inode-record-vectors.json` | doc 29.6 |
| `inode-gs.dat`, `inode-gs-encrypted.dat` | `evidence/session/fixtures/` (synthetic records) | doc 29.6 |

`../data/vif-subkeys.bin` and `../data/vif-sp.bin` are the firmware tables
from `data/inode/` (VA 0x42d590 / 0x42d610, SHA256 in
`data/inode/manifest.json`); they are compiled into the crate.

The `success` and `echo*` frames of the 802.1X cases come from a forced
Ruijie parser/state-4 exploration and are not iNode keepalive evidence
(doc 22.1, 25.5); the tests only use the Success frame as input.
