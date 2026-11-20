# gswifi-h3c-portal test data

Copied from the research pack
`~/Documents/Codex/2026-11-19/x20/outputs/campus-auth-research/` (GS r1161
`usr/sbin/mentohust`). Client payloads are outputs of the original GS
builders/state functions under QEMU; server messages were synthesised by
the researchers (doc 29: a replayed exchange is not a real server login).

| File | Source | Content |
|---|---|---|
| `algorithm-comparison-h3c.json` | `evidence/deep/algorithm-comparison.json`, cases `h3c-info`, `h3c-block`, `h3c-login` (11) | doc 13.6–13.8 |
| `h3c-session-vectors.json` | `evidence/session/h3c-session-vectors.json` | the 11-frame exchange, doc 29.4 |
| `h3c-blob-vectors.json` | `evidence/session/h3c-blob-vectors.json` | 114 + `0.0.0.0`, doc 29.3 |
| `h3c-check-vectors.json` | `evidence/session/h3c-check-vectors.json` | 45 checks, five families, doc 29.5 |
| `receive-vectors-h3c.json` | `evidence/session/receive-vectors.json`, the 88 `auth == 2` records | doc 29.2 |
| `builder-vectors-h3c.json` | `evidence/session/builder-vectors.json`, the 30 `auth == 2` records | GS states 0–4, doc 29.3 |
| `inode-gs.dat` | `evidence/session/fixtures/inode-gs.dat` (synthetic records) | doc 29.6 |

Frames are complete Ethernet/IPv4/UDP frames; the tests use bytes 42.. as
the UDP payload and bytes 34..38 as ports. The ARP frames inside the
state-4 builder records are not H3C Portal traffic and are skipped.
