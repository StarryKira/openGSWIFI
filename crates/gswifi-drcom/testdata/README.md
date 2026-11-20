# gswifi-drcom test vectors

Copied or reformatted (one case per line, no JSON dependency) from the research pack
`outputs/campus-auth-research/`. All inputs (accounts,
IPs, DLL files, server datagrams) are synthetic; outputs are from original GS r1161
`usr/sbin/mentohust` functions run under QEMU (grade D), see that pack's
`evidence/session/README.md` and `evidence/deep/README.md`. No Dogcom (AGPLv3) source or
output is included.

| File | Source | Content |
|---|---|---|
| `primitives.txt` | `evidence/deep/algorithm-comparison.json` (49 `dr-*` cases) and `evidence/p0/pure-more.log` (8 `DRMIX` lines) | md5a/md5b (seed 00010203, password `abc…` of length n), check16/check32 (input `(i*13+7)&255`), direct seed hash (seed `[s,91,22,e3]`), mixed seed hash (seed `[s,1,2,3]`, columns enabled/selector/ret/out), MAC XOR. `cc…` = original output buffer left untouched |
| `control.txt` | `evidence/session/control-vectors.json` | 40 `CTRL`/`CTRL96` lines of the original control encoders; inputs as in `reference/test_session.py` |
| `receive.txt` | `evidence/session/receive-vectors.json` minus the 88 H3C cases | `auth mode state udp_body_hex actions`; the 42-byte Ethernet/IP/UDP header is stripped |
| `session.txt` | `evidence/session/dr-session-vectors.json` | 24 AuthType×DrMode joined replays: `event state_before state_after timers body` and every UDP client `frame tag body` (ARP and EAPOL frames dropped) |
| `dll.txt`, `dll/*.bin` | `evidence/session/dr-dll-vectors.json`, `evidence/session/fixtures/dll-*.bin` | `file fingerprint version` (`-` not called, `err` original returned -1) |
| `errors.txt` | `evidence/session/dr-error-texts.json` | GS failure texts for codes 1..23 |
| `dr-control-fallback.bin` | `data/session/dr-control-fallback.bin` (VA 0x42f458) | 8-byte fallback CRC |
| `dr-mode4-http.bin` | `data/session/dr-mode4-http.bin` (VA 0x42f48c) | DrMode 4 helper HTTP request |
