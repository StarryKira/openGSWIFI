# gswifi-anlang test data

## `vectors.json`

Verbatim copy of `reference/vectors.json` from the campus-auth research pack
(`campus-auth-research/reference/vectors.json`,
SHA256 `2a7f5a38b8d6ad8ce568380d31ce337963782376c3a44efca8c57218be0f8334`, matches
the pack's `SHA256SUMS`).

These are golden vectors exported by the independent Python reference
`reference/atcodec.py` (SHA256 `e2138cb9…6bb025`), which was written from the
static analysis of firmware `/bin/atclient` (doc 04). Status in the file itself:
"synthetic/offline; not captured from a server". The account `alice` /
`synthetic`, IP `192.0.2.10` (TEST-NET-1) and MAC `02:00:00:00:00:01` are
made up.

Each of the four requests (discovery op 12, service query op 7, login op 1,
heartbeat op 3) records the plain view, the bit-permuted wire bytes, the digest
validity and the TLV list. `src/codec.rs` rebuilds every request from
`inputs` and must reproduce `plain_hex` and `wire_hex` byte for byte;
`src/driver.rs` checks that the driver emits the same wire bytes.

The cases of `reference/test_atcodec.py` (SHA256 `6bdcbb28…a057`) are ported
as individual unit tests in `src/codec.rs`; they need no data file.

No response vectors exist: the reference's response tests use synthetic op
codes (2, 8) that are **not** confirmed server values (doc 04.5).
