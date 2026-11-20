//! Extended format of MentoHUST GS (research doc 18.7), which the client
//! prints as "standard algorithm": chosen when the authenticator is not a
//! Ruijie switch. The vendor attributes move into a 459 byte area that
//! the MD5 response carries inside its EAP message, and the Identity
//! response carries none. The area is a 57 byte head (0x11 version, 0x50
//! addresses) followed by a fixed 402 byte template ending in an `ff` mark.

use super::{Checks, ExtParams};

/// Template after the head (VA 0x423530, `template-rj-v4-402.bin`).
const TEMPLATE: &[u8; 402] = include_bytes!("data/template-rj-v4-402.bin");
const HEAD_LEN: usize = 57;
/// Length of the area including the trailing `ff`.
pub const AREA_LEN: usize = HEAD_LEN + TEMPLATE.len();
/// Version in 0x11 when none is configured, as in the classic template.
const DEFAULT_VERSION: [u8; 2] = [4, 10];

// Value offsets inside the area; each value follows `type | value_len`.
const OFF_MAC: usize = 59;
/// 0x63: 2 in internal DHCP mode 4 (after the DHCP of mode 1), else 1.
const OFF_DHCP_STAGE: usize = 67;
/// 0x2f: password attribute, a 16 byte slot.
const OFF_PASSWORD: usize = 143;
const OFF_FIELD4D: usize = 161;
const OFF_FIELD60: usize = 291;
/// 0x70: `40` in the template, the original builder writes `20`.
const OFF_0X70: usize = 438;

/// OUI prefixes of the authenticator for which the normal format is kept
/// (table of 0x40b528).
const RUIJIE_OUIS: [[u8; 3]; 4] = [[0x14, 0x14, 0x4b], [0x00, 0x1a, 0xa9], [0x58, 0x69, 0x6c], [0x00, 0xd0, 0xf8]];

/// Whether an authenticator with this MAC gets the extended format. The
/// original decides on the first Identity/Notification/type 20 request of a
/// round (doc 18.7).
pub fn wanted_by(server: &[u8; 6]) -> bool {
    !RUIJIE_OUIS.iter().any(|oui| server[..3] == *oui)
}

/// The whole area, `ff` mark included.
pub fn build(p: &ExtParams, checks: Checks) -> Vec<u8> {
    let mut area = Vec::with_capacity(AREA_LEN);
    let mut name = [0u8; 32];
    name[..9].copy_from_slice(b"8021x.exe");
    area.extend_from_slice(&[0x11, 36]);
    area.extend_from_slice(&name);
    area.extend_from_slice(&p.version.unwrap_or(DEFAULT_VERSION));
    area.extend_from_slice(&[0, 0]);

    // The first round of DHCP mode 1 has no address yet.
    let ip = if p.dhcp_mode == 1 { [0; 4] } else { p.net.ip };
    area.extend_from_slice(&[0x50, 17]);
    for a in [&ip, &p.net.mask, &p.net.gateway, &p.net.dns] {
        area.extend_from_slice(a);
    }
    area.push((p.dhcp_mode != 0) as u8);

    area.extend_from_slice(TEMPLATE);
    area[OFF_MAC..OFF_MAC + 6].copy_from_slice(&p.mac);
    area[OFF_DHCP_STAGE] = if p.dhcp_mode == 4 { 2 } else { 1 };
    area[OFF_0X70] = 0x20;
    if let Some(value) = checks.field2f {
        area[OFF_PASSWORD..OFF_PASSWORD + 16].copy_from_slice(value);
    }
    // One mix result for both; without one the template values stay.
    if let Some(value) = checks.field4d {
        area[OFF_FIELD4D..OFF_FIELD4D + 128].copy_from_slice(value);
        area[OFF_FIELD60..OFF_FIELD60 + 128].copy_from_slice(value);
    }
    area
}

/// Password attribute (0x40b5f4 -> 0x407e24, doc 18.4): the password padded
/// with zeros to whole 16 byte blocks, the first block XOR
/// `MD5(username || seed)`, each later one XOR `MD5(username || previous
/// encrypted block)`.
pub fn password_property(username: &[u8], password: &[u8], seed: &[u8; 16]) -> Vec<u8> {
    let mut out = password.to_vec();
    out.resize(password.len().div_ceil(16) * 16, 0);
    let mut prev = seed.to_vec();
    for block in out.chunks_mut(16) {
        let key = md5::compute([username, &prev].concat()).0;
        block.iter_mut().zip(key).for_each(|(b, k)| *b ^= k);
        prev = block.to_vec();
    }
    out
}

/// Value for the 16 byte 0x2f slot. The original only writes a result that
/// fits the slot, so passwords longer than 16 bytes (and an empty one) keep
/// the template value.
pub fn password_attribute(username: &[u8], password: &[u8], seed: &[u8; 16]) -> Option<[u8; 16]> {
    password_property(username, password, seed).try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Original 0x407e24 with username "synthetic" (evidence/p0/pure-more.log,
    /// PROP lines). The harness reused its seed buffer after a loop that
    /// left seed[0] = 3, hence 03 01 02 .. 0f.
    #[test]
    fn password_property_vectors() {
        let seed: [u8; 16] = std::array::from_fn(|i| if i == 0 { 3 } else { i as u8 });
        let prop = |pw: &[u8]| hex::encode(password_property(b"synthetic", pw, &seed));
        assert_eq!(prop(b"synthetic"), "26e1ee3b2bf6442edde87889af681850");
        assert_eq!(prop(b"0123456789abcdefXYZ"), "65a9b27c77a6067086d119ebcc0c7d365b72be63536ebb7dc2e60aab5738b8cf");
        assert_eq!(prop(b""), "");
        assert!(password_attribute(b"synthetic", b"synthetic", &seed).is_some());
        assert!(password_attribute(b"synthetic", b"0123456789abcdefXYZ", &seed).is_none());
        assert!(password_attribute(b"synthetic", b"", &seed).is_none());
    }

    #[test]
    fn ruijie_switches_keep_the_normal_format() {
        for oui in RUIJIE_OUIS {
            assert!(!wanted_by(&[oui[0], oui[1], oui[2], 1, 2, 3]));
        }
        assert!(wanted_by(&[0x02, 0, 0, 0, 0, 2]));
        assert!(wanted_by(&[0x00, 0xd0, 0xf9, 0, 0, 2]));
    }

    #[test]
    fn template_layout() {
        assert_eq!(AREA_LEN, 459);
        let at = |off: usize| TEMPLATE[off - HEAD_LEN - 2];
        assert_eq!(
            [at(OFF_MAC), at(OFF_DHCP_STAGE), at(OFF_PASSWORD), at(OFF_FIELD4D), at(OFF_FIELD60), at(OFF_0X70)],
            [0x2d, 0x63, 0x2f, 0x4d, 0x60, 0x70]
        );
        assert_eq!(
            TEMPLATE[OFF_FIELD4D - HEAD_LEN..OFF_FIELD4D - HEAD_LEN + 128],
            TEMPLATE[OFF_FIELD60 - HEAD_LEN..OFF_FIELD60 - HEAD_LEN + 128]
        );
        assert_eq!((TEMPLATE[OFF_0X70 - HEAD_LEN], TEMPLATE[401]), (0x40, 0xff));
    }
}
