//! MentoHUST style Ruijie extension (research doc 18): an encoded 23 byte IPv4
//! header followed by a fixed 448 byte attribute template.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::crypt::{check_sum, encrypt_rtv};
use super::{Checks, ExtParams, NetInfo};

/// Default extension body after the IPv4 header (doc 18.3, `template-rj-448.bin`).
const TEMPLATE: &[u8; 448] = include_bytes!("data/template-rj-448.bin");

// Offsets inside TEMPLATE; the doc counts from the start of the extension,
// i.e. 23 bytes earlier, and gives the attribute start (the `1a` byte), the
// value begins 8 bytes later.
/// Client version, two raw bytes major/minor (4.10 = `04 0a`).
const OFF_VERSION: usize = 59 - 23;
/// Value of attribute 0x17 (32 ASCII bytes).
const OFF_FIELD17: usize = 70 + 8 - 23;
/// Value of attribute 0x4d (128 ASCII bytes).
const OFF_FIELD4D: usize = 201 + 8 - 23;
/// Value of attribute 0x18 (`00 00 00 flag`).
const OFF_DHCP_FLAG: usize = 110 + 8 - 23;
/// Value of attribute 0x2d (local MAC).
const OFF_MAC: usize = 122 + 8 - 23;

/// Suffix of the attribute 0x17 placeholder (doc 18.4).
const PLACEHOLDER_SUFFIX: &str = "388498639f49ebaca773dfd78789088ac9534";

/// `00 00 13 11 | dhcp | ip | mask | gateway | dns | checksum`, encoded.
pub fn ip_header(net: &NetInfo, dhcp: bool) -> [u8; 23] {
    let mut plain = [0u8; 23];
    plain[..4].copy_from_slice(&[0x00, 0x00, 0x13, 0x11]);
    plain[4] = dhcp as u8;
    plain[5..9].copy_from_slice(&net.ip);
    plain[9..13].copy_from_slice(&net.mask);
    plain[13..17].copy_from_slice(&net.gateway);
    plain[17..21].copy_from_slice(&net.dns);
    let sum = check_sum(&plain[..21]);
    plain[21..].copy_from_slice(&sum);
    let mut out = [0u8; 23];
    out.copy_from_slice(&encrypt_rtv(&plain));
    out
}

pub fn build(p: &ExtParams, checks: Checks) -> Vec<u8> {
    let mut body = *TEMPLATE;
    if let Some(version) = p.version {
        body[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&version);
    }
    if let Some(value) = checks.field17 {
        body[OFF_FIELD17..OFF_FIELD17 + 32].copy_from_slice(value);
    }
    if let Some(value) = checks.field4d {
        body[OFF_FIELD4D..OFF_FIELD4D + 128].copy_from_slice(value);
    }
    // Only the first round of DHCP mode 1 (secondary authentication) sets it.
    body[OFF_DHCP_FLAG + 3] = (p.dhcp_mode == 1) as u8;
    body[OFF_MAC..OFF_MAC + 6].copy_from_slice(&p.mac);

    let mut ext = Vec::with_capacity(23 + TEMPLATE.len());
    ext.extend_from_slice(&ip_header(p.net, p.dhcp_mode != 0));
    ext.extend_from_slice(&body);
    ext
}

/// Value of attribute 0x17 when there is no challenge to compute a check
/// from: five `rand()` results as `%X`, then a fixed suffix, cut to 32 bytes.
pub fn placeholder(rand: [u32; 5]) -> [u8; 32] {
    let mut s = String::with_capacity(80);
    for v in rand {
        s.push_str(&format!("{:X}", v));
    }
    s.push_str(PLACEHOLDER_SUFFIX);
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.as_bytes()[..32]);
    out
}

/// Placeholder with fresh pseudo random numbers (31 bit, like C `rand()`).
pub fn random_placeholder() -> [u8; 32] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut x = now.as_secs() ^ ((now.subsec_nanos() as u64) << 32) | 1;
    let mut rand = [0u32; 5];
    for v in rand.iter_mut() {
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *v = (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 33) as u32 & 0x7fff_ffff;
    }
    placeholder(rand)
}

/// Value of attribute 0x17 kept in the MD5 frame when no V2 check is computed.
#[cfg(test)]
pub fn template_field17() -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&TEMPLATE[OFF_FIELD17..OFF_FIELD17 + 32]);
    out
}

/// Parses "4.10" / "3.30" into the two raw version bytes.
pub fn parse_version(s: &str) -> Option<[u8; 2]> {
    let (major, minor) = s.trim().split_once('.')?;
    Some([major.parse().ok()?, minor.parse().ok()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_matches_doc() {
        assert_eq!(&placeholder([0x10203; 5]), b"10203102031020310203102033884986");
        assert_eq!(&template_field17(), b"68DC123B7EB239F23A8C000388498639");
        assert!(random_placeholder().iter().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("4.10"), Some([4, 10]));
        assert_eq!(parse_version("3.30"), Some([3, 30]));
        assert_eq!(parse_version("x"), None);
        assert_eq!(&TEMPLATE[OFF_VERSION..OFF_VERSION + 2], &[4, 10]);
    }
}
