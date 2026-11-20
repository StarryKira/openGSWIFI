//! What iNode puts into EAP responses (research doc 22.3, 22.4).
//!
//! Every function returns the EAP *type data*: the bytes after the EAP
//! type byte of a Response. The EAP length field covers all of them. Wrap
//! them with [`gswifi_eapol::frame::identity_response`] or an equivalent
//! frame builder; the destination is the source MAC of the request.

use gswifi_eapol::frame::md5_digest;

/// EAP type of the H3C online re-query that is answered like Identity
/// (decimal 20 = 0x14, doc 22.4).
pub const EAP_TYPE_INODE_ONLINE: u8 = 20;

/// IP upload field: `15 04 | IPv4` — six bytes; the length byte 04 counts
/// the value only (doc 22.3, global 0x440110 switch `UploadIP`).
pub fn ip_field(ip: [u8; 4]) -> [u8; 6] {
    [0x15, 0x04, ip[0], ip[1], ip[2], ip[3]]
}

/// Type data of the first Response/Identity of a round (doc 22.3):
///
/// ```text
/// [15 04 IPv4]                          if UploadIP  (ip = Some)
/// [06 07 Base64(mixed20) 20 20]         if UploadVer and a version exists
/// username
/// ```
///
/// Both switches default to on in the GS configuration and are
/// independent. Without a version (no `iNode.vif`) the original omits the
/// 32-byte field and still sends IP + username (doc 22.5).
pub fn identity_data(ip: Option<[u8; 4]>, version_text: Option<&[u8; 32]>, username: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(38 + username.len());
    if let Some(ip) = ip {
        out.extend_from_slice(&ip_field(ip));
    }
    if let Some(text) = version_text {
        out.extend_from_slice(text);
    }
    out.extend_from_slice(username);
    out
}

/// Type data of the online Identity answer `0x40ffc8` (doc 22.4): the
/// response copies the request identifier and type; type 1 carries
/// `15 04 IPv4 | text32` (no username), type 20 the same after a `00`.
///
/// The docs do not say whether UploadIP / UploadVer apply here or what is
/// sent without a version (doc 22.4 only has the both-present sample); a
/// missing version yields only the IP field. // doc 22: unknown
pub fn online_identity_data(request_type: u8, ip: [u8; 4], version_text: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(39);
    if request_type == EAP_TYPE_INODE_ONLINE {
        out.push(0);
    }
    out.extend_from_slice(&ip_field(ip));
    if let Some(text) = version_text {
        out.extend_from_slice(text);
    }
    out
}

/// Type data of `0x41007c` (doc 22.4): the 22-byte raw version field
/// `01 16 | mixed20`, sent with the request's type copied. The research
/// sample answers a type 2 request; which requests trigger it in a real
/// session is not documented. // doc 22: unknown trigger
pub fn raw_version_data(mixed: &[u8; 20]) -> Vec<u8> {
    crate::mixed::raw_field(mixed).to_vec()
}

/// The MD5-Challenge digest of `0x40ccf4` (doc 13.4):
/// `MD5(identifier || password || challenge)`, or with ASCII `xxghlmxhzb`
/// between password and challenge when `(StartMode & 3) == 2`.
pub fn md5_value(identifier: u8, password: &[u8], challenge: &[u8], start_mode: u8) -> [u8; 16] {
    let salt: &[u8] = if start_mode & 3 == 2 { b"xxghlmxhzb" } else { b"" };
    md5_digest(identifier, password, salt, challenge)
}

/// Type data of the iNode Response/MD5-Challenge (doc 22.3): standard
/// `16 | digest | username`, no vendor extension.
pub fn md5_response_data(identifier: u8, password: &[u8], challenge: &[u8], username: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + username.len());
    out.push(16);
    out.extend_from_slice(&md5_value(identifier, password, challenge, 0));
    out.extend_from_slice(username);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc13_md5_values() {
        let c: Vec<u8> = (0..16).collect();
        assert_eq!(md5_value(7, b"synthetic", &c, 0), hex16("aa38fa828d4775e47e0c2a14b275189f"));
        assert_eq!(md5_value(7, b"synthetic", &c, 2), hex16("488e4bf09a8d375e78a63267374a2ef7"));
    }

    #[test]
    fn identity_lengths_doc22() {
        let text = [0x20u8; 32];
        let u = b"synthetic";
        // EAP type data lengths behind the 23-byte Ethernet/EAPOL/EAP head.
        assert_eq!(23 + identity_data(Some([1; 4]), Some(&text), u).len(), 70);
        assert_eq!(23 + identity_data(Some([1; 4]), None, u).len(), 38);
        assert_eq!(23 + identity_data(None, Some(&text), u).len(), 64);
        assert_eq!(23 + identity_data(None, None, u).len(), 32);
        assert_eq!(23 + online_identity_data(1, [1; 4], Some(&text)).len(), 61);
        assert_eq!(23 + online_identity_data(20, [1; 4], Some(&text)).len(), 62);
    }

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
