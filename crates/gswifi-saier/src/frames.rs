//! Saier frames (MentoHUST StartMode 2, research doc 21.2). Everything goes
//! to the standard PAE group address; control frames carry 42 bytes of 0xa5.

use gswifi_core::NetInfo;
use gswifi_eapol::frame::{
    eapol_header, md5_response, CODE_RESPONSE, EAP_TYPE_IDENTITY, MAC_STANDARD, TYPE_EAP_PACKET,
};

/// Inserted between password and challenge in the MD5 response.
pub const SALT: &[u8] = b"xxghlmxhzb";
/// Version string inside the Identity response.
const VERSION: &[u8; 8] = b"03.02.05";
/// Keepalive EAPOL type.
pub const TYPE_KEEPALIVE: u8 = 6;
/// Saier server message (EAP request type).
pub const EAP_TYPE_MESSAGE: u8 = 10;
/// EAP type some Saier servers use for their identity request.
pub const EAP_TYPE_IDENTITY_20: u8 = 20;

/// Saier servers ask for "User name" (doc 21.2).
pub fn is_saier_identity(data: &[u8]) -> bool {
    data.starts_with(b"User name")
}

/// Start (1), Logoff (2) or keepalive (6): 18 byte header and 42 x 0xa5.
pub fn build_control_packet(typ: u8, local_mac: &[u8; 6]) -> Vec<u8> {
    let mut frame = eapol_header(&MAC_STANDARD, local_mac, typ, 0);
    frame.extend_from_slice(&[0xa5; 42]);
    frame
}

/// `01 | ip | mask | gateway | 00000000 | "03.02.05" | username`
///
/// The fourth 4-byte slot is always zero: the original builder (doc 25.3)
/// writes IP/mask/gateway and then clears it, regardless of the configured
/// DNS. An earlier reading of this as the DNS field was wrong.
pub fn build_identity_packet(local_mac: &[u8; 6], net: &NetInfo, identity: &[u8], id: u8) -> Vec<u8> {
    let eap_len = (30 + identity.len()) as u16;
    let mut frame = eapol_header(&MAC_STANDARD, local_mac, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(EAP_TYPE_IDENTITY);
    frame.push(0x01);
    for a in [net.ip, net.mask, net.gateway, [0u8; 4]] {
        frame.extend_from_slice(&a);
    }
    frame.extend_from_slice(VERSION);
    frame.extend_from_slice(identity);
    frame
}

/// MD5 response: `MD5(id || password || SALT || challenge)`, then the
/// username, to the group address.
pub fn build_password_packet(local_mac: &[u8; 6], identity: &[u8], password: &[u8], seed: &[u8], id: u8) -> Vec<u8> {
    let digest = gswifi_eapol::frame::md5_digest(id, password, SALT, seed);
    md5_response(&MAC_STANDARD, local_mac, id, &digest, identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// doc 25.3 / saier-dns-vectors.json: the fourth slot is zero whatever the
    /// configured DNS is.
    #[test]
    fn identity_fourth_slot_is_zero() {
        let net = NetInfo {
            ip: [192, 0, 2, 10],
            mask: [255, 255, 255, 0],
            gateway: [192, 0, 2, 1],
            dns: [203, 0, 113, 53],
            ipv6: [0; 16],
        };
        let frame = build_identity_packet(&[2, 0, 0, 0, 0, 1], &net, b"synthetic", 7);
        assert_eq!(
            hex::encode(&frame),
            "0180c2000003020000000001888e01000027020700270101c000020affffff00c00002010000000030332e30322e303573796e746865746963"
        );
    }

    #[test]
    fn control_and_password_frames() {
        let start = build_control_packet(1, &[2, 0, 0, 0, 0, 1]);
        assert_eq!(start.len(), 60);
        assert_eq!(&start[..18], &hex::decode("0180c2000003020000000001888e01010000").unwrap()[..]);
        assert!(start[18..].iter().all(|&b| b == 0xa5));
        // doc 21.2 / auth_primitives.eap_md5 with start_mode 2: the salt sits
        // between password and challenge.
        let seed: Vec<u8> = (0..16).collect();
        let frame = build_password_packet(&[2, 0, 0, 0, 0, 1], b"u", b"p", &seed, 3);
        let mut input = vec![3u8];
        input.extend_from_slice(b"p");
        input.extend_from_slice(SALT);
        input.extend_from_slice(&seed);
        assert_eq!(frame[..6], MAC_STANDARD);
        assert_eq!(&frame[24..40], &gswifi_eapol::frame::md5_digest(3, b"p", SALT, &seed));
        assert_eq!(&frame[40..], b"u");
    }
}
