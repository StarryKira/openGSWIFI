//! EAPOL (IEEE 802.1X) and EAP (RFC 3748) wire format.

/// EtherType of EAPOL frames.
pub const ETH_P_PAE: u16 = 0x888e;
pub const EAPOL_VERSION: u8 = 1;

/// EAPOL packet types.
pub const TYPE_EAP_PACKET: u8 = 0;
pub const TYPE_EAPOL_START: u8 = 1;
pub const TYPE_EAPOL_LOGOFF: u8 = 2;

/// EAP codes.
pub const CODE_REQUEST: u8 = 1;
pub const CODE_RESPONSE: u8 = 2;
pub const CODE_SUCCESS: u8 = 3;
pub const CODE_FAILURE: u8 = 4;

/// EAP request/response types.
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_MD5_CHALLENGE: u8 = 4;

/// IEEE 802.1X PAE group address.
pub const MAC_STANDARD: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];
/// Ruijie private group address.
pub const MAC_RUIJIE: [u8; 6] = [0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03];
pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];

/// Destination of the first EAPOL-Start for MentoHUST's StartMode
/// (doc 21.1): 0 standard group, 1 Ruijie group, 2 (Saier) standard
/// group, 3 broadcast.
pub fn start_dest(start_mode: u8) -> [u8; 6] {
    match start_mode & 3 {
        1 => MAC_RUIJIE,
        3 => MAC_BROADCAST,
        _ => MAC_STANDARD,
    }
}

/// Destination of the `attempt`-th Start of a round: the configured one
/// first, then Ruijie group → broadcast → standard group in turn, so a
/// wrong StartMode still finds the server (doc 21.3).
pub fn rotating_start_dest(start_mode: u8, attempt: u32) -> [u8; 6] {
    const ROTATION: [u8; 3] = [1, 3, 0];
    let first = ROTATION.iter().position(|&m| m == start_mode & 3).unwrap_or(0);
    start_dest(ROTATION[(first + attempt as usize) % ROTATION.len()])
}

/// Destination of Identity/MD5 responses and keepalives: the server, or
/// the standard group address with PktType 1. Saier always uses the group
/// address.
pub fn response_dest(start_mode: u8, pkt_type: u8, server: &[u8; 6]) -> [u8; 6] {
    if start_mode & 3 == 2 || pkt_type == 1 {
        MAC_STANDARD
    } else {
        *server
    }
}

/// Destination of EAPOL-Logoff: like a response, except broadcast in
/// StartMode 3.
pub fn logoff_dest(start_mode: u8, pkt_type: u8, server: &[u8; 6]) -> [u8; 6] {
    if start_mode & 3 == 3 {
        MAC_BROADCAST
    } else {
        response_dest(start_mode, pkt_type, server)
    }
}

/// Ethernet + EAPOL header; `len` is the EAPOL body length.
pub fn eapol_header(dest: &[u8; 6], src: &[u8; 6], typ: u8, len: u16) -> Vec<u8> {
    let mut head = Vec::with_capacity(1000);
    head.extend_from_slice(dest);
    head.extend_from_slice(src);
    head.extend_from_slice(&ETH_P_PAE.to_be_bytes());
    head.push(EAPOL_VERSION);
    head.push(typ);
    head.extend_from_slice(&len.to_be_bytes());
    head
}

/// EAPOL-Start / EAPOL-Logoff without body.
pub fn control_frame(dest: &[u8; 6], src: &[u8; 6], typ: u8) -> Vec<u8> {
    eapol_header(dest, src, typ, 0)
}

/// EAP-Response/Identity carrying `identity`.
pub fn identity_response(dest: &[u8; 6], src: &[u8; 6], id: u8, identity: &[u8]) -> Vec<u8> {
    let eap_len = (identity.len() + 5) as u16;
    let mut frame = eapol_header(dest, src, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(EAP_TYPE_IDENTITY);
    frame.extend_from_slice(identity);
    frame
}

/// EAP-Response/MD5-Challenge: the 16 byte digest followed by `name`.
pub fn md5_response(dest: &[u8; 6], src: &[u8; 6], id: u8, digest: &[u8; 16], name: &[u8]) -> Vec<u8> {
    let eap_len = (name.len() + 22) as u16;
    let mut frame = eapol_header(dest, src, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(EAP_TYPE_MD5_CHALLENGE);
    frame.push(16);
    frame.extend_from_slice(digest);
    frame.extend_from_slice(name);
    frame
}

/// `MD5(id || password || salt || challenge)` (RFC 3748 §5.4 with an empty
/// salt; Saier inserts one, doc 21.2).
pub fn md5_digest(id: u8, password: &[u8], salt: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(1 + password.len() + salt.len() + challenge.len());
    input.push(id);
    input.extend_from_slice(password);
    input.extend_from_slice(salt);
    input.extend_from_slice(challenge);
    md5::compute(input).0
}

/// An EAP packet received from the authenticator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received<'a> {
    Request {
        src: [u8; 6],
        id: u8,
        kind: u8,
        data: &'a [u8],
    },
    Success {
        src: [u8; 6],
        id: u8,
    },
    Failure {
        src: [u8; 6],
        id: u8,
    },
    /// Another EAPOL type (vendor keepalive, key frames) or EAP code.
    Other {
        typ: u8,
    },
}

/// Parses an Ethernet frame. `None` if it is not EAPOL at all. The request
/// data is clamped to the EAP length and the frame.
pub fn parse(frame: &[u8]) -> Option<Received<'_>> {
    if frame.len() < 22 || frame[12..14] != ETH_P_PAE.to_be_bytes() {
        return None;
    }
    if frame[15] != TYPE_EAP_PACKET {
        return Some(Received::Other { typ: frame[15] });
    }
    let src: [u8; 6] = frame[6..12].try_into().unwrap();
    let (code, id) = (frame[18], frame[19]);
    let eap_len = u16::from_be_bytes([frame[20], frame[21]]) as usize;
    Some(match code {
        CODE_REQUEST if frame.len() > 22 => {
            let end = (18 + eap_len).clamp(23, frame.len());
            Received::Request { src, id, kind: frame[22], data: &frame[23..end] }
        }
        CODE_SUCCESS => Received::Success { src, id },
        CODE_FAILURE => Received::Failure { src, id },
        _ => Received::Other { typ: TYPE_EAP_PACKET },
    })
}

/// Server message that Ruijie/H3C style authenticators put after the
/// 4 byte EAP header of Success/Failure: `BE16 length @26 | text @28`.
pub fn trailer_message(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 28 {
        return None;
    }
    let m = u16::from_be_bytes([frame[26], frame[27]]) as usize;
    frame.get(28..28 + m).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];

    #[test]
    fn standard_frames() {
        assert_eq!(
            hex::encode(control_frame(&MAC_STANDARD, &LOCAL, TYPE_EAPOL_START)),
            "0180c2000003020000000001888e01010000"
        );
        assert_eq!(
            hex::encode(identity_response(&SERVER, &LOCAL, 1, b"user")),
            "020000000002020000000001888e01000009020100090175736572"
        );
        let digest = md5_digest(2, b"pass", b"", &[0x11; 16]);
        let frame = md5_response(&SERVER, &LOCAL, 2, &digest, b"user");
        assert_eq!(&frame[14..24], &[1, 0, 0, 26, 2, 2, 0, 26, 4, 16]);
        assert_eq!(&frame[24..40], &digest);
        assert_eq!(&frame[40..], b"user");
    }

    #[test]
    fn start_rotation() {
        let seq = |mode| (0..4).map(|i| rotating_start_dest(mode, i)).collect::<Vec<_>>();
        assert_eq!(seq(0), [MAC_STANDARD, MAC_RUIJIE, MAC_BROADCAST, MAC_STANDARD]);
        assert_eq!(seq(1), [MAC_RUIJIE, MAC_BROADCAST, MAC_STANDARD, MAC_RUIJIE]);
        assert_eq!(seq(3), [MAC_BROADCAST, MAC_STANDARD, MAC_RUIJIE, MAC_BROADCAST]);
        assert_eq!(response_dest(0, 0, &SERVER), SERVER);
        assert_eq!(response_dest(0, 1, &SERVER), MAC_STANDARD);
        assert_eq!(response_dest(2, 0, &SERVER), MAC_STANDARD);
        assert_eq!(logoff_dest(3, 0, &SERVER), MAC_BROADCAST);
        assert_eq!(logoff_dest(1, 0, &SERVER), SERVER);
    }

    #[test]
    fn rfc3748_md5() {
        // MD5(0x02 || "pass" || challenge), computed independently.
        let mut input = vec![2u8];
        input.extend_from_slice(b"pass");
        input.extend_from_slice(&[0x11; 16]);
        assert_eq!(md5_digest(2, b"pass", b"", &[0x11; 16]), md5::compute(&input).0);
    }

    #[test]
    fn parse_requests() {
        let mut req = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 5);
        req.extend_from_slice(&[CODE_REQUEST, 7, 0, 5, EAP_TYPE_IDENTITY]);
        req.resize(60, 0);
        assert_eq!(parse(&req), Some(Received::Request { src: SERVER, id: 7, kind: 1, data: &[] }));

        let mut md5 = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 22);
        md5.extend_from_slice(&[CODE_REQUEST, 8, 0, 22, EAP_TYPE_MD5_CHALLENGE, 16]);
        md5.extend_from_slice(&[0xaa; 16]);
        match parse(&md5) {
            Some(Received::Request { kind: 4, data, .. }) => assert_eq!(data.len(), 17),
            other => panic!("{:?}", other),
        }
        // An EAP length beyond the frame is clamped.
        md5[20..22].copy_from_slice(&500u16.to_be_bytes());
        assert!(matches!(parse(&md5), Some(Received::Request { data, .. }) if data.len() == 17));

        let mut fail = eapol_header(&LOCAL, &SERVER, TYPE_EAP_PACKET, 4);
        fail.extend_from_slice(&[CODE_FAILURE, 9, 0, 4]);
        assert_eq!(parse(&fail), Some(Received::Failure { src: SERVER, id: 9 }));
        assert_eq!(trailer_message(&fail), None);

        let keepalive = eapol_header(&LOCAL, &SERVER, 0xbf, 0);
        assert_eq!(parse(&[keepalive, vec![0; 8]].concat()), Some(Received::Other { typ: 0xbf }));
        assert_eq!(parse(&[0u8; 30]), None);
        assert_eq!(parse(&req[..21]), None);
    }
}
