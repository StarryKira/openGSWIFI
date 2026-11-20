//! Frames of the Ruijie client: EAPOL control frames, Identity and MD5
//! responses with the vendor extension in its three formats, and the
//! EAPOL heartbeat (research docs 17, 18).

mod rtv;
pub mod classic;
pub mod echo;
pub mod v4;

pub use gswifi_core::NetInfo;
pub use gswifi_eapol::frame::{
    logoff_dest, md5_digest, response_dest, start_dest, ETH_P_PAE, MAC_BROADCAST, MAC_RUIJIE, MAC_STANDARD, TYPE_EAPOL_LOGOFF, TYPE_EAPOL_START, TYPE_EAP_PACKET,
};
use gswifi_eapol::frame::{eapol_header, CODE_RESPONSE, EAP_TYPE_IDENTITY, EAP_TYPE_MD5_CHALLENGE};

/// 锐捷心跳
pub const TYPE_EAPOL_HEARTBEAT: u8 = 0xbf;

/// Length the classic Ruijie client pads every frame carrying its extension to.
const CLASSIC_FRAME_LEN: usize = 1000;

/// What follows the standard EAP part of the frames we send.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExtFormat {
    /// Extension of a recent Ruijie client; what mentorust has always sent.
    Modern,
    /// MentoHUST style: encoded IPv4 header + 448 byte template, frames padded
    /// to 1000 bytes.
    Classic,
    /// Plain IEEE 802.1X / EAP-MD5 without vendor data.
    None,
    /// Extended format MentoHUST GS switches Classic to when the
    /// authenticator is not a Ruijie switch (doc 18.7); never configured.
    V4,
}

impl ExtFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "modern" | "" => Some(ExtFormat::Modern),
            "classic" | "mentohust" => Some(ExtFormat::Classic),
            "none" | "standard" => Some(ExtFormat::None),
            _ => None,
        }
    }
}

/// Everything the vendor extension of one frame depends on.
pub struct ExtParams<'a> {
    pub format: ExtFormat,
    pub mac: [u8; 6],
    pub net: &'a NetInfo,
    /// Internal DHCP mode 0..=6 (4..=6: DHCP of mode 1..=3 already done).
    pub dhcp_mode: u8,
    /// Client version written into the classic template, `None` keeps 4.10.
    pub version: Option<[u8; 2]>,
}

/// Per frame attribute values; `None` keeps the default of the format.
/// The client checks of an MD5 response (doc 20.2) are V2 in 0x17 and the
/// mix result in 0x4d (in V4 also 0x60, no 0x17); 0x2f is the password
/// attribute of the V4 format.
#[derive(Clone, Copy, Debug, Default)]
pub struct Checks<'a> {
    pub field17: Option<&'a [u8; 32]>,
    pub field4d: Option<&'a [u8; 128]>,
    pub field2f: Option<&'a [u8; 16]>,
}

impl ExtParams<'_> {
    pub fn build(&self, checks: Checks) -> Vec<u8> {
        match self.format {
            ExtFormat::None => Vec::new(),
            ExtFormat::Modern => rtv::build_modern(&self.mac, &self.net.ip, &self.net.ipv6, checks),
            ExtFormat::Classic => classic::build(self, checks),
            ExtFormat::V4 => v4::build(self, checks),
        }
    }
}

/// Start and Logoff only carry the extension in the classic and V4 formats
/// with the Ruijie group address (StartMode 1); the modern format never did.
pub fn control_has_ext(format: ExtFormat, start_mode: u8) -> bool {
    matches!(format, ExtFormat::Classic | ExtFormat::V4) && start_mode & 3 == 1
}

/// Appends the extension; frames of the classic and V4 formats are padded
/// to 1000 bytes.
fn finish(mut frame: Vec<u8>, format: ExtFormat, ext: Vec<u8>) -> Vec<u8> {
    let had_ext = !ext.is_empty();
    frame.extend_from_slice(&ext);
    if had_ext && matches!(format, ExtFormat::Classic | ExtFormat::V4) && frame.len() < CLASSIC_FRAME_LEN {
        frame.resize(CLASSIC_FRAME_LEN, 0);
    }
    frame
}

/// EAPOL-Start or EAPOL-Logoff, optionally followed by the vendor extension.
pub fn build_control_packet(typ: u8, dest_mac: &[u8; 6], ext: Option<(&ExtParams, Checks)>, local_mac: &[u8; 6]) -> Vec<u8> {
    let frame = eapol_header(dest_mac, local_mac, typ, 0);
    match ext {
        Some((p, checks)) => finish(frame, p.format, p.build(checks)),
        None => frame,
    }
}

/// EAP-Response/Identity. The V4 format sends it without extension.
pub fn build_identity_packet(
    dest_mac: &[u8; 6],
    p: &ExtParams,
    field17: Option<&[u8; 32]>,
    identity: &[u8],
    id: u8,
) -> Vec<u8> {
    let eap_len = (identity.len() + 5) as u16;
    let mut frame = eapol_header(dest_mac, &p.mac, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(EAP_TYPE_IDENTITY);
    frame.extend_from_slice(identity);
    if p.format == ExtFormat::V4 {
        return frame;
    }
    finish(frame, p.format, p.build(Checks { field17, ..Default::default() }))
}

/// EAP-Response/MD5-Challenge. In the V4 format the area replaces the
/// username inside the EAP message, without its trailing `ff` mark.
pub fn build_password_packet(
    dest_mac: &[u8; 6],
    p: &ExtParams,
    checks: Checks,
    identity: &[u8],
    digest: &[u8; 16],
    id: u8,
) -> Vec<u8> {
    let area = (p.format == ExtFormat::V4).then(|| v4::build(p, checks));
    let body = match &area {
        Some(area) => &area[..area.len() - 1],
        None => identity,
    };
    let eap_len = (body.len() + 22) as u16;
    let mut frame = eapol_header(dest_mac, &p.mac, TYPE_EAP_PACKET, eap_len);
    frame.extend_from_slice(&[CODE_RESPONSE, id]);
    frame.extend_from_slice(&eap_len.to_be_bytes());
    frame.push(EAP_TYPE_MD5_CHALLENGE);
    frame.push(16);
    frame.extend_from_slice(digest);
    frame.extend_from_slice(body);
    if area.is_some() {
        return frame;
    }
    finish(frame, p.format, p.build(checks))
}

/// The fixed heartbeat mentorust has always sent. Used when the Success frame
/// carries no echo key.
pub fn build_legacy_heartbeat_packet(dest_mac: &[u8; 6], local_mac: &[u8; 6]) -> Vec<u8> {
    const ECHO_DATA: [u8; 30] = [
        0xFF, 0xFF, 0x37, 0x77, 0x7F, 0x9F, 0xF7, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x37, 0x77, 0x7F,
        0x9F, 0xF7, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x37, 0x77, 0x7F, 0x3F, 0xFF, 0x00, 0x00, 0x00,
    ];
    let mut frame = eapol_header(dest_mac, local_mac, TYPE_EAPOL_HEARTBEAT, 0x1e);
    frame.extend_from_slice(&ECHO_DATA);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use gswifi_saier::frames as saier;

    const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SERVER: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const USER: &[u8] = b"synthetic";

    fn challenge() -> Vec<u8> {
        (0..16).collect()
    }

    fn mac_str(m: &[u8; 6]) -> String {
        m.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    /// Builds one frame of the GS matrix the way the session does.
    fn gs_frame(start_mode: u8, pkt_type: u8, dhcp_mode: u8, version: [u8; 2], tag: &str) -> ([u8; 6], Vec<u8>) {
        let net = NetInfo {
            ip: [192, 0, 2, 10],
            mask: [255, 255, 255, 0],
            gateway: [192, 0, 2, 1],
            dns: if start_mode == 2 { [0; 4] } else { [198, 51, 100, 53] },
            ipv6: [0; 16],
        };
        let p = ExtParams {
            format: ExtFormat::Classic,
            mac: LOCAL,
            net: &net,
            dhcp_mode,
            version: Some(version),
        };
        let placeholder = classic::placeholder([0x10203; 5]);
        let resp = response_dest(start_mode, pkt_type, &SERVER);
        let checks = Checks { field17: Some(&placeholder), ..Default::default() };
        let ext = control_has_ext(p.format, start_mode).then_some((&p, checks));
        match (start_mode, tag) {
            (2, "start") => (MAC_STANDARD, saier::build_control_packet(TYPE_EAPOL_START, &LOCAL)),
            (2, "logoff") => (MAC_STANDARD, saier::build_control_packet(TYPE_EAPOL_LOGOFF, &LOCAL)),
            (2, t) if t.starts_with("echo") => (MAC_STANDARD, saier::build_control_packet(saier::TYPE_KEEPALIVE, &LOCAL)),
            (2, "identity") => (resp, saier::build_identity_packet(&LOCAL, &net, USER, 7)),
            (2, "md5") => {
                let digest = md5_digest(7, USER, saier::SALT, &challenge());
                let none = ExtParams { format: ExtFormat::None, ..p };
                (resp, build_password_packet(&resp, &none, Checks::default(), USER, &digest, 7))
            }
            (_, "start") => {
                let dst = start_dest(start_mode);
                (dst, build_control_packet(TYPE_EAPOL_START, &dst, ext, &LOCAL))
            }
            (_, "logoff") => {
                let dst = logoff_dest(start_mode, pkt_type, &SERVER);
                (dst, build_control_packet(TYPE_EAPOL_LOGOFF, &dst, ext, &LOCAL))
            }
            (_, "identity") => (resp, build_identity_packet(&resp, &p, Some(&placeholder), USER, 7)),
            (_, "md5") => {
                let digest = md5_digest(7, USER, b"", &challenge());
                (resp, build_password_packet(&resp, &p, Checks::default(), USER, &digest, 7))
            }
            (_, t) if t.starts_with("echo") => {
                let seq = echo::FIRST_SEQUENCE + (t.as_bytes()[4] - b'1') as u32;
                (resp, echo::build_echo_packet(&resp, &LOCAL, 0x1020_3040, seq))
            }
            _ => panic!("unknown tag {}", tag),
        }
    }

    /// StartMode 0..3 x PktType 0..1 x internal DHCP mode 0..6, plus version
    /// 3.30: every Start/Identity/MD5/Logoff/heartbeat of the GS matrix.
    #[test]
    fn gs_frame_matrix() {
        let data = include_str!("testdata/gs-frames.txt");
        let mut checked = 0;
        for line in data.lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (case, tag, dst, len, digest) = (f[0], f[1], f[2], f[3], f[4]);
            let (sm, pt, dm, version) = if case == "rj-330" {
                (1, 0, 0, [3, 30])
            } else {
                let n: Vec<u8> = case[3..].split('-').map(|x| x.parse().unwrap()).collect();
                (n[0], n[1], n[2], [4, 10])
            };
            let (dest, frame) = gs_frame(sm, pt, dm, version, tag);
            assert_eq!(mac_str(&dest), dst, "{} {}", case, tag);
            assert_eq!(frame.len().to_string(), len, "{} {}", case, tag);
            assert_eq!(hex::encode(md5::compute(&frame).0), digest, "{} {}", case, tag);
            checked += 1;
        }
        assert_eq!(checked, 399);
    }

    /// Extended format (doc 18.7): the original builders with the flag set
    /// after a normal Start, internal DHCP mode 0/1/4, algorithm 2.00 (V2
    /// only) and 4.81 (mix check) over the synthetic data file, version 4.81.
    #[test]
    fn v4_layout_vectors() {
        use crate::check::mix;
        use crate::materials::{self, ClientFiles};
        // "V4校验值" printed by the original for 4.81.
        const MIX_481: &str = "6daf7645121c88725de73a2e61def8aafd73b4284a7d3c7c6491d40363e46f619d4946c5232e1a16509c56d5ef50484d80fb1370369d9308833c7fa939509fe5";
        let seed: [u8; 16] = std::array::from_fn(|i| i as u8);
        let net = NetInfo {
            ip: [192, 0, 2, 10],
            mask: [255, 255, 255, 0],
            gateway: [192, 0, 2, 1],
            dns: [198, 51, 100, 53],
            ipv6: [0; 16],
        };
        let files = ClientFiles {
            data: Some(include_bytes!("../check/testdata/materials/dat/default.mpf").to_vec()),
            ..Default::default()
        };
        let digest = md5_digest(7, USER, b"", &seed);
        let password = v4::password_attribute(USER, USER, &seed);
        let mut checked = 0;
        for line in include_str!("testdata/v4-layout.txt").lines().filter(|l| !l.starts_with('#')) {
            let f: Vec<&str> = line.split(' ').collect();
            let (dhcp_mode, version, stage) = (f[0].parse().unwrap(), f[1].parse().unwrap(), f[2]);
            let m = materials::assemble(&files, version).unwrap();
            let mixed = (m.check_type != 2).then(|| mix::family_result(version, &m.a, &m.b, &seed));
            if version == 481 {
                assert_eq!(std::str::from_utf8(mixed.as_ref().unwrap()).unwrap(), MIX_481);
            }
            let format = if stage == "start-before" { ExtFormat::Classic } else { ExtFormat::V4 };
            let p = ExtParams { format, mac: LOCAL, net: &net, dhcp_mode, version: Some([4, 81]) };
            // Start and Logoff rebuild the template, 0x2f from the last seed.
            let control = Checks { field2f: password.as_ref(), ..Default::default() };
            let (dest, frame) = match stage {
                "start-before" | "start-after" => {
                    let dst = start_dest(1);
                    (dst, build_control_packet(TYPE_EAPOL_START, &dst, Some((&p, control)), &LOCAL))
                }
                "identity" => (MAC_STANDARD, build_identity_packet(&MAC_STANDARD, &p, None, USER, 7)),
                "md5" => {
                    let checks = Checks { field17: None, field4d: mixed.as_ref(), field2f: password.as_ref() };
                    (MAC_STANDARD, build_password_packet(&MAC_STANDARD, &p, checks, USER, &digest, 7))
                }
                "logoff" => (MAC_STANDARD, build_control_packet(TYPE_EAPOL_LOGOFF, &MAC_STANDARD, Some((&p, control)), &LOCAL)),
                s => panic!("stage {}", s),
            };
            let eapol = u16::from_be_bytes([frame[16], frame[17]]);
            assert_eq!([mac_str(&dest).replace(':', ""), frame.len().to_string(), eapol.to_string()], [f[5], f[3], f[4]], "{}", line);
            if f[6] != "-" {
                let md5 = stage == "md5";
                let area = if md5 { &frame[40..] } else { &frame[18..18 + v4::AREA_LEN] };
                let template = v4::build(&p, Checks::default());
                assert_eq!(hex::encode(&area[..57]), f[6], "{}", line);
                assert_eq!((&area[59..65], format!("{:02x}", area[67]), area[438]), (&LOCAL[..], f[7].to_string(), 0x20), "{}", line);
                assert_eq!(area[161..289], area[291..419], "{}", line);
                assert_eq!(area[161..289] != template[161..289], f[8] == "1", "{}", line);
                assert_eq!(area[143..159], password.unwrap(), "{}", line);
                if md5 {
                    // Both lengths 480: the area without its ff mark is part of the EAP message.
                    assert_eq!((&frame[20..22], &frame[24..40]), (&eapol.to_be_bytes()[..], &digest[..]), "{}", line);
                } else {
                    assert_eq!(area[458], 0xff, "{}", line);
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 30);
    }

    /// The modern format must stay byte for byte what mentorust 1.0 sent.
    #[test]
    fn modern_frames_unchanged() {
        let data = include_str!("testdata/modern-baseline.txt");
        let get = |k: &str| data.lines().find_map(|l| l.strip_prefix(k)).unwrap().trim().to_string();
        let net = NetInfo { ip: [10, 20, 30, 40], ..Default::default() };
        let p = ExtParams { format: ExtFormat::Modern, mac: LOCAL, net: &net, dhcp_mode: 0, version: None };
        assert_eq!(hex::encode(build_control_packet(TYPE_EAPOL_START, &SERVER, None, &LOCAL)), get("START "));
        assert_eq!(hex::encode(build_identity_packet(&SERVER, &p, None, USER, 7)), get("IDENT0 "));
        let digest = md5_digest(7, USER, b"", &challenge());
        assert_eq!(hex::encode(build_password_packet(&SERVER, &p, Checks::default(), USER, &digest, 7)), get("MD50 "));
        assert_eq!(hex::encode(build_legacy_heartbeat_packet(&SERVER, &LOCAL)), get("HB "));
        let net6 = NetInfo { ipv6: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8], ..net };
        let p = ExtParams { net: &net6, ..p };
        assert_eq!(hex::encode(build_identity_packet(&SERVER, &p, None, USER, 7)), get("IDENT6 "));
    }

    /// Synthetic password vector: id 7, password "synthetic", challenge 00..0f.
    #[test]
    fn md5_digest_with_and_without_saier_salt() {
        let challenge: Vec<u8> = (0..16).collect();
        assert_eq!(
            hex::encode(md5_digest(7, b"synthetic", b"", &challenge)),
            "aa38fa828d4775e47e0c2a14b275189f"
        );
        assert_eq!(
            hex::encode(md5_digest(7, b"synthetic", saier::SALT, &challenge)),
            "488e4bf09a8d375e78a63267374a2ef7"
        );
    }
}
