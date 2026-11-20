//! Ruijie EAPOL heartbeat (research doc 17): key and interval from the
//! Success frame, 45 byte type 0xbf frames with a running sequence number.

use crate::crypt::encrypt_rtv;
use super::{eapol_header, TYPE_EAPOL_HEARTBEAT};

/// Sequence number of the first heartbeat after an MD5 response.
pub const FIRST_SEQUENCE: u32 = 0x102b;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SuccessInfo {
    pub key: u32,
    /// Heartbeat interval in seconds: the configured value, or the one from
    /// the Success frame when the configured value is 0.
    pub interval: u32,
    /// 255 when the Success frame carries no extension.
    pub flag: u8,
}

fn decode_u32(b: &[u8]) -> u32 {
    let d = encrypt_rtv(b);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// Length of the server message that starts at frame[28].
fn message_len(frame: &[u8]) -> Option<usize> {
    (frame.len() >= 28).then(|| u16::from_be_bytes([frame[26], frame[27]]) as usize)
}

/// Server message at the start of a Success/Failure trailer (e.g. "OK\r\n").
pub fn server_message(frame: &[u8]) -> Option<&[u8]> {
    let m = message_len(frame)?;
    frame.get(28..28 + m).filter(|s| !s.is_empty())
}

/// Reads the heartbeat key and interval. Unlike the original client this
/// refuses truncated frames instead of reading past them.
pub fn parse_success(frame: &[u8], configured_interval: u32) -> Option<SuccessInfo> {
    if frame.len() < 28 || frame[12..14] != [0x88, 0x8e] || frame[18] != 3 {
        return None;
    }
    let m = message_len(frame)?;
    let key_at = m + 157;
    let tail = frame.get(m + 156..key_at + 8)?;
    let key = decode_u32(&tail[1..5]);
    let interval = if configured_interval != 0 {
        configured_interval
    } else {
        decode_u32(&tail[5..9])
    };
    let eapol_len = u16::from_be_bytes([frame[16], frame[17]]);
    let flag = if eapol_len < 13 { 255 } else { tail[0] };
    Some(SuccessInfo { key, interval, flag })
}

/// 45 byte heartbeat; the EAPOL header announces 30 bytes, the original
/// client sends 45 (the NIC pads to 60 either way).
pub fn build_echo_packet(dest_mac: &[u8; 6], local_mac: &[u8; 6], key: u32, sequence: u32) -> Vec<u8> {
    const FILL1: [u8; 6] = [0xff, 0xff, 0x37, 0x77, 0x7f, 0x9f];
    const FILL2: [u8; 7] = [0xff, 0xff, 0x37, 0x77, 0x7f, 0x3f, 0xff];
    let mut frame = eapol_header(dest_mac, local_mac, TYPE_EAPOL_HEARTBEAT, 0x1e);
    frame.extend_from_slice(&FILL1);
    frame.extend_from_slice(&encrypt_rtv(&key.wrapping_add(sequence).to_be_bytes()));
    frame.extend_from_slice(&FILL1);
    frame.extend_from_slice(&encrypt_rtv(&sequence.to_be_bytes()));
    frame.extend_from_slice(&FILL2);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic Success and the three heartbeats that follow it
    /// (evidence/p0/success-three-echo.json).
    const SUCCESS: &str = "020000000001020000000002888e0100009c030700040000000000044f4b0d0a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f7fbf3fdffffff870000000000";
    const ECHOES: [&str; 3] = [
        "020000000002020000000001888e01bf001effff37777f9ff7fbfd29ffff37777f9ffffff72bffff37777f3fff",
        "020000000002020000000001888e01bf001effff37777f9ff7fbfdc9ffff37777f9ffffff7cbffff37777f3fff",
        "020000000002020000000001888e01bf001effff37777f9ff7fbfd49ffff37777f9ffffff74bffff37777f3fff",
    ];

    #[test]
    fn success_and_three_echoes() {
        let success = hex::decode(SUCCESS).unwrap();
        let info = parse_success(&success, 0).unwrap();
        assert_eq!(info, SuccessInfo { key: 0x1020_3040, interval: 30, flag: 1 });
        assert_eq!(server_message(&success), Some(&b"OK\r\n"[..]));
        let server = [2, 0, 0, 0, 0, 2];
        let local = [2, 0, 0, 0, 0, 1];
        for (i, want) in ECHOES.iter().enumerate() {
            let frame = build_echo_packet(&server, &local, info.key, FIRST_SEQUENCE + i as u32);
            assert_eq!(hex::encode(&frame), *want);
            assert_eq!(frame.len(), 45);
        }
    }

    #[test]
    fn configured_interval_wins_and_message_moves_fields() {
        let success = hex::decode(SUCCESS).unwrap();
        assert_eq!(parse_success(&success, 17).unwrap().interval, 17);
        // A longer message moves the key and interval with it.
        let mut longer = success[..28].to_vec();
        longer.extend_from_slice(b"0123456789");
        longer.extend_from_slice(&success[28..]);
        longer[26..28].copy_from_slice(&14u16.to_be_bytes());
        assert_eq!(parse_success(&longer, 0), parse_success(&success, 0));
        assert_eq!(parse_success(&success[..164], 0), None);
    }

    #[test]
    fn sequence_wraps() {
        let frame = build_echo_packet(&[0; 6], &[0; 6], 2, u32::MAX);
        assert_eq!(encrypt_rtv(&frame[24..28]), vec![0, 0, 0, 1]);
        assert_eq!(encrypt_rtv(&frame[34..38]), vec![0xff; 4]);
    }
}
