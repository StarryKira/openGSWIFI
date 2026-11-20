//! 安朗 802.1X (MentoHUST AuthType 7) username format (doc 14.5, doc 22.2).
//!
//! The 802.1X exchange itself lives in the EAPOL engine; this module only
//! provides the identity string that AuthType 7 sends instead of the bare
//! account name. It is a different protocol from the UDP client in this
//! crate (doc 01.2, doc 14.5).

use std::net::Ipv4Addr;

use crate::codec::CodecError;

/// Longest formatted username: the original `snprintf` buffer holds 115
/// bytes including the NUL (doc 14.5).
pub const EAP_USERNAME_MAX: usize = 114;

/// Formats the AuthType 7 identity:
/// `username + "#" + decimal(dhcp_mode != 0) + IPv4 text + "#4.2.1#EXT"`
/// (doc 14.5, MentoHUST GS `0x40bd2a..0x40bd5e`). There is no `#` between
/// the DHCP flag and the address: `student#0192.0.2.10#4.2.1#EXT`.
///
/// The original truncates silently at 114 bytes; this returns an error
/// instead, as `reference/auth_primitives.py::anlang_eap_username` does. A
/// NUL in the username is also refused, since the original C string would
/// have ended there. Static recovery only: the initialisation function was
/// not executed dynamically (doc 14.5).
pub fn eap_username(username: &str, ipv4: Ipv4Addr, dhcp_mode: bool) -> Result<String, CodecError> {
    if username.contains('\0') {
        return Err(CodecError::InvalidUsername);
    }
    let formatted = format!("{}#{}{}#4.2.1#EXT", username, u8::from(dhcp_mode), ipv4);
    if formatted.len() > EAP_USERNAME_MAX {
        return Err(CodecError::UsernameTooLong(formatted.len()));
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    #[test]
    fn doc_14_5_examples() {
        assert_eq!(eap_username("student", IP, false).unwrap(), "student#0192.0.2.10#4.2.1#EXT");
        assert_eq!(eap_username("student", IP, true).unwrap(), "student#1192.0.2.10#4.2.1#EXT");
    }

    #[test]
    fn length_limit_matches_reference() {
        // Suffix for 192.0.2.10 is 22 bytes: "#0" + 10 + "#4.2.1#EXT".
        let ok = "u".repeat(92);
        assert_eq!(eap_username(&ok, IP, false).unwrap().len(), 114);
        let long = "u".repeat(93);
        assert_eq!(eap_username(&long, IP, false), Err(CodecError::UsernameTooLong(115)));
        // Length counts UTF-8 bytes, like `len(result.encode())`.
        let wide = "学".repeat(31); // 93 bytes
        assert!(eap_username(&wide, IP, false).is_err());
        assert!(eap_username("a\0b", IP, false).is_err());
    }

    #[test]
    fn address_is_canonical_dotted_quad() {
        let ip = Ipv4Addr::new(10, 0, 200, 1);
        assert_eq!(eap_username("x", ip, true).unwrap(), "x#110.0.200.1#4.2.1#EXT");
        assert_eq!(eap_username("", ip, false).unwrap(), "#010.0.200.1#4.2.1#EXT");
    }
}
