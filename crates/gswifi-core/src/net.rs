use std::net::Ipv4Addr;

/// Addresses of the authenticating interface. Unknown fields are zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetInfo {
    pub ip: [u8; 4],
    pub mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    /// First global IPv6 address, zero when there is none.
    pub ipv6: [u8; 16],
}

impl NetInfo {
    pub fn has_ipv4(&self) -> bool {
        self.ip != [0; 4]
    }

    pub fn ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ip)
    }
}

/// What a driver knows about its interface when it is created.
#[derive(Clone, Debug, Default)]
pub struct Env {
    /// Interface name (`eth0.2`, `wan`, `en0`).
    pub interface: String,
    pub mac: [u8; 6],
    pub net: NetInfo,
}

pub fn mac_str(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Parses `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for byte in mac.iter_mut() {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trip() {
        let mac = [0x00, 0x1a, 0xa9, 0xff, 0x10, 0x02];
        assert_eq!(mac_str(&mac), "00:1a:a9:ff:10:02");
        assert_eq!(parse_mac("00:1a:a9:ff:10:02"), Some(mac));
        assert_eq!(parse_mac("00-1A-A9-FF-10-02"), Some(mac));
        assert_eq!(parse_mac("00:1a:a9:ff:10"), None);
        assert_eq!(parse_mac("00:1a:a9:ff:10:02:03"), None);
        assert_eq!(parse_mac("0:1a:a9:ff:10:02"), None);
    }
}
