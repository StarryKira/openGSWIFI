//! Interface addresses (mentorust `net.rs`).

use std::fs;
use std::net::{IpAddr, Ipv4Addr};

use gswifi_core::{Env, NetInfo};
use log::info;
use pnet_datalink::NetworkInterface;

fn by_name(name: &str) -> Option<NetworkInterface> {
    pnet_datalink::interfaces().into_iter().find(|i| i.name == name)
}

/// Names of all interfaces, for error messages.
pub fn interface_names() -> Vec<String> {
    pnet_datalink::interfaces().into_iter().map(|i| i.name).collect()
}

/// Addresses of an interface. Gateway and DNS come from the routing table
/// and the resolver files; drivers apply their configured overrides.
pub fn read_net_info(name: &str) -> NetInfo {
    let mut net = NetInfo::default();
    if let Some(inet) = by_name(name) {
        // The last address of each family wins, as in mentorust.
        for ip in inet.ips {
            match ip.ip() {
                IpAddr::V4(v4) => {
                    net.ip = v4.octets();
                    if let IpAddr::V4(mask) = ip.mask() {
                        net.mask = mask.octets();
                    }
                }
                IpAddr::V6(v6) => net.ipv6 = v6.octets(),
            }
        }
    }
    net.gateway = default_gateway(name).map(|a| a.octets()).unwrap_or_default();
    net.dns = nameserver().map(|a| a.octets()).unwrap_or_default();
    net
}

/// MAC and addresses of `name`; an empty name picks the interface with a
/// `10.x.x.x` address (preferring `en*`/`eth*`), as mentorust did.
pub fn lookup(name: &str) -> Result<Env, String> {
    let all = pnet_datalink::interfaces();
    let inet = if name.is_empty() {
        info!("未指定网卡，寻找有 10.x.x.x 地址的网卡...");
        let candidates: Vec<_> = all
            .iter()
            .filter(|i| i.ips.iter().any(|ip| matches!(ip.ip(), IpAddr::V4(v4) if v4.octets()[0] == 10)))
            .collect();
        match candidates.as_slice() {
            [one] => (*one).clone(),
            [] => return Err(format!("没有找到 10.x.x.x 地址的网卡，请指定网卡。当前网卡: {}", interface_names().join(", "))),
            many => many
                .iter()
                .find(|i| i.name.starts_with("en") || i.name.starts_with("eth"))
                .map(|i| (*i).clone())
                .ok_or_else(|| format!("有多个 10.x.x.x 地址的网卡，请指定网卡。当前网卡: {}", interface_names().join(", ")))?,
        }
    } else {
        all.iter()
            .find(|i| i.name == name)
            .cloned()
            .ok_or_else(|| format!("未找到网卡 {}，请检查名称。当前网卡: {}", name, interface_names().join(", ")))?
    };
    let mac = inet.mac.map(|m| m.octets()).filter(|m| *m != [0; 6]).ok_or_else(|| format!("网卡 {} 没有 MAC 地址", inet.name))?;
    Ok(Env { net: read_net_info(&inet.name), interface: inet.name, mac })
}

/// Blocks until the IPv4 address or the MAC of `name` differs from `since`
/// (DHCP gave a new address, the interface was rebuilt), checking every
/// two seconds. Returns `false` when `stop` was set first.
pub fn wait_for_change(name: &str, since: &Env, stop: &std::sync::atomic::AtomicBool) -> bool {
    use std::sync::atomic::Ordering;
    loop {
        for _ in 0..4 {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if let Ok(now) = lookup(name) {
            if now.mac != since.mac || (now.net.ip != since.net.ip && now.net.has_ipv4()) {
                return true;
            }
        }
    }
}

/// Default IPv4 gateway of `name` from /proc/net/route (Linux).
fn default_gateway(name: &str) -> Option<Ipv4Addr> {
    let table = fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&table, name)
}

fn parse_route_table(table: &str, name: &str) -> Option<Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[0] != name || f[1] != "00000000" {
            return None;
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        (gw != 0).then(|| Ipv4Addr::from(gw.to_le_bytes()))
    })
}

/// First upstream name server. On OpenWrt /etc/resolv.conf points at the
/// local dnsmasq; the upstream servers are in resolv.conf.auto.
fn nameserver() -> Option<Ipv4Addr> {
    const FILES: [&str; 3] = ["/tmp/resolv.conf.d/resolv.conf.auto", "/tmp/resolv.conf.auto", "/etc/resolv.conf"];
    FILES.iter().filter_map(|f| fs::read_to_string(f).ok()).find_map(|text| parse_resolv(&text))
}

fn parse_resolv(text: &str) -> Option<Ipv4Addr> {
    text.lines().find_map(|line| {
        let addr: Ipv4Addr = line.trim().strip_prefix("nameserver")?.trim().parse().ok()?;
        (!addr.is_loopback() && !addr.is_unspecified()).then_some(addr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\n\
                     wan\t0000A8C0\t00000000\t0001\n\
                     wan\t00000000\t0101A8C0\t0003\n";
        assert_eq!(parse_route_table(table, "wan"), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_route_table(table, "lan"), None);
    }

    #[test]
    fn resolv_skips_local() {
        let text = "# auto\nnameserver 127.0.0.1\nnameserver ::1\nnameserver 10.0.0.53\n";
        assert_eq!(parse_resolv(text), Some(Ipv4Addr::new(10, 0, 0, 53)));
    }
}
