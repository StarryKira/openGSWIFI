//! Address renewal for [`Action::RequestDhcp`](gswifi_core::Action)
//! (mentorust `run_dhcp`, doc 21.4).

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use gswifi_core::NetInfo;
use log::{info, warn};

use crate::iface::read_net_info;

/// How long to wait for an IPv4 address after running the script.
const WAIT_SECS: u64 = 30;

/// Runs the DHCP script (`sh -c`), if any, and waits until the interface
/// has an IPv4 address. Without a script someone else (netifd, dhclient)
/// renews; give it a few seconds.
pub fn renew_address(interface: &str, script: Option<&str>, old: &NetInfo, stop: &AtomicBool) -> NetInfo {
    if let Some(script) = script {
        match Command::new("sh").arg("-c").arg(script).status() {
            Ok(status) if status.success() => {}
            Ok(status) => warn!("DHCP 脚本退出码 {:?}", status.code()),
            Err(e) => warn!("无法执行 DHCP 脚本: {}", e),
        }
    }
    let mut net = read_net_info(interface);
    for second in 0..=WAIT_SECS {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        net = read_net_info(interface);
        let settled = script.is_some() || second >= 3 || net.ip != old.ip;
        if net.has_ipv4() && settled {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if net.has_ipv4() {
        info!(
            "网卡({})IPv4地址: {}，掩码 {}，网关 {}，DNS {}",
            interface,
            net.ipv4(),
            std::net::Ipv4Addr::from(net.mask),
            std::net::Ipv4Addr::from(net.gateway),
            std::net::Ipv4Addr::from(net.dns)
        );
    } else {
        warn!("网卡 {} 仍没有 IPv4 地址，继续认证", interface);
    }
    net
}
