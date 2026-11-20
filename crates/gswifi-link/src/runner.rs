//! Event loop: feeds a [`Driver`] with frames, datagrams, timer expiries
//! and address changes, and executes the actions it returns.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use gswifi_core::text::hex_head;
use gswifi_core::{mac_str, Action, AuthState, Datagram, Driver, NetInfo, Stop};
use log::{debug, error, info, warn};
use pcap::{Active, Capture, Device};

use crate::dhcp::renew_address;
use crate::iface::read_net_info;

/// Set by SIGTERM/SIGINT: log off and leave.
pub static STOP: AtomicBool = AtomicBool::new(false);

/// Longest single wait, so a stop request is noticed quickly.
const MAX_WAIT: Duration = Duration::from_millis(500);
/// How often addresses are re-read to notice DHCP renewals.
const NET_POLL: Duration = Duration::from_secs(10);

/// SIGTERM/SIGINT set [`STOP`].
pub fn install_signal_handlers() {
    #[cfg(unix)]
    {
        extern "C" fn on_signal(_: libc::c_int) {
            STOP.store(true, Ordering::SeqCst);
        }
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: the handler only stores to an atomic.
        unsafe {
            libc::signal(libc::SIGTERM, handler);
            libc::signal(libc::SIGINT, handler);
        }
    }
}

/// Settings of the runtime, not of the protocol.
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    /// Interface name.
    pub interface: String,
    /// MAC of the interface (frame filter).
    pub mac: [u8; 6],
    /// Command that renews the address for [`Action::RequestDhcp`].
    pub dhcp_script: Option<String>,
    /// Log every frame and datagram (first 64 bytes).
    pub trace: bool,
}

struct Link<'a> {
    opts: &'a RunOptions,
    ttl: Option<u32>,
    cap: Option<Capture<Active>>,
    /// UDP sockets by local port; 0 is the shared ephemeral one.
    udp: BTreeMap<u16, UdpSocket>,
    net: NetInfo,
}

/// Runs `driver` until it stops or [`STOP`] is set; returns why it ended.
pub fn run(driver: &mut dyn Driver, opts: &RunOptions) -> Result<Stop, String> {
    let req = driver.requirements();
    let info = driver.info();
    info!("认证方式: {}（{}，{}）", info.title, info.name, info.support);
    if info.support.is_experimental() {
        warn!("{} 的支持等级为 {}，尚未在真实校园网验证", info.name, info.support);
    }

    let mut link = Link { opts, ttl: req.udp_ttl, cap: None, udp: BTreeMap::new(), net: read_net_info(&opts.interface) };
    if req.needs_ipv4 && !link.net.has_ipv4() {
        info!("等待网卡 {} 获取 IPv4 地址...", opts.interface);
        crate::status::state(AuthState::WaitingIp, &link.net);
        while !link.net.has_ipv4() {
            if STOP.load(Ordering::SeqCst) {
                return Ok(Stop::Finished);
            }
            std::thread::sleep(Duration::from_secs(1));
            link.net = read_net_info(&opts.interface);
        }
        // The driver was built with the old addresses.
        let actions = driver.on_net_change(link.net, Instant::now());
        if let Some(stop) = link.execute(driver, actions)? {
            return Ok(stop);
        }
    }
    if let Some(ethertype) = req.ethertype {
        link.cap = Some(open_capture(&opts.interface, &opts.mac, ethertype)?);
    }
    for &port in &req.udp_ports {
        link.socket(port)?;
    }

    let actions = driver.start(Instant::now());
    if let Some(stop) = link.execute(driver, actions)? {
        return Ok(stop);
    }
    let mut state = driver.state();
    crate::status::state(state, &link.net);
    let mut next_net_poll = Instant::now() + NET_POLL;
    let mut buf = vec![0u8; 4096];
    loop {
        if STOP.load(Ordering::SeqCst) {
            let actions = driver.logoff(Instant::now());
            let stop = link.execute(driver, actions)?;
            info!("已下线，程序退出");
            return Ok(stop.unwrap_or(Stop::Finished));
        }

        // Frames.
        while let Some(frame) = link.next_frame()? {
            if opts.trace {
                info!("收到报文({:?}): {}", driver.state(), hex_head(&frame, 64));
            }
            let actions = driver.on_frame(&frame, Instant::now());
            if let Some(stop) = link.execute(driver, actions)? {
                return Ok(stop);
            }
        }

        // Datagrams.
        let ports: Vec<u16> = link.udp.keys().copied().collect();
        for port in ports {
            #[allow(clippy::while_let_loop)]
            loop {
                let received = match link.udp.get(&port) {
                    Some(socket) => socket.recv_from(&mut buf),
                    None => break,
                };
                let (n, from) = match received {
                    Ok((n, SocketAddr::V4(from))) => (n, from),
                    Ok(_) => continue,
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                    // ICMP port unreachable surfaces as ConnectionRefused on some systems.
                    Err(e) if e.kind() == ErrorKind::ConnectionRefused => break,
                    Err(e) => {
                        warn!("UDP 端口 {} 接收失败: {}", port, e);
                        break;
                    }
                };
                let local_port = link.udp[&port].local_addr().map(|a| a.port()).unwrap_or(port);
                if opts.trace {
                    info!("收到 UDP({} -> :{}): {}", from, local_port, hex_head(&buf[..n], 64));
                }
                let datagram = Datagram { local_port, from, payload: &buf[..n] };
                let actions = driver.on_datagram(datagram, Instant::now());
                if let Some(stop) = link.execute(driver, actions)? {
                    return Ok(stop);
                }
            }
        }

        // Timers.
        let now = Instant::now();
        if driver.next_deadline().is_some_and(|d| now >= d) {
            let actions = driver.on_timer(now);
            if let Some(stop) = link.execute(driver, actions)? {
                return Ok(stop);
            }
        }

        // Address changes (DHCP renewals behind our back).
        if now >= next_net_poll {
            next_net_poll = now + NET_POLL;
            let net = read_net_info(&opts.interface);
            if net != link.net {
                if net.ip != link.net.ip {
                    info!("网卡 {} 的 IPv4 地址变为 {}", opts.interface, net.ipv4());
                }
                link.net = net;
                let actions = driver.on_net_change(net, now);
                if let Some(stop) = link.execute(driver, actions)? {
                    return Ok(stop);
                }
                crate::status::state(driver.state(), &link.net);
            }
        }

        if driver.state() != state {
            state = driver.state();
            crate::status::state(state, &link.net);
            debug!("状态: {:?}", state);
            if state == AuthState::Online {
                info!("在线");
            }
        }

        let wait = driver
            .next_deadline()
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(MAX_WAIT)
            .min(MAX_WAIT)
            .min(next_net_poll.saturating_duration_since(Instant::now()));
        link.wait(wait);
    }
}

impl Link<'_> {
    /// Executes actions in order; returns the stop if one was among them.
    fn execute(&mut self, driver: &mut dyn Driver, actions: Vec<Action>) -> Result<Option<Stop>, String> {
        let mut queue = std::collections::VecDeque::from(actions);
        while let Some(action) = queue.pop_front() {
            match action {
                Action::SendFrame(frame) => {
                    if self.opts.trace {
                        info!("发送报文({:?}): {}", driver.state(), hex_head(&frame, 64));
                    }
                    match self.cap.as_mut() {
                        Some(cap) => {
                            if let Err(e) = cap.sendpacket(frame) {
                                error!("发送数据包失败: {:?}", e);
                            }
                        }
                        None => warn!("驱动没有申请网卡抓包，丢弃要发送的以太网帧"),
                    }
                }
                Action::SendUdp { local_port, to, payload } => {
                    if self.opts.trace {
                        info!("发送 UDP(:{} -> {}): {}", local_port, to, hex_head(&payload, 64));
                    }
                    match self.socket(local_port) {
                        Ok(socket) => {
                            if let Err(e) = socket.send_to(&payload, to) {
                                warn!("发送 UDP 到 {} 失败: {}", to, e);
                            }
                        }
                        Err(e) => warn!("{}", e),
                    }
                }
                Action::RequestDhcp => {
                    let net = renew_address(&self.opts.interface, self.opts.dhcp_script.as_deref(), &self.net, &STOP);
                    self.net = net;
                    // Whatever the driver does next runs before the rest.
                    let more = driver.on_net_change(net, Instant::now());
                    for (i, a) in more.into_iter().enumerate() {
                        queue.insert(i, a);
                    }
                }
                Action::Http { id, request } => {
                    if self.opts.trace {
                        info!("HTTP #{} {} {}", id, request.method, request.url);
                    }
                    let response = crate::http::fetch(&request);
                    if let Err(e) = &response {
                        debug!("HTTP #{} 失败: {}", id, e);
                    }
                    let more = driver.on_http(id, response, Instant::now());
                    for (i, a) in more.into_iter().enumerate() {
                        queue.insert(i, a);
                    }
                }
                Action::Stop(stop) => return Ok(Some(stop)),
            }
        }
        Ok(None)
    }

    /// Socket bound to `port` on all addresses (port 0: one shared
    /// ephemeral socket), bound to the interface where the OS allows it.
    fn socket(&mut self, port: u16) -> Result<&UdpSocket, String> {
        if !self.udp.contains_key(&port) {
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
                .map_err(|e| format!("无法绑定 UDP 端口 {}: {}", port, e))?;
            socket.set_nonblocking(true).map_err(|e| format!("UDP 端口 {}: {}", port, e))?;
            bind_to_device(&socket, &self.opts.interface);
            if let Some(ttl) = self.ttl {
                if let Err(e) = socket.set_ttl(ttl) {
                    debug!("无法设置 UDP TTL {}: {}", ttl, e);
                }
            }
            debug!("已绑定 UDP 端口 {}", socket.local_addr().map(|a| a.port()).unwrap_or(port));
            self.udp.insert(port, socket);
        }
        Ok(&self.udp[&port])
    }

    fn next_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some(cap) = self.cap.as_mut() else { return Ok(None) };
        match cap.next_packet() {
            Ok(p) => Ok(Some(p.data.to_vec())),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(format!("监听网卡数据包失败: {:?}", e)),
        }
    }

    /// Waits until a frame or datagram may be readable, or `max` passed.
    #[cfg(unix)]
    fn wait(&self, max: Duration) {
        use std::os::fd::AsRawFd;
        let mut fds: Vec<libc::pollfd> = Vec::new();
        if let Some(cap) = &self.cap {
            fds.push(libc::pollfd { fd: cap.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        for socket in self.udp.values() {
            fds.push(libc::pollfd { fd: socket.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        // SAFETY: fds is a valid array for its length; EINTR just ends the wait.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, max.as_millis() as libc::c_int) };
    }

    #[cfg(not(unix))]
    fn wait(&self, max: Duration) {
        std::thread::sleep(max.min(Duration::from_millis(20)));
    }
}

/// SO_BINDTODEVICE on Linux so datagrams leave through the authenticating
/// interface even with several WANs; best effort elsewhere.
#[cfg(target_os = "linux")]
fn bind_to_device(socket: &UdpSocket, interface: &str) {
    use std::os::fd::AsRawFd;
    let name = interface.as_bytes();
    // SAFETY: valid fd and buffer of the given length.
    let r = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    if r != 0 {
        debug!("SO_BINDTODEVICE {} 失败: {}", interface, std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_to_device(_socket: &UdpSocket, _interface: &str) {}

/// pcap handle for `ethertype` frames addressed to us, the 802.1X groups or
/// broadcast, not sent by us (mentorust `open_pcap`).
fn open_capture(interface: &str, mac: &[u8; 6], ethertype: u16) -> Result<Capture<Active>, String> {
    let devices = Device::list().map_err(|e| format!("无法列出网卡: {:?}", e))?;
    let device = devices
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| format!("libpcap 找不到网卡 {}", interface))?;
    let mut cap = Capture::from_device(device)
        .and_then(|c| {
            c.immediate_mode(true)
                .snaplen(2048)
                .promisc(false)
                .timeout(1000)
                // With only a few hundred bytes the Linux ring holds a single
                // frame and the second of two back-to-back frames is dropped.
                .buffer_size(128 * 1024)
                .open()
        })
        .and_then(|c| c.setnonblock())
        .map_err(|e| format!("无法打开网卡 {}: {:?}", interface, e))?;
    let mac = mac_str(mac);
    let rule = format!(
        "ether proto 0x{:04x} and (ether dst {} or ether dst 01:80:c2:00:00:03 or ether dst 01:d0:f8:00:00:03 or ether broadcast) and not ether src {}",
        ethertype, mac, mac
    );
    cap.filter(&rule, true).map_err(|e| format!("无法设置过滤规则: {:?}", e))?;
    Ok(cap)
}
