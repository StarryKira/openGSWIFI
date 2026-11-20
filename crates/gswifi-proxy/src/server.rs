//! Linux side of the transparent proxy: listeners, original destination
//! lookup and the per-connection relay.
//!
//! One thread per connection, each polling its two sockets. Both sockets are
//! non-blocking; at most [`MAX_PENDING`] bytes are buffered per direction, so
//! a slow reader slows its writer down instead of growing memory. A FIN is
//! passed on as a FIN (half-close) and a reset as a reset.

use std::io::{self, ErrorKind, Read, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::exit;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};

use super::http::Rewriter;
use super::ProxyOptions;

/// getsockopt(SOL_IP, SO_ORIGINAL_DST) and (SOL_IPV6, IP6T_SO_ORIGINAL_DST).
const SO_ORIGINAL_DST: libc::c_int = 80;
const READ_SIZE: usize = 16 * 1024;
const MAX_PENDING: usize = 64 * 1024;
/// How long the first bytes of a connection may be held back to tell whether
/// it is HTTP.
const DETECT_WAIT: Duration = Duration::from_millis(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STACK_SIZE: usize = 128 * 1024;
const STATS_INTERVAL: Duration = Duration::from_secs(5);

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static REWRITTEN: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);

struct Shared {
    ua: String,
    strip: Vec<String>,
    idle: Duration,
    max_conns: usize,
}

pub fn run(opts: ProxyOptions) {
    let v4 = match listen(SocketAddr::from((Ipv4Addr::UNSPECIFIED, opts.port))) {
        Ok(l) => l,
        Err(e) => {
            error!("透明代理无法监听端口 {}: {}", opts.port, e);
            exit(1);
        }
    };
    let v6 = match listen(SocketAddr::from((Ipv6Addr::UNSPECIFIED, opts.port))) {
        Ok(l) => Some(l),
        Err(e) => {
            warn!("透明代理不处理 IPv6（无法监听 [::]:{}: {}）", opts.port, e);
            None
        }
    };

    let shared = Arc::new(Shared {
        ua: opts.ua,
        strip: opts.strip_headers,
        idle: Duration::from_secs(opts.idle_timeout.max(10)),
        max_conns: opts.max_conns.max(1),
    });

    if shared.ua.is_empty() {
        info!("透明代理已启动，端口 {}，不改写 User-Agent", opts.port);
    } else {
        info!("透明代理已启动，端口 {}，User-Agent 统一为: {}", opts.port, shared.ua);
    }
    if !shared.strip.is_empty() {
        info!("删除请求头: {}", shared.strip.join(", "));
    }

    if let Some(path) = opts.stats {
        thread::spawn(move || stats_loop(&path));
    }
    if let Some(cmd) = opts.ready_cmd {
        let pid = std::process::id().to_string();
        thread::spawn(move || match std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&cmd)
            .env("GSWIFI_PROXY_PID", pid)
            .status()
        {
            Ok(st) if st.success() => {}
            Ok(st) => warn!("启动后命令 `{}` 退出码 {:?}", cmd, st.code()),
            Err(e) => warn!("无法执行启动后命令 `{}`: {}", cmd, e),
        });
    }

    if let Some(v6) = v6 {
        let shared = shared.clone();
        thread::spawn(move || accept_loop(v6, true, shared));
    }
    accept_loop(v4, false, shared);
}

/// A listening socket; IPv6 ones are IPv6-only, so that both can share the port.
fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let v6 = addr.is_ipv6();
    let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Owns the descriptor from here on, closing it on error.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };

    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    if v6 {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
    }

    let rc = unsafe {
        match addr {
            SocketAddr::V4(a) => {
                let mut sa: libc::sockaddr_in = mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_port = a.port().to_be();
                sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                libc::bind(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of_val(&sa) as libc::socklen_t)
            }
            SocketAddr::V6(a) => {
                let mut sa: libc::sockaddr_in6 = mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_port = a.port().to_be();
                sa.sin6_addr.s6_addr = a.ip().octets();
                libc::bind(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of_val(&sa) as libc::socklen_t)
            }
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(fd, 1024) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(listener)
}

fn setsockopt_int(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void, mem::size_of_val(&value) as libc::socklen_t)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Closes the connection with a reset instead of a FIN.
fn reset(s: TcpStream) {
    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
    unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            mem::size_of_val(&linger) as libc::socklen_t,
        );
    }
}

/// Where the client meant to connect before nftables redirected it here.
fn original_dst(s: &TcpStream, v6: bool) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();
    unsafe {
        if v6 {
            let mut sa: libc::sockaddr_in6 = mem::zeroed();
            let mut len = mem::size_of_val(&sa) as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IPV6, SO_ORIGINAL_DST, &mut sa as *mut _ as *mut libc::c_void, &mut len) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(sa.sin6_addr.s6_addr), u16::from_be(sa.sin6_port), 0, 0)))
        } else {
            let mut sa: libc::sockaddr_in = mem::zeroed();
            let mut len = mem::size_of_val(&sa) as libc::socklen_t;
            if libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, &mut sa as *mut _ as *mut libc::c_void, &mut len) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port))))
        }
    }
}

/// Decrements the active connection count when a connection thread ends.
struct ActiveGuard;

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

fn accept_loop(listener: TcpListener, v6: bool, shared: Arc<Shared>) {
    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(e) => {
                // Out of descriptors or memory: back off instead of spinning.
                warn!("透明代理接受连接失败: {}", e);
                thread::sleep(Duration::from_millis(200));
                continue;
            }
        };

        if ACTIVE.load(Ordering::Relaxed) >= shared.max_conns {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            reset(client);
            continue;
        }
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        TOTAL.fetch_add(1, Ordering::Relaxed);
        let guard = ActiveGuard;

        let shared = shared.clone();
        let spawned = thread::Builder::new().stack_size(STACK_SIZE).spawn(move || {
            let _guard = guard;
            handle(client, v6, &shared);
        });
        if let Err(e) = spawned {
            // The closure, with the connection and the guard, is dropped.
            warn!("透明代理无法创建线程: {}", e);
        }
    }
}

fn handle(client: TcpStream, v6: bool, shared: &Shared) {
    let dst = match original_dst(&client, v6) {
        Ok(d) => d,
        Err(e) => {
            debug!("取不到原目的地址: {}", e);
            REFUSED.fetch_add(1, Ordering::Relaxed);
            reset(client);
            return;
        }
    };
    // A connection made to the proxy port itself was not redirected; relaying
    // it would connect the proxy to itself.
    if client.local_addr().map_or(true, |l| l == dst) {
        REFUSED.fetch_add(1, Ordering::Relaxed);
        reset(client);
        return;
    }

    let server = match TcpStream::connect_timeout(&dst, CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            debug!("连接 {} 失败: {}", dst, e);
            FAILED.fetch_add(1, Ordering::Relaxed);
            // The client already has an established connection; a reset is
            // the closest thing to the refusal or timeout it would have seen.
            reset(client);
            return;
        }
    };

    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    if client.set_nonblocking(true).is_err() || server.set_nonblocking(true).is_err() {
        reset(client);
        reset(server);
        return;
    }

    let mut rw = Rewriter::new(&shared.ua, &shared.strip);
    if let Err(e) = relay(&client, &server, &mut rw, shared.idle) {
        debug!("{} 连接中断: {}", dst, e);
        reset(client);
        reset(server);
    }
}

/// One direction of a connection.
#[derive(Default)]
struct Half {
    /// Bytes read but not yet written to the other side.
    buf: Vec<u8>,
    /// The reading side has seen end of stream.
    eof: bool,
    /// The end of stream has been passed on to the writing side.
    shut: bool,
}

impl Half {
    fn wants_read(&self) -> bool {
        !self.eof && self.buf.len() < MAX_PENDING
    }

    /// Writes as much of the buffer as the socket takes.
    fn flush(&mut self, mut w: &TcpStream) -> io::Result<()> {
        while !self.buf.is_empty() {
            match w.write(&self.buf) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.buf.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if self.buf.is_empty() && self.buf.capacity() > 2 * MAX_PENDING {
            self.buf = Vec::new();
        }
        Ok(())
    }

    /// Passes a seen end of stream on once everything before it is written.
    fn pass_eof(&mut self, w: &TcpStream) {
        if self.eof && self.buf.is_empty() && !self.shut {
            let _ = w.shutdown(Shutdown::Write);
            self.shut = true;
        }
    }
}

/// Reads once from `r`. Ok(None): nothing to read right now.
fn read_some(mut r: &TcpStream, tmp: &mut [u8]) -> io::Result<Option<usize>> {
    match r.read(tmp) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => Ok(None),
        Err(e) => Err(e),
    }
}

fn relay(client: &TcpStream, server: &TcpStream, rw: &mut Rewriter, idle: Duration) -> io::Result<()> {
    let mut up = Half::default(); // client -> server, through the rewriter
    let mut down = Half::default(); // server -> client, unchanged
    let mut tmp = vec![0u8; READ_SIZE];
    let mut last = Instant::now();
    let mut detect_since: Option<Instant> = None;

    loop {
        up.flush(server)?;
        down.flush(client)?;
        up.pass_eof(server);
        down.pass_eof(client);
        if up.shut && down.shut {
            return Ok(());
        }

        let mut ce: libc::c_short = 0;
        let mut se: libc::c_short = 0;
        if up.wants_read() {
            ce |= libc::POLLIN;
        }
        if !down.buf.is_empty() {
            ce |= libc::POLLOUT;
        }
        if down.wants_read() {
            se |= libc::POLLIN;
        }
        if !up.buf.is_empty() {
            se |= libc::POLLOUT;
        }

        let now = Instant::now();
        let mut wait = idle.saturating_sub(now.duration_since(last));
        if rw.detecting() {
            let since = *detect_since.get_or_insert(now);
            if now.duration_since(since) >= DETECT_WAIT {
                // The client sent a few bytes that could start an HTTP
                // request and stopped: not HTTP after all.
                rw.give_up(&mut up.buf);
                detect_since = None;
                continue;
            }
            wait = wait.min(DETECT_WAIT - now.duration_since(since));
        } else {
            detect_since = None;
        }

        // A descriptor with nothing to wait for is left out: poll would
        // otherwise keep reporting its hang-up and spin.
        let mut fds = [
            libc::pollfd { fd: if ce != 0 { client.as_raw_fd() } else { -1 }, events: ce, revents: 0 },
            libc::pollfd { fd: if se != 0 { server.as_raw_fd() } else { -1 }, events: se, revents: 0 },
        ];
        let ms = wait.as_millis().min(i32::MAX as u128) as libc::c_int;
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            if last.elapsed() >= idle {
                debug!("连接空闲超时");
                return Ok(());
            }
            continue;
        }
        last = Instant::now();

        let ready = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
        if fds[0].revents & ready != 0 && !up.eof {
            match read_some(client, &mut tmp)? {
                Some(0) => {
                    up.eof = true;
                    rw.give_up(&mut up.buf);
                }
                Some(n) => {
                    let (r0, w0) = (rw.requests, rw.rewritten);
                    rw.feed(&tmp[..n], &mut up.buf);
                    REQUESTS.fetch_add(rw.requests - r0, Ordering::Relaxed);
                    REWRITTEN.fetch_add(rw.rewritten - w0, Ordering::Relaxed);
                }
                None => {}
            }
        }
        if fds[1].revents & ready != 0 && !down.eof {
            match read_some(server, &mut tmp)? {
                Some(0) => down.eof = true,
                Some(n) => down.buf.extend_from_slice(&tmp[..n]),
                None => {}
            }
        }
        // An error on a socket that is only waited on for writing shows up
        // in the next write.
    }
}

fn stats_loop(path: &str) {
    let tmp = format!("{}.tmp", path);
    let pid = std::process::id();
    loop {
        let text = format!(
            "{{\"pid\":{},\"active\":{},\"total\":{},\"requests\":{},\"rewritten\":{},\"failed\":{},\"refused\":{}}}\n",
            pid,
            ACTIVE.load(Ordering::Relaxed),
            TOTAL.load(Ordering::Relaxed),
            REQUESTS.load(Ordering::Relaxed),
            REWRITTEN.load(Ordering::Relaxed),
            FAILED.load(Ordering::Relaxed),
            REFUSED.load(Ordering::Relaxed),
        );
        if std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, path)).is_err() {
            // The directory may not exist (yet); try again next time.
            let _ = std::fs::remove_file(&tmp);
        }
        thread::sleep(STATS_INTERVAL);
    }
}
