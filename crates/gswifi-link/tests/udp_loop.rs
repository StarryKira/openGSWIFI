//! Runs the real event loop against a UDP echo server on loopback: send,
//! receive, timer, stop — no pcap, no network access.

use std::net::{SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use gswifi_core::*;
use gswifi_link::{run, RunOptions};

static INFO: DriverInfo = DriverInfo {
    name: "loop",
    title: "loop",
    transport: Transport::Udp,
    support: SupportLevel::Documented,
    docs: &[],
};

/// Sends "ping", expects the echo, then waits one timer tick and stops.
struct Ping {
    server: SocketAddrV4,
    got: Option<Vec<u8>>,
    deadline: Option<Instant>,
}

impl Driver for Ping {
    fn info(&self) -> &'static DriverInfo {
        &INFO
    }
    fn requirements(&self) -> Requirements {
        Requirements { ethertype: None, udp_ports: vec![0], needs_ipv4: false, udp_ttl: Some(64) }
    }
    fn start(&mut self, _now: Instant) -> Vec<Action> {
        vec![Action::SendUdp { local_port: 0, to: self.server, payload: b"ping".to_vec() }]
    }
    fn on_datagram(&mut self, d: Datagram<'_>, now: Instant) -> Vec<Action> {
        assert_eq!(d.from, self.server);
        self.got = Some(d.payload.to_vec());
        self.deadline = Some(now + Duration::from_millis(50));
        Vec::new()
    }
    fn on_timer(&mut self, _now: Instant) -> Vec<Action> {
        vec![Action::Stop(Stop::Rejected { stage: RejectStage::Other, message: Some("done".into()) })]
    }
    fn on_net_change(&mut self, _net: NetInfo, _now: Instant) -> Vec<Action> {
        Vec::new()
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
    fn logoff(&mut self, _now: Instant) -> Vec<Action> {
        vec![Action::Stop(Stop::Finished)]
    }
    fn state(&self) -> AuthState {
        AuthState::Authenticating
    }
}

#[test]
fn udp_round_trip_and_timer() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = match server.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    let echo = thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        server.send_to(&buf[..n], from).unwrap();
    });
    let mut driver = Ping { server: addr, got: None, deadline: None };
    let opts = RunOptions { interface: if cfg!(target_os = "linux") { "lo".into() } else { "lo0".into() }, ..Default::default() };
    let stop = run(&mut driver, &opts).unwrap();
    echo.join().unwrap();
    assert_eq!(driver.got.as_deref(), Some(&b"ping"[..]));
    assert_eq!(stop, Stop::Rejected { stage: RejectStage::Other, message: Some("done".into()) });
}
