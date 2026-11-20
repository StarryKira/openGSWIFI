use std::fmt;
use std::net::SocketAddrV4;
use std::time::Instant;

use crate::net::NetInfo;
use crate::support::DriverInfo;

/// What the runtime must open before [`Driver::start`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Requirements {
    /// Capture and send raw Ethernet frames of this EtherType on the
    /// interface (0x888e for 802.1X).
    pub ethertype: Option<u16>,
    /// Local UDP ports to bind on the interface address. Port 0 is one
    /// shared ephemeral socket. Datagrams for a port that is not listed
    /// here are sent from a socket the runtime binds on demand.
    pub udp_ports: Vec<u16>,
    /// The driver cannot start before the interface has an IPv4 address.
    pub needs_ipv4: bool,
    /// IP TTL of the UDP sockets; `None` keeps the system default. Ruijie's
    /// Windows client sends its UDP heartbeat with 128 (doc 20.5).
    pub udp_ttl: Option<u32>,
}

/// A UDP datagram received on one of the driver's sockets.
#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    pub local_port: u16,
    pub from: SocketAddrV4,
    pub payload: &'a [u8],
}

/// Plain HTTP/1.1 request for web Portals. The runtime does not follow
/// redirects: Portal logins read `Location` themselves (WISPr).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// `http://host[:port]/path?query`. HTTPS is not supported.
    pub url: String,
    /// Extra headers; `Host`, `Connection` and `Content-Length` are added.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Response to an [`HttpRequest`]; chunked bodies are already decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// First header of that name, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Side effects a driver asks the runtime to perform, in order.
#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    /// Send one complete Ethernet frame on the interface.
    SendFrame(Vec<u8>),
    /// Send a UDP datagram from the given local port (0: ephemeral).
    SendUdp { local_port: u16, to: SocketAddrV4, payload: Vec<u8> },
    /// Perform an HTTP request and report it with [`Driver::on_http`]
    /// under the same `id`.
    Http { id: u32, request: HttpRequest },
    /// Obtain/renew the interface address (DHCP script or netifd), then
    /// report the result with [`Driver::on_net_change`].
    RequestDhcp,
    /// The session is over; the runtime exits with [`Stop::exit_code`].
    Stop(Stop),
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::SendFrame(frame) => write!(f, "SendFrame({} bytes)", frame.len()),
            Action::SendUdp { local_port, to, payload } => {
                write!(f, "SendUdp(:{} -> {}, {} bytes)", local_port, to, payload.len())
            }
            Action::Http { id, request } => write!(f, "Http(#{} {} {})", id, request.method, request.url),
            Action::RequestDhcp => f.write_str("RequestDhcp"),
            Action::Stop(stop) => write!(f, "Stop({:?})", stop),
        }
    }
}

/// Which step the server refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectStage {
    /// Username or the vendor extension (Identity stage).
    Identity,
    /// Password, MAC binding or account state (challenge stage).
    Password,
    /// Anything else the protocol reports as a refusal.
    Other,
}

/// Why a session ended. Rejections must not be retried automatically: a
/// wrong password retried forever gets accounts locked (doc 09.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Logged off on request.
    Finished,
    /// No authentication server answered the discovery at all.
    ServerNotFound,
    /// The server explicitly refused the credentials or the client.
    Rejected { stage: RejectStage, message: Option<String> },
    /// No answer after the configured number of rounds.
    GaveUp { rounds: u32 },
    /// Configuration or material error the driver cannot recover from.
    Fatal(String),
}

impl Stop {
    /// Process exit codes, compatible with mentorust's supervisor.
    pub fn exit_code(&self) -> i32 {
        match self {
            Stop::Finished => 0,
            Stop::Fatal(_) => 1,
            Stop::Rejected { stage: RejectStage::Identity, .. } => 2,
            Stop::Rejected { .. } => 3,
            Stop::GaveUp { .. } => 4,
            Stop::ServerNotFound => 255,
        }
    }
}

/// Public state of a session (doc 09.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthState {
    /// Not started.
    Idle,
    /// Waiting for an address before or after authenticating.
    WaitingIp,
    /// Looking for the authentication server.
    Discovering,
    /// Exchanging credentials.
    Authenticating,
    /// Authenticated and keeping the session alive.
    Online,
    /// Waiting before the next attempt.
    Backoff,
    /// Ended (see the [`Stop`] that was returned).
    Stopped,
}

/// One authentication session on one interface.
///
/// Every method returns the actions to execute, in order. `now` is a
/// monotonic timestamp from the runtime; drivers must not read the clock.
pub trait Driver: Send {
    /// Static description of the protocol.
    fn info(&self) -> &'static DriverInfo;

    /// What the runtime must open for this session.
    fn requirements(&self) -> Requirements;

    /// Begins the first round.
    fn start(&mut self, now: Instant) -> Vec<Action>;

    /// A raw frame of [`Requirements::ethertype`] arrived.
    fn on_frame(&mut self, _frame: &[u8], _now: Instant) -> Vec<Action> {
        Vec::new()
    }

    /// A datagram arrived on one of the driver's UDP sockets.
    fn on_datagram(&mut self, _datagram: Datagram<'_>, _now: Instant) -> Vec<Action> {
        Vec::new()
    }

    /// The [`Action::Http`] with this `id` finished (or failed to connect).
    fn on_http(&mut self, _id: u32, _response: Result<HttpResponse, String>, _now: Instant) -> Vec<Action> {
        Vec::new()
    }

    /// Called once `now` reaches [`Driver::next_deadline`].
    fn on_timer(&mut self, now: Instant) -> Vec<Action>;

    /// The interface addresses changed, or a [`Action::RequestDhcp`] finished.
    fn on_net_change(&mut self, net: NetInfo, now: Instant) -> Vec<Action>;

    /// When [`Driver::on_timer`] must be called next.
    fn next_deadline(&self) -> Option<Instant>;

    /// Stop was requested (SIGTERM): log off if possible. The runtime exits
    /// after executing the returned actions.
    fn logoff(&mut self, now: Instant) -> Vec<Action>;

    /// Current public state.
    fn state(&self) -> AuthState;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_mentorust() {
        assert_eq!(Stop::Finished.exit_code(), 0);
        assert_eq!(Stop::Rejected { stage: RejectStage::Identity, message: None }.exit_code(), 2);
        assert_eq!(Stop::Rejected { stage: RejectStage::Password, message: None }.exit_code(), 3);
        assert_eq!(Stop::GaveUp { rounds: 3 }.exit_code(), 4);
        assert_eq!(Stop::ServerNotFound.exit_code(), 255);
    }
}
