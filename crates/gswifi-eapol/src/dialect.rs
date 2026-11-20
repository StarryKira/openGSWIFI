use std::time::Instant;

use gswifi_core::{Action, Credentials, DriverInfo, NetInfo};

use crate::frame::trailer_message;

/// Where the supplicant is in the current round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Sending EAPOL-Start.
    Start,
    /// Answered an Identity request, waiting for the challenge.
    Identity,
    /// Answered the challenge, waiting for Success.
    Md5,
    /// Authenticated, sending keepalives.
    Online,
    /// Waiting before starting over.
    Waiting,
}

/// Session facts a dialect needs to build its frames.
pub struct Ctx<'a> {
    pub mac: [u8; 6],
    pub net: &'a NetInfo,
    pub credentials: &'a Credentials,
    pub stage: Stage,
    /// Internal DHCP mode 0..=6 as in MentoHUST: 1..=3 are the configured
    /// modes, 4..=6 mean the DHCP of mode 1..=3 is already done (doc 21.4).
    pub dhcp_mode: u8,
    /// Source MAC of the last request, once a server answered.
    pub server: Option<[u8; 6]>,
}

/// How the supplicant treats an EAP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// Answer with [`Dialect::identity`].
    Identity,
    /// `data` is `size | challenge`; answer with [`Dialect::challenge`].
    Challenge,
    /// Show `data` as a server message.
    Notification,
    /// Answer with [`Dialect::answer`] and stay in the current stage (an
    /// online status query that is not a re-authentication, e.g. iNode's
    /// online Identity, doc 22.4).
    Answer,
    /// Log and ignore.
    Unsupported,
}

/// The vendor specific part of an 802.1X client.
///
/// Every method returns complete Ethernet frames; the supplicant decides
/// when they are sent and repeated.
pub trait Dialect: Send {
    fn info(&self) -> &'static DriverInfo;

    /// EAPOL-Start of the current round; `attempt` counts the Starts already
    /// sent in this round (destination rotation).
    fn start(&mut self, ctx: &Ctx, attempt: u32) -> Vec<u8>;

    /// Decides how to answer a request. Called for every request before
    /// the answer is built, so a dialect can also detect the server type
    /// here.
    fn classify(&mut self, ctx: &Ctx, src: &[u8; 6], kind: u8, data: &[u8]) -> RequestKind;

    /// Response to an Identity request.
    fn identity(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, data: &[u8]) -> Vec<u8>;

    /// Response to an MD5 challenge. `frame` is the whole request (vendor
    /// attributes may follow the challenge).
    fn challenge(&mut self, ctx: &Ctx, src: &[u8; 6], id: u8, seed: &[u8], frame: &[u8]) -> Vec<u8>;

    /// Response to a request classified as [`RequestKind::Answer`]; the
    /// session stage and timers do not change. `None` sends nothing.
    fn answer(&mut self, _ctx: &Ctx, _src: &[u8; 6], _id: u8, _kind: u8, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// EAP-Success arrived. Returns the keepalive interval the server asked
    /// for, 0 when it did not say.
    fn success(&mut self, ctx: &Ctx, frame: &[u8]) -> u32;

    /// Server message of a Failure frame.
    fn failure_message(&self, frame: &[u8]) -> Option<Vec<u8>> {
        trailer_message(frame).map(<[u8]>::to_vec)
    }

    /// Keepalive frame, sent every interval while online; `None` sends none.
    fn keepalive(&mut self, ctx: &Ctx) -> Option<Vec<u8>>;

    /// EAPOL-Logoff; `None` when the dialect cannot log off.
    fn logoff(&mut self, ctx: &Ctx) -> Option<Vec<u8>>;

    /// UDP sockets the dialect needs besides the 802.1X link.
    fn udp_ports(&self) -> Vec<u16> {
        Vec::new()
    }

    /// IP TTL of those sockets (see [`gswifi_core::Requirements::udp_ttl`]).
    fn udp_ttl(&self) -> Option<u32> {
        None
    }

    /// The session just went online (after any post-authentication DHCP).
    fn on_online(&mut self, _ctx: &Ctx, _now: Instant) -> Vec<Action> {
        Vec::new()
    }

    /// Extra timer while online (vendor UDP heartbeats).
    fn deadline(&self) -> Option<Instant> {
        None
    }

    /// [`Dialect::deadline`] passed while online.
    fn on_timer(&mut self, _ctx: &Ctx, _now: Instant) -> Vec<Action> {
        Vec::new()
    }

    /// The session left the online state or a new round begins: drop what
    /// belongs to the previous login.
    fn on_offline(&mut self) {}
}
