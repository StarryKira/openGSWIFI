//! Runtime of Open GSWIFI: the only crate that touches the operating
//! system. It looks up the interface, opens what a driver's
//! [`Requirements`](gswifi_core::Requirements) ask for (a pcap handle for
//! raw 802.1X frames, UDP sockets), and runs the event loop that feeds the
//! driver and executes its actions.

mod dhcp;
pub mod http;
pub mod json;
pub mod protect;
pub mod iface;
mod runner;
pub mod status;

pub use dhcp::renew_address;
pub use runner::{install_signal_handlers, run, RunOptions, STOP};
