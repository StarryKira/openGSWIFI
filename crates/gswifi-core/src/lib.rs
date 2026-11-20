//! Interface shared by every Open GSWIFI authentication driver.
//!
//! A driver is a pure state machine (research doc 09.3): it never opens a
//! socket, runs a command or reads the clock. The runtime (`gswifi-link`)
//! feeds it received frames/datagrams, timer expiries and address changes,
//! and executes the [`Action`]s it returns. That keeps every protocol crate
//! testable offline and lets the same driver run on any transport.

mod driver;
mod net;
mod secret;
mod support;
pub mod text;

pub use driver::{Action, AuthState, Datagram, Driver, HttpRequest, HttpResponse, RejectStage, Requirements, Stop};
pub use net::{mac_str, parse_mac, Env, NetInfo};
pub use secret::{Credentials, Secret};
pub use support::{DriverInfo, SupportLevel, Transport};
