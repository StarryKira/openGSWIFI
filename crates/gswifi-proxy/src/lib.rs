//! Transparent TCP proxy for the OpenWrt traffic protection, from mentorust
//! (`gswifi proxy`). nftables redirects LAN TCP connections to it; it
//! connects to the original destination from the router itself, so upstream
//! sees the router's TCP stack instead of each device's, and it unifies the
//! User-Agent of plain HTTP requests on the way (see [`http`]).

pub mod http;

#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
pub use server::run;

/// Settings of `gswifi proxy`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct ProxyOptions {
    pub port: u16,
    pub ua: String,
    pub strip_headers: Vec<String>,
    pub max_conns: usize,
    pub idle_timeout: u64,
    pub stats: Option<String>,
    pub ready_cmd: Option<String>,
}
