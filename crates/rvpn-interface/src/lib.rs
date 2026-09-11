//! Platform-neutral asynchronous Layer-3 virtual-interface API.
//!
//! Linux creation needs access to `/dev/net/tun` and normally `CAP_NET_ADMIN`.
//! This crate only creates and uses a TUN device; addresses, routes, forwarding,
//! and NAT belong to a future networking layer.

mod config;
mod error;
mod platform;

pub use config::{DEFAULT_MTU, TunConfig};
pub use error::InterfaceError;
pub use platform::TunDevice;
