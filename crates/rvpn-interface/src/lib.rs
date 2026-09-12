//! Platform-neutral asynchronous Layer-3 (TUN) and Layer-2 (TAP) virtual-interface API.
//!
//! Linux creation needs access to `/dev/net/tun` and normally `CAP_NET_ADMIN`.

mod config;
mod error;
mod platform;

pub use config::{DEFAULT_MTU, DeviceMode, TunConfig};
pub use error::InterfaceError;
pub use platform::TunDevice;
