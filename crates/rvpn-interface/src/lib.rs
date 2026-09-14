mod config;
mod error;
mod platform;

pub use config::{DEFAULT_MTU, DeviceMode, TunConfig};
pub use error::InterfaceError;
pub use platform::VirtualInterface;
