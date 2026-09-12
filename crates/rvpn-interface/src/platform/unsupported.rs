use crate::{DeviceMode, InterfaceError, TunConfig};
use bytes::Bytes;

/// Placeholder for a future native platform implementation.
pub struct TunDevice;

impl TunDevice {
    /// Always reports that this platform has no implementation yet.
    pub async fn create(_: TunConfig) -> Result<Self, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
    /// Interface name placeholder.
    pub fn name(&self) -> &str {
        ""
    }
    /// Interface MTU placeholder.
    pub const fn mtu(&self) -> u16 {
        0
    }
    /// Interface mode placeholder.
    pub const fn mode(&self) -> DeviceMode {
        DeviceMode::Tun
    }
    /// Always reports that this platform has no implementation yet.
    pub async fn recv(&self) -> Result<Bytes, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
    /// Always reports that this platform has no implementation yet.
    pub async fn send(&self, _: &[u8]) -> Result<(), InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
}
