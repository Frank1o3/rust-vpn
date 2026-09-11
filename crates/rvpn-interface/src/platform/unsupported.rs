use crate::{InterfaceError, TunConfig};
use bytes::Bytes;

/// Placeholder for a future native platform implementation.
pub struct TunDevice;

impl TunDevice {
    /// Always reports that this platform has no implementation yet.
    pub async fn create(_: TunConfig) -> Result<Self, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
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
