use crate::{DeviceMode, InterfaceError, TunConfig};
use bytes::Bytes;

pub struct VirtualInterface;

impl VirtualInterface {
    pub async fn create(_: TunConfig) -> Result<Self, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    pub fn from_raw_fd(
        _: std::os::fd::RawFd,
        _: String,
        _: u16,
        _: DeviceMode,
    ) -> Result<Self, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }

    pub fn name(&self) -> &str {
        ""
    }

    pub const fn mtu(&self) -> u16 {
        0
    }

    pub const fn mode(&self) -> DeviceMode {
        DeviceMode::Tun
    }

    pub async fn recv(&self) -> Result<Bytes, InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
    
    pub async fn send(&self, _: &[u8]) -> Result<(), InterfaceError> {
        Err(InterfaceError::UnsupportedPlatform)
    }
}
