use thiserror::Error;

use crate::DeviceMode;

#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("TUN/TAP interfaces are not supported on this platform")]
    UnsupportedPlatform,
    #[error("virtual device mode {0:?} is not supported on this platform")]
    UnsupportedMode(DeviceMode),
    #[error("invalid interface name")]
    InvalidInterfaceName,
    #[error("invalid MTU {0}; it must be at least 576")]
    InvalidMtu(u16),
    #[error("packet is empty or does not begin with an IPv4/IPv6 version nibble")]
    InvalidIpPacket,
    #[error("Ethernet frame is smaller than minimum header length (14 bytes)")]
    InvalidEthernetFrame,
    #[error("packet size {size} exceeds interface MTU {mtu}")]
    PacketTooLarge { size: usize, mtu: u16 },
    #[error("virtual device write was partial: {written} of {expected} bytes")]
    PartialWrite { written: usize, expected: usize },
    #[error("virtual device operation failed: {0}")]
    Io(#[from] std::io::Error),
}

impl InterfaceError {
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Io(_) | Self::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatality_classification() {
        assert!(InterfaceError::UnsupportedPlatform.is_fatal());
        assert!(InterfaceError::Io(std::io::Error::other("disk error")).is_fatal());

        assert!(!InterfaceError::UnsupportedMode(DeviceMode::Tun).is_fatal());
        assert!(!InterfaceError::InvalidInterfaceName.is_fatal());
        assert!(!InterfaceError::InvalidMtu(100).is_fatal());
        assert!(!InterfaceError::InvalidIpPacket.is_fatal());
        assert!(!InterfaceError::InvalidEthernetFrame.is_fatal());
        assert!(
            !InterfaceError::PacketTooLarge {
                size: 2000,
                mtu: 1500
            }
            .is_fatal()
        );
        assert!(
            !InterfaceError::PartialWrite {
                written: 10,
                expected: 20
            }
            .is_fatal()
        );
    }
}
