use thiserror::Error;

/// Virtual network device creation, I/O, and validation errors.
#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("TUN/TAP interfaces are not supported on this platform")]
    UnsupportedPlatform,
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
