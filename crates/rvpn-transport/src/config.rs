use crate::TransportError;
use std::net::SocketAddr;

/// Largest UDP payload accepted by this transport. This is a UDP limit, not an
/// MTU recommendation; callers should select a smaller operational packet size.
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;

/// Socket and buffer limits for a UDP transport endpoint.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Address on which to bind the UDP socket.
    pub local_address: SocketAddr,
    /// Optional default peer. When set, [`crate::UdpTransport::send`] can be used.
    pub remote_address: Option<SocketAddr>,
    /// Maximum accepted or transmitted datagram payload size.
    pub max_datagram_size: usize,
}

impl TransportConfig {
    /// Creates a configuration with a conservative 1200-byte payload limit.
    pub fn new(local_address: SocketAddr) -> Self {
        Self {
            local_address,
            remote_address: None,
            max_datagram_size: 1200,
        }
    }

    /// Checks configuration limits before opening a socket.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.max_datagram_size == 0 || self.max_datagram_size > MAX_UDP_PAYLOAD_SIZE {
            return Err(TransportError::InvalidDatagramSize {
                size: self.max_datagram_size,
                maximum: MAX_UDP_PAYLOAD_SIZE,
            });
        }
        Ok(())
    }
}
