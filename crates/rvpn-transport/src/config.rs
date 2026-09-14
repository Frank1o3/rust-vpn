use crate::TransportError;
use std::net::SocketAddr;

pub const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub local_address: SocketAddr,
    pub remote_address: Option<SocketAddr>,
    pub max_datagram_size: usize,
}

impl TransportConfig {
    pub fn new(local_address: SocketAddr) -> Self {
        Self {
            local_address,
            remote_address: None,
            max_datagram_size: 1200,
        }
    }

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
