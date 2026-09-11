use thiserror::Error;

/// Transport-level failures. Protocol parsing and cryptographic failures never
/// cross this boundary.
#[derive(Debug, Error)]
pub enum TransportError {
    /// UDP socket operation failed.
    #[error("UDP I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A datagram exceeds the configured bounded buffer.
    #[error("datagram size {size} exceeds the configured maximum {maximum}")]
    DatagramTooLarge { size: usize, maximum: usize },
    /// A configured datagram limit is not a valid UDP payload size.
    #[error("datagram size {size} is invalid; expected 1 through {maximum}")]
    InvalidDatagramSize { size: usize, maximum: usize },
    /// An API requiring a configured peer was called without one.
    #[error("no remote peer is configured")]
    MissingRemoteAddress,
    /// Reliable or ordered semantics were requested before their implementation.
    #[error("reliable and ordered delivery are not implemented yet")]
    UnsupportedDeliveryMode,
    /// An event queue cannot be created without room for an event.
    #[error("event queue capacity must be greater than zero")]
    InvalidEventCapacity,
}
