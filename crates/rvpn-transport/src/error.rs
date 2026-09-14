use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("UDP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("datagram size {size} exceeds the configured maximum {maximum}")]
    DatagramTooLarge { size: usize, maximum: usize },
    #[error("datagram size {size} is invalid; expected 1 through {maximum}")]
    InvalidDatagramSize { size: usize, maximum: usize },
    #[error("no remote peer is configured")]
    MissingRemoteAddress,
    #[error("reliable and ordered delivery are not implemented yet")]
    UnsupportedDeliveryMode,
    #[error("event queue capacity must be greater than zero")]
    InvalidEventCapacity,
    #[error("path rejected a {attempted}-byte datagram; effective MTU is now {effective} bytes")]
    PathMtuExceeded { attempted: usize, effective: usize },
    #[error("outbound queue is full; apply backpressure")]
    Backpressure,
}
