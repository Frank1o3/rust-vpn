use bytes::Bytes;
use std::{net::SocketAddr, time::Instant};

/// Identifier reserved for future acknowledgement and duplicate tracking.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PacketId(pub u64);

/// An opaque inbound transport message and useful receive metadata.
#[derive(Clone, Debug)]
pub struct TransportPacket {
    /// Source endpoint reported by UDP.
    pub peer: SocketAddr,
    /// Exact opaque bytes received from UDP.
    pub payload: Bytes,
    /// Time at which the socket receive operation completed.
    pub received_at: Instant,
}

/// Backwards-compatible name for an inbound UDP datagram.
pub type ReceivedDatagram = TransportPacket;
