use bytes::Bytes;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PacketId(pub u64);

#[derive(Clone, Debug)]
pub struct TransportPacket {
    pub peer: SocketAddr,
    pub payload: Bytes,
    pub received_at: Instant,
}

impl TransportPacket {
    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

pub type ReceivedDatagram = TransportPacket;

#[derive(Clone, Copy, Debug)]
pub struct RecvMeta {
    pub peer: SocketAddr,
    pub len: usize,
    pub received_at: Instant,
}
