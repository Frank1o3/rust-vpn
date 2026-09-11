//! Reusable unencrypted datagram transport abstractions.

use bytes::Bytes;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::UdpSocket;

/// Bytes received from a peer.
#[derive(Clone, Debug)]
pub struct ReceivedDatagram {
    /// Source address reported by UDP.
    pub peer: SocketAddr,
    /// Exact opaque payload received from UDP.
    pub bytes: Bytes,
}

/// A UDP transport that only moves opaque bytes. It performs no encryption.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds a UDP socket to `address`.
    pub async fn bind(address: SocketAddr) -> Result<Self, TransportError> {
        Ok(Self {
            socket: UdpSocket::bind(address).await?,
        })
    }

    /// Returns the bound local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    /// Sends opaque bytes to `peer`.
    pub async fn send(&self, peer: SocketAddr, bytes: &[u8]) -> Result<usize, TransportError> {
        Ok(self.socket.send_to(bytes, peer).await?)
    }

    /// Receives one datagram, up to `max_size` bytes.
    pub async fn receive(&self, max_size: usize) -> Result<ReceivedDatagram, TransportError> {
        if max_size == 0 {
            return Err(TransportError::InvalidReceiveSize);
        }
        let mut buffer = vec![0; max_size];
        let (length, peer) = self.socket.recv_from(&mut buffer).await?;
        buffer.truncate(length);
        Ok(ReceivedDatagram {
            peer,
            bytes: Bytes::from(buffer),
        })
    }
}

/// Transport-level failures. Packet format and cryptographic failures never appear here.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("UDP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("receive buffer size must be greater than zero")]
    InvalidReceiveSize,
}
