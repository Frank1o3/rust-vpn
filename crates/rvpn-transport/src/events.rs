use crate::{SendOptions, TransportError, TransportPacket, UdpTransport, transport::receive_from};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::{sync::mpsc, task::JoinHandle};

/// An asynchronously produced transport event.
#[derive(Debug)]
pub enum TransportEvent {
    /// An opaque UDP datagram arrived from a peer.
    PacketReceived(TransportPacket),
    /// Receiving from UDP failed and the event loop stopped.
    ReceiveFailed(TransportError),
}

/// Tokio-compatible event receiver for an [`EventTransport`].
pub struct TransportEvents {
    receiver: mpsc::Receiver<TransportEvent>,
}

impl TransportEvents {
    /// Waits for the next transport event; `None` means the event loop stopped.
    pub async fn recv(&mut self) -> Option<TransportEvent> {
        self.receiver.recv().await
    }
}

/// A UDP transport with a background receive task and event channel.
pub struct EventTransport {
    transport: UdpTransport,
    receive_task: JoinHandle<()>,
}

impl EventTransport {
    /// Starts a bounded event loop. Dropping all [`TransportEvents`] receivers
    /// stops the loop without polling or busy waiting.
    pub fn new(
        transport: UdpTransport,
        capacity: usize,
    ) -> Result<(Self, TransportEvents), TransportError> {
        if capacity == 0 {
            return Err(TransportError::InvalidEventCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        let socket = transport.socket();
        let maximum = transport.config().max_datagram_size;
        let receive_task = tokio::spawn(async move {
            loop {
                let event = match receive_from(&socket, maximum).await {
                    Ok(packet) => TransportEvent::PacketReceived(packet),
                    Err(error) => TransportEvent::ReceiveFailed(error),
                };
                let terminal = matches!(event, TransportEvent::ReceiveFailed(_));
                if sender.send(event).await.is_err() || terminal {
                    break;
                }
            }
        });
        Ok((
            Self {
                transport,
                receive_task,
            },
            TransportEvents { receiver },
        ))
    }

    /// Sends opaque bytes to the configured peer.
    pub async fn send(
        &self,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.transport.send(payload, options).await
    }

    /// Sends opaque bytes to an explicit peer.
    pub async fn send_to(
        &self,
        peer: SocketAddr,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.transport.send_to(peer, payload, options).await
    }

    /// Stops the background event loop.
    pub fn close(&self) {
        self.receive_task.abort();
    }
}

impl Drop for EventTransport {
    fn drop(&mut self) {
        self.receive_task.abort();
    }
}
