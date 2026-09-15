use crate::{
    SendOptions, TransportError, TransportPacket, UdpTransport, metrics::TransportMetrics,
    transport::receive_from,
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Debug)]
pub enum TransportEvent {
    PacketReceived(TransportPacket),
    DatagramDropped { size: usize, maximum: usize },
    ReceiveFailed(TransportError),
}

pub struct TransportEvents {
    receiver: mpsc::Receiver<TransportEvent>,
}

impl TransportEvents {
    pub async fn recv(&mut self) -> Option<TransportEvent> {
        self.receiver.recv().await
    }
}

pub struct EventTransport {
    transport: UdpTransport,
    receive_task: JoinHandle<()>,
}

impl EventTransport {
    pub fn new(
        transport: UdpTransport,
        capacity: usize,
    ) -> Result<(Self, TransportEvents), TransportError> {
        if capacity == 0 {
            return Err(TransportError::InvalidEventCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        let socket = transport.socket();
        let pool = Arc::clone(&transport.recv_pool);
        let metrics: Arc<TransportMetrics> = Arc::clone(&transport.metrics);
        let keepalive = Arc::clone(&transport.keepalive);
        let receive_task = tokio::spawn(async move {
            loop {
                let event = match receive_from(&socket, &pool, &metrics).await {
                    Ok(packet) => {
                        keepalive.record_activity();
                        TransportEvent::PacketReceived(packet)
                    }
                    Err(TransportError::DatagramTooLarge { size, maximum }) => {
                        TransportEvent::DatagramDropped { size, maximum }
                    }
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

    pub async fn send(
        &self,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.transport.send(payload, options).await
    }

    pub async fn send_to(
        &self,
        peer: SocketAddr,
        payload: Bytes,
        options: SendOptions,
    ) -> Result<usize, TransportError> {
        self.transport.send_to(peer, payload, options).await
    }

    pub fn close(&self) {
        self.receive_task.abort();
    }
}

impl Drop for EventTransport {
    fn drop(&mut self) {
        self.receive_task.abort();
    }
}
