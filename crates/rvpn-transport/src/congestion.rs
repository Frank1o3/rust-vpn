use crate::TransportError;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct QueuedDatagram {
    pub peer: SocketAddr,
    pub payload: Bytes,
}

#[derive(Debug)]
pub struct OutboundQueue {
    sender: mpsc::Sender<QueuedDatagram>,
    capacity: usize,
    queued: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub struct OutboundQueueReceiver {
    receiver: mpsc::Receiver<QueuedDatagram>,
    queued: Arc<AtomicUsize>,
}

impl OutboundQueue {
    pub fn new(capacity: usize) -> (Arc<Self>, OutboundQueueReceiver) {
        let capacity = capacity.max(1);
        let (sender, receiver) = mpsc::channel(capacity);
        let queued = Arc::new(AtomicUsize::new(0));
        let queue = Arc::new(Self {
            sender,
            capacity,
            queued: Arc::clone(&queued),
        });
        (queue, OutboundQueueReceiver { receiver, queued })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn queued_len(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    pub fn try_enqueue(&self, peer: SocketAddr, payload: Bytes) -> Result<(), TransportError> {
        match self.sender.try_send(QueuedDatagram { peer, payload }) {
            Ok(()) => {
                self.queued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportError::Backpressure),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::Backpressure),
        }
    }
}

impl OutboundQueueReceiver {
    pub async fn recv(&mut self) -> Option<QueuedDatagram> {
        let datagram = self.receiver.recv().await;
        if datagram.is_some() {
            self.queued.fetch_sub(1, Ordering::Relaxed);
        }
        datagram
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    #[test]
    fn reports_backpressure_when_full() {
        let (queue, _receiver) = OutboundQueue::new(2);
        assert!(queue.try_enqueue(addr(), Bytes::from_static(b"a")).is_ok());
        assert!(queue.try_enqueue(addr(), Bytes::from_static(b"b")).is_ok());
        assert!(matches!(
            queue.try_enqueue(addr(), Bytes::from_static(b"c")),
            Err(TransportError::Backpressure)
        ));
        assert_eq!(queue.queued_len(), 2);
    }

    #[tokio::test]
    async fn draining_frees_capacity() {
        let (queue, mut receiver) = OutboundQueue::new(1);
        queue.try_enqueue(addr(), Bytes::from_static(b"a")).unwrap();
        assert!(matches!(
            queue.try_enqueue(addr(), Bytes::from_static(b"b")),
            Err(TransportError::Backpressure)
        ));
        let drained = receiver.recv().await.unwrap();
        assert_eq!(drained.payload, Bytes::from_static(b"a"));
        assert_eq!(queue.queued_len(), 0);
        assert!(queue.try_enqueue(addr(), Bytes::from_static(b"b")).is_ok());
    }
}