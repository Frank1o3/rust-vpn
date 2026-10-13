use crate::TransportError;
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;

const DRR_QUANTUM: usize = 1500;
const MAX_PEER_QUEUE: usize = 256;

#[derive(Debug)]
pub struct QueuedDatagram {
    pub peer: SocketAddr,
    pub payload: Bytes,
}

#[derive(Debug)]
pub struct OutboundQueue {
    capacity: usize,
    per_peer_capacity: usize,
    queued: Arc<AtomicUsize>,
    state: Arc<Mutex<QueueState>>,
    ready: Arc<Notify>,
}

#[derive(Debug)]
pub struct OutboundQueueReceiver {
    queued: Arc<AtomicUsize>,
    state: Arc<Mutex<QueueState>>,
    ready: Arc<Notify>,
}

#[derive(Debug, Default)]
struct QueueState {
    peers: HashMap<SocketAddr, PeerQueue>,
    rotation: VecDeque<SocketAddr>,
    queued: usize,
}

#[derive(Debug, Default)]
struct PeerQueue {
    packets: VecDeque<QueuedDatagram>,
    deficit: usize,
    in_round: bool,
}

impl OutboundQueue {
    pub fn new(capacity: usize) -> (Arc<Self>, OutboundQueueReceiver) {
        let capacity = capacity.max(1);
        let queued = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(QueueState::default()));
        let ready = Arc::new(Notify::new());
        let queue = Arc::new(Self {
            capacity,
            per_peer_capacity: capacity.min(MAX_PEER_QUEUE),
            queued: Arc::clone(&queued),
            state: Arc::clone(&state),
            ready: Arc::clone(&ready),
        });
        (
            queue,
            OutboundQueueReceiver {
                queued,
                state,
                ready,
            },
        )
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn queued_len(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    pub fn try_enqueue(&self, peer: SocketAddr, payload: Bytes) -> Result<(), TransportError> {
        let mut state = self.state.lock().expect("outbound queue mutex poisoned");
        if state.queued >= self.capacity {
            return Err(TransportError::Backpressure);
        }
        let peer_queue = state.peers.entry(peer).or_default();
        if peer_queue.packets.len() >= self.per_peer_capacity {
            return Err(TransportError::Backpressure);
        }
        if peer_queue.packets.is_empty() {
            state.rotation.push_back(peer);
        }
        state
            .peers
            .get_mut(&peer)
            .expect("peer queue was just created")
            .packets
            .push_back(QueuedDatagram { peer, payload });
        state.queued += 1;
        self.queued.fetch_add(1, Ordering::Relaxed);
        drop(state);
        self.ready.notify_one();
        Ok(())
    }
}

impl Drop for OutboundQueue {
    fn drop(&mut self) {
        self.ready.notify_one();
    }
}

impl OutboundQueueReceiver {
    pub async fn recv(&mut self) -> Option<QueuedDatagram> {
        loop {
            // Register before looking at the queue so an enqueue between the
            // check and await is retained as a notification permit.
            let notified = self.ready.notified();
            let closed;
            {
                let mut state = self.state.lock().expect("outbound queue mutex poisoned");
                while let Some(peer) = state.rotation.pop_front() {
                    let Some(peer_queue) = state.peers.get_mut(&peer) else {
                        continue;
                    };
                    if !peer_queue.in_round {
                        peer_queue.deficit = peer_queue.deficit.saturating_add(DRR_QUANTUM);
                        peer_queue.in_round = true;
                    }
                    let packet_size = peer_queue
                        .packets
                        .front()
                        .map(|packet| packet.payload.len())
                        .unwrap_or(0);
                    if packet_size > peer_queue.deficit {
                        peer_queue.in_round = false;
                        state.rotation.push_back(peer);
                        continue;
                    }
                    peer_queue.deficit -= packet_size;
                    let packet = peer_queue.packets.pop_front();
                    if peer_queue.packets.is_empty() {
                        state.peers.remove(&peer);
                    } else if peer_queue
                        .packets
                        .front()
                        .is_some_and(|next| next.payload.len() <= peer_queue.deficit)
                    {
                        state.rotation.push_front(peer);
                    } else {
                        peer_queue.in_round = false;
                        state.rotation.push_back(peer);
                    }
                    if let Some(packet) = packet {
                        state.queued -= 1;
                        self.queued.fetch_sub(1, Ordering::Relaxed);
                        return Some(packet);
                    }
                }
                closed = state.queued == 0 && Arc::strong_count(&self.state) == 1;
            }
            if closed {
                return None;
            }
            notified.await;
        }
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
