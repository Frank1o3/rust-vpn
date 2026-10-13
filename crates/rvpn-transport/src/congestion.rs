use crate::TransportError;
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

const DRR_QUANTUM: usize = 1500;
const MAX_PEER_QUEUE: usize = 256;
const MAX_TRACKED_PEERS: usize = 8192;

#[derive(Debug)]
pub struct QueuedDatagram {
    pub peer: SocketAddr,
    pub payload: Bytes,
}

#[derive(Debug)]
pub struct OutboundQueue {
    capacity: usize,
    per_peer_capacity: usize,
    rate_bytes_per_sec: Option<u64>,
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
    peers: HashMap<QueueKey, PeerQueue>,
    rotation: VecDeque<QueueKey>,
    queued: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum QueueKey {
    Endpoint(SocketAddr),
    Stable([u8; 16]),
}

#[derive(Debug)]
struct PeerQueue {
    packets: VecDeque<QueuedDatagram>,
    deficit: usize,
    in_round: bool,
    rate_bucket: Option<RateBucket>,
    last_activity: Instant,
}

impl PeerQueue {
    fn new(rate_bytes_per_sec: Option<u64>) -> Self {
        Self {
            packets: VecDeque::new(),
            deficit: 0,
            in_round: false,
            rate_bucket: rate_bytes_per_sec.map(RateBucket::new),
            last_activity: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct RateBucket {
    rate_bytes_per_sec: u64,
    capacity: u64,
    tokens: u64,
    updated: Instant,
}

impl RateBucket {
    fn new(rate_bytes_per_sec: u64) -> Self {
        // Keep at least one maximum UDP payload's worth of burst capacity so
        // a configured rate below the packet size can still make progress.
        let capacity = rate_bytes_per_sec.max(65_535);
        Self {
            rate_bytes_per_sec,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        }
    }

    fn consume_or_delay(&mut self, bytes: usize) -> Result<(), Duration> {
        let now = Instant::now();
        let replenished = now
            .duration_since(self.updated)
            .as_nanos()
            .saturating_mul(u128::from(self.rate_bytes_per_sec))
            / 1_000_000_000;
        self.tokens = self.capacity.min(
            self.tokens
                .saturating_add(u64::try_from(replenished).unwrap_or(u64::MAX)),
        );
        self.updated = now;
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        if self.tokens >= bytes {
            self.tokens -= bytes;
            return Ok(());
        }
        let missing = u128::from(bytes - self.tokens);
        let nanos = missing
            .saturating_mul(1_000_000_000)
            .div_ceil(u128::from(self.rate_bytes_per_sec));
        Err(Duration::from_nanos(
            u64::try_from(nanos).unwrap_or(u64::MAX),
        ))
    }
}

impl OutboundQueue {
    pub fn new(capacity: usize) -> (Arc<Self>, OutboundQueueReceiver) {
        Self::new_with_rate(capacity, 0)
    }

    /// Creates a fair queue with an optional per-peer transmit rate.
    /// A zero rate leaves transmission unlimited.
    pub fn new_with_rate(
        capacity: usize,
        rate_bytes_per_sec: u64,
    ) -> (Arc<Self>, OutboundQueueReceiver) {
        let capacity = capacity.max(1);
        let queued = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(QueueState::default()));
        let ready = Arc::new(Notify::new());
        let queue = Arc::new(Self {
            capacity,
            per_peer_capacity: capacity.min(MAX_PEER_QUEUE),
            rate_bytes_per_sec: (rate_bytes_per_sec != 0).then_some(rate_bytes_per_sec),
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
        self.try_enqueue_keyed(QueueKey::Endpoint(peer), peer, payload)
    }

    /// Enqueues data under a stable authenticated peer key. The endpoint can
    /// then roam without resetting its fair-queue slot or rate bucket.
    pub fn try_enqueue_for_peer(
        &self,
        peer_key: [u8; 16],
        endpoint: SocketAddr,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        self.try_enqueue_keyed(QueueKey::Stable(peer_key), endpoint, payload)
    }

    fn try_enqueue_keyed(
        &self,
        key: QueueKey,
        endpoint: SocketAddr,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        let mut state = self.state.lock().expect("outbound queue mutex poisoned");
        let now = Instant::now();
        state.peers.retain(|_, peer_queue| {
            !peer_queue.packets.is_empty()
                || now.duration_since(peer_queue.last_activity) < Duration::from_secs(1)
        });
        if state.queued >= self.capacity {
            return Err(TransportError::Backpressure);
        }
        if !state.peers.contains_key(&key) && state.peers.len() >= MAX_TRACKED_PEERS {
            return Err(TransportError::Backpressure);
        }
        let peer_queue = state
            .peers
            .entry(key)
            .or_insert_with(|| PeerQueue::new(self.rate_bytes_per_sec));
        if peer_queue.packets.len() >= self.per_peer_capacity {
            return Err(TransportError::Backpressure);
        }
        if peer_queue.packets.is_empty() {
            state.rotation.push_back(key);
        }
        let peer_queue = state
            .peers
            .get_mut(&key)
            .expect("peer queue was just created");
        peer_queue.packets.push_back(QueuedDatagram {
            peer: endpoint,
            payload,
        });
        peer_queue.last_activity = now;
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
            let mut wait_for: Option<Duration> = None;
            let mut yielded_to_deficit = false;
            {
                let mut state = self.state.lock().expect("outbound queue mutex poisoned");
                let peers_to_visit = state.rotation.len();
                for _ in 0..peers_to_visit {
                    let Some(key) = state.rotation.pop_front() else {
                        break;
                    };
                    let Some(peer_queue) = state.peers.get_mut(&key) else {
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
                        state.rotation.push_back(key);
                        yielded_to_deficit = true;
                        continue;
                    }
                    if let Some(bucket) = &mut peer_queue.rate_bucket {
                        if let Err(delay) = bucket.consume_or_delay(packet_size) {
                            peer_queue.in_round = false;
                            wait_for = Some(wait_for.map_or(delay, |old| old.min(delay)));
                            state.rotation.push_back(key);
                            continue;
                        }
                    }
                    peer_queue.deficit -= packet_size;
                    let packet = peer_queue.packets.pop_front();
                    peer_queue.last_activity = Instant::now();
                    let mut remove_peer = false;
                    if peer_queue.packets.is_empty() {
                        peer_queue.in_round = false;
                        peer_queue.deficit = 0;
                        remove_peer = peer_queue.rate_bucket.is_none();
                    } else if peer_queue
                        .packets
                        .front()
                        .is_some_and(|next| next.payload.len() <= peer_queue.deficit)
                    {
                        state.rotation.push_front(key);
                    } else {
                        peer_queue.in_round = false;
                        state.rotation.push_back(key);
                    }
                    if remove_peer {
                        state.peers.remove(&key);
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
            if let Some(delay) = wait_for {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = notified => {},
                }
            } else if yielded_to_deficit {
                tokio::task::yield_now().await;
            } else {
                notified.await;
            }
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
