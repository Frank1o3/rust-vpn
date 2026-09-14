//! A small pool of pre-allocated receive buffers.
//!
//! UDP receive traditionally allocates a fresh buffer per datagram. Under
//! sustained or bursty traffic this becomes steady allocator churn for no
//! benefit -- the buffer's *shape* (capacity) is identical every time.
//! [`BufferPool`] amortizes that churn: buffers are checked out before a
//! receive and, whenever a caller doesn't need to keep the resulting
//! allocation (for example, the oversized-datagram reject path), checked
//! back in for reuse instead of being dropped.
//!
//! Buffers that *are* handed out as owned `Bytes` (via
//! [`crate::UdpTransport::receive`]) are not returned automatically --
//! ownership has left the pool -- so the pool simply grows a fresh
//! replacement lazily on the next `acquire`, up to `max_pooled` idle
//! buffers kept ready between bursts. Callers who want a truly zero-
//! allocation steady state should prefer [`crate::UdpTransport::receive_into`],
//! which reuses one caller-owned buffer across every call.

use bytes::BytesMut;
use std::sync::Mutex;

/// A pool of same-sized [`BytesMut`] buffers, safe to share across
/// concurrently receiving tasks.
#[derive(Debug)]
pub struct BufferPool {
    capacity: usize,
    max_pooled: usize,
    idle: Mutex<Vec<BytesMut>>,
}

impl BufferPool {
    /// Creates a pool of buffers with the given per-buffer `capacity`,
    /// keeping at most `max_pooled` idle buffers ready for reuse.
    pub fn new(capacity: usize, max_pooled: usize) -> Self {
        Self {
            capacity,
            max_pooled,
            idle: Mutex::new(Vec::with_capacity(max_pooled.min(16))),
        }
    }

    /// The fixed capacity of every buffer this pool hands out.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Checks out a cleared buffer with at least `capacity` bytes of room,
    /// reusing a pooled allocation when one is available.
    pub fn acquire(&self) -> BytesMut {
        let pooled = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            idle.pop()
        };
        match pooled {
            Some(mut buf) => {
                buf.clear();
                if buf.capacity() < self.capacity {
                    buf.reserve(self.capacity - buf.capacity());
                }
                buf
            }
            None => BytesMut::with_capacity(self.capacity),
        }
    }

    /// Returns a buffer to the pool for reuse, provided the pool has room.
    /// Buffers that were frozen into `Bytes` and handed to a caller cannot
    /// be released this way -- ownership has already left the pool.
    pub fn release(&self, mut buf: BytesMut) {
        if buf.capacity() < self.capacity {
            // Undersized (e.g. a stray external buffer); not worth keeping.
            return;
        }
        buf.clear();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < self.max_pooled {
            idle.push(buf);
        }
    }

    /// Number of buffers currently idle in the pool. Exposed for tests and
    /// diagnostics only.
    pub fn idle_len(&self) -> usize {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_reuses_released_buffers() {
        let pool = BufferPool::new(128, 4);
        let buf = pool.acquire();
        assert_eq!(buf.capacity(), 128);
        assert_eq!(pool.idle_len(), 0);
        pool.release(buf);
        assert_eq!(pool.idle_len(), 1);
        let reused = pool.acquire();
        assert!(reused.capacity() >= 128);
        assert_eq!(pool.idle_len(), 0);
    }

    #[test]
    fn pool_size_is_bounded() {
        let pool = BufferPool::new(64, 2);
        for _ in 0..5 {
            pool.release(BytesMut::with_capacity(64));
        }
        assert_eq!(pool.idle_len(), 2);
    }

    #[test]
    fn acquire_without_pooled_buffers_allocates_fresh() {
        let pool = BufferPool::new(256, 4);
        let buf = pool.acquire();
        assert!(buf.capacity() >= 256);
        assert!(buf.is_empty());
    }

    #[test]
    fn undersized_buffers_are_not_pooled() {
        let pool = BufferPool::new(256, 4);
        pool.release(BytesMut::with_capacity(4));
        assert_eq!(pool.idle_len(), 0);
    }
}
