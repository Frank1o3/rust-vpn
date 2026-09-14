use bytes::BytesMut;
use std::sync::Mutex;

#[derive(Debug)]
pub struct BufferPool {
    capacity: usize,
    max_pooled: usize,
    idle: Mutex<Vec<BytesMut>>,
}

impl BufferPool {
    pub fn new(capacity: usize, max_pooled: usize) -> Self {
        Self {
            capacity,
            max_pooled,
            idle: Mutex::new(Vec::with_capacity(max_pooled.min(16))),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

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

    pub fn release(&self, mut buf: BytesMut) {
        if buf.capacity() < self.capacity {
            return;
        }
        buf.clear();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < self.max_pooled {
            idle.push(buf);
        }
    }

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
