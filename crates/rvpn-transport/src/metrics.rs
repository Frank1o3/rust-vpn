use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct TransportMetrics {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    packets_dropped_oversized: AtomicU64,
    packets_dropped_backpressure: AtomicU64,
    send_errors: AtomicU64,
    congestion_events: AtomicU64,
    keepalives_sent: AtomicU64,
    keepalives_skipped: AtomicU64,
    mtu_changes: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped_oversized: u64,
    pub packets_dropped_backpressure: u64,
    pub send_errors: u64,
    pub congestion_events: u64,
    pub keepalives_sent: u64,
    pub keepalives_skipped: u64,
    pub mtu_changes: u64,
}

impl TransportMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dropped_oversized(&self) {
        self.packets_dropped_oversized
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dropped_backpressure(&self) {
        self.packets_dropped_backpressure
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn record_congestion_event(&self) {
        self.congestion_events.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn record_keepalive_sent(&self) {
        self.keepalives_sent.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub(crate) fn record_keepalive_skipped(&self) {
        self.keepalives_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_mtu_change(&self) {
        self.mtu_changes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_dropped_oversized: self.packets_dropped_oversized.load(Ordering::Relaxed),
            packets_dropped_backpressure: self.packets_dropped_backpressure.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            congestion_events: self.congestion_events.load(Ordering::Relaxed),
            keepalives_sent: self.keepalives_sent.load(Ordering::Relaxed),
            keepalives_skipped: self.keepalives_skipped.load(Ordering::Relaxed),
            mtu_changes: self.mtu_changes.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshot_consistently() {
        let metrics = TransportMetrics::new();
        metrics.record_sent(100);
        metrics.record_sent(50);
        metrics.record_received(80);
        metrics.record_dropped_oversized();
        metrics.record_congestion_event();
        metrics.record_mtu_change();

        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_sent, 150);
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.bytes_received, 80);
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.packets_dropped_oversized, 1);
        assert_eq!(snap.congestion_events, 1);
        assert_eq!(snap.mtu_changes, 1);
    }
}
