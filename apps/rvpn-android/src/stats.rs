//! Tunnel statistics and telemetry tracking.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Live statistics for an active RVPN tunnel session.
#[derive(Debug, Default)]
pub struct TunnelStats {
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub packets_rx: AtomicU64,
}

impl TunnelStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_tx(&self, bytes: usize) {
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rx(&self, bytes: usize) {
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, start_time: Option<Instant>) -> StatsSnapshot {
        StatsSnapshot {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            uptime_ms: start_time.map_or(0, |t| t.elapsed().as_millis() as u64),
        }
    }
}

/// Immutable snapshot of tunnel metrics at a point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub uptime_ms: u64,
}
