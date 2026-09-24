use rand::{TryRng, rngs::SysRng};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

pub fn random_keepalive_len() -> usize {
    let mut bytes = [0u8; 1];
    if SysRng.try_fill_bytes(&mut bytes).is_ok() {
        (bytes[0] % 49) as usize
    } else {
        0
    }
}

pub fn random_keepalive_payload() -> Vec<u8> {
    vec![0u8; random_keepalive_len()]
}

fn jitter_interval(interval: Duration, jitter_pct: u8) -> Duration {
    if jitter_pct == 0 {
        return interval;
    }
    let interval_ms = interval.as_millis() as i64;
    let max_delta = (interval_ms * jitter_pct as i64) / 100;
    if max_delta == 0 {
        return interval;
    }
    let mut bytes = [0u8; 8];
    if SysRng.try_fill_bytes(&mut bytes).is_err() {
        return interval;
    }
    let rand_val = u64::from_le_bytes(bytes);
    let span = (max_delta * 2 + 1) as u64;
    let delta = (rand_val % span) as i64 - max_delta;
    let jittered_ms = (interval_ms + delta).max(1) as u64;
    Duration::from_millis(jittered_ms)
}

#[derive(Debug)]
pub struct KeepaliveScheduler {
    interval: Duration,
    jitter_pct: u8,
    epoch: Instant,
    next_due_ms: AtomicI64,
}

impl KeepaliveScheduler {
    pub fn new(interval: Duration) -> Self {
        Self::with_jitter(interval, 0)
    }

    pub fn with_jitter(interval: Duration, jitter_pct: u8) -> Self {
        let epoch = Instant::now();
        let jittered = jitter_interval(interval, jitter_pct);
        let due = jittered.as_millis().min(i64::MAX as u128) as i64;
        Self {
            interval,
            jitter_pct,
            epoch,
            next_due_ms: AtomicI64::new(due),
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn jitter_pct(&self) -> u8 {
        self.jitter_pct
    }

    pub fn record_activity(&self) {
        let jittered = jitter_interval(self.interval, self.jitter_pct);
        let due_ms = self.epoch.elapsed().as_millis() as i64 + jittered.as_millis() as i64;
        self.next_due_ms.store(due_ms, Ordering::Relaxed);
    }

    pub fn next_due_delay(&self) -> Duration {
        let now_ms = self.epoch.elapsed().as_millis() as i64;
        let due_ms = self.next_due_ms.load(Ordering::Relaxed);
        Duration::from_millis(due_ms.saturating_sub(now_ms).max(0) as u64)
    }

    pub async fn wait_for_due(&self) {
        loop {
            let due_ms = self.next_due_ms.load(Ordering::Relaxed);
            let deadline = self.epoch + Duration::from_millis(due_ms.max(0) as u64);
            sleep_until(deadline).await;
            let now_ms = self.epoch.elapsed().as_millis() as i64;
            if now_ms >= self.next_due_ms.load(Ordering::Relaxed) {
                return;
            }
        }
    }

    pub fn record_keepalive_sent(&self) {
        self.record_activity();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn fires_after_the_configured_interval() {
        let scheduler = KeepaliveScheduler::new(StdDuration::from_millis(30));
        let start = std::time::Instant::now();
        scheduler.wait_for_due().await;
        assert!(start.elapsed() >= StdDuration::from_millis(25));
    }

    #[tokio::test]
    async fn activity_pushes_the_deadline_out() {
        let scheduler = KeepaliveScheduler::new(StdDuration::from_millis(60));
        tokio::time::sleep(StdDuration::from_millis(40)).await;
        scheduler.record_activity();
        tokio::select! {
            _ = scheduler.wait_for_due() => {
                panic!("keepalive fired despite recent activity pushing the deadline out");
            }
            _ = tokio::time::sleep(StdDuration::from_millis(30)) => {}
        }
    }

    #[test]
    fn unchanged_behaviour_for_jitter_zero() {
        let interval = StdDuration::from_millis(1000);
        let scheduler = KeepaliveScheduler::new(interval);
        assert_eq!(scheduler.jitter_pct(), 0);
        for _ in 0..50 {
            scheduler.record_activity();
            let delay = scheduler.next_due_delay();
            assert!(
                delay >= StdDuration::from_millis(995) && delay <= StdDuration::from_millis(1005)
            );
        }
    }

    #[test]
    fn due_times_stay_within_twenty_percent_jitter_bounds() {
        let interval = StdDuration::from_millis(1000);
        let scheduler = KeepaliveScheduler::with_jitter(interval, 20);
        assert_eq!(scheduler.jitter_pct(), 20);

        let mut saw_below = false;
        let mut saw_above = false;

        for _ in 0..100 {
            scheduler.record_activity();
            let delay = scheduler.next_due_delay();
            // Bounds: [0.8, 1.2] * 1000ms = [800ms, 1200ms]
            assert!(
                delay >= StdDuration::from_millis(795) && delay <= StdDuration::from_millis(1205),
                "delay {delay:?} outside [800ms, 1200ms]"
            );
            if delay < StdDuration::from_millis(980) {
                saw_below = true;
            }
            if delay > StdDuration::from_millis(1020) {
                saw_above = true;
            }
        }
        assert!(saw_below, "expected some delays below interval");
        assert!(saw_above, "expected some delays above interval");
    }

    #[test]
    fn random_keepalive_payload_bounds() {
        for _ in 0..100 {
            let payload = random_keepalive_payload();
            assert!(payload.len() <= 48);
            assert!(payload.iter().all(|&b| b == 0));
        }
    }
}
