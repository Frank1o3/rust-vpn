use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

#[derive(Debug)]
pub struct KeepaliveScheduler {
    interval: Duration,
    epoch: Instant,
    next_due_ms: AtomicI64,
}

impl KeepaliveScheduler {
    pub fn new(interval: Duration) -> Self {
        let epoch = Instant::now();
        let due = interval.as_millis().min(i64::MAX as u128) as i64;
        Self {
            interval,
            epoch,
            next_due_ms: AtomicI64::new(due),
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn record_activity(&self) {
        let due_ms = self.epoch.elapsed().as_millis() as i64 + self.interval.as_millis() as i64;
        self.next_due_ms.store(due_ms, Ordering::Relaxed);
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
}
