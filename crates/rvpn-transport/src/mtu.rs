use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtuChangeReason {
    PathMtuExceeded,
    SustainedInstability,
    ProbeUp,
    ProbeReverted,
}

#[derive(Clone, Copy, Debug)]
pub struct MtuSnapshot {
    pub target_mtu: usize,
    pub effective_mtu: usize,
    pub minimum_mtu: usize,
    pub maximum_mtu: usize,
    pub probing: bool,
}

#[derive(Debug)]
struct MtuState {
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_change: Instant,
    probe_candidate: Option<usize>,
    probe_started: Option<Instant>,
}

#[derive(Debug)]
pub struct AdaptiveMtu {
    target_mtu: usize,
    minimum_mtu: usize,
    maximum_mtu: usize,
    effective_mtu: AtomicUsize,
    state: Mutex<MtuState>,
}

impl AdaptiveMtu {
    const FAILURE_THRESHOLD: u32 = 5;
    const SUCCESS_THRESHOLD: u32 = 64;
    const MIN_CHANGE_INTERVAL: Duration = Duration::from_secs(5);
    const PROBE_EVALUATION_WINDOW: Duration = Duration::from_secs(3);
    const PROBE_SUCCESS_THRESHOLD: u32 = 16;
    const STEP_DOWN_NUMERATOR: usize = 9;
    const STEP_DOWN_DENOMINATOR: usize = 10;
    const STEP_UP_NUMERATOR: usize = 1;
    const STEP_UP_DENOMINATOR: usize = 8;

    pub fn new(target_mtu: usize, minimum_mtu: usize) -> Self {
        let target_mtu = target_mtu.max(1);
        let minimum_mtu = minimum_mtu.min(target_mtu).max(1);
        Self {
            target_mtu,
            minimum_mtu,
            maximum_mtu: target_mtu,
            effective_mtu: AtomicUsize::new(target_mtu),
            state: Mutex::new(MtuState {
                consecutive_failures: 0,
                consecutive_successes: 0,
                last_change: Instant::now(),
                probe_candidate: None,
                probe_started: None,
            }),
        }
    }

    pub fn target_mtu(&self) -> usize {
        self.target_mtu
    }

    pub fn minimum_mtu(&self) -> usize {
        self.minimum_mtu
    }

    pub fn maximum_mtu(&self) -> usize {
        self.maximum_mtu
    }

    pub fn effective_mtu(&self) -> usize {
        self.effective_mtu.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> MtuSnapshot {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        MtuSnapshot {
            target_mtu: self.target_mtu,
            effective_mtu: self.effective_mtu(),
            minimum_mtu: self.minimum_mtu,
            maximum_mtu: self.maximum_mtu,
            probing: state.probe_candidate.is_some(),
        }
    }

    pub fn record_success(&self) -> Option<MtuChangeReason> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_failures = 0;

        if let Some(candidate) = state.probe_candidate {
            state.consecutive_successes += 1;
            let started = state.probe_started.unwrap_or_else(Instant::now);
            if state.consecutive_successes >= Self::PROBE_SUCCESS_THRESHOLD
                && started.elapsed() >= Self::PROBE_EVALUATION_WINDOW
            {
                self.effective_mtu.store(candidate, Ordering::Release);
                state.probe_candidate = None;
                state.probe_started = None;
                state.consecutive_successes = 0;
                state.last_change = Instant::now();
                return Some(MtuChangeReason::ProbeUp);
            }
            return None;
        }

        state.consecutive_successes += 1;
        if state.consecutive_successes >= Self::SUCCESS_THRESHOLD
            && state.last_change.elapsed() >= Self::MIN_CHANGE_INTERVAL
        {
            let current = self.effective_mtu();
            if current < self.target_mtu {
                let gap = self.target_mtu - current;
                let step = (gap * Self::STEP_UP_NUMERATOR / Self::STEP_UP_DENOMINATOR).max(1);
                let candidate = (current + step).min(self.target_mtu);
                state.probe_candidate = Some(candidate);
                state.probe_started = Some(Instant::now());
                state.consecutive_successes = 0;
            }
        }
        None
    }

    pub fn record_path_failure(&self) -> Option<MtuChangeReason> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_successes = 0;

        if state.probe_candidate.is_some() {
            state.probe_candidate = None;
            state.probe_started = None;
            state.consecutive_failures = 0;
            state.last_change = Instant::now();
            return Some(MtuChangeReason::ProbeReverted);
        }

        state.consecutive_failures += 1;
        if state.consecutive_failures >= Self::FAILURE_THRESHOLD
            && state.last_change.elapsed() >= Self::MIN_CHANGE_INTERVAL
        {
            let current = self.effective_mtu();
            let reduced = (current * Self::STEP_DOWN_NUMERATOR / Self::STEP_DOWN_DENOMINATOR)
                .max(self.minimum_mtu);
            state.consecutive_failures = 0;
            state.last_change = Instant::now();
            if reduced < current {
                self.effective_mtu.store(reduced, Ordering::Release);
                return Some(MtuChangeReason::SustainedInstability);
            }
        }
        None
    }

    pub fn record_oversized(&self, attempted: usize) -> Option<MtuChangeReason> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_failures = 0;
        state.consecutive_successes = 0;
        state.probe_candidate = None;
        state.probe_started = None;

        if state.last_change.elapsed() < Self::MIN_CHANGE_INTERVAL {
            return None;
        }

        let current = self.effective_mtu();
        let ceiling = attempted.saturating_sub(1).max(self.minimum_mtu);
        let stepped = (current * Self::STEP_DOWN_NUMERATOR / Self::STEP_DOWN_DENOMINATOR)
            .max(self.minimum_mtu);
        let reduced = stepped.min(ceiling).max(self.minimum_mtu);
        state.last_change = Instant::now();
        if reduced < current {
            self.effective_mtu.store(reduced, Ordering::Release);
            Some(MtuChangeReason::PathMtuExceeded)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expire_cooldown(mtu: &AdaptiveMtu) {
        let mut state = mtu.state.lock().unwrap();
        state.last_change = Instant::now() - AdaptiveMtu::MIN_CHANGE_INTERVAL;
    }

    #[test]
    fn starts_at_target_and_never_exceeds_configured_bounds() {
        let mtu = AdaptiveMtu::new(1400, 576);
        assert_eq!(mtu.effective_mtu(), 1400);
        assert_eq!(mtu.target_mtu(), 1400);
        assert_eq!(mtu.minimum_mtu(), 576);
        assert_eq!(mtu.maximum_mtu(), 1400);
    }

    #[test]
    fn minimum_is_clamped_to_target() {
        let mtu = AdaptiveMtu::new(1000, 2000);
        assert_eq!(mtu.minimum_mtu(), 1000);
    }

    #[test]
    fn single_failure_does_not_move_effective_mtu() {
        let mtu = AdaptiveMtu::new(1400, 576);
        mtu.record_path_failure();
        assert_eq!(mtu.effective_mtu(), 1400);
    }

    #[test]
    fn sustained_failures_reduce_effective_mtu_after_cooldown_elapses() {
        let mtu = AdaptiveMtu::new(1400, 576);
        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::FAILURE_THRESHOLD {
            mtu.record_path_failure();
        }
        assert!(mtu.effective_mtu() < 1400);
        assert!(mtu.effective_mtu() >= mtu.minimum_mtu());
    }

    #[test]
    fn effective_mtu_never_drops_below_minimum() {
        let mtu = AdaptiveMtu::new(600, 576);
        for _ in 0..200 {
            expire_cooldown(&mtu);
            for _ in 0..AdaptiveMtu::FAILURE_THRESHOLD {
                mtu.record_path_failure();
            }
        }
        assert!(mtu.effective_mtu() >= 576);
    }

    #[test]
    fn oversized_evidence_reduces_immediately_but_respects_cooldown() {
        let mtu = AdaptiveMtu::new(1400, 576);
        expire_cooldown(&mtu);
        let reason = mtu.record_oversized(1400);
        assert_eq!(reason, Some(MtuChangeReason::PathMtuExceeded));
        assert!(mtu.effective_mtu() < 1400);

        let before = mtu.effective_mtu();
        mtu.record_oversized(before);
        assert_eq!(
            mtu.effective_mtu(),
            before,
            "cooldown must suppress a second reduction"
        );
    }

    #[test]
    fn hysteresis_prevents_rapid_oscillation() {
        let mtu = AdaptiveMtu::new(1400, 576);
        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::FAILURE_THRESHOLD {
            mtu.record_path_failure();
        }
        let after_first_drop = mtu.effective_mtu();
        assert!(after_first_drop < 1400);

        // A single success right after a drop must not immediately move
        // anything -- no probing without a sustained run + cooldown.
        mtu.record_success();
        assert_eq!(mtu.effective_mtu(), after_first_drop);
    }

    #[test]
    fn sustained_success_eventually_probes_upward_and_commits() {
        let mtu = AdaptiveMtu::new(1400, 576);
        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::FAILURE_THRESHOLD {
            mtu.record_path_failure();
        }
        let reduced = mtu.effective_mtu();
        assert!(reduced < 1400);

        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::SUCCESS_THRESHOLD {
            mtu.record_success();
        }
        assert!(mtu.snapshot().probing, "a probe should now be in flight");
        assert_eq!(
            mtu.effective_mtu(),
            reduced,
            "probing must not change effective MTU yet"
        );

        {
            let mut state = mtu.state.lock().unwrap();
            state.probe_started = Some(Instant::now() - AdaptiveMtu::PROBE_EVALUATION_WINDOW);
        }
        for _ in 0..AdaptiveMtu::PROBE_SUCCESS_THRESHOLD {
            mtu.record_success();
        }
        assert!(mtu.effective_mtu() > reduced);
        assert!(mtu.effective_mtu() <= 1400);
    }

    #[test]
    fn failure_during_probe_reverts_it() {
        let mtu = AdaptiveMtu::new(1400, 576);
        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::FAILURE_THRESHOLD {
            mtu.record_path_failure();
        }
        let reduced = mtu.effective_mtu();
        expire_cooldown(&mtu);
        for _ in 0..AdaptiveMtu::SUCCESS_THRESHOLD {
            mtu.record_success();
        }
        assert!(mtu.snapshot().probing);
        mtu.record_path_failure();
        assert!(!mtu.snapshot().probing);
        assert_eq!(mtu.effective_mtu(), reduced);
    }
}
