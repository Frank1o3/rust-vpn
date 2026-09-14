//! Adaptive effective-MTU tracking, decoupled from any specific platform.
//!
//! Configuration supplies a *target* MTU (the operator's preference) and a
//! *minimum* MTU (the floor RVPN will not shrink below). The transport
//! maintains a separate *effective* MTU that starts at the target and only
//! moves in response to sustained, distinguishable evidence:
//!
//! * a hard, authoritative "too large" signal (the OS reporting `EMSGSIZE`
//!   on send) drops the effective MTU immediately, because the evidence is
//!   unambiguous;
//! * a *soft* signal -- repeated caller-reported path failures -- only
//!   drops the effective MTU after a sustained run of failures, and never
//!   more than once per [`AdaptiveMtu::MIN_CHANGE_INTERVAL`], to avoid
//!   reacting to an isolated lost packet;
//! * after a sustained run of successes *and* the cooldown has elapsed, the
//!   effective MTU is cautiously probed upward in small steps back toward
//!   the target, and only kept if the probe itself proves stable.
//!
//! This module intentionally has no notion of "congestion" -- queueing
//! delay and packet loss unrelated to size belong to [`crate::metrics`] and
//! the caller's own reliability/backpressure handling, not to MTU sizing.
//! The distinction matters: shrinking the MTU does nothing to relieve a
//! congested link, and would just waste path capacity while achieving
//! nothing to reduce it.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A single transition of the effective MTU, useful for logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtuChangeReason {
    /// The OS reported the datagram exceeded the path MTU.
    PathMtuExceeded,
    /// A sustained run of caller-reported path failures.
    SustainedInstability,
    /// A cautious upward probe after a sustained run of successes.
    ProbeUp,
    /// An upward probe was reverted after it failed to prove stable.
    ProbeReverted,
}

/// A point-in-time view of the adaptive MTU controller's state.
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
    /// Set while an upward probe's outcome is still being evaluated.
    probe_candidate: Option<usize>,
    probe_started: Option<Instant>,
}

/// Tracks a target/effective/minimum/maximum MTU and applies hysteresis so
/// the effective value only moves on real, sustained evidence.
#[derive(Debug)]
pub struct AdaptiveMtu {
    target_mtu: usize,
    minimum_mtu: usize,
    maximum_mtu: usize,
    effective_mtu: AtomicUsize,
    state: Mutex<MtuState>,
}

impl AdaptiveMtu {
    /// Consecutive soft failures required before shrinking the effective MTU.
    const FAILURE_THRESHOLD: u32 = 5;
    /// Consecutive successes required before a probe upward is attempted.
    const SUCCESS_THRESHOLD: u32 = 64;
    /// Minimum time between any two effective-MTU changes (hysteresis).
    const MIN_CHANGE_INTERVAL: Duration = Duration::from_secs(5);
    /// How long an upward probe is given to prove itself before committing.
    const PROBE_EVALUATION_WINDOW: Duration = Duration::from_secs(3);
    /// Successes required, once probing, to keep the probe.
    const PROBE_SUCCESS_THRESHOLD: u32 = 16;
    /// Fraction the effective MTU shrinks by on sustained soft failure.
    const STEP_DOWN_NUMERATOR: usize = 9;
    const STEP_DOWN_DENOMINATOR: usize = 10;
    /// Fraction of the remaining gap to target covered by one upward probe.
    const STEP_UP_NUMERATOR: usize = 1;
    const STEP_UP_DENOMINATOR: usize = 8;

    /// Creates a controller starting at `target_mtu`, the caller's preferred
    /// value. `minimum_mtu` is clamped to be no larger than `target_mtu`.
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

    /// The MTU higher layers should currently size packets against.
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

    /// Records a successful send at the current effective MTU. Feeds both
    /// the failure-streak reset and eligibility for an upward probe.
    ///
    /// Note this is a *weak* positive signal: it only means the local
    /// socket accepted the send, not that the datagram was actually
    /// delivered end-to-end. It is enough to avoid probing upward during an
    /// actively failing path, but genuine end-to-end confirmation (for
    /// example, from protocol-level acknowledgements) would make upward
    /// probing more confident -- see the crate-level "future work" notes.
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
                // Probing doesn't change the effective MTU yet -- only a
                // proven probe does, in the branch above.
            }
        }
        None
    }

    /// Records a caller-observed path failure (timeout, retransmit, etc.).
    /// This is a *soft* signal: it only shrinks the effective MTU once
    /// [`Self::FAILURE_THRESHOLD`] consecutive failures have accumulated
    /// and the change-interval cooldown has elapsed.
    pub fn record_path_failure(&self) -> Option<MtuChangeReason> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_successes = 0;

        if state.probe_candidate.is_some() {
            // A failure during an upward probe reverts it immediately --
            // no reason to keep testing a candidate that just failed.
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

    /// Records the OS's own, authoritative "this datagram exceeds the path
    /// MTU" signal (`EMSGSIZE`/`WSAEMSGSIZE`). Unlike
    /// [`Self::record_path_failure`], this is definitive evidence, not a
    /// heuristic, so it acts immediately rather than waiting for a
    /// sustained run -- but it still respects the change-interval cooldown
    /// to avoid thrashing against a flapping path, and it still steps down
    /// gradually rather than jumping straight to the floor.
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
        assert_eq!(mtu.effective_mtu(), before, "cooldown must suppress a second reduction");
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