use thiserror::Error;

const WORDS: usize = 32;
const WINDOW: u64 = (WORDS as u64) * 64;

#[derive(Clone, Debug)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: [0; WORDS],
        }
    }
}

impl ReplayWindow {
    pub fn check_and_record(&mut self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.set_bit(sequence);
            return Ok(());
        };

        if sequence > highest {
            let shift = sequence - highest;
            if shift >= WINDOW {
                self.seen = [0; WORDS];
            } else {
                self.clear_range(highest, shift);
            }
            self.highest = Some(sequence);
            self.set_bit(sequence);
            return Ok(());
        }

        let offset = highest - sequence;
        if offset >= WINDOW {
            return Err(ReplayError::TooOld);
        }
        if self.test_bit(sequence) {
            return Err(ReplayError::Duplicate);
        }
        self.set_bit(sequence);
        Ok(())
    }

    fn set_bit(&mut self, sequence: u64) {
        let idx = (sequence % WINDOW) as usize;
        self.seen[idx / 64] |= 1_u64 << (idx % 64);
    }

    fn test_bit(&self, sequence: u64) -> bool {
        let idx = (sequence % WINDOW) as usize;
        self.seen[idx / 64] & (1_u64 << (idx % 64)) != 0
    }

    fn clear_range(&mut self, highest: u64, shift: u64) {
        debug_assert!(shift < WINDOW);
        if shift == 0 {
            return;
        }

        let start = ((highest + 1) % WINDOW) as usize;
        let mut word = start / 64;
        let mut bit_offset = start % 64;
        let mut remaining = shift;

        while remaining > 0 {
            let bits_here = remaining.min(64 - bit_offset as u64) as u32;
            let mask: u64 = if bits_here == 64 {
                u64::MAX
            } else {
                ((1_u64 << bits_here) - 1) << bit_offset
            };
            self.seen[word] &= !mask;

            remaining -= u64::from(bits_here);
            word = (word + 1) % WORDS;
            bit_offset = 0;
        }
    }
}

/// Replay-window rejection reason.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("packet sequence was already received")]
    Duplicate,
    #[error("packet sequence is outside the replay window")]
    TooOld,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reordering_but_rejects_duplicates_and_old_packets() {
        let mut window = ReplayWindow::default();
        for sequence in [10, 12, 11] {
            window.check_and_record(sequence).unwrap();
        }
        assert_eq!(window.check_and_record(11), Err(ReplayError::Duplicate));
        window.check_and_record(2100).unwrap();
        assert_eq!(window.check_and_record(10), Err(ReplayError::TooOld));
    }

    #[test]
    fn window_width_is_2048() {
        let mut window = ReplayWindow::default();
        window.check_and_record(2047).unwrap();
        window.check_and_record(0).unwrap();
        window.check_and_record(2048).unwrap();
        assert_eq!(window.check_and_record(0), Err(ReplayError::TooOld));
    }

    #[test]
    fn duplicate_is_rejected_within_large_window() {
        let mut window = ReplayWindow::default();
        window.check_and_record(1000).unwrap();
        window.check_and_record(1500).unwrap();
        assert_eq!(window.check_and_record(1000), Err(ReplayError::Duplicate));
    }

    #[test]
    fn full_reset_when_advance_exceeds_window() {
        let mut window = ReplayWindow::default();
        window.check_and_record(0).unwrap();
        window.check_and_record(9999).unwrap();
        assert_eq!(window.check_and_record(0), Err(ReplayError::TooOld));
        window.check_and_record(9998).unwrap();
    }

    #[test]
    fn shift_smaller_than_one_word_clears_only_the_entering_bits() {
        let mut window = ReplayWindow::default();
        window.check_and_record(100).unwrap();

        // Simulate stale ring-buffer bits occupying the slots that are about
        // to be reused by the small forward shift.
        for sequence in 101..=105 {
            window.set_bit(sequence);
        }

        window.check_and_record(105).unwrap();

        assert_eq!(window.check_and_record(100), Err(ReplayError::Duplicate));
        for sequence in 101..105 {
            assert!(!window.test_bit(sequence));
        }
        assert!(window.test_bit(105));
    }

    #[test]
    fn shift_exactly_divisible_by_word_size() {
        let mut window = ReplayWindow::default();
        window.check_and_record(0).unwrap();
        window.check_and_record(128).unwrap();
        window.check_and_record(1).unwrap();
        assert_eq!(window.check_and_record(1), Err(ReplayError::Duplicate));
        assert_eq!(window.check_and_record(128), Err(ReplayError::Duplicate));
    }

    #[test]
    fn shift_crossing_a_word_boundary_clears_only_the_right_bits() {
        let mut window = ReplayWindow::default();
        window.check_and_record(60).unwrap();
        window.check_and_record(70).unwrap();
        for seq in 61..70 {
            window.check_and_record(seq).unwrap();
        }
        assert_eq!(window.check_and_record(70), Err(ReplayError::Duplicate));
    }

    #[test]
    fn shift_just_under_window_width_clears_almost_everything_in_bounded_time() {
        let mut window = ReplayWindow::default();
        window.check_and_record(0).unwrap();

        // Fill every ring slot to verify that a near-window-width shift
        // clears exactly the entering range while preserving the old edge.
        window.seen.fill(u64::MAX);

        window.check_and_record(WINDOW - 1).unwrap();

        assert!(window.test_bit(0));
        for sequence in 1..WINDOW - 1 {
            assert!(!window.test_bit(sequence));
        }
        assert!(window.test_bit(WINDOW - 1));
        assert_eq!(window.check_and_record(0), Err(ReplayError::Duplicate));
        assert_eq!(window.check_and_record(WINDOW - 1), Err(ReplayError::Duplicate));
    }

    #[test]
    fn shift_at_or_beyond_window_width_still_resets_fully() {
        let mut window = ReplayWindow::default();
        window.check_and_record(5).unwrap();
        window.check_and_record(5 + WINDOW).unwrap();
        assert_eq!(window.check_and_record(5), Err(ReplayError::TooOld));
        window.check_and_record(5 + WINDOW).unwrap_err();
    }

    #[test]
    fn sequence_values_near_u64_max_do_not_overflow() {
        let mut window = ReplayWindow::default();
        let near_max = u64::MAX - 5;
        window.check_and_record(near_max).unwrap();
        window.check_and_record(u64::MAX).unwrap();
        assert_eq!(
            window.check_and_record(near_max),
            Err(ReplayError::Duplicate)
        );
    }
}
