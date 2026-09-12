use thiserror::Error;

/// Number of `u64` words in the bitmap — 32 × 64 = 2 048 sequence-number window.
const WORDS: usize = 32;
const WINDOW: u64 = (WORDS as u64) * 64;

/// A 2 048-packet anti-replay window for one `(session, key phase)`.
///
/// The window is implemented as an array of 32 × `u64` bitmaps (2 048 bits total),
/// which gives the receiver enough headroom to tolerate aggressive OS scheduling
/// jitter and out-of-order delivery at 10 Gbps before discarding legitimate packets.
/// WireGuard uses 2 048 as well; RFC 4303 specifies 64 as the minimum.
#[derive(Debug)]
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
    /// Records a fresh sequence or rejects a duplicate/too-old sequence.
    pub fn check_and_record(&mut self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.set_bit(sequence);
            return Ok(());
        };

        if sequence > highest {
            let shift = sequence - highest;
            if shift >= WINDOW {
                // The entire old window falls outside the new position; reset.
                self.seen = [0; WORDS];
            } else {
                self.shift_window(shift);
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

    /// Sets the bit corresponding to `sequence` in the circular bitmap.
    fn set_bit(&mut self, sequence: u64) {
        let idx = (sequence % WINDOW) as usize;
        self.seen[idx / 64] |= 1_u64 << (idx % 64);
    }

    /// Returns `true` if the bit for `sequence` is already set.
    fn test_bit(&self, sequence: u64) -> bool {
        let idx = (sequence % WINDOW) as usize;
        self.seen[idx / 64] & (1_u64 << (idx % 64)) != 0
    }

    /// Clears the bitmap slots that are about to be reused by the `shift` new
    /// sequences advancing past `highest`.  Each incoming sequence wraps into
    /// the circular buffer at `(seq % WINDOW)`, so we must zero the slot before
    /// the new sequence lands in it.
    fn shift_window(&mut self, shift: u64) {
        let highest = self.highest.expect("called only when highest is Some");
        for s in 1..=shift {
            let seq = highest + s;
            let idx = (seq % WINDOW) as usize;
            self.seen[idx / 64] &= !(1_u64 << (idx % 64));
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
        // Establish highest at 2047.
        window.check_and_record(2047).unwrap();
        // Sequence 0 is exactly at the edge of the window (offset = 2047 < 2048).
        window.check_and_record(0).unwrap();
        // Advance to 2048; now sequence 0 falls outside (offset = 2048 >= 2048).
        window.check_and_record(2048).unwrap();
        assert_eq!(window.check_and_record(0), Err(ReplayError::TooOld));
    }

    #[test]
    fn duplicate_is_rejected_within_large_window() {
        let mut window = ReplayWindow::default();
        window.check_and_record(1000).unwrap();
        window.check_and_record(1500).unwrap();
        // 1000 is within 2048 of 1500; must be detected as duplicate.
        assert_eq!(window.check_and_record(1000), Err(ReplayError::Duplicate));
    }

    #[test]
    fn full_reset_when_advance_exceeds_window() {
        let mut window = ReplayWindow::default();
        window.check_and_record(0).unwrap();
        // Jump well beyond the window.
        window.check_and_record(9999).unwrap();
        // Old sequence 0 is now too old.
        assert_eq!(window.check_and_record(0), Err(ReplayError::TooOld));
        // New sequence just behind highest must be accepted.
        window.check_and_record(9998).unwrap();
    }
}
