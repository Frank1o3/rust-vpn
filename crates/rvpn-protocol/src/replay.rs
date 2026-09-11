use thiserror::Error;

/// A bounded 64-packet anti-replay window for one `(session, key phase)`.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    /// Records a fresh sequence or rejects a duplicate/too-old sequence.
    pub fn check_and_record(&mut self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen = 1;
            return Ok(());
        };
        if sequence > highest {
            let shift = sequence - highest;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = Some(sequence);
            return Ok(());
        }
        let offset = highest - sequence;
        if offset >= 64 {
            return Err(ReplayError::TooOld);
        }
        let bit = 1_u64 << offset;
        if self.seen & bit != 0 {
            return Err(ReplayError::Duplicate);
        }
        self.seen |= bit;
        Ok(())
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
        window.check_and_record(100).unwrap();
        assert_eq!(window.check_and_record(10), Err(ReplayError::TooOld));
    }
}
