//! Anti-replay protection with a sliding window (RFC 3711 §3.3.2).
//!
//! Each receiving SRTP/SRTCP context keeps the highest packet index it has
//! authenticated and a bitmap of which of the preceding indices have already
//! been seen. A packet is rejected if its index is at or below the
//! trailing edge of the window, or if its bit inside the window is already set.
//!
//! Per RFC 3711 the replay check is performed *before* decryption for the
//! initial bounds test and the accepted index is only committed *after* the
//! authentication tag verifies, so this type separates [`ReplayWindow::check`]
//! from [`ReplayWindow::mark`].

use crate::error::{Result, SrtpError};

#[allow(missing_docs)]
pub const MIN_WINDOW_SIZE: usize = 64;
#[allow(missing_docs)]
pub const MAX_WINDOW_SIZE: usize = 1024;
#[allow(missing_docs)]
pub const DEFAULT_WINDOW_SIZE: usize = MAX_WINDOW_SIZE;

const WORDS: usize = MAX_WINDOW_SIZE / 64;

/// A sliding replay window keyed on the 48-bit (SRTP) or 31-bit (SRTCP)
/// packet index.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest index accepted so far. `None` until the first packet.
    highest: Option<u64>,
    /// Bitmap of seen indices: bit `index % MAX_WINDOW_SIZE` records `index`
    /// for the indices inside the window.
    bitmap: [u64; WORDS],
    size: usize,
}

/// Outcome of a replay-window bounds check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// The index is fresh and may be processed.
    Ok,
    /// The index has already been seen or is too old; reject it.
    Replayed,
}

const fn bit(index: u64) -> (usize, u64) {
    let position = (index % MAX_WINDOW_SIZE as u64) as usize;
    (position / 64, 1 << (position % 64))
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// A fresh, empty replay window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: [0; WORDS],
            size: DEFAULT_WINDOW_SIZE,
        }
    }

    #[allow(missing_docs)]
    pub fn with_size(size: usize) -> Result<Self> {
        if !(MIN_WINDOW_SIZE..=MAX_WINDOW_SIZE).contains(&size) {
            return Err(SrtpError::InvalidReplayWindow(size));
        }
        Ok(Self {
            size,
            ..Self::new()
        })
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Test whether `index` is acceptable, without mutating the window.
    ///
    /// Call this before authenticating a packet; only after the tag verifies
    /// should the index be committed with [`ReplayWindow::mark`].
    #[must_use]
    pub const fn check(&self, index: u64) -> ReplayCheck {
        let Some(highest) = self.highest else {
            return ReplayCheck::Ok;
        };
        if index > highest {
            return ReplayCheck::Ok;
        }
        if highest - index >= self.size as u64 {
            // Older than the trailing edge of the window.
            return ReplayCheck::Replayed;
        }
        let (word, mask) = bit(index);
        if self.bitmap[word] & mask == 0 {
            ReplayCheck::Ok
        } else {
            ReplayCheck::Replayed
        }
    }

    /// Commit an authenticated `index`, sliding the window forward if needed.
    ///
    /// Should only be called after [`ReplayWindow::check`] returned
    /// [`ReplayCheck::Ok`] and the packet authenticated.
    pub fn mark(&mut self, index: u64) {
        match self.highest {
            Some(highest) if index <= highest => {
                if highest - index < self.size as u64 {
                    self.set(index);
                }
            }
            Some(highest) if index - highest < MAX_WINDOW_SIZE as u64 => {
                for skipped in highest + 1..index {
                    let (word, mask) = bit(skipped);
                    self.bitmap[word] &= !mask;
                }
                self.set(index);
                self.highest = Some(index);
            }
            _ => {
                self.bitmap = [0; WORDS];
                self.set(index);
                self.highest = Some(index);
            }
        }
    }

    fn set(&mut self, index: u64) {
        let (word, mask) = bit(index);
        self.bitmap[word] |= mask;
    }

    /// The highest index accepted so far, if any.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }
}
