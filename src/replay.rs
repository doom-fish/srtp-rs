//! Anti-replay protection with a 64-bit sliding window (RFC 3711 §3.3.2).
//!
//! Each receiving SRTP/SRTCP context keeps the highest packet index it has
//! authenticated and a 64-entry bitmap of which of the preceding indices have
//! already been seen. A packet is rejected if its index is at or below the
//! trailing edge of the window, or if its bit inside the window is already set.
//!
//! Per RFC 3711 the replay check is performed *before* decryption for the
//! initial bounds test and the accepted index is only committed *after* the
//! authentication tag verifies, so this type separates [`ReplayWindow::check`]
//! from [`ReplayWindow::mark`].

/// Width of the sliding replay window, in packets.
pub const WINDOW_SIZE: u64 = 64;

/// A 64-bit sliding replay window keyed on the 48-bit (SRTP) or 31-bit (SRTCP)
/// packet index.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    /// Highest index accepted so far. `None` until the first packet.
    highest: Option<u64>,
    /// Bitmap of seen indices: bit `n` corresponds to index `highest - n`.
    bitmap: u64,
}

/// Outcome of a replay-window bounds check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// The index is fresh and may be processed.
    Ok,
    /// The index has already been seen or is too old; reject it.
    Replayed,
}

impl ReplayWindow {
    /// A fresh, empty replay window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
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
        let delta = highest - index;
        if delta >= WINDOW_SIZE {
            // Older than the trailing edge of the window.
            return ReplayCheck::Replayed;
        }
        if (self.bitmap >> delta) & 1 == 1 {
            ReplayCheck::Replayed
        } else {
            ReplayCheck::Ok
        }
    }

    /// Commit an authenticated `index`, sliding the window forward if needed.
    ///
    /// Should only be called after [`ReplayWindow::check`] returned
    /// [`ReplayCheck::Ok`] and the packet authenticated.
    pub fn mark(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.bitmap = 1; // bit 0 == this (the highest) index
            }
            Some(highest) if index > highest => {
                let shift = index - highest;
                if shift >= WINDOW_SIZE {
                    self.bitmap = 1;
                } else {
                    self.bitmap = (self.bitmap << shift) | 1;
                }
                self.highest = Some(index);
            }
            Some(highest) => {
                let delta = highest - index;
                if delta < WINDOW_SIZE {
                    self.bitmap |= 1 << delta;
                }
            }
        }
    }

    /// The highest index accepted so far, if any.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }
}
