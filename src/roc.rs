//! Rollover-counter (ROC) management (RFC 3711 §3.3.1 and Appendix A).
//!
//! RTP carries only a 16-bit sequence number, but SRTP needs a 48-bit packet
//! index `i = 2^16 * ROC + SEQ` to build a unique per-packet IV. The ROC is the
//! number of times the 16-bit sequence number has wrapped. It is never sent on
//! the wire, so each endpoint maintains it locally: the sender simply counts
//! wraps, and the receiver *estimates* the ROC of every incoming packet from
//! the highest sequence number seen so far using the algorithm in Appendix A.

/// Half of the 16-bit sequence-number space; the wrap-detection threshold.
const SEQ_HALF: i32 = 0x8000;
/// Size of the 16-bit sequence-number space.
const SEQ_MOD: i64 = 0x1_0000;

/// Compute the 48-bit packet index from a ROC and a 16-bit sequence number.
#[must_use]
pub const fn packet_index(roc: u32, seq: u16) -> u64 {
    (roc as u64) * (SEQ_MOD as u64) + (seq as u64)
}

/// Sender-side ROC tracking: the sequence number is assumed to advance
/// monotonically, so the ROC is incremented whenever the sequence number wraps
/// past zero.
#[derive(Debug, Clone, Default)]
pub struct SenderRoc {
    roc: u32,
    last_seq: Option<u16>,
}

impl SenderRoc {
    /// A fresh sender ROC starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            roc: 0,
            last_seq: None,
        }
    }

    /// Record an outgoing sequence number and return the ROC to use for it.
    pub fn next(&mut self, seq: u16) -> u32 {
        if let Some(prev) = self.last_seq {
            // A wrap is a large backwards jump (prev near 0xFFFF, seq near 0).
            if seq < prev && (i32::from(prev) - i32::from(seq)) > SEQ_HALF {
                self.roc = self.roc.wrapping_add(1);
            }
        }
        self.last_seq = Some(seq);
        self.roc
    }

    /// The current ROC value.
    #[must_use]
    pub const fn roc(&self) -> u32 {
        self.roc
    }
}

/// Receiver-side ROC estimation (RFC 3711 Appendix A).
///
/// The receiver keeps the highest sequence number it has accepted (`s_l`) and
/// the ROC associated with it. For each incoming packet it guesses which ROC
/// the sender must have used, which may be the current ROC, one less (a late
/// packet from before the most recent wrap), or one more (a packet from just
/// after a wrap that arrived before `s_l` caught up).
#[derive(Debug, Clone, Default)]
pub struct ReceiverRoc {
    roc: u32,
    s_l: Option<u16>,
}

impl ReceiverRoc {
    /// A fresh receiver ROC with no packets seen yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { roc: 0, s_l: None }
    }

    /// The current ROC value (for the highest sequence number seen).
    #[must_use]
    pub const fn roc(&self) -> u32 {
        self.roc
    }

    /// The highest sequence number accepted so far, if any.
    #[must_use]
    pub const fn highest_seq(&self) -> Option<u16> {
        self.s_l
    }

    /// Estimate the ROC and 48-bit index for an incoming sequence number
    /// without mutating any state (RFC 3711 Appendix A `guess` step).
    #[must_use]
    pub fn estimate(&self, seq: u16) -> (u32, u64) {
        let Some(s_l) = self.s_l else {
            // First packet: ROC is whatever we have (zero by default).
            return (self.roc, packet_index(self.roc, seq));
        };

        let seq_i = i32::from(seq);
        let s_l_i = i32::from(s_l);
        let v = if s_l_i < SEQ_HALF {
            if seq_i.wrapping_sub(s_l_i) > SEQ_HALF {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if s_l_i.wrapping_sub(SEQ_HALF) > seq_i {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        };

        (v, packet_index(v, seq))
    }

    /// Commit an accepted packet, advancing `s_l`/ROC if this packet's index is
    /// the new highest. `guessed_roc` must be the value returned by
    /// [`ReceiverRoc::estimate`] for `seq`.
    pub fn update(&mut self, seq: u16, guessed_roc: u32) {
        let new_index = packet_index(guessed_roc, seq);
        let cur_index = self.s_l.map_or(0, |s_l| packet_index(self.roc, s_l));
        if self.s_l.is_none() || new_index >= cur_index {
            self.roc = guessed_roc;
            self.s_l = Some(seq);
        }
    }
}
