//! Error type for SRTP / SRTCP processing.

use core::fmt;

/// Errors returned by SRTP / SRTCP protect and unprotect operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum SrtpError {
    /// The AEAD authentication tag (or HMAC) did not verify. The packet has
    /// been tampered with, corrupted, or keyed incorrectly.
    AuthFailed,
    /// The packet's index falls inside the replay window and has already been
    /// seen, or it is older than the trailing edge of the window.
    Replay,
    /// The supplied output buffer is too small to hold the protected packet.
    OutputTooSmall {
        /// Bytes the operation needed.
        needed: usize,
        /// Bytes the caller provided.
        provided: usize,
    },
    /// The input slice is shorter than the minimum valid SRTP/SRTCP framing.
    TooShort,
    /// A key or salt length did not match the chosen [`crate::Profile`].
    BadKeyLength {
        /// Bytes the profile expects.
        expected: usize,
        /// Bytes that were supplied.
        actual: usize,
    },
    /// The underlying `rtp` codec failed to parse the packet.
    Rtp(rtp::Error),
    /// A platform crypto primitive (CommonCrypto / CryptoKit) failed.
    Crypto(String),
    #[allow(missing_docs)]
    KeyExpired,
    #[allow(missing_docs)]
    IndexReused,
    #[allow(missing_docs)]
    SessionKeyReuse,
    #[allow(missing_docs)]
    InvalidReplayWindow(usize),
    #[allow(missing_docs)]
    Unencrypted,
}

impl fmt::Display for SrtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => f.write_str("SRTP authentication tag verification failed"),
            Self::Replay => f.write_str("SRTP replay check rejected the packet"),
            Self::OutputTooSmall { needed, provided } => write!(
                f,
                "output buffer too small: need {needed} bytes, have {provided}"
            ),
            Self::TooShort => f.write_str("packet shorter than the minimum SRTP/SRTCP framing"),
            Self::BadKeyLength { expected, actual } => {
                write!(f, "bad key/salt length: expected {expected}, got {actual}")
            }
            Self::Rtp(e) => write!(f, "RTP codec error: {e}"),
            Self::Crypto(msg) => write!(f, "platform crypto error: {msg}"),
            Self::KeyExpired => f.write_str(
                "SRTP key lifetime exhausted (2^48 SRTP or 2^31 SRTCP packets); rekey",
            ),
            Self::IndexReused => f.write_str(
                "packet index already protected with this key; reusing it would repeat the keystream",
            ),
            Self::SessionKeyReuse => f.write_str("SRTP and SRTCP must use different session keys"),
            Self::InvalidReplayWindow(size) => write!(
                f,
                "replay window must hold {} to {} packets, got {size}",
                crate::replay::MIN_WINDOW_SIZE,
                crate::replay::MAX_WINDOW_SIZE
            ),
            Self::Unencrypted => {
                f.write_str("SRTCP packet is not encrypted but the session requires encryption")
            }
        }
    }
}

impl std::error::Error for SrtpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rtp(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rtp::Error> for SrtpError {
    fn from(e: rtp::Error) -> Self {
        Self::Rtp(e)
    }
}

/// Convenience alias for results returned by this crate.
pub type Result<T> = core::result::Result<T, SrtpError>;
