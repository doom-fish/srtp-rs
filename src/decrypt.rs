//! Authentication-tag verification helpers used by the `unprotect` direction.
//!
//! [`crate::encrypt`] owns the cipher and IV machinery; this module owns the
//! constant-time tag comparison that gates whether a decrypted packet is
//! accepted. AES-GCM tag verification happens inside CryptoKit
//! ([`crate::encrypt::gcm_open`]); the AES-CM profiles authenticate with a
//! truncated HMAC-SHA1 that must be compared here in constant time.

use crate::encrypt::hmac_sha1_tag;
use crate::error::{Result, SrtpError};

/// Constant-time equality test for two byte slices of equal length.
///
/// Returns `false` immediately for a length mismatch (the lengths are not
/// secret), otherwise compares every byte without an early exit so the timing
/// of a comparison does not leak how many leading bytes matched.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify the truncated HMAC-SHA1 tag of an AES-CM profile.
///
/// `authenticated` is the byte range the tag covers (the SRTP/SRTCP packet
/// bytes, including the appended ROC for SRTP). `tag` is the received tag.
///
/// # Errors
/// Returns [`SrtpError::AuthFailed`] if the recomputed tag does not match.
pub fn verify_hmac(auth_key: &[u8], authenticated: &[u8], tag: &[u8]) -> Result<()> {
    let expected = hmac_sha1_tag(auth_key, authenticated, tag.len());
    if ct_eq(&expected, tag) {
        Ok(())
    } else {
        Err(SrtpError::AuthFailed)
    }
}
