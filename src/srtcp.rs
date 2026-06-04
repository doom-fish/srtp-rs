//! SRTCP protection (RFC 3711 §3.4, RFC 7714 §9).
//!
//! SRTCP differs from SRTP in three ways:
//!
//! * The first 8 octets of the RTCP compound packet (version/type/length and
//!   the sender SSRC) are left in the clear; only the bytes from octet 8 onward
//!   are encrypted.
//! * A 4-octet trailer is appended carrying a 1-bit **E flag** (set when the
//!   packet is encrypted) and a 31-bit **SRTCP index** that replaces the
//!   `ROC || SEQ` packet index used by SRTP.
//! * The index is explicit on the wire, so the receiver reads it directly
//!   instead of estimating a rollover counter.

use crate::decrypt::verify_hmac;
use crate::encrypt::{aes_cm_xor, gcm_open, gcm_seal, hmac_sha1_tag, srtcp_cm_iv, srtcp_gcm_iv};
use crate::error::{Result, SrtpError};
use crate::replay::{ReplayCheck, ReplayWindow};
use crate::session::SrtpKey;

/// Number of clear-header octets at the start of every SRTCP packet.
const HEADER_CLEAR: usize = 8;
/// Width of the appended `E || SRTCP index` trailer.
const TRAILER_LEN: usize = 4;
/// The E flag, set in the trailer when the packet body is encrypted.
const E_FLAG: u32 = 0x8000_0000;
/// Mask for the 31-bit SRTCP index.
const INDEX_MASK: u32 = 0x7FFF_FFFF;

/// An SRTCP context for one direction of one session.
#[derive(Debug)]
pub struct SrtcpSession {
    key: SrtpKey,
    index: u32,
    replay: ReplayWindow,
}

impl SrtcpSession {
    /// Create the sending half of an SRTCP session. The SRTCP index starts at
    /// zero and increments after each protected packet.
    #[must_use]
    pub const fn new_sender(key: SrtpKey) -> Self {
        Self {
            key,
            index: 0,
            replay: ReplayWindow::new(),
        }
    }

    /// Create the receiving half of an SRTCP session.
    #[must_use]
    pub const fn new_receiver(key: SrtpKey) -> Self {
        Self::new_sender(key)
    }

    /// Override the next SRTCP index the sender will use.
    ///
    /// Primarily useful for resuming an externally-sequenced stream and for
    /// reproducing the published SRTCP test vectors, which fix the index.
    pub fn set_index(&mut self, index: u32) {
        self.index = index & INDEX_MASK;
    }

    /// The next SRTCP index that will be used (sender) or the highest index
    /// accepted so far is tracked separately by the replay window (receiver).
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Protect an RTCP compound packet, writing the SRTCP packet into `out` and
    /// returning the number of bytes written.
    ///
    /// # Errors
    /// Returns [`SrtpError::TooShort`] if `rtcp` is shorter than the 8-octet
    /// clear header, [`SrtpError::OutputTooSmall`] if `out` is too small, or
    /// [`SrtpError::Crypto`] on a cipher failure.
    pub fn protect(&mut self, rtcp: &[u8], out: &mut [u8]) -> Result<usize> {
        if rtcp.len() < HEADER_CLEAR {
            return Err(SrtpError::TooShort);
        }
        let (enc_key, salt, auth_key) = self.key.srtcp_material();
        let profile = self.key.profile();
        let index = self.index;
        let ssrc = u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]);
        let esrtcp = (index & INDEX_MASK) | E_FLAG;
        let esrtcp_bytes = esrtcp.to_be_bytes();

        let header = &rtcp[..HEADER_CLEAR];
        let body = &rtcp[HEADER_CLEAR..];

        let written = if profile.is_aead() {
            let needed = HEADER_CLEAR + body.len() + profile.tag_len() + TRAILER_LEN;
            if out.len() < needed {
                return Err(SrtpError::OutputTooSmall {
                    needed,
                    provided: out.len(),
                });
            }
            let iv = srtcp_gcm_iv(salt, ssrc, index);
            let mut aad = Vec::with_capacity(HEADER_CLEAR + TRAILER_LEN);
            aad.extend_from_slice(header);
            aad.extend_from_slice(&esrtcp_bytes);
            let ct = gcm_seal(enc_key, &iv, &aad, body)?;

            out[..HEADER_CLEAR].copy_from_slice(header);
            out[HEADER_CLEAR..HEADER_CLEAR + ct.len()].copy_from_slice(&ct);
            let trailer_at = HEADER_CLEAR + ct.len();
            out[trailer_at..trailer_at + TRAILER_LEN].copy_from_slice(&esrtcp_bytes);
            trailer_at + TRAILER_LEN
        } else {
            let needed = HEADER_CLEAR + body.len() + TRAILER_LEN + profile.tag_len();
            if out.len() < needed {
                return Err(SrtpError::OutputTooSmall {
                    needed,
                    provided: out.len(),
                });
            }
            out[..HEADER_CLEAR].copy_from_slice(header);
            let enc = &mut out[HEADER_CLEAR..HEADER_CLEAR + body.len()];
            enc.copy_from_slice(body);
            let iv = srtcp_cm_iv(salt, ssrc, index);
            aes_cm_xor(enc_key, &iv, enc)?;

            let trailer_at = HEADER_CLEAR + body.len();
            out[trailer_at..trailer_at + TRAILER_LEN].copy_from_slice(&esrtcp_bytes);
            let body_end = trailer_at + TRAILER_LEN;
            let tag = hmac_sha1_tag(auth_key, &out[..body_end], profile.tag_len());
            out[body_end..body_end + tag.len()].copy_from_slice(&tag);
            body_end + tag.len()
        };

        self.index = (self.index + 1) & INDEX_MASK;
        Ok(written)
    }

    /// Unprotect an SRTCP packet, returning the recovered RTCP compound packet.
    ///
    /// # Errors
    /// Returns [`SrtpError::TooShort`] if the framing is incomplete,
    /// [`SrtpError::Replay`] if the SRTCP index is a replay,
    /// [`SrtpError::AuthFailed`] if authentication fails, or
    /// [`SrtpError::Crypto`] on a cipher failure.
    pub fn unprotect(&mut self, srtcp: &[u8]) -> Result<Vec<u8>> {
        let (enc_key, salt, auth_key) = self.key.srtcp_material();
        let profile = self.key.profile();
        let tag_len = profile.tag_len();

        if profile.is_aead() {
            // Layout: header(8) || ciphertext+tag || E||index(4)
            if srtcp.len() < HEADER_CLEAR + tag_len + TRAILER_LEN {
                return Err(SrtpError::TooShort);
            }
            let trailer_at = srtcp.len() - TRAILER_LEN;
            let esrtcp = u32::from_be_bytes([
                srtcp[trailer_at],
                srtcp[trailer_at + 1],
                srtcp[trailer_at + 2],
                srtcp[trailer_at + 3],
            ]);
            let index = esrtcp & INDEX_MASK;
            if self.replay.check(u64::from(index)) == ReplayCheck::Replayed {
                return Err(SrtpError::Replay);
            }
            let ssrc = u32::from_be_bytes([srtcp[4], srtcp[5], srtcp[6], srtcp[7]]);
            let iv = srtcp_gcm_iv(salt, ssrc, index);
            let mut aad = Vec::with_capacity(HEADER_CLEAR + TRAILER_LEN);
            aad.extend_from_slice(&srtcp[..HEADER_CLEAR]);
            aad.extend_from_slice(&srtcp[trailer_at..]);
            let ct = &srtcp[HEADER_CLEAR..trailer_at];
            let pt = gcm_open(enc_key, &iv, &aad, ct)?;

            self.replay.mark(u64::from(index));
            let mut out = Vec::with_capacity(HEADER_CLEAR + pt.len());
            out.extend_from_slice(&srtcp[..HEADER_CLEAR]);
            out.extend_from_slice(&pt);
            Ok(out)
        } else {
            // Layout: header(8) || ciphertext || E||index(4) || tag
            if srtcp.len() < HEADER_CLEAR + TRAILER_LEN + tag_len {
                return Err(SrtpError::TooShort);
            }
            let body_end = srtcp.len() - tag_len;
            let trailer_at = body_end - TRAILER_LEN;
            let esrtcp = u32::from_be_bytes([
                srtcp[trailer_at],
                srtcp[trailer_at + 1],
                srtcp[trailer_at + 2],
                srtcp[trailer_at + 3],
            ]);
            let index = esrtcp & INDEX_MASK;
            if self.replay.check(u64::from(index)) == ReplayCheck::Replayed {
                return Err(SrtpError::Replay);
            }
            verify_hmac(auth_key, &srtcp[..body_end], &srtcp[body_end..])?;

            let ssrc = u32::from_be_bytes([srtcp[4], srtcp[5], srtcp[6], srtcp[7]]);
            let mut out = Vec::with_capacity(trailer_at);
            out.extend_from_slice(&srtcp[..trailer_at]);
            if esrtcp & E_FLAG != 0 {
                let iv = srtcp_cm_iv(salt, ssrc, index);
                aes_cm_xor(enc_key, &iv, &mut out[HEADER_CLEAR..])?;
            }

            self.replay.mark(u64::from(index));
            Ok(out)
        }
    }
}
