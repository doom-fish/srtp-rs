//! Session keys and the SRTP `protect` / `unprotect` state machines.
//!
//! An [`SrtpKey`] holds the per-session encryption key, salt, and (for the
//! AES-CM profiles) authentication key for both the SRTP and SRTCP directions.
//! It can be built either by running the RFC 3711 key-derivation function over a
//! master key and salt ([`SrtpKey::from_master`]), which is what DTLS-SRTP
//! (RFC 5764) exports, or by injecting externally-derived session keys for
//! each direction ([`SrtpKey::from_session`]), which is what the RFC 7714 test
//! vectors provide.
//!
//! An [`SrtpSession`] binds a key to one direction (sender or receiver) and owns
//! the rollover counter and, for receivers, the replay window.

use rtp::{Packet, RtpPacket, RtpPacketMut};

use crate::decrypt::{ct_eq, verify_hmac};
use crate::encrypt::{aes_cm_xor, gcm_open, gcm_seal, hmac_sha1_tag, srtp_cm_iv, srtp_gcm_iv};
use crate::error::{Result, SrtpError};
use crate::kdf;
use crate::profile::Profile;
use crate::replay::{ReplayCheck, ReplayWindow};
use crate::roc::{ReceiverRoc, SenderRoc};

/// Derived session keying material for one SRTP/SRTCP session.
///
/// The same struct carries both the SRTP and SRTCP session keys because they
/// share a master key but use distinct KDF labels (RFC 3711 §4.3).
#[derive(Clone)]
pub struct SrtpKey {
    profile: Profile,
    srtp_enc: Vec<u8>,
    srtp_salt: Vec<u8>,
    srtp_auth: Vec<u8>,
    srtcp_enc: Vec<u8>,
    srtcp_salt: Vec<u8>,
    srtcp_auth: Vec<u8>,
}

#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub struct SessionKeys<'a> {
    pub encryption: &'a [u8],
    pub salt: &'a [u8],
    pub authentication: &'a [u8],
}

impl SessionKeys<'_> {
    fn check(self, profile: Profile) -> Result<()> {
        let lengths = [
            (profile.session_key_len(), self.encryption.len()),
            (profile.session_salt_len(), self.salt.len()),
            (profile.auth_key_len(), self.authentication.len()),
        ];
        for (expected, actual) in lengths {
            if expected != actual {
                return Err(SrtpError::BadKeyLength { expected, actual });
            }
        }
        Ok(())
    }
}

impl core::fmt::Debug for SrtpKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key bytes.
        f.debug_struct("SrtpKey")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl SrtpKey {
    /// Derive session keys from a master key and master salt using the RFC 3711
    /// key-derivation function.
    ///
    /// # Errors
    /// Returns [`SrtpError::BadKeyLength`] if `master_key` or `master_salt` do
    /// not match the lengths required by `profile`, or [`SrtpError::Crypto`] if
    /// the underlying AES-CTR PRF fails.
    pub fn from_master(master_key: &[u8], master_salt: &[u8], profile: Profile) -> Result<Self> {
        if master_key.len() != profile.master_key_len() {
            return Err(SrtpError::BadKeyLength {
                expected: profile.master_key_len(),
                actual: master_key.len(),
            });
        }
        if master_salt.len() != profile.master_salt_len() {
            return Err(SrtpError::BadKeyLength {
                expected: profile.master_salt_len(),
                actual: master_salt.len(),
            });
        }

        let enc_len = profile.session_key_len();
        let salt_len = profile.session_salt_len();
        let auth_len = profile.auth_key_len();

        Ok(Self {
            profile,
            srtp_enc: kdf::derive(master_key, master_salt, kdf::LABEL_SRTP_ENCRYPTION, enc_len)?,
            srtp_salt: kdf::derive(master_key, master_salt, kdf::LABEL_SRTP_SALT, salt_len)?,
            srtp_auth: kdf::derive(master_key, master_salt, kdf::LABEL_SRTP_AUTH, auth_len)?,
            srtcp_enc: kdf::derive(master_key, master_salt, kdf::LABEL_SRTCP_ENCRYPTION, enc_len)?,
            srtcp_salt: kdf::derive(master_key, master_salt, kdf::LABEL_SRTCP_SALT, salt_len)?,
            srtcp_auth: kdf::derive(master_key, master_salt, kdf::LABEL_SRTCP_AUTH, auth_len)?,
        })
    }

    /// Build a key directly from already-derived session material for the SRTP
    /// and the SRTCP direction.
    ///
    /// This is the constructor used with the RFC 7714 published test vectors,
    /// which specify session keys rather than master keys. DTLS-SRTP exports a
    /// master key and salt; use [`SrtpKey::from_master`] for those.
    ///
    /// # Errors
    /// Returns [`SrtpError::BadKeyLength`] if any length disagrees with
    /// `profile`, and [`SrtpError::SessionKeyReuse`] if both directions share
    /// an encryption key or (AES-CM) an authentication key: the SRTP and SRTCP
    /// IVs coincide, so one key for both would repeat the keystream.
    pub fn from_session(
        profile: Profile,
        media: SessionKeys<'_>,
        control: SessionKeys<'_>,
    ) -> Result<Self> {
        media.check(profile)?;
        control.check(profile)?;
        let shared_auth =
            profile.auth_key_len() > 0 && ct_eq(media.authentication, control.authentication);
        if ct_eq(media.encryption, control.encryption) || shared_auth {
            return Err(SrtpError::SessionKeyReuse);
        }

        Ok(Self {
            profile,
            srtp_enc: media.encryption.to_vec(),
            srtp_salt: media.salt.to_vec(),
            srtp_auth: media.authentication.to_vec(),
            srtcp_enc: control.encryption.to_vec(),
            srtcp_salt: control.salt.to_vec(),
            srtcp_auth: control.authentication.to_vec(),
        })
    }

    /// The negotiated protection profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    pub(crate) fn srtcp_material(&self) -> (&[u8], &[u8], &[u8]) {
        (&self.srtcp_enc, &self.srtcp_salt, &self.srtcp_auth)
    }
}

/// An SRTP context for one direction of one session.
///
/// A sender created with [`SrtpSession::new_sender`] turns RTP packets into SRTP
/// packets with [`SrtpSession::protect`]. A receiver created with
/// [`SrtpSession::new_receiver`] turns SRTP packets back into RTP packets with
/// [`SrtpSession::unprotect`], verifying authentication and rejecting replays.
#[derive(Debug)]
pub struct SrtpSession {
    key: SrtpKey,
    sender_roc: SenderRoc,
    receiver_roc: ReceiverRoc,
    replay: ReplayWindow,
}

impl SrtpSession {
    /// Create the sending half of an SRTP session.
    #[must_use]
    pub const fn new_sender(key: SrtpKey) -> Self {
        Self {
            key,
            sender_roc: SenderRoc::new(),
            receiver_roc: ReceiverRoc::new(),
            replay: ReplayWindow::new(),
        }
    }

    /// Create the receiving half of an SRTP session.
    #[must_use]
    pub const fn new_receiver(key: SrtpKey) -> Self {
        Self::new_sender(key)
    }

    #[allow(missing_docs)]
    pub fn with_replay_window(self, size: usize) -> Result<Self> {
        Ok(Self {
            replay: ReplayWindow::with_size(size)?,
            ..self
        })
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn with_roc(self, roc: u32) -> Self {
        Self {
            sender_roc: SenderRoc::with_roc(roc),
            receiver_roc: ReceiverRoc::with_roc(roc),
            ..self
        }
    }

    /// The negotiated protection profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.key.profile
    }

    /// The current rollover counter (sender side).
    #[must_use]
    pub const fn sender_roc(&self) -> u32 {
        self.sender_roc.roc()
    }

    /// Protect an RTP packet, writing the SRTP packet into `out` and returning
    /// the number of bytes written.
    ///
    /// The header is copied verbatim (it is authenticated, never re-encoded);
    /// the payload (and any RTP padding) is encrypted, and the authentication
    /// tag is appended.
    ///
    /// # Errors
    /// Returns [`SrtpError::OutputTooSmall`] if `out` cannot hold the protected
    /// packet, [`SrtpError::IndexReused`] if this packet index was already
    /// protected, [`SrtpError::KeyExpired`] once the `2^48`-packet key lifetime
    /// is used up, or [`SrtpError::Crypto`] on a cipher failure.
    pub fn protect<P: Packet>(&mut self, pkt: &P, out: &mut [u8]) -> Result<usize> {
        let wire = pkt.as_bytes();
        let payload_off = pkt.payload_offset();
        let header = &wire[..payload_off];
        let payload = &wire[payload_off..];
        let ssrc = pkt.header().ssrc();
        let seq = pkt.header().sequence_number();

        let needed = payload_off + payload.len() + self.key.profile.tag_len();
        if out.len() < needed {
            return Err(SrtpError::OutputTooSmall {
                needed,
                provided: out.len(),
            });
        }
        let roc = self.sender_roc.next(seq)?;

        out[..payload_off].copy_from_slice(header);

        if self.key.profile.is_aead() {
            let iv = srtp_gcm_iv(&self.key.srtp_salt, ssrc, roc, seq);
            let ct = gcm_seal(&self.key.srtp_enc, &iv, header, payload)?;
            out[payload_off..payload_off + ct.len()].copy_from_slice(&ct);
            Ok(payload_off + ct.len())
        } else {
            let iv = srtp_cm_iv(&self.key.srtp_salt, ssrc, roc, seq);
            let enc = &mut out[payload_off..payload_off + payload.len()];
            enc.copy_from_slice(payload);
            aes_cm_xor(&self.key.srtp_enc, &iv, enc)?;

            let body_end = payload_off + payload.len();
            let mut auth_input = out[..body_end].to_vec();
            auth_input.extend_from_slice(&roc.to_be_bytes());
            let tag = hmac_sha1_tag(&self.key.srtp_auth, &auth_input, self.key.profile.tag_len());
            out[body_end..body_end + tag.len()].copy_from_slice(&tag);
            Ok(body_end + tag.len())
        }
    }

    /// Unprotect an SRTP packet in place, returning a borrowed view of the
    /// recovered RTP packet over the same buffer.
    ///
    /// The buffer is decrypted in place and the authentication tag is verified
    /// (for AES-CM, in constant time) before any plaintext is returned. The
    /// returned [`RtpPacket`] borrows the leading `total_len` bytes of `srtp`,
    /// which now hold the decrypted RTP packet.
    ///
    /// # Errors
    /// Returns [`SrtpError::Replay`] if the packet index is a replay,
    /// [`SrtpError::KeyExpired`] if it lies past the `2^48`-packet key lifetime,
    /// [`SrtpError::AuthFailed`] if authentication fails, [`SrtpError::TooShort`]
    /// if the buffer is too small to hold the framing, or an [`SrtpError::Rtp`]
    /// error if the recovered packet does not parse.
    pub fn unprotect<'a>(&mut self, srtp: &'a mut [u8]) -> Result<RtpPacket<'a>> {
        let (payload_off, ssrc, seq) = {
            let m = RtpPacketMut::parse(srtp)?;
            (
                m.payload_offset(),
                m.header().ssrc(),
                m.header().sequence_number(),
            )
        };

        let (roc, index) = self.receiver_roc.estimate(seq)?;
        if self.replay.check(index) == ReplayCheck::Replayed {
            return Err(SrtpError::Replay);
        }

        let tag_len = self.key.profile.tag_len();
        if srtp.len() < payload_off + tag_len {
            return Err(SrtpError::TooShort);
        }

        let total_len = if self.key.profile.is_aead() {
            let iv = srtp_gcm_iv(&self.key.srtp_salt, ssrc, roc, seq);
            let (header, ct) = srtp.split_at(payload_off);
            let pt = gcm_open(&self.key.srtp_enc, &iv, header, ct)?;
            let end = payload_off + pt.len();
            srtp[payload_off..end].copy_from_slice(&pt);
            end
        } else {
            let body_end = srtp.len() - tag_len;
            let mut auth_input = srtp[..body_end].to_vec();
            auth_input.extend_from_slice(&roc.to_be_bytes());
            verify_hmac(&self.key.srtp_auth, &auth_input, &srtp[body_end..])?;

            let iv = srtp_cm_iv(&self.key.srtp_salt, ssrc, roc, seq);
            aes_cm_xor(&self.key.srtp_enc, &iv, &mut srtp[payload_off..body_end])?;
            body_end
        };

        self.receiver_roc.update(seq, roc);
        self.replay.mark(index);

        Ok(RtpPacket::parse(&srtp[..total_len])?)
    }
}
