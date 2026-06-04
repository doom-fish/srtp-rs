//! Low-level cipher helpers and the SRTP `protect` direction.
//!
//! This module owns the IV-construction rules (RFC 7714 §8.1 for AES-GCM,
//! RFC 3711 §4.1.1 for AES-CM) and the thin wrappers around CryptoKit AES-GCM
//! and the CommonCrypto AES-CTR primitive. [`crate::decrypt`] reuses these
//! helpers for the `unprotect` direction.

use cryptokit::aes_gcm::{AesGcm, AesGcmNonce, AesGcmSealedBox};
use cryptokit::symmetric::SymmetricKey;

use crate::error::{Result, SrtpError};
use crate::ffi::commoncrypto;

/// Length of an AES-GCM IV / nonce.
pub const GCM_IV_LEN: usize = 12;
/// Length of the AES-GCM authentication tag.
pub const GCM_TAG_LEN: usize = 16;

/// Build the 12-octet AES-GCM IV for an SRTP packet (RFC 7714 §8.1):
/// `IV = salt XOR (0x0000 || SSRC || ROC || SEQ)`.
#[must_use]
pub fn srtp_gcm_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; GCM_IV_LEN] {
    let mut iv = [0u8; GCM_IV_LEN];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[6..10].copy_from_slice(&roc.to_be_bytes());
    iv[10..12].copy_from_slice(&seq.to_be_bytes());
    for (b, s) in iv.iter_mut().zip(salt.iter()) {
        *b ^= *s;
    }
    iv
}

/// Build the 12-octet AES-GCM IV for an SRTCP packet (RFC 7714 §9.1):
/// `IV = salt XOR (0x0000 || SSRC || 0x0000 || 0+index)`. The 31-bit index is
/// supplied with its top bit already cleared.
#[must_use]
pub fn srtcp_gcm_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; GCM_IV_LEN] {
    let mut iv = [0u8; GCM_IV_LEN];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[8..12].copy_from_slice(&(index & 0x7FFF_FFFF).to_be_bytes());
    for (b, s) in iv.iter_mut().zip(salt.iter()) {
        *b ^= *s;
    }
    iv
}

/// Build the 16-octet AES Counter-Mode IV for an SRTP packet (RFC 3711 §4.1.1):
/// `IV = (salt << 16) XOR (SSRC << 64) XOR (i << 16)` where `i = ROC || SEQ`.
#[must_use]
pub fn srtp_cm_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..salt.len().min(14)].copy_from_slice(&salt[..salt.len().min(14)]);
    iv[4..8].iter_mut().zip(ssrc.to_be_bytes()).for_each(|(b, s)| *b ^= s);
    iv[8..12].iter_mut().zip(roc.to_be_bytes()).for_each(|(b, s)| *b ^= s);
    iv[12..14].iter_mut().zip(seq.to_be_bytes()).for_each(|(b, s)| *b ^= s);
    iv
}

/// Build the 16-octet AES Counter-Mode IV for an SRTCP packet, using the
/// 31-bit SRTCP index in place of `ROC || SEQ`.
#[must_use]
pub fn srtcp_cm_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..salt.len().min(14)].copy_from_slice(&salt[..salt.len().min(14)]);
    iv[4..8].iter_mut().zip(ssrc.to_be_bytes()).for_each(|(b, s)| *b ^= s);
    iv[8..12]
        .iter_mut()
        .zip((index & 0x7FFF_FFFF).to_be_bytes())
        .for_each(|(b, s)| *b ^= s);
    iv
}

/// AES-GCM seal: returns `ciphertext || tag`.
///
/// # Errors
/// Returns [`SrtpError::Crypto`] if CryptoKit rejects the request.
pub fn gcm_seal(key: &[u8], iv: &[u8; GCM_IV_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let sealed = AesGcm::seal_with_aad(plaintext, &symmetric, Some(iv), aad)
        .map_err(|e| SrtpError::Crypto(format!("AES-GCM seal failed: {e}")))?;
    let mut out = Vec::with_capacity(sealed.ciphertext().len() + GCM_TAG_LEN);
    out.extend_from_slice(sealed.ciphertext());
    out.extend_from_slice(sealed.tag());
    Ok(out)
}

/// AES-GCM open: verifies the tag and returns the recovered plaintext.
///
/// # Errors
/// Returns [`SrtpError::AuthFailed`] if the tag does not verify, or
/// [`SrtpError::TooShort`] if `ciphertext_and_tag` is shorter than a tag.
pub fn gcm_open(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < GCM_TAG_LEN {
        return Err(SrtpError::TooShort);
    }
    let split = ciphertext_and_tag.len() - GCM_TAG_LEN;
    let (ct, tag) = ciphertext_and_tag.split_at(split);
    let symmetric = SymmetricKey::from_bytes(key.to_vec());
    let nonce =
        AesGcmNonce::from_bytes(iv.to_vec()).map_err(|e| SrtpError::Crypto(e.to_string()))?;
    let sealed =
        AesGcmSealedBox::from_parts(&nonce, ct, tag).map_err(|e| SrtpError::Crypto(e.to_string()))?;
    AesGcm::open_with_aad(&sealed, &symmetric, aad).map_err(|_| SrtpError::AuthFailed)
}

/// XOR `data` in place with the AES Counter-Mode keystream produced by `key`
/// and the 16-octet counter block `iv`.
///
/// # Errors
/// Returns [`SrtpError::Crypto`] if the CommonCrypto AES-CTR primitive fails.
pub fn aes_cm_xor(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<()> {
    let keystream = commoncrypto::aes_ctr_keystream(key, iv, data.len())
        .map_err(|status| SrtpError::Crypto(format!("AES-CTR failed (status {status})")))?;
    for (d, k) in data.iter_mut().zip(keystream.iter()) {
        *d ^= *k;
    }
    Ok(())
}

/// Compute the truncated HMAC-SHA1 authentication tag over `data` (already
/// including the appended ROC for SRTP), returning `tag_len` bytes.
#[must_use]
pub fn hmac_sha1_tag(auth_key: &[u8], data: &[u8], tag_len: usize) -> Vec<u8> {
    let full = commoncrypto::hmac_sha1(auth_key, data);
    full[..tag_len.min(full.len())].to_vec()
}
