//! SRTP key-derivation function (RFC 3711 §4.3) — the AES Counter-Mode PRF.
//!
//! Every SRTP profile, including the AES-GCM ones, derives its session keys
//! from a master key and master salt using this KDF. The PRF is AES in Counter
//! Mode keyed with the master key; the counter block is the master salt with
//! the one-octet key label XORed in (RFC 3711 §4.3.1, §4.3.3).
//!
//! `CryptoKit` does not expose AES-CTR, so the keystream is produced through
//! the CommonCrypto FFI in [`crate::ffi::commoncrypto`].

use crate::error::{Result, SrtpError};
use crate::ffi::commoncrypto;

/// Key label for the SRTP encryption key (RFC 3711 §4.3.1).
pub const LABEL_SRTP_ENCRYPTION: u8 = 0x00;
/// Key label for the SRTP authentication key.
pub const LABEL_SRTP_AUTH: u8 = 0x01;
/// Key label for the SRTP salt.
pub const LABEL_SRTP_SALT: u8 = 0x02;
/// Key label for the SRTCP encryption key.
pub const LABEL_SRTCP_ENCRYPTION: u8 = 0x03;
/// Key label for the SRTCP authentication key.
pub const LABEL_SRTCP_AUTH: u8 = 0x04;
/// Key label for the SRTCP salt.
pub const LABEL_SRTCP_SALT: u8 = 0x05;

/// Derive `out_len` bytes of key material for `label`.
///
/// The key-derivation rate is fixed at zero (initial derivation), so
/// `index DIV kdr` is the all-zero six-octet string and only the master key,
/// master salt, and `label` contribute.
///
/// The counter block is built exactly as the worked examples in RFC 3711 §B.3:
/// the master salt is copied into a 16-octet block (left-aligned), the one-byte
/// label is XORed at octet offset 7 (the most-significant octet of the 7-octet
/// `key_id = label || index`), and the trailing two octets act as the AES-CM
/// block counter. This layout reproduces the §B.3 cipher key, cipher salt, and
/// auth key vectors for the 14-octet AES-CM master salt and follows the
/// de-facto convention for the 12-octet AES-GCM master salt.
///
/// # Errors
/// Returns [`SrtpError::Crypto`] if the CommonCrypto AES-CTR primitive fails.
pub fn derive(master_key: &[u8], master_salt: &[u8], label: u8, out_len: usize) -> Result<Vec<u8>> {
    let mut counter = [0u8; 16];
    let copy = master_salt.len().min(16);
    counter[..copy].copy_from_slice(&master_salt[..copy]);
    // key_id = label || (index DIV kdr); with kdr == 0 the index part is zero,
    // so only the label octet (most significant octet of the 7-octet key_id,
    // which sits at offset 7 when right-aligned against the salt) is XORed in.
    counter[7] ^= label;

    commoncrypto::aes_ctr_keystream(master_key, &counter, out_len)
        .map_err(|status| SrtpError::Crypto(format!("AES-CTR KDF failed (status {status})")))
}
