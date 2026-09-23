//! Thin FFI to Apple's CommonCrypto (`<CommonCrypto/CommonCryptor.h>` and
//! `<CommonCrypto/CommonHMAC.h>`).
//!
//! `CryptoKit` exposes AES-GCM but deliberately omits AES in Counter Mode
//! (AES-CTR) and HMAC-SHA1 from its safe surface. SRTP needs both:
//!
//! * The mandatory SRTP key-derivation function (RFC 3711 §4.3) is *defined*
//!   in terms of AES-128/256 in Counter Mode, and it is required for **every**
//!   profile — including the AES-GCM ones, whose session keys are still derived
//!   with the AES-CM PRF.
//! * The legacy `AES_CM_128_HMAC_SHA1_*` profiles encrypt with AES-CTR and
//!   authenticate with HMAC-SHA1.
//!
//! Both primitives live in `libSystem`, which every macOS binary already links
//! against, so no extra link flags are needed. This mirrors the precedent set
//! by the sibling `stun-rs` crate.

use core::ffi::c_void;

/// `kCCEncrypt` — encrypt operation (also drives CTR keystream generation).
const KCC_ENCRYPT: u32 = 0;
/// `kCCModeCTR` — Counter Mode.
const KCC_MODE_CTR: u32 = 4;
/// `kCCAlgorithmAES`.
const KCC_ALGORITHM_AES: u32 = 0;
/// `ccNoPadding`.
const CC_NO_PADDING: u32 = 0;
/// `kCCModeOptionCTR_BE` — big-endian counter increment (the SRTP convention).
const KCC_MODE_OPTION_CTR_BE: u32 = 2;

/// `kCCSuccess`.
const KCC_SUCCESS: i32 = 0;

/// `CCHmacAlgorithm` value for HMAC-SHA1 (`kCCHmacAlgSHA1`).
const KCC_HMAC_ALG_SHA1: u32 = 0;

/// Length in bytes of a SHA-1 / HMAC-SHA1 digest.
pub const SHA1_DIGEST_LEN: usize = 20;

#[allow(non_camel_case_types)]
type CCCryptorRef = *mut c_void;

extern "C" {
    fn CCCryptorCreateWithMode(
        op: u32,
        mode: u32,
        alg: u32,
        padding: u32,
        iv: *const u8,
        key: *const u8,
        key_length: usize,
        tweak: *const u8,
        tweak_length: usize,
        num_rounds: i32,
        options: u32,
        cryptor_ref: *mut CCCryptorRef,
    ) -> i32;

    fn CCCryptorUpdate(
        cryptor_ref: CCCryptorRef,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    fn CCCryptorRelease(cryptor_ref: CCCryptorRef) -> i32;

    /// `void CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength,
    ///             const void *data, size_t dataLength, void *macOut);`
    fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );
}

/// Apply AES in Counter Mode (big-endian counter) to `input`, writing the
/// result into `output`.
///
/// Encryption and decryption are identical in CTR mode (the keystream is XORed
/// with the data), and feeding all-zero input yields the raw keystream, which
/// is how the SRTP KDF and AES-CM cipher are built on top of this function.
///
/// * `key` must be 16, 24, or 32 bytes (AES-128/192/256).
/// * `iv` is the initial 16-byte counter block.
/// * `output` must be at least `input.len()` bytes long.
///
/// # Errors
/// Returns the raw `CCCryptorStatus` if CommonCrypto rejects the parameters or
/// the cryptor cannot be created.
pub fn aes_ctr(key: &[u8], iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), i32> {
    assert!(output.len() >= input.len(), "output buffer too small");
    let mut cryptor: CCCryptorRef = core::ptr::null_mut();
    // SAFETY: pointers are valid for the lengths passed; cryptor is released below.
    let status = unsafe {
        CCCryptorCreateWithMode(
            KCC_ENCRYPT,
            KCC_MODE_CTR,
            KCC_ALGORITHM_AES,
            CC_NO_PADDING,
            iv.as_ptr(),
            key.as_ptr(),
            key.len(),
            core::ptr::null(),
            0,
            0,
            KCC_MODE_OPTION_CTR_BE,
            &raw mut cryptor,
        )
    };
    if status != KCC_SUCCESS {
        return Err(status);
    }

    let mut moved: usize = 0;
    // SAFETY: cryptor is valid; input/output spans are in bounds.
    let status = unsafe {
        CCCryptorUpdate(
            cryptor,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &raw mut moved,
        )
    };
    // SAFETY: cryptor was successfully created above.
    unsafe {
        CCCryptorRelease(cryptor);
    }
    if status != KCC_SUCCESS {
        return Err(status);
    }
    debug_assert_eq!(moved, input.len());
    Ok(())
}

/// Generate `len` bytes of AES-CTR keystream from `key` and the initial counter
/// block `iv` (equivalent to encrypting `len` zero bytes).
///
/// # Errors
/// Propagates the `CCCryptorStatus` from [`aes_ctr`].
pub fn aes_ctr_keystream(key: &[u8], iv: &[u8; 16], len: usize) -> Result<Vec<u8>, i32> {
    let zeros = vec![0u8; len];
    let mut out = vec![0u8; len];
    aes_ctr(key, iv, &zeros, &mut out)?;
    Ok(out)
}

/// Compute `HMAC-SHA1(key, data)`.
#[must_use]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_DIGEST_LEN] {
    let mut out = [0u8; SHA1_DIGEST_LEN];
    // SAFETY: all pointers/lengths describe valid live slices.
    unsafe {
        CCHmac(
            KCC_HMAC_ALG_SHA1,
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr().cast(),
        );
    }
    out
}
