//! RFC 7714 AES-GCM SRTCP test vectors (§17.1 and §17.2).

mod common;
use common::{hex, to_hex};

use srtp::{Profile, SrtcpSession, SrtpKey};

/// The cleartext RTCP compound packet shared by the SRTCP vectors.
fn cleartext_rtcp() -> Vec<u8> {
    hex(
        "81c8000d 4d617273 4e545031 4e545032 \
         52545020 0000042a 0000e930 4c756e61 \
         deadbeef deadbeef deadbeef deadbeef \
         deadbeef",
    )
}

#[test]
fn srtcp_aes128_gcm_encrypt_17_1() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let expected = hex(
        "81c8000d 4d617273 63e94885 dcdab67c \
         a727d766 2f6b7e99 7ff5c0f7 6c06f32d \
         c676a5f1 730d6fda 4ce09b46 86303ded \
         0bb9275b c84aa458 96cf4d2f c5abf872 \
         45d9eade 800005d4",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();
    let mut tx = SrtcpSession::new_sender(srtp_key);
    tx.set_index(0x0000_05d4);

    let mut out = vec![0u8; expected.len()];
    let n = tx.protect(&cleartext_rtcp(), &mut out).unwrap();
    out.truncate(n);

    assert_eq!(to_hex(&out), to_hex(&expected));
}

#[test]
fn srtcp_aes128_gcm_decrypt_17_1() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let protected = hex(
        "81c8000d 4d617273 63e94885 dcdab67c \
         a727d766 2f6b7e99 7ff5c0f7 6c06f32d \
         c676a5f1 730d6fda 4ce09b46 86303ded \
         0bb9275b c84aa458 96cf4d2f c5abf872 \
         45d9eade 800005d4",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();
    let mut rx = SrtcpSession::new_receiver(srtp_key);
    let recovered = rx.unprotect(&protected).unwrap();
    assert_eq!(to_hex(&recovered), to_hex(&cleartext_rtcp()));
}

#[test]
fn srtcp_aes256_gcm_decrypt_17_2() {
    let key = hex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    let salt = hex("51756964 2070726f 2071756f");
    let protected = hex(
        "81c8000d 4d617273 d50ae4d1 f5ce5d30 \
         4ba297e4 7d470c28 2c3ece5d bffe0a50 \
         a2eaa5c1 110555be 8415f658 c61de047 \
         6f1b6fad 1d1eb30c 4446839f 57ff6f6c \
         b26ac3be 800005d4",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes256Gcm, &key, &salt, &[]).unwrap();
    let mut rx = SrtcpSession::new_receiver(srtp_key);
    let recovered = rx.unprotect(&protected).unwrap();
    assert_eq!(to_hex(&recovered), to_hex(&cleartext_rtcp()));
}

#[test]
fn srtcp_aes128_gcm_roundtrip() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();

    let mut tx = SrtcpSession::new_sender(srtp_key.clone());
    let mut out = vec![0u8; cleartext_rtcp().len() + 32];
    let n = tx.protect(&cleartext_rtcp(), &mut out).unwrap();
    out.truncate(n);

    let mut rx = SrtcpSession::new_receiver(srtp_key);
    let recovered = rx.unprotect(&out).unwrap();
    assert_eq!(to_hex(&recovered), to_hex(&cleartext_rtcp()));
}

#[test]
fn srtcp_replay_rejected() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();

    let mut tx = SrtcpSession::new_sender(srtp_key.clone());
    let mut out = vec![0u8; cleartext_rtcp().len() + 32];
    let n = tx.protect(&cleartext_rtcp(), &mut out).unwrap();
    out.truncate(n);

    let mut rx = SrtcpSession::new_receiver(srtp_key);
    assert!(rx.unprotect(&out).is_ok());
    // Same index again must be rejected as a replay.
    assert!(rx.unprotect(&out).is_err());
}
