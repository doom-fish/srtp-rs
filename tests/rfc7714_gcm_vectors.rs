//! RFC 7714 AES-GCM SRTP test vectors (§16.1 and §16.2).

mod common;
use common::{hex, to_hex};

use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

/// The cleartext RTP packet shared by §16.1.1 and §16.2.1.
fn cleartext_rtp() -> Vec<u8> {
    hex(
        "8040f17b 8041f8d3 5501a0b2 47616c6c \
         69612065 7374206f 6d6e6973 20646976 \
         69736120 696e2070 61727465 73207472 \
         6573",
    )
}

#[test]
fn srtp_aes128_gcm_encrypt_16_1_1() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let expected = hex(
        "8040f17b 8041f8d3 5501a0b2 f24de3a3 \
         fb34de6c acba861c 9d7e4bca be633bd5 \
         0d294e6f 42a5f47a 51c7d19b 36de3adf \
         8833899d 7f27beb1 6a9152cf 765ee439 \
         0cce",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();
    let mut tx = SrtpSession::new_sender(srtp_key);

    let clear = cleartext_rtp();
    let pkt = RtpPacket::parse(&clear).unwrap();
    let mut out = vec![0u8; expected.len()];
    let n = tx.protect(&pkt, &mut out).unwrap();
    out.truncate(n);

    assert_eq!(to_hex(&out), to_hex(&expected));
}

#[test]
fn srtp_aes128_gcm_decrypt_16_1_2() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let mut protected = hex(
        "8040f17b 8041f8d3 5501a0b2 f24de3a3 \
         fb34de6c acba861c 9d7e4bca be633bd5 \
         0d294e6f 42a5f47a 51c7d19b 36de3adf \
         8833899d 7f27beb1 6a9152cf 765ee439 \
         0cce",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();
    let mut rx = SrtpSession::new_receiver(srtp_key);

    let recovered = rx.unprotect(&mut protected).unwrap();
    assert_eq!(to_hex(recovered.as_bytes()), to_hex(&cleartext_rtp()));
}

#[test]
fn srtp_aes256_gcm_encrypt_16_2_1() {
    let key = hex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    let salt = hex("51756964 2070726f 2071756f");
    let expected = hex(
        "8040f17b 8041f8d3 5501a0b2 32b1de78 \
         a822fe12 ef9f78fa 332e33aa b1801238 \
         9a58e2f3 b50b2a02 76ffae0f 1ba63799 \
         b87b7aa3 db36dfff d6b0f9bb 7878d7a7 \
         6c13",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes256Gcm, &key, &salt, &[]).unwrap();
    let mut tx = SrtpSession::new_sender(srtp_key);

    let clear = cleartext_rtp();
    let pkt = RtpPacket::parse(&clear).unwrap();
    let mut out = vec![0u8; expected.len()];
    let n = tx.protect(&pkt, &mut out).unwrap();
    out.truncate(n);

    assert_eq!(to_hex(&out), to_hex(&expected));
}

#[test]
fn srtp_aes256_gcm_roundtrip_16_2() {
    let key = hex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    let salt = hex("51756964 2070726f 2071756f");
    let mut protected = hex(
        "8040f17b 8041f8d3 5501a0b2 32b1de78 \
         a822fe12 ef9f78fa 332e33aa b1801238 \
         9a58e2f3 b50b2a02 76ffae0f 1ba63799 \
         b87b7aa3 db36dfff d6b0f9bb 7878d7a7 \
         6c13",
    );

    let srtp_key = SrtpKey::from_session(Profile::AeadAes256Gcm, &key, &salt, &[]).unwrap();
    let mut rx = SrtpSession::new_receiver(srtp_key);
    let recovered = rx.unprotect(&mut protected).unwrap();
    assert_eq!(to_hex(recovered.as_bytes()), to_hex(&cleartext_rtp()));
}

#[test]
fn srtp_gcm_tampered_tag_rejected() {
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let salt = hex("51756964 2070726f 2071756f");
    let mut protected = hex(
        "8040f17b 8041f8d3 5501a0b2 f24de3a3 \
         fb34de6c acba861c 9d7e4bca be633bd5 \
         0d294e6f 42a5f47a 51c7d19b 36de3adf \
         8833899d 7f27beb1 6a9152cf 765ee439 \
         0cce",
    );
    // Flip a bit in the authentication tag.
    let last = protected.len() - 1;
    protected[last] ^= 0x01;

    let srtp_key = SrtpKey::from_session(Profile::AeadAes128Gcm, &key, &salt, &[]).unwrap();
    let mut rx = SrtpSession::new_receiver(srtp_key);
    assert!(rx.unprotect(&mut protected).is_err());
}
