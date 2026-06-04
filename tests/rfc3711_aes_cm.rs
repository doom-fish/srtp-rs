//! RFC 3711 §B.2 AES-CM keystream vector and AES-CM SRTP round-trips.
//!
//! §B.2 publishes only the raw keystream (no full SRTP packet), so the
//! keystream is checked directly against the FFI primitive. The full
//! `AES_CM_128_HMAC_SHA1_80` / `_32` packet paths are exercised with
//! self-consistent protect -> unprotect round-trips, since the RFC does
//! not include an end-to-end SRTP packet vector for AES-CM.

mod common;
use common::{hex, to_hex};

use srtp::encrypt::srtp_cm_iv;
use srtp::ffi::commoncrypto::aes_ctr_keystream;
use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

#[test]
fn aes_cm_keystream_b2() {
    // Session key, salt, and zero SSRC/ROC/SEQ from §B.2.
    let key = hex("2B7E151628AED2A6ABF7158809CF4F3C");
    let salt = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD"); // 14-octet session salt

    let iv = srtp_cm_iv(&salt, 0, 0, 0);
    assert_eq!(to_hex(&iv), "f0f1f2f3f4f5f6f7f8f9fafbfcfd0000");

    let ks = aes_ctr_keystream(&key, &iv, 48).unwrap();
    assert_eq!(
        to_hex(&ks[0..16]),
        "e03ead0935c95e80e166b16dd92b4eb4"
    );
    assert_eq!(
        to_hex(&ks[16..32]),
        "d23513162b02d0f72a43a2fe4a5f97ab"
    );
    assert_eq!(
        to_hex(&ks[32..48]),
        "41e95b3bb0a2e8dd477901e4fca894c0"
    );
}

fn cm_roundtrip(profile: Profile) {
    let master_key = hex("E1F97A0D3E018BE0D64FA32C06DE4139");
    let master_salt = hex("0EC675AD498AFEEBB6960B3AABE6");
    let key = SrtpKey::from_master(&master_key, &master_salt, profile).unwrap();

    let payload: Vec<u8> = (0u8..64).collect();
    let packet = RtpPacket::builder()
        .ssrc(0xdead_beef)
        .sequence_number(0x1234)
        .payload(&payload)
        .build();
    let plain = packet.as_view().as_bytes().to_vec();

    let mut tx = SrtpSession::new_sender(key.clone());
    let mut buf = vec![0u8; plain.len() + 32];
    let n = tx.protect(&packet, &mut buf).unwrap();
    buf.truncate(n);

    // Ciphertext must differ from plaintext payload.
    assert_ne!(to_hex(&buf[..plain.len()]), to_hex(&plain));

    let mut rx = SrtpSession::new_receiver(key);
    let recovered = rx.unprotect(&mut buf).unwrap();
    assert_eq!(to_hex(recovered.payload()), to_hex(&payload));
}

#[test]
fn aes_cm_128_hmac_sha1_80_roundtrip() {
    cm_roundtrip(Profile::AesCm128HmacSha1_80);
}

#[test]
fn aes_cm_128_hmac_sha1_32_roundtrip() {
    cm_roundtrip(Profile::AesCm128HmacSha1_32);
}
