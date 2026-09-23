mod common;
use common::{hex, srtcp_session_key, to_hex};

use srtp::encrypt::hmac_sha1_tag;
use srtp::{Profile, SessionKeys, SrtcpSession, SrtpError, SrtpKey};

const KEY_128: &str = "000102030405060708090a0b0c0d0e0f";
const KEY_256: &str = "000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f";
const SALT: &str = "517569642070726f2071756f";
const TAG_128: &str = "841dd968 3dd78ec9 2ae58790 125f62b3 000005d4";
const TAG_256: &str = "91db4afb feee5a97 8fab4393 ed2615fe 000005d4";

fn cleartext_rtcp() -> Vec<u8> {
    hex(
        "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61 \
         deadbeef deadbeef deadbeef deadbeef deadbeef",
    )
}

fn tagged(tag_and_trailer: &str) -> Vec<u8> {
    let mut packet = cleartext_rtcp();
    packet.extend_from_slice(&hex(tag_and_trailer));
    packet
}

fn gcm_128() -> SrtpKey {
    srtcp_session_key(Profile::AeadAes128Gcm, &hex(KEY_128), &hex(SALT))
}

fn aes_cm_key() -> SrtpKey {
    SrtpKey::from_session(
        Profile::AesCm128HmacSha1_80,
        SessionKeys {
            encryption: &[1u8; 16],
            salt: &[2u8; 14],
            authentication: &[3u8; 20],
        },
        SessionKeys {
            encryption: &[4u8; 16],
            salt: &[5u8; 14],
            authentication: &[6u8; 20],
        },
    )
    .unwrap()
}

fn unencrypted_aes_cm_packet(index: u32) -> Vec<u8> {
    let mut packet = cleartext_rtcp();
    packet.extend_from_slice(&index.to_be_bytes());
    let tag = hmac_sha1_tag(&[6u8; 20], &packet, 10);
    packet.extend_from_slice(&tag);
    packet
}

#[test]
fn rfc7714_17_3_aes128_gcm_tag_only_packet_verifies() {
    let mut rx = SrtcpSession::new_receiver(gcm_128());
    let recovered = rx.unprotect(&tagged(TAG_128)).unwrap();
    assert_eq!(to_hex(&recovered), to_hex(&cleartext_rtcp()));
    assert!(matches!(
        rx.unprotect(&tagged(TAG_128)),
        Err(SrtpError::Replay)
    ));
}

#[test]
fn rfc7714_17_4_aes256_gcm_tag_only_packet_verifies() {
    let key = srtcp_session_key(Profile::AeadAes256Gcm, &hex(KEY_256), &hex(SALT));
    let mut rx = SrtcpSession::new_receiver(key);
    let recovered = rx.unprotect(&tagged(TAG_256)).unwrap();
    assert_eq!(to_hex(&recovered), to_hex(&cleartext_rtcp()));
}

#[test]
fn gcm_tag_only_packet_is_rejected_when_encryption_is_required() {
    let mut rx = SrtcpSession::new_receiver(gcm_128()).require_encryption(true);
    assert!(matches!(
        rx.unprotect(&tagged(TAG_128)),
        Err(SrtpError::Unencrypted)
    ));
}

#[test]
fn gcm_tag_only_packet_with_a_modified_body_fails_authentication() {
    let mut packet = tagged(TAG_128);
    packet[12] ^= 0x01;
    let mut rx = SrtcpSession::new_receiver(gcm_128());
    assert!(matches!(rx.unprotect(&packet), Err(SrtpError::AuthFailed)));
}

#[test]
fn flipping_the_e_flag_fails_authentication() {
    let key = gcm_128();
    let mut tx = SrtcpSession::new_sender(key.clone());
    let mut out = vec![0u8; cleartext_rtcp().len() + 32];
    let n = tx.protect(&cleartext_rtcp(), &mut out).unwrap();
    out.truncate(n);
    out[n - 4] &= 0x7f;
    let mut rx = SrtcpSession::new_receiver(key);
    assert!(matches!(rx.unprotect(&out), Err(SrtpError::AuthFailed)));

    let mut tag_only = tagged(TAG_128);
    let trailer_at = tag_only.len() - 4;
    tag_only[trailer_at] |= 0x80;
    assert!(matches!(
        rx.unprotect(&tag_only),
        Err(SrtpError::AuthFailed)
    ));
}

#[test]
fn aes_cm_unencrypted_packet_is_accepted_unless_encryption_is_required() {
    let packet = unencrypted_aes_cm_packet(9);
    let mut rx = SrtcpSession::new_receiver(aes_cm_key());
    assert_eq!(
        to_hex(&rx.unprotect(&packet).unwrap()),
        to_hex(&cleartext_rtcp())
    );

    let mut strict = SrtcpSession::new_receiver(aes_cm_key()).require_encryption(true);
    assert!(matches!(
        strict.unprotect(&packet),
        Err(SrtpError::Unencrypted)
    ));
}

#[test]
fn a_rejected_unencrypted_packet_does_not_consume_its_index() {
    let mut strict = SrtcpSession::new_receiver(aes_cm_key()).require_encryption(true);
    assert!(matches!(
        strict.unprotect(&unencrypted_aes_cm_packet(9)),
        Err(SrtpError::Unencrypted)
    ));

    let mut tx = SrtcpSession::new_sender(aes_cm_key());
    tx.set_index(9).unwrap();
    let mut out = vec![0u8; cleartext_rtcp().len() + 32];
    let n = tx.protect(&cleartext_rtcp(), &mut out).unwrap();
    assert_eq!(
        to_hex(&strict.unprotect(&out[..n]).unwrap()),
        to_hex(&cleartext_rtcp())
    );
}
