//! End-to-end integration tests building real RTP packets with `rtp-rs`,
//! protecting them, and unprotecting them across all four profiles.
#![allow(clippy::cast_possible_truncation)]

mod common;
use common::to_hex;

use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

fn master(profile: Profile) -> SrtpKey {
    let master_key: Vec<u8> = (0..profile.master_key_len()).map(|b| b as u8).collect();
    let master_salt: Vec<u8> = (0..profile.master_salt_len()).map(|b| b as u8).collect();
    SrtpKey::from_master(&master_key, &master_salt, profile).unwrap()
}

fn roundtrip_stream(profile: Profile) {
    let key = master(profile);
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key);

    for i in 0u16..200 {
        let payload = format!("packet number {i}").into_bytes();
        let packet = RtpPacket::builder()
            .ssrc(0x1122_3344)
            .sequence_number(i)
            .payload(&payload)
            .build();

        let mut buf = vec![0u8; payload.len() + 64];
        let n = tx.protect(&packet.as_view(), &mut buf).unwrap();
        buf.truncate(n);

        let recovered = rx.unprotect(&mut buf).unwrap();
        assert_eq!(to_hex(recovered.payload()), to_hex(&payload));
    }
}

#[test]
fn integration_gcm128() {
    roundtrip_stream(Profile::AeadAes128Gcm);
}

#[test]
fn integration_gcm256() {
    roundtrip_stream(Profile::AeadAes256Gcm);
}

#[test]
fn integration_cm_80() {
    roundtrip_stream(Profile::AesCm128HmacSha1_80);
}

#[test]
fn integration_cm_32() {
    roundtrip_stream(Profile::AesCm128HmacSha1_32);
}

#[test]
fn integration_sequence_wrap() {
    let key = master(Profile::AeadAes128Gcm);
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key);

    // Start just before the 16-bit sequence wrap so the ROC must advance.
    let seqs: Vec<u16> = (0xfffd_u16..=0xffff).chain(0u16..3).collect();
    for seq in seqs {
        let payload = vec![(seq & 0xff) as u8; 20];
        let packet = RtpPacket::builder()
            .ssrc(0x1122_3344)
            .sequence_number(seq)
            .payload(&payload)
            .build();

        let mut buf = vec![0u8; payload.len() + 64];
        let n = tx.protect(&packet.as_view(), &mut buf).unwrap();
        buf.truncate(n);

        let recovered = rx.unprotect(&mut buf).unwrap();
        assert_eq!(to_hex(recovered.payload()), to_hex(&payload));
    }
}

#[test]
fn integration_replay_is_rejected() {
    let key = master(Profile::AeadAes128Gcm);
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key);

    let payload = b"hello world".to_vec();
    let packet = RtpPacket::builder()
        .ssrc(0x1122_3344)
        .sequence_number(7)
        .payload(&payload)
        .build();
    let mut buf = vec![0u8; payload.len() + 64];
    let n = tx.protect(&packet.as_view(), &mut buf).unwrap();
    buf.truncate(n);

    let mut copy = buf.clone();
    assert!(rx.unprotect(&mut buf).is_ok());
    // Replaying the same protected packet must fail.
    assert!(rx.unprotect(&mut copy).is_err());
}

#[test]
fn integration_tamper_is_rejected() {
    let key = master(Profile::AesCm128HmacSha1_80);
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key);

    let payload = b"authenticate me".to_vec();
    let packet = RtpPacket::builder()
        .ssrc(0x1122_3344)
        .sequence_number(1)
        .payload(&payload)
        .build();
    let mut buf = vec![0u8; payload.len() + 64];
    let n = tx.protect(&packet.as_view(), &mut buf).unwrap();
    buf.truncate(n);

    // Flip a bit in the encrypted payload.
    buf[14] ^= 0x01;
    assert!(rx.unprotect(&mut buf).is_err());
}
