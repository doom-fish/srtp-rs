mod common;
use common::{hex, srtcp_session_key};

use srtp::rtp::{Packet, RtpPacket, RtpPacketOwned};
use srtp::{Profile, SessionKeys, SrtcpSession, SrtpError, SrtpKey, SrtpSession};

fn master(profile: Profile) -> SrtpKey {
    let key: Vec<u8> = (1..=u8::MAX).take(profile.master_key_len()).collect();
    let salt: Vec<u8> = (1..=u8::MAX).take(profile.master_salt_len()).collect();
    SrtpKey::from_master(&key, &salt, profile).unwrap()
}

fn rtp(seq: u16) -> RtpPacketOwned {
    RtpPacket::builder()
        .ssrc(0x0bad_cafe)
        .sequence_number(seq)
        .payload(b"media payload")
        .build()
        .unwrap()
}

fn protect(tx: &mut SrtpSession, seq: u16) -> Result<Vec<u8>, SrtpError> {
    let packet = rtp(seq);
    let mut out = vec![0u8; packet.as_view().as_bytes().len() + 16];
    let n = tx.protect(&packet.as_view(), &mut out)?;
    out.truncate(n);
    Ok(out)
}

#[test]
fn srtcp_sender_stops_after_the_last_31_bit_index() {
    let key = srtcp_session_key(
        Profile::AeadAes128Gcm,
        &hex("000102030405060708090a0b0c0d0e0f"),
        &hex("517569642070726f2071756f"),
    );
    let rtcp = hex("81c80006 4d617273 00000000 00000000 00000000 00000000 00000000");
    let mut tx = SrtcpSession::new_sender(key.clone());
    let mut rx = SrtcpSession::new_receiver(key);
    tx.set_index(0x7fff_fffe).unwrap();

    let mut out = vec![0u8; rtcp.len() + 32];
    tx.protect(&rtcp, &mut out).unwrap();
    let n = tx.protect(&rtcp, &mut out).unwrap();
    assert_eq!(out[n - 4..n], [0xff, 0xff, 0xff, 0xff]);
    assert_eq!(rx.unprotect(&out[..n]).unwrap(), rtcp);

    assert_eq!(tx.index(), 0x8000_0000);
    assert!(matches!(tx.protect(&rtcp, &mut out), Err(SrtpError::KeyExpired)));
}

#[test]
fn srtcp_set_index_only_moves_forward() {
    let mut tx = SrtcpSession::new_sender(master(Profile::AesCm128HmacSha1_80));
    let rtcp = hex("81c90001 4d617273");
    let mut out = vec![0u8; 64];

    tx.set_index(10).unwrap();
    tx.protect(&rtcp, &mut out).unwrap();
    assert!(matches!(tx.set_index(10), Err(SrtpError::IndexReused)));
    assert!(matches!(tx.set_index(0), Err(SrtpError::IndexReused)));
    assert!(matches!(tx.set_index(0x8000_0000), Err(SrtpError::KeyExpired)));
    tx.set_index(11).unwrap();
    assert_eq!(tx.index(), 11);
}

#[test]
fn srtp_sender_refuses_to_reuse_an_index() {
    for profile in [Profile::AeadAes128Gcm, Profile::AesCm128HmacSha1_80] {
        let mut tx = SrtpSession::new_sender(master(profile));
        protect(&mut tx, 7).unwrap();
        assert!(matches!(protect(&mut tx, 7), Err(SrtpError::IndexReused)));
        protect(&mut tx, 6).unwrap();
        assert!(matches!(protect(&mut tx, 6), Err(SrtpError::IndexReused)));
        protect(&mut tx, 8).unwrap();
    }
}

#[test]
fn srtp_sender_stops_before_the_rollover_counter_wraps() {
    let key = master(Profile::AeadAes256Gcm);
    let mut tx = SrtpSession::new_sender(key.clone()).with_roc(u32::MAX);
    let mut rx = SrtpSession::new_receiver(key).with_roc(u32::MAX);

    let mut last = protect(&mut tx, 0xffff).unwrap();
    assert_eq!(rx.unprotect(&mut last).unwrap().payload(), b"media payload");
    assert_eq!(tx.sender_roc(), u32::MAX);
    assert!(matches!(protect(&mut tx, 0x0000), Err(SrtpError::KeyExpired)));

    let mut past_the_end = rtp(0x0000).as_view().as_bytes().to_vec();
    past_the_end.extend_from_slice(&[0u8; 16]);
    assert!(matches!(rx.unprotect(&mut past_the_end), Err(SrtpError::KeyExpired)));
}

#[test]
fn too_small_output_does_not_consume_the_index() {
    let mut tx = SrtpSession::new_sender(master(Profile::AesCm128HmacSha1_32));
    let packet = rtp(42);
    let mut small = vec![0u8; 4];
    assert!(matches!(
        tx.protect(&packet.as_view(), &mut small),
        Err(SrtpError::OutputTooSmall { .. })
    ));
    protect(&mut tx, 42).unwrap();
}

#[test]
fn from_session_rejects_keys_shared_by_srtp_and_srtcp() {
    let enc = [0x11u8; 16];
    let other = [0x22u8; 16];
    let gcm_salt = [0x33u8; 12];
    let cm_salt = [0x33u8; 14];
    let auth = [0x44u8; 20];
    let other_auth = [0x55u8; 20];

    let gcm = |srtp_enc: &[u8], srtcp_enc: &[u8]| {
        SrtpKey::from_session(
            Profile::AeadAes128Gcm,
            SessionKeys { encryption: srtp_enc, salt: &gcm_salt, authentication: &[] },
            SessionKeys { encryption: srtcp_enc, salt: &gcm_salt, authentication: &[] },
        )
    };
    assert!(matches!(gcm(&enc, &enc), Err(SrtpError::SessionKeyReuse)));
    assert!(gcm(&enc, &other).is_ok());

    let cm = |srtp_auth: &[u8], srtcp_auth: &[u8]| {
        SrtpKey::from_session(
            Profile::AesCm128HmacSha1_80,
            SessionKeys { encryption: &enc, salt: &cm_salt, authentication: srtp_auth },
            SessionKeys { encryption: &other, salt: &cm_salt, authentication: srtcp_auth },
        )
    };
    assert!(matches!(cm(&auth, &auth), Err(SrtpError::SessionKeyReuse)));
    assert!(cm(&auth, &other_auth).is_ok());
    assert!(matches!(
        cm(&auth, &auth[..10]),
        Err(SrtpError::BadKeyLength { expected: 20, actual: 10 })
    ));
}
