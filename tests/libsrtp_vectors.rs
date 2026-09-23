mod common;
use common::{hex, to_hex};

use srtp::encrypt::srtcp_cm_iv;
use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtcpSession, SrtpKey, SrtpSession};

const CM_MASTER_KEY: &str = "e1f97a0d3e018be0d64fa32c06de4139";
const CM_MASTER_SALT: &str = "0ec675ad498afeebb6960b3aabe6";
const GCM_MASTER_KEY: &str = "000102030405060708090a0b0c0d0e0f";
const GCM_MASTER_SALT: &str = "a0a1a2a3a4a5a6a7a8a9aaab";

const RTP_PLAINTEXT: &str = "800f1234 decafbad cafebabe abababab abababab abababab abababab";
const RTCP_PLAINTEXT: &str = "81c8000b cafebabe abababab abababab abababab abababab";

const CM_SRTP: &str = "800f1234 decafbad cafebabe 4e55dc4c e79978d8 8ca4d215 949d2402 \
                       b78d6acc 99ea179b 8dbb";
const CM_SRTCP: &str = "81c8000b cafebabe 7128035b e487b9bd bef89041 f977a5a8 80000001 \
                        993e08cd 54d6c123 0798";
const GCM_SRTP: &str = "800f1234 decafbad cafebabe c5002ede 04cfdd2e b91159e0 880aa06e \
                        d2976826 f796b201 df3131a1 27e8a392";
const GCM_SRTCP: &str = "81c8000b cafebabe c98b8b5d f0392a55 852b6c21 ac8e7025 c52c6fbe \
                         a2b3b446 ea31123b a88ce61e 80000001";

fn master_key(profile: Profile, key: &str, salt: &str) -> SrtpKey {
    SrtpKey::from_master(&hex(key), &hex(salt), profile).unwrap()
}

fn assert_srtp_vector(key: &SrtpKey, protected: &str) {
    let clear = hex(RTP_PLAINTEXT);
    let expected = hex(protected);

    let mut tx = SrtpSession::new_sender(key.clone());
    let mut out = vec![0u8; expected.len()];
    let n = tx
        .protect(&RtpPacket::parse(&clear).unwrap(), &mut out)
        .unwrap();
    assert_eq!(to_hex(&out[..n]), to_hex(&expected));

    let mut rx = SrtpSession::new_receiver(key.clone());
    let mut wire = expected;
    let recovered = rx.unprotect(&mut wire).unwrap();
    assert_eq!(to_hex(recovered.as_bytes()), to_hex(&clear));
}

fn assert_srtcp_vector(key: &SrtpKey, protected: &str) {
    let clear = hex(RTCP_PLAINTEXT);
    let expected = hex(protected);

    let mut tx = SrtcpSession::new_sender(key.clone());
    tx.set_index(1).unwrap();
    let mut out = vec![0u8; expected.len()];
    let n = tx.protect(&clear, &mut out).unwrap();
    assert_eq!(to_hex(&out[..n]), to_hex(&expected));

    let mut rx = SrtcpSession::new_receiver(key.clone());
    assert_eq!(to_hex(&rx.unprotect(&expected).unwrap()), to_hex(&clear));
}

#[test]
fn libsrtp_aes_cm_128_hmac_sha1_80_srtp_packet() {
    let key = master_key(Profile::AesCm128HmacSha1_80, CM_MASTER_KEY, CM_MASTER_SALT);
    assert_srtp_vector(&key, CM_SRTP);
}

#[test]
fn libsrtp_aes_cm_128_hmac_sha1_80_srtcp_packet() {
    let key = master_key(Profile::AesCm128HmacSha1_80, CM_MASTER_KEY, CM_MASTER_SALT);
    assert_srtcp_vector(&key, CM_SRTCP);
}

#[test]
fn libsrtp_aes_cm_128_hmac_sha1_32_srtcp_packet_uses_the_80_bit_tag() {
    let key = master_key(Profile::AesCm128HmacSha1_32, CM_MASTER_KEY, CM_MASTER_SALT);
    assert_srtcp_vector(&key, CM_SRTCP);
    assert_eq!(Profile::AesCm128HmacSha1_32.tag_len(), 4);
    assert_eq!(Profile::AesCm128HmacSha1_32.srtcp_tag_len(), 10);
}

#[test]
fn libsrtp_aead_aes_128_gcm_srtp_packet() {
    let key = master_key(Profile::AeadAes128Gcm, GCM_MASTER_KEY, GCM_MASTER_SALT);
    assert_srtp_vector(&key, GCM_SRTP);
}

#[test]
fn libsrtp_aead_aes_128_gcm_srtcp_packet() {
    let key = master_key(Profile::AeadAes128Gcm, GCM_MASTER_KEY, GCM_MASTER_SALT);
    assert_srtcp_vector(&key, GCM_SRTCP);
}

#[test]
fn srtcp_cm_iv_places_the_index_at_octets_10_to_14() {
    let iv = srtcp_cm_iv(&[0u8; 14], 0x0102_0304, 0xffed_cba9);
    assert_eq!(to_hex(&iv), "000000000102030400007fedcba90000");

    let salt = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfd");
    let iv = srtcp_cm_iv(&salt, 0, 0x0000_0001);
    assert_eq!(to_hex(&iv), "f0f1f2f3f4f5f6f7f8f9fafbfcfc0000");
}
