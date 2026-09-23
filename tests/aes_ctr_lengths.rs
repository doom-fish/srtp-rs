mod common;
use common::{hex, to_hex};

use cryptokit::aes_gcm::AesGcm;
use cryptokit::symmetric::SymmetricKey;
use srtp::encrypt::srtp_cm_iv;
use srtp::ffi::commoncrypto::{aes_ctr, aes_ctr_in_place, aes_ctr_keystream};
use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SessionKeys, SrtpKey, SrtpSession};

const ODD_LENGTHS: [usize; 19] = [
    0, 1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 47, 63, 65, 100, 255, 1000, 1500, 4097,
];

fn pattern(len: usize) -> Vec<u8> {
    (0u8..=u8::MAX)
        .cycle()
        .take(len)
        .map(|b| b.wrapping_mul(31) ^ 0x5a)
        .collect()
}

#[test]
fn keystream_of_every_length_is_a_prefix_of_the_rfc3711_b2_keystream() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000").try_into().unwrap();
    let full = hex(
        "e03ead0935c95e80e166b16dd92b4eb4 d23513162b02d0f72a43a2fe4a5f97ab \
         41e95b3bb0a2e8dd477901e4fca894c0",
    );
    for len in 0..=full.len() {
        let keystream = aes_ctr_keystream(&key, &iv, len).unwrap();
        assert_eq!(to_hex(&keystream), to_hex(&full[..len]), "length {len}");
    }
}

#[test]
fn in_place_ctr_matches_the_aes_gcm_counter_stream_for_odd_lengths() {
    let nonce = hex("cafebabefacedbaddecaf888");
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(&nonce);
    counter[15] = 2;
    let keys = [
        hex("feffe9928665731c6d6a8f9467308308"),
        hex("feffe9928665731c6d6a8f9467308308 feffe9928665731c6d6a8f9467308308"),
    ];
    for key in keys {
        let symmetric = SymmetricKey::from_bytes(key.clone());
        for len in ODD_LENGTHS {
            let plaintext = pattern(len);
            let sealed = AesGcm::seal(&plaintext, &symmetric, Some(&nonce)).unwrap();
            let mut data = plaintext;
            aes_ctr_in_place(&key, &counter, &mut data).unwrap();
            assert_eq!(
                to_hex(&data),
                to_hex(sealed.ciphertext()),
                "{}-byte key, length {len}",
                key.len()
            );
        }
    }
}

#[test]
fn out_of_place_ctr_matches_in_place_and_rejects_a_short_output() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = [0x42u8; 16];
    for len in ODD_LENGTHS.into_iter().filter(|&len| len > 0) {
        let input = pattern(len);
        let mut in_place = input.clone();
        aes_ctr_in_place(&key, &iv, &mut in_place).unwrap();

        let mut output = vec![0u8; len + 3];
        aes_ctr(&key, &iv, &input, &mut output).unwrap();
        assert_eq!(output[..len], in_place[..]);
        assert_eq!(output[len..], [0, 0, 0]);

        let mut short = vec![0u8; len - 1];
        assert_eq!(aes_ctr(&key, &iv, &input, &mut short), Err(-4301));
    }
    assert!(aes_ctr_in_place(&key[..15], &iv, &mut [0u8; 4]).is_err());
}

#[test]
fn aes_cm_srtp_payloads_of_every_length_match_the_keystream() {
    let enc = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let salt = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfd");
    let key = SrtpKey::from_session(
        Profile::AesCm128HmacSha1_80,
        SessionKeys {
            encryption: &enc,
            salt: &salt,
            authentication: &[0x11; 20],
        },
        SessionKeys {
            encryption: &[0x22; 16],
            salt: &salt,
            authentication: &[0x33; 20],
        },
    )
    .unwrap();
    let mut tx = SrtpSession::new_sender(key.clone());
    let mut rx = SrtpSession::new_receiver(key);

    for (seq, len) in (0u16..).zip(0usize..=70) {
        let payload = pattern(len);
        let packet = RtpPacket::builder()
            .ssrc(0x1234_5678)
            .sequence_number(seq)
            .payload(&payload)
            .build()
            .unwrap();
        let header_len = packet.as_view().payload_offset();
        let mut out = vec![0u8; header_len + len + 10];
        let n = tx.protect(&packet.as_view(), &mut out).unwrap();
        assert_eq!(n, header_len + len + 10);

        let iv = srtp_cm_iv(&salt, 0x1234_5678, 0, seq);
        let keystream = aes_ctr_keystream(&enc, &iv, len).unwrap();
        let expected: Vec<u8> = payload
            .iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();
        assert_eq!(
            to_hex(&out[header_len..header_len + len]),
            to_hex(&expected),
            "length {len}"
        );

        let recovered = rx.unprotect(&mut out[..n]).unwrap();
        assert_eq!(recovered.payload(), &payload[..]);
    }
}
