//! Round-trip an RTP packet through SRTP protect -> unprotect and verify the
//! recovered payload matches the original.
//!
//! Run with: `cargo run --example 02_unprotect_packet`

use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

fn main() {
    let master_key: Vec<u8> = (0u8..16).collect();
    let master_salt: Vec<u8> = (0u8..14).collect();

    // Both endpoints share the same master key/salt.
    let key = SrtpKey::from_master(&master_key, &master_salt, Profile::AesCm128HmacSha1_80)
        .expect("valid key material");
    let mut sender = SrtpSession::new_sender(key.clone());
    let mut receiver = SrtpSession::new_receiver(key);

    let payload = b"voice frame payload";
    let packet = RtpPacket::builder()
        .ssrc(0x0102_0304)
        .sequence_number(42)
        .payload(payload)
        .build();

    let mut buf = vec![0u8; payload.len() + 64];
    let n = sender
        .protect(&packet.as_view(), &mut buf)
        .expect("protect succeeds");
    buf.truncate(n);
    println!("on the wire   : {} bytes", buf.len());

    let recovered = receiver.unprotect(&mut buf).expect("authenticated + decrypted");
    println!("recovered     : {:?}", String::from_utf8_lossy(recovered.payload()));

    assert_eq!(recovered.payload(), payload);
    println!("round-trip OK: payload matches the original");
}
