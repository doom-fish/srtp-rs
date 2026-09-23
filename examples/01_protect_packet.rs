//! Protect an RTP packet with SRTP (`AEAD_AES_128_GCM`) and print the result.
//!
//! Run with: `cargo run --example 01_protect_packet`

use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

fn main() {
    // 16-octet master key + 12-octet master salt for the GCM profile.
    let master_key: Vec<u8> = (0u8..16).collect();
    let master_salt: Vec<u8> = (0u8..12).collect();

    let key = SrtpKey::from_master(&master_key, &master_salt, Profile::AeadAes128Gcm)
        .expect("valid key material");
    let mut sender = SrtpSession::new_sender(key);

    let payload = b"the quick brown fox";
    let packet = RtpPacket::builder()
        .ssrc(0xcafe_b0ba)
        .sequence_number(1000)
        .payload(payload)
        .build()
        .expect("valid RTP packet");

    let plain = packet.as_view();
    println!("cleartext RTP : {}", hex(plain.as_bytes()));

    let mut out = vec![0u8; payload.len() + 64];
    let n = sender
        .protect(&plain, &mut out)
        .expect("protect succeeds");
    out.truncate(n);

    println!("protected SRTP: {}", hex(&out));
    println!(
        "added {} bytes of GCM authentication tag",
        out.len() - plain.as_bytes().len()
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
