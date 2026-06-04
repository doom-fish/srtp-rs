//! Demonstrate the SRTP key-derivation function (RFC 3711 §4.3) using the
//! published §B.3 master key/salt and printing the derived session keys.
//!
//! Run with: `cargo run --example 03_kdf_demo`

use srtp::kdf;

fn main() {
    // RFC 3711 Appendix B.3 inputs.
    let master_key = [
        0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41,
        0x39,
    ];
    let master_salt = [
        0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
    ];

    let cipher_key = kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_ENCRYPTION, 16).unwrap();
    let cipher_salt = kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_SALT, 14).unwrap();
    let auth_key = kdf::derive(&master_key, &master_salt, kdf::LABEL_SRTP_AUTH, 94).unwrap();

    println!("master key  : {}", hex(&master_key));
    println!("master salt : {}", hex(&master_salt));
    println!();
    println!("cipher key  : {}", hex(&cipher_key));
    println!("cipher salt : {}", hex(&cipher_salt));
    println!("auth key    : {}", hex(&auth_key));

    // The §B.3 expected cipher key.
    assert_eq!(hex(&cipher_key), "c61e7a93744f39ee10734afe3ff7a087");
    println!("\nderived cipher key matches RFC 3711 §B.3");
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
