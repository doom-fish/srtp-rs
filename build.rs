#![allow(clippy::doc_markdown)]
//! Build script for `srtp-rs`.
//!
//! The AES-CTR key-derivation function and the HMAC-SHA1 authentication tag
//! call into Apple's CommonCrypto, which lives in `libSystem` and is linked
//! automatically — no extra link flags are needed here. AES-GCM is provided by
//! the sibling `cryptokit-rs` crate, which links `CryptoKit` from its own build
//! script. This build script exists so the crate layout matches its siblings
//! and to give CommonCrypto a documented home.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
