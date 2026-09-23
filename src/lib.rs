//! `srtp` — Secure RTP / Secure RTCP (RFC 3711, RFC 7714) layered on `rtp`.
//!
//! This crate protects and unprotects RTP and RTCP packets using the SRTP
//! framework. It targets the AES-GCM AEAD profiles of RFC 7714 — the default
//! for WebRTC media endpoints — and also implements the original AES Counter
//! Mode / HMAC-SHA1 profiles of RFC 3711 for interoperability with SFUs and
//! legacy peers.
//!
//! # Profiles
//!
//! | [`Profile`] | Cipher | Auth | IANA |
//! |---|---|---|---|
//! | [`Profile::AeadAes128Gcm`] | AES-128-GCM | AEAD tag | `0x0007` |
//! | [`Profile::AeadAes256Gcm`] | AES-256-GCM | AEAD tag | `0x0008` |
//! | [`Profile::AesCm128HmacSha1_80`] | AES-128-CTR | HMAC-SHA1-80 | `0x0001` |
//! | [`Profile::AesCm128HmacSha1_32`] | AES-128-CTR | HMAC-SHA1-32 | `0x0002` |
//!
//! # Cryptography
//!
//! AES-GCM is provided by the sibling `cryptokit` crate (Apple CryptoKit). The
//! mandatory RFC 3711 key-derivation function and the AES-CM / HMAC-SHA1
//! profiles use AES Counter Mode and HMAC-SHA1 from Apple's CommonCrypto via a
//! thin FFI in [`ffi::commoncrypto`]. There are no third-party crypto
//! dependencies.
//!
//! # Example
//!
//! ```
//! use srtp::{Profile, SrtpKey, SrtpSession};
//! use srtp::rtp::{Packet, RtpPacket};
//!
//! // Session keys (e.g. exported by DTLS-SRTP).
//! let enc = [0u8; 16];
//! let salt = [0u8; 12];
//! let key = SrtpKey::from_session(Profile::AeadAes128Gcm, &enc, &salt, &[]).unwrap();
//! let mut tx = SrtpSession::new_sender(key);
//!
//! let rtp = RtpPacket::builder().ssrc(0x1234).sequence_number(1).payload(b"hi").build().unwrap();
//! let view = rtp.as_view();
//! let mut out = vec![0u8; view.as_bytes().len() + 16];
//! let n = tx.protect(&view, &mut out).unwrap();
//! out.truncate(n);
//! ```
#![warn(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod ffi;
pub mod kdf;
pub mod profile;
pub mod replay;
pub mod roc;
pub mod session;
pub mod srtcp;

pub use error::{Result, SrtpError};
pub use profile::Profile;
pub use session::{SrtpKey, SrtpSession};
pub use srtcp::SrtcpSession;

/// Re-export of the underlying `rtp` crate so callers can build and read
/// packets without adding a separate dependency.
pub use rtp;
