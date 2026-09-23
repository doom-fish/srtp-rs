# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Security

- The key lifetime is enforced. Protecting past SRTP index 2^48 − 1 or SRTCP
  index 2^31 − 1 fails with `SrtpError::KeyExpired` instead of wrapping the
  rollover counter or the SRTCP index, which repeated the AES-CM keystream and
  the AES-GCM nonce. Receivers reject packets whose estimated index passes
  2^48 − 1 the same way.
- A sender never protects the same packet index twice
  (`SrtpError::IndexReused`). Protecting a sequence number again used to
  reuse the nonce.
- `SrtpKey::from_session` no longer applies one key to both SRTP and SRTCP.
  Their IVs coincide, so that repeated the keystream (see Changed).
- `SrtpSession::with_roc` and `with_replay_window` (and
  `SrtcpSession::with_replay_window`) return `SrtpError::SessionStarted` on a
  session that has already processed packets. Otherwise they would discard
  the record of used indices or the replay state.
- Session keys, derived keys and keystreams are zeroized on drop, and `Debug`
  stays redacted. `decrypt::ct_eq` accumulates through `core::hint::black_box`.

### Fixed

- AES-CM SRTCP put the SRTCP index at IV octets 8..12. RFC 3711 §4.1.1 and
  libsrtp use octets 10..14, so AES-CM SRTCP only worked against this crate.
- AES-GCM SRTCP packets sent with the E flag clear (RFC 7714 §9.3, tag only)
  always failed authentication. They now verify.
- SRTCP under `AES_CM_128_HMAC_SHA1_32` used a 32-bit tag. RFC 5764 §4.1.2 and
  libsrtp use an 80-bit RTCP tag for that profile, so SRTCP did not
  interoperate.
- The sender estimates its ROC with the receiver's RFC 3711 Appendix A rule. A
  packet re-sent from before a sequence wrap no longer advances the sender ROC
  and desynchronises the receiver. At ROC zero the estimator no longer guesses
  ROC `u32::MAX` for a late packet; like libsrtp, it stays at zero.
- The 64-packet replay window dropped valid video packets delayed by bursts or
  reordering. The default is now 1024 packets.
- `SrtpSession::protect` checks the output buffer before it consumes an index,
  so a retry with a larger buffer succeeds.
- `ffi::commoncrypto::aes_ctr` panicked on a short output buffer. It now returns
  `kCCBufferTooSmall`. AES-CTR runs in place and fails unless CommonCrypto
  processed every byte, in release builds too.

### Changed

- **Breaking:** `SrtpKey::from_session(profile, media, control)` takes a
  `SessionKeys` for each direction. It rejects a shared encryption key or
  (AES-CM) authentication key with `SrtpError::SessionKeyReuse`.
- **Breaking:** `SrtcpSession::set_index` returns `Result` and only moves
  forward.
- **Breaking:** `roc::SenderRoc::next` and `roc::ReceiverRoc::estimate` return
  `Result`.
- **Breaking:** `replay::WINDOW_SIZE` is replaced by `MIN_WINDOW_SIZE` (64),
  `MAX_WINDOW_SIZE` (1024) and `DEFAULT_WINDOW_SIZE` (1024).
- **Breaking:** `kdf::derive` and `ffi::commoncrypto::aes_ctr_keystream`
  return `Zeroizing<Vec<u8>>`.
- **Breaking:** requires rtp-rs 0.2 (`>=0.2, <0.3`), whose packet builder and
  compound encoder are fallible, and cryptokit-rs 0.3 (`>=0.3, <0.4`).
- `rust-version` is 1.82. The unused `libc` dependency is removed, and
  `zeroize` (`>=1.6, <1.9`) is added.

### Added

- `replay::ReplayWindow::with_size` and `size`, plus
  `SrtpSession::with_replay_window` and `SrtcpSession::with_replay_window`
  (64 to 1024 packets).
- `SrtcpSession::require_encryption` rejects authenticated packets with the E
  flag clear (`SrtpError::Unencrypted`).
- `SrtpSession::with_roc`, `SenderRoc::with_roc` and `ReceiverRoc::with_roc` to
  continue a stream's ROC after a rekey, as RFC 3711 §3.3.1 requires.
- `Profile::srtcp_tag_len` (10 bytes for both AES-CM profiles, 16 for GCM).
- `ffi::commoncrypto::aes_ctr_in_place` and `SessionKeys`.
- `SrtpError::{KeyExpired, IndexReused, SessionKeyReuse, InvalidReplayWindow,
  Unencrypted, SessionStarted}`.
- Known-answer tests from libsrtp (`srtp_validate`, `srtp_validate_gcm`) and
  RFC 7714 §17.3 / §17.4, plus AES-CTR tests for lengths that are not a
  multiple of the block size.

## [0.1.0] - 2026-06-04

Initial release.

### Added

- **AES-GCM profiles** (RFC 7714): `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM`
  for both SRTP and SRTCP, using CryptoKit through the sibling `cryptokit-rs`
  binding. Validated byte-for-byte against the RFC 7714 §16 and §17 vectors.
- **AES-CM profiles** (RFC 3711): `AES_CM_128_HMAC_SHA1_80` and
  `AES_CM_128_HMAC_SHA1_32`, with AES-CTR keystream and HMAC-SHA1 truncated
  authentication via a thin CommonCrypto FFI.
- **Key-derivation function** (RFC 3711 §4.3): derives the session cipher key,
  cipher salt and authentication key from a master key/salt, validated against
  the §B.3 vectors. `SrtpKey::from_master` runs the KDF; `SrtpKey::from_session`
  accepts pre-derived session keys.
- **Session API**: `SrtpSession::protect` / `unprotect` for RTP and
  `SrtcpSession::protect` / `unprotect` for RTCP, operating in place over the
  `rtp-rs` borrowing contract so authentication tags stay valid.
- **Roll-over counter**: a monotonic sender counter and the RFC 3711 Appendix A
  receiver estimator that recovers the 48-bit packet index across 16-bit
  sequence-number wraps.
- **Anti-replay**: a 64-packet sliding window (RFC 3711 §3.3.2) that is checked
  before authentication and only committed after the tag verifies.
- **SRTCP framing**: the E-bit and 31-bit SRTCP index trailer, for both the
  AES-GCM and AES-CM wire layouts.
- **Constant-time** authentication-tag comparison.
- Three runnable examples and an integration test suite covering the RFC 3711
  and RFC 7714 vectors plus multi-packet, sequence-wrap, replay and tamper
  round-trips.

### Notes

- No third-party crypto crates: primitives come from Apple's CryptoKit and
  CommonCrypto. The only crates.io dependency is `libc`; the rest are sibling
  path dependencies (`rtp-rs`, `cryptokit-rs`).
- Apple-platform only (macOS, iOS, …); the security frameworks are linked
  automatically.
- Deferred to a later release: RFC 6904 header-extension encryption, MKI,
  non-zero key-derivation rates, and the `NULL` cipher/auth debugging profiles.
  See [COVERAGE.md](COVERAGE.md) for the full matrix.

[0.2.0]: https://github.com/doom-fish/srtp-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/doom-fish/srtp-rs/releases/tag/v0.1.0
