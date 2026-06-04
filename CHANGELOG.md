# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-06-04

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

[0.1.0]: https://github.com/doom-fish/srtp-rs/releases/tag/v0.1.0
