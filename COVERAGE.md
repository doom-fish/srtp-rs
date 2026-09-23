# Coverage

This crate implements SRTP/SRTCP by hand against RFC 3711 and RFC 7714, using
Apple's CryptoKit (AES-GCM) and CommonCrypto (AES-CTR, HMAC-SHA1) for the
underlying primitives. The tables below record what is covered, what is
intentionally deferred, and the honest gaps.

## RFC coverage

| RFC | Title | Status |
|-----|-------|--------|
| 3711 | SRTP / SRTCP | AES-CM cipher, HMAC-SHA1 auth, KDF, ROC, replay window, SRTCP framing, key lifetime |
| 7714 | AES-GCM for SRTP/SRTCP | `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM`, SRTP and SRTCP (encrypted and tag-only) |

## Crypto transforms

| Profile | DTLS-SRTP id | SRTP | SRTCP | Validated against |
|---------|--------------|------|-------|-------------------|
| `AEAD_AES_128_GCM` | 0x0007 | ✅ | ✅ | RFC 7714 §16.1, §17.1, §17.3 (byte-exact); libsrtp `srtp_validate_gcm` |
| `AEAD_AES_256_GCM` | 0x0008 | ✅ | ✅ | RFC 7714 §16.2 (SRTP), §17.2 and §17.4 (SRTCP verify) |
| `AES_CM_128_HMAC_SHA1_80` | 0x0001 | ✅ | ✅ | libsrtp `srtp_validate` SRTP and SRTCP packets (byte-exact); RFC 3711 §B.2 keystream |
| `AES_CM_128_HMAC_SHA1_32` | 0x0002 | ✅ | ✅ | round-trip only (same cipher path as `_80`, 4-byte tag) |

## Building blocks

| Component | Status | Reference |
|-----------|--------|-----------|
| Key derivation function | ✅ cipher key / salt / auth key | RFC 3711 §4.3, validated against §B.3 |
| AES-CM keystream | ✅ | RFC 3711 §4.1.1, validated against §B.2 |
| AES-GCM seal/open with AAD | ✅ | RFC 7714 §8, §9 |
| HMAC-SHA1 auth tag (80/32-bit) | ✅ | RFC 3711 §4.2.1 |
| Roll-over counter (sender) | ✅ | RFC 3711 §3.3.1 |
| Roll-over counter (receiver estimator) | ✅ | RFC 3711 Appendix A |
| Anti-replay sliding window (64–1024, default 1024) | ✅ check-then-commit | RFC 3711 §3.3.2 |
| SRTCP E-bit + 31-bit index trailer | ✅ both layouts on receive; optional `require_encryption` | RFC 3711 §3.4, RFC 7714 §9.2–9.3 |
| Key lifetime (2^48 SRTP / 2^31 SRTCP packets) | ✅ `KeyExpired`, no ROC or index wrap | RFC 3711 §3.3.1, §9.2 |
| Sender index reuse | ✅ refused with `IndexReused` | RFC 3711 §9.1 |
| Distinct SRTP and SRTCP session keys | ✅ enforced by `from_session` | RFC 3711 §4.3 |
| Constant-time tag comparison | ✅ | — |
| Key material zeroized on drop | ✅ `zeroize` | — |

## Test vectors reproduced

| Vector | What it checks |
|--------|----------------|
| RFC 7714 §16.1.1 | SRTP `AEAD_AES_128_GCM` encrypt, full packet byte-exact |
| RFC 7714 §16.1.2 | SRTP `AEAD_AES_128_GCM` decrypt |
| RFC 7714 §16.2.1 | SRTP `AEAD_AES_256_GCM` encrypt, full packet byte-exact |
| RFC 7714 §17.1 | SRTCP `AEAD_AES_128_GCM` encrypt + decrypt, byte-exact |
| RFC 7714 §17.2 | SRTCP `AEAD_AES_256_GCM` decrypt |
| RFC 7714 §17.3 / §17.4 | SRTCP tag-only (E = 0) verification, 128- and 256-bit keys |
| libsrtp `srtp_validate` | `AES_CM_128_HMAC_SHA1_80` SRTP and SRTCP packets from a master key, both directions |
| libsrtp `srtp_validate_gcm` | `AEAD_AES_128_GCM` SRTP and SRTCP packets from a master key (12-byte salt), both directions |
| RFC 3711 §B.2 | AES-CM keystream (three blocks), and every prefix length from 0 to 48 bytes |
| RFC 3711 §B.3 | KDF cipher key, cipher salt, 94-octet auth key |

Plus self-consistent property tests: 200-packet streams across all four
profiles, 16-bit sequence-number wrap with ROC advance, anti-replay rejection,
authentication-tag tamper rejection, key-lifetime and index-reuse limits,
configurable replay windows, E-flag handling, and AES-CTR output for lengths
0 to 4097 checked against CryptoKit's AES-GCM counter stream.

## Intentionally deferred

These are out of scope for the 0.2 release and documented honestly rather than
stubbed:

- **RFC 6904** — encryption of RTP header extensions. Not implemented; header
  extensions are authenticated (when present in the authenticated portion) but
  not separately encrypted.
- **MKI** (Master Key Identifier, RFC 3711 §3.1) — not emitted or parsed; a
  single master key per session is assumed.
- **Key-derivation rate** — fixed at 0 (derive once per session), which is the
  universally deployed setting and the one the RFC test vectors use. Non-zero
  rates that re-derive mid-session are not supported.
- **`AES_CM_128_HMAC_SHA1_*` with non-default tag/auth lengths** beyond the two
  standard 80/32-bit variants.
- **`NULL` cipher / `NULL` auth** debugging profiles.
- **Sending unencrypted SRTCP.** Receivers verify E = 0 packets; senders always
  encrypt.

## Platform notes

The cryptographic primitives come from Apple frameworks (CryptoKit via
`cryptokit-rs`, CommonCrypto via a local FFI), so the crate is Apple-platform
only. There are no third-party crypto crates in the dependency graph; the sole
crates.io dependency is `zeroize`.
