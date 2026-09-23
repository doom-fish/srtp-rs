# srtp-rs

Secure RTP and RTCP (**SRTP** / **SRTCP**, RFC 3711 with the RFC 7714 AES-GCM
authenticated-encryption profiles) layered directly on the sibling `rtp-rs`
wire codec. `srtp-rs` protects and unprotects packets in place, tracks the
roll-over counter and a sliding anti-replay window, and validates against the
published RFC test vectors byte-for-byte.

Cryptography is provided by the Apple security frameworks — AES-GCM via the
sibling `cryptokit-rs` binding (CryptoKit) and AES-CTR plus HMAC-SHA1 via a
thin CommonCrypto FFI — so there are **no third-party crypto crates** in the
dependency tree. The only crates.io dependency is `zeroize`, which wipes key
material on drop; everything else is a sibling path dependency.

The crate is not published to crates.io (`publish = false`); depend on it by
path from a sibling checkout:

```toml
[dependencies]
srtp = { package = "srtp-rs", path = "../srtp-rs", version = "0.1" }
```

## Features

| Area | Coverage |
|------|----------|
| **AES-GCM profiles** (RFC 7714) | `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` for both SRTP and SRTCP |
| **AES-CM profiles** (RFC 3711) | `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32` |
| **Key derivation** (RFC 3711 §4.3) | AES-CM PRF deriving cipher key, salt and auth key from a master key/salt |
| **Roll-over counter** | sender counter + receiver estimator (RFC 3711 Appendix A) |
| **Anti-replay** | sliding window (RFC 3711 §3.3.2) of 64 to 1024 packets, default 1024 (`with_replay_window`); checked before auth, committed after |
| **Key lifetime** | protecting past 2^48 SRTP or 2^31 SRTCP packets fails with `KeyExpired`; a sender never protects the same index twice (`IndexReused`) |
| **SRTCP** | E-bit + 31-bit index trailer, GCM and AES-CM; unencrypted (E = 0) packets are verified on both paths and can be refused with `require_encryption(true)`; senders always encrypt |
| **Key material** | session keys, derived keys and keystreams are zeroized on drop; `Debug` never prints them |
| **In-place processing** | authenticates and decrypts over the original wire bytes via the `rtp-rs` borrowing contract |

## Quick start

Protect an outgoing RTP packet and unprotect it on the far side:

```rust
use srtp::rtp::{Packet, RtpPacket};
use srtp::{Profile, SrtpKey, SrtpSession};

// Shared master key (16 octets) + master salt (12 octets for GCM).
let master_key: Vec<u8> = (0u8..16).collect();
let master_salt: Vec<u8> = (0u8..12).collect();
let key = SrtpKey::from_master(&master_key, &master_salt, Profile::AeadAes128Gcm).unwrap();

let mut sender = SrtpSession::new_sender(key.clone());
let mut receiver = SrtpSession::new_receiver(key);

let packet = RtpPacket::builder()
    .ssrc(0xcafe_b0ba)
    .sequence_number(1000)
    .payload(b"hello srtp")
    .build()
    .unwrap();

let mut buf = vec![0u8; 64];
let n = sender.protect(&packet.as_view(), &mut buf).unwrap();
buf.truncate(n);

let recovered = receiver.unprotect(&mut buf).unwrap();
assert_eq!(recovered.payload(), b"hello srtp");
```

Protect an RTCP compound packet:

```rust
use srtp::rtp::{CompoundPacket, RtcpPacket};
use srtp::{Profile, SrtcpSession, SrtpKey};

let master_key: Vec<u8> = (0u8..16).collect();
let master_salt: Vec<u8> = (0u8..12).collect();
let key = SrtpKey::from_master(&master_key, &master_salt, Profile::AeadAes128Gcm).unwrap();

let mut tx = SrtcpSession::new_sender(key.clone());
let mut rx = SrtcpSession::new_receiver(key);

let rtcp = CompoundPacket::new()
    .add(RtcpPacket::receiver_report().ssrc(0x4d61_7273).build())
    .encode()
    .unwrap();

let mut buf = vec![0u8; rtcp.len() + 32];
let n = tx.protect(&rtcp, &mut buf).unwrap();
buf.truncate(n);

let recovered = rx.unprotect(&buf).unwrap();
assert_eq!(recovered, rtcp);
```

## How it derives keys

`SrtpKey` is constructed either from master key material (and runs the RFC 3711
key-derivation function for you) or directly from pre-derived session keys.
DTLS-SRTP (RFC 5764) exports a master key and salt, so use `from_master` for
it. `from_session` takes separate SRTP and SRTCP keys and rejects a key shared
by both directions, because their IVs coincide:

```rust
use srtp::{Profile, SessionKeys, SrtpKey};

// Run the KDF from a master key + salt.
let mk: Vec<u8> = (0u8..16).collect();
let ms: Vec<u8> = (0u8..14).collect();
let derived = SrtpKey::from_master(&mk, &ms, Profile::AesCm128HmacSha1_80).unwrap();

// Or supply already-derived session keys for each direction.
let salt: Vec<u8> = (0u8..14).collect();
let rtp_enc: Vec<u8> = (0u8..16).collect();
let rtp_auth: Vec<u8> = (0u8..20).collect();
let rtcp_enc: Vec<u8> = (16u8..32).collect();
let rtcp_auth: Vec<u8> = (20u8..40).collect();
let session = SrtpKey::from_session(
    Profile::AesCm128HmacSha1_80,
    SessionKeys { encryption: &rtp_enc, salt: &salt, authentication: &rtp_auth },
    SessionKeys { encryption: &rtcp_enc, salt: &salt, authentication: &rtcp_auth },
)
.unwrap();
```

## Validated against the RFCs

The test suite reproduces the published vectors exactly:

- **RFC 7714 §16.1 / §16.2** — `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM` SRTP
  encrypt and decrypt, byte-for-byte.
- **RFC 7714 §17.1 / §17.2** — `AEAD_AES_128_GCM` SRTCP encrypt/decrypt and the
  `AEAD_AES_256_GCM` SRTCP decrypt vector.
- **RFC 7714 §17.3 / §17.4** — unencrypted (tag-only) SRTCP for both key sizes.
- **libsrtp `srtp_validate` / `srtp_validate_gcm`** — full `AES_CM_128_HMAC_SHA1_80`
  and `AEAD_AES_128_GCM` SRTP and SRTCP packets from a master key, in both
  directions.
- **RFC 3711 §B.2** — the AES-CM keystream, at every length from 0 to 48 bytes.
- **RFC 3711 §B.3** — the key-derivation cipher key, cipher salt and auth key.

See [COVERAGE.md](COVERAGE.md) for the full matrix and the honestly-deferred
items.

## Examples

```sh
cargo run --example 01_protect_packet
cargo run --example 02_unprotect_packet
cargo run --example 03_kdf_demo
```

## Platform

The crypto primitives are provided by Apple's CryptoKit and CommonCrypto, so
this crate targets Apple platforms (macOS, iOS, …). The frameworks are linked
automatically; no system packages are required.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
