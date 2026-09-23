//! Shared hex helpers for the integration tests.

#![allow(dead_code)]

/// Decode a hex string, ignoring all ASCII whitespace.
#[must_use]
pub fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encode bytes as a lower-case hex string.
#[must_use]
pub fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[must_use]
pub fn srtp_session_key(profile: srtp::Profile, key: &[u8], salt: &[u8]) -> srtp::SrtpKey {
    let other: Vec<u8> = key.iter().map(|b| !b).collect();
    srtp::SrtpKey::from_session(
        profile,
        srtp::SessionKeys {
            encryption: key,
            salt,
            authentication: &[],
        },
        srtp::SessionKeys {
            encryption: &other,
            salt,
            authentication: &[],
        },
    )
    .unwrap()
}

#[must_use]
pub fn srtcp_session_key(profile: srtp::Profile, key: &[u8], salt: &[u8]) -> srtp::SrtpKey {
    let other: Vec<u8> = key.iter().map(|b| !b).collect();
    srtp::SrtpKey::from_session(
        profile,
        srtp::SessionKeys {
            encryption: &other,
            salt,
            authentication: &[],
        },
        srtp::SessionKeys {
            encryption: key,
            salt,
            authentication: &[],
        },
    )
    .unwrap()
}
