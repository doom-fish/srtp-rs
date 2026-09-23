//! SRTP crypto profiles (a.k.a. protection profiles / crypto suites) and their
//! key, salt, and tag length tables.
//!
//! The IANA "DTLS-SRTP Protection Profiles" registry assigns each profile a
//! two-octet value; those values are what DTLS-SRTP (RFC 5764) negotiates and
//! what `dtls-rs` will hand to this crate when it exports keying material.

/// A negotiated SRTP protection profile.
///
/// The two AES-GCM profiles (RFC 7714) are the WebRTC default and the primary
/// target of this crate. The two AES-CM / HMAC-SHA1 profiles (RFC 3711,
/// registered by RFC 5764) are provided for interoperability with SFUs and
/// older media endpoints that only offer them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// `SRTP_AEAD_AES_128_GCM` (RFC 7714), IANA value `0x0007`. The WebRTC
    /// default and the primary target of this crate.
    AeadAes128Gcm,
    /// `SRTP_AEAD_AES_256_GCM` (RFC 7714), IANA value `0x0008`.
    AeadAes256Gcm,
    /// `SRTP_AES128_CM_HMAC_SHA1_80` (RFC 5764 §4.1.2), IANA value `0x0001`.
    /// AES counter-mode encryption with an 80-bit HMAC-SHA1 tag.
    AesCm128HmacSha1_80,
    /// `SRTP_AES128_CM_HMAC_SHA1_32` (RFC 5764 §4.1.2), IANA value `0x0002`.
    /// As above but with a 32-bit HMAC-SHA1 tag.
    AesCm128HmacSha1_32,
}

impl Profile {
    /// The IANA "DTLS-SRTP Protection Profiles" two-octet identifier.
    #[must_use]
    pub const fn iana_value(self) -> u16 {
        match self {
            Self::AeadAes128Gcm => 0x0007,
            Self::AeadAes256Gcm => 0x0008,
            Self::AesCm128HmacSha1_80 => 0x0001,
            Self::AesCm128HmacSha1_32 => 0x0002,
        }
    }

    /// Whether this profile uses an AEAD cipher (AES-GCM) rather than the
    /// encrypt-then-MAC AES-CM / HMAC-SHA1 construction.
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }

    /// Length in bytes of the master key carried by DTLS-SRTP keying material.
    #[must_use]
    pub const fn master_key_len(self) -> usize {
        match self {
            Self::AeadAes256Gcm => 32,
            _ => 16,
        }
    }

    /// Length in bytes of the master salt carried by DTLS-SRTP keying material.
    #[must_use]
    pub const fn master_salt_len(self) -> usize {
        match self {
            // AES-GCM uses a 96-bit master salt (RFC 7714 Tables 2 & 3).
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 12,
            // AES-CM uses a 112-bit master salt (RFC 3711 §5).
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => 14,
        }
    }

    /// Length in bytes of the derived session encryption key.
    #[must_use]
    pub const fn session_key_len(self) -> usize {
        self.master_key_len()
    }

    /// Length in bytes of the derived session salt.
    ///
    /// For AES-GCM this is the 96-bit (12-octet) value that is XORed with the
    /// per-packet `(SSRC || ROC || SEQ)` IV input (RFC 7714 §8.1). For AES-CM
    /// it is the 112-bit (14-octet) cipher salt (RFC 3711 §4.1.1).
    #[must_use]
    pub const fn session_salt_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 12,
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => 14,
        }
    }

    /// Length in bytes of the derived session authentication key.
    ///
    /// Zero for AES-GCM (authentication is built into the AEAD); 20 bytes
    /// (160-bit HMAC-SHA1 key) for the AES-CM profiles (RFC 3711 §5.2).
    #[must_use]
    pub const fn auth_key_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 0,
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => 20,
        }
    }

    /// Length in bytes of the authentication tag appended to a protected
    /// SRTP packet (the AEAD tag for GCM, the truncated HMAC for AES-CM).
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 16,
            Self::AesCm128HmacSha1_80 => 10,
            Self::AesCm128HmacSha1_32 => 4,
        }
    }

    #[allow(missing_docs)]
    #[must_use]
    pub const fn srtcp_tag_len(self) -> usize {
        match self {
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 16,
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 => 10,
        }
    }

    /// Construct a profile from its IANA two-octet identifier.
    #[must_use]
    pub const fn from_iana_value(value: u16) -> Option<Self> {
        match value {
            0x0007 => Some(Self::AeadAes128Gcm),
            0x0008 => Some(Self::AeadAes256Gcm),
            0x0001 => Some(Self::AesCm128HmacSha1_80),
            0x0002 => Some(Self::AesCm128HmacSha1_32),
            _ => None,
        }
    }
}
