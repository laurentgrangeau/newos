#![no_std]

//! Modular Cryptographic Abstraction Layer
//! for `NewOS`.
//!
//! Every cryptographic algorithm is independently toggleable via Cargo features:
//! - `--no-default-features`: zero cryptographic implementations compiled in (traits & registry only).
//! - `sha3`: FIPS 202 `SHA3-512` + `SHAKE256` XOF.
//! - `chacha20-poly1305`: RFC 8439 / OpenSSH `chacha20-poly1305@openssh.com` AEAD.
//! - `ml-kem-1024`: NIST FIPS 203 ML-KEM-1024 key encapsulation mechanism.
//! - `ml-dsa-87`: NIST FIPS 204 ML-DSA-87 digital signature scheme.
//! - `suite-pq-level5`: enables the NIST Level 5 post-quantum suite.

#[cfg(feature = "chacha20-poly1305")]
pub mod chacha20_poly1305;
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa;
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem;
#[cfg(feature = "sha3")]
pub mod sha3;

/// Common cryptographic operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoError {
    /// Supplied key slice did not match the algorithm's required key size.
    InvalidKeyLength,
    /// Supplied input buffer violated algorithm preconditions (e.g., too short).
    InvalidInput,
    /// AEAD authentication tag verification failed in constant time.
    AuthenticationFailed,
    /// Digital signature verification failed.
    SignatureInvalid,
    /// Requested cryptographic algorithm is not enabled in this build.
    UnsupportedAlgorithm,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::InvalidKeyLength => "invalid cryptographic key length",
            Self::InvalidInput => "invalid cryptographic input",
            Self::AuthenticationFailed => "AEAD authentication failed",
            Self::SignatureInvalid => "digital signature invalid",
            Self::UnsupportedAlgorithm => "unsupported cryptographic algorithm",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for CryptoError {}

/// Fixed-output cryptographic hash function (e.g., `SHA3-512`, future `SHA-256` / `BLAKE3`).
pub trait Hasher<const N: usize> {
    const NAME: &'static str;

    fn hash(data: &[u8]) -> [u8; N];

    #[must_use]
    fn digest_prefix_u64(data: &[u8]) -> u64 {
        let d = Self::hash(data);
        let mut b = [0u8; 8];
        let take = N.min(8);
        b[..take].copy_from_slice(&d[..take]);
        u64::from_be_bytes(b)
    }
}

/// Extendable-output function (XOF) for KDF / CSPRNG expansion (e.g., `SHAKE256`).
pub trait Xof {
    const NAME: &'static str;

    fn derive(input: &[u8], out: &mut [u8]);
}

/// Authenticated Encryption with Associated Data (AEAD) cipher.
pub trait AeadCipher {
    const NAME: &'static str;
    const KEY_LEN: usize;
    const TAG_LEN: usize;

    /// Encrypt `packet_with_len` in place and return its 16-byte authentication tag.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if `packet_with_len` is shorter than the 4-byte
    /// packet length header.
    fn seal_packet(&self, seq: u64, packet_with_len: &mut [u8]) -> Result<[u8; 16], CryptoError>;

    /// Verify `tag` in constant time and decrypt `packet_with_len` in place.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if `packet_with_len` is shorter than the 4-byte
    /// packet length header, or [`CryptoError::AuthenticationFailed`] if tag verification fails.
    fn open_packet(
        &self,
        seq: u64,
        packet_with_len: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError>;
}

/// Key Encapsulation Mechanism (KEM) interface (e.g., `ML-KEM-1024`, future `X25519`).
pub trait Kem {
    const NAME: &'static str;
    const EK_BYTES: usize;
    const CT_BYTES: usize;
    const SS_BYTES: usize;
}

/// Digital signature scheme interface (e.g., `ML-DSA-87`, future `Ed25519`).
pub trait SignatureScheme {
    const NAME: &'static str;
    const PK_BYTES: usize;
    const SIG_BYTES: usize;
}

/// Compile-time list of cryptographic algorithms enabled in this build.
pub const ENABLED_ALGORITHMS: &[&str] = &[
    #[cfg(feature = "sha3")]
    "sha3-512",
    #[cfg(feature = "sha3")]
    "shake256",
    #[cfg(feature = "chacha20-poly1305")]
    "chacha20-poly1305@openssh.com",
    #[cfg(feature = "ml-kem-1024")]
    "ml-kem-1024",
    #[cfg(feature = "ml-dsa-87")]
    "ml-dsa-87",
];

/// Returns `true` if any cryptographic algorithm is compiled into this build.
#[inline]
#[must_use]
pub const fn has_any_crypto() -> bool {
    !ENABLED_ALGORITHMS.is_empty()
}

/// Returns `true` if the named algorithm is compiled into this build.
#[must_use]
pub fn is_algorithm_enabled(name: &str) -> bool {
    ENABLED_ALGORITHMS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_reflects_compiled_features() {
        assert_eq!(is_algorithm_enabled("sha3-512"), cfg!(feature = "sha3"));
        assert_eq!(is_algorithm_enabled("shake256"), cfg!(feature = "sha3"));
        assert_eq!(
            is_algorithm_enabled("chacha20-poly1305@openssh.com"),
            cfg!(feature = "chacha20-poly1305")
        );
        assert_eq!(
            is_algorithm_enabled("ml-kem-1024"),
            cfg!(feature = "ml-kem-1024")
        );
        assert_eq!(
            is_algorithm_enabled("ml-dsa-87"),
            cfg!(feature = "ml-dsa-87")
        );
        let any_expected = cfg!(feature = "sha3")
            || cfg!(feature = "chacha20-poly1305")
            || cfg!(feature = "ml-kem-1024")
            || cfg!(feature = "ml-dsa-87");
        assert_eq!(has_any_crypto(), any_expected);
    }

    #[test]
    fn crypto_error_display_and_core_error() {
        use core::fmt::Write as _;

        fn assert_error<E: core::error::Error>(_: &E) {}

        struct StackWriter {
            buf: [u8; 64],
            len: usize,
        }

        impl core::fmt::Write for StackWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let avail = self.buf.len().saturating_sub(self.len);
                let copy = bytes.len().min(avail);
                self.buf[self.len..self.len + copy].copy_from_slice(&bytes[..copy]);
                self.len += copy;
                Ok(())
            }
        }

        let variants = [
            CryptoError::InvalidKeyLength,
            CryptoError::InvalidInput,
            CryptoError::AuthenticationFailed,
            CryptoError::SignatureInvalid,
            CryptoError::UnsupportedAlgorithm,
        ];
        for err in variants {
            assert_error(&err);
            let mut writer = StackWriter {
                buf: [0u8; 64],
                len: 0,
            };
            assert!(write!(&mut writer, "{err}").is_ok());
            assert!(writer.len > 0);
        }
    }
}
