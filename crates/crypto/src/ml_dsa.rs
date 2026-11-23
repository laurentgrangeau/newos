//! NIST FIPS 204 **ML-DSA-87** Digital Signature Scheme adapter (`newos-crypto`).

use crate::SignatureScheme;

pub use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey,
    VerifyingKey,
};

/// ML-DSA-87 wire sizes (FIPS 204).
pub const PK_BYTES: usize = 2592;
pub const SIG_BYTES: usize = 4627;

/// Marker type implementing [`SignatureScheme`] for NIST Level 5 ML-DSA-87.
pub struct MlDsa87Scheme;

impl SignatureScheme for MlDsa87Scheme {
    const NAME: &'static str = "ml-dsa-87";
    const PK_BYTES: usize = PK_BYTES;
    const SIG_BYTES: usize = SIG_BYTES;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_trait_constants_match_fips204() {
        assert_eq!(MlDsa87Scheme::NAME, "ml-dsa-87");
        assert_eq!(MlDsa87Scheme::PK_BYTES, 2592);
        assert_eq!(MlDsa87Scheme::SIG_BYTES, 4627);
    }
}
