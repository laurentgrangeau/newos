//! NIST FIPS 203 **ML-KEM-1024** Key Encapsulation Mechanism adapter (`newos-crypto`).

use crate::Kem;

pub use ml_kem::{
    B32, Ciphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024, Seed,
    kem::{Decapsulate, KeyExport},
};

/// ML-KEM-1024 wire sizes (FIPS 203).
pub const EK_BYTES: usize = 1568;
pub const CT_BYTES: usize = 1568;
pub const SS_BYTES: usize = 32;

/// Marker type implementing [`Kem`] for NIST Level 5 ML-KEM-1024.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MlKem1024Scheme;

impl Kem for MlKem1024Scheme {
    const NAME: &'static str = "ml-kem-1024";
    const EK_BYTES: usize = EK_BYTES;
    const CT_BYTES: usize = CT_BYTES;
    const SS_BYTES: usize = SS_BYTES;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_trait_constants_match_fips203() {
        fn assert_std_traits<T: core::fmt::Debug + Default + Copy + Eq + core::hash::Hash>(
            expected: T,
        ) {
            assert_eq!(T::default(), expected);
        }
        assert_std_traits(MlKem1024Scheme);
        assert_eq!(MlKem1024Scheme::NAME, "ml-kem-1024");
        assert_eq!(MlKem1024Scheme::EK_BYTES, 1568);
        assert_eq!(MlKem1024Scheme::CT_BYTES, 1568);
        assert_eq!(MlKem1024Scheme::SS_BYTES, 32);
    }
}
