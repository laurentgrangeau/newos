//! Workspace E2E integration test crate (`H5`).

use newos_rng::{EntropySource, RngError};

/// Deterministic `SplitMix64` entropy source shared by host E2E and regression tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicTestEntropy(pub u64);

impl EntropySource for DeterministicTestEntropy {
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        for b in dst.iter_mut() {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)).to_le_bytes()[0];
        }
        Ok(())
    }
}
