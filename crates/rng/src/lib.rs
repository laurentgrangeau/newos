#![no_std]

//! Capability-Scoped EL0 Hardware Entropy & Fast-Key-Erasure CSPRNG (`newos-rng`).
//!
//! Supports both hardware targets:
//! - **Raspberry Pi 5 (BCM2712):** Broadcom `iproc-rng200` (`0x10_7D20_8000`, zero DMA)
//! - **QEMU `aarch64` `virt`:** Modern VirtIO 1.0+ MMIO RNG (`virtio-rng-device`, `device_id == 4`)
//!
//! Raw hardware entropy passes NIST SP 800-90B startup health tests (fail-closed),
//! is conditioned with FIPS 202 `SHAKE256`, and drives a fast-key-erasure ChaCha20 CSPRNG.

#[cfg(feature = "bcm2712")]
pub mod bcm2712;
#[cfg(feature = "csprng")]
pub mod csprng;
#[cfg(feature = "virtio")]
pub mod virtio;

#[cfg(feature = "bcm2712")]
pub use bcm2712::Bcm2712Rng200;
#[cfg(feature = "csprng")]
pub use csprng::{
    ConditionedCsprng, RESEED_INTERVAL_BYTES, SEED_BLOCK_BYTES, verify_entropy_health,
};
#[cfg(feature = "virtio")]
pub use virtio::{VIRTIO_DEVICE_RNG, VIRTIO_MMIO_MAGIC, VirtioRngDevice, VirtioRngDma};

use newos_abi::SysError;

/// Capability-scoped MMIO + `VirtToPhys` transport for EL0 RNG drivers.
pub trait RngTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
    fn virt_to_phys<T>(&self, _r: &T) -> Result<u64, SysError> {
        Err(SysError::Unsupported)
    }
}

/// Raw hardware entropy source trait implemented by `Bcm2712Rng200` and `VirtioRngDevice`.
pub trait EntropySource {
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError>;
}

/// Detected EL0 hardware RNG backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngKind {
    /// QEMU `virt` modern VirtIO-MMIO v2 RNG (`device_id == 4`).
    VirtioRng { version: u32 },
    /// Raspberry Pi 5 BCM2712 Broadcom `iproc-rng200`.
    Bcm2712Rng200,
}

impl RngKind {
    pub fn driver_name(&self) -> &'static str {
        match self {
            RngKind::VirtioRng { .. } => "virtio-rng-v2",
            RngKind::Bcm2712Rng200 => "bcm2712-rng200",
        }
    }
}

/// Fail-closed hardware RNG & CSPRNG error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    Sys(SysError),
    DeviceNotFound,
    HardwareFault,
    HardwareTimeout,
    HealthCheckFailed,
}

/// Probe a capability-scoped `BOOTSTRAP_RNG_MMIO` region to detect VirtIO-RNG v2 or BCM2712 RNG200.
pub fn probe_rng<F>(mut read32: F) -> Result<RngKind, RngError>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    let reg0 = read32(0x00).map_err(RngError::Sys)?;
    #[cfg(feature = "virtio")]
    if reg0 == VIRTIO_MMIO_MAGIC {
        let version = read32(0x04).map_err(RngError::Sys)?;
        let device_id = read32(0x08).map_err(RngError::Sys)?;
        if device_id == VIRTIO_DEVICE_RNG && version >= 2 {
            return Ok(RngKind::VirtioRng { version });
        }
        return Err(RngError::DeviceNotFound);
    }
    let _ = reg0;
    #[cfg(feature = "bcm2712")]
    {
        // Otherwise validate that `REG_FIFO_COUNT` (`0x24`) is readable within the scoped `0x28` window.
        let _ = read32(bcm2712::REG_FIFO_COUNT).map_err(RngError::Sys)?;
        Ok(RngKind::Bcm2712Rng200)
    }
    #[cfg(not(feature = "bcm2712"))]
    Err(RngError::DeviceNotFound)
}

#[cfg(test)]
#[cfg(all(feature = "bcm2712", feature = "virtio", feature = "csprng"))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct MockBcm2712Transport {
        ctrl: AtomicU32,
        state: AtomicU32,
        lockout: bool,
    }

    impl MockBcm2712Transport {
        fn new(seed: u32, lockout: bool) -> Self {
            Self {
                ctrl: AtomicU32::new(0),
                state: AtomicU32::new(seed),
                lockout,
            }
        }
    }

    impl RngTransport for &MockBcm2712Transport {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                bcm2712::REG_CTRL => Ok(self.ctrl.load(Ordering::Relaxed)),
                bcm2712::REG_INT_STATUS => Ok(if self.lockout {
                    bcm2712::INT_MASTER_FAIL_LOCKOUT
                } else {
                    0
                }),
                bcm2712::REG_FIFO_COUNT => Ok(4),
                bcm2712::REG_FIFO_DATA => {
                    // Deterministic high-entropy-looking SplitMix32 sequence for unit test
                    let mut x = self
                        .state
                        .fetch_add(0x9E37_79B9, Ordering::Relaxed)
                        .wrapping_add(0x9E37_79B9);
                    x = (x ^ (x >> 16)).wrapping_mul(0x85EB_CA6B);
                    x = (x ^ (x >> 13)).wrapping_mul(0xC2B2_AE35);
                    Ok(x ^ (x >> 16))
                }
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == bcm2712::REG_CTRL {
                self.ctrl.store(val, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    #[test]
    fn probe_detects_virtio_rng_and_bcm2712() {
        let v = probe_rng(|off| match off {
            0x00 => Ok(VIRTIO_MMIO_MAGIC),
            0x04 => Ok(2),
            0x08 => Ok(VIRTIO_DEVICE_RNG),
            _ => Ok(0),
        })
        .unwrap();
        assert_eq!(v, RngKind::VirtioRng { version: 2 });

        let b = probe_rng(|off| match off {
            0x00 => Ok(0),
            bcm2712::REG_FIFO_COUNT => Ok(8),
            _ => Ok(0),
        })
        .unwrap();
        assert_eq!(b, RngKind::Bcm2712Rng200);
    }

    #[test]
    fn bcm2712_driver_initializes_and_feeds_conditioned_csprng() {
        let mock = MockBcm2712Transport::new(0x1234_5678, false);
        let drv = Bcm2712Rng200::init(&mock).expect("bcm2712 init");
        assert_eq!(mock.ctrl.load(Ordering::Relaxed) & bcm2712::CTRL_RBGEN, 1);

        let mut rng = ConditionedCsprng::new(drv, b"newos-test").expect("csprng seed");
        let key_before = rng.debug_key_snapshot();

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a).unwrap();
        let key_after = rng.debug_key_snapshot();
        rng.fill_bytes(&mut b).unwrap();

        // Fast-key-erasure: key must mutate on every request and outputs must differ.
        assert_ne!(key_before, key_after);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn bcm2712_lockout_fault_fails_closed() {
        let mock = MockBcm2712Transport::new(0x1234_5678, true);
        assert_eq!(
            Bcm2712Rng200::init(&mock).err(),
            Some(RngError::HardwareFault)
        );
    }

    #[test]
    fn health_check_fails_closed_on_stuck_or_zero_entropy() {
        struct StuckSource(u8);
        impl EntropySource for StuckSource {
            fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
                dst.fill(self.0);
                Ok(())
            }
        }

        assert_eq!(
            ConditionedCsprng::new(StuckSource(0x00), b"").err(),
            Some(RngError::HealthCheckFailed)
        );
        assert_eq!(
            ConditionedCsprng::new(StuckSource(0xFF), b"").err(),
            Some(RngError::HealthCheckFailed)
        );

        // Biased source (alternating 0xAA/0x55 -> fails Adaptive Proportion Test: 32 > 16)
        struct BiasedSource;
        impl EntropySource for BiasedSource {
            fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
                for (i, b) in dst.iter_mut().enumerate() {
                    *b = if i % 2 == 0 { 0xAA } else { 0x55 };
                }
                Ok(())
            }
        }
        assert_eq!(
            ConditionedCsprng::new(BiasedSource, b"").err(),
            Some(RngError::HealthCheckFailed)
        );
    }

    #[test]
    fn rfc8439_chacha20_block_vector() {
        // RFC 8439 Section 2.3.2 test vector
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let block = csprng::chacha20_block(&key, 1, &nonce);
        let expected_first_16 = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        assert_eq!(&block[..16], &expected_first_16);
    }
}
