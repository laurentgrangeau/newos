#![no_std]

//! Capability-Scoped EL0 Hardware Entropy & Fast-Key-Erasure CSPRNG (`newos-rng`).
//!
//! Supports both hardware targets:
//! - **Raspberry Pi 5 (BCM2712):** Broadcom `iproc-rng200` (`0x10_7D20_8000`, zero DMA)
//! - **QEMU `aarch64` `virt`:** Modern `VirtIO` 1.0+ MMIO RNG (`virtio-rng-device`, `device_id == 4`)
//!
//! Raw hardware entropy passes NIST SP 800-90B startup health tests (fail-closed),
//! is conditioned with FIPS 202 `SHAKE256`, and drives a fast-key-erasure `ChaCha20` CSPRNG.

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
    /// Read a 32-bit hardware register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit hardware register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;

    /// Translate an EL0 DMA buffer reference into its physical address.
    ///
    /// # Errors
    /// Returns [`SysError::Unsupported`] if the transport does not support DMA translation,
    /// or another [`SysError`] if translation fails.
    fn virt_to_phys<T>(&self, _r: &T) -> Result<u64, SysError> {
        Err(SysError::Unsupported)
    }
}

/// Raw hardware entropy source trait implemented by `Bcm2712Rng200` and `VirtioRngDevice`.
pub trait EntropySource {
    /// Fill `dst` with raw entropy bytes from the hardware RNG.
    ///
    /// # Errors
    /// Returns [`RngError`] if the hardware transport faults, times out, or fails health checks.
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError>;
}

/// Detected EL0 hardware RNG backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngKind {
    /// QEMU `virt` modern `VirtIO`-MMIO v2 RNG (`device_id == 4`).
    VirtioRng { version: u32 },
    /// Raspberry Pi 5 BCM2712 Broadcom `iproc-rng200`.
    Bcm2712Rng200,
}

impl RngKind {
    /// Return the static human-readable driver identifier for this hardware RNG backend.
    #[must_use]
    pub const fn driver_name(&self) -> &'static str {
        match self {
            Self::VirtioRng { .. } => "virtio-rng-v2",
            Self::Bcm2712Rng200 => "bcm2712-rng200",
        }
    }
}

impl core::fmt::Display for RngKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.driver_name())
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

impl From<SysError> for RngError {
    fn from(err: SysError) -> Self {
        Self::Sys(err)
    }
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sys(err) => write!(f, "RNG transport error: {err}"),
            Self::DeviceNotFound => f.write_str("hardware RNG device not found"),
            Self::HardwareFault => f.write_str("hardware RNG fault"),
            Self::HardwareTimeout => f.write_str("hardware RNG poll timed out"),
            Self::HealthCheckFailed => f.write_str("RNG entropy health check failed"),
        }
    }
}

impl core::error::Error for RngError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Sys(err) => Some(err),
            Self::DeviceNotFound
            | Self::HardwareFault
            | Self::HardwareTimeout
            | Self::HealthCheckFailed => None,
        }
    }
}

/// Probe a capability-scoped `BOOTSTRAP_RNG_MMIO` region to detect `VirtIO`-RNG v2 or BCM2712 RNG200.
///
/// # Errors
/// Returns [`RngError::Sys`] if MMIO reads fail or [`RngError::DeviceNotFound`] if no supported
/// RNG device is detected.
pub fn probe_rng<F>(mut read32: F) -> Result<RngKind, RngError>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    let reg0 = read32(0x00)?;
    #[cfg(feature = "virtio")]
    if reg0 == VIRTIO_MMIO_MAGIC {
        let version = read32(0x04)?;
        let device_id = read32(0x08)?;
        if device_id == VIRTIO_DEVICE_RNG && version >= 2 {
            return Ok(RngKind::VirtioRng { version });
        }
        return Err(RngError::DeviceNotFound);
    }
    let _ = reg0;
    #[cfg(feature = "bcm2712")]
    {
        // Otherwise validate that `REG_FIFO_COUNT` (`0x24`) is readable within the scoped `0x28` window.
        let _ = read32(bcm2712::REG_FIFO_COUNT)?;
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
        .expect("probe virtio rng");
        assert_eq!(v, RngKind::VirtioRng { version: 2 });

        let b = probe_rng(|off| match off {
            0x00 => Ok(0),
            bcm2712::REG_FIFO_COUNT => Ok(8),
            _ => Ok(0),
        })
        .expect("probe bcm2712 rng");
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
        rng.fill_bytes(&mut a).expect("fill a");
        let key_after = rng.debug_key_snapshot();
        rng.fill_bytes(&mut b).expect("fill b");

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
            ConditionedCsprng::new(StuckSource(0x00), b"").err(),
            Some(RngError::HealthCheckFailed)
        );
        assert_eq!(
            ConditionedCsprng::new(StuckSource(0xFF), b"").err(),
            Some(RngError::HealthCheckFailed)
        );
        assert_eq!(
            ConditionedCsprng::new(BiasedSource, b"").err(),
            Some(RngError::HealthCheckFailed)
        );
    }

    #[test]
    fn rfc8439_chacha20_block_vector() {
        // RFC 8439 Section 2.3.2 test vector
        let mut key = [0u8; 32];
        for (i, b) in (0u8..32).zip(&mut key) {
            *b = i;
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

    #[test]
    fn health_check_rejects_repeating_patterns() {
        // 16-byte repeating pattern has 16 unique bytes and max count 4 (passes RCT/APT/delta),
        // but must be rejected by the periodic pattern check.
        let mut pat16 = [0u8; SEED_BLOCK_BYTES];
        let base: [u8; 16] = [
            0x13, 0x7A, 0x4C, 0xF1, 0x02, 0x99, 0xE5, 0x38, 0xB4, 0x6D, 0x20, 0x8F, 0xC7, 0x51,
            0xA6, 0x0E,
        ];
        for (i, b) in pat16.iter_mut().enumerate() {
            *b = base[i % 16];
        }
        assert_eq!(
            verify_entropy_health(&pat16),
            Err(RngError::HealthCheckFailed)
        );
    }

    struct StackBuf {
        buf: [u8; 128],
        len: usize,
    }

    impl StackBuf {
        const fn new() -> Self {
            Self {
                buf: [0u8; 128],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).expect("utf8")
        }
    }

    impl core::fmt::Write for StackBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let avail = self.buf.len().saturating_sub(self.len);
            let take = bytes.len().min(avail);
            self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            Ok(())
        }
    }

    #[test]
    fn rng_error_display_error_source_and_from_sys_error() {
        use core::error::Error;
        use core::fmt::Write;

        let err: RngError = SysError::WouldBlock.into();
        assert_eq!(err, RngError::Sys(SysError::WouldBlock));
        assert!(err.source().is_some());

        let mut out = StackBuf::new();
        write!(out, "{err}").expect("format sys error");
        assert!(out.as_str().contains("RNG transport error"));

        for other in [
            RngError::DeviceNotFound,
            RngError::HardwareFault,
            RngError::HardwareTimeout,
            RngError::HealthCheckFailed,
        ] {
            assert!(other.source().is_none());
            let mut msg = StackBuf::new();
            write!(msg, "{other}").expect("format rng error");
            assert_ne!(msg.as_str(), "");
        }
    }

    #[test]
    fn rng_kind_const_driver_name_and_display() {
        use core::fmt::Write;

        const VIRTIO_NAME: &str = RngKind::VirtioRng { version: 2 }.driver_name();
        const BCM_NAME: &str = RngKind::Bcm2712Rng200.driver_name();
        assert_eq!(VIRTIO_NAME, "virtio-rng-v2");
        assert_eq!(BCM_NAME, "bcm2712-rng200");

        let mut out = StackBuf::new();
        write!(out, "{}", RngKind::Bcm2712Rng200).expect("format rng kind");
        assert_eq!(out.as_str(), "bcm2712-rng200");
    }
}
