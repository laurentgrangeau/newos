//! Raspberry Pi 5 (BCM2712) Broadcom `iproc-rng200` Hardware TRNG Driver.
//!
//! Physical MMIO base: `0x10_7D20_8000` (scoped to `0x28` bytes via `CapId::BOOTSTRAP_RNG_MMIO`).
//! Requires zero DMA and zero `VSpace` capability on Raspberry Pi 5.

use crate::{EntropySource, RngError, RngTransport};

/// `RNG_CTRL` register offset (`bit 0 = RBGEN`).
pub const REG_CTRL: u64 = 0x00;
/// `RNG_SOFT_RESET` register offset (`bit 0 = RNG_SOFT_RESET`).
pub const REG_SOFT_RESET: u64 = 0x04;
/// `RBG_SOFT_RESET` register offset (`bit 0 = RBG_SOFT_RESET`).
pub const REG_RBG_SOFT_RESET: u64 = 0x08;
/// `RNG_INT_STATUS` register offset (`bit 31 = MASTER_FAIL_LOCKOUT_IRQ`).
pub const REG_INT_STATUS: u64 = 0x18;
/// `RNG_FIFO_DATA` register offset (32-bit TRNG output word).
pub const REG_FIFO_DATA: u64 = 0x20;
/// `RNG_FIFO_COUNT` register offset (bits `0..8` = available 32-bit words).
pub const REG_FIFO_COUNT: u64 = 0x24;

pub const CTRL_RBGEN: u32 = 1 << 0;
pub const SOFT_RESET_BIT: u32 = 1 << 0;
pub const INT_MASTER_FAIL_LOCKOUT: u32 = 1 << 31;
pub const FIFO_COUNT_MASK: u32 = 0xFF;

const WARMUP_WORDS: usize = 4;
const MAX_POLL_ITERS: u32 = 100_000;

/// Capability-scoped EL0 driver for the Raspberry Pi 5 BCM2712 `iproc-rng200` hardware TRNG.
#[derive(Debug)]
pub struct Bcm2712Rng200<T: RngTransport> {
    transport: T,
}

impl<T: RngTransport> Bcm2712Rng200<T> {
    /// Initialize and warm up the BCM2712 `iproc-rng200` hardware block.
    ///
    /// Fails closed if the MMIO capability is missing, the hardware reports a lockout fault
    /// that does not clear on soft reset, or the FIFO stalls during warm-up.
    ///
    /// # Errors
    /// Returns [`RngError::Sys`] if MMIO reads/writes fail, [`RngError::HardwareFault`] if the
    /// lockout status persists after soft reset, or [`RngError::HardwareTimeout`] if the FIFO
    /// stalls during warm-up.
    pub fn init(transport: T) -> Result<Self, RngError> {
        let status = transport.read32(REG_INT_STATUS)?;
        if (status & INT_MASTER_FAIL_LOCKOUT) != 0 {
            // Attempt one soft reset of the RBG/RNG pipeline per Broadcom iproc-rng200 spec.
            transport.write32(REG_RBG_SOFT_RESET, SOFT_RESET_BIT)?;
            transport.write32(REG_SOFT_RESET, SOFT_RESET_BIT)?;
            transport.write32(REG_RBG_SOFT_RESET, 0)?;
            transport.write32(REG_SOFT_RESET, 0)?;
            let post_status = transport.read32(REG_INT_STATUS)?;
            if (post_status & INT_MASTER_FAIL_LOCKOUT) != 0 {
                return Err(RngError::HardwareFault);
            }
        }

        let ctrl = transport.read32(REG_CTRL)?;
        if (ctrl & CTRL_RBGEN) == 0 {
            transport.write32(REG_CTRL, ctrl | CTRL_RBGEN)?;
        }

        let dev = Self { transport };
        // Discard initial warm-up words from the FIFO.
        for _ in 0..WARMUP_WORDS {
            let _ = dev.next_u32()?;
        }
        Ok(dev)
    }

    fn next_u32(&self) -> Result<u32, RngError> {
        for _ in 0..MAX_POLL_ITERS {
            let status = self.transport.read32(REG_INT_STATUS)?;
            if (status & INT_MASTER_FAIL_LOCKOUT) != 0 {
                return Err(RngError::HardwareFault);
            }
            let count = self.transport.read32(REG_FIFO_COUNT)? & FIFO_COUNT_MASK;
            if count > 0 {
                return Ok(self.transport.read32(REG_FIFO_DATA)?);
            }
            core::hint::spin_loop();
        }
        Err(RngError::HardwareTimeout)
    }
}

impl<T: RngTransport> EntropySource for Bcm2712Rng200<T> {
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        let mut offset = 0;
        while offset < dst.len() {
            let word = self.next_u32()?.to_le_bytes();
            let take = (dst.len() - offset).min(4);
            dst[offset..offset + take].copy_from_slice(&word[..take]);
            offset += take;
        }
        Ok(())
    }
}
