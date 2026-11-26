#![no_std]

//! Raspberry Pi 5 (16 GB) Board Peripherals Suite.
//!
//! All drivers run in EL0 over capability-scoped MMIO (`MmioRead32`/`MmioWrite32`) and
//! PAN-safe DMA translation/cache ops (`VirtToPhys`/`DmaCacheOp`):
//! - [`mailbox`]: BCM2712 `VideoCore` Property Mailbox (`0x10_7C01_3880`)
//! - [`thermal`]: BCM2712 AVS TMON Thermal Sensor (`0x10_7D5D_2200`) & Active Cooler PWM Fan Curve
//! - [`rtc`]: Raspberry Pi 5 RTC epoch / Gregorian calendar & alarm driver
//! - [`rp1_bus`]: RP1 40-pin header PL011 UART, `DesignWare` I2C, `DesignWare` SPI, and RP1 PWM

#[cfg(feature = "mailbox")]
pub mod mailbox;
#[cfg(feature = "rp1-bus")]
pub mod rp1_bus;
#[cfg(feature = "rtc")]
pub mod rtc;
#[cfg(feature = "thermal")]
pub mod thermal;

use newos_abi::SysError;

/// Capability-scoped 32-bit MMIO register transport injected by EL0 `user-rt` or mock tests.
pub trait MmioTransport {
    /// Read a 32-bit register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Capability-scoped MMIO + DMA translation & cache-maintenance transport (for `VideoCore` Mailbox).
pub trait MmioDmaTransport: MmioTransport {
    /// Translate an EL0 DMA buffer reference into its physical address.
    ///
    /// # Errors
    /// Returns [`SysError`] if translation fails or is unsupported.
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    /// Clean data cache lines covering `value` before DMA device reads.
    ///
    /// # Errors
    /// Returns [`SysError`] if the cache maintenance syscall fails.
    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }

    /// Invalidate data cache lines covering `value` after DMA device writes.
    ///
    /// # Errors
    /// Returns [`SysError`] if the cache maintenance syscall fails.
    fn dma_invalidate<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}
