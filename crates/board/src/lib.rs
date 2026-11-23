#![no_std]
#![forbid(unsafe_code)]

//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 (16 GB) Board Peripherals Suite.
//!
//! All drivers run 100% in EL0 over capability-scoped MMIO (`MmioRead32`/`MmioWrite32`) and
//! PAN-safe DMA translation/cache ops (`VirtToPhys`/`DmaCacheOp`):
//! - [`mailbox`]: BCM2712 VideoCore Property Mailbox (`0x10_7C01_3880`)
//! - [`thermal`]: BCM2712 AVS TMON Thermal Sensor (`0x10_7D5D_2200`) & Active Cooler PWM Fan Curve
//! - [`rtc`]: Raspberry Pi 5 RTC epoch / Gregorian calendar & alarm driver
//! - [`rp1_bus`]: RP1 40-pin header PL011 UART, DesignWare I2C, DesignWare SPI, and RP1 PWM

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
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Capability-scoped MMIO + DMA translation & cache-maintenance transport (for VideoCore Mailbox).
pub trait MmioDmaTransport: MmioTransport {
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }

    fn dma_invalidate<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}
