//! Raspberry Pi 5 RP1 40-Pin Header Bus Peripheral Drivers.
//!
//! Covers the four primary RP1 serial/bus controllers exposed on the 40-pin header:
//! - [`Rp1Uart`]: ARM PL011 UART (`UART0` `0x1F_0003_0000` .. `UART4`, 48 MHz clock)
//! - [`Rp1I2c`]: Synopsys `DesignWare` APB I2C (`I2C0` `0x1F_0007_0000`, `I2C1` `0x1F_0007_4000`)
//! - [`Rp1Spi`]: Synopsys `DesignWare` SSI SPI (`SPI0` `0x1F_0005_0000`)
//! - [`Rp1Pwm`]: RP1 4-channel PWM (`PWM0` `0x1F_0009_8000` — 40-pin PWM & Active Cooler fan)

use crate::MmioTransport;
use core::num::NonZeroU32;
use newos_abi::SysError;

/// RP1 Peripheral Physical Base Addresses (relative to RP1 BAR `0x1F_0000_0000`).
pub const RP1_UART0_PHYS: u64 = 0x1F_0003_0000;
pub const RP1_SPI0_PHYS: u64 = 0x1F_0005_0000;
pub const RP1_I2C0_PHYS: u64 = 0x1F_0007_0000;
pub const RP1_I2C1_PHYS: u64 = 0x1F_0007_4000;
pub const RP1_PWM0_PHYS: u64 = 0x1F_0009_8000;
/// Base of the capability-scoped `BOOTSTRAP_RP1_PERIPH_MMIO` window (`UART0`..`PWM0`).
pub const RP1_PERIPH_BASE_PHYS: u64 = RP1_UART0_PHYS;
pub const RP1_PERIPH_LEN: u64 = (RP1_PWM0_PHYS - RP1_UART0_PHYS) + 0x1000;

/// Offsets within `BOOTSTRAP_RP1_PERIPH_MMIO` (base = `RP1_UART0_PHYS`).
pub const OFF_UART0: u64 = 0;
pub const OFF_SPI0: u64 = RP1_SPI0_PHYS - RP1_PERIPH_BASE_PHYS;
pub const OFF_I2C0: u64 = RP1_I2C0_PHYS - RP1_PERIPH_BASE_PHYS;
pub const OFF_I2C1: u64 = RP1_I2C1_PHYS - RP1_PERIPH_BASE_PHYS;
pub const OFF_PWM0: u64 = RP1_PWM0_PHYS - RP1_PERIPH_BASE_PHYS;

// ---------------------------------------------------------------------------
// 1. RP1 PL011 UART (48 MHz reference clock)
// ---------------------------------------------------------------------------

pub const RP1_UART_CLK_HZ: u32 = 48_000_000;
const PL011_DR: u64 = 0x00;
const PL011_FR: u64 = 0x18;
const PL011_IBRD: u64 = 0x24;
const PL011_FBRD: u64 = 0x28;
const PL011_LCR_H: u64 = 0x2C;
const PL011_CR: u64 = 0x30;
const PL011_ICR: u64 = 0x44;
const PL011_FR_RXFE: u32 = 1 << 4;
const PL011_FR_TXFF: u32 = 1 << 5;
const PL011_LCR_H_8N1_FIFO: u32 = (0b11 << 5) | (1 << 4);
const PL011_CR_ENABLE_TX_RX: u32 = (1 << 0) | (1 << 8) | (1 << 9);

/// Capability-scoped EL0 RP1 PL011 UART driver (`UART0`..`UART4`).
#[derive(Debug)]
pub struct Rp1Uart<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Uart<T> {
    /// Construct an RP1 PL011 UART driver at `base_off` within `transport`.
    #[must_use]
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize the PL011 UART to `baud` 8N1 with FIFOs enabled (from 48 MHz RP1 clock).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `baud` is `0`, exceeds `3_000_000`, or produces an
    /// out-of-range integer baud divisor; or a transport [`SysError`] if MMIO writes fail.
    pub fn init(&self, baud: u32) -> Result<(), SysError> {
        if baud == 0 || baud > 3_000_000 {
            return Err(SysError::InvalidArgument);
        }
        // BaudDiv = UARTCLK / (16 * baud) -> fixed-point 1/64ths = (4 * UARTCLK) / baud
        let div64 = ((u64::from(RP1_UART_CLK_HZ) * 4) + u64::from(baud / 2)) / u64::from(baud);
        let ibrd = u32::try_from(div64 >> 6).map_err(|_| SysError::InvalidArgument)?;
        let fbrd = u32::try_from(div64 & 0x3F).map_err(|_| SysError::InvalidArgument)?;
        if ibrd == 0 || ibrd > 0xFFFF {
            return Err(SysError::InvalidArgument);
        }

        self.transport.write32(self.base_off + PL011_CR, 0)?;
        self.transport.write32(self.base_off + PL011_ICR, 0x7FF)?;
        self.transport.write32(self.base_off + PL011_IBRD, ibrd)?;
        self.transport.write32(self.base_off + PL011_FBRD, fbrd)?;
        self.transport
            .write32(self.base_off + PL011_LCR_H, PL011_LCR_H_8N1_FIFO)?;
        self.transport
            .write32(self.base_off + PL011_CR, PL011_CR_ENABLE_TX_RX)
    }

    /// Non-blocking write of a single byte to the PL011 TX FIFO.
    ///
    /// # Errors
    /// Returns [`SysError::WouldBlock`] if the TX FIFO is full, or a transport [`SysError`].
    pub fn try_write_byte(&self, byte: u8) -> Result<(), SysError> {
        if (self.transport.read32(self.base_off + PL011_FR)? & PL011_FR_TXFF) != 0 {
            return Err(SysError::WouldBlock);
        }
        self.transport
            .write32(self.base_off + PL011_DR, u32::from(byte))
    }

    /// Non-blocking read of a single byte from the PL011 RX FIFO.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO reads fail.
    pub fn try_read_byte(&self) -> Result<Option<u8>, SysError> {
        if (self.transport.read32(self.base_off + PL011_FR)? & PL011_FR_RXFE) != 0 {
            return Ok(None);
        }
        let dr = self.transport.read32(self.base_off + PL011_DR)?;
        Ok(Some(dr.to_le_bytes()[0]))
    }
}

// ---------------------------------------------------------------------------
// 2. RP1 Synopsys DesignWare APB I2C (`I2C0`..`I2C6`)
// ---------------------------------------------------------------------------

const DW_IC_CON: u64 = 0x00;
const DW_IC_TAR: u64 = 0x04;
const DW_IC_DATA_CMD: u64 = 0x10;
const DW_IC_SS_SCL_HCNT: u64 = 0x14;
const DW_IC_SS_SCL_LCNT: u64 = 0x18;
const DW_IC_FS_SCL_HCNT: u64 = 0x1C;
const DW_IC_FS_SCL_LCNT: u64 = 0x20;
const DW_IC_RAW_INTR_STAT: u64 = 0x34;
const DW_IC_CLR_TX_ABRT: u64 = 0x54;
const DW_IC_ENABLE: u64 = 0x6C;
const DW_IC_STATUS: u64 = 0x70;
const DW_IC_CON_MASTER_SS: u32 = (1 << 0) | (0b01 << 1) | (1 << 5) | (1 << 6);
const DW_IC_CON_MASTER_FS: u32 = (1 << 0) | (0b10 << 1) | (1 << 5) | (1 << 6);
const DW_IC_CMD_READ: u32 = 1 << 8;
const DW_IC_CMD_STOP: u32 = 1 << 9;
const DW_IC_INTR_TX_ABRT: u32 = 1 << 6;
const DW_IC_STATUS_TFNF: u32 = 1 << 1;
const DW_IC_STATUS_RFNE: u32 = 1 << 3;

/// I2C bus speed mode for RP1 `DesignWare` I2C.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum I2cSpeed {
    #[default]
    Standard100k,
    Fast400k,
}

/// Capability-scoped EL0 RP1 `DesignWare` I2C controller driver.
#[derive(Debug)]
pub struct Rp1I2c<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1I2c<T> {
    /// Construct an RP1 `DesignWare` I2C driver at `base_off` within `transport`.
    #[must_use]
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize the `DesignWare` I2C controller in 7-bit controller mode (200 MHz RP1 sysclk).
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO writes fail.
    pub fn init(&self, speed: I2cSpeed) -> Result<(), SysError> {
        self.transport.write32(self.base_off + DW_IC_ENABLE, 0)?;
        match speed {
            I2cSpeed::Standard100k => {
                self.transport
                    .write32(self.base_off + DW_IC_CON, DW_IC_CON_MASTER_SS)?;
                self.transport
                    .write32(self.base_off + DW_IC_SS_SCL_HCNT, 800)?;
                self.transport
                    .write32(self.base_off + DW_IC_SS_SCL_LCNT, 940)?;
            }
            I2cSpeed::Fast400k => {
                self.transport
                    .write32(self.base_off + DW_IC_CON, DW_IC_CON_MASTER_FS)?;
                self.transport
                    .write32(self.base_off + DW_IC_FS_SCL_HCNT, 120)?;
                self.transport
                    .write32(self.base_off + DW_IC_FS_SCL_LCNT, 260)?;
            }
        }
        self.transport.write32(self.base_off + DW_IC_ENABLE, 1)
    }

    /// Write `data` to 7-bit I2C target address `addr` (`0x00..=0x7F`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `addr > 0x7F`, `data` is empty, or the target
    /// NACKs (`TX_ABRT`); [`SysError::WouldBlock`] on TX FIFO poll timeout; or a transport
    /// [`SysError`].
    pub fn write(&self, addr: u8, data: &[u8]) -> Result<(), SysError> {
        if addr > 0x7F || data.is_empty() {
            return Err(SysError::InvalidArgument);
        }
        self.transport.write32(self.base_off + DW_IC_ENABLE, 0)?;
        self.transport
            .write32(self.base_off + DW_IC_TAR, u32::from(addr))?;
        self.transport.write32(self.base_off + DW_IC_ENABLE, 1)?;

        let last = data.len() - 1;
        for (i, &b) in data.iter().enumerate() {
            let mut ready = false;
            for _ in 0..10_000u32 {
                if (self.transport.read32(self.base_off + DW_IC_STATUS)? & DW_IC_STATUS_TFNF) != 0 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !ready {
                return Err(SysError::WouldBlock);
            }
            let stop = if i == last { DW_IC_CMD_STOP } else { 0 };
            self.transport
                .write32(self.base_off + DW_IC_DATA_CMD, u32::from(b) | stop)?;
        }
        // Check DW_IC_RAW_INTR_STAT (0x34) for TX_ABRT (bit 6) so a NACKed/missing target
        // is reported as an error instead of silent success (`P12`).
        if (self.transport.read32(self.base_off + DW_IC_RAW_INTR_STAT)? & DW_IC_INTR_TX_ABRT) != 0 {
            let _ = self.transport.read32(self.base_off + DW_IC_CLR_TX_ABRT);
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Read `dst.len()` bytes from 7-bit I2C target address `addr` (`0x00..=0x7F`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `addr > 0x7F` or `dst` is empty,
    /// [`SysError::WouldBlock`] on RX FIFO poll timeout, or a transport [`SysError`].
    pub fn read(&self, addr: u8, dst: &mut [u8]) -> Result<(), SysError> {
        if addr > 0x7F || dst.is_empty() {
            return Err(SysError::InvalidArgument);
        }
        self.transport.write32(self.base_off + DW_IC_ENABLE, 0)?;
        self.transport
            .write32(self.base_off + DW_IC_TAR, u32::from(addr))?;
        self.transport.write32(self.base_off + DW_IC_ENABLE, 1)?;

        let last = dst.len() - 1;
        for (i, slot) in dst.iter_mut().enumerate() {
            let stop = if i == last { DW_IC_CMD_STOP } else { 0 };
            self.transport
                .write32(self.base_off + DW_IC_DATA_CMD, DW_IC_CMD_READ | stop)?;
            let mut got = false;
            for _ in 0..10_000u32 {
                if (self.transport.read32(self.base_off + DW_IC_STATUS)? & DW_IC_STATUS_RFNE) != 0 {
                    *slot = self
                        .transport
                        .read32(self.base_off + DW_IC_DATA_CMD)?
                        .to_le_bytes()[0];
                    got = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !got {
                return Err(SysError::WouldBlock);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 3. RP1 Synopsys DesignWare SSI SPI (`SPI0`..`SPI6`)
// ---------------------------------------------------------------------------

const DW_SPI_CTRLR0: u64 = 0x00;
const DW_SPI_SSIENR: u64 = 0x08;
const DW_SPI_SER: u64 = 0x10;
const DW_SPI_BAUDR: u64 = 0x14;
const DW_SPI_SR: u64 = 0x28;
const DW_SPI_DR: u64 = 0x60;
const DW_SPI_SR_TFNF: u32 = 1 << 1;
const DW_SPI_SR_RFNE: u32 = 1 << 3;

/// SPI clock polarity (`CPOL`) and phase (`CPHA`) mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiMode {
    /// `CPOL = 0, CPHA = 0`.
    #[default]
    Mode0,
    /// `CPOL = 0, CPHA = 1`.
    Mode1,
    /// `CPOL = 1, CPHA = 0`.
    Mode2,
    /// `CPOL = 1, CPHA = 1`.
    Mode3,
}

impl SpiMode {
    /// Return the `DesignWare` `CTRLR0` `SCPH` (bit 6) and `SCPOL` (bit 7) bits.
    #[inline]
    const fn ctrlr0_bits(self) -> u32 {
        match self {
            Self::Mode0 => 0,
            Self::Mode1 => 1 << 6,
            Self::Mode2 => 1 << 7,
            Self::Mode3 => (1 << 6) | (1 << 7),
        }
    }
}

/// Capability-scoped EL0 RP1 `DesignWare` SPI controller driver.
#[derive(Debug)]
pub struct Rp1Spi<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Spi<T> {
    /// Construct an RP1 `DesignWare` SPI driver at `base_off` within `transport`.
    #[must_use]
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize SPI in 8-bit full-duplex controller mode with `mode` and even `clk_div` (`>= 2`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `clk_div < 2` or odd, or a transport [`SysError`].
    pub fn init(&self, mode: SpiMode, clk_div: u16) -> Result<(), SysError> {
        if clk_div < 2 || (clk_div & 1) != 0 {
            return Err(SysError::InvalidArgument);
        }
        // DFS_32 = 7 (8-bit frame) at bits 20:16, SCPH bit 6, SCPOL bit 7
        let ctrlr0 = (7u32 << 16) | mode.ctrlr0_bits();
        self.transport.write32(self.base_off + DW_SPI_SSIENR, 0)?;
        self.transport
            .write32(self.base_off + DW_SPI_CTRLR0, ctrlr0)?;
        self.transport
            .write32(self.base_off + DW_SPI_BAUDR, u32::from(clk_div))?;
        self.transport.write32(self.base_off + DW_SPI_SER, 1)?;
        self.transport.write32(self.base_off + DW_SPI_SSIENR, 1)
    }

    /// Full-duplex SPI transfer (`tx.len() == rx.len()`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `tx.len() != rx.len()`, [`SysError::WouldBlock`]
    /// on TX/RX FIFO poll timeout, or a transport [`SysError`].
    pub fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SysError> {
        if tx.len() != rx.len() {
            return Err(SysError::InvalidArgument);
        }
        for (&out_b, in_slot) in tx.iter().zip(rx.iter_mut()) {
            let mut tx_ok = false;
            for _ in 0..10_000u32 {
                if (self.transport.read32(self.base_off + DW_SPI_SR)? & DW_SPI_SR_TFNF) != 0 {
                    tx_ok = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !tx_ok {
                return Err(SysError::WouldBlock);
            }
            self.transport
                .write32(self.base_off + DW_SPI_DR, u32::from(out_b))?;
            let mut rx_ok = false;
            for _ in 0..10_000u32 {
                if (self.transport.read32(self.base_off + DW_SPI_SR)? & DW_SPI_SR_RFNE) != 0 {
                    *in_slot = self
                        .transport
                        .read32(self.base_off + DW_SPI_DR)?
                        .to_le_bytes()[0];
                    rx_ok = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !rx_ok {
                return Err(SysError::WouldBlock);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 4. RP1 4-Channel PWM (`PWM0` `0x1F_0009_8000` — 40-pin PWM & Active Cooler Fan)
// ---------------------------------------------------------------------------

const RP1_PWM_GLOBAL_CTRL: u64 = 0x00;
const RP1_PWM_CHAN_STRIDE: u64 = 0x10;
const RP1_PWM_CHAN0_BASE: u64 = 0x14;
const RP1_PWM_CHAN_CTRL: u64 = 0x00;
const RP1_PWM_CHAN_RANGE: u64 = 0x04;
const RP1_PWM_CHAN_DUTY: u64 = 0x0C;
const RP1_PWM_GLOBAL_SET_UPDATE: u32 = 1 << 31;
const RP1_PWM_MODE_TRAILING_EDGE: u32 = 1;

/// Hardware PWM output channel on RP1 `PWM0` (`0..=3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PwmChannel {
    Ch0 = 0,
    Ch1 = 1,
    Ch2 = 2,
    Ch3 = 3,
}

impl TryFrom<u8> for PwmChannel {
    type Error = SysError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ch0),
            1 => Ok(Self::Ch1),
            2 => Ok(Self::Ch2),
            3 => Ok(Self::Ch3),
            _ => Err(SysError::InvalidArgument),
        }
    }
}

/// Capability-scoped EL0 RP1 4-channel PWM driver (`Ch0..=Ch3`).
#[derive(Debug)]
pub struct Rp1Pwm<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Pwm<T> {
    /// Construct an RP1 4-channel PWM driver at `base_off` within `transport`.
    #[must_use]
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Configure PWM `channel` with non-zero period `range` and `duty` (`<= range`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `duty > range.get()`, or a transport [`SysError`].
    pub fn configure_channel(
        &self,
        channel: PwmChannel,
        range: NonZeroU32,
        duty: u32,
    ) -> Result<(), SysError> {
        if duty > range.get() {
            return Err(SysError::InvalidArgument);
        }
        let ch_idx = channel as u8;
        let ch_base = self.base_off + RP1_PWM_CHAN0_BASE + u64::from(ch_idx) * RP1_PWM_CHAN_STRIDE;
        self.transport
            .write32(ch_base + RP1_PWM_CHAN_CTRL, RP1_PWM_MODE_TRAILING_EDGE)?;
        self.transport
            .write32(ch_base + RP1_PWM_CHAN_RANGE, range.get())?;
        self.transport.write32(ch_base + RP1_PWM_CHAN_DUTY, duty)?;
        let cur = self.transport.read32(self.base_off + RP1_PWM_GLOBAL_CTRL)?;
        let next = cur | (1u32 << ch_idx) | RP1_PWM_GLOBAL_SET_UPDATE;
        self.transport
            .write32(self.base_off + RP1_PWM_GLOBAL_CTRL, next)
    }

    /// Set PWM `channel` duty cycle as a percentage (`0..=100`, e.g. for Active Cooler fan).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `pct > 100`, or a transport [`SysError`].
    pub fn set_duty_percent(
        &self,
        channel: PwmChannel,
        range: NonZeroU32,
        pct: u8,
    ) -> Result<(), SysError> {
        if pct > 100 {
            return Err(SysError::InvalidArgument);
        }
        let duty = u32::try_from((u64::from(range.get()) * u64::from(pct)) / 100)
            .map_err(|_| SysError::InvalidArgument)?;
        self.configure_channel(channel, range, duty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockBus {
        last_off: RefCell<u64>,
        last_val: RefCell<u32>,
        spi_ctrlr0: RefCell<u32>,
        rx_byte: RefCell<u8>,
    }

    impl MockBus {
        fn new(rx_byte: u8) -> Self {
            Self {
                last_off: RefCell::new(0),
                last_val: RefCell::new(0),
                spi_ctrlr0: RefCell::new(0),
                rx_byte: RefCell::new(rx_byte),
            }
        }
    }

    impl MmioTransport for &MockBus {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                o if o == OFF_UART0 + PL011_FR => Ok(0),
                o if o == OFF_UART0 + PL011_DR => Ok(u32::from(*self.rx_byte.borrow())),
                o if o == OFF_I2C0 + DW_IC_STATUS => Ok(DW_IC_STATUS_TFNF | DW_IC_STATUS_RFNE),
                o if o == OFF_I2C0 + DW_IC_DATA_CMD => Ok(u32::from(*self.rx_byte.borrow())),
                o if o == OFF_SPI0 + DW_SPI_SR => Ok(DW_SPI_SR_TFNF | DW_SPI_SR_RFNE),
                o if o == OFF_SPI0 + DW_SPI_DR => Ok(u32::from(*self.rx_byte.borrow())),
                o if o == OFF_PWM0 + RP1_PWM_GLOBAL_CTRL => Ok(0),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            *self.last_off.borrow_mut() = offset;
            *self.last_val.borrow_mut() = val;
            if offset == OFF_SPI0 + DW_SPI_CTRLR0 {
                *self.spi_ctrlr0.borrow_mut() = val;
            }
            Ok(())
        }
    }

    #[test]
    fn rp1_uart_i2c_spi_pwm_drivers_smoke_test() {
        let mock = MockBus::new(0x5A);

        let uart = Rp1Uart::new(&mock, OFF_UART0);
        assert_eq!(uart.init(0), Err(SysError::InvalidArgument));
        uart.init(115_200).expect("uart init");
        uart.try_write_byte(b'A').expect("uart tx");
        assert_eq!(uart.try_read_byte(), Ok(Some(0x5A)));

        let i2c = Rp1I2c::new(&mock, OFF_I2C0);
        i2c.init(I2cSpeed::Fast400k).expect("i2c init");
        assert_eq!(i2c.write(0x80, &[1]), Err(SysError::InvalidArgument));
        i2c.write(0x48, &[0x01, 0x02]).expect("i2c write");
        let mut rbuf = [0u8; 2];
        i2c.read(0x48, &mut rbuf).expect("i2c read");
        assert_eq!(rbuf, [0x5A, 0x5A]);

        let spi = Rp1Spi::new(&mock, OFF_SPI0);
        assert_eq!(spi.init(SpiMode::Mode0, 3), Err(SysError::InvalidArgument));
        spi.init(SpiMode::Mode0, 8).expect("spi init");
        let mut spi_rx = [0u8; 2];
        spi.transfer(&[0x9F, 0x00], &mut spi_rx).expect("spi xfer");
        assert_eq!(spi_rx, [0x5A, 0x5A]);

        let pwm = Rp1Pwm::new(&mock, OFF_PWM0);
        assert_eq!(PwmChannel::try_from(4), Err(SysError::InvalidArgument));
        let range = NonZeroU32::new(2000).expect("non-zero range");
        pwm.set_duty_percent(PwmChannel::Ch2, range, 50)
            .expect("pwm 50%");
        assert_eq!(*mock.last_off.borrow(), OFF_PWM0 + RP1_PWM_GLOBAL_CTRL);
        assert_ne!(*mock.last_val.borrow() & (1 << 2), 0);
    }

    #[test]
    fn spi_modes_and_pwm_channel_conversion() {
        let mock = MockBus::new(0);
        let spi = Rp1Spi::new(&mock, OFF_SPI0);

        for (mode, expected_bits) in [
            (SpiMode::Mode0, 0),
            (SpiMode::Mode1, 1 << 6),
            (SpiMode::Mode2, 1 << 7),
            (SpiMode::Mode3, (1 << 6) | (1 << 7)),
        ] {
            spi.init(mode, 4).expect("spi mode init");
            assert_eq!(*mock.spi_ctrlr0.borrow(), (7u32 << 16) | expected_bits);
        }

        assert_eq!(PwmChannel::try_from(0), Ok(PwmChannel::Ch0));
        assert_eq!(PwmChannel::try_from(3), Ok(PwmChannel::Ch3));
        assert_eq!(PwmChannel::try_from(4), Err(SysError::InvalidArgument));
        assert_eq!(I2cSpeed::default(), I2cSpeed::Standard100k);
    }
}
