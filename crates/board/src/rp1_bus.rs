//! Raspberry Pi 5 RP1 40-Pin Header Bus Peripheral Drivers.
//!
//! Covers the four primary RP1 serial/bus controllers exposed on the 40-pin header:
//! - [`Rp1Uart`]: ARM PL011 UART (`UART0` `0x1F_0003_0000` .. `UART4`, 48 MHz clock)
//! - [`Rp1I2c`]: Synopsys DesignWare APB I2C (`I2C0` `0x1F_0007_0000`, `I2C1` `0x1F_0007_4000`)
//! - [`Rp1Spi`]: Synopsys DesignWare SSI SPI (`SPI0` `0x1F_0005_0000`)
//! - [`Rp1Pwm`]: RP1 4-channel PWM (`PWM0` `0x1F_0009_8000` — 40-pin PWM & Active Cooler fan)

use crate::MmioTransport;
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
pub struct Rp1Uart<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Uart<T> {
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize the PL011 UART to `baud` 8N1 with FIFOs enabled (from 48 MHz RP1 clock).
    pub fn init(&self, baud: u32) -> Result<(), SysError> {
        if baud == 0 || baud > 3_000_000 {
            return Err(SysError::InvalidArgument);
        }
        // BaudDiv = UARTCLK / (16 * baud) -> fixed-point 1/64ths = (4 * UARTCLK) / baud
        let div64 = ((u64::from(RP1_UART_CLK_HZ) * 4) + u64::from(baud / 2)) / u64::from(baud);
        let ibrd = (div64 >> 6) as u32;
        let fbrd = (div64 & 0x3F) as u32;
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

    pub fn try_write_byte(&self, byte: u8) -> Result<(), SysError> {
        if (self.transport.read32(self.base_off + PL011_FR)? & PL011_FR_TXFF) != 0 {
            return Err(SysError::WouldBlock);
        }
        self.transport
            .write32(self.base_off + PL011_DR, u32::from(byte))
    }

    pub fn try_read_byte(&self) -> Result<Option<u8>, SysError> {
        if (self.transport.read32(self.base_off + PL011_FR)? & PL011_FR_RXFE) != 0 {
            return Ok(None);
        }
        let dr = self.transport.read32(self.base_off + PL011_DR)?;
        Ok(Some((dr & 0xFF) as u8))
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
const DW_IC_ENABLE: u64 = 0x6C;
const DW_IC_STATUS: u64 = 0x70;
const DW_IC_CON_MASTER_SS: u32 = (1 << 0) | (0b01 << 1) | (1 << 5) | (1 << 6);
const DW_IC_CON_MASTER_FS: u32 = (1 << 0) | (0b10 << 1) | (1 << 5) | (1 << 6);
const DW_IC_CMD_READ: u32 = 1 << 8;
const DW_IC_CMD_STOP: u32 = 1 << 9;
const DW_IC_STATUS_TFNF: u32 = 1 << 1;
const DW_IC_STATUS_RFNE: u32 = 1 << 3;

/// I2C bus speed mode for RP1 DesignWare I2C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    Standard100k,
    Fast400k,
}

/// Capability-scoped EL0 RP1 DesignWare I2C master driver.
pub struct Rp1I2c<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1I2c<T> {
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize the DesignWare I2C controller in 7-bit master mode (200 MHz RP1 sysclk).
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

    /// Write `data` to 7-bit I2C slave address `addr` (`0x00..=0x7F`).
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
        // Check DW_IC_RAW_INTR_STAT (0x34) for TX_ABRT (bit 6) so a NACKed/missing slave
        // is reported as an error instead of silent success (`P12`).
        const DW_IC_RAW_INTR_STAT: u64 = 0x34;
        const DW_IC_CLR_TX_ABRT: u64 = 0x54;
        const DW_IC_INTR_TX_ABRT: u32 = 1 << 6;
        if (self.transport.read32(self.base_off + DW_IC_RAW_INTR_STAT)? & DW_IC_INTR_TX_ABRT) != 0 {
            let _ = self.transport.read32(self.base_off + DW_IC_CLR_TX_ABRT);
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Read `dst.len()` bytes from 7-bit I2C slave address `addr` (`0x00..=0x7F`).
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
                    *slot = (self.transport.read32(self.base_off + DW_IC_DATA_CMD)? & 0xFF) as u8;
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

/// Capability-scoped EL0 RP1 DesignWare SPI master driver.
pub struct Rp1Spi<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Spi<T> {
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Initialize SPI in 8-bit full-duplex master mode with `cpol`/`cpha` and even `clk_div` (`>= 2`).
    pub fn init(&self, cpol: bool, cpha: bool, clk_div: u16) -> Result<(), SysError> {
        if clk_div < 2 || (clk_div & 1) != 0 {
            return Err(SysError::InvalidArgument);
        }
        // DFS_32 = 7 (8-bit frame) at bits 20:16, SCPH bit 6, SCPOL bit 7
        let mut ctrlr0 = 7u32 << 16;
        if cpha {
            ctrlr0 |= 1 << 6;
        }
        if cpol {
            ctrlr0 |= 1 << 7;
        }
        self.transport.write32(self.base_off + DW_SPI_SSIENR, 0)?;
        self.transport
            .write32(self.base_off + DW_SPI_CTRLR0, ctrlr0)?;
        self.transport
            .write32(self.base_off + DW_SPI_BAUDR, u32::from(clk_div))?;
        self.transport.write32(self.base_off + DW_SPI_SER, 1)?;
        self.transport.write32(self.base_off + DW_SPI_SSIENR, 1)
    }

    /// Full-duplex SPI transfer (`tx.len() == rx.len()`).
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
                    *in_slot = (self.transport.read32(self.base_off + DW_SPI_DR)? & 0xFF) as u8;
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

/// Capability-scoped EL0 RP1 4-channel PWM driver (`chan 0..=3`).
pub struct Rp1Pwm<T: MmioTransport> {
    transport: T,
    base_off: u64,
}

impl<T: MmioTransport> Rp1Pwm<T> {
    pub const fn new(transport: T, base_off: u64) -> Self {
        Self {
            transport,
            base_off,
        }
    }

    /// Configure PWM `channel` (`0..=3`) with period `range` (`>= 1`) and `duty` (`<= range`).
    pub fn configure_channel(&self, channel: u8, range: u32, duty: u32) -> Result<(), SysError> {
        if channel >= 4 || range == 0 || duty > range {
            return Err(SysError::InvalidArgument);
        }
        let ch_base = self.base_off + RP1_PWM_CHAN0_BASE + u64::from(channel) * RP1_PWM_CHAN_STRIDE;
        self.transport
            .write32(ch_base + RP1_PWM_CHAN_CTRL, RP1_PWM_MODE_TRAILING_EDGE)?;
        self.transport
            .write32(ch_base + RP1_PWM_CHAN_RANGE, range)?;
        self.transport.write32(ch_base + RP1_PWM_CHAN_DUTY, duty)?;
        let cur = self.transport.read32(self.base_off + RP1_PWM_GLOBAL_CTRL)?;
        let next = cur | (1u32 << channel) | RP1_PWM_GLOBAL_SET_UPDATE;
        self.transport
            .write32(self.base_off + RP1_PWM_GLOBAL_CTRL, next)
    }

    /// Set PWM `channel` (`0..=3`) duty cycle as a percentage (`0..=100`, e.g. for Active Cooler fan).
    pub fn set_duty_percent(&self, channel: u8, range: u32, pct: u8) -> Result<(), SysError> {
        if pct > 100 {
            return Err(SysError::InvalidArgument);
        }
        let duty = ((u64::from(range) * u64::from(pct)) / 100) as u32;
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
        rx_byte: RefCell<u8>,
    }

    impl MockBus {
        fn new(rx_byte: u8) -> Self {
            Self {
                last_off: RefCell::new(0),
                last_val: RefCell::new(0),
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
        assert_eq!(spi.init(false, false, 3), Err(SysError::InvalidArgument));
        spi.init(false, false, 8).expect("spi init");
        let mut spi_rx = [0u8; 2];
        spi.transfer(&[0x9F, 0x00], &mut spi_rx).expect("spi xfer");
        assert_eq!(spi_rx, [0x5A, 0x5A]);

        let pwm = Rp1Pwm::new(&mock, OFF_PWM0);
        assert_eq!(
            pwm.configure_channel(4, 1000, 500),
            Err(SysError::InvalidArgument)
        );
        pwm.set_duty_percent(2, 2000, 50).expect("pwm 50%");
        assert_eq!(*mock.last_off.borrow(), OFF_PWM0 + RP1_PWM_GLOBAL_CTRL);
        assert_ne!(*mock.last_val.borrow() & (1 << 2), 0);
    }
}
