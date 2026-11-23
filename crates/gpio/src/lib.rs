#![no_std]
#![forbid(unsafe_code)]

//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 RP1 40-Pin GPIO Driver.
//!
//! Targets the RP1 Southbridge Bank 0 GPIO controller (`GPIO 0..=27` on the 40-pin header):
//! - `IO_BANK0`:   `0x1F_000D_0000` (offset `+0x00000`) — per-pin `STATUS` & `CTRL` (`FUNCSEL`)
//! - `RIO0`:       `0x1F_000E_0000` (offset `+0x10000`) — `OUT`, `OE`, `IN` + atomic `XOR`/`SET`/`CLR`
//! - `PADS_BANK0`: `0x1F_000F_0000` (offset `+0x20000`) — per-pin pad drive, pull-up/down, Schmitt, IE/OD
//!
//! Runs 100% in EL0 via `CapId::BOOTSTRAP_GPIO_MMIO` (`MmioRead32`/`MmioWrite32`).

use newos_abi::SysError;

/// Physical MMIO base of RP1 `IO_BANK0` on Raspberry Pi 5.
pub const RP1_GPIO_PHYS: u64 = 0x1F_000D_0000;
/// Span covering `IO_BANK0` (`+0x00000`), `RIO0` (`+0x10000`), and `PADS_BANK0` (`+0x20000..+0x24000`).
pub const RP1_GPIO_LEN: u64 = 0x24000;

/// Number of user-accessible GPIOs on the Raspberry Pi 5 40-pin header (`GPIO 0..=27`).
pub const NUM_BANK0_PINS: u8 = 28;

// Sub-block offsets relative to `RP1_GPIO_PHYS` (`0x1F_000D_0000`)
pub const IO_BANK0_OFF: u64 = 0x0_0000;
pub const RIO0_OFF: u64 = 0x1_0000;
pub const PADS_BANK0_OFF: u64 = 0x2_0000;

// RP1 atomic register alias offsets (valid within IO_BANK0, RIO0, and PADS_BANK0)
pub const ATOMIC_XOR: u64 = 0x1000;
pub const ATOMIC_SET: u64 = 0x2000;
pub const ATOMIC_CLR: u64 = 0x3000;

// RIO0 register offsets
pub const RIO_OUT: u64 = 0x00;
pub const RIO_OE: u64 = 0x04;
pub const RIO_IN: u64 = 0x08;

// PADS_BANK0 bitfields
pub const PAD_SLEWFAST: u32 = 1 << 0;
pub const PAD_SCHMITT: u32 = 1 << 1;
pub const PAD_PDE: u32 = 1 << 2;
pub const PAD_PUE: u32 = 1 << 3;
pub const PAD_DRIVE_SHIFT: u32 = 4;
pub const PAD_IE: u32 = 1 << 6;
pub const PAD_OD: u32 = 1 << 7;

// IO_BANK0 GPIOx_CTRL bitfields
pub const CTRL_FUNCSEL_MASK: u32 = 0x1F;

/// RP1 `IO_BANK0` alternate-function selection (`GPIOx_CTRL.FUNCSEL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioFunc {
    Alt0 = 0,
    Alt1 = 1,
    Alt2 = 2,
    Alt3 = 3,
    Alt4 = 4,
    /// Software-controlled Register I/O (`RIO0` standard GPIO input/output).
    Rio = 5,
    Alt6 = 6,
    Alt7 = 7,
    Alt8 = 8,
    /// Disconnected / high-impedance null function.
    Null = 31,
}

/// Internal pull resistor configuration for an RP1 GPIO pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    None,
    Up,
    Down,
}

/// RP1 GPIO pad drive strength (`PADS_BANK0.DRIVE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DriveStrength {
    Ma2 = 0,
    Ma4 = 1,
    Ma8 = 2,
    Ma12 = 3,
}

/// Electrical configuration for an RP1 Bank 0 pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PadConfig {
    pub pull: Pull,
    pub drive: DriveStrength,
    pub schmitt: bool,
    pub slew_fast: bool,
    pub input_enable: bool,
    pub output_disable: bool,
}

impl PadConfig {
    pub const fn default_output() -> Self {
        Self {
            pull: Pull::None,
            drive: DriveStrength::Ma4,
            schmitt: true,
            slew_fast: false,
            input_enable: true,
            output_disable: false,
        }
    }

    pub const fn default_input(pull: Pull) -> Self {
        Self {
            pull,
            drive: DriveStrength::Ma4,
            schmitt: true,
            slew_fast: false,
            input_enable: true,
            output_disable: true,
        }
    }

    #[inline]
    pub const fn encode(self) -> u32 {
        let mut v = (self.drive as u32) << PAD_DRIVE_SHIFT;
        if self.slew_fast {
            v |= PAD_SLEWFAST;
        }
        if self.schmitt {
            v |= PAD_SCHMITT;
        }
        match self.pull {
            Pull::None => {}
            Pull::Up => v |= PAD_PUE,
            Pull::Down => v |= PAD_PDE,
        }
        if self.input_enable {
            v |= PAD_IE;
        }
        if self.output_disable {
            v |= PAD_OD;
        }
        v
    }
}

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait GpioTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

#[inline]
const fn check_pin(pin: u8) -> Result<u64, SysError> {
    if pin < NUM_BANK0_PINS {
        Ok(pin as u64)
    } else {
        Err(SysError::InvalidArgument)
    }
}

#[inline]
const fn gpio_ctrl_off(pin: u64) -> u64 {
    IO_BANK0_OFF + pin * 8 + 4
}

#[inline]
const fn pad_ctrl_off(pin: u64) -> u64 {
    // PADS_BANK0 offset 0x00 is VOLTAGE_SELECT; GPIO0 pad starts at 0x04.
    PADS_BANK0_OFF + 0x04 + pin * 4
}

/// Capability-scoped EL0 driver for Raspberry Pi 5 RP1 Bank 0 GPIOs (`GPIO 0..=27`).
pub struct Rp1Gpio<T: GpioTransport> {
    transport: T,
}

impl<T: GpioTransport> Rp1Gpio<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Select the alternate function (`FUNCSEL`) for `pin` (`0..=27`) in `IO_BANK0`.
    pub fn set_function(&self, pin: u8, func: GpioFunc) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        let ctrl_off = gpio_ctrl_off(p);
        let cur = self.transport.read32(ctrl_off)?;
        let next = (cur & !CTRL_FUNCSEL_MASK) | (func as u32);
        self.transport.write32(ctrl_off, next)
    }

    /// Program the electrical pad configuration for `pin` in `PADS_BANK0`.
    pub fn set_pad(&self, pin: u8, cfg: PadConfig) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        self.transport.write32(pad_ctrl_off(p), cfg.encode())
    }

    /// Configure `pin` (`0..=27`) as a software-controlled push-pull GPIO output (`GpioFunc::Rio`)
    /// with a glitch-free initial logic level.
    pub fn configure_output(&self, pin: u8, initial_high: bool) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        let bit = 1u32 << p;
        // 1. Pre-load output level before enabling output driver
        if initial_high {
            self.transport
                .write32(RIO0_OFF + ATOMIC_SET + RIO_OUT, bit)?;
        } else {
            self.transport
                .write32(RIO0_OFF + ATOMIC_CLR + RIO_OUT, bit)?;
        }
        // 2. Enable RIO output driver + pad + pinmux to RIO
        self.transport
            .write32(RIO0_OFF + ATOMIC_SET + RIO_OE, bit)?;
        self.set_pad(pin, PadConfig::default_output())?;
        self.set_function(pin, GpioFunc::Rio)
    }

    /// Configure `pin` (`0..=27`) as a GPIO input with internal `pull` resistor.
    pub fn configure_input(&self, pin: u8, pull: Pull) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        let bit = 1u32 << p;
        self.transport
            .write32(RIO0_OFF + ATOMIC_CLR + RIO_OE, bit)?;
        self.set_pad(pin, PadConfig::default_input(pull))?;
        self.set_function(pin, GpioFunc::Rio)
    }

    /// Atomically drive output `pin` high via RP1 `RIO_OUT` SET alias.
    #[inline]
    pub fn set_high(&self, pin: u8) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        self.transport
            .write32(RIO0_OFF + ATOMIC_SET + RIO_OUT, 1u32 << p)
    }

    /// Atomically drive output `pin` low via RP1 `RIO_OUT` CLR alias.
    #[inline]
    pub fn set_low(&self, pin: u8) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        self.transport
            .write32(RIO0_OFF + ATOMIC_CLR + RIO_OUT, 1u32 << p)
    }

    /// Atomically toggle output `pin` via RP1 `RIO_OUT` XOR alias.
    #[inline]
    pub fn toggle(&self, pin: u8) -> Result<(), SysError> {
        let p = check_pin(pin)?;
        self.transport
            .write32(RIO0_OFF + ATOMIC_XOR + RIO_OUT, 1u32 << p)
    }

    /// Sample the current logic level of `pin` (`0..=27`) from `RIO_IN`.
    #[inline]
    pub fn read(&self, pin: u8) -> Result<bool, SysError> {
        let p = check_pin(pin)?;
        let bits = self.transport.read32(RIO0_OFF + RIO_IN)?;
        Ok((bits & (1u32 << p)) != 0)
    }

    /// Sample all 28 Bank 0 GPIO input levels as a bitmask (`bit N = GPIO N`).
    #[inline]
    pub fn read_all(&self) -> Result<u32, SysError> {
        let bits = self.transport.read32(RIO0_OFF + RIO_IN)?;
        Ok(bits & ((1u32 << NUM_BANK0_PINS) - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockRp1Gpio {
        ctrl: RefCell<[u32; 28]>,
        pads: RefCell<[u32; 28]>,
        rio_out: RefCell<u32>,
        rio_oe: RefCell<u32>,
        rio_in: RefCell<u32>,
    }

    impl MockRp1Gpio {
        fn new() -> Self {
            Self {
                ctrl: RefCell::new([GpioFunc::Null as u32; 28]),
                pads: RefCell::new([0; 28]),
                rio_out: RefCell::new(0),
                rio_oe: RefCell::new(0),
                rio_in: RefCell::new(0),
            }
        }
    }

    impl GpioTransport for &MockRp1Gpio {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            if offset < RIO0_OFF && (offset % 8) == 4 {
                let pin = (offset / 8) as usize;
                return Ok(self.ctrl.borrow()[pin]);
            }
            if offset == RIO0_OFF + RIO_IN {
                return Ok(*self.rio_in.borrow());
            }
            if offset >= PADS_BANK0_OFF + 4 {
                let pin = ((offset - PADS_BANK0_OFF - 4) / 4) as usize;
                return Ok(self.pads.borrow()[pin]);
            }
            Err(SysError::InvalidArgument)
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset < RIO0_OFF && (offset % 8) == 4 {
                let pin = (offset / 8) as usize;
                self.ctrl.borrow_mut()[pin] = val;
                return Ok(());
            }
            if offset == RIO0_OFF + ATOMIC_SET + RIO_OUT {
                *self.rio_out.borrow_mut() |= val;
                return Ok(());
            }
            if offset == RIO0_OFF + ATOMIC_CLR + RIO_OUT {
                *self.rio_out.borrow_mut() &= !val;
                return Ok(());
            }
            if offset == RIO0_OFF + ATOMIC_XOR + RIO_OUT {
                *self.rio_out.borrow_mut() ^= val;
                return Ok(());
            }
            if offset == RIO0_OFF + ATOMIC_SET + RIO_OE {
                *self.rio_oe.borrow_mut() |= val;
                return Ok(());
            }
            if offset == RIO0_OFF + ATOMIC_CLR + RIO_OE {
                *self.rio_oe.borrow_mut() &= !val;
                return Ok(());
            }
            if offset >= PADS_BANK0_OFF + 4 {
                let pin = ((offset - PADS_BANK0_OFF - 4) / 4) as usize;
                self.pads.borrow_mut()[pin] = val;
                return Ok(());
            }
            Err(SysError::InvalidArgument)
        }
    }

    #[test]
    fn configure_output_toggle_and_reject_out_of_range_pin() {
        let mock = MockRp1Gpio::new();
        let gpio = Rp1Gpio::new(&mock);

        assert_eq!(
            gpio.configure_output(28, true),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(gpio.read(28), Err(SysError::InvalidArgument));

        gpio.configure_output(17, true)
            .expect("configure GPIO17 output");
        assert_eq!(
            mock.ctrl.borrow()[17] & CTRL_FUNCSEL_MASK,
            GpioFunc::Rio as u32
        );
        assert_ne!(*mock.rio_oe.borrow() & (1 << 17), 0);
        assert_ne!(*mock.rio_out.borrow() & (1 << 17), 0);

        gpio.toggle(17).expect("toggle low");
        assert_eq!(*mock.rio_out.borrow() & (1 << 17), 0);
        gpio.set_high(17).expect("set high");
        assert_ne!(*mock.rio_out.borrow() & (1 << 17), 0);
        gpio.set_low(17).expect("set low");
        assert_eq!(*mock.rio_out.borrow() & (1 << 17), 0);
    }

    #[test]
    fn configure_input_pull_and_sample_levels() {
        let mock = MockRp1Gpio::new();
        let gpio = Rp1Gpio::new(&mock);

        gpio.configure_input(4, Pull::Up)
            .expect("configure GPIO4 input");
        assert_eq!(*mock.rio_oe.borrow() & (1 << 4), 0);
        assert_ne!(mock.pads.borrow()[4] & (PAD_IE | PAD_OD | PAD_PUE), 0);

        *mock.rio_in.borrow_mut() = (1 << 4) | (1 << 27);
        assert_eq!(gpio.read(4), Ok(true));
        assert_eq!(gpio.read(5), Ok(false));
        assert_eq!(gpio.read_all(), Ok((1 << 4) | (1 << 27)));
    }
}
