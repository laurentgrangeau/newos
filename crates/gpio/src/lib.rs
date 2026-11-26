#![no_std]

//! Raspberry Pi 5 RP1 40-Pin GPIO Driver.
//!
//! Targets the RP1 Southbridge Bank 0 GPIO controller (`GPIO 0..=27` on the 40-pin header):
//! - `IO_BANK0`:   `0x1F_000D_0000` (offset `+0x00000`) — per-pin `STATUS` & `CTRL` (`FUNCSEL`)
//! - `RIO0`:       `0x1F_000E_0000` (offset `+0x10000`) — `OUT`, `OE`, `IN` + atomic `XOR`/`SET`/`CLR`
//! - `PADS_BANK0`: `0x1F_000F_0000` (offset `+0x20000`) — per-pin pad drive, pull-up/down, Schmitt, IE/OD
//!
//! Runs in EL0 via `CapId::BOOTSTRAP_GPIO_MMIO` (`MmioRead32`/`MmioWrite32`).

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

/// Validated RP1 Bank 0 GPIO pin identifier (`GPIO 0..=27`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GpioPin(u8);

impl GpioPin {
    /// Validate and construct a Bank 0 GPIO pin (`0..NUM_BANK0_PINS`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `pin >= NUM_BANK0_PINS`.
    #[inline]
    pub const fn new(pin: u8) -> Result<Self, SysError> {
        if pin < NUM_BANK0_PINS {
            Ok(Self(pin))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Return the zero-based Bank 0 pin index (`0..=27`).
    #[inline]
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    #[inline]
    const fn bit_mask(self) -> u32 {
        1u32 << self.0
    }
}

impl TryFrom<u8> for GpioPin {
    type Error = SysError;

    #[inline]
    fn try_from(pin: u8) -> Result<Self, Self::Error> {
        Self::new(pin)
    }
}

impl From<GpioPin> for u8 {
    #[inline]
    fn from(pin: GpioPin) -> Self {
        pin.0
    }
}

/// Electrical logic level for a GPIO pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    #[default]
    Low,
    High,
}

impl Level {
    /// Return `true` if the logic level is [`Self::High`].
    #[inline]
    #[must_use]
    pub const fn is_high(self) -> bool {
        matches!(self, Self::High)
    }

    /// Return `true` if the logic level is [`Self::Low`].
    #[inline]
    #[must_use]
    pub const fn is_low(self) -> bool {
        matches!(self, Self::Low)
    }
}

impl From<bool> for Level {
    #[inline]
    fn from(high: bool) -> Self {
        if high { Self::High } else { Self::Low }
    }
}

impl From<Level> for bool {
    #[inline]
    fn from(level: Level) -> Self {
        level.is_high()
    }
}

/// Internal pull resistor configuration for an RP1 GPIO pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pull {
    #[default]
    None,
    Up,
    Down,
}

/// RP1 GPIO pad drive strength (`PADS_BANK0.DRIVE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum DriveStrength {
    Ma2 = 0,
    #[default]
    Ma4 = 1,
    Ma8 = 2,
    Ma12 = 3,
}

/// RP1 GPIO pad output slew rate (`PADS_BANK0.SLEWFAST`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlewRate {
    #[default]
    Slow,
    Fast,
}

/// RP1 GPIO pad Schmitt trigger hysteresis control (`PADS_BANK0.SCHMITT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchmittTrigger {
    Disabled,
    #[default]
    Enabled,
}

/// RP1 GPIO pad input receiver enable (`PADS_BANK0.IE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputBuffer {
    Disabled,
    #[default]
    Enabled,
}

/// RP1 GPIO pad output driver state (`PADS_BANK0.OD`, inverted bit in hardware).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputDriver {
    Enabled,
    #[default]
    Disabled,
}

/// Electrical configuration for an RP1 Bank 0 pad.
///
/// Defaults to a safe high-impedance input configuration (`Pull::None`, `DriveStrength::Ma4`,
/// `SchmittTrigger::Enabled`, `SlewRate::Slow`, `InputBuffer::Enabled`, `OutputDriver::Disabled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PadConfig {
    pub pull: Pull,
    pub drive: DriveStrength,
    pub schmitt: SchmittTrigger,
    pub slew: SlewRate,
    pub input_buffer: InputBuffer,
    pub output_driver: OutputDriver,
}

impl PadConfig {
    /// Return a standard push-pull output pad configuration (`4 mA`, Schmitt enabled).
    #[must_use]
    pub const fn default_output() -> Self {
        Self {
            pull: Pull::None,
            drive: DriveStrength::Ma4,
            schmitt: SchmittTrigger::Enabled,
            slew: SlewRate::Slow,
            input_buffer: InputBuffer::Enabled,
            output_driver: OutputDriver::Enabled,
        }
    }

    /// Return a high-impedance input pad configuration with the requested `pull` resistor.
    #[must_use]
    pub const fn default_input(pull: Pull) -> Self {
        Self {
            pull,
            drive: DriveStrength::Ma4,
            schmitt: SchmittTrigger::Enabled,
            slew: SlewRate::Slow,
            input_buffer: InputBuffer::Enabled,
            output_driver: OutputDriver::Disabled,
        }
    }

    /// Encode this pad configuration into the RP1 `PADS_BANK0` register bitfield.
    #[inline]
    #[must_use]
    pub const fn encode(self) -> u32 {
        let mut v = (self.drive as u32) << PAD_DRIVE_SHIFT;
        if matches!(self.slew, SlewRate::Fast) {
            v |= PAD_SLEWFAST;
        }
        if matches!(self.schmitt, SchmittTrigger::Enabled) {
            v |= PAD_SCHMITT;
        }
        match self.pull {
            Pull::None => {}
            Pull::Up => v |= PAD_PUE,
            Pull::Down => v |= PAD_PDE,
        }
        if matches!(self.input_buffer, InputBuffer::Enabled) {
            v |= PAD_IE;
        }
        if matches!(self.output_driver, OutputDriver::Disabled) {
            v |= PAD_OD;
        }
        v
    }
}

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait GpioTransport {
    /// Read a 32-bit register at `offset` within the scoped RP1 GPIO MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit register at `offset` within the scoped RP1 GPIO MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

#[inline]
const fn gpio_ctrl_off(pin: GpioPin) -> u64 {
    IO_BANK0_OFF + (pin.index() as u64) * 8 + 4
}

#[inline]
const fn pad_ctrl_off(pin: GpioPin) -> u64 {
    // PADS_BANK0 offset 0x00 is VOLTAGE_SELECT; GPIO0 pad starts at 0x04.
    PADS_BANK0_OFF + 0x04 + (pin.index() as u64) * 4
}

/// Capability-scoped EL0 driver for Raspberry Pi 5 RP1 Bank 0 GPIOs (`GPIO 0..=27`).
#[derive(Debug)]
pub struct Rp1Gpio<T: GpioTransport> {
    transport: T,
}

impl<T: GpioTransport> Rp1Gpio<T> {
    /// Construct a new RP1 Bank 0 GPIO driver over a capability-scoped MMIO transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Select the alternate function (`FUNCSEL`) for `pin` in `IO_BANK0`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO reads/writes fail.
    pub fn set_function(&self, pin: GpioPin, func: GpioFunc) -> Result<(), SysError> {
        let ctrl_off = gpio_ctrl_off(pin);
        let cur = self.transport.read32(ctrl_off)?;
        let next = (cur & !CTRL_FUNCSEL_MASK) | (func as u32);
        self.transport.write32(ctrl_off, next)
    }

    /// Program the electrical pad configuration for `pin` in `PADS_BANK0`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    pub fn set_pad(&self, pin: GpioPin, cfg: PadConfig) -> Result<(), SysError> {
        self.transport.write32(pad_ctrl_off(pin), cfg.encode())
    }

    /// Configure `pin` as a software-controlled push-pull GPIO output (`GpioFunc::Rio`)
    /// with a glitch-free initial logic level.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO reads/writes fail.
    pub fn configure_output(&self, pin: GpioPin, initial: Level) -> Result<(), SysError> {
        let bit = pin.bit_mask();
        // 1. Pre-load output level before enabling output driver
        match initial {
            Level::High => self
                .transport
                .write32(RIO0_OFF + ATOMIC_SET + RIO_OUT, bit)?,
            Level::Low => self
                .transport
                .write32(RIO0_OFF + ATOMIC_CLR + RIO_OUT, bit)?,
        }
        // 2. Enable RIO output driver + pad + pinmux to RIO
        self.transport
            .write32(RIO0_OFF + ATOMIC_SET + RIO_OE, bit)?;
        self.set_pad(pin, PadConfig::default_output())?;
        self.set_function(pin, GpioFunc::Rio)
    }

    /// Configure `pin` as a GPIO input with internal `pull` resistor.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO reads/writes fail.
    pub fn configure_input(&self, pin: GpioPin, pull: Pull) -> Result<(), SysError> {
        let bit = pin.bit_mask();
        self.transport
            .write32(RIO0_OFF + ATOMIC_CLR + RIO_OE, bit)?;
        self.set_pad(pin, PadConfig::default_input(pull))?;
        self.set_function(pin, GpioFunc::Rio)
    }

    /// Atomically drive output `pin` high via RP1 `RIO_OUT` SET alias.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    #[inline]
    pub fn set_high(&self, pin: GpioPin) -> Result<(), SysError> {
        self.transport
            .write32(RIO0_OFF + ATOMIC_SET + RIO_OUT, pin.bit_mask())
    }

    /// Atomically drive output `pin` low via RP1 `RIO_OUT` CLR alias.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    #[inline]
    pub fn set_low(&self, pin: GpioPin) -> Result<(), SysError> {
        self.transport
            .write32(RIO0_OFF + ATOMIC_CLR + RIO_OUT, pin.bit_mask())
    }

    /// Atomically toggle output `pin` via RP1 `RIO_OUT` XOR alias.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    #[inline]
    pub fn toggle(&self, pin: GpioPin) -> Result<(), SysError> {
        self.transport
            .write32(RIO0_OFF + ATOMIC_XOR + RIO_OUT, pin.bit_mask())
    }

    /// Sample the current logic level of `pin` from `RIO_IN`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO read fails.
    #[inline]
    pub fn read(&self, pin: GpioPin) -> Result<Level, SysError> {
        let bits = self.transport.read32(RIO0_OFF + RIO_IN)?;
        Ok(Level::from((bits & pin.bit_mask()) != 0))
    }

    /// Sample all 28 Bank 0 GPIO input levels as a bitmask (`bit N = GPIO N`).
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO read fails.
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

        assert_eq!(GpioPin::new(28), Err(SysError::InvalidArgument));
        assert_eq!(GpioPin::try_from(u8::MAX), Err(SysError::InvalidArgument));

        let pin17 = GpioPin::new(17).expect("GPIO17 valid");
        assert_eq!(u8::from(pin17), 17);

        gpio.configure_output(pin17, Level::High)
            .expect("configure GPIO17 output");
        assert_eq!(
            mock.ctrl.borrow()[17] & CTRL_FUNCSEL_MASK,
            GpioFunc::Rio as u32
        );
        assert_ne!(*mock.rio_oe.borrow() & (1 << 17), 0);
        assert_ne!(*mock.rio_out.borrow() & (1 << 17), 0);

        gpio.toggle(pin17).expect("toggle low");
        assert_eq!(*mock.rio_out.borrow() & (1 << 17), 0);
        gpio.set_high(pin17).expect("set high");
        assert_ne!(*mock.rio_out.borrow() & (1 << 17), 0);
        gpio.set_low(pin17).expect("set low");
        assert_eq!(*mock.rio_out.borrow() & (1 << 17), 0);

        // Configure initially low as well
        let pin0 = GpioPin::try_from(0).expect("GPIO0 valid");
        gpio.configure_output(pin0, Level::Low)
            .expect("configure GPIO0 low");
        assert_eq!(*mock.rio_out.borrow() & 1, 0);
    }

    #[test]
    fn configure_input_pull_and_sample_levels() {
        let mock = MockRp1Gpio::new();
        let gpio = Rp1Gpio::new(&mock);
        let pin4 = GpioPin::new(4).expect("GPIO4 valid");
        let pin5 = GpioPin::new(5).expect("GPIO5 valid");

        gpio.configure_input(pin4, Pull::Up)
            .expect("configure GPIO4 input");
        assert_eq!(*mock.rio_oe.borrow() & (1 << 4), 0);
        assert_ne!(mock.pads.borrow()[4] & (PAD_IE | PAD_OD | PAD_PUE), 0);

        *mock.rio_in.borrow_mut() = (1 << 4) | (1 << 27);
        assert_eq!(gpio.read(pin4), Ok(Level::High));
        assert_eq!(gpio.read(pin5), Ok(Level::Low));
        assert_eq!(gpio.read_all(), Ok((1 << 4) | (1 << 27)));
    }

    #[test]
    fn gpio_pin_boundaries_level_and_pad_config_encoding() {
        assert_eq!(GpioPin::new(0).map(GpioPin::index), Ok(0));
        assert_eq!(GpioPin::new(27).map(GpioPin::index), Ok(27));
        assert_eq!(GpioPin::new(28), Err(SysError::InvalidArgument));

        assert!(Level::High.is_high());
        assert!(!Level::High.is_low());
        assert!(Level::Low.is_low());
        assert_eq!(Level::from(true), Level::High);
        assert_eq!(Level::from(false), Level::Low);
        assert!(bool::from(Level::High));
        assert!(!bool::from(Level::Low));

        // Default PadConfig matches safe high-Z input with no pull
        assert_eq!(PadConfig::default(), PadConfig::default_input(Pull::None));
        let custom = PadConfig {
            pull: Pull::Down,
            drive: DriveStrength::Ma12,
            schmitt: SchmittTrigger::Disabled,
            slew: SlewRate::Fast,
            input_buffer: InputBuffer::Disabled,
            output_driver: OutputDriver::Enabled,
        };
        assert_eq!(
            custom.encode(),
            ((DriveStrength::Ma12 as u32) << PAD_DRIVE_SHIFT) | PAD_SLEWFAST | PAD_PDE
        );
    }
}
