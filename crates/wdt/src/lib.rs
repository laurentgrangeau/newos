#![no_std]

//! Raspberry Pi 5 (BCM2712) Hardware Watchdog Driver.
//!
//! Targets the Broadcom BCM2712 Power Management / Watchdog block (`brcm,bcm2712-pm`,
//! physical MMIO base `0x10_7D20_0000`, scoped to `0x100` bytes via `CapId::BOOTSTRAP_WDT_MMIO`).
//!
//! Runs in EL0 via capability-scoped 32-bit MMIO reads/writes (`MmioRead32`/`MmioWrite32`).

use newos_abi::SysError;

/// BCM2712 PM / Watchdog physical MMIO base address on Raspberry Pi 5.
pub const BCM2712_PM_PHYS: u64 = 0x10_7D20_0000;
/// Capability-scoped MMIO window length (bytes) covering `PM_RSTC`, `PM_RSTS`, and `PM_WDOG`.
pub const BCM2712_PM_LEN: u64 = 0x100;

/// `PM_RSTC` register offset (Reset Control).
pub const REG_PM_RSTC: u64 = 0x1C;
/// `PM_RSTS` register offset (Reset Status).
pub const REG_PM_RSTS: u64 = 0x20;
/// `PM_WDOG` register offset (Watchdog Countdown Counter).
pub const REG_PM_WDOG: u64 = 0x24;

/// Required 8-bit password (`0x5A << 24`) on all writes to `PM_RSTC`, `PM_RSTS`, and `PM_WDOG`.
pub const PM_PASSWORD: u32 = 0x5A00_0000;

/// Mask for `WRCFG` reset-mode bits in `PM_RSTC`.
pub const PM_RSTC_WRCFG_MASK: u32 = 0x0000_0030;
/// Clear mask for `WRCFG` bits in `PM_RSTC`.
pub const PM_RSTC_WRCFG_CLR: u32 = !PM_RSTC_WRCFG_MASK;
/// `WRCFG` full-reset mode (triggers full SoC reset when `PM_WDOG` reaches 0).
pub const PM_RSTC_WRCFG_FULL_RESET: u32 = 0x0000_0020;
/// `PM_RSTC` stop/disarm value.
pub const PM_RSTC_RESET: u32 = 0x0000_0102;

/// 20-bit watchdog tick field mask in `PM_WDOG` (`0..=1_048_575` ticks).
pub const PM_WDOG_TIME_MASK: u32 = 0x000F_FFFF;
/// Watchdog clock rate in Hz (`65,536` ticks/sec -> max timeout ~15,999 ms).
pub const PM_WDOG_TICKS_PER_SEC: u64 = 65_536;
/// Maximum supported watchdog timeout in milliseconds (~15.999 s).
pub const MAX_TIMEOUT_MS: u32 = 15_999;

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait WdtTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Convert a timeout in milliseconds (`1..=MAX_TIMEOUT_MS`) to 20-bit BCM2712 watchdog ticks.
#[inline]
pub const fn ms_to_ticks(timeout_ms: u32) -> Result<u32, SysError> {
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(SysError::InvalidArgument);
    }
    let ticks = ((timeout_ms as u64) * PM_WDOG_TICKS_PER_SEC).div_ceil(1000);
    if ticks == 0 {
        Ok(1)
    } else if ticks > PM_WDOG_TIME_MASK as u64 {
        Ok(PM_WDOG_TIME_MASK)
    } else {
        Ok(ticks as u32)
    }
}

/// Convert raw BCM2712 watchdog ticks back to milliseconds (rounded down).
#[inline]
pub const fn ticks_to_ms(ticks: u32) -> u32 {
    (((ticks & PM_WDOG_TIME_MASK) as u64) * 1000 / PM_WDOG_TICKS_PER_SEC) as u32
}

/// Capability-scoped EL0 driver for the Raspberry Pi 5 BCM2712 hardware watchdog.
pub struct Bcm2712Watchdog<T: WdtTransport> {
    transport: T,
    timeout_ticks: u32,
    armed: bool,
}

impl<T: WdtTransport> Bcm2712Watchdog<T> {
    /// Construct an initially disarmed BCM2712 watchdog handle.
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            timeout_ticks: 0,
            armed: false,
        }
    }

    /// Arm (or reconfigure) the hardware watchdog for `timeout_ms` (`1..=15_999` ms)
    /// in full-SoC-reset mode.
    pub fn arm(&mut self, timeout_ms: u32) -> Result<(), SysError> {
        let ticks = ms_to_ticks(timeout_ms)?;
        // 1. Load countdown timer first (prevents immediate expiry on stale 0 count)
        self.transport
            .write32(REG_PM_WDOG, PM_PASSWORD | (ticks & PM_WDOG_TIME_MASK))?;
        // 2. Preserve existing PM_RSTC bits while setting WRCFG = FULL_RESET
        let cur = self.transport.read32(REG_PM_RSTC)?;
        let next = PM_PASSWORD | (cur & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET;
        self.transport.write32(REG_PM_RSTC, next)?;
        self.timeout_ticks = ticks;
        self.armed = true;
        Ok(())
    }

    /// Pet (reload) an armed watchdog back to its configured timeout.
    pub fn pet(&self) -> Result<(), SysError> {
        if !self.armed || self.timeout_ticks == 0 {
            return Err(SysError::InvalidArgument);
        }
        self.transport.write32(
            REG_PM_WDOG,
            PM_PASSWORD | (self.timeout_ticks & PM_WDOG_TIME_MASK),
        )
    }

    /// Disarm (stop) the hardware watchdog cleanly.
    pub fn disarm(&mut self) -> Result<(), SysError> {
        self.transport
            .write32(REG_PM_RSTC, PM_PASSWORD | PM_RSTC_RESET)?;
        self.armed = false;
        Ok(())
    }

    /// Read the remaining countdown ticks (`0..=0x000F_FFFF`) from `PM_WDOG`.
    pub fn remaining_ticks(&self) -> Result<u32, SysError> {
        Ok(self.transport.read32(REG_PM_WDOG)? & PM_WDOG_TIME_MASK)
    }

    /// Read the remaining countdown time in milliseconds.
    pub fn remaining_ms(&self) -> Result<u32, SysError> {
        Ok(ticks_to_ms(self.remaining_ticks()?))
    }

    /// Read the reset status register (`PM_RSTS`).
    pub fn reset_status(&self) -> Result<u32, SysError> {
        self.transport.read32(REG_PM_RSTS)
    }

    /// Trigger an immediate hardware SoC reset via the BCM2712 watchdog (10-tick expiry).
    pub fn trigger_reset(&mut self) -> Result<(), SysError> {
        let cur = self.transport.read32(REG_PM_RSTC)?;
        let next = PM_PASSWORD | (cur & PM_RSTC_WRCFG_CLR) | PM_RSTC_WRCFG_FULL_RESET;
        self.transport.write32(REG_PM_WDOG, PM_PASSWORD | 10)?;
        self.transport.write32(REG_PM_RSTC, next)?;
        self.armed = true;
        self.timeout_ticks = 10;
        Ok(())
    }

    #[inline]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockWdt {
        rstc: RefCell<u32>,
        rsts: RefCell<u32>,
        wdog: RefCell<u32>,
        writes: RefCell<u32>,
    }

    impl MockWdt {
        fn new() -> Self {
            Self {
                rstc: RefCell::new(0x0000_0102),
                rsts: RefCell::new(0x0000_1000),
                wdog: RefCell::new(0),
                writes: RefCell::new(0),
            }
        }
    }

    impl WdtTransport for &MockWdt {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_PM_RSTC => Ok(*self.rstc.borrow()),
                REG_PM_RSTS => Ok(*self.rsts.borrow()),
                REG_PM_WDOG => Ok(*self.wdog.borrow()),
                _ => Err(SysError::InvalidArgument),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            // BCM2712 hardware ignores writes without PM_PASSWORD in bits 31:24.
            assert_eq!(val & 0xFF00_0000, PM_PASSWORD);
            *self.writes.borrow_mut() += 1;
            match offset {
                REG_PM_RSTC => *self.rstc.borrow_mut() = val & 0x00FF_FFFF,
                REG_PM_RSTS => *self.rsts.borrow_mut() = val & 0x00FF_FFFF,
                REG_PM_WDOG => *self.wdog.borrow_mut() = val & PM_WDOG_TIME_MASK,
                _ => return Err(SysError::InvalidArgument),
            }
            Ok(())
        }
    }

    #[test]
    fn ms_to_ticks_validates_bounds_and_roundtrips() {
        assert_eq!(ms_to_ticks(0), Err(SysError::InvalidArgument));
        assert_eq!(
            ms_to_ticks(MAX_TIMEOUT_MS + 1),
            Err(SysError::InvalidArgument)
        );
        // Minimum boundary (1 ms -> >= 1 tick) and exact MAX_TIMEOUT_MS boundary
        let t1 = ms_to_ticks(1).expect("1ms valid");
        assert!(t1 >= 1);
        let t1000 = ms_to_ticks(1000).expect("1s valid");
        assert_eq!(t1000, 65_536);
        assert_eq!(ticks_to_ms(t1000), 1000);
        let tmax = ms_to_ticks(MAX_TIMEOUT_MS).expect("max valid");
        assert!(tmax <= PM_WDOG_TIME_MASK);
        // Verify exact bitmask invariant for PM_RSTC_WRCFG_CLR
        assert_eq!(PM_RSTC_WRCFG_CLR & PM_RSTC_WRCFG_MASK, 0);
        assert_ne!(PM_RSTC_WRCFG_CLR, PM_RSTC_WRCFG_MASK);
    }

    #[test]
    fn arm_pet_remaining_and_disarm_sequence() {
        let mock = MockWdt::new();
        // Pre-populate PM_RSTC with PM_RSTC_WRCFG_FULL_RESET already set so `|` vs `^` is caught!
        *mock.rstc.borrow_mut() = PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET | 0x0102;
        let mut wdt = Bcm2712Watchdog::new(&mock);
        assert!(!wdt.is_armed());
        assert_eq!(wdt.pet(), Err(SysError::InvalidArgument));

        wdt.arm(5_000).expect("arm 5s");
        assert!(wdt.is_armed());
        assert_eq!(
            *mock.rstc.borrow() & PM_RSTC_WRCFG_MASK,
            PM_RSTC_WRCFG_FULL_RESET
        );
        assert_eq!(*mock.rstc.borrow() & 0x0102, 0x0102);
        assert_eq!(wdt.remaining_ms().unwrap(), 5_000);

        // Simulate countdown then pet (re-verify PM_PASSWORD and exact tick reload)
        *mock.wdog.borrow_mut() = 1000;
        assert!(wdt.remaining_ms().unwrap() < 20);
        wdt.pet().expect("pet reloads timeout");
        assert_eq!(wdt.remaining_ms().unwrap(), 5_000);

        // Disarm (with PM_RSTC_RESET bits already present in mock.rstc to catch `|` vs `^`)
        *mock.rstc.borrow_mut() = PM_RSTC_RESET;
        wdt.disarm().expect("disarm");
        assert!(!wdt.is_armed());
        assert_eq!(*mock.rstc.borrow(), PM_RSTC_RESET);
        assert_eq!(wdt.pet(), Err(SysError::InvalidArgument));
        assert_eq!(wdt.reset_status().unwrap(), 0x0000_1000);
    }

    #[test]
    fn trigger_reset_programs_short_full_reset() {
        let mock = MockWdt::new();
        *mock.rstc.borrow_mut() = PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET | 0x0005;
        let mut wdt = Bcm2712Watchdog::new(&mock);
        wdt.trigger_reset().expect("trigger reset");
        assert!(wdt.is_armed());
        assert_eq!(*mock.wdog.borrow(), 10);
        assert_eq!(
            *mock.rstc.borrow() & PM_RSTC_WRCFG_MASK,
            PM_RSTC_WRCFG_FULL_RESET
        );
        assert_eq!(*mock.rstc.borrow() & 0x0005, 0x0005);
    }
}
