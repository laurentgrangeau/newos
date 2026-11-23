//! Raspberry Pi 5 (BCM2712) AVS TMON Thermal Sensor & Active Cooler Fan Curve.
//!
//! Physical MMIO page: `0x10_7D5D_2000` (AVS TMON registers at offset `0x200`, `0x10_7D5D_2200`).

use crate::MmioTransport;
use newos_abi::SysError;

/// Page-aligned physical MMIO base for BCM2712 AVS TMON.
pub const BCM2712_THERMAL_PAGE_PHYS: u64 = 0x10_7D5D_2000;
/// `TEMP_VALUE` status register offset within the `0x10_7D5D_2000` page (`0x10_7D5D_2200`).
pub const REG_TMON_TEMP_VALUE: u64 = 0x200;

/// Bit 10 of `TEMP_VALUE`: measurement valid flag.
pub const TMON_TEMP_VALID: u32 = 1 << 10;
/// Bits 9:0 of `TEMP_VALUE`: 10-bit raw ADC code.
pub const TMON_TEMP_MASK: u32 = 0x3FF;

/// Convert a 10-bit BCM2712 AVS TMON raw ADC code to milli-degrees Celsius.
///
/// Formula from Broadcom `brcmstb_thermal` (BCM2712): `T(m°C) = 410_040 - (raw * 487)`.
#[inline]
pub const fn raw_to_millic(raw: u32) -> i32 {
    410_040 - ((raw & TMON_TEMP_MASK) as i32) * 487
}

/// Capability-scoped EL0 driver for the BCM2712 AVS TMON SoC thermal sensor.
pub struct Bcm2712Thermal<T: MmioTransport> {
    transport: T,
}

impl<T: MmioTransport> Bcm2712Thermal<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Read SoC junction temperature in milli-degrees Celsius (e.g. `52_340` = 52.34 °C).
    pub fn read_temp_millic(&self) -> Result<i32, SysError> {
        let reg = self.transport.read32(REG_TMON_TEMP_VALUE)?;
        if (reg & TMON_TEMP_VALID) == 0 {
            return Err(SysError::WouldBlock);
        }
        Ok(raw_to_millic(reg))
    }
}

/// Raspberry Pi 5 Active Cooler 4-pin JST PWM fan trip-point controller with hysteresis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanController {
    current_duty_pct: u8,
}

impl Default for FanController {
    fn default() -> Self {
        Self::new()
    }
}

impl FanController {
    pub const fn new() -> Self {
        Self {
            current_duty_pct: 0,
        }
    }

    /// Update PWM fan duty cycle (`0..=100`%) from SoC temperature in milli-degrees Celsius
    /// using Raspberry Pi 5's standard 4-stage trip points with 5 °C hysteresis.
    pub fn update(&mut self, temp_millic: i32) -> u8 {
        let target = if temp_millic >= 75_000 {
            100
        } else if temp_millic >= 67_500 {
            70
        } else if temp_millic >= 60_000 {
            50
        } else if temp_millic >= 50_000 {
            30
        } else {
            0
        };

        // Apply 5 °C hysteresis on spin-down to avoid fan oscillation.
        if target >= self.current_duty_pct {
            self.current_duty_pct = target;
        } else {
            let hyst_threshold = match self.current_duty_pct {
                100 => 70_000,
                70 => 62_500,
                50 => 55_000,
                30 => 45_000,
                _ => i32::MIN,
            };
            if temp_millic <= hyst_threshold {
                self.current_duty_pct = target;
            }
        }
        self.current_duty_pct
    }

    /// Fail-safe thermal control update (`P14`): ramps fan to 100% duty on any sensor read error
    /// or implausible temperature reading (`< -40 °C` or `> 125 °C`) instead of leaving fan off.
    pub fn update_from_sensor(&mut self, reading: Result<i32, SysError>) -> u8 {
        match reading {
            Ok(temp_millic) if (-40_000..=125_000).contains(&temp_millic) => {
                self.update(temp_millic)
            }
            _ => {
                self.current_duty_pct = 100;
                100
            }
        }
    }

    #[inline]
    pub const fn duty_pct(&self) -> u8 {
        self.current_duty_pct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockThermal(u32);
    impl MmioTransport for MockThermal {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            if offset == REG_TMON_TEMP_VALUE {
                Ok(self.0)
            } else {
                Err(SysError::InvalidArgument)
            }
        }
        fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
            Err(SysError::Unsupported)
        }
    }

    #[test]
    fn thermal_converts_raw_adc_and_rejects_invalid_bit() {
        let invalid = Bcm2712Thermal::new(MockThermal(740));
        assert_eq!(invalid.read_temp_millic(), Err(SysError::WouldBlock));

        // raw = 740 => 410_040 - 740*487 = 49_660 m°C (49.66 °C)
        let valid = Bcm2712Thermal::new(MockThermal(TMON_TEMP_VALID | 740));
        assert_eq!(valid.read_temp_millic(), Ok(49_660));
    }

    #[test]
    fn fan_controller_ramps_and_applies_hysteresis() {
        let mut fan = FanController::new();
        assert_eq!(fan.update(42_000), 0);
        assert_eq!(fan.update(51_000), 30);
        // 48 °C is above 45 °C hysteresis floor -> stays at 30%
        assert_eq!(fan.update(48_000), 30);
        assert_eq!(fan.update(44_000), 0);
        assert_eq!(fan.update(76_000), 100);
        assert_eq!(fan.update(71_000), 100);
        assert_eq!(fan.update(69_000), 70);
    }
}
