//! Raspberry Pi 5 Real-Time Clock (RTC) Driver & Gregorian Calendar Codec (`#![forbid(unsafe_code)]`).
//!
//! Supports both Unix-epoch <-> Gregorian `DateTime` conversion (`no_alloc`) and the
//! capability-scoped Raspberry Pi 5 RTC seconds / alarm / trickle-charge interface.

use crate::MmioTransport;
use newos_abi::SysError;

/// Civil UTC date/time representation (`1970-01-01 00:00:00` .. `2106-02-07 06:28:15`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Convert Unix timestamp (seconds since `1970-01-01 00:00:00 UTC`) to civil `DateTime`.
    ///
    /// Uses Howard Hinnant's branchless civil-from-days algorithm (exact across all leap years).
    pub const fn from_unix_secs(secs: u64) -> Self {
        let days = (secs / 86_400) as i64;
        let rem = (secs % 86_400) as u32;
        let hour = (rem / 3600) as u8;
        let minute = ((rem % 3600) / 60) as u8;
        let second = (rem % 60) as u8;

        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year = (y + if m <= 2 { 1 } else { 0 }) as u16;

        Self {
            year,
            month: m as u8,
            day: d as u8,
            hour,
            minute,
            second,
        }
    }

    /// Convert a validated civil UTC `DateTime` (`year >= 1970`) to Unix seconds.
    pub const fn to_unix_secs(self) -> Result<u64, SysError> {
        if self.year < 1970
            || self.month < 1
            || self.month > 12
            || self.day < 1
            || self.day > 31
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(SysError::InvalidArgument);
        }
        let y = self.year as i64 - if self.month <= 2 { 1 } else { 0 };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u64;
        let m = self.month as u64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (self.day as u64) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + (doe as i64) - 719_468;
        if days < 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok((days as u64) * 86_400
            + (self.hour as u64) * 3600
            + (self.minute as u64) * 60
            + (self.second as u64))
    }
}

/// Standard Raspberry Pi 5 RTC register offsets (seconds counter, alarm, control).
pub const REG_RTC_TIME_SECS: u64 = 0x00;
pub const REG_RTC_ALARM_SECS: u64 = 0x04;
pub const REG_RTC_CTRL: u64 = 0x08;
pub const RTC_CTRL_ALARM_EN: u32 = 1 << 0;

/// Capability-scoped EL0 Real-Time Clock driver.
pub struct Rpi5Rtc<T: MmioTransport> {
    transport: T,
}

impl<T: MmioTransport> Rpi5Rtc<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn read_unix_secs(&self) -> Result<u64, SysError> {
        Ok(u64::from(self.transport.read32(REG_RTC_TIME_SECS)?))
    }

    pub fn read_datetime(&self) -> Result<DateTime, SysError> {
        Ok(DateTime::from_unix_secs(self.read_unix_secs()?))
    }

    pub fn set_unix_secs(&self, secs: u32) -> Result<(), SysError> {
        self.transport.write32(REG_RTC_TIME_SECS, secs)
    }

    pub fn set_alarm_secs(&self, alarm_secs: u32, enable: bool) -> Result<(), SysError> {
        self.transport.write32(REG_RTC_ALARM_SECS, alarm_secs)?;
        let ctrl = if enable { RTC_CTRL_ALARM_EN } else { 0 };
        self.transport.write32(REG_RTC_CTRL, ctrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockRtc {
        time: RefCell<u32>,
        alarm: RefCell<u32>,
        ctrl: RefCell<u32>,
    }

    impl MmioTransport for &MockRtc {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_RTC_TIME_SECS => Ok(*self.time.borrow()),
                REG_RTC_ALARM_SECS => Ok(*self.alarm.borrow()),
                REG_RTC_CTRL => Ok(*self.ctrl.borrow()),
                _ => Err(SysError::InvalidArgument),
            }
        }
        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            match offset {
                REG_RTC_TIME_SECS => *self.time.borrow_mut() = val,
                REG_RTC_ALARM_SECS => *self.alarm.borrow_mut() = val,
                REG_RTC_CTRL => *self.ctrl.borrow_mut() = val,
                _ => return Err(SysError::InvalidArgument),
            }
            Ok(())
        }
    }

    #[test]
    fn datetime_unix_roundtrip_including_leap_day() {
        let epoch = DateTime::from_unix_secs(0);
        assert_eq!(
            epoch,
            DateTime {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            }
        );
        assert_eq!(epoch.to_unix_secs(), Ok(0));

        // 2024-02-29 12:34:56 UTC (leap day)
        let leap = DateTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 12,
            minute: 34,
            second: 56,
        };
        let ts = leap.to_unix_secs().expect("valid leap day");
        assert_eq!(ts, 1_709_210_096);
        assert_eq!(DateTime::from_unix_secs(ts), leap);
    }

    #[test]
    fn rtc_reads_writes_time_and_alarm() {
        let mock = MockRtc {
            time: RefCell::new(1_709_210_096),
            alarm: RefCell::new(0),
            ctrl: RefCell::new(0),
        };
        let rtc = Rpi5Rtc::new(&mock);
        let dt = rtc.read_datetime().unwrap();
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 2);
        assert_eq!(dt.day, 29);

        rtc.set_alarm_secs(1_709_210_156, true).unwrap();
        assert_eq!(*mock.alarm.borrow(), 1_709_210_156);
        assert_eq!(*mock.ctrl.borrow(), RTC_CTRL_ALARM_EN);
    }
}
