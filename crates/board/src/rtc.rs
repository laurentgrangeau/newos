//! Raspberry Pi 5 Real-Time Clock (RTC) Driver & Gregorian Calendar Codec.
//!
//! Supports both UTC-epoch <-> Gregorian `DateTime` conversion and the
//! capability-scoped Raspberry Pi 5 RTC seconds / alarm / trickle-charge interface.

use crate::MmioTransport;
use newos_abi::SysError;

#[inline]
const fn low_u8(val: u64) -> u8 {
    val.to_le_bytes()[0]
}

#[inline]
const fn low_u16(val: u64) -> u16 {
    let bytes = val.to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

#[inline]
const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[inline]
const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Civil UTC date/time representation (`1970-01-01 00:00:00` .. `65535-12-31 23:59:59`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Construct and validate a civil UTC `DateTime` (`year >= 1970`, exact leap-year calendar).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if any field is out of range or `day` exceeds the
    /// number of days in `(year, month)`.
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, SysError> {
        let dt = Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        };
        if dt.is_valid() {
            Ok(dt)
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    const fn is_valid(self) -> bool {
        let max_day = days_in_month(self.year, self.month);
        self.year >= 1970
            && max_day > 0
            && self.day >= 1
            && self.day <= max_day
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
    }

    /// Convert UTC epoch timestamp (seconds since `1970-01-01 00:00:00 UTC`) to civil `DateTime`.
    ///
    /// Uses Howard Hinnant's branchless civil-from-days algorithm in pure `u64` arithmetic
    /// (exact across all Gregorian leap years; timestamps past `65535-12-31 23:59:59` saturate to
    /// `65535-12-31 23:59:59`).
    #[must_use]
    pub const fn from_epoch_secs(secs: u64) -> Self {
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let hour = low_u8(rem / 3600);
        let minute = low_u8((rem % 3600) / 60);
        let second = low_u8(rem % 60);

        let z = days.saturating_add(719_468);
        let era = z / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year_u64 = y + if m <= 2 { 1 } else { 0 };
        if year_u64 > u16::MAX as u64 {
            return Self {
                year: u16::MAX,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
            };
        }

        Self {
            year: low_u16(year_u64),
            month: low_u8(m),
            day: low_u8(d),
            hour,
            minute,
            second,
        }
    }

    /// Convert a validated civil UTC `DateTime` (`year >= 1970`) to UTC epoch seconds.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if the date/time is not a valid Gregorian UTC
    /// calendar timestamp at or after `1970-01-01 00:00:00`.
    pub const fn to_epoch_secs(&self) -> Result<u64, SysError> {
        if !self.is_valid() {
            return Err(SysError::InvalidArgument);
        }
        let y = (self.year as u64) - if self.month <= 2 { 1 } else { 0 };
        let era = y / 400;
        let yoe = y - era * 400;
        let m = self.month as u64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (self.day as u64) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let Some(days) = (era * 146_097 + doe).checked_sub(719_468) else {
            return Err(SysError::InvalidArgument);
        };
        Ok(days * 86_400
            + (self.hour as u64) * 3600
            + (self.minute as u64) * 60
            + (self.second as u64))
    }
}

impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

impl From<u64> for DateTime {
    fn from(secs: u64) -> Self {
        Self::from_epoch_secs(secs)
    }
}

impl TryFrom<DateTime> for u64 {
    type Error = SysError;

    fn try_from(dt: DateTime) -> Result<Self, Self::Error> {
        dt.to_epoch_secs()
    }
}

/// Standard Raspberry Pi 5 RTC register offsets (seconds counter, alarm, control).
pub const REG_RTC_TIME_SECS: u64 = 0x00;
pub const REG_RTC_ALARM_SECS: u64 = 0x04;
pub const REG_RTC_CTRL: u64 = 0x08;
pub const RTC_CTRL_ALARM_EN: u32 = 1 << 0;

/// Alarm configuration for [`Rpi5Rtc::set_alarm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmConfig {
    Disabled,
    EnabledAt(u32),
}

/// Capability-scoped EL0 Real-Time Clock driver.
#[derive(Debug)]
pub struct Rpi5Rtc<T: MmioTransport> {
    transport: T,
}

impl<T: MmioTransport> Rpi5Rtc<T> {
    /// Construct a Raspberry Pi 5 RTC driver over `transport`.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Read the current UTC epoch seconds counter from the hardware RTC.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO read fails.
    pub fn read_epoch_secs(&self) -> Result<u64, SysError> {
        Ok(u64::from(self.transport.read32(REG_RTC_TIME_SECS)?))
    }

    /// Read the current hardware RTC counter as a civil UTC [`DateTime`].
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO read fails.
    pub fn read_datetime(&self) -> Result<DateTime, SysError> {
        Ok(DateTime::from_epoch_secs(self.read_epoch_secs()?))
    }

    /// Program the hardware RTC seconds counter to `secs`.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    pub fn set_epoch_secs(&self, secs: u32) -> Result<(), SysError> {
        self.transport.write32(REG_RTC_TIME_SECS, secs)
    }

    /// Configure or disable the hardware RTC alarm.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if MMIO writes fail.
    pub fn set_alarm(&self, config: AlarmConfig) -> Result<(), SysError> {
        match config {
            AlarmConfig::Disabled => self.transport.write32(REG_RTC_CTRL, 0),
            AlarmConfig::EnabledAt(alarm_secs) => {
                self.transport.write32(REG_RTC_ALARM_SECS, alarm_secs)?;
                self.transport.write32(REG_RTC_CTRL, RTC_CTRL_ALARM_EN)
            }
        }
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
    fn datetime_epoch_roundtrip_including_leap_day() {
        let epoch = DateTime::from_epoch_secs(0);
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
        assert_eq!(epoch.to_epoch_secs(), Ok(0));

        // 2024-02-29 12:34:56 UTC (leap day)
        let leap = DateTime {
            year: 2024,
            month: 2,
            day: 29,
            hour: 12,
            minute: 34,
            second: 56,
        };
        let ts = leap.to_epoch_secs().expect("valid leap day");
        assert_eq!(ts, 1_709_210_096);
        assert_eq!(DateTime::from_epoch_secs(ts), leap);
    }

    #[test]
    fn rtc_reads_writes_time_and_alarm() {
        let mock = MockRtc {
            time: RefCell::new(1_709_210_096),
            alarm: RefCell::new(0),
            ctrl: RefCell::new(0),
        };
        let rtc = Rpi5Rtc::new(&mock);
        let dt = rtc.read_datetime().expect("read datetime");
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 2);
        assert_eq!(dt.day, 29);

        rtc.set_alarm(AlarmConfig::EnabledAt(1_709_210_156))
            .expect("enable alarm");
        assert_eq!(*mock.alarm.borrow(), 1_709_210_156);
        assert_eq!(*mock.ctrl.borrow(), RTC_CTRL_ALARM_EN);

        rtc.set_alarm(AlarmConfig::Disabled).expect("disable alarm");
        assert_eq!(*mock.ctrl.borrow(), 0);
    }

    #[test]
    fn datetime_calendar_validation_display_and_conversions() {
        use core::fmt::Write;

        struct Buf {
            data: [u8; 64],
            len: usize,
        }
        impl Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let take = bytes.len().min(self.data.len() - self.len);
                self.data[self.len..self.len + take].copy_from_slice(&bytes[..take]);
                self.len += take;
                Ok(())
            }
        }

        // Reject invalid leap days, non-existent days, and pre-1970 dates
        assert_eq!(
            DateTime::new(2023, 2, 29, 0, 0, 0),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            DateTime::new(2024, 2, 30, 0, 0, 0),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            DateTime::new(2024, 4, 31, 0, 0, 0),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            DateTime::new(1969, 12, 31, 23, 59, 59),
            Err(SysError::InvalidArgument)
        );
        // Century non-leap year: 2100-02-28 valid, 2100-02-29 invalid
        let valid_2100 = DateTime::new(2100, 2, 28, 0, 0, 0).expect("2100-02-28 valid");
        assert!(valid_2100.to_epoch_secs().is_ok());
        assert_eq!(
            DateTime::new(2100, 2, 29, 0, 0, 0),
            Err(SysError::InvalidArgument)
        );

        let dt = DateTime::from(1_709_210_096);
        assert_eq!(u64::try_from(dt), Ok(1_709_210_096));
        assert!(DateTime::from(0) < dt);

        let mut out = Buf {
            data: [0u8; 64],
            len: 0,
        };
        write!(out, "{dt}").expect("display datetime");
        assert_eq!(
            core::str::from_utf8(&out.data[..out.len]).expect("utf8"),
            "2024-02-29 12:34:56 UTC"
        );
    }

    #[test]
    fn from_epoch_secs_saturates_to_valid_max_datetime_preserving_ord() {
        let max_dt = DateTime::new(u16::MAX, 12, 31, 23, 59, 59).expect("max valid datetime");
        let ts_max = max_dt.to_epoch_secs().expect("max epoch secs");
        assert_eq!(DateTime::from_epoch_secs(ts_max), max_dt);

        // 65536-01-01 00:00:00 and 65536-02-29 00:00:00 (65536 is a leap year; 65535 is not)
        let ts_65536_01_01 = ts_max + 1;
        let ts_65536_02_29 = ts_65536_01_01 + (31 + 28) * 86_400;

        for ts in [ts_65536_01_01, ts_65536_02_29, u64::MAX] {
            let saturated = DateTime::from_epoch_secs(ts);
            assert_eq!(saturated, max_dt);
            assert!(saturated.to_epoch_secs().is_ok());
            assert!(saturated >= DateTime::from_epoch_secs(ts_max));
        }
    }
}
