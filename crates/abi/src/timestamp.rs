//! Monotonic nanosecond timestamp conversion, formatting, and line-start state machine.
//!
//! Pure `#![no_std]` and zero-allocation so both the EL1 `Pl011` serial driver (`crates/hal`)
//! and host unit tests can share the exact same logic.

/// Maximum byte length of a formatted timestamp prefix (`[18446744073709551615.999999999] ` = 33 bytes).
pub const MAX_PREFIX_LEN: usize = 36;

/// Minimum width of the whole-seconds field (`[    0.000123456] `).
const MIN_SECS_WIDTH: usize = 5;

const NANOS_PER_SEC: u64 = 1_000_000_000;
const MAX_NANOS: u32 = 999_999_999;

/// Convert elapsed monotonic counter ticks and timer frequency (`CNTFRQ_EL0`) into
/// `(whole_seconds, subsec_nanoseconds)`.
///
/// Returns `(0, 0)` safely if `freq_hz == 0`. Never overflows for any `u64` inputs.
#[inline]
pub fn ticks_to_secs_nanos(elapsed_ticks: u64, freq_hz: u64) -> (u64, u32) {
    if freq_hz == 0 {
        return (0, 0);
    }
    let secs = elapsed_ticks / freq_hz;
    let rem = elapsed_ticks % freq_hz;
    let nanos = match rem.checked_mul(NANOS_PER_SEC) {
        Some(scaled) => (scaled / freq_hz) as u32,
        None => ((u128::from(rem) * u128::from(NANOS_PER_SEC)) / u128::from(freq_hz)) as u32,
    };
    (secs, nanos.min(MAX_NANOS))
}

/// Format `(secs, nanos)` as a fixed-style `[SSSSS.NNNNNNNNN] ` prefix into `buf`
/// without heap allocation or `core::fmt` overhead.
///
/// Seconds are right-aligned to at least 5 characters and expand automatically for
/// uptimes `>= 100_000` seconds. Nanoseconds are always zero-padded to 9 digits.
pub fn format_prefix(secs: u64, nanos: u32, buf: &mut [u8; MAX_PREFIX_LEN]) -> &str {
    let nanos = nanos.min(MAX_NANOS);

    let mut sec_digits = [b'0'; 20];
    let mut sec_len = 0usize;
    let mut s = secs;
    loop {
        sec_digits[sec_len] = b'0' + (s % 10) as u8;
        sec_len += 1;
        s /= 10;
        if s == 0 {
            break;
        }
    }

    let mut pos = 0usize;
    buf[pos] = b'[';
    pos += 1;

    let pad = MIN_SECS_WIDTH.saturating_sub(sec_len);
    for _ in 0..pad {
        buf[pos] = b' ';
        pos += 1;
    }

    for i in (0..sec_len).rev() {
        buf[pos] = sec_digits[i];
        pos += 1;
    }

    buf[pos] = b'.';
    pos += 1;

    let mut n = nanos;
    for i in (0..9).rev() {
        buf[pos + i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    pos += 9;

    buf[pos] = b']';
    pos += 1;
    buf[pos] = b' ';
    pos += 1;

    // SAFETY-free UTF-8 slice: all bytes written above are guaranteed ASCII (`[`, ` `, `0..=9`, `.`, `]`).
    core::str::from_utf8(&buf[..pos]).unwrap_or("")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscState {
    Normal,
    Esc,
    Csi,
}

/// Pure line-start tracker for inserting nanosecond timestamps into a byte stream
/// without corrupting blank lines or ANSI CSI terminal control sequences (`\x1b[2J`, `\x1b[H`, `\r\x1b[K`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineTimestampState {
    at_line_start: bool,
    esc: EscState,
}

impl Default for LineTimestampState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl LineTimestampState {
    #[inline]
    pub const fn new() -> Self {
        Self::with_at_line_start(true)
    }

    #[inline]
    pub const fn with_at_line_start(at_line_start: bool) -> Self {
        Self {
            at_line_start,
            esc: EscState::Normal,
        }
    }

    #[inline]
    pub const fn at_line_start(&self) -> bool {
        self.at_line_start
    }

    /// Advance the state machine by one outgoing byte.
    ///
    /// Returns `true` if a `[SSSSS.NNNNNNNNN] ` timestamp prefix should be emitted
    /// immediately before `byte`.
    #[inline]
    pub fn on_byte(&mut self, byte: u8) -> bool {
        match self.esc {
            EscState::Esc => {
                if byte == b'[' {
                    self.esc = EscState::Csi;
                } else {
                    self.esc = EscState::Normal;
                }
                false
            }
            EscState::Csi => {
                if (0x40..=0x7E).contains(&byte) {
                    self.esc = EscState::Normal;
                    if byte == b'K' || byte == b'H' {
                        self.at_line_start = true;
                    }
                } else if !(0x20..=0x3F).contains(&byte) {
                    self.esc = EscState::Normal;
                    if byte == b'\n' {
                        self.at_line_start = true;
                    }
                }
                false
            }
            EscState::Normal => match byte {
                b'\n' => {
                    self.at_line_start = true;
                    false
                }
                b'\r' => false,
                0x1B => {
                    self.esc = EscState::Esc;
                    false
                }
                _ => {
                    if self.at_line_start {
                        self.at_line_start = false;
                        true
                    } else {
                        false
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_to_secs_nanos_handles_zero_freq_and_known_frequencies() {
        assert_eq!(ticks_to_secs_nanos(123_456, 0), (0, 0));
        assert_eq!(ticks_to_secs_nanos(0, 62_500_000), (0, 0));

        // QEMU virt: 62.5 MHz -> 1 tick = 16 ns
        assert_eq!(ticks_to_secs_nanos(1, 62_500_000), (0, 16));
        assert_eq!(ticks_to_secs_nanos(62_500_000, 62_500_000), (1, 0));
        assert_eq!(
            ticks_to_secs_nanos(62_500_000 * 3 + 62_500, 62_500_000),
            (3, 1_000_000)
        );

        // Raspberry Pi 5 BCM2712: 54 MHz -> 1 tick = 18.518... ns -> 18 ns
        assert_eq!(ticks_to_secs_nanos(1, 54_000_000), (0, 18));
        assert_eq!(ticks_to_secs_nanos(54_000, 54_000_000), (0, 1_000_000));
        assert_eq!(
            ticks_to_secs_nanos(54_000_000 * 42 + 27_000_000, 54_000_000),
            (42, 500_000_000)
        );

        // Overflow-safe path when rem * 1e9 > u64::MAX (very large synthetic freq_hz)
        let huge_freq = 100_000_000_000u64;
        assert_eq!(
            ticks_to_secs_nanos(huge_freq * 5 + huge_freq / 4, huge_freq),
            (5, 250_000_000)
        );
        let (max_secs, max_nanos) = ticks_to_secs_nanos(u64::MAX, 54_000_000);
        assert!(max_secs > 0);
        assert!(max_nanos < 1_000_000_000);
    }

    #[test]
    fn format_prefix_alignment_and_expansion() {
        let mut buf = [0u8; MAX_PREFIX_LEN];
        assert_eq!(format_prefix(0, 0, &mut buf), "[    0.000000000] ");
        assert_eq!(format_prefix(0, 16, &mut buf), "[    0.000000016] ");
        assert_eq!(
            format_prefix(12, 345_678_901, &mut buf),
            "[   12.345678901] "
        );
        assert_eq!(
            format_prefix(99_999, 999_999_999, &mut buf),
            "[99999.999999999] "
        );
        assert_eq!(format_prefix(123_456, 7, &mut buf), "[123456.000000007] ");
        // Clamps out-of-range nanos safely
        assert_eq!(format_prefix(1, u32::MAX, &mut buf), "[    1.999999999] ");
    }

    #[test]
    fn line_timestamp_state_handles_fragments_blanks_and_ansi_csi() {
        let mut st = LineTimestampState::new();

        // Multi-fragment line only stamps on first byte
        let mut stamps = 0usize;
        for b in b"[newos] ".iter().chain(b"booting\n") {
            if st.on_byte(*b) {
                stamps += 1;
            }
        }
        assert_eq!(stamps, 1);

        // Blank lines do not trigger timestamps
        assert!(!st.on_byte(b'\r'));
        assert!(!st.on_byte(b'\n'));
        assert!(!st.on_byte(b'\n'));

        // ANSI clear screen (`\x1b[2J\x1b[H`) passes through without consuming line start
        for b in b"\x1b[2J\x1b[H" {
            assert!(!st.on_byte(*b));
        }
        // Prompt after clear gets stamped
        assert!(st.on_byte(b'n'));
        for b in b"ewos > " {
            assert!(!st.on_byte(*b));
        }

        // Background log clear-line (`\r\x1b[K`) mid-line resets line start
        for b in b"\r\x1b[K" {
            assert!(!st.on_byte(*b));
        }
        assert!(st.on_byte(b'['));
        for b in b"net-pd] up\n" {
            assert!(!st.on_byte(*b));
        }
        assert!(st.on_byte(b'n'));
    }
}
