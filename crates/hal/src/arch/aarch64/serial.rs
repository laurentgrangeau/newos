//! ARM `PL011` UART driver via HHDM MMIO (QEMU `virt` `0x0900_0000`, Pi 5 `BCM2712` `0x10_7D00_1000`).

use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use newos_abi::timestamp::{
    LinePosition, LineTimestampState, MAX_PREFIX_LEN, format_prefix, ticks_to_secs_nanos,
};

use super::syscall::{IrqSpinLock, read_cntfrq, read_cntvct};

const UART_DR_OFF: usize = 0x00;
const UART_FR_OFF: usize = 0x18;
const UART_FR_RXFE: u32 = 1 << 4;
const UART_FR_TXFF: u32 = 1 << 5;

const LINE_POS_START: u8 = 0;
const LINE_POS_MID: u8 = 1;

struct AtomicLinePosition(AtomicU8);

impl AtomicLinePosition {
    const fn new(pos: LinePosition) -> Self {
        Self(AtomicU8::new(Self::encode(pos)))
    }

    const fn encode(pos: LinePosition) -> u8 {
        match pos {
            LinePosition::LineStart => LINE_POS_START,
            LinePosition::MidLine => LINE_POS_MID,
        }
    }

    fn load(&self) -> LinePosition {
        match self.0.load(Ordering::Relaxed) {
            LINE_POS_START => LinePosition::LineStart,
            _ => LinePosition::MidLine,
        }
    }

    fn store(&self, pos: LinePosition) {
        self.0.store(Self::encode(pos), Ordering::Relaxed);
    }
}

static PL011_VIRT_BASE: AtomicUsize = AtomicUsize::new(0);
static BOOT_COUNTER_START: AtomicU64 = AtomicU64::new(0);
static BOOT_COUNTER_FREQ: AtomicU64 = AtomicU64::new(0);
static PL011_LOCK: IrqSpinLock<LineTimestampState> = IrqSpinLock::new(LineTimestampState::new());
static UNLOCKED_LINE_POS: AtomicLinePosition = AtomicLinePosition::new(LinePosition::LineStart);

/// Capture the monotonic ARM Generic Virtual Counter (`CNTVCT_EL0`) and frequency
/// (`CNTFRQ_EL0`) at kernel entry (`_start`) as the `0.000000000s` boot clock origin.
pub fn init_boot_clock() {
    BOOT_COUNTER_START.store(read_cntvct(), Ordering::Release);
    BOOT_COUNTER_FREQ.store(read_cntfrq(), Ordering::Release);
}

/// Elapsed monotonic `(whole_seconds, subsec_nanoseconds)` since `init_boot_clock()`.
#[must_use]
#[inline]
pub fn boot_elapsed_secs_nanos() -> (u64, u32) {
    let start = BOOT_COUNTER_START.load(Ordering::Acquire);
    let freq = BOOT_COUNTER_FREQ.load(Ordering::Acquire);
    let elapsed = read_cntvct().saturating_sub(start);
    ticks_to_secs_nanos(elapsed, freq)
}

/// Initialize `PL011` virtual MMIO base address.
///
/// # Safety
/// `virt_base` must be a valid, page-aligned Device-nGnRnE MMIO mapping in `TTBR1_EL1`
/// covering the `PL011` UART register block (`DR` at `+0x00`, `FR` at `+0x18`).
pub(super) unsafe fn init_virt(virt_base: usize) {
    PL011_VIRT_BASE.store(virt_base, Ordering::Release);
}

/// Non-blocking 1-byte read from `PL011` RX FIFO (SMP-synchronized via `PL011_LOCK`).
#[must_use]
pub fn try_read_byte() -> Option<u8> {
    let _guard = PL011_LOCK.lock();
    let base = PL011_VIRT_BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    // SAFETY: `PL011_VIRT_BASE` points to the PL011 MMIO registers mapped in TTBR1_EL1.
    unsafe {
        let fr = (base + UART_FR_OFF) as *const u32;
        if (read_volatile(fr) & UART_FR_RXFE) != 0 {
            return None;
        }
        let dr = (base + UART_DR_OFF) as *const u32;
        u8::try_from(read_volatile(dr) & 0xFF).ok()
    }
}

/// SMP-synchronized `PL011` UART console writer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pl011;

/// Lock-bypassing `PL011` writer reserved strictly for fatal EL1 panic/exception paths
/// so a crash while holding `PL011_LOCK` never deadlocks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnlockedPl011;

impl Pl011 {
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    #[inline]
    fn write_byte_mmio(fr: *const u32, dr: *mut u32, byte: u8) {
        // SAFETY: `fr` and `dr` point to valid PL011 UART MMIO registers mapped via HHDM.
        unsafe {
            while (read_volatile(fr) & UART_FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            write_volatile(dr, u32::from(byte));
        }
    }

    fn write_str_with_state(s: &str, state: &mut LineTimestampState) {
        let base = PL011_VIRT_BASE.load(Ordering::Acquire);
        if base == 0 {
            return;
        }
        let fr = (base + UART_FR_OFF) as *const u32;
        let dr = (base + UART_DR_OFF) as *mut u32;
        let mut ts_buf = [0u8; MAX_PREFIX_LEN];
        for byte in s.bytes() {
            if state.on_byte(byte) {
                let (secs, nanos) = boot_elapsed_secs_nanos();
                let prefix = format_prefix(secs, nanos, &mut ts_buf);
                for pb in prefix.bytes() {
                    Self::write_byte_mmio(fr, dr, pb);
                }
            }
            if byte == b'\n' {
                Self::write_byte_mmio(fr, dr, b'\r');
            }
            Self::write_byte_mmio(fr, dr, byte);
        }
    }

    /// Write `s` directly to `PL011` without acquiring `PL011_LOCK` (fatal panic/exception path only).
    pub fn write_str_unlocked(s: &str) {
        let initial = UNLOCKED_LINE_POS.load();
        let mut state = LineTimestampState::with_position(initial);
        Self::write_str_with_state(s, &mut state);
        let next_pos = if state.at_line_start() {
            LinePosition::LineStart
        } else {
            LinePosition::MidLine
        };
        UNLOCKED_LINE_POS.store(next_pos);
    }
}

impl Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut state = PL011_LOCK.lock();
        Self::write_str_with_state(s, &mut state);
        Ok(())
    }
}

impl Write for UnlockedPl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Pl011::write_str_unlocked(s);
        Ok(())
    }
}
