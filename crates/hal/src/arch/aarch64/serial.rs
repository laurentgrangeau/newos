//! ARM PL011 UART driver via HHDM MMIO (QEMU `virt` `0x0900_0000`, Pi 5 BCM2712 `0x10_7D00_1000`).

use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

const UART_DR_OFF: usize = 0x00;
const UART_FR_OFF: usize = 0x18;
const UART_FR_TXFF: u32 = 1 << 5;

static PL011_VIRT_BASE: AtomicU64 = AtomicU64::new(0);

/// Initialize PL011 virtual MMIO base address.
pub fn init_virt(virt_base: u64) {
    PL011_VIRT_BASE.store(virt_base, Ordering::Release);
}

pub struct Pl011;

impl Pl011 {
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    fn write_byte(&mut self, byte: u8) {
        let base = PL011_VIRT_BASE.load(Ordering::Acquire) as usize;
        if base == 0 {
            return;
        }
        // SAFETY: `PL011_VIRT_BASE` points to the PL011 UART MMIO registers mapped via HHDM.
        unsafe {
            let fr = (base + UART_FR_OFF) as *const u32;
            let dr = (base + UART_DR_OFF) as *mut u32;
            while (read_volatile(fr) & UART_FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            write_volatile(dr, u32::from(byte));
        }
    }
}

impl Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}
