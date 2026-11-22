//! Early COM1 (16550A UART) serial diagnostics writer for `x86_64`.

use core::arch::asm;
use core::fmt::{self, Write};

const COM1_BASE: u16 = 0x3F8;

/// Write a single byte to an x86 I/O port.
///
/// # Safety
/// Caller must ensure `port` is a valid hardware/QEMU I/O port and writing `val`
/// does not violate memory or device invariants.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller guarantees port validity and side-effect safety.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

/// Read a single byte from an x86 I/O port.
///
/// # Safety
/// Caller must ensure `port` is a valid hardware/QEMU I/O port.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller guarantees port validity.
    unsafe {
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write a 32-bit value to an x86 I/O port.
///
/// # Safety
/// Caller must ensure `port` is a valid 32-bit I/O port.
#[inline]
pub unsafe fn outl(port: u16, val: u32) {
    // SAFETY: Caller guarantees port validity and side-effect safety.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
    }
}

/// Initialize COM1 (115200 8N1) for early kernel diagnostics.
pub fn init() {
    // SAFETY: Standard PC/QEMU 16550A UART COM1 initialization sequence on ports 0x3F8..0x3FD.
    unsafe {
        outb(COM1_BASE + 1, 0x00); // Disable interrupts
        outb(COM1_BASE + 3, 0x80); // Enable DLAB
        outb(COM1_BASE, 0x01); // 115200 baud (divisor = 1)
        outb(COM1_BASE + 1, 0x00);
        outb(COM1_BASE + 3, 0x03); // 8N1
        outb(COM1_BASE + 2, 0xC7); // Enable & clear FIFO
        outb(COM1_BASE + 4, 0x0B); // RTS/DSR + OUT2
    }
}

/// Non-blocking 1-byte read from COM1 RX buffer (returns `None` if no byte is ready).
pub fn try_read_byte() -> Option<u8> {
    // SAFETY: Reading COM1 Line Status Register (0x3FD) bit 0 (Data Ready) and RX buffer (0x3F8).
    unsafe {
        if (inb(COM1_BASE + 5) & 0x01) != 0 {
            Some(inb(COM1_BASE))
        } else {
            None
        }
    }
}

/// Stateless handle for writing to COM1 (usable from normal code, exceptions, and panic).
pub struct SerialPort;

impl SerialPort {
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    fn write_byte(&mut self, byte: u8) {
        // SAFETY: Reading COM1 Line Status Register (0x3FD) and writing TX holding register (0x3F8).
        unsafe {
            while (inb(COM1_BASE + 5) & 0x20) == 0 {
                core::hint::spin_loop();
            }
            outb(COM1_BASE, byte);
        }
    }
}

impl Write for SerialPort {
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
