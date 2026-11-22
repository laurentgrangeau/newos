//! `x86_64` 256-entry Interrupt Descriptor Table (IDT) with IST `#DF` protection
//! and Ring-3 crash isolation (redirecting Ring-3 faults to the Ring-3 supervisor).

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::Write;
use core::mem::size_of;
use core::ptr::write_volatile;
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::QemuExitCode;

use super::{apic, gdt, serial, syscall};

pub const APIC_TIMER_VECTOR: u8 = 0x20;
pub const APIC_SPURIOUS_VECTOR: u8 = 0xFF;

static BREAKPOINT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_COUNT: AtomicU64 = AtomicU64::new(0);

/// CPU-pushed interrupt stack frame for `extern "x86-interrupt"` handlers.
#[repr(C)]
pub struct InterruptStackFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

const _: () = assert!(size_of::<IdtEntry>() == 16);

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    fn interrupt_gate(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: gdt::KERNEL_CS,
            ist: ist & 0x7,
            type_attr: 0x8E, // Present=1, DPL=0, Type=0xE (64-bit Interrupt Gate)
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

#[repr(C, align(16))]
struct IdtTable([IdtEntry; 256]);

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

static IDT: SyncUnsafeCell<IdtTable> = SyncUnsafeCell::new(IdtTable([IdtEntry::missing(); 256]));

/// Populate and load the 64-bit IDT via `lidt`.
pub fn init() {
    // SAFETY: Called once during early boot before enabling maskable interrupts.
    unsafe {
        let idt = &mut (*IDT.get()).0;

        for slot in idt.iter_mut() {
            *slot = IdtEntry::interrupt_gate(default_handler as *const () as u64, 0);
        }

        idt[3] = IdtEntry::interrupt_gate(breakpoint_handler as *const () as u64, 0);
        idt[6] = IdtEntry::interrupt_gate(invalid_opcode_handler as *const () as u64, 0);
        idt[8] = IdtEntry::interrupt_gate(
            double_fault_handler as *const () as u64,
            gdt::DOUBLE_FAULT_IST_INDEX,
        );
        idt[13] = IdtEntry::interrupt_gate(gp_fault_handler as *const () as u64, 0);
        idt[14] = IdtEntry::interrupt_gate(page_fault_handler as *const () as u64, 0);
        idt[APIC_TIMER_VECTOR as usize] =
            IdtEntry::interrupt_gate(apic_timer_handler as *const () as u64, 0);
        idt[APIC_SPURIOUS_VECTOR as usize] =
            IdtEntry::interrupt_gate(apic_spurious_handler as *const () as u64, 0);

        let idtr = IdtPointer {
            limit: (size_of::<IdtTable>() - 1) as u16,
            base: IDT.get() as u64,
        };

        asm!("lidt [{idtr}]", idtr = in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Load the already-initialized shared 64-bit IDT onto a secondary (AP) CPU.
pub fn load_current() {
    let idtr = IdtPointer {
        limit: (size_of::<IdtTable>() - 1) as u16,
        base: IDT.get() as u64,
    };
    // SAFETY: `IDT` was populated once on BSP and is immutable thereafter.
    unsafe {
        asm!("lidt [{idtr}]", idtr = in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

pub fn breakpoint_count() -> u64 {
    BREAKPOINT_COUNT.load(Ordering::Acquire)
}

pub fn timer_count() -> u64 {
    TIMER_COUNT.load(Ordering::Acquire)
}

/// If an exception originated in Ring 3 (`CPL == 3`) and a supervisor recovery handler is
/// registered, redirect `frame` to the Ring-3 supervisor so the microkernel stays unaffected.
fn try_redirect_ring3_fault(frame: &mut InterruptStackFrame, vector: u8, name: &str) -> bool {
    if (frame.cs & 3) != 3 {
        return false;
    }
    let Some((rec_rip, rec_rsp)) = syscall::try_recover_user_fault(vector) else {
        return false;
    };
    let mut s = serial::SerialPort::new();
    let _ = writeln!(
        s,
        "[newos-hal] caught Ring-3 {name} (vec={vector}, RIP={:#018x}) -> kernel healthy, redirecting to Ring-3 supervisor",
        frame.rip
    );
    // SAFETY: `frame` points directly to the hardware-pushed interrupt stack frame for `iretq`.
    unsafe {
        write_volatile(&raw mut frame.rip, rec_rip);
        write_volatile(&raw mut frame.rsp, rec_rsp);
    }
    true
}

extern "x86-interrupt" fn breakpoint_handler(_frame: InterruptStackFrame) {
    BREAKPOINT_COUNT.fetch_add(1, Ordering::Release);
}

extern "x86-interrupt" fn invalid_opcode_handler(mut frame: InterruptStackFrame) {
    if try_redirect_ring3_fault(&mut frame, 6, "#UD") {
        return;
    }
    let mut s = serial::SerialPort::new();
    let _ = writeln!(s, "[newos-hal] EXCEPTION #UD at RIP={:#018x}", frame.rip);
    super::exit_qemu(QemuExitCode::Failed);
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
    let mut s = serial::SerialPort::new();
    let _ = writeln!(
        s,
        "[newos-hal] EXCEPTION #DF (IST1) err={:#x} RIP={:#018x} RSP={:#018x}",
        error_code, frame.rip, frame.rsp
    );
    super::exit_qemu(QemuExitCode::Failed)
}

extern "x86-interrupt" fn gp_fault_handler(mut frame: InterruptStackFrame, error_code: u64) {
    if try_redirect_ring3_fault(&mut frame, 13, "#GP") {
        return;
    }
    let mut s = serial::SerialPort::new();
    let _ = writeln!(
        s,
        "[newos-hal] EXCEPTION #GP err={:#x} RIP={:#018x}",
        error_code, frame.rip
    );
    super::exit_qemu(QemuExitCode::Failed);
}

extern "x86-interrupt" fn page_fault_handler(mut frame: InterruptStackFrame, error_code: u64) {
    if try_redirect_ring3_fault(&mut frame, 14, "#PF") {
        return;
    }
    let cr2: u64;
    // SAFETY: Reading CR2 in Ring-0 #PF handler returns the faulting linear address.
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    let mut s = serial::SerialPort::new();
    let _ = writeln!(
        s,
        "[newos-hal] EXCEPTION #PF addr={:#018x} err={:#x} RIP={:#018x}",
        cr2, error_code, frame.rip
    );
    super::exit_qemu(QemuExitCode::Failed);
}

extern "x86-interrupt" fn apic_timer_handler(_frame: InterruptStackFrame) {
    TIMER_COUNT.fetch_add(1, Ordering::Release);
    apic::eoi();
}

extern "x86-interrupt" fn apic_spurious_handler(_frame: InterruptStackFrame) {}

extern "x86-interrupt" fn default_handler(frame: InterruptStackFrame) {
    let mut s = serial::SerialPort::new();
    let _ = writeln!(
        s,
        "[newos-hal] UNHANDLED INTERRUPT at RIP={:#018x}",
        frame.rip
    );
    super::exit_qemu(QemuExitCode::Failed);
}
