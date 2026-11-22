//! Pure x2APIC (MSR-only, zero legacy xAPIC MMIO) and tickless oneshot timer.

use super::{idt, percpu, serial};

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_X2APIC: u64 = 1 << 10;

// Architectural x2APIC MSRs
const X2APIC_EOI_MSR: u32 = 0x80B;
const X2APIC_SVR_MSR: u32 = 0x80F;
const X2APIC_LVT_TIMER_MSR: u32 = 0x832;
const X2APIC_TIMER_INIT_MSR: u32 = 0x838;
const X2APIC_TIMER_DIV_MSR: u32 = 0x83E;

const SVR_APIC_ENABLE: u32 = 1 << 8;
const TIMER_DIVIDE_BY_16: u32 = 0b0011;

/// Mask legacy 8259 PIC chips if present on chipset so spurious legacy IRQs never fire.
fn mask_legacy_pic() {
    // SAFETY: Standard PC/Q35 8259 PIC IMR ports (0x21 master, 0xA1 slave).
    unsafe {
        serial::outb(0xA1, 0xFF);
        serial::outb(0x21, 0xFF);
    }
}

/// Initialize the Local APIC strictly in modern x2APIC (MSR) mode.
pub fn init(limine_x2apic: bool) {
    mask_legacy_pic();

    // SAFETY: `IA32_APIC_BASE_MSR` is architectural on all 64-bit x86_64 CPUs.
    let apic_base = unsafe { percpu::rdmsr(IA32_APIC_BASE_MSR) };
    let x2apic_active = limine_x2apic || (apic_base & APIC_BASE_X2APIC) != 0;
    assert!(
        x2apic_active,
        "NewOS requires modern x2APIC (legacy xAPIC MMIO is unsupported)"
    );

    // SAFETY: x2APIC mode is active; writing SVR enables software APIC delivery.
    unsafe {
        percpu::wrmsr(
            X2APIC_SVR_MSR,
            u64::from(SVR_APIC_ENABLE | u32::from(idt::APIC_SPURIOUS_VECTOR)),
        );
        percpu::wrmsr(X2APIC_TIMER_DIV_MSR, u64::from(TIMER_DIVIDE_BY_16));
    }
}

/// Initialize the Local x2APIC on a secondary (AP) CPU.
pub fn init_ap() {
    // SAFETY: Secondary CPUs booted by Limine with `MP_FLAG_X2APIC` already have x2APIC active.
    unsafe {
        percpu::wrmsr(
            X2APIC_SVR_MSR,
            u64::from(SVR_APIC_ENABLE | u32::from(idt::APIC_SPURIOUS_VECTOR)),
        );
        percpu::wrmsr(X2APIC_TIMER_DIV_MSR, u64::from(TIMER_DIVIDE_BY_16));
    }
}

/// Arm the Local x2APIC timer in oneshot mode (fires vector `APIC_TIMER_VECTOR` once).
pub fn arm_oneshot_timer(initial_count: u32) {
    let lvt_oneshot = u32::from(idt::APIC_TIMER_VECTOR);
    // SAFETY: x2APIC is initialized; programming LVT timer + initial count arms oneshot IRQ.
    unsafe {
        percpu::wrmsr(X2APIC_LVT_TIMER_MSR, u64::from(lvt_oneshot));
        percpu::wrmsr(X2APIC_TIMER_INIT_MSR, u64::from(initial_count));
    }
}

/// Signal End-Of-Interrupt (EOI) via x2APIC MSR.
#[inline]
pub fn eoi() {
    // SAFETY: Writing 0 to `X2APIC_EOI_MSR` acknowledges the active interrupt.
    unsafe {
        percpu::wrmsr(X2APIC_EOI_MSR, 0);
    }
}
