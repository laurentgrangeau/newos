//! Audited `AArch64` EL0/EL1 architectural register state, FP/SIMD save/restore,
//! `TTBR0_EL1` ASID switching, ARM Generic Virtual Timer, and low-level barriers.

use core::arch::asm;
use core::sync::atomic::Ordering;

use super::{CNTV_CTL_ENABLE, TIMER_TICK_INTERVAL, TTBR0_ADDR_MASK};

// SAFETY: `__newos_el0_enter_frame` is defined in `mod.rs` `global_asm!` and restores a valid `TrapFrame` before `eret`.
unsafe extern "C" {
    pub(super) fn __newos_el0_enter_frame(frame: *const TrapFrame) -> !;
}

/// Full EL0 register trap frame saved on `SP_EL1` by `__newos_sync_el0` (272 bytes, 16B-aligned).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
}

const _: () = assert!(core::mem::size_of::<TrapFrame>() == 272);

impl TrapFrame {
    pub(super) const ZERO: Self = Self {
        x: [0; 31],
        sp_el0: 0,
        elr_el1: 0,
        spsr_el1: 0,
    };
}

/// Full `AArch64` Advanced SIMD (NEON) & FP register state saved/restored across EL0 context switches.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub(super) struct FpState {
    fpcr: u64,
    fpsr: u64,
    q: [[u64; 2]; 32],
}

const _: () = assert!(core::mem::size_of::<FpState>() == 528);

impl FpState {
    pub(super) const ZERO: Self = Self {
        fpcr: 0,
        fpsr: 0,
        q: [[0; 2]; 32],
    };
}

#[inline]
pub(in crate::arch::aarch64) fn enable_fp_simd() {
    // SAFETY: Setting `CPACR_EL1.FPEN = 0b11` (bits 21:20) enables FP/NEON in EL1 and EL0
    // so EL0 SIMD instructions and EL1 `save_fp_state`/`restore_fp_state` never trap.
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr, options(nomem, nostack));
        cpacr |= 0b11 << 20;
        asm!("msr cpacr_el1, {}", "isb", in(reg) cpacr, options(nomem, nostack));
    }
}

#[inline]
pub(super) fn save_fp_state(dst: &mut FpState) {
    let base = core::ptr::from_mut(dst).cast::<u8>();
    // SAFETY: `dst` is a 16-byte-aligned, exclusively borrowed `FpState` (528 bytes) and
    // `enable_fp_simd()` has unmasked FP/SIMD access in `CPACR_EL1`.
    unsafe {
        asm!(
            ".arch_extension fp",
            "mrs {t0}, fpcr",
            "mrs {t1}, fpsr",
            "stp {t0}, {t1}, [{base}, #0]",
            "stp q0,  q1,  [{base}, #16]",
            "stp q2,  q3,  [{base}, #48]",
            "stp q4,  q5,  [{base}, #80]",
            "stp q6,  q7,  [{base}, #112]",
            "stp q8,  q9,  [{base}, #144]",
            "stp q10, q11, [{base}, #176]",
            "stp q12, q13, [{base}, #208]",
            "stp q14, q15, [{base}, #240]",
            "stp q16, q17, [{base}, #272]",
            "stp q18, q19, [{base}, #304]",
            "stp q20, q21, [{base}, #336]",
            "stp q22, q23, [{base}, #368]",
            "stp q24, q25, [{base}, #400]",
            "stp q26, q27, [{base}, #432]",
            "stp q28, q29, [{base}, #464]",
            "stp q30, q31, [{base}, #496]",
            ".arch_extension nofp",
            base = in(reg) base,
            t0 = out(reg) _,
            t1 = out(reg) _,
            options(nostack),
        );
    }
}

#[inline]
pub(super) fn restore_fp_state(src: &FpState) {
    let base = core::ptr::from_ref(src).cast::<u8>();
    // SAFETY: `src` is a 16-byte-aligned, valid `FpState` (528 bytes) and
    // `enable_fp_simd()` has unmasked FP/SIMD access in `CPACR_EL1`.
    unsafe {
        asm!(
            ".arch_extension fp",
            "ldp {t0}, {t1}, [{base}, #0]",
            "msr fpcr, {t0}",
            "msr fpsr, {t1}",
            "ldp q0,  q1,  [{base}, #16]",
            "ldp q2,  q3,  [{base}, #48]",
            "ldp q4,  q5,  [{base}, #80]",
            "ldp q6,  q7,  [{base}, #112]",
            "ldp q8,  q9,  [{base}, #144]",
            "ldp q10, q11, [{base}, #176]",
            "ldp q12, q13, [{base}, #208]",
            "ldp q14, q15, [{base}, #240]",
            "ldp q16, q17, [{base}, #272]",
            "ldp q18, q19, [{base}, #304]",
            "ldp q20, q21, [{base}, #336]",
            "ldp q22, q23, [{base}, #368]",
            "ldp q24, q25, [{base}, #400]",
            "ldp q26, q27, [{base}, #432]",
            "ldp q28, q29, [{base}, #464]",
            "ldp q30, q31, [{base}, #496]",
            ".arch_extension nofp",
            base = in(reg) base,
            t0 = out(reg) _,
            t1 = out(reg) _,
            options(nostack),
        );
    }
}

#[inline]
pub(super) fn read_tpidr_el0() -> u64 {
    let v: u64;
    // SAFETY: Reading `TPIDR_EL0` in EL1 saves the active EL0 thread pointer (`M7`).
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
pub(super) fn write_tpidr_el0(v: u64) {
    // SAFETY: Writing `TPIDR_EL0` in EL1 restores the target EL0 thread pointer (`M7`).
    unsafe {
        asm!("msr tpidr_el0, {}", in(reg) v, options(nomem, nostack));
    }
}

#[inline]
pub(super) fn switch_ttbr0(ttbr0_phys: u64, pd_id: usize) {
    let asid = ((pd_id + 1) as u64) & 0xFFFF;
    let val = (asid << 48) | (ttbr0_phys & TTBR0_ADDR_MASK);
    // SAFETY: `ttbr0_phys` is a verified 4 KiB-aligned EL0 L0 page-table physical address whose
    // user leaf PTEs are tagged with `DESC_NG = 1 << 11`. `TCR_EL1.A1 == 0` routes 16-bit ASID
    // selection through `TTBR0_EL1[63:48]`, isolating per-PD TLB entries without global flushes.
    unsafe {
        asm!(
            "msr ttbr0_el1, {val}",
            "isb",
            val = in(reg) val,
            options(nostack),
        );
    }
}

#[inline]
pub(super) fn clear_ttbr0() {
    // SAFETY: Detaches the dying domain's `TTBR0_EL1` (and ASID) from this CPU before releasing
    // `DOMAINS.lock()` so `teardown_domain_locked` on another core can safely zero page tables.
    unsafe {
        asm!(
            "msr ttbr0_el1, xzr",
            "isb",
            options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub(super) fn read_esr_el1() -> u64 {
    let esr: u64;
    // SAFETY: Reading `ESR_EL1` in EL1 synchronous exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
    }
    esr
}

#[inline]
pub(super) fn read_far_el1() -> u64 {
    let far: u64;
    // SAFETY: Reading `FAR_EL1` in EL1 synchronous fault handler is architectural.
    unsafe {
        asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags));
    }
    far
}

#[must_use]
#[inline]
pub fn read_cntfrq() -> u64 {
    let freq: u64;
    // SAFETY: Reading `CNTFRQ_EL0` in EL1 returns the architectural Generic Timer frequency in Hz.
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    freq
}

#[must_use]
#[inline]
pub fn read_cntvct() -> u64 {
    let v: u64;
    // SAFETY: `CNTVCT_EL0` is always readable in EL1.
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Read the architectural Generic Virtual Counter (`CNTVCT_EL0`), which matches `TimerFreq`
/// (`CNTFRQ_EL0`) and is monotonic across all SMP cores (`P6`).
#[inline]
pub(super) fn read_cycles() -> u64 {
    read_cntvct()
}

#[inline]
pub(super) fn read_cntv_ctl() -> u64 {
    let ctl: u64;
    // SAFETY: Reading `CNTV_CTL_EL0` in EL1 checks the Virtual Timer status register.
    unsafe {
        asm!("mrs {}, cntv_ctl_el0", out(reg) ctl, options(nomem, nostack));
    }
    ctl
}

#[inline]
pub(super) fn arm_virtual_timer(ticks: u64) {
    let clamped = ticks.clamp(10_000, u64::from(u32::MAX));
    // SAFETY: Programming ARM Generic Virtual Timer (`CNTV_TVAL_EL0` / `CNTV_CTL_EL0`) in EL1.
    unsafe {
        asm!(
            "msr cntv_tval_el0, {tval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            tval = in(reg) clamped,
            ctl = in(reg) CNTV_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

pub(super) fn init_preempt_timer() {
    let freq = read_cntfrq();
    // 10 ms tick interval (fallback to 625_000 ticks if CNTFRQ_EL0 reports 0).
    let interval = if freq >= 100 { freq / 100 } else { 625_000 };
    TIMER_TICK_INTERVAL.store(interval, Ordering::Release);
    arm_virtual_timer(interval);
}

/// Spectre v1 Consumption of Speculative Data Barrier (`csdb`) after bounds checks.
#[allow(clippy::inline_always)] // Intentional: Spectre v1 `csdb` must emit inline after bounds check.
#[inline(always)]
pub(super) fn spec_barrier() {
    // SAFETY: `csdb` is an architectural hint-space barrier (NOP on older cores, speculation barrier on v8.2+).
    unsafe {
        asm!("csdb", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub(super) fn disable_virtual_timer() {
    // SAFETY: Masking and disabling `CNTV_CTL_EL0` (`IMASK=1, ENABLE=0`) in EL1 prevents
    // idle cores from taking spurious virtual timer IRQs (`P9`).
    unsafe {
        asm!(
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            ctl = in(reg) 2u64,
            options(nomem, nostack),
        );
    }
}

#[inline]
pub(super) fn arm_virtual_timer_cval(deadline_ticks: u64) {
    // SAFETY: Programs absolute compare value `CNTV_CVAL_EL0` and unmasks the virtual timer
    // so an idle core parked in `wfi` wakes at `CNTVCT_EL0 >= deadline_ticks`.
    unsafe {
        asm!(
            "msr cntv_cval_el0, {cval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            cval = in(reg) deadline_ticks,
            ctl = in(reg) CNTV_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

/// Mask local IRQs (`daifset #2`) before checking runnable state and entering `wfi` (`P9`).
#[inline]
pub(super) fn mask_local_irqs() {
    // SAFETY: Masking local IRQs in EL1 around the idle check + `wfi`.
    unsafe {
        asm!("msr daifset, #2", options(nomem, nostack));
    }
}

/// Park in low-power `wfi` with IRQs masked (wakes on pending SGI/IRQ/timer), then unmask briefly.
#[inline]
pub(super) fn wfi_unmask_cycle() {
    // SAFETY: Low-power WFI with IRQs masked (wakes on pending SGI/IRQ/timer), then unmask to service it.
    unsafe {
        asm!(
            "dsb sy",
            "wfi",
            "msr daifclr, #2",
            "isb",
            options(nomem, nostack),
        );
    }
}
