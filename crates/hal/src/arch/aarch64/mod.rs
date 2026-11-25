//! Pure 64-bit `aarch64` HAL (ARMv8.2-A / Cortex-A76 / Raspberry Pi 5):
//! `PL011` UART, `VBAR_EL1` vectors, `TPIDR_EL1` per-CPU, 4-level `TTBR0/TTBR1` paging,
//! EL0 `svc #0` + `TTBR0_EL1` multi-process switching, SMP, and PSCI `SYSTEM_OFF`.

pub mod gic;
pub mod paging;
pub mod serial;
pub mod smp;
pub mod syscall;

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use newos_abi::{ShutdownStatus, SysError, cpu_isa};
use newos_kernel_core::memory::{CpuSecurityFeatures, PhysAddr, UntypedInventory, VirtAddr};
use newos_kernel_core::{BootInfo, DomainRole, HalPlatform};

const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

static BREAKPOINT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_COUNT: AtomicU64 = AtomicU64::new(0);
static PAN_ENABLED: AtomicBool = AtomicBool::new(false);
static SSBS_ENABLED: AtomicBool = AtomicBool::new(false);
static CSV2_SUPPORTED: AtomicBool = AtomicBool::new(false);
static CSV3_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PMUV3_ENABLED: AtomicBool = AtomicBool::new(false);
static CPU_ISA_FEATURES: AtomicU64 = AtomicU64::new(0);
static PSCI_USE_SMC: AtomicBool = AtomicBool::new(false);
static ENTROPY_STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

#[inline]
pub fn cpu_isa_features() -> u64 {
    CPU_ISA_FEATURES.load(Ordering::Acquire)
}

#[inline]
pub fn pmuv3_enabled() -> bool {
    PMUV3_ENABLED.load(Ordering::Acquire)
}

/// Probe ARMv8.2-A Cortex-A76 CPU security & ISA features (`PAN`, `SSBS`, `CSV2`, `CSV3`,
/// `LSE`, `CRC32`, `AES`, `PMULL`, `SHA1`, `SHA256`, `DOTPROD`, `FP16`, `ASIMD`, `PMUv3`),
/// cache line size (`CTR_EL0`), and physical address width (`ID_AA64MMFR0_EL1.PARange`).
/// Enables hardware `PAN`, `SCTLR_EL1.DSSBS`, and `PMUv3` cycle counter when present.
fn probe_and_enable_cpu_hardening() {
    let mmfr0: u64;
    let mmfr1: u64;
    let pfr0: u64;
    let pfr1: u64;
    let isar0: u64;
    let dfr0: u64;
    let ctr: u64;
    // SAFETY: Reading architectural ID and cache-type registers in EL1 inspects hardware capabilities.
    unsafe {
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack));
        asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack));
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nomem, nostack));
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) pfr1, options(nomem, nostack));
        asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack));
        asm!("mrs {}, id_aa64dfr0_el1", out(reg) dfr0, options(nomem, nostack));
        asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
    }
    let has_pan = ((mmfr1 >> 20) & 0xF) != 0;
    let has_csv2 = ((pfr0 >> 56) & 0xF) != 0;
    let has_csv3 = ((pfr0 >> 60) & 0xF) != 0;
    let has_ssbs = ((pfr1 >> 4) & 0xF) != 0;

    if has_pan || has_ssbs {
        // SAFETY: CPU advertises PAN and/or SSBS; clearing `SCTLR_EL1.SPAN` (bit 23) forces
        // `PSTATE.PAN = 1` on EL1 entry, and clearing `SCTLR_EL1.DSSBS` (bit 44 = 0) sets
        // `PSTATE.SSBS = 0` on EL1 entry so Speculative Store Bypass is *prevented* (`M6`).
        unsafe {
            let mut sctlr: u64;
            asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
            if has_pan {
                sctlr &= !(1u64 << 23);
            }
            if has_ssbs {
                sctlr &= !(1u64 << 44);
            }
            asm!("msr sctlr_el1, {}", "isb", in(reg) sctlr, options(nomem, nostack));
            if has_pan {
                asm!("msr pan, #1", "isb", options(nomem, nostack));
            }
            if has_ssbs {
                // Set `PSTATE.SSBS = 0` immediately via architectural `SSBS` system register (`s3_3_c4_c2_6`).
                asm!("msr s3_3_c4_c2_6, xzr", "isb", options(nomem, nostack));
            }
        }
    }

    // Decode ARMv8.2-A Cortex-A76 ISA extensions & cache/PA geometry.
    let mut isa = 0u64;
    let aes_field = (isar0 >> 4) & 0xF;
    if aes_field >= 1 {
        isa |= cpu_isa::AES;
    }
    if aes_field >= 2 {
        isa |= cpu_isa::PMULL;
    }
    if ((isar0 >> 8) & 0xF) >= 1 {
        isa |= cpu_isa::SHA1;
    }
    if ((isar0 >> 12) & 0xF) >= 1 {
        isa |= cpu_isa::SHA256;
    }
    if ((isar0 >> 16) & 0xF) >= 1 {
        isa |= cpu_isa::CRC32;
    }
    if ((isar0 >> 20) & 0xF) >= 2 {
        isa |= cpu_isa::LSE;
    }
    if ((isar0 >> 44) & 0xF) >= 1 {
        isa |= cpu_isa::DOTPROD;
    }
    let asimd_field = (pfr0 >> 20) & 0xF;
    let fp_field = (pfr0 >> 16) & 0xF;
    if asimd_field != 0xF {
        isa |= cpu_isa::ASIMD;
    }
    if asimd_field == 1 || fp_field == 1 {
        isa |= cpu_isa::FP16;
    }
    let pmu_ver = (dfr0 >> 8) & 0xF;
    let has_pmuv3 = pmu_ver >= 1 && pmu_ver != 0xF;
    if has_pmuv3 {
        isa |= cpu_isa::PMUV3;
        // SAFETY: CPU advertises PMUv3 (`ID_AA64DFR0_EL1.PMUVer`); enable the architectural
        // 64-bit cycle counter (`PMCCNTR_EL0`) for EL1 only (`PMUSERENR_EL0 = 0` so unprivileged
        // EL0 processes do not get a free high-resolution side-channel timer).
        unsafe {
            let pmcr: u64 = (1 << 0) | (1 << 2); // E (enable) | C (reset cycle counter)
            let cntenset: u64 = 1 << 31; // Enable PMCCNTR_EL0
            let userenr: u64 = 0; // Disallow direct EL0 PMU counter reads
            asm!(
                "msr pmuserenr_el0, {userenr}",
                "msr pmcr_el0, {pmcr}",
                "msr pmcntenset_el0, {cntenset}",
                "isb",
                userenr = in(reg) userenr,
                pmcr = in(reg) pmcr,
                cntenset = in(reg) cntenset,
                options(nomem, nostack),
            );
        }
    }

    let pa_bits: u8 = match mmfr0 & 0xF {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        _ => 40,
    };
    let dmin_line = (ctr >> 16) & 0xF;
    let dcache_line_bytes = (4u16).checked_shl(dmin_line as u32).unwrap_or(64);
    paging::set_dcache_line_bytes(u64::from(dcache_line_bytes));

    PAN_ENABLED.store(has_pan, Ordering::Release);
    SSBS_ENABLED.store(has_ssbs, Ordering::Release);
    CSV2_SUPPORTED.store(has_csv2, Ordering::Release);
    CSV3_SUPPORTED.store(has_csv3, Ordering::Release);
    PMUV3_ENABLED.store(has_pmuv3, Ordering::Release);
    CPU_ISA_FEATURES.store(
        cpu_isa::pack(isa, pa_bits, dcache_line_bytes),
        Ordering::Release,
    );
}

// 2 KiB-aligned EL1 exception vector table handling EL1 `brk #0` and EL0 `svc #0` / faults.
global_asm!(
    ".balign 2048",
    ".global __newos_aarch64_vectors",
    "__newos_aarch64_vectors:",
    // Current EL with SP0 (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Current EL with SPx (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_irq_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch64 (4 x 128B) -> EL0 `svc #0` / faults & EL0 IRQ preemption!
    ".balign 128", "b __newos_sync_el0",
    ".balign 128", "b __newos_irq_el0",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch32 (unused — pure 64-bit only!)
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    "__newos_sync_el1:",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x16, x17, [sp, #-16]!",
    "stp x18, xzr, [sp, #-16]!",
    "stp x29, x30, [sp, #-16]!",
    "bl {sync_el1}",
    "ldp x29, x30, [sp], #16",
    "ldp x18, xzr, [sp], #16",
    "ldp x16, x17, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x8,  x9,  [sp], #16",
    "ldp x6,  x7,  [sp], #16",
    "ldp x4,  x5,  [sp], #16",
    "ldp x2,  x3,  [sp], #16",
    "ldp x0,  x1,  [sp], #16",
    "eret",
    "__newos_irq_el1:",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x16, x17, [sp, #-16]!",
    "stp x18, xzr, [sp, #-16]!",
    "stp x29, x30, [sp, #-16]!",
    "bl {irq_el1}",
    "ldp x29, x30, [sp], #16",
    "ldp x18, xzr, [sp], #16",
    "ldp x16, x17, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x8,  x9,  [sp], #16",
    "ldp x6,  x7,  [sp], #16",
    "ldp x4,  x5,  [sp], #16",
    "ldp x2,  x3,  [sp], #16",
    "ldp x0,  x1,  [sp], #16",
    "eret",
    // EL0 synchronous entry: save full 272-byte `TrapFrame` (`x0..x30, sp_el0, elr_el1, spsr_el1`)
    "__newos_sync_el0:",
    "sub sp, sp, #272",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "mrs x9,  sp_el0",
    "stp x30, x9,  [sp, #240]",
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #256]",
    // Spectre-BHB mitigation (Cortex-A76: 24-iteration branch-history clearing loop + ISB)
    "mov x10, #24",
    "1: b 2f",
    "2: subs x10, x10, #1",
    "b.ne 1b",
    "isb",
    "mov x0, sp",
    "bl {sync_el0}",
    "b __newos_el0_restore",
    // EL0 IRQ entry: save full 272-byte `TrapFrame` for preemptive timer context switches
    "__newos_irq_el0:",
    "sub sp, sp, #272",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "mrs x9,  sp_el0",
    "stp x30, x9,  [sp, #240]",
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #256]",
    // Spectre-BHB mitigation (Cortex-A76: 24-iteration branch-history clearing loop + ISB)
    "mov x10, #24",
    "3: b 4f",
    "4: subs x10, x10, #1",
    "b.ne 3b",
    "isb",
    "mov x0, sp",
    "bl {irq_el0}",
    // Restore (possibly TTBR0-switched!) `TrapFrame` and return to EL0 via `eret`
    "__newos_el0_restore:",
    "ldp x10, x11, [sp, #256]",
    "msr elr_el1, x10",
    "msr spsr_el1, x11",
    "ldp x30, x9,  [sp, #240]",
    "msr sp_el0, x9",
    "ldp x28, x29, [sp, #224]",
    "ldp x26, x27, [sp, #208]",
    "ldp x24, x25, [sp, #192]",
    "ldp x22, x23, [sp, #176]",
    "ldp x20, x21, [sp, #160]",
    "ldp x18, x19, [sp, #144]",
    "ldp x16, x17, [sp, #128]",
    "ldp x14, x15, [sp, #112]",
    "ldp x12, x13, [sp, #96]",
    "ldp x10, x11, [sp, #80]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x0,  x1,  [sp, #0]",
    "add sp, sp, #272",
    "eret",
    // Enter EL0 from a `TrapFrame` pointer in `x0` (restores all x0..x30, sp_el0, elr_el1, spsr_el1)
    ".global __newos_el0_enter_frame",
    "__newos_el0_enter_frame:",
    "ldp x10, x11, [x0, #256]",
    "msr elr_el1, x10",
    "msr spsr_el1, x11",
    "ldp x30, x9,  [x0, #240]",
    "msr sp_el0, x9",
    "ldp x28, x29, [x0, #224]",
    "ldp x26, x27, [x0, #208]",
    "ldp x24, x25, [x0, #192]",
    "ldp x22, x23, [x0, #176]",
    "ldp x20, x21, [x0, #160]",
    "ldp x18, x19, [x0, #144]",
    "ldp x16, x17, [x0, #128]",
    "ldp x14, x15, [x0, #112]",
    "ldp x12, x13, [x0, #96]",
    "ldp x10, x11, [x0, #80]",
    "ldp x8,  x9,  [x0, #64]",
    "ldp x6,  x7,  [x0, #48]",
    "ldp x4,  x5,  [x0, #32]",
    "ldp x2,  x3,  [x0, #16]",
    "ldp x0,  x1,  [x0, #0]",
    "eret",
    "__newos_unhandled_el1:",
    "adrp x9, {emerg_stack}",
    "add x9, x9, :lo12:{emerg_stack}",
    "add sp, x9, #4096",
    "mrs x0, esr_el1",
    "mrs x1, elr_el1",
    "mrs x2, far_el1",
    "mrs x3, spsr_el1",
    "bl {unhandled_el1}",
    "1: wfi",
    "b 1b",
    sync_el1 = sym aarch64_sync_el1_handler,
    irq_el1 = sym aarch64_irq_el1_handler,
    sync_el0 = sym syscall::sync_el0_dispatch,
    irq_el0 = sym syscall::irq_el0_dispatch,
    unhandled_el1 = sym aarch64_unhandled_el1_handler,
    emerg_stack = sym EL1_EMERGENCY_STACK,
);

/// Static 4 KiB emergency stack used exclusively by `__newos_unhandled_el1` so an EL1
/// stack overflow into a guard page prints diagnostics instead of double-faulting.
#[repr(C, align(16))]
struct EmergencyStack([u8; 4096]);

static EL1_EMERGENCY_STACK: EmergencyStack = EmergencyStack([0; 4096]);

/// Per-CPU top-of-stack virtual addresses for guarded 32 KiB EL1 stacks (4 KiB unmapped guard below).
static EL1_GUARDED_STACK_TOPS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Return the top-of-stack VA for `cpu_id`'s guarded EL1 stack (or `0` if not mapped).
#[inline]
pub fn guarded_el1_stack_top(cpu_id: usize) -> u64 {
    if cpu_id < EL1_GUARDED_STACK_TOPS.len() {
        EL1_GUARDED_STACK_TOPS[cpu_id].load(Ordering::Acquire)
    } else {
        0
    }
}

/// Pivot `SP_EL1` to `new_sp` and branch directly to diverging `target`.
///
/// # Safety
/// `new_sp` must be 16-byte aligned and point to the top of a valid, writable EL1 stack.
// SAFETY: Caller guarantees `new_sp` is 16-byte aligned, writable, and `target` never returns.
pub unsafe fn pivot_sp_and_jump(new_sp: u64, target: extern "C" fn() -> !) -> ! {
    // SAFETY: Caller guarantees `new_sp` is valid and `target` never returns.
    unsafe {
        asm!(
            "mov sp, {sp}",
            "br {target}",
            sp = in(reg) new_sp,
            target = in(reg) target,
            options(noreturn),
        );
    }
}

// SAFETY: `__newos_aarch64_vectors` is defined by the `global_asm!` block above as a
// 2 KiB-aligned EL1 exception vector table.
unsafe extern "C" {
    static __newos_aarch64_vectors: u8;
}

extern "C" fn aarch64_unhandled_el1_handler(esr: u64, elr: u64, far: u64, spsr: u64) -> ! {
    let mut s = serial::UnlockedPl011;
    let _ = writeln!(
        s,
        "[newos-hal] FATAL unhandled EL1 exception ESR={:#018x} ELR={:#018x} FAR={:#018x} SPSR={:#018x}",
        esr, elr, far, spsr
    );
    system_off(ShutdownStatus::Failed)
}

extern "C" fn aarch64_irq_el1_handler() {
    if let Some(iar) = gic::acknowledge() {
        let irq_id = iar & 0x3FF;
        if irq_id == gic::SGI_RESCHEDULE && get_cpu_id() != 0 {
            smp::record_ap_sgi_ack();
        } else if irq_id == gic::virt_timer_irq() {
            // Mask and disable the virtual timer so an idle core in EL1 never enters a
            // continuous timer-IRQ storm (`P9`), record the tick for boot self-check (`H5`),
            // and wake any threads whose `SleepUntil` / `NotifyWait` deadline has expired.
            // SAFETY: Disabling `CNTV_CTL_EL0` (`IMASK=1, ENABLE=0`) in EL1 IRQ context.
            unsafe {
                asm!("msr cntv_ctl_el0, {}", "isb", in(reg) 2u64, options(nomem, nostack));
            }
            TIMER_COUNT.fetch_add(1, Ordering::Release);
            syscall::wake_expired_timers();
        } else if (32..1020).contains(&irq_id) {
            // Route external SPIs arriving while in EL1 (e.g., idle `wfi` or inside a syscall)
            // through the exact same mask+signal path as EL0 IRQs so edge IRQs are never dropped.
            syscall::dispatch_peripheral_spi(irq_id);
        }
        gic::end_of_interrupt(iar);
    }
}

extern "C" fn aarch64_sync_el1_handler() {
    let esr: u64;
    let elr: u64;
    let far: u64;
    // SAFETY: Reading `ESR_EL1`, `ELR_EL1`, and `FAR_EL1` inside EL1 synchronous exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
        asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack));
        asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0xFFFF;
    // Only skip `brk #0` (the boot-time vector self-test). Every other `brk` immediate —
    // including KCFI traps (`brk #0x822x`) and compiler traps (`brk #0x1`) — is fatal (`H1`).
    if ec == 0x3C && iss == 0 {
        BREAKPOINT_COUNT.fetch_add(1, Ordering::Release);
        // SAFETY: Advancing `ELR_EL1` by 4 skips the `brk #0` self-test instruction cleanly.
        unsafe {
            asm!("msr elr_el1, {}", in(reg) elr + 4, options(nomem, nostack));
        }
        return;
    }

    let mut s = serial::UnlockedPl011;
    let _ = writeln!(
        s,
        "[newos-hal] FATAL AArch64 EL1 sync exception EC={:#x} ISS={:#x} ELR={:#018x} FAR={:#018x}",
        ec, iss, elr, far
    );
    system_off(ShutdownStatus::Failed)
}

pub fn install_vectors() {
    let addr = (&raw const __newos_aarch64_vectors) as u64;
    // SAFETY: Limine enters `_start` on aarch64 with `SPSel = 0` (`SP_EL0` active, `SP_EL1 = 0`).
    // Switch to `SP_EL1` with the active stack pointer and install `VBAR_EL1`.
    unsafe {
        asm!(
            "mov x9, sp",
            "msr spsel, #1",
            "mov sp, x9",
            "msr vbar_el1, {vbar}",
            "isb",
            vbar = in(reg) addr,
            out("x9") _,
            options(nostack),
        );
    }
}

pub fn set_cpu_id(id: u64) {
    // SAFETY: Writing logical CPU ID into EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) id, options(nomem, nostack));
    }
}

pub fn get_cpu_id() -> u64 {
    let id: u64;
    // SAFETY: Reading EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) id, options(nomem, nostack));
    }
    id
}

static IN_SYSTEM_OFF: AtomicBool = AtomicBool::new(false);

/// Power off or reboot cleanly via PSCI `SYSTEM_OFF` / `SYSTEM_RESET`
/// (`smc #0` on Raspberry Pi 5 ATF/UEFI, `hvc #0` on QEMU `virt`).
pub fn system_off(code: ShutdownStatus) -> ! {
    // Prevent infinite recursion if a wrong PSCI conduit faults back into `aarch64_sync_el1_handler`.
    if IN_SYSTEM_OFF.swap(true, Ordering::AcqRel) {
        loop {
            // SAFETY: Mask interrupts and halt forever on recursive shutdown fault.
            unsafe {
                asm!("msr daifset, #0xf", "wfi", options(nomem, nostack));
            }
        }
    }
    let mut s = serial::UnlockedPl011;
    let psci_fn = match code {
        ShutdownStatus::Success => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=OK)");
            PSCI_SYSTEM_OFF
        }
        ShutdownStatus::Failed => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=FAIL)");
            PSCI_SYSTEM_OFF
        }
        ShutdownStatus::Reboot => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_RESET (reboot)");
            PSCI_SYSTEM_RESET
        }
    };
    let use_smc = PSCI_USE_SMC.load(Ordering::Acquire);
    // SAFETY: Invoking ARM PSCI `SYSTEM_OFF` (0x8400_0008) or `SYSTEM_RESET` (0x8400_0009)
    // over the board's PSCI conduit (`smc #0` on RPi5 ATF/EL3, `hvc #0` on QEMU `virt`),
    // declaring SMCCC caller-saved register clobbers (`x0..x3`).
    unsafe {
        if use_smc {
            asm!(
                "smc #0",
                inout("x0") psci_fn => _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                options(nomem, nostack),
            );
        } else {
            asm!(
                "hvc #0",
                inout("x0") psci_fn => _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                options(nomem, nostack),
            );
        }
    }
    loop {
        // SAFETY: Fallback low-power WFI loop if PSCI is unavailable.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

pub struct Aarch64Platform {
    board: &'static crate::board::BoardDescriptor,
    serial: serial::Pl011,
    vspace: paging::Aarch64VSpace,
    online_cpus: usize,
}

#[derive(Default)]
struct AcpiHardware {
    psci_use_hvc: Option<bool>,
    spcr_uart_base: Option<u64>,
    gicd_base: Option<u64>,
    gicc_base: Option<u64>,
    gic_version: u8,
    madt_cpus: usize,
    virt_timer_irq: Option<u32>,
    ecam_base: Option<u64>,
}

/// Read `dst.len()` bytes from physical memory `phys_addr` using HHDM if already mapped,
/// or by temporarily mapping each 4 KiB page read-only at `ACPI_SCRATCH_VIRT`.
#[cfg(feature = "acpi")]
fn read_phys_bytes(
    vspace: &mut paging::Aarch64VSpace,
    untyped: &mut UntypedInventory,
    hhdm_offset: u64,
    phys_addr: u64,
    dst: &mut [u8],
) -> bool {
    use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
    const ACPI_SCRATCH_VIRT: u64 = 0xffff_b003_0000_0000;

    let Ok(ro_flags) = PageFlags::new_wx(false, false, false, false) else {
        return false;
    };
    let Ok(scratch_va) = VirtAddr::new_page_aligned(ACPI_SCRATCH_VIRT) else {
        return false;
    };

    let mut copied = 0usize;
    while copied < dst.len() {
        let Some(cur_phys) = phys_addr.checked_add(copied as u64) else {
            return false;
        };
        let page_phys = cur_phys & !0xFFF;
        let page_off = (cur_phys & 0xFFF) as usize;
        let chunk = (4096 - page_off).min(dst.len() - copied);

        let hhdm_page = hhdm_offset.wrapping_add(page_phys);
        if hhdm_offset != 0
            && let Ok(hhdm_va) = VirtAddr::new_canonical(hhdm_page)
            && vspace.translate(hhdm_va).is_some()
        {
            // SAFETY: `vspace.translate(hhdm_va)` confirmed this 4 KiB page is mapped in `TTBR1_EL1`.
            let src = unsafe {
                core::slice::from_raw_parts((hhdm_page + page_off as u64) as *const u8, chunk)
            };
            dst[copied..copied + chunk].copy_from_slice(src);
        } else {
            let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(page_phys)) else {
                return false;
            };
            if vspace.map_4k(scratch_va, frame, ro_flags, untyped).is_err() {
                return false;
            }
            // SAFETY: `scratch_va` was just mapped read-only to `frame` in `TTBR1_EL1`.
            let src = unsafe {
                core::slice::from_raw_parts(
                    (ACPI_SCRATCH_VIRT + page_off as u64) as *const u8,
                    chunk,
                )
            };
            dst[copied..copied + chunk].copy_from_slice(src);
            let _ = vspace.unmap_4k(scratch_va);
        }
        copied += chunk;
    }
    true
}

/// Inspect ACPI RSDP -> XSDT -> FADT / SPCR / MADT / GTDT / MCFG from physical memory.
#[cfg(feature = "acpi")]
fn probe_acpi_hardware(
    vspace: &mut paging::Aarch64VSpace,
    untyped: &mut UntypedInventory,
    hhdm_offset: u64,
    rsdp_addr: u64,
) -> AcpiHardware {
    let mut hw = AcpiHardware::default();
    if rsdp_addr == 0 {
        return hw;
    }
    let mut rsdp_buf = [0u8; 36];
    if !read_phys_bytes(vspace, untyped, hhdm_offset, rsdp_addr, &mut rsdp_buf) {
        return hw;
    }
    let Some(rsdp) = newos_kernel_core::acpi::parse_rsdp(&rsdp_buf) else {
        return hw;
    };
    if rsdp.xsdt_addr == 0 {
        return hw;
    }

    let mut hdr_buf = [0u8; 36];
    if !read_phys_bytes(vspace, untyped, hhdm_offset, rsdp.xsdt_addr, &mut hdr_buf) {
        return hw;
    }
    let xsdt_len = u32::from_le_bytes([hdr_buf[4], hdr_buf[5], hdr_buf[6], hdr_buf[7]]) as usize;
    let mut xsdt_buf = [0u8; 4096];
    if !(36..=xsdt_buf.len()).contains(&xsdt_len)
        || !read_phys_bytes(
            vspace,
            untyped,
            hhdm_offset,
            rsdp.xsdt_addr,
            &mut xsdt_buf[..xsdt_len],
        )
    {
        return hw;
    }
    let xsdt = &xsdt_buf[..xsdt_len];
    if newos_kernel_core::acpi::validate_sdt(xsdt, b"XSDT").is_none() {
        return hw;
    }

    let mut tbl_buf = [0u8; 4096];
    let mut off = 36usize;
    while off + 8 <= xsdt_len {
        let entry_phys = u64::from_le_bytes([
            xsdt[off],
            xsdt[off + 1],
            xsdt[off + 2],
            xsdt[off + 3],
            xsdt[off + 4],
            xsdt[off + 5],
            xsdt[off + 6],
            xsdt[off + 7],
        ]);
        off += 8;
        if entry_phys == 0 {
            continue;
        }
        if !read_phys_bytes(vspace, untyped, hhdm_offset, entry_phys, &mut hdr_buf) {
            continue;
        }
        let tbl_len = u32::from_le_bytes([hdr_buf[4], hdr_buf[5], hdr_buf[6], hdr_buf[7]]) as usize;
        if !(36..=tbl_buf.len()).contains(&tbl_len) {
            continue;
        }
        match &hdr_buf[0..4] {
            b"FACP" | b"SPCR" | b"APIC" | b"GTDT" | b"MCFG" => {}
            _ => continue,
        }
        if !read_phys_bytes(
            vspace,
            untyped,
            hhdm_offset,
            entry_phys,
            &mut tbl_buf[..tbl_len],
        ) {
            continue;
        }
        let tbl = &tbl_buf[..tbl_len];
        match &hdr_buf[0..4] {
            b"FACP" => {
                if let Some(arm) = newos_kernel_core::acpi::parse_fadt_arm_boot_arch(tbl)
                    && arm.psci_compliant
                {
                    hw.psci_use_hvc = Some(arm.psci_use_hvc);
                }
            }
            b"SPCR" => {
                if let Some(spcr) = newos_kernel_core::acpi::parse_spcr(tbl)
                    && spcr.interface_type == newos_kernel_core::acpi::SPCR_INTERFACE_PL011
                    && spcr.base_address != 0
                    && (spcr.base_address & 0xFFF) == 0
                {
                    hw.spcr_uart_base = Some(spcr.base_address);
                }
            }
            b"APIC" => {
                if let Some(madt) = newos_kernel_core::acpi::parse_madt(tbl) {
                    if madt.gicd_base != 0 && (madt.gicd_base & 0xFFF) == 0 {
                        hw.gicd_base = Some(madt.gicd_base);
                    }
                    if madt.gicc_base != 0 && (madt.gicc_base & 0xFFF) == 0 {
                        hw.gicc_base = Some(madt.gicc_base);
                    }
                    hw.gic_version = madt.gic_version;
                    hw.madt_cpus = madt.cpu_count;
                }
            }
            b"GTDT" => {
                if let Some(gtdt) = newos_kernel_core::acpi::parse_gtdt(tbl)
                    && gtdt.el1_virt_timer_gsiv != 0
                {
                    hw.virt_timer_irq = Some(gtdt.el1_virt_timer_gsiv);
                }
            }
            b"MCFG" => {
                if let Some(mcfg) = newos_kernel_core::acpi::parse_mcfg(tbl)
                    && mcfg.ecam_base != 0
                {
                    hw.ecam_base = Some(mcfg.ecam_base);
                }
            }
            _ => {}
        }
    }
    hw
}

impl Aarch64Platform {
    pub fn init(info: &mut BootInfo) -> Self {
        use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
        let board = crate::board::select_board(info.qemu_virt);
        if info.hhdm_offset == 0 {
            let mut s = serial::UnlockedPl011;
            let _ = writeln!(
                s,
                "[newos-hal] FATAL: Limine HHDM offset is 0; halting via PSCI"
            );
            system_off(ShutdownStatus::Failed);
        }
        let mut vspace = paging::Aarch64VSpace::from_current_ttbr1(info.hhdm_offset);

        // Allocate per-CPU guarded 32 KiB EL1 kernel stacks in `TTBR1_EL1` with an unmapped
        // 4 KiB guard page directly below each core's stack.
        const KERNEL_STACK_BASE: u64 = 0xffff_b010_0000_0000;
        const KERNEL_GUARD_BYTES: u64 = 4096;
        const KERNEL_STACK_PAGES: u64 = 8;
        const KERNEL_STACK_STRIDE: u64 = KERNEL_GUARD_BYTES + KERNEL_STACK_PAGES * 4096;
        if let Ok(stack_flags) = PageFlags::new_wx(true, false, false, false) {
            for (cpu, stack_top) in EL1_GUARDED_STACK_TOPS.iter().enumerate() {
                let base = KERNEL_STACK_BASE + (cpu as u64) * KERNEL_STACK_STRIDE;
                let mut ok = true;
                for p in 0..KERNEL_STACK_PAGES {
                    let va = base + KERNEL_GUARD_BYTES + p * 4096;
                    let mapped = VirtAddr::new_page_aligned(va)
                        .and_then(|v| {
                            info.untyped
                                .retype_frame()
                                .and_then(|fr| vspace.map_4k(v, fr, stack_flags, &mut info.untyped))
                        })
                        .is_ok();
                    if !mapped {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    stack_top.store(base + KERNEL_STACK_STRIDE, Ordering::Release);
                }
            }
        }

        // Discover hardware dynamically from ACPI (FADT/SPCR/MADT/GTDT/MCFG) when enabled,
        // falling back to the active `BoardDescriptor`.
        #[cfg(feature = "acpi")]
        let acpi = probe_acpi_hardware(
            &mut vspace,
            &mut info.untyped,
            info.hhdm_offset,
            info.rsdp_addr,
        );
        #[cfg(not(feature = "acpi"))]
        let acpi = AcpiHardware::default();

        // Lock PT_GNU_RELRO (`.data.rel.ro`, `.got`, `.dynamic`) read-only in `TTBR1_EL1`
        // after Limine has finished applying PIE relocations.
        // SAFETY: `__relro_start` and `__relro_end` are linker-defined section boundary symbols
        // in `crates/kernel/linker-aarch64.ld`; only their addresses are taken via `&raw const`.
        unsafe extern "C" {
            static __relro_start: u8;
            static __relro_end: u8;
        }
        let relro_start = (&raw const __relro_start) as u64;
        let relro_end = (&raw const __relro_end) as u64;
        if relro_end > relro_start {
            vspace.protect_ro_range(relro_start, relro_end);
        }

        // Select PL011 MMIO physical base (ACPI SPCR -> board descriptor fallback):
        const UART_VIRT: u64 = 0xffff_b000_0000_0000;
        let uart_phys = acpi.spcr_uart_base.unwrap_or(board.uart.phys_base);
        if let Ok(uart_virt) = VirtAddr::new_page_aligned(UART_VIRT)
            && let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(uart_phys))
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && vspace
                .map_4k(uart_virt, frame, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            serial::init_virt(UART_VIRT);
        } else {
            serial::init_virt(info.hhdm_offset.wrapping_add(uart_phys));
        }

        // Map capability-scoped Network Controller MMIO window (4 pages, Device-nGnRnE):
        // - Default: Raspberry Pi 5 (BCM2712 + RP1 Cadence GEM Gigabit Ethernet): `0x1F_0010_0000`
        // - Local test harness (`qemu` cmdline): QEMU `virt` VirtIO-MMIO slots 0..31: `0x0A00_0000`
        const RPI5_RP1_GEM_PHYS: u64 = 0x1F_0010_0000;
        const QEMU_NET_MMIO_PHYS: u64 = 0x0a00_0000;
        const NET_MMIO_VIRT: u64 = 0xffff_b001_0000_0000;
        const NET_MMIO_PAGES: u64 = 4;
        let net_mmio_phys = if info.qemu_virt {
            QEMU_NET_MMIO_PHYS
        } else {
            RPI5_RP1_GEM_PHYS
        };
        let mut net_mmio_mapped = false;
        if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true) {
            net_mmio_mapped = true;
            for p in 0..NET_MMIO_PAGES {
                let off = p * 4096;
                let mapped = VirtAddr::new_page_aligned(NET_MMIO_VIRT + off)
                    .and_then(|va| {
                        PhysFrame::from_aligned(PhysAddr::new(net_mmio_phys + off)).and_then(
                            |frame| vspace.map_4k(va, frame, mmio_flags, &mut info.untyped),
                        )
                    })
                    .is_ok();
                if !mapped {
                    net_mmio_mapped = false;
                    break;
                }
            }
        }
        let net_mmio = if !net_mmio_mapped {
            None
        } else if info.qemu_virt {
            // Scope BOOTSTRAP_NET_MMIO strictly to the single 512-byte VirtIO-Net slot (`C-3`)
            // rather than exposing all 32 VirtIO-MMIO devices on the bus.
            const VIRTIO_MAGIC: u32 = 0x7472_6976;
            const VIRTIO_DEV_NET: u32 = 1;
            const SLOT_STRIDE: u64 = 0x200;
            let mut found = None;
            for slot in 0..32u64 {
                let off = slot * SLOT_STRIDE;
                let base_va = NET_MMIO_VIRT + off;
                // SAFETY: All `NET_MMIO_PAGES` pages of `NET_MMIO_VIRT..NET_MMIO_VIRT + 16 KiB`
                // were verified mapped above as Device-nGnRnE.
                let (magic, dev_id) = unsafe {
                    (
                        core::ptr::read_volatile(base_va as *const u32),
                        core::ptr::read_volatile((base_va + 8) as *const u32),
                    )
                };
                if magic == VIRTIO_MAGIC && dev_id == VIRTIO_DEV_NET {
                    found = Some((
                        PhysAddr::new(net_mmio_phys + off),
                        base_va,
                        SLOT_STRIDE,
                        Some(crate::board::IrqLine::gic(48 + slot as u16)),
                    ));
                    break;
                }
            }
            found
        } else {
            Some((
                PhysAddr::new(net_mmio_phys),
                NET_MMIO_VIRT,
                NET_MMIO_PAGES * 4096,
                board.net_irq,
            ))
        };
        let net_irq = net_mmio.and_then(|(_, _, _, irq)| irq);
        let net_mmio = net_mmio.map(|(pa, va, len, _)| (pa, va, len));

        // Map capability-scoped Hardware RNG MMIO window (Device-nGnRnE):
        // - Raspberry Pi 5 (BCM2712 `iproc-rng200`): `0x10_7D20_8000` (scoped to `0x28` bytes)
        // - QEMU `virt`: single 512-byte VirtIO-RNG slot (`device_id == 4`) on `0x0A00_0000`
        const RPI5_RNG200_PHYS: u64 = 0x10_7D20_8000;
        const RPI5_RNG200_LEN: u64 = 0x28;
        const RNG_MMIO_VIRT: u64 = 0xffff_b005_0000_0000;
        let rng_mmio = if info.qemu_virt {
            if !net_mmio_mapped {
                None
            } else {
                const VIRTIO_MAGIC: u32 = 0x7472_6976;
                const VIRTIO_DEV_RNG: u32 = 4;
                const SLOT_STRIDE: u64 = 0x200;
                let mut found = None;
                for slot in 0..32u64 {
                    let off = slot * SLOT_STRIDE;
                    let base_va = NET_MMIO_VIRT + off;
                    // SAFETY: `NET_MMIO_VIRT..+16 KiB` was verified mapped as Device-nGnRnE.
                    let (magic, dev_id) = unsafe {
                        (
                            core::ptr::read_volatile(base_va as *const u32),
                            core::ptr::read_volatile((base_va + 8) as *const u32),
                        )
                    };
                    if magic == VIRTIO_MAGIC && dev_id == VIRTIO_DEV_RNG {
                        found = Some((
                            PhysAddr::new(net_mmio_phys + off),
                            base_va,
                            SLOT_STRIDE,
                            Some(crate::board::IrqLine::gic(48 + slot as u16)),
                        ));
                        break;
                    }
                }
                found
            }
        } else if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && let Ok(rng_va) = VirtAddr::new_page_aligned(RNG_MMIO_VIRT)
            && let Ok(rng_fr) = PhysFrame::from_aligned(PhysAddr::new(RPI5_RNG200_PHYS))
            && vspace
                .map_4k(rng_va, rng_fr, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            // Optionally mix 64 bits of hardware TRNG into `ENTROPY_STATE` for EL0 ASLR
            // before handing `BOOTSTRAP_RNG_MMIO` exclusively to `newos-key-pd`.
            // SAFETY: `RNG_MMIO_VIRT` was just mapped as Device-nGnRnE to BCM2712 `iproc-rng200`.
            unsafe {
                let ctrl = RNG_MMIO_VIRT as *mut u32;
                let fifo_cnt = (RNG_MMIO_VIRT + 0x24) as *const u32;
                let fifo_data = (RNG_MMIO_VIRT + 0x20) as *const u32;
                let cur = core::ptr::read_volatile(ctrl);
                core::ptr::write_volatile(ctrl, cur | 1);
                for _ in 0..256u32 {
                    if (core::ptr::read_volatile(fifo_cnt) & 0xFF) >= 2 {
                        let lo = u64::from(core::ptr::read_volatile(fifo_data));
                        let hi = u64::from(core::ptr::read_volatile(fifo_data));
                        ENTROPY_STATE.fetch_xor((hi << 32) | lo, Ordering::Relaxed);
                        break;
                    }
                }
            }
            Some((
                PhysAddr::new(RPI5_RNG200_PHYS),
                RNG_MMIO_VIRT,
                RPI5_RNG200_LEN,
                board.rng_irq,
            ))
        } else {
            None
        };
        let rng_irq = rng_mmio.and_then(|(_, _, _, irq)| irq);
        let rng_mmio = rng_mmio.map(|(pa, va, len, _)| (pa, va, len));
        syscall::register_board_irqs(net_irq, rng_irq, board.uart_irq);

        // Map GICv2 / GIC-400 Distributor & CPU Interface (ACPI MADT -> board descriptor fallback):
        const GICD_VIRT: u64 = 0xffff_b002_0000_0000;
        const GICC_VIRT: u64 = 0xffff_b002_0000_1000;
        let gicd_phys = acpi.gicd_base.unwrap_or(board.gicd.phys_base);
        let gicc_phys = acpi.gicc_base.unwrap_or(board.gicc.phys_base);
        let virt_timer_irq = acpi.virt_timer_irq.unwrap_or(gic::IRQ_VIRTUAL_TIMER);
        if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && let Ok(gicd_va) = VirtAddr::new_page_aligned(GICD_VIRT)
            && let Ok(gicc_va) = VirtAddr::new_page_aligned(GICC_VIRT)
            && let Ok(gicd_fr) = PhysFrame::from_aligned(PhysAddr::new(gicd_phys))
            && let Ok(gicc_fr) = PhysFrame::from_aligned(PhysAddr::new(gicc_phys))
            && vspace
                .map_4k(gicd_va, gicd_fr, mmio_flags, &mut info.untyped)
                .is_ok()
            && vspace
                .map_4k(gicc_va, gicc_fr, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            gic::init(GICD_VIRT, GICC_VIRT, virt_timer_irq);
        }

        // Select PSCI conduit from ACPI FADT `ARM_BOOT_ARCH` when available; fallback to board descriptor.
        let use_smc = match acpi.psci_use_hvc {
            Some(use_hvc) => !use_hvc,
            None => board.psci_use_smc,
        };
        PSCI_USE_SMC.store(use_smc, Ordering::Release);

        // Map capability-scoped Raspberry Pi 5 BCM2712 Hardware Watchdog MMIO (`0x10_7D20_0000`, `0x100` B):
        #[cfg(feature = "mmio-wdt")]
        let wdt_mmio = {
            const RPI5_PM_WDT_PHYS: u64 = 0x10_7D20_0000;
            const RPI5_PM_WDT_LEN: u64 = 0x100;
            const WDT_MMIO_VIRT: u64 = 0xffff_b006_0000_0000;
            if !info.qemu_virt
                && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
                && let Ok(wdt_va) = VirtAddr::new_page_aligned(WDT_MMIO_VIRT)
                && let Ok(wdt_fr) = PhysFrame::from_aligned(PhysAddr::new(RPI5_PM_WDT_PHYS))
                && vspace
                    .map_4k(wdt_va, wdt_fr, mmio_flags, &mut info.untyped)
                    .is_ok()
            {
                Some((
                    PhysAddr::new(RPI5_PM_WDT_PHYS),
                    WDT_MMIO_VIRT,
                    RPI5_PM_WDT_LEN,
                ))
            } else {
                None
            }
        };
        #[cfg(not(feature = "mmio-wdt"))]
        let wdt_mmio: Option<(PhysAddr, u64, u64)> = None;

        set_cpu_id(0);
        probe_and_enable_cpu_hardening();
        install_vectors();
        syscall::init(
            info.hhdm_offset,
            net_mmio,
            rng_mmio,
            wdt_mmio,
            info.qemu_virt,
            info.net_module.is_some(),
        );

        // Map Raspberry Pi 5 board peripherals (Device-nGnRnE) and grant capabilities to `init`:
        // - Slot 19 (`BOOTSTRAP_GPIO_MMIO`): RP1 IO_BANK0 / RIO0 / PADS_BANK0 (40-pin GPIO 0..=27)
        // - Slot 20 (`BOOTSTRAP_MBOX_MMIO`): BCM2712 VideoCore Property Mailbox (`0x10_7C01_3000`)
        // - Slot 21 (`BOOTSTRAP_THERMAL_MMIO`): BCM2712 AVS TMON Thermal Sensor (`0x10_7D5D_2000`)
        // - Slot 22 (`BOOTSTRAP_RP1_PERIPH_MMIO`): RP1 UART0, SPI0, I2C0, I2C1, PWM0
        if !info.qemu_virt
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
        {
            #[cfg(feature = "mmio-gpio")]
            {
                const RP1_GPIO_PHYS: u64 = 0x1F_000D_0000;
                const RP1_GPIO_LEN: u64 = 0x24000;
                const RP1_GPIO_VIRT: u64 = 0xffff_b007_0000_0000;
                let mut gpio_ok = true;
                for block_off in [0x0_0000u64, 0x1_0000u64, 0x2_0000u64] {
                    let mut block_mapped = true;
                    for p in 0..4u64 {
                        let off = block_off + p * 4096;
                        let ok = VirtAddr::new_page_aligned(RP1_GPIO_VIRT + off)
                            .and_then(|va| {
                                PhysFrame::from_aligned(PhysAddr::new(RP1_GPIO_PHYS + off))
                                    .and_then(|fr| {
                                        vspace.map_4k(va, fr, mmio_flags, &mut info.untyped)
                                    })
                            })
                            .is_ok();
                        if !ok {
                            block_mapped = false;
                            break;
                        }
                    }
                    if block_mapped {
                        syscall::register_extra_mmio_mapping(
                            PhysAddr::new(RP1_GPIO_PHYS + block_off),
                            RP1_GPIO_VIRT + block_off,
                            0x4000,
                        );
                    } else {
                        gpio_ok = false;
                    }
                }
                if gpio_ok {
                    syscall::register_init_mmio_cap(19, PhysAddr::new(RP1_GPIO_PHYS), RP1_GPIO_LEN);
                }
            }

            #[cfg(feature = "mmio-mbox")]
            {
                const MBOX_PHYS: u64 = 0x10_7C01_3000;
                const MBOX_VIRT: u64 = 0xffff_b008_0000_0000;
                if let Ok(va) = VirtAddr::new_page_aligned(MBOX_VIRT)
                    && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(MBOX_PHYS))
                    && vspace.map_4k(va, fr, mmio_flags, &mut info.untyped).is_ok()
                {
                    syscall::register_extra_mmio_mapping(
                        PhysAddr::new(MBOX_PHYS),
                        MBOX_VIRT,
                        0x1000,
                    );
                    syscall::register_init_mmio_cap(20, PhysAddr::new(MBOX_PHYS), 0x1000);
                }
            }

            #[cfg(feature = "mmio-thermal")]
            {
                const THERMAL_PHYS: u64 = 0x10_7D5D_2000;
                const THERMAL_VIRT: u64 = 0xffff_b009_0000_0000;
                if let Ok(va) = VirtAddr::new_page_aligned(THERMAL_VIRT)
                    && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(THERMAL_PHYS))
                    && vspace.map_4k(va, fr, mmio_flags, &mut info.untyped).is_ok()
                {
                    syscall::register_extra_mmio_mapping(
                        PhysAddr::new(THERMAL_PHYS),
                        THERMAL_VIRT,
                        0x1000,
                    );
                    syscall::register_init_mmio_cap(21, PhysAddr::new(THERMAL_PHYS), 0x1000);
                }
            }

            // Narrow RP1 peripheral capability to the 4 KiB RP1 UART0 page (`P10`) instead of
            // spanning UART0, SPI0, I2C0, I2C1, and PWM0 in a single 420 KiB capability.
            #[cfg(feature = "mmio-rp1-uart")]
            {
                const RP1_UART0_PHYS: u64 = 0x1F_0003_0000;
                const RP1_UART0_VIRT: u64 = 0xffff_b00a_0000_0000;
                if let Ok(va) = VirtAddr::new_page_aligned(RP1_UART0_VIRT)
                    && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(RP1_UART0_PHYS))
                    && vspace.map_4k(va, fr, mmio_flags, &mut info.untyped).is_ok()
                {
                    syscall::register_extra_mmio_mapping(
                        PhysAddr::new(RP1_UART0_PHYS),
                        RP1_UART0_VIRT,
                        0x1000,
                    );
                    syscall::register_init_mmio_cap(22, PhysAddr::new(RP1_UART0_PHYS), 0x1000);
                }
            }

            // BCM2712 MIP MSI-X (`0x10_0013_0000`), microSD SDHCI (`0x10_00ff_f000`),
            // RP1 dual xHCI USB 3.0 (`0x1f_0020_0000` / `0x1f_0030_0000`), and PCIe ECAM.
            const RPI5_MIP_PHYS: u64 = 0x10_0013_0000;
            const RPI5_MIP_VIRT: u64 = 0xffff_b00b_0000_0000;
            if let Ok(va) = VirtAddr::new_page_aligned(RPI5_MIP_VIRT)
                && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(RPI5_MIP_PHYS))
                && vspace.map_4k(va, fr, mmio_flags, &mut info.untyped).is_ok()
            {
                gic::init_bcm2712_mip(RPI5_MIP_VIRT);
            }

            #[cfg(feature = "mmio-sdhci")]
            {
                const RPI5_SDHCI_PHYS: u64 = 0x10_00ff_f000;
                const RPI5_SDHCI_VIRT: u64 = 0xffff_b00c_0000_0000;
                if let Ok(va) = VirtAddr::new_page_aligned(RPI5_SDHCI_VIRT)
                    && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(RPI5_SDHCI_PHYS))
                    && vspace.map_4k(va, fr, mmio_flags, &mut info.untyped).is_ok()
                {
                    syscall::register_extra_mmio_mapping(
                        PhysAddr::new(RPI5_SDHCI_PHYS),
                        RPI5_SDHCI_VIRT,
                        0x1000,
                    );
                    syscall::register_init_mmio_cap(23, PhysAddr::new(RPI5_SDHCI_PHYS), 0x1000);
                }
            }

            #[cfg(feature = "mmio-xhci")]
            for (slot, xhci_phys, xhci_virt) in [
                (24usize, 0x1f_0020_0000u64, 0xffff_b00d_0000_0000u64),
                (25usize, 0x1f_0030_0000u64, 0xffff_b00e_0000_0000u64),
            ] {
                let mut xhci_ok = true;
                for p in 0..4u64 {
                    let off = p * 4096;
                    let ok = VirtAddr::new_page_aligned(xhci_virt + off)
                        .and_then(|va| {
                            PhysFrame::from_aligned(PhysAddr::new(xhci_phys + off))
                                .and_then(|fr| vspace.map_4k(va, fr, mmio_flags, &mut info.untyped))
                        })
                        .is_ok();
                    if !ok {
                        xhci_ok = false;
                        break;
                    }
                }
                if xhci_ok {
                    syscall::register_extra_mmio_mapping(
                        PhysAddr::new(xhci_phys),
                        xhci_virt,
                        0x4000,
                    );
                    syscall::register_init_mmio_cap(slot, PhysAddr::new(xhci_phys), 0x4000);
                }
            }

            // PCIe ECAM and BCM2712 IOMMU are intentionally kept kernel-owned (`P4`):
            // never hand raw PCIe configuration space or IOMMU registers to EL0 `init`.
            // VideoCore VII V3D 7.1 (`0x10_0200_0000` Hub + `0x10_0200_8000` Core 0).
            #[cfg(feature = "mmio-v3d")]
            {
                const RPI5_V3D_PHYS: u64 = 0x10_0200_0000;
                const RPI5_V3D_LEN: u64 = 0x9000;
                const RPI5_V3D_VIRT: u64 = 0xffff_b010_0000_0000;
                let mut v3d_ok = true;
                for off in [0x0000u64, 0x8000u64] {
                    let ok = VirtAddr::new_page_aligned(RPI5_V3D_VIRT + off)
                        .and_then(|va| {
                            PhysFrame::from_aligned(PhysAddr::new(RPI5_V3D_PHYS + off))
                                .and_then(|fr| vspace.map_4k(va, fr, mmio_flags, &mut info.untyped))
                        })
                        .is_ok();
                    if ok {
                        syscall::register_extra_mmio_mapping(
                            PhysAddr::new(RPI5_V3D_PHYS + off),
                            RPI5_V3D_VIRT + off,
                            0x1000,
                        );
                    } else {
                        v3d_ok = false;
                    }
                }
                if v3d_ok {
                    syscall::register_init_mmio_cap(28, PhysAddr::new(RPI5_V3D_PHYS), RPI5_V3D_LEN);
                }
            }
        }

        // Map UEFI GOP / Limine linear framebuffer if present (capped at 4 MiB, slot 27).
        if let Some(fb) = info.framebuffer
            && fb.phys_addr != 0
            && (fb.phys_addr & 0xFFF) == 0
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
        {
            const FB_VIRT: u64 = 0xffff_b012_0000_0000;
            let raw_bytes = u64::from(fb.height).saturating_mul(u64::from(fb.pitch));
            let map_bytes = raw_bytes.min(4 * 1024 * 1024);
            let pages = map_bytes.div_ceil(4096);
            let mut mapped_pages = 0u64;
            for p in 0..pages {
                let off = p * 4096;
                let ok = VirtAddr::new_page_aligned(FB_VIRT + off)
                    .and_then(|va| {
                        PhysFrame::from_aligned(PhysAddr::new(fb.phys_addr + off))
                            .and_then(|fr| vspace.map_4k(va, fr, mmio_flags, &mut info.untyped))
                    })
                    .is_ok();
                if !ok {
                    break;
                }
                mapped_pages += 1;
            }
            if mapped_pages > 0 {
                let len = mapped_pages * 4096;
                syscall::register_extra_mmio_mapping(PhysAddr::new(fb.phys_addr), FB_VIRT, len);
                syscall::register_init_mmio_cap(27, PhysAddr::new(fb.phys_addr), len);
            }
        }
        #[cfg(feature = "smp")]
        let online_cpus = smp::bring_up_aps();
        #[cfg(not(feature = "smp"))]
        let online_cpus = 1usize;
        syscall::set_sys_info(online_cpus, info.interactive_shell);

        let mut serial = serial::Pl011::new();
        let _ = writeln!(
            serial,
            "[newos-hal] board={} ACPI/GIC: uart={:#x} gicd={:#x} gicc={:#x} (v{}, cpus={}) timer_irq={} psci={} ecam={:#x} ap_sgi_acks={}",
            board.name,
            uart_phys,
            gicd_phys,
            gicc_phys,
            acpi.gic_version,
            acpi.madt_cpus,
            virt_timer_irq,
            if use_smc { "SMC" } else { "HVC" },
            acpi.ecam_base.unwrap_or(0),
            smp::ap_sgi_ack_count(),
        );
        Self {
            board,
            serial,
            vspace,
            online_cpus,
        }
    }
}

impl Write for Aarch64Platform {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.serial.write_str(s)
    }
}

pub(super) fn next_aslr_entropy() -> u64 {
    let mut x =
        ENTROPY_STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed) ^ syscall::read_cntvct();
    // SplitMix64 finalizer for uniform ASLR slide distribution
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

impl HalPlatform for Aarch64Platform {
    type VSpace = paging::Aarch64VSpace;

    fn arch_name(&self) -> &'static str {
        self.board.arch
    }

    fn board_name(&self) -> &'static str {
        self.board.name
    }

    fn security_features(&self) -> CpuSecurityFeatures {
        CpuSecurityFeatures {
            pxn: true,
            uxn: true,
            pan: PAN_ENABLED.load(Ordering::Acquire),
            wx_enforced: true,
            ssbs: SSBS_ENABLED.load(Ordering::Acquire),
            csv2: CSV2_SUPPORTED.load(Ordering::Acquire),
            csv3: CSV3_SUPPORTED.load(Ordering::Acquire),
        }
    }

    fn cpu_isa_features(&self) -> u64 {
        cpu_isa_features()
    }

    fn current_cpu_id(&self) -> u32 {
        get_cpu_id() as u32
    }

    fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    fn trigger_breakpoint(&mut self) {
        // SAFETY: `install_vectors` installed a `brk #0` handler that advances `ELR_EL1 += 4`.
        unsafe {
            asm!("brk #0", options(nomem, nostack));
        }
    }

    fn breakpoint_count(&self) -> u64 {
        BREAKPOINT_COUNT.load(Ordering::Acquire)
    }

    fn arm_oneshot_timer(&mut self, ticks: u32) {
        let clamped = u64::from(ticks.max(1));
        // SAFETY: Program the real ARM Generic Virtual Timer (`CNTV_TVAL_EL0` / `CNTV_CTL_EL0`)
        // so the boot self-check verifies actual GICv2 PPI delivery (`H5`).
        unsafe {
            asm!(
                "msr cntv_tval_el0, {tval}",
                "msr cntv_ctl_el0, {ctl}",
                "isb",
                tval = in(reg) clamped,
                ctl = in(reg) 1u64, // ENABLE=1, IMASK=0
                options(nomem, nostack),
            );
        }
    }

    fn timer_count(&self) -> u64 {
        TIMER_COUNT.load(Ordering::Acquire)
    }

    fn enable_interrupts(&mut self) {
        // SAFETY: Unmasking EL1 IRQ bit (`daifclr #2`).
        unsafe {
            asm!("msr daifclr, #2", options(nomem, nostack));
        }
    }
    fn disable_interrupts(&mut self) {
        // SAFETY: Masking EL1 IRQ bit (`daifset #2`).
        unsafe {
            asm!("msr daifset, #2", options(nomem, nostack));
        }
    }
    fn wait_for_interrupt(&mut self) {
        // SAFETY: Low-power wait-for-interrupt instruction in EL1.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }

    fn random_u64(&mut self) -> u64 {
        let mut x = ENTROPY_STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            ^ syscall::read_cntvct();
        // SplitMix64 finalizer for uniform ASLR slide distribution
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    fn vspace_mut(&mut self) -> &mut Self::VSpace {
        &mut self.vspace
    }

    fn create_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self::VSpace, SysError> {
        self.vspace.new_user_vspace(untyped)
    }

    fn probe_mapped_u64(&self, virt: VirtAddr, pattern: u64) -> Result<u64, SysError> {
        paging::probe_mapped_u64(&self.vspace, virt, pattern)
    }

    fn register_domain(
        &mut self,
        role: DomainRole,
        entry: VirtAddr,
        user_sp: VirtAddr,
        user_shadow_sp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError> {
        syscall::register_domain(
            role,
            entry.raw(),
            user_sp.raw(),
            user_shadow_sp.raw(),
            vspace_root.raw(),
        )
    }

    fn register_boot_module(&mut self, role: DomainRole, elf_bytes: &'static [u8]) {
        syscall::register_boot_module(role, elf_bytes);
    }

    fn install_runtime_untyped(&mut self, untyped: UntypedInventory) {
        syscall::set_untyped_inventory(untyped);
    }

    fn start_userspace(&mut self) -> ! {
        let top = guarded_el1_stack_top(0);
        if top != 0 {
            extern "C" fn bsp_userspace_trampoline() -> ! {
                syscall::start_userspace()
            }
            // SAFETY: `top` is a 16-byte-aligned 32 KiB mapped stack with an unmapped 4 KiB
            // guard page beneath it, and `bsp_userspace_trampoline` never returns.
            unsafe { pivot_sp_and_jump(top, bsp_userspace_trampoline) }
        }
        syscall::start_userspace()
    }

    fn exit(&mut self, code: ShutdownStatus) -> ! {
        system_off(code)
    }
}
