//! SMP secondary core (AP) bring-up on `aarch64` (Cortex-A76 / Raspberry Pi 5) via Limine MP,
//! per-core hardening (`PAN`/`SSBS`, `CPACR_EL1.FPEN`), GICv2 secondary CPU interface init,
//! and cross-core SGI IPI wakeup verification.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;

use crate::boot;

static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);
static AP_SGI_ACK_COUNT: AtomicU64 = AtomicU64::new(0);
static USERSPACE_READY: AtomicBool = AtomicBool::new(false);
static IDLE_AP_MASK: AtomicU8 = AtomicU8::new(0);

/// Signal all parked secondary Cortex-A76 cores that EL0 processes are ready to schedule,
/// waking them via GICv2 `SGI_RESCHEDULE`.
pub fn signal_userspace_ready() {
    USERSPACE_READY.store(true, Ordering::Release);
    let online = ONLINE_CPUS.load(Ordering::Acquire);
    if online > 1 {
        let mut mask = 0u8;
        for cpu in 1..online.min(8) {
            mask |= 1u8 << cpu;
        }
        if mask != 0 {
            super::gic::send_sgi(super::gic::SGI_RESCHEDULE, mask);
        }
    }
}

/// Record whether core `cpu_id` (`0..8`) is currently idle in `wfi`.
#[inline]
pub fn mark_ap_idle(cpu_id: usize, idle: bool) {
    if cpu_id < 8 {
        let bit = 1u8 << cpu_id;
        if idle {
            IDLE_AP_MASK.fetch_or(bit, Ordering::Release);
        } else {
            IDLE_AP_MASK.fetch_and(!bit, Ordering::Release);
        }
    }
}

/// Wake any idle secondary Cortex-A76 cores via GICv2 `SGI_RESCHEDULE` when work becomes runnable.
#[inline]
pub fn wake_idle_aps() {
    let mask = IDLE_AP_MASK.load(Ordering::Acquire);
    if mask != 0 {
        super::gic::send_sgi(super::gic::SGI_RESCHEDULE, mask);
    }
}

/// Called by the EL1 IRQ handler when a secondary core receives `SGI_RESCHEDULE`.
#[inline]
pub(super) fn record_ap_sgi_ack() {
    AP_SGI_ACK_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// Number of cross-core SGIs acknowledged by secondary cores.
#[inline]
pub fn ap_sgi_ack_count() -> u64 {
    AP_SGI_ACK_COUNT.load(Ordering::Acquire)
}

/// Boot all secondary ARM64 cores discovered by Limine, wait until they are online,
/// and broadcast a GICv2 `SGI_RESCHEDULE` IPI to verify cross-core interrupt delivery.
pub fn bring_up_aps() -> usize {
    let Some(mp) = boot::mp_response() else {
        return 1;
    };

    let bsp_mpidr = mp.bsp_mpidr;
    let mut target_online = 1usize;
    let mut next_cpu_id = 1u64;

    for cpu in mp.cpus() {
        if cpu.mpidr == bsp_mpidr {
            continue;
        }
        cpu.bootstrap(ap_entry, next_cpu_id);
        next_cpu_id += 1;
        target_online += 1;
    }

    // Bounded spin wait so a non-responsive secondary core cannot hang boot forever.
    for _ in 0..50_000_000u32 {
        if ONLINE_CPUS.load(Ordering::Acquire) >= target_online {
            break;
        }
        core::hint::spin_loop();
    }
    let actual_online = ONLINE_CPUS.load(Ordering::Acquire);

    // Verify cross-core GICv2 SGI delivery to all secondary cores (CPU mask bits 1..target_online).
    if target_online > 1 {
        let mut target_mask = 0u8;
        for cpu in 1..target_online.min(8) {
            target_mask |= 1u8 << cpu;
        }
        let expected = (target_online.min(8) - 1) as u64;
        super::gic::send_sgi(super::gic::SGI_RESCHEDULE, target_mask);
        for _ in 0..5_000_000u32 {
            if AP_SGI_ACK_COUNT.load(Ordering::Acquire) >= expected {
                break;
            }
            core::hint::spin_loop();
        }
    }

    actual_online
}

// SAFETY: Limine invokes this `extern "C"` AP entry point once per secondary core
// with a valid `&MpInfo` and a dedicated per-CPU stack.
unsafe extern "C" fn ap_entry(info: &MpInfo) -> ! {
    let cpu_id = info.extra_argument();
    super::set_cpu_id(cpu_id);
    super::probe_and_enable_cpu_hardening();
    super::syscall::enable_fp_simd();
    super::install_vectors();
    super::gic::init_secondary();
    assert_eq!(super::get_cpu_id(), cpu_id);

    // SAFETY: Unmasking EL1 IRQ bit (`daifclr #2`) on secondary core so GICv2 SGIs wake `wfi`.
    unsafe {
        asm!("msr daifclr, #2", options(nomem, nostack));
    }

    ONLINE_CPUS.fetch_add(1, Ordering::AcqRel);

    // Wait in low-power WFI until BSP finishes early boot and signals EL0 userspace ready.
    while !USERSPACE_READY.load(Ordering::Acquire) {
        // SAFETY: Secondary ARM64 core parks in low-power WFI until woken by an SGI/IRQ.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }

    // Enter multi-core EL0 scheduler on this secondary Cortex-A76 core.
    super::syscall::ap_enter_scheduler()
}
