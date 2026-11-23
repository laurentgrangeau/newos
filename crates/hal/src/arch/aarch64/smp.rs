//! SMP secondary core (AP) bring-up on `aarch64` (Cortex-A76 / Raspberry Pi 5) via Limine MP,
//! per-core hardening (`PAN`/`SSBS`, `CPACR_EL1.FPEN`), GICv2 secondary CPU interface init,
//! and cross-core SGI IPI wakeup verification.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;

use crate::boot;

static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);
static AP_SGI_ACK_COUNT: AtomicU64 = AtomicU64::new(0);

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

    while ONLINE_CPUS.load(Ordering::Acquire) < target_online {
        core::hint::spin_loop();
    }

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

    target_online
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

    loop {
        // SAFETY: Secondary ARM64 core parks in low-power WFI until woken by an SGI/IRQ.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}
