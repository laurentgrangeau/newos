//! SMP secondary core (AP) bring-up on `aarch64` (Cortex-A76 / Raspberry Pi 5) via Limine MP.

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use limine::mp::MpInfo;

use crate::boot;

static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);

/// Boot all secondary ARM64 cores discovered by Limine and wait until they are online.
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

    target_online
}

unsafe extern "C" fn ap_entry(info: &MpInfo) -> ! {
    let cpu_id = info.extra_argument();
    super::set_cpu_id(cpu_id);
    super::install_vectors();
    assert_eq!(super::get_cpu_id(), cpu_id);

    ONLINE_CPUS.fetch_add(1, Ordering::AcqRel);

    loop {
        // SAFETY: Secondary ARM64 core parks in low-power WFI until woken by an SGI/IRQ.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}
