//! SMP secondary core (AP) bring-up via Limine Multi-Processing protocol.

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use limine::mp::MpInfo;

use super::{apic, gdt, idt, paging, percpu, syscall};
use crate::boot;

static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);

/// Boot all secondary CPUs (APs) discovered by Limine and wait until they are online.
///
/// Returns the total number of online CPUs (including BSP).
pub fn bring_up_aps() -> usize {
    let Some(mp) = boot::mp_response() else {
        return 1;
    };

    let bsp_lapic = mp.bsp_lapic_id;
    let mut target_online = 1usize;
    let mut next_cpu_id = 1usize;

    for cpu in mp.cpus() {
        if cpu.lapic_id == bsp_lapic {
            continue;
        }
        if next_cpu_id >= gdt::MAX_CPUS {
            break;
        }
        cpu.bootstrap(ap_entry, next_cpu_id as u64);
        next_cpu_id += 1;
        target_online += 1;
    }

    while ONLINE_CPUS.load(Ordering::Acquire) < target_online {
        core::hint::spin_loop();
    }

    target_online
}

unsafe extern "C" fn ap_entry(info: &MpInfo) -> ! {
    let cpu_id = info.extra_argument() as usize;

    gdt::init_cpu(cpu_id);
    idt::load_current();
    percpu::init_cpu(cpu_id, info.lapic_id);
    apic::init_ap();
    let _ = paging::enable_modern_cpu_features();
    syscall::init_ap();

    // Verify per-CPU `gs:[8]` resolves to this secondary core's exact logical ID.
    assert_eq!(percpu::current_cpu_id() as usize, cpu_id);

    ONLINE_CPUS.fetch_add(1, Ordering::AcqRel);

    loop {
        // SAFETY: Secondary core parks cleanly in Ring 0 until woken by an IPI/timer.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}
