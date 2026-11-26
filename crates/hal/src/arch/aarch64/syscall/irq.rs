//! Hardware IRQ binding table, orphaned-IRQ cleanup, timer expiry wakeup, and EL0 IRQ dispatch.

use core::sync::atomic::Ordering;
use newos_kernel_core::cspace::IrqController;
use newos_kernel_core::ipc::KernelIpcState;

use super::arch_state::{
    TrapFrame, arm_virtual_timer, clear_ttbr0, read_cntv_ctl, read_cntvct, read_tpidr_el0,
    restore_fp_state, save_fp_state, switch_ttbr0, write_tpidr_el0,
};
use super::domain::{
    ExecutionState, context_switch, park_cpu_until_runnable, wake_expired_timers_locked,
    wake_notif_waiter_locked,
};
use super::lock::IrqSpinLock;
use super::{
    CNTV_CTL_ISTATUS, DOMAINS, IPC_STATE, PREEMPT_PENDING, TIMER_TICK_INTERVAL, current_cpu_idx,
};
use crate::arch::aarch64::gic::{self, MipMask};
use crate::arch::aarch64::smp;

const MAX_GIC_IRQS: usize = 1024;
const MAX_MIP_VECTORS: usize = 64;
const MAX_IRQS: usize = MAX_GIC_IRQS + MAX_MIP_VECTORS;

#[derive(Debug, Clone, Copy)]
pub(super) struct IrqBinding {
    pub(super) notif_id: u32,
    pub(super) badge_bit: u8,
    pub(super) controller: IrqController,
    pub(super) irq: u16,
}

pub(super) static IRQ_TABLE: IrqSpinLock<[Option<IrqBinding>; MAX_IRQS]> =
    IrqSpinLock::new([None; MAX_IRQS]);

#[inline]
pub(super) const fn irq_table_index(irq: u16, controller: IrqController) -> Option<usize> {
    match controller {
        IrqController::Mip => {
            let v = irq as usize;
            if v < MAX_MIP_VECTORS {
                Some(MAX_GIC_IRQS + v)
            } else {
                None
            }
        }
        IrqController::GicSpi => {
            let id = irq as usize;
            if id >= 32 && id < 1020 {
                Some(id)
            } else {
                None
            }
        }
    }
}

/// Unbind and mask any `IRQ_TABLE` entries whose `IrqHandler` capability is no longer live.
/// Caller holds `IPC_STATE` (or invokes independently); `IRQ_TABLE` is a leaf lock.
pub(super) fn cleanup_orphaned_irqs(ipc: &KernelIpcState) {
    let mut table = IRQ_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some(binding) = *slot
            && !ipc.has_live_irq_cap(binding.irq, binding.controller)
        {
            *slot = None;
            match binding.controller {
                IrqController::Mip => {
                    if let Ok(vec) = u8::try_from(binding.irq) {
                        gic::set_mip_vector_masked(vec, MipMask::Masked);
                    }
                }
                IrqController::GicSpi => {
                    gic::disable_irq(u32::from(binding.irq));
                }
            }
        }
    }
}

/// Wake expired sleeping/timed-out threads from EL1 timer IRQ context and kick idle APs.
pub fn wake_expired_timers() {
    let woke = {
        let mut table = DOMAINS.lock();
        wake_expired_timers_locked(&mut table, read_cntvct())
    };
    if woke {
        smp::wake_idle_aps();
    }
}

/// Unified EL1/EL0 external SPI dispatch.
///
/// Masks the SPI at the GIC, copies any `IrqBinding` out of leaf lock `IRQ_TABLE` (dropping
/// `IRQ_TABLE` before acquiring `DOMAINS -> IPC_STATE`), signals the bound notification, and
/// wakes any matching `WaitingNotif` thread.
pub fn dispatch_peripheral_spi(irq_id: u32) {
    gic::disable_irq(irq_id);
    let binding = u16::try_from(irq_id)
        .ok()
        .and_then(|irq| irq_table_index(irq, IrqController::GicSpi))
        .and_then(|idx| IRQ_TABLE.lock()[idx]);
    let woke = {
        let mut table = DOMAINS.lock();
        let mut ipc = IPC_STATE.lock();
        // Unbound peripheral SPIs stay masked at the GIC and are dropped rather than
        // injecting spurious bits into notification 0 (shared with worker-pd).
        binding.is_some_and(|b| {
            let bit = 1u64 << (b.badge_bit & 63);
            let _ = ipc.notify_signal_id(b.notif_id, bit);
            wake_notif_waiter_locked(&mut table, &mut ipc, b.notif_id)
        })
    };
    if woke {
        smp::wake_idle_aps();
    }
}

/// Rust handler invoked by `__newos_irq_el0` on hardware IRQs (ARM Generic Timer preemption,
/// timed `SleepUntil`/`NotifyWait` wakeups, and peripheral SPIs delivered via `IrqBind`/`IrqAck`).
pub extern "C" fn irq_el0_dispatch(frame: &mut TrapFrame) {
    let iar = gic::acknowledge();
    let irq_id = iar.map(|v| v & 0x3FF);
    if (read_cntv_ctl() & CNTV_CTL_ISTATUS) != 0 {
        let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
        arm_virtual_timer(interval);

        let woke_idle = {
            let mut table = DOMAINS.lock();
            let woke = wake_expired_timers_locked(&mut table, read_cntvct());
            if let Some(cur) = table.current_for_this_cpu()
                && table.sched.on_timer_tick_for(cur)
            {
                if let Some(next) = table.pick_next_runnable(cur) {
                    context_switch(&mut table, cur, next, frame);
                    PREEMPT_PENDING.store(false, Ordering::Release);
                } else {
                    PREEMPT_PENDING.store(true, Ordering::Release);
                }
            }
            woke
        };
        if woke_idle {
            smp::wake_idle_aps();
        }
    } else if let Some(id) = irq_id
        && (32..1020).contains(&id)
    {
        dispatch_peripheral_spi(id);
    }
    if let Some(id) = iar {
        gic::end_of_interrupt(id);
    }
    // Cross-core SMP `DomainDestroy` handshake: if another core marked our currently running
    // domain `PendingDestroy`, immediately deschedule off this core so it can be torn down safely.
    let mut should_park = false;
    {
        let mut table = DOMAINS.lock();
        if let Some(cur) = table.current_for_this_cpu()
            && table.domains[cur]
                .is_some_and(|d| matches!(d.exec, ExecutionState::PendingDestroy { .. }))
        {
            let cpu = current_cpu_idx();
            if let Some(dom) = table.domains[cur].as_mut() {
                dom.frame = *frame;
                save_fp_state(&mut dom.fp);
                dom.tpidr_el0 = read_tpidr_el0();
                dom.exec = ExecutionState::ReadyToDestroy;
            }
            table.cpu_current[cpu] = None;
            if let Some(next) = table.pick_next_runnable(cur)
                && let Some(next_dom) = table.domains[next].as_mut()
            {
                next_dom.exec = ExecutionState::Running { cpu_id: cpu };
                let next_ttbr0 = next_dom.ttbr0;
                let next_fp = next_dom.fp;
                let next_tpidr = next_dom.tpidr_el0;
                let next_frame = next_dom.frame;
                table.cpu_current[cpu] = Some(next);
                switch_ttbr0(next_ttbr0, next);
                restore_fp_state(&next_fp);
                write_tpidr_el0(next_tpidr);
                *frame = next_frame;
            } else {
                clear_ttbr0();
                should_park = true;
            }
        }
    }
    if should_park {
        park_cpu_until_runnable(frame);
    }
}
