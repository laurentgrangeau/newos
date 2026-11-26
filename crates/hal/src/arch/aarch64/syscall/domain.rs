//! Protection-domain state machine (`Option<ActiveDomain>`), scheduler context switching,
//! timer/notification wakeups, and BSP/AP EL0 entry points.

use core::fmt::Write;
use core::sync::atomic::Ordering;
use newos_abi::{NOTIFY_WAIT_TIMEOUT, ShutdownStatus, SysError};
use newos_kernel_core::DomainRole;
use newos_kernel_core::ipc::{KernelIpcState, MAX_ENDPOINTS};
use newos_kernel_core::sched::Scheduler;

use super::arch_state::{
    __newos_el0_enter_frame, FpState, TrapFrame, arm_virtual_timer, arm_virtual_timer_cval,
    disable_virtual_timer, enable_fp_simd, init_preempt_timer, mask_local_irqs, read_cntvct,
    read_tpidr_el0, restore_fp_state, save_fp_state, switch_ttbr0, wfi_unmask_cycle,
    write_tpidr_el0,
};
use super::{DOMAINS, MAX_CPUS, MAX_DOMAINS, TIMER_TICK_INTERVAL, current_cpu_idx};
use crate::arch::aarch64::{paging, serial, smp, system_off};

/// Blocking / scheduling wait state of an active protection domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitState {
    Runnable,
    WaitingReply {
        ep_id: u32,
    },
    WaitingRecv {
        ep_id: u32,
    },
    WaitingNotif {
        notif_id: u32,
        mask: u64,
        deadline_ticks: Option<u64>,
    },
    Sleeping {
        deadline_ticks: u64,
    },
}

impl WaitState {
    #[inline]
    pub(super) const fn deadline_ticks(self) -> Option<u64> {
        match self {
            Self::WaitingNotif { deadline_ticks, .. } => deadline_ticks,
            Self::Sleeping { deadline_ticks } => Some(deadline_ticks),
            Self::Runnable | Self::WaitingReply { .. } | Self::WaitingRecv { .. } => None,
        }
    }
}

/// CPU execution ownership state for an active protection domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutionState {
    /// Not currently executing on any CPU (ready or blocked).
    Detached,
    /// Currently executing in EL0 on logical CPU `cpu_id`.
    Running { cpu_id: usize },
    /// Marked for destruction while executing on `cpu_id`; will deschedule on next IRQ.
    PendingDestroy { cpu_id: usize },
    /// Descheduled after `PendingDestroy`; awaits teardown without being re-claimable.
    ReadyToDestroy,
}

/// Registered EL0 self-recovery fault handler entrypoint and stack pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FaultHandler {
    pub(super) pc: u64,
    pub(super) sp: u64,
}

/// Captured diagnostic record for an isolated non-root EL0 fault.
#[derive(Debug, Clone, Copy)]
pub(super) struct FaultRecord {
    pub(super) role: DomainRole,
    pub(super) esr: u64,
    pub(super) elr: u64,
}

/// Active EL0 protection domain slot (stored inside `Option<ActiveDomain>` so inactive
/// slots cannot carry stale wait/execution/TTBR0 state).
#[derive(Debug, Clone, Copy)]
pub(super) struct ActiveDomain {
    pub(super) role: DomainRole,
    pub(super) ttbr0: u64,
    pub(super) wait: WaitState,
    pub(super) exec: ExecutionState,
    /// Single-use implicit Reply capability minted on `IpcCall` rendezvous, consumed on `IpcReplyRecv`.
    pub(super) reply_target: Option<usize>,
    pub(super) fault_handler: Option<FaultHandler>,
    pub(super) shadow_sp: u64,
    pub(super) tpidr_el0: u64,
    pub(super) frame: TrapFrame,
    pub(super) fp: FpState,
}

pub(super) struct DomainTable {
    pub(super) domains: [Option<ActiveDomain>; MAX_DOMAINS],
    pub(super) sched: Scheduler<MAX_DOMAINS>,
    recv_waiters: [u8; MAX_ENDPOINTS],
    pub(super) last_fault: [Option<FaultRecord>; MAX_DOMAINS],
    pub(super) count: usize,
    pub(super) cpu_current: [Option<usize>; MAX_CPUS],
}

impl DomainTable {
    pub(super) const fn new() -> Self {
        Self {
            domains: [None; MAX_DOMAINS],
            sched: Scheduler::new(),
            recv_waiters: [0; MAX_ENDPOINTS],
            last_fault: [None; MAX_DOMAINS],
            count: 0,
            cpu_current: [None; MAX_CPUS],
        }
    }

    #[inline]
    pub(super) fn current_for_this_cpu(&self) -> Option<usize> {
        self.cpu_current[current_cpu_idx()]
    }

    #[inline]
    pub(super) fn has_any_active(&self) -> bool {
        self.domains.iter().any(Option::is_some)
    }

    #[inline]
    pub(super) fn active_count(&self) -> usize {
        self.domains.iter().filter(|d| d.is_some()).count()
    }

    #[inline]
    pub(super) fn set_wait_state(&mut self, pd_id: usize, new_state: WaitState) {
        let Some(dom) = self.domains.get_mut(pd_id).and_then(Option::as_mut) else {
            return;
        };
        let bit = 1u8 << pd_id;
        let old_state = dom.wait;
        if let WaitState::WaitingRecv { ep_id } = old_state
            && let Some(entry) = self.recv_waiters.get_mut(ep_id as usize)
        {
            *entry &= !bit;
        }
        dom.wait = new_state;
        if let WaitState::WaitingRecv { ep_id } = new_state
            && let Some(entry) = self.recv_waiters.get_mut(ep_id as usize)
        {
            *entry |= bit;
        }
        if new_state == WaitState::Runnable && old_state != WaitState::Runnable {
            smp::wake_idle_aps();
        }
    }

    /// Mint single-use Reply capability on `server` pointing exclusively to `client`,
    /// failing and waking any stranded previous caller (`H3`/`M19`).
    #[inline]
    pub(super) fn replace_reply_target(&mut self, server: usize, client: usize) {
        let prev = self
            .domains
            .get_mut(server)
            .and_then(Option::as_mut)
            .and_then(|s| s.reply_target.replace(client));
        if let Some(prev_client) = prev
            && prev_client != client
            && let Some(prev_dom) = self.domains.get_mut(prev_client).and_then(Option::as_mut)
            && matches!(prev_dom.wait, WaitState::WaitingReply { .. })
        {
            prev_dom.frame.x[0] = SysError::InvalidCapability as u64;
            prev_dom.frame.x[1] = 0;
            prev_dom.frame.x[2] = 0;
            self.set_wait_state(prev_client, WaitState::Runnable);
            let _ = self.sched.wake_slot(prev_client);
        }
    }

    /// Block `cur_pd` in the scheduler and either context-switch to another runnable domain
    /// (returning `true`) or save/detach `cur_pd` so the caller can drop `DOMAINS` and park
    /// this CPU via `park_cpu_until_runnable(frame)` (returning `false`).
    #[inline]
    pub(super) fn block_or_detach_current(&mut self, cur_pd: usize, frame: &mut TrapFrame) -> bool {
        let _ = self.sched.block_slot(cur_pd);
        if let Some(next) = self.pick_next_runnable(cur_pd) {
            context_switch(self, cur_pd, next, frame);
            return true;
        }
        let cpu = current_cpu_idx();
        if let Some(dom) = self.domains.get_mut(cur_pd).and_then(Option::as_mut) {
            dom.frame = *frame;
            save_fp_state(&mut dom.fp);
            dom.tpidr_el0 = read_tpidr_el0();
            dom.exec = ExecutionState::Detached;
        }
        self.cpu_current[cpu] = None;
        false
    }

    #[inline]
    pub(super) fn pick_next_runnable(&self, from: usize) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        // SMP-safe lookup: scan only genuinely `Ready` slots without demoting any
        // thread currently `Running` on another CPU.
        if let Some(next) = self.sched.pick_next_ready(from)
            && next != from
            && self.domains[next].is_some_and(|d| {
                d.wait == WaitState::Runnable && d.exec == ExecutionState::Detached
            })
        {
            return Some(next);
        }
        // Fallback linear scan in case a runnable slot was temporarily out of sync.
        for offset in 1..self.count {
            let next = (from + offset) % self.count;
            if next != from
                && self.domains[next].is_some_and(|d| {
                    d.wait == WaitState::Runnable && d.exec == ExecutionState::Detached
                })
            {
                return Some(next);
            }
        }
        None
    }

    #[inline]
    pub(super) fn claim_any_runnable(&mut self, cpu_id: usize) -> Option<usize> {
        for (pd_id, slot) in self.domains.iter_mut().enumerate() {
            if let Some(dom) = slot.as_mut()
                && dom.wait == WaitState::Runnable
                && dom.exec == ExecutionState::Detached
            {
                dom.exec = ExecutionState::Running { cpu_id };
                self.cpu_current[cpu_id] = Some(pd_id);
                self.sched.mark_running(pd_id);
                return Some(pd_id);
            }
        }
        None
    }

    #[inline]
    pub(super) fn has_other_running_cpu(&self, this_cpu: usize) -> bool {
        self.cpu_current
            .iter()
            .enumerate()
            .any(|(cpu, slot)| cpu != this_cpu && slot.is_some())
    }

    #[inline]
    pub(super) fn find_recv_waiter(&self, ep_id: u32, exclude: usize) -> Option<usize> {
        let ep = ep_id as usize;
        let mut mask = *self.recv_waiters.get(ep)?;
        if exclude < MAX_DOMAINS {
            mask &= !(1u8 << exclude);
        }
        (mask != 0).then_some(mask.trailing_zeros() as usize)
    }
}

/// Save `from`'s GPR + `TPIDR_EL0` + NEON/FP state and switch `TTBR0_EL1` + registers to `to`.
#[inline]
pub(super) fn context_switch(
    table: &mut DomainTable,
    from: usize,
    to: usize,
    frame: &mut TrapFrame,
) {
    let cpu = current_cpu_idx();
    if let Some(from_dom) = table.domains.get_mut(from).and_then(Option::as_mut) {
        from_dom.frame = *frame;
        from_dom.tpidr_el0 = read_tpidr_el0();
        save_fp_state(&mut from_dom.fp);
        from_dom.exec = ExecutionState::Detached;
        if from_dom.wait == WaitState::Runnable {
            table.sched.mark_ready(from);
        }
    }
    if let Some(to_dom) = table.domains.get_mut(to).and_then(Option::as_mut) {
        to_dom.exec = ExecutionState::Running { cpu_id: cpu };
        let to_ttbr0 = to_dom.ttbr0;
        let to_tpidr = to_dom.tpidr_el0;
        let to_fp = to_dom.fp;
        let to_frame = to_dom.frame;
        table.cpu_current[cpu] = Some(to);
        table.sched.mark_running(to);
        switch_ttbr0(to_ttbr0, to);
        write_tpidr_el0(to_tpidr);
        restore_fp_state(&to_fp);
        *frame = to_frame;
    }
}

/// Wake any `WaitingNotif` or `Sleeping` threads whose deadline has elapsed (`deadline <= now`).
/// Caller MUST hold `DOMAINS`.
pub(super) fn wake_expired_timers_locked(table: &mut DomainTable, now: u64) -> bool {
    let mut woke_any = false;
    let limit = table.count.min(MAX_DOMAINS);
    for pd_id in 0..limit {
        let Some(dom) = table.domains[pd_id].as_mut() else {
            continue;
        };
        let Some(deadline) = dom.wait.deadline_ticks() else {
            continue;
        };
        if now < deadline {
            continue;
        }
        match dom.wait {
            WaitState::WaitingNotif { .. } => {
                dom.frame.x[0] = 0;
                dom.frame.x[1] = 0;
                dom.frame.x[2] = NOTIFY_WAIT_TIMEOUT;
            }
            WaitState::Sleeping { .. } => {
                dom.frame.x[0] = 0;
                dom.frame.x[1] = 0;
                dom.frame.x[2] = 0;
            }
            WaitState::Runnable
            | WaitState::WaitingReply { .. }
            | WaitState::WaitingRecv { .. } => {
                continue;
            }
        }
        table.set_wait_state(pd_id, WaitState::Runnable);
        let _ = table.sched.wake_slot(pd_id);
        woke_any = true;
    }
    woke_any
}

/// If any thread is blocked in `WaitingNotif` on `notif_id` with a mask intersecting the pending
/// bits, consume the matched bits into its `TrapFrame` and wake it. Caller holds `DOMAINS -> IPC_STATE`.
pub(super) fn wake_notif_waiter_locked(
    table: &mut DomainTable,
    ipc: &mut KernelIpcState,
    notif_id: u32,
) -> bool {
    let limit = table.count.min(MAX_DOMAINS);
    for pd_id in 0..limit {
        let Some(dom) = table.domains[pd_id].as_mut() else {
            continue;
        };
        if let WaitState::WaitingNotif {
            notif_id: wait_id,
            mask,
            ..
        } = dom.wait
            && wait_id == notif_id
            && let Ok(matched) = ipc.notify_consume_mask(notif_id, mask)
            && matched != 0
        {
            dom.frame.x[0] = 0;
            dom.frame.x[1] = matched;
            dom.frame.x[2] = 0;
            table.set_wait_state(pd_id, WaitState::Runnable);
            let _ = table.sched.wake_slot(pd_id);
            return true;
        }
    }
    false
}

/// Park this CPU in low-power WFI until another runnable EL0 protection domain can be claimed (`P2`/`P9`).
/// Arms `CNTV_CVAL_EL0` with the earliest deadline across blocked threads before `wfi`
/// so all-idle timed `SleepUntil`/`NotifyWait` callers never deadlock.
pub(super) fn park_cpu_until_runnable(frame: &mut TrapFrame) {
    let this_cpu = current_cpu_idx();
    disable_virtual_timer();
    loop {
        // Mask IRQs before checking runnable state and entering `wfi` to close the lost-wakeup
        // window (`P9`): on AArch64, `wfi` wakes on any pending IRQ even when `PSTATE.I == 1`.
        mask_local_irqs();
        let earliest_deadline: Option<u64>;
        {
            let mut t = DOMAINS.lock();
            let _ = wake_expired_timers_locked(&mut t, read_cntvct());
            if let Some(next) = t.claim_any_runnable(this_cpu)
                && let Some(next_dom) = t.domains[next]
            {
                smp::set_ap_activity(this_cpu, smp::CoreActivity::Active);
                switch_ttbr0(next_dom.ttbr0, next);
                write_tpidr_el0(next_dom.tpidr_el0);
                restore_fp_state(&next_dom.fp);
                *frame = next_dom.frame;
                drop(t);
                let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
                arm_virtual_timer(interval);
                // Keep IRQs masked until `eret` atomically restores `SPSR_EL1` (`M5`).
                return;
            }
            let mut min_dl: Option<u64> = None;
            for dom in t.domains.iter().take(t.count.min(MAX_DOMAINS)).flatten() {
                if let Some(dl) = dom.wait.deadline_ticks() {
                    min_dl = Some(min_dl.map_or(dl, |cur| cur.min(dl)));
                }
            }
            earliest_deadline = min_dl;
            // Publish idle bit while still holding `DOMAINS` so no concurrent wakeup SGI is lost.
            smp::set_ap_activity(this_cpu, smp::CoreActivity::Idle);
        }
        if let Some(deadline) = earliest_deadline {
            arm_virtual_timer_cval(deadline);
        } else {
            disable_virtual_timer();
        }
        wfi_unmask_cycle();
    }
}

/// Enter EL0 userspace in Protection Domain 0 (`supervisor-pd`).
///
/// Loads PD 0's isolated `TTBR0_EL1`, signals secondary `Cortex-A76` cores to enter the
/// multi-core EL0 scheduler, and enters EL0 via full `TrapFrame` restore (scrubbing all
/// general registers so no kernel pointers leak to EL0).
pub fn start_userspace() -> ! {
    let (ttbr0, tpidr_el0, init_frame) = {
        let mut table = DOMAINS.lock();
        let Some(init_dom) = table.domains[0].as_mut() else {
            drop(table);
            let mut s = serial::UnlockedPl011;
            let _ = writeln!(
                s,
                "[newos-hal] FATAL: start_userspace called without active PD 0 (supervisor-pd)"
            );
            system_off(ShutdownStatus::Failed);
        };
        init_dom.exec = ExecutionState::Running { cpu_id: 0 };
        let state = (init_dom.ttbr0, init_dom.tpidr_el0, init_dom.frame);
        table.cpu_current[0] = Some(0);
        table.sched.mark_running(0);
        state
    };

    paging::ensure_ttbr0_asid_enabled();
    enable_fp_simd();
    switch_ttbr0(ttbr0, 0);
    write_tpidr_el0(tpidr_el0);
    restore_fp_state(&FpState::ZERO);
    init_preempt_timer();
    smp::signal_userspace_ready();

    // SAFETY: `init_frame` is a valid zero-scrubbed `TrapFrame` with EL0t `SPSR_EL1 = 0`,
    // valid `elr_el1`, `sp_el0`, and `x18` (SCS). `__newos_el0_enter_frame` restores all
    // registers `x0..x30` before `eret` without leaking kernel pointers.
    unsafe { __newos_el0_enter_frame(&raw const init_frame) }
}

/// Secondary `Cortex-A76` core (AP) EL0 scheduler entry.
///
/// Claims any runnable, unassigned EL0 protection domain from `DOMAINS` and enters EL0 via full
/// `TrapFrame` + `TPIDR_EL0` + FP/SIMD restore (`P3`), or parks in low-power `wfi` with
/// the virtual timer disabled (`P9`) until woken by a `GICv2` `SGI_RESCHEDULE` IPI.
pub fn ap_enter_scheduler() -> ! {
    let cpu_id = current_cpu_idx();
    paging::ensure_ttbr0_asid_enabled();
    enable_fp_simd();
    disable_virtual_timer();

    loop {
        // Mask IRQs before checking runnable state and entering `wfi` to close the lost-wakeup
        // window (`P9`): `wfi` still wakes on pending IRQs/SGIs when `PSTATE.I == 1`.
        mask_local_irqs();

        let claimed = {
            let mut table = DOMAINS.lock();
            if let Some(pd_id) = table.claim_any_runnable(cpu_id)
                && let Some(dom) = table.domains[pd_id]
            {
                smp::set_ap_activity(cpu_id, smp::CoreActivity::Active);
                Some((pd_id, dom.ttbr0, dom.tpidr_el0, dom.frame, dom.fp))
            } else {
                // Publish idle bit while still holding `DOMAINS` so no wakeup SGI is lost.
                smp::set_ap_activity(cpu_id, smp::CoreActivity::Idle);
                None
            }
        };

        if let Some((pd_id, ttbr0, tpidr_el0, saved_frame, fp)) = claimed {
            switch_ttbr0(ttbr0, pd_id);
            write_tpidr_el0(tpidr_el0);
            restore_fp_state(&fp);
            init_preempt_timer();
            // SAFETY: Secondary core holds exclusive `ExecutionState::Running { cpu_id }`
            // ownership of `pd_id` and restores the FULL saved `TrapFrame` (`x0..x30`, `sp_el0`,
            // `elr_el1`, `spsr_el1`) via `__newos_el0_enter_frame` (`P3`).
            unsafe { __newos_el0_enter_frame(&raw const saved_frame) }
        }

        wfi_unmask_cycle();
    }
}
