//! Synchronous EL0 trap dispatch (`svc #0` syscalls and hardware EL0 fault isolation).

use core::fmt::Write;
use core::sync::atomic::Ordering;
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, IrqTriggerMode, ObjectType, Rights, ShutdownStatus, SysError,
    SyscallNumber,
};
use newos_kernel_core::cspace::IrqController;
use newos_kernel_core::memory::{PhysFrame, VSpaceMapper};

use super::arch_state::{
    FpState, TrapFrame, arm_virtual_timer, read_cntfrq, read_cntv_ctl, read_cntvct, read_cycles,
    read_esr_el1, read_far_el1, read_tpidr_el0, restore_fp_state, save_fp_state, spec_barrier,
};
use super::domain::{
    ExecutionState, FaultHandler, FaultRecord, WaitState, context_switch, park_cpu_until_runnable,
    wake_notif_waiter_locked,
};
use super::irq::{IRQ_TABLE, IrqBinding, cleanup_orphaned_irqs, irq_table_index};
use super::lifecycle::{
    handle_domain_destroy, handle_domain_get_fault_info, handle_domain_respawn,
    respawn_supervisor_fresh_vspace, teardown_domain_locked,
};
use super::mem_ops::{
    handle_debug_write, handle_dma_cache_op, handle_dma_map, handle_dma_unmap, handle_frame_map,
    handle_map_page, handle_mmio_map, handle_mmio_read32, handle_mmio_write32, handle_unmap_page,
    handle_virt_to_phys,
};
use super::{
    CNTV_CTL_ISTATUS, DOMAINS, FRAME_MAPPINGS, HHDM_OFFSET, IPC_STATE, MAX_DOMAINS,
    PREEMPT_PENDING, RUNTIME_UNTYPED, SYS_INFO_PACKED, SYSCALL_TICK_COUNTER, TIMER_TICK_INTERVAL,
    USER_ADDR_LIMIT, YIELD_COUNTER, current_cpu_idx,
};
use crate::arch::aarch64::{gic, paging, serial, smp, system_off};

/// Return `(err, val, badge)` across EL0 `svc #0` in `(x0, x1, x2)` — preserving full 64-bit badges.
#[inline]
const fn set_ipc_return(frame: &mut TrapFrame, payload: u64, badge: u64) {
    frame.x[0] = 0;
    frame.x[1] = payload;
    frame.x[2] = badge;
}

#[inline]
const fn parse_rights(raw: u64) -> Result<Rights, SysError> {
    if raw > u8::MAX as u64 {
        return Err(SysError::InvalidArgument);
    }
    #[allow(clippy::cast_possible_truncation)] // Verified `raw <= u8::MAX as u64` above.
    match Rights::from_bits(raw as u8) {
        Some(r) => Ok(r),
        None => Err(SysError::InvalidArgument),
    }
}

#[inline]
const fn parse_mint_rights_and_badge(a2: u64, a3: u64) -> Result<(Rights, Option<u64>), SysError> {
    let raw_rights = a2 & !CAP_MINT_SET_BADGE;
    let rights = match parse_rights(raw_rights) {
        Ok(r) => r,
        Err(e) => return Err(e),
    };
    let badge = if (a2 & CAP_MINT_SET_BADGE) != 0 {
        Some(a3)
    } else {
        None
    };
    Ok((rights, badge))
}

fn handle_el0_fault(frame: &mut TrapFrame, esr: u64, ec: u64) {
    let (cur_pd, fault_handler, rec_shadow_sp) = {
        let table = DOMAINS.lock();
        let Some(cur) = table.current_for_this_cpu() else {
            system_off(ShutdownStatus::Failed);
        };
        table
            .domains
            .get(cur)
            .and_then(|d| *d)
            .map_or((cur, None, 0), |dom| {
                (cur, dom.fault_handler, dom.shadow_sp)
            })
    };
    if let Some(handler) = fault_handler {
        let elr = frame.elr_el1;
        let mut s = serial::Pl011::new();
        let _ = writeln!(
            s,
            "[newos-hal] caught EL0 fault (EC={ec:#x}, ELR={elr:#018x}) -> kernel healthy, redirecting to EL0 supervisor"
        );
        // Signal fault notification in supervisor PD 0
        let _ = IPC_STATE
            .lock()
            .notify_signal_for(0, CapId::BOOTSTRAP_FAULT_NOTIF, 1u64 << 6);
        // Scrub all GPRs and NEON/FP registers, then restore clean Shadow Call Stack (`x18`).
        frame.x = [0; 31];
        frame.x[18] = rec_shadow_sp;
        restore_fp_state(&FpState::ZERO);
        frame.elr_el1 = handler.pc;
        frame.sp_el0 = handler.sp;
        frame.spsr_el1 = 0;
        return;
    }
    // Non-root EL0 fault without self-handler: record fault diagnostics, tear down ONLY the
    // faulting protection domain (reclaiming all frames), signal `1 << cur_pd` on PD 0's
    // `BOOTSTRAP_FAULT_NOTIF` (`notif_id = 1`), and wake PD 0 if blocked in `NotifyWait`.
    if cur_pd != 0 {
        let mut s = serial::Pl011::new();
        let far = read_far_el1();
        let elr = frame.elr_el1;
        let _ = writeln!(
            s,
            "[newos-hal] isolated EL0 fault (pd={cur_pd}, EC={ec:#x}, ELR={elr:#018x}, FAR={far:#018x}) -> notifying supervisor-pd"
        );
        let mut table = DOMAINS.lock();
        if let Some(dom) = table.domains[cur_pd] {
            table.last_fault[cur_pd] = Some(FaultRecord {
                role: dom.role,
                esr,
                elr: frame.elr_el1,
            });
        }
        teardown_domain_locked(&mut table, cur_pd);
        {
            let mut ipc = IPC_STATE.lock();
            let _ = ipc.notify_signal_id(1, 1u64 << (cur_pd & 63));
            let _ = wake_notif_waiter_locked(&mut table, &mut ipc, 1);
            if table.sched.ready_count() == 0 {
                ipc.drain_buffered_call_senders(|client| {
                    if let Some(client_dom) = table.domains.get_mut(client).and_then(Option::as_mut)
                        && matches!(client_dom.wait, WaitState::WaitingReply { .. })
                    {
                        client_dom.frame.x[0] = SysError::InvalidCapability as u64;
                        client_dom.frame.x[1] = 0;
                        client_dom.frame.x[2] = 0;
                        table.set_wait_state(client, WaitState::Runnable);
                        let _ = table.sched.wake_slot(client);
                    }
                });
            }
        }
        smp::wake_idle_aps();
        if let Some(next) = table.pick_next_runnable(cur_pd) {
            context_switch(&mut table, cur_pd, next, frame);
            return;
        }
        if table.has_any_active() {
            drop(table);
            park_cpu_until_runnable(frame);
            return;
        }
    }
    if cur_pd == 0 && respawn_supervisor_fresh_vspace(frame) {
        return;
    }
    let elr = frame.elr_el1;
    let mut s = serial::Pl011::new();
    let _ = writeln!(
        s,
        "[newos-hal] UNHANDLED EL0 FAULT EC={ec:#x} ELR={elr:#018x}"
    );
    system_off(ShutdownStatus::Failed);
}

fn handle_notify_signal(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let woke_idle = {
        // Lock order: DOMAINS -> IPC_STATE.
        let mut table = DOMAINS.lock();
        let mut ipc = IPC_STATE.lock();
        let (notif_id, effective) = ipc.resolve_notify_signal_for(cur_pd, CapId::new(a0), a1)?;
        let _ = ipc.notify_signal_id(notif_id, effective)?;
        wake_notif_waiter_locked(&mut table, &mut ipc, notif_id)
    };
    if woke_idle {
        smp::wake_idle_aps();
    }
    Ok(0)
}

fn handle_ipc_send(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let mut table = DOMAINS.lock();
    let mut ipc = IPC_STATE.lock();
    let (ep_id, badge) = ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    // Strictly wake only `WaitingRecv` servers — NEVER hijack `WaitingReply` callers.
    if let Some(peer) = table.find_recv_waiter(ep_id, cur_pd)
        && let Some(peer_dom) = table.domains[peer].as_mut()
    {
        set_ipc_return(&mut peer_dom.frame, a1, badge);
        table.set_wait_state(peer, WaitState::Runnable);
        let _ = table.sched.wake_slot(peer);
        return Ok(0);
    }
    ipc.ipc_send_resolved(ep_id, badge, a1, None).map(|()| 0)
}

/// Returns `None` if a context switch or CPU park occurred (caller returns immediately).
fn handle_ipc_call(
    cur_pd: usize,
    a0: u64,
    a1: u64,
    frame: &mut TrapFrame,
) -> Option<Result<u64, SysError>> {
    let mut table = DOMAINS.lock();
    let mut ipc = IPC_STATE.lock();
    let (ep_id, badge) = match ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::WRITE) {
        Ok(v) => v,
        Err(e) => return Some(Err(e)),
    };
    if let Some(server) = table.find_recv_waiter(ep_id, cur_pd)
        && let Some(server_dom) = table.domains[server].as_mut()
        && server_dom.exec == ExecutionState::Detached
    {
        drop(ipc);
        // Mint single-use Reply capability on `server` pointing exclusively to `cur_pd`,
        // failing and waking any stranded previous caller (`M19`).
        set_ipc_return(&mut server_dom.frame, a1, badge);
        table.set_wait_state(server, WaitState::Runnable);
        table.replace_reply_target(server, cur_pd);
        table.set_wait_state(cur_pd, WaitState::WaitingReply { ep_id });
        let _ = table.sched.block_slot(cur_pd);
        let _ = table.sched.wake_slot(server);
        context_switch(&mut table, cur_pd, server, frame);
        return None;
    }
    let this_cpu = current_cpu_idx();
    if table.sched.ready_count() == 0 && !table.has_other_running_cpu(this_cpu) {
        return Some(Err(SysError::WouldBlock));
    }
    if let Err(e) = ipc.ipc_send_resolved(ep_id, badge, a1, Some(cur_pd)) {
        return Some(Err(e));
    }
    table.set_wait_state(cur_pd, WaitState::WaitingReply { ep_id });
    let _ = table.sched.block_slot(cur_pd);
    if let Some(next) = table.pick_next_runnable(cur_pd) {
        drop(ipc);
        context_switch(&mut table, cur_pd, next, frame);
        return None;
    }
    if table.has_other_running_cpu(this_cpu) {
        // True SMP blocking IPC: park `cur_pd` in `WaitingReply` and release `DOMAINS`
        // so the peer running on another core can receive the buffered message and reply.
        if let Some(dom) = table.domains[cur_pd].as_mut() {
            dom.frame = *frame;
            dom.tpidr_el0 = read_tpidr_el0();
            save_fp_state(&mut dom.fp);
            dom.exec = ExecutionState::Detached;
        }
        table.cpu_current[this_cpu] = None;
        drop(ipc);
        drop(table);
        park_cpu_until_runnable(frame);
        return None;
    }
    // Roll back buffered message so no orphan remains in the endpoint.
    let _ = ipc.ipc_recv_resolved(ep_id);
    table.set_wait_state(cur_pd, WaitState::Runnable);
    let _ = table.sched.wake_slot(cur_pd);
    table.sched.mark_running(cur_pd);
    Some(Err(SysError::WouldBlock))
}

/// Returns `None` if a context switch occurred (caller returns immediately).
fn handle_ipc_reply_recv(
    cur_pd: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    frame: &mut TrapFrame,
    ipc_badge_out: &mut u64,
) -> Option<Result<u64, SysError>> {
    let mut table = DOMAINS.lock();
    let mut ipc = IPC_STATE.lock();
    // Server receive right (`Rights::READ`) governs `IpcReplyRecv`; replying consumes
    // the kernel-minted single-use `reply_target` capability rather than endpoint `WRITE`.
    let (ep_id, badge) = match ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::READ) {
        Ok(v) => v,
        Err(e) => return Some(Err(e)),
    };
    let mut fastpath_client = None;
    if a2 != 0 {
        let reply_client = table.domains[cur_pd]
            .as_mut()
            .and_then(|d| d.reply_target.take());
        if let Some(client) = reply_client
            && let Some(client_dom) = table.domains.get_mut(client).and_then(Option::as_mut)
            && matches!(client_dom.wait, WaitState::WaitingReply { .. })
        {
            set_ipc_return(&mut client_dom.frame, a1, badge);
            table.set_wait_state(client, WaitState::Runnable);
            let _ = table.sched.wake_slot(client);
            fastpath_client = Some(client);
        }
    }
    match ipc.ipc_recv_resolved(ep_id) {
        Ok((msg, sender_pid)) => {
            if let Some(caller) = sender_pid
                && table
                    .domains
                    .get(caller)
                    .and_then(|d| *d)
                    .is_some_and(|d| matches!(d.wait, WaitState::WaitingReply { .. }))
            {
                // Never silently overwrite an unanswered reply target (`H3`):
                // fail-and-wake any stranded previous caller first.
                table.replace_reply_target(cur_pd, caller);
            }
            *ipc_badge_out = msg.badge;
            Some(Ok(msg.payload))
        }
        Err(SysError::WouldBlock) => {
            if let Some(client) = fastpath_client
                && table.domains[client].is_some_and(|d| d.exec == ExecutionState::Detached)
            {
                drop(ipc);
                table.set_wait_state(cur_pd, WaitState::WaitingRecv { ep_id });
                let _ = table.sched.block_slot(cur_pd);
                context_switch(&mut table, cur_pd, client, frame);
                return None;
            }
            if table.sched.ready_count() > 0 {
                table.set_wait_state(cur_pd, WaitState::WaitingRecv { ep_id });
                let _ = table.sched.block_slot(cur_pd);
                if let Some(next) = table.pick_next_runnable(cur_pd) {
                    drop(ipc);
                    context_switch(&mut table, cur_pd, next, frame);
                    return None;
                }
                table.set_wait_state(cur_pd, WaitState::Runnable);
                let _ = table.sched.wake_slot(cur_pd);
                table.sched.mark_running(cur_pd);
            }
            Some(Err(SysError::WouldBlock))
        }
        Err(e) => Some(Err(e)),
    }
}

fn handle_cap_delete(cur_pd: usize, cur_ttbr0: u64, a0: u64) -> Result<u64, SysError> {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut ipc = IPC_STATE.lock();
    ipc.cap_delete_for_with_frame_reclaim_cb(cur_pd, CapId::new(a0), |phys, can_reclaim| {
        // Reclaim physical frame if this was the last Frame capability and no
        // virtual mappings remain (`M3`).
        if can_reclaim {
            let mut untyped = RUNTIME_UNTYPED.lock();
            let mappings = FRAME_MAPPINGS.lock();
            if !mappings.has_mapping_for_phys(phys)
                && let Ok(f) = PhysFrame::from_aligned(phys)
            {
                let vs = paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                vs.zero_frame(&f);
                let _ = untyped.reclaim_frame(f);
            }
        }
    })?;
    cleanup_orphaned_irqs(&ipc);
    Ok(0)
}

#[allow(clippy::significant_drop_tightening)] // Lock hierarchy requires holding `DOMAINS -> IPC_STATE`.
fn handle_cap_revoke(cur_pd: usize, cur_ttbr0: u64, a0: u64) -> Result<u64, SysError> {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
    let mut table = DOMAINS.lock();
    let mut ipc = IPC_STATE.lock();
    let revoked_count =
        ipc.cap_revoke_for_with_frame_reclaim_cb(cur_pd, CapId::new(a0), |phys, can_reclaim| {
            let mut reclaimed_frame = None;
            let mut mappings = [None; 8];
            loop {
                let n = FRAME_MAPPINGS.lock().drain_for_phys(phys, &mut mappings);
                if n == 0 {
                    break;
                }
                for m in mappings[..n].iter().flatten() {
                    let mut vs = paging::Aarch64VSpace::from_root_phys(m.vspace_root.raw(), hhdm);
                    if let Ok(f) = vs.unmap_4k(m.virt) {
                        reclaimed_frame = Some(f);
                    }
                }
            }
            if can_reclaim {
                // Lock order: IPC_STATE (held) -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
                let mut untyped = RUNTIME_UNTYPED.lock();
                let mappings_guard = FRAME_MAPPINGS.lock();
                if !mappings_guard.has_mapping_for_phys(phys) {
                    let vs = paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                    if let Some(f) = reclaimed_frame {
                        vs.zero_frame(&f);
                        let _ = untyped.reclaim_frame(f);
                    } else if let Ok(f) = PhysFrame::from_aligned(phys) {
                        vs.zero_frame(&f);
                        let _ = untyped.reclaim_frame(f);
                    }
                }
            }
        })?;
    // Wake any threads blocked on endpoints or notifications that no longer have any live capability (`M5`).
    for pd_id in 0..MAX_DOMAINS {
        let Some(dom) = table.domains[pd_id].as_mut() else {
            continue;
        };
        let blocked_gone = match dom.wait {
            WaitState::WaitingReply { ep_id } | WaitState::WaitingRecv { ep_id } => {
                !ipc.has_live_endpoint_cap(ep_id)
            }
            WaitState::WaitingNotif { notif_id, .. } => !ipc.has_live_notif_cap(notif_id),
            WaitState::Runnable | WaitState::Sleeping { .. } => false,
        };
        if blocked_gone {
            dom.frame.x[0] = SysError::InvalidCapability as u64;
            dom.frame.x[1] = 0;
            dom.frame.x[2] = 0;
            table.set_wait_state(pd_id, WaitState::Runnable);
            let _ = table.sched.wake_slot(pd_id);
        }
    }
    cleanup_orphaned_irqs(&ipc);
    Ok(revoked_count as u64)
}

fn handle_set_priority(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let new_prio = u8::try_from(a1).map_err(|_| SysError::InvalidArgument)?;
    let target_pd = IPC_STATE
        .lock()
        .validate_thread_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let mut table = DOMAINS.lock();
    if target_pd >= table.count {
        return Err(SysError::InvalidArgument);
    }
    if cur_pd != 0
        && table
            .sched
            .tcb(cur_pd)
            .is_none_or(|tcb| new_prio > tcb.priority)
    {
        // Prevent unprivileged priority escalation above caller's MCP ceiling.
        return Err(SysError::InsufficientRights);
    }
    table.sched.set_priority(target_pd, new_prio).map(|()| 0)
}

fn handle_untyped_retype(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> Result<u64, SysError> {
    let obj_type = ObjectType::from_u64(a1).ok_or(SysError::InvalidArgument)?;
    let dst_slot = usize::try_from(a2).map_err(|_| SysError::InvalidArgument)?;
    if obj_type == ObjectType::IrqHandler {
        #[allow(clippy::cast_possible_truncation)] // Masked to 16 bits (`a3 & 0xFFFF`).
        let irq = (a3 & 0xFFFF) as u16;
        let controller = if ((a3 >> 16) & 1) != 0 {
            IrqController::Mip
        } else {
            IrqController::GicSpi
        };
        return IPC_STATE
            .lock()
            .untyped_retype_irq_for(cur_pd, CapId::new(a0), dst_slot, irq, controller)
            .map(CapId::raw);
    }
    let mut ipc = IPC_STATE.lock();
    let mut untyped = RUNTIME_UNTYPED.lock();
    let new_cap =
        ipc.untyped_retype_for(cur_pd, CapId::new(a0), obj_type, dst_slot, &mut untyped)?;
    // Zero newly retyped Frame before exposing it to EL0.
    if obj_type == ObjectType::Frame
        && let Ok(phys) = ipc.validate_frame_for(cur_pd, new_cap, Rights::NONE)
        && let Ok(frame_obj) = PhysFrame::from_aligned(phys)
    {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        let vs = paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
        vs.zero_frame(&frame_obj);
    }
    Ok(new_cap.raw())
}

fn handle_irq_ack(cur_pd: usize, a0: u64) -> Result<u64, SysError> {
    let (irq, controller) =
        IPC_STATE
            .lock()
            .validate_irq_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    match controller {
        IrqController::Mip => {
            let vec = u8::try_from(irq).map_err(|_| SysError::InvalidArgument)?;
            gic::set_mip_vector_masked(vec, gic::MipMask::Unmasked);
        }
        IrqController::GicSpi => {
            gic::enable_irq(u32::from(irq));
        }
    }
    Ok(u64::from(irq))
}

fn handle_irq_bind(cur_pd: usize, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    let mode = IrqTriggerMode::from_u64(a3).ok_or(SysError::InvalidArgument)?;
    if a2 >= 64 {
        return Err(SysError::InvalidArgument);
    }
    #[allow(clippy::cast_possible_truncation)] // Verified `a2 < 64` above.
    let badge_bit = a2 as u8;
    // Lock order: IPC_STATE -> IRQ_TABLE (leaf).
    let ipc = IPC_STATE.lock();
    let (irq, controller) = ipc.validate_irq_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let notif_id = ipc.validate_notification_id_for(cur_pd, CapId::new(a1), Rights::WRITE)?;
    let idx = irq_table_index(irq, controller).ok_or(SysError::InvalidArgument)?;
    let mut irq_table = IRQ_TABLE.lock();
    if irq_table[idx].is_some() {
        return Err(SysError::SlotOccupied);
    }
    irq_table[idx] = Some(IrqBinding {
        notif_id,
        badge_bit,
        controller,
        irq,
    });
    match controller {
        IrqController::Mip => {
            let vec = u8::try_from(irq).map_err(|_| SysError::InvalidArgument)?;
            gic::set_mip_vector_masked(vec, gic::MipMask::Unmasked);
        }
        IrqController::GicSpi => {
            let trigger = if mode == IrqTriggerMode::EdgeRising {
                gic::TriggerMode::Edge
            } else {
                gic::TriggerMode::Level
            };
            gic::configure_spi(u32::from(irq), 0x01, trigger, 0x80);
            gic::enable_irq(u32::from(irq));
        }
    }
    Ok(0)
}

/// Returns `None` if the thread blocked (caller returns immediately).
fn handle_notify_wait(
    cur_pd: usize,
    a0: u64,
    mask: u64,
    timeout_ns: u64,
    frame: &mut TrapFrame,
) -> Option<Result<u64, SysError>> {
    if mask == 0 {
        return Some(Err(SysError::InvalidArgument));
    }
    // Step 1 (fastpath): validate and consume matching bits under `IPC_STATE`.
    let (notif_id, matched) = {
        let mut ipc = IPC_STATE.lock();
        let nid = match ipc.validate_notification_id_for(cur_pd, CapId::new(a0), Rights::READ) {
            Ok(id) => id,
            Err(e) => return Some(Err(e)),
        };
        match ipc.notify_consume_mask(nid, mask) {
            Ok(m) => (nid, m),
            Err(e) => return Some(Err(e)),
        }
    };
    if matched != 0 {
        return Some(Ok(matched));
    }
    let deadline_ticks = if timeout_ns > 0 {
        let freq = read_cntfrq().max(1);
        let ticks =
            u64::try_from(((u128::from(timeout_ns) * u128::from(freq)) / 1_000_000_000).max(1))
                .unwrap_or(u64::MAX);
        Some(read_cntvct().saturating_add(ticks))
    } else {
        None
    };
    // Step 2 (slowpath): acquire `DOMAINS -> IPC_STATE` in canonical order and
    // re-check to close the lost-wakeup window.
    let mut table = DOMAINS.lock();
    let recheck = {
        let mut ipc = IPC_STATE.lock();
        ipc.notify_consume_mask(notif_id, mask)
    };
    match recheck {
        Err(e) => Some(Err(e)),
        Ok(m) if m != 0 => Some(Ok(m)),
        Ok(_) => {
            table.set_wait_state(
                cur_pd,
                WaitState::WaitingNotif {
                    notif_id,
                    mask,
                    deadline_ticks,
                },
            );
            if !table.block_or_detach_current(cur_pd, frame) {
                drop(table);
                park_cpu_until_runnable(frame);
            }
            None
        }
    }
}

/// Returns `None` if the thread blocked (caller returns immediately).
fn handle_sleep_until(
    cur_pd: usize,
    deadline: u64,
    frame: &mut TrapFrame,
) -> Option<Result<u64, SysError>> {
    if read_cntvct() >= deadline {
        return Some(Ok(0));
    }
    let mut table = DOMAINS.lock();
    table.set_wait_state(
        cur_pd,
        WaitState::Sleeping {
            deadline_ticks: deadline,
        },
    );
    if !table.block_or_detach_current(cur_pd, frame) {
        drop(table);
        park_cpu_until_runnable(frame);
    }
    None
}

fn handle_thread_exit(cur_pd: usize, frame: &mut TrapFrame) {
    if cur_pd == 0 {
        if respawn_supervisor_fresh_vspace(frame) {
            return;
        }
        system_off(ShutdownStatus::Failed);
    }
    let mut table = DOMAINS.lock();
    teardown_domain_locked(&mut table, cur_pd);
    if let Some(next) = table.pick_next_runnable(cur_pd) {
        context_switch(&mut table, cur_pd, next, frame);
        return;
    }
    if table.has_any_active() {
        // Other protection domains are still running on other cores or blocked (`P2`/`M2`):
        // park this core in idle instead of powering off the machine!
        drop(table);
        park_cpu_until_runnable(frame);
        return;
    }
    drop(table);
    system_off(ShutdownStatus::Success);
}

fn maybe_preempt_on_syscall_exit(frame: &mut TrapFrame) {
    // Sample hardware-latched Virtual Timer status every 64 syscalls (avoiding unconditional
    // `isb` + `mrs cntvct_el0` + `AcqRel swap` on every non-switching syscall exit).
    let check_timer = SYSCALL_TICK_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .trailing_zeros()
        >= 6;
    let tick_elapsed = check_timer && (read_cntv_ctl() & CNTV_CTL_ISTATUS) != 0;
    let preempt_flag =
        PREEMPT_PENDING.load(Ordering::Relaxed) && PREEMPT_PENDING.swap(false, Ordering::AcqRel);
    if tick_elapsed || preempt_flag {
        if tick_elapsed {
            let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
            arm_virtual_timer(interval);
        }
        let mut table = DOMAINS.lock();
        if let Some(cur) = table.current_for_this_cpu() {
            let should_preempt = if tick_elapsed {
                table.sched.on_timer_tick_for(cur)
            } else {
                true
            };
            if should_preempt && let Some(next) = table.pick_next_runnable(cur) {
                context_switch(&mut table, cur, next, frame);
            }
        }
    }
}

fn handle_debug_write_syscall(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Result<u64, SysError> {
    // Drop `IPC_STATE` before `copy_from_user` and PL011 UART polling.
    let allowed = IPC_STATE
        .lock()
        .validate_console_for(cur_pd, CapId::new(a0), Rights::WRITE);
    allowed.and_then(|()| handle_debug_write(cur_ttbr0, a1, a2))
}

fn handle_debug_read_syscall(cur_pd: usize, a0: u64) -> Result<u64, SysError> {
    // Drop `IPC_STATE` before acquiring `PL011_LOCK`.
    let allowed = IPC_STATE
        .lock()
        .validate_console_for(cur_pd, CapId::new(a0), Rights::READ);
    allowed.and_then(|()| {
        serial::try_read_byte()
            .map(u64::from)
            .ok_or(SysError::WouldBlock)
    })
}

fn handle_exit_syscall(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    // Drop `IPC_STATE` before invoking PSCI `system_off`.
    let allowed = IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::WRITE);
    allowed.map(|()| {
        let code = match a1 {
            x if x == ShutdownStatus::Success as u64 => ShutdownStatus::Success,
            x if x == ShutdownStatus::Reboot as u64 => ShutdownStatus::Reboot,
            _ => ShutdownStatus::Failed,
        };
        system_off(code)
    })
}

fn handle_sys_info_syscall(cur_pd: usize, a0: u64) -> Result<u64, SysError> {
    // CRITICAL: Drop `IPC_STATE` before acquiring `DOMAINS` to preserve lock order
    // `DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS`.
    let allowed = IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
    allowed.map(|()| {
        let domain_count = DOMAINS.lock().active_count() as u64;
        let base = SYS_INFO_PACKED.load(Ordering::Acquire);
        base | ((domain_count & 0xFFFF) << 16)
    })
}

fn handle_mem_stats_syscall(
    cur_pd: usize,
    a0: u64,
    ipc_badge_out: &mut u64,
) -> Result<u64, SysError> {
    // Drop `IPC_STATE` before acquiring `RUNTIME_UNTYPED`.
    let allowed = IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
    allowed.map(|()| {
        let untyped = RUNTIME_UNTYPED.lock();
        *ipc_badge_out = untyped.reclaimed_count() as u64;
        untyped.remaining_frames()
    })
}

fn handle_cpu_features_syscall(cur_pd: usize, a0: u64) -> Result<u64, SysError> {
    let allowed = IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
    allowed.map(|()| crate::arch::aarch64::cpu_isa_features())
}

fn handle_yield_syscall(cur_pd: usize, frame: &mut TrapFrame) {
    let next_count = YIELD_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    frame.x[0] = 0;
    frame.x[1] = next_count;
    PREEMPT_PENDING.store(false, Ordering::Release);
    let mut table = DOMAINS.lock();
    if let Some(next) = table.pick_next_runnable(cur_pd) {
        context_switch(&mut table, cur_pd, next, frame);
    }
}

fn handle_set_fault_handler(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    if a0 == 0 || a0 >= USER_ADDR_LIMIT || a1 == 0 || a1 >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let mut table = DOMAINS.lock();
    if let Some(dom) = table.domains[cur_pd].as_mut() {
        dom.fault_handler = Some(FaultHandler { pc: a0, sp: a1 });
    }
    Ok(0)
}

fn handle_cap_mint(cur_pd: usize, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    let (rights, badge) = parse_mint_rights_and_badge(a2, a3)?;
    let slot = usize::try_from(a1).map_err(|_| SysError::InvalidArgument)?;
    IPC_STATE
        .lock()
        .cap_mint_for(cur_pd, CapId::new(a0), slot, rights, badge)
        .map(CapId::raw)
}

fn handle_cap_copy(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let slot = usize::try_from(a1).map_err(|_| SysError::InvalidArgument)?;
    IPC_STATE
        .lock()
        .cap_copy_for(cur_pd, CapId::new(a0), slot)
        .map(CapId::raw)
}

fn handle_cap_move(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let slot = usize::try_from(a1).map_err(|_| SysError::InvalidArgument)?;
    IPC_STATE
        .lock()
        .cap_move_for(cur_pd, CapId::new(a0), slot)
        .map(CapId::raw)
}

fn handle_cap_grant(cur_pd: usize, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    let (rights, badge) = parse_mint_rights_and_badge(a2, a3)?;
    let active_count = DOMAINS.lock().count;
    IPC_STATE
        .lock()
        .cap_grant_between_checked(
            cur_pd,
            CapId::new(a0),
            CapId::new(a1),
            rights,
            badge,
            active_count,
        )
        .map(CapId::raw)
}

/// Dispatch a validated `SyscallNumber`. Returns `None` when a context switch, CPU park,
/// or thread exit already updated `frame` and the caller must return immediately.
fn dispatch_syscall(
    syscall: SyscallNumber,
    cur_pd: usize,
    cur_ttbr0: u64,
    frame: &mut TrapFrame,
    ipc_badge_out: &mut u64,
) -> Option<Result<u64, SysError>> {
    let (a0, a1, a2, a3) = (frame.x[0], frame.x[1], frame.x[2], frame.x[3]);
    let res = match syscall {
        SyscallNumber::DebugWrite => handle_debug_write_syscall(cur_pd, cur_ttbr0, a0, a1, a2),
        SyscallNumber::Yield => {
            handle_yield_syscall(cur_pd, frame);
            return None;
        }
        SyscallNumber::Exit => handle_exit_syscall(cur_pd, a0, a1),
        SyscallNumber::NotifySignal => handle_notify_signal(cur_pd, a0, a1),
        SyscallNumber::NotifyPoll => IPC_STATE.lock().notify_poll_for(cur_pd, CapId::new(a0)),
        SyscallNumber::IpcSend => handle_ipc_send(cur_pd, a0, a1),
        SyscallNumber::IpcRecv => {
            IPC_STATE
                .lock()
                .ipc_recv_for(cur_pd, CapId::new(a0))
                .map(|msg| {
                    *ipc_badge_out = msg.badge;
                    msg.payload
                })
        }
        SyscallNumber::IpcCall => return handle_ipc_call(cur_pd, a0, a1, frame),
        SyscallNumber::IpcReplyRecv => {
            return handle_ipc_reply_recv(cur_pd, a0, a1, a2, frame, ipc_badge_out);
        }
        SyscallNumber::ReadCycles => Ok(read_cycles()),
        SyscallNumber::SetFaultHandler => handle_set_fault_handler(cur_pd, a0, a1),
        SyscallNumber::MmioRead32 => handle_mmio_read32(cur_pd, a0, a1),
        SyscallNumber::MmioWrite32 => handle_mmio_write32(cur_pd, a0, a1, a2),
        SyscallNumber::DebugRead => handle_debug_read_syscall(cur_pd, a0),
        SyscallNumber::SysInfo => handle_sys_info_syscall(cur_pd, a0),
        SyscallNumber::VirtToPhys => handle_virt_to_phys(cur_pd, cur_ttbr0, a0, a1),
        SyscallNumber::CapMint => handle_cap_mint(cur_pd, a0, a1, a2, a3),
        SyscallNumber::CapCopy => handle_cap_copy(cur_pd, a0, a1),
        SyscallNumber::CapMove => handle_cap_move(cur_pd, a0, a1),
        SyscallNumber::CapDelete => handle_cap_delete(cur_pd, cur_ttbr0, a0),
        SyscallNumber::CapRevoke => handle_cap_revoke(cur_pd, cur_ttbr0, a0),
        SyscallNumber::CapGrant => handle_cap_grant(cur_pd, a0, a1, a2, a3),
        SyscallNumber::SetPriority => handle_set_priority(cur_pd, a0, a1),
        SyscallNumber::MapPage => handle_map_page(cur_pd, cur_ttbr0, a0, a1, a2, parse_rights),
        SyscallNumber::UnmapPage => handle_unmap_page(cur_pd, cur_ttbr0, a0, a1),
        SyscallNumber::UntypedRetype => handle_untyped_retype(cur_pd, cur_ttbr0, a0, a1, a2, a3),
        SyscallNumber::FrameMap => {
            handle_frame_map(cur_pd, cur_ttbr0, a0, a1, a2, a3, parse_rights)
        }
        SyscallNumber::TimerFreq => Ok(read_cntfrq()),
        SyscallNumber::ThreadExit => {
            handle_thread_exit(cur_pd, frame);
            return None;
        }
        SyscallNumber::IrqAck => handle_irq_ack(cur_pd, a0),
        SyscallNumber::DmaCacheOp => handle_dma_cache_op(cur_pd, cur_ttbr0, a0, a1, a2, a3),
        SyscallNumber::CpuFeatures => handle_cpu_features_syscall(cur_pd, a0),
        SyscallNumber::NotifyWait => return handle_notify_wait(cur_pd, a0, a1, a2, frame),
        SyscallNumber::IrqBind => handle_irq_bind(cur_pd, a0, a1, a2, a3),
        SyscallNumber::SleepUntil => return handle_sleep_until(cur_pd, a0, frame),
        SyscallNumber::MmioMap => handle_mmio_map(cur_pd, cur_ttbr0, a0, a1, a2),
        SyscallNumber::DomainRespawn => handle_domain_respawn(cur_pd, a0, a1),
        SyscallNumber::DomainDestroy => handle_domain_destroy(cur_pd, a0),
        SyscallNumber::DomainGetFaultInfo => {
            handle_domain_get_fault_info(cur_pd, a0, a1, ipc_badge_out)
        }
        SyscallNumber::MemStats => handle_mem_stats_syscall(cur_pd, a0, ipc_badge_out),
        SyscallNumber::DmaMap => handle_dma_map(cur_pd, cur_ttbr0, a0, a1, a2, a3),
        SyscallNumber::DmaUnmap => handle_dma_unmap(cur_pd, a0, a1),
    };
    Some(res)
}

/// Rust handler invoked by `__newos_sync_el0` on any synchronous trap from EL0 (`svc #0` or fault).
pub extern "C" fn sync_el0_dispatch(frame: &mut TrapFrame) {
    let esr = read_esr_el1();
    let ec = (esr >> 26) & 0x3F;
    if ec != 0x15 {
        handle_el0_fault(frame, esr, ec);
        return;
    }

    // `svc #0` syscall from EL0: x8 = num, x0..x3 = args, return (err, val) in (x0, x1)
    let Some(syscall) = SyscallNumber::from_u64(frame.x[8]) else {
        frame.x[0] = SysError::Unsupported as u64;
        frame.x[1] = 0;
        return;
    };
    spec_barrier();

    let Some((cur_pd, cur_ttbr0)) = ({
        let table = DOMAINS.lock();
        table.current_for_this_cpu().and_then(|cur| {
            table
                .domains
                .get(cur)
                .and_then(|d| *d)
                .map(|d| (cur, d.ttbr0))
        })
    }) else {
        // Fail closed if no active protection domain is recorded for this CPU.
        frame.x[0] = SysError::InvalidArgument as u64;
        frame.x[1] = 0;
        frame.x[2] = 0;
        return;
    };

    let mut ipc_badge_out: u64 = 0;
    let Some(result) = dispatch_syscall(syscall, cur_pd, cur_ttbr0, frame, &mut ipc_badge_out)
    else {
        return;
    };

    match result {
        Ok(val) => {
            frame.x[0] = 0;
            frame.x[1] = val;
            frame.x[2] = ipc_badge_out;
        }
        Err(e) => {
            frame.x[0] = e as u64;
            frame.x[1] = 0;
            frame.x[2] = 0;
        }
    }

    maybe_preempt_on_syscall_exit(frame);
}
