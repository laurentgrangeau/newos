//! Protection-domain teardown, RAII `VSpace` rollback guards, `VirtIO` DMA quiescing,
//! supervisor fresh-`VSpace` respawn, and lifecycle syscalls (`DomainRespawn`, `DomainDestroy`,
//! `DomainGetFaultInfo`).

#[cfg(feature = "userspace")]
use core::fmt::Write;
#[cfg(feature = "userspace")]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
#[cfg(feature = "userspace")]
use newos_abi::DomainRoleId;
use newos_abi::{CapId, RING_PEER_RESET_BIT, Rights, SysError};
use newos_kernel_core::DomainRole;
#[cfg(feature = "userspace")]
use newos_kernel_core::memory::{PAGE_SIZE, UntypedInventory};
use newos_kernel_core::memory::{PhysAddr, PhysFrame, VSpaceMapper};
#[cfg(feature = "userspace")]
use newos_kernel_core::{USER_PQ_STACK_PAGES, USER_STACK_PAGES};

#[cfg(not(feature = "userspace"))]
use super::arch_state::TrapFrame;
#[cfg(feature = "userspace")]
use super::arch_state::{FpState, TrapFrame, restore_fp_state, switch_ttbr0, write_tpidr_el0};
#[cfg(feature = "userspace")]
use super::bootstrap::{find_boot_module, register_domain, reset_shared_rings_for_role};
use super::domain::{DomainTable, ExecutionState, WaitState, wake_notif_waiter_locked};
use super::irq::cleanup_orphaned_irqs;
use super::{
    DOMAINS, FRAME_MAPPINGS, HHDM_OFFSET, IPC_STATE, IS_QEMU_VIRT, MAX_DOMAINS, NET_MMIO_LEN,
    NET_MMIO_VIRT, RNG_MMIO_LEN, RNG_MMIO_VIRT, RUNTIME_UNTYPED, current_cpu_idx, domain_asid,
};
use crate::arch::aarch64::paging::{self, ReclaimedFrameKind};
#[cfg(feature = "userspace")]
use crate::arch::aarch64::serial;
use crate::arch::aarch64::smp;

#[cfg(feature = "userspace")]
const MAX_SUPERVISOR_RESPAWNS: u64 = 5;
#[cfg(feature = "userspace")]
static SUPERVISOR_RESPAWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// RAII rollback guard for a freshly allocated user `VSpace` during ELF loading while
/// `untyped` is already borrowed. Reclaims all mapped user & page-table frames on drop
/// unless [`Self::commit`] is called.
#[cfg(feature = "userspace")]
struct ScopedVSpaceGuard<'a> {
    vspace: Option<paging::Aarch64VSpace>,
    untyped: &'a mut UntypedInventory,
}

#[cfg(feature = "userspace")]
impl<'a> ScopedVSpaceGuard<'a> {
    const fn new(vspace: paging::Aarch64VSpace, untyped: &'a mut UntypedInventory) -> Self {
        Self {
            vspace: Some(vspace),
            untyped,
        }
    }

    fn vspace_and_untyped(
        &mut self,
    ) -> Option<(&mut paging::Aarch64VSpace, &mut UntypedInventory)> {
        self.vspace.as_mut().map(|vs| (vs, &mut *self.untyped))
    }

    fn commit(mut self) -> Option<PhysAddr> {
        self.vspace.take().map(|vs| vs.root_phys())
    }
}

#[cfg(feature = "userspace")]
impl Drop for ScopedVSpaceGuard<'_> {
    fn drop(&mut self) {
        if let Some(mut vs) = self.vspace.take() {
            vs.reclaim_all_user_frames(|fr, _kind| {
                let _ = self.untyped.reclaim_frame(fr);
            });
        }
    }
}

/// RAII rollback guard for a fully loaded user `VSpace` across `register_domain` (when no
/// higher lock is held). Acquires `RUNTIME_UNTYPED` and reclaims all frames on drop unless
/// [`Self::commit`] is called.
#[cfg(feature = "userspace")]
struct OwnedVSpaceGuard {
    root_phys: Option<PhysAddr>,
    hhdm: u64,
}

#[cfg(feature = "userspace")]
impl OwnedVSpaceGuard {
    const fn new(root_phys: PhysAddr, hhdm: u64) -> Self {
        Self {
            root_phys: Some(root_phys),
            hhdm,
        }
    }

    fn commit(mut self) -> Option<PhysAddr> {
        self.root_phys.take()
    }
}

#[cfg(feature = "userspace")]
impl Drop for OwnedVSpaceGuard {
    fn drop(&mut self) {
        if let Some(root_phys) = self.root_phys.take() {
            let mut untyped = RUNTIME_UNTYPED.lock();
            let mut vs = paging::Aarch64VSpace::from_root_phys(root_phys.raw(), self.hhdm);
            vs.reclaim_all_user_frames(|fr, _kind| {
                let _ = untyped.reclaim_frame(fr);
            });
        }
    }
}

/// Quiesce `VirtIO`-MMIO DMA engines (`REG_STATUS = 0`) BEFORE reclaiming a dying driver
/// domain's physical frames so QEMU/hardware cannot DMA into freed page tables.
fn quiesce_virtio_dma(dying_role: DomainRole) {
    if !IS_QEMU_VIRT.load(Ordering::Acquire) {
        return;
    }
    if dying_role == DomainRole::Net {
        let net_virt = NET_MMIO_VIRT.load(Ordering::Acquire);
        let net_len = NET_MMIO_LEN.load(Ordering::Acquire);
        if net_virt != 0 && net_len >= 0x200 {
            let slots = (net_len / 0x200).min(32);
            for s in 0..slots {
                let base = net_virt + s * 0x200;
                // SAFETY: `NET_MMIO_VIRT..NET_MMIO_VIRT+NET_MMIO_LEN` is the kernel-mapped
                // VirtIO-MMIO window; resetting `REG_STATUS` (`0x70`) to 0 stops DMA.
                unsafe {
                    let magic = core::ptr::read_volatile(base as *const u32);
                    let dev_id = core::ptr::read_volatile((base + 0x008) as *const u32);
                    if magic == 0x7472_6976 && dev_id == 1 {
                        core::ptr::write_volatile((base + 0x070) as *mut u32, 0);
                    }
                }
            }
        }
    } else if dying_role == DomainRole::Key {
        let rng_virt = RNG_MMIO_VIRT.load(Ordering::Acquire);
        let rng_len = RNG_MMIO_LEN.load(Ordering::Acquire);
        if rng_virt != 0 && rng_len >= 0x100 {
            // SAFETY: `RNG_MMIO_VIRT` is the kernel-mapped VirtIO-RNG MMIO slot.
            unsafe {
                let magic = core::ptr::read_volatile(rng_virt as *const u32);
                let dev_id = core::ptr::read_volatile((rng_virt + 0x008) as *const u32);
                if magic == 0x7472_6976 && dev_id == 4 {
                    core::ptr::write_volatile((rng_virt + 0x070) as *mut u32, 0);
                }
            }
        }
    }
}

/// Tear down an exiting or fatally faulting non-root protection domain (`M4`):
/// wake any waiting reply caller, unmap & reclaim its tracked mappings, clear its `CSpace`,
/// and recycle its scheduler & domain slot. Caller MUST hold `DOMAINS` lock.
pub(super) fn teardown_domain_locked(table: &mut DomainTable, pd_id: usize) {
    let cpu = current_cpu_idx();
    table.set_wait_state(pd_id, WaitState::Runnable);
    let Some(dying) = table.domains.get_mut(pd_id).and_then(Option::take) else {
        return;
    };
    if let Some(client) = dying.reply_target
        && let Some(client_dom) = table.domains.get_mut(client).and_then(Option::as_mut)
        && matches!(client_dom.wait, WaitState::WaitingReply { .. })
    {
        client_dom.frame.x[0] = SysError::InvalidCapability as u64;
        client_dom.frame.x[1] = 0;
        client_dom.frame.x[2] = 0;
        table.set_wait_state(client, WaitState::Runnable);
        let _ = table.sched.wake_slot(client);
    }

    let ttbr0 = dying.ttbr0;
    let dying_role = dying.role;
    let asid = domain_asid(pd_id);
    if table.cpu_current[cpu] == Some(pd_id) {
        table.cpu_current[cpu] = None;
    }
    let _ = table.sched.exit_slot(pd_id);
    if pd_id == 0 {
        return;
    }

    table.sched.reclaim_slot(pd_id);
    // Lock order: DOMAINS (held) -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut ipc = IPC_STATE.lock();
    let mut untyped = RUNTIME_UNTYPED.lock();
    let mut mappings = FRAME_MAPPINGS.lock();
    // Clear any buffered `IpcCall` sent by this dying protection domain so endpoints never jam.
    ipc.clear_buffered_calls_from(pd_id);
    // Drain `FRAME_MAPPINGS` entries for `ttbr0` first so shared-frame checks stay accurate,
    // then walk the full EL0 page-table hierarchy (`L0[0..256]` -> `L1` -> `L2` -> `L3`) to
    // zero and reclaim every ELF, stack, shadow-stack, `MapPage`, and page-table frame.
    let mut batch = [None; 8];
    while mappings.drain_for_vspace(PhysAddr::new(ttbr0), &mut batch) > 0 {}
    quiesce_virtio_dma(dying_role);

    let mut vs = paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
    vs.reclaim_all_user_frames(|frame, kind| match kind {
        ReclaimedFrameKind::PageTable => {
            let _ = untyped.reclaim_frame(frame);
        }
        ReclaimedFrameKind::LeafRam => {
            let pa = frame.start_addr();
            if !ipc.has_live_frame_cap(pa)
                && !mappings.has_mapping_for_phys(pa)
                && !mappings.is_dma_pinned(pa)
            {
                let zeroer = paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                zeroer.zero_frame(&frame);
                mappings.clear_ever_written(pa);
                let _ = untyped.reclaim_frame(frame);
            }
        }
    });
    let _ = ipc.clear_domain_cspace(pd_id, |phys, can_reclaim| {
        if can_reclaim
            && !mappings.has_mapping_for_phys(phys)
            && !mappings.is_dma_pinned(phys)
            && let Ok(frame) = PhysFrame::from_aligned(phys)
        {
            let zeroer = paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
            zeroer.zero_frame(&frame);
            mappings.clear_ever_written(phys);
            let _ = untyped.reclaim_frame(frame);
        }
    });
    drop(mappings);
    drop(untyped);

    // Wake any peers blocked on endpoints/notifications that lost their server or last cap (`M19`).
    for other in 0..MAX_DOMAINS {
        let Some(other_dom) = table.domains[other].as_mut() else {
            continue;
        };
        let blocked_dead = match other_dom.wait {
            WaitState::WaitingReply { ep_id } => !ipc.has_live_endpoint_server(ep_id),
            WaitState::WaitingRecv { ep_id } => !ipc.has_live_endpoint_cap(ep_id),
            WaitState::WaitingNotif { notif_id, .. } => !ipc.has_live_notif_cap(notif_id),
            WaitState::Runnable | WaitState::Sleeping { .. } => false,
        };
        if blocked_dead {
            other_dom.frame.x[0] = SysError::InvalidCapability as u64;
            other_dom.frame.x[1] = 0;
            other_dom.frame.x[2] = 0;
            table.set_wait_state(other, WaitState::Runnable);
            let _ = table.sched.wake_slot(other);
        }
    }
    // If `ssh-pd` died (panic or hardware fault), immediately notify `key-pd` and `net-pd`
    // via `RING_PEER_RESET_BIT` so `key-pd` closes `BOOTSTRAP_AUTH_GATE_EP` fail-closed (`M13`).
    if dying_role == DomainRole::Ssh {
        let _ = ipc.notify_signal_id(4, RING_PEER_RESET_BIT);
        let _ = wake_notif_waiter_locked(table, &mut ipc, 4);
        let _ = ipc.notify_signal_id(2, RING_PEER_RESET_BIT);
        let _ = wake_notif_waiter_locked(table, &mut ipc, 2);
    }
    cleanup_orphaned_irqs(&ipc);
    paging::tlbi_asid(asid);
}

#[cfg(not(feature = "userspace"))]
pub(super) const fn respawn_supervisor_fresh_vspace(_frame: &mut TrapFrame) -> bool {
    false
}

/// Reload PD 0 (`supervisor-pd`) from its immutable boot ELF into a brand-new `TTBR0_EL1` `VSpace`
/// with fresh ASLR slides while preserving PD 0's `CSpace` (zero disruption to running child PDs),
/// reclaiming all frames of the old PD 0 `VSpace`, and signaling `SUPERVISOR_RESPAWNED_BIT`.
#[cfg(feature = "userspace")]
pub(super) fn respawn_supervisor_fresh_vspace(frame: &mut TrapFrame) -> bool {
    let prev = SUPERVISOR_RESPAWN_COUNT.fetch_add(1, Ordering::AcqRel);
    if prev >= MAX_SUPERVISOR_RESPAWNS {
        let mut s = serial::Pl011::new();
        let _ = writeln!(
            s,
            "[newos-hal] FATAL: supervisor-pd exceeded max fresh-VSpace respawns ({MAX_SUPERVISOR_RESPAWNS}); halting"
        );
        return false;
    }
    let Some(elf_bytes) = find_boot_module(DomainRole::Supervisor) else {
        return false;
    };
    let entropy = crate::arch::aarch64::next_aslr_entropy();
    let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
    let pie_base = 0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
    let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let loaded = (|| -> Result<_, SysError> {
        let mut untyped = RUNTIME_UNTYPED.lock();
        let root_vs = paging::Aarch64VSpace::from_current_ttbr1(hhdm);
        let vs = root_vs.new_user_vspace(&mut untyped)?;
        let mut guard = ScopedVSpaceGuard::new(vs, &mut untyped);
        let (vs_ref, untyped_ref) = guard
            .vspace_and_untyped()
            .ok_or(SysError::InvalidArgument)?;
        let (entry, user_sp, user_shadow_sp, _segs) = newos_kernel_core::load_elf64_into_vspace(
            vs_ref,
            elf_bytes,
            untyped_ref,
            pie_base,
            stack_slide,
            shadow_slide,
            USER_STACK_PAGES,
        )?;
        let new_root = guard.commit().ok_or(SysError::InvalidArgument)?;
        Ok((entry, user_sp, user_shadow_sp, new_root))
    })();
    let Ok((entry, user_sp, user_shadow_sp, new_root)) = loaded else {
        return false;
    };
    let new_ttbr0 = new_root.raw();
    let mut new_frame = TrapFrame::ZERO;
    new_frame.x[18] = user_shadow_sp.raw();
    new_frame.elr_el1 = entry.raw();
    new_frame.sp_el0 = user_sp.raw();
    new_frame.spsr_el1 = 0;

    // Switch TTBR0_EL1 to the new VSpace before zeroing & reclaiming the old VSpace.
    switch_ttbr0(new_ttbr0, 0);
    paging::tlbi_asid(1);
    restore_fp_state(&FpState::ZERO);
    write_tpidr_el0(0);

    {
        // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
        let mut table = DOMAINS.lock();
        let Some(sup) = table.domains[0].as_mut() else {
            return false;
        };
        let old_ttbr0 = sup.ttbr0;
        sup.ttbr0 = new_ttbr0;
        sup.fault_handler = None;
        sup.shadow_sp = user_shadow_sp.raw();
        sup.tpidr_el0 = 0;
        sup.fp = FpState::ZERO;
        sup.frame = new_frame;
        table.set_wait_state(0, WaitState::Runnable);

        let mut ipc = IPC_STATE.lock();
        let _ = ipc.bind_bootstrap_vspace(0, new_root);
        let _ = ipc.notify_signal_id(1, newos_abi::supervisor_notif::SUPERVISOR_RESPAWNED_BIT);

        let mut untyped = RUNTIME_UNTYPED.lock();
        let mut mappings = FRAME_MAPPINGS.lock();
        let mut batch = [None; 8];
        while mappings.drain_for_vspace(PhysAddr::new(old_ttbr0), &mut batch) > 0 {}
        let mut old_vs = paging::Aarch64VSpace::from_root_phys(old_ttbr0, hhdm);
        old_vs.reclaim_all_user_frames(|fr, kind| match kind {
            ReclaimedFrameKind::PageTable => {
                let _ = untyped.reclaim_frame(fr);
            }
            ReclaimedFrameKind::LeafRam => {
                let pa = fr.start_addr();
                if !ipc.has_live_frame_cap(pa)
                    && !mappings.has_mapping_for_phys(pa)
                    && !mappings.is_dma_pinned(pa)
                {
                    let zeroer = paging::Aarch64VSpace::from_root_phys(old_ttbr0, hhdm);
                    zeroer.zero_frame(&fr);
                    mappings.clear_ever_written(pa);
                    let _ = untyped.reclaim_frame(fr);
                }
            }
        });
    }

    *frame = new_frame;
    let mut s = serial::Pl011::new();
    let attempt = prev + 1;
    let _ = writeln!(
        s,
        "[newos-hal] respawned supervisor-pd (pd=0) into fresh TTBR0_EL1 (ttbr0={new_ttbr0:#018x}, attempt={attempt})"
    );
    true
}

#[cfg(not(feature = "userspace"))]
pub(super) const fn handle_domain_respawn(
    _cur_pd: usize,
    _a0: u64,
    _a1: u64,
) -> Result<u64, SysError> {
    Err(SysError::Unsupported)
}

#[cfg(feature = "userspace")]
pub(super) fn handle_domain_respawn(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let role_id = DomainRoleId::from_u64(a1).ok_or(SysError::InvalidArgument)?;
    if role_id == DomainRoleId::Supervisor {
        return Err(SysError::InvalidArgument);
    }
    let role = DomainRole::from_abi(role_id);
    let already_active = {
        let table = DOMAINS.lock();
        table
            .domains
            .iter()
            .take(table.count.min(MAX_DOMAINS))
            .flatten()
            .any(|d| d.role == role)
    };
    if already_active {
        return Err(SysError::SlotOccupied);
    }
    let elf_bytes = find_boot_module(role).ok_or(SysError::InvalidArgument)?;
    let entropy = crate::arch::aarch64::next_aslr_entropy();
    let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
    let pie_base = 0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
    let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
    let stack_pages = if matches!(role, DomainRole::Net | DomainRole::Key | DomainRole::Ssh) {
        USER_PQ_STACK_PAGES
    } else {
        USER_STACK_PAGES
    };
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let (entry, user_sp, user_shadow_sp, root_phys) = {
        let mut untyped = RUNTIME_UNTYPED.lock();
        let root_vs = paging::Aarch64VSpace::from_current_ttbr1(hhdm);
        let vs = root_vs.new_user_vspace(&mut untyped)?;
        let mut guard = ScopedVSpaceGuard::new(vs, &mut untyped);
        let (vs_ref, untyped_ref) = guard
            .vspace_and_untyped()
            .ok_or(SysError::InvalidArgument)?;
        let (entry, user_sp, user_shadow_sp, _segs) = newos_kernel_core::load_elf64_into_vspace(
            vs_ref,
            elf_bytes,
            untyped_ref,
            pie_base,
            stack_slide,
            shadow_slide,
            stack_pages,
        )?;
        let root = guard.commit().ok_or(SysError::InvalidArgument)?;
        (entry, user_sp, user_shadow_sp, root)
    };
    let owned_vs = OwnedVSpaceGuard::new(root_phys, hhdm);
    let new_pd = register_domain(
        role,
        entry.raw(),
        user_sp.raw(),
        user_shadow_sp.raw(),
        root_phys.raw(),
    )?;
    let _ = owned_vs.commit();
    paging::tlbi_asid(domain_asid(new_pd));
    reset_shared_rings_for_role(role);
    smp::wake_idle_aps();
    Ok(new_pd as u64)
}

#[allow(clippy::significant_drop_tightening)] // Lock hierarchy requires holding `DOMAINS` while validating under `IPC_STATE`.
pub(super) fn handle_domain_destroy(cur_pd: usize, a0: u64) -> Result<u64, SysError> {
    let mut table = DOMAINS.lock();
    let target_pd = IPC_STATE
        .lock()
        .validate_thread_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    if target_pd == 0 || target_pd >= MAX_DOMAINS || target_pd == cur_pd {
        return Err(SysError::InvalidArgument);
    }
    let Some(target_dom) = table.domains[target_pd].as_mut() else {
        return Err(SysError::InvalidArgument);
    };
    match target_dom.exec {
        ExecutionState::Running { cpu_id } | ExecutionState::PendingDestroy { cpu_id } => {
            // Mark `PendingDestroy` + block in scheduler, then SGI remote cores so
            // `irq_el0_dispatch` immediately deschedules `target_pd` off its core.
            target_dom.exec = ExecutionState::PendingDestroy { cpu_id };
            let _ = table.sched.block_slot(target_pd);
            drop(table);
            smp::wake_idle_aps();
            Err(SysError::WouldBlock)
        }
        ExecutionState::Detached | ExecutionState::ReadyToDestroy => {
            teardown_domain_locked(&mut table, target_pd);
            Ok(0)
        }
    }
}

#[allow(clippy::significant_drop_tightening)] // Lock hierarchy requires holding `DOMAINS` before `IPC_STATE`.
pub(super) fn handle_domain_get_fault_info(
    cur_pd: usize,
    a0: u64,
    a1: u64,
    ipc_badge_out: &mut u64,
) -> Result<u64, SysError> {
    let pd_id = usize::try_from(a1).map_err(|_| SysError::InvalidArgument)?;
    let mut table = DOMAINS.lock();
    IPC_STATE
        .lock()
        .validate_power_for(cur_pd, CapId::new(a0), Rights::READ)?;
    let rec = table
        .last_fault
        .get_mut(pd_id)
        .and_then(Option::take)
        .ok_or(SysError::InvalidArgument)?;
    let packed = ((rec.role.to_abi() as u64) << 56) | (rec.esr & 0x00FF_FFFF_FFFF_FFFF);
    *ipc_badge_out = rec.elr;
    Ok(packed)
}
