//! Bootstrap capability provisioning, MMIO address translation, boot-module ELF registry,
//! shared-memory ring allocation, and protection-domain registration.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "userspace")]
use newos_abi::RING_PEER_RESET_BIT;
use newos_abi::{CapId, SysError};
use newos_kernel_core::DomainRole;
use newos_kernel_core::ipc::{KernelIpcState, KeyPdVSpaceAccess};
#[cfg(feature = "userspace")]
use newos_kernel_core::memory::PhysFrame;
use newos_kernel_core::memory::{PhysAddr, UntypedInventory, VSpaceMapper};
use newos_kernel_core::sched::DEFAULT_PRIORITY;

use super::arch_state::{FpState, TrapFrame};
#[cfg(feature = "userspace")]
use super::domain::wake_notif_waiter_locked;
use super::domain::{ActiveDomain, ExecutionState, WaitState};
use super::lock::IrqSpinLock;
use super::{
    DOMAINS, HHDM_OFFSET, IPC_STATE, IS_QEMU_VIRT, MAX_DOMAINS, NET_MMIO_LEN, NET_MMIO_PHYS,
    NET_MMIO_VIRT, RNG_MMIO_LEN, RNG_MMIO_PHYS, RNG_MMIO_VIRT, RUNTIME_UNTYPED, SYS_INFO_PACKED,
    WDT_MMIO_LEN, WDT_MMIO_PHYS, WDT_MMIO_VIRT,
};
use crate::arch::aarch64::paging;

#[derive(Debug, Clone, Copy)]
struct ExtraMmioEntry {
    phys: u64,
    virt: u64,
    len: u64,
}

struct ExtraMmioTable<const N: usize> {
    entries: [ExtraMmioEntry; N],
    count: usize,
}

impl<const N: usize> ExtraMmioTable<N> {
    const fn new() -> Self {
        Self {
            entries: [ExtraMmioEntry {
                phys: 0,
                virt: 0,
                len: 0,
            }; N],
            count: 0,
        }
    }

    const fn push(&mut self, phys: u64, virt: u64, len: u64) {
        if self.count < N && len > 0 {
            self.entries[self.count] = ExtraMmioEntry { phys, virt, len };
            self.count += 1;
        }
    }

    fn translate(&self, phys: u64) -> Option<u64> {
        for e in &self.entries[..self.count] {
            if phys >= e.phys && phys < e.phys.saturating_add(e.len) {
                return Some(e.virt + (phys - e.phys));
            }
        }
        None
    }
}

static EXTRA_MMIO_MAPS: IrqSpinLock<ExtraMmioTable<32>> = IrqSpinLock::new(ExtraMmioTable::new());

#[derive(Debug, Clone, Copy)]
struct BoardIrqs {
    net: Option<crate::board::IrqLine>,
    rng: Option<crate::board::IrqLine>,
    uart: Option<crate::board::IrqLine>,
}

static BOARD_IRQS: IrqSpinLock<BoardIrqs> = IrqSpinLock::new(BoardIrqs {
    net: None,
    rng: None,
    uart: None,
});

/// Immutable `Limine` boot-module ELF64 slice retained for `DomainRespawn`.
#[derive(Debug, Clone, Copy)]
struct BootModuleSlice {
    role: DomainRole,
    #[cfg(feature = "userspace")]
    bytes: &'static [u8],
}

static BOOT_MODULES: IrqSpinLock<[Option<BootModuleSlice>; MAX_DOMAINS]> =
    IrqSpinLock::new([None; MAX_DOMAINS]);

/// Persistent 4 KiB physical addresses for inter-domain shared-memory `SpscRing` frames.
static NET_SSH_RING_PHYS: AtomicU64 = AtomicU64::new(0);
static SSH_KEY_RING_PHYS: AtomicU64 = AtomicU64::new(0);
static NET_DMA_RING_PHYS: AtomicU64 = AtomicU64::new(0);
/// Whether `newos-net-pd` is loaded in this boot image (controls `BOOTSTRAP_NET_EP` provisioning).
static NET_PD_PRESENT: AtomicBool = AtomicBool::new(false);

/// Initialize syscall globals and PD 0 (`supervisor-pd`) bootstrap capabilities.
pub fn init(
    hhdm_offset: u64,
    net_mmio: Option<(PhysAddr, u64, u64)>,
    rng_mmio: Option<(PhysAddr, u64, u64)>,
    wdt_mmio: Option<(PhysAddr, u64, u64)>,
    qemu_virt: bool,
    net_pd_present: bool,
) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Release);
    IS_QEMU_VIRT.store(qemu_virt, Ordering::Release);
    let cap_region = net_mmio.map(|(phys, virt, len)| {
        NET_MMIO_PHYS.store(phys.raw(), Ordering::Release);
        NET_MMIO_VIRT.store(virt, Ordering::Release);
        NET_MMIO_LEN.store(len, Ordering::Release);
        (phys, len)
    });
    if let Some((phys, virt, len)) = rng_mmio {
        RNG_MMIO_PHYS.store(phys.raw(), Ordering::Release);
        RNG_MMIO_VIRT.store(virt, Ordering::Release);
        RNG_MMIO_LEN.store(len, Ordering::Release);
    }
    if let Some((phys, virt, len)) = wdt_mmio {
        WDT_MMIO_PHYS.store(phys.raw(), Ordering::Release);
        WDT_MMIO_VIRT.store(virt, Ordering::Release);
        WDT_MMIO_LEN.store(len, Ordering::Release);
    }
    // When `newos-net-pd` (PD 2) is loaded, omit `BOOTSTRAP_NET_MMIO` from `supervisor-pd` (PD 0)
    // so `net-pd` is the sole holder of NIC DMA authority. Conversely, when `newos-net-pd` is
    // absent, omit `BOOTSTRAP_NET_EP` from PD 0 so shell `net` commands never block on an
    // unserved endpoint.
    NET_PD_PRESENT.store(net_pd_present, Ordering::Release);
    let init_net_cap = if net_pd_present { None } else { cap_region };
    let mut ipc = IPC_STATE.lock();
    let _ = ipc.init_bootstrap_caps(init_net_cap);
    if !net_pd_present {
        let _ = ipc.cap_delete_for(0, CapId::BOOTSTRAP_NET_EP);
    }
    if let Some((phys, _, len)) = wdt_mmio {
        let _ = ipc.register_wdt_mmio_cap(phys, len);
    }
}

/// Record a verified Device-nGnRnE physical->virtual MMIO mapping for capability-gated EL0 access.
pub fn register_extra_mmio_mapping(phys: PhysAddr, virt: u64, len: u64) {
    EXTRA_MMIO_MAPS.lock().push(phys.raw(), virt, len);
}

/// Grant a capability-scoped `MmioRegion` (`R|W`) at `slot` in `init` (PD 0)'s `CSpace`.
pub fn register_init_mmio_cap(slot: usize, phys: PhysAddr, len: u64) {
    let _ = IPC_STATE
        .lock()
        .register_bootstrap_mmio_cap(slot, phys, len);
}

/// Record online CPU count and interactive shell flag for [`newos_abi::SyscallNumber::SysInfo`].
pub fn set_sys_info(online_cpus: usize, interactive_shell: bool) {
    let packed = (u64::from(interactive_shell) << 32) | (online_cpus as u64 & 0xFFFF);
    SYS_INFO_PACKED.store(packed, Ordering::Release);
}

/// Record an immutable boot-module ELF64 slice for runtime `DomainRespawn` supervision.
pub fn register_boot_module(role: DomainRole, elf_bytes: &'static [u8]) {
    #[cfg(not(feature = "userspace"))]
    let _ = elf_bytes;
    let mut mods = BOOT_MODULES.lock();
    for slot in mods.iter_mut() {
        if slot.is_some_and(|m| m.role == role) {
            *slot = Some(BootModuleSlice {
                role,
                #[cfg(feature = "userspace")]
                bytes: elf_bytes,
            });
            return;
        }
    }
    for slot in mods.iter_mut() {
        if slot.is_none() {
            *slot = Some(BootModuleSlice {
                role,
                #[cfg(feature = "userspace")]
                bytes: elf_bytes,
            });
            return;
        }
    }
}

#[cfg(feature = "userspace")]
pub(super) fn find_boot_module(role: DomainRole) -> Option<&'static [u8]> {
    let mods = BOOT_MODULES.lock();
    mods.iter()
        .flatten()
        .find(|m| m.role == role && !m.bytes.is_empty())
        .map(|m| m.bytes)
}

/// Register board-discovered hardware IRQ lines for bootstrap `IrqHandler` provisioning.
pub fn register_board_irqs(
    net: Option<crate::board::IrqLine>,
    rng: Option<crate::board::IrqLine>,
    uart: Option<crate::board::IrqLine>,
) {
    let mut b = BOARD_IRQS.lock();
    b.net = net;
    b.rng = rng;
    b.uart = uart;
}

/// Install remaining bootstrap `UntypedInventory` for runtime `MapPage`/`UnmapPage` syscalls,
/// binding PD 0's `BOOTSTRAP_UNTYPED` cap to the largest usable physical memory region.
pub fn set_untyped_inventory(untyped: UntypedInventory) {
    if let Some(largest) = untyped.largest_region_index()
        && let Ok(region_idx) = u16::try_from(largest)
    {
        let _ = IPC_STATE.lock().bind_bootstrap_untyped_region(region_idx);
    }
    *RUNTIME_UNTYPED.lock() = untyped;
}

#[inline]
pub(super) fn mmio_phys_to_virt(phys: u64) -> Option<u64> {
    for (p_atom, v_atom, l_atom) in [
        (&NET_MMIO_PHYS, &NET_MMIO_VIRT, &NET_MMIO_LEN),
        (&RNG_MMIO_PHYS, &RNG_MMIO_VIRT, &RNG_MMIO_LEN),
        (&WDT_MMIO_PHYS, &WDT_MMIO_VIRT, &WDT_MMIO_LEN),
    ] {
        let base_phys = p_atom.load(Ordering::Acquire);
        let base_virt = v_atom.load(Ordering::Acquire);
        let len = l_atom.load(Ordering::Acquire);
        if len > 0 && phys >= base_phys && phys < base_phys.saturating_add(len) {
            return Some(base_virt + (phys - base_phys));
        }
    }
    // Never fall back to cacheable HHDM for Device MMIO (`H-5`).
    EXTRA_MMIO_MAPS.lock().translate(phys)
}

/// Lazily allocate (and zero) a persistent shared-memory ring `Frame` from `RUNTIME_UNTYPED`.
fn ensure_shared_ring_frame(slot: &AtomicU64) -> Option<PhysAddr> {
    let cur = slot.load(Ordering::Acquire);
    if cur != 0 {
        return Some(PhysAddr::new(cur));
    }
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut untyped = RUNTIME_UNTYPED.lock();
    let cur = slot.load(Ordering::Acquire);
    if cur != 0 {
        return Some(PhysAddr::new(cur));
    }
    let frame = untyped.retype_frame().ok()?;
    let vs = paging::Aarch64VSpace::from_current_ttbr1(hhdm);
    vs.zero_frame(&frame);
    let pa = frame.start_addr().raw();
    slot.store(pa, Ordering::Release);
    Some(PhysAddr::new(pa))
}

/// Zero any shared-memory ring frames touched by `role` and signal `RING_PEER_RESET_BIT` on
/// surviving peers so shared `SpscRing` indices never desync across protection domain respawns.
#[cfg(feature = "userspace")]
pub(super) fn reset_shared_rings_for_role(role: DomainRole) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vs = paging::Aarch64VSpace::from_current_ttbr1(hhdm);
    let mut table = DOMAINS.lock();
    let mut ipc = IPC_STATE.lock();
    if matches!(role, DomainRole::Net | DomainRole::Ssh) {
        let pa = NET_SSH_RING_PHYS.load(Ordering::Acquire);
        if pa != 0
            && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(pa))
        {
            vs.zero_frame(&fr);
        }
        let peer_notif = if role == DomainRole::Net { 3 } else { 2 };
        let _ = ipc.notify_signal_id(peer_notif, RING_PEER_RESET_BIT);
        let _ = wake_notif_waiter_locked(&mut table, &mut ipc, peer_notif);
    }
    if matches!(role, DomainRole::Key | DomainRole::Ssh) {
        let pa = SSH_KEY_RING_PHYS.load(Ordering::Acquire);
        if pa != 0
            && let Ok(fr) = PhysFrame::from_aligned(PhysAddr::new(pa))
        {
            vs.zero_frame(&fr);
        }
        let peer_notif = if role == DomainRole::Key { 3 } else { 4 };
        let _ = ipc.notify_signal_id(peer_notif, RING_PEER_RESET_BIT);
        let _ = wake_notif_waiter_locked(&mut table, &mut ipc, peer_notif);
    }
}

fn provision_role_caps(
    ipc: &mut KernelIpcState,
    role: DomainRole,
    pd_id: usize,
    ttbr0: u64,
    board_irqs: BoardIrqs,
) -> Result<(), SysError> {
    // Assign capabilities strictly by explicit `DomainRole`, NEVER by spawn order / PD (`N5`).
    match role {
        DomainRole::Supervisor => {
            ipc.bind_bootstrap_vspace(pd_id, PhysAddr::new(ttbr0))?;
            if let Some(irq) = board_irqs.uart {
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 32, irq.irq(), irq.controller());
            }
        }
        DomainRole::Shell => {
            ipc.init_shell_pd_bootstrap_caps(pd_id, NET_PD_PRESENT.load(Ordering::Acquire))?;
            let _ = ipc.register_child_thread_cap_in_root(40, pd_id)?;
            let _ = ipc.register_child_caps_in_root(pd_id)?;
        }
        DomainRole::Worker => {
            let _ = ipc.init_worker_pd_bootstrap_caps(pd_id)?;
            let _ = ipc.register_child_thread_cap_in_root(41, pd_id)?;
            let _ = ipc.register_child_caps_in_root(pd_id)?;
        }
        DomainRole::Net => {
            let len = NET_MMIO_LEN.load(Ordering::Acquire);
            let net_cap =
                (len > 0).then(|| (PhysAddr::new(NET_MMIO_PHYS.load(Ordering::Acquire)), len));
            ipc.init_net_pd_bootstrap_caps(pd_id, net_cap)?;
            ipc.bind_bootstrap_vspace(pd_id, PhysAddr::new(ttbr0))?;
            if let Some(irq) = board_irqs.net {
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 30, irq.irq(), irq.controller());
            }
            if let Some(ring_pa) = ensure_shared_ring_frame(&NET_SSH_RING_PHYS) {
                let _ = ipc.register_bootstrap_frame_cap(pd_id, 36, ring_pa);
            }
            if let Some(dma_pa) = ensure_shared_ring_frame(&NET_DMA_RING_PHYS) {
                let _ = ipc.register_bootstrap_frame_cap(pd_id, 39, dma_pa);
            }
            let _ = ipc.register_child_thread_cap_in_root(42, pd_id)?;
            let _ = ipc.register_child_caps_in_root(pd_id)?;
        }
        DomainRole::Key => {
            let len = RNG_MMIO_LEN.load(Ordering::Acquire);
            let rng_cap =
                (len > 0).then(|| (PhysAddr::new(RNG_MMIO_PHYS.load(Ordering::Acquire)), len));
            let qemu = IS_QEMU_VIRT.load(Ordering::Acquire);
            let vspace_access = if qemu {
                KeyPdVSpaceAccess::ReadWrite
            } else {
                KeyPdVSpaceAccess::WriteOnly
            };
            ipc.init_key_pd_bootstrap_caps(pd_id, rng_cap, vspace_access)?;
            if qemu {
                ipc.bind_bootstrap_vspace(pd_id, PhysAddr::new(ttbr0))?;
            }
            if let Some(irq) = board_irqs.rng {
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 31, irq.irq(), irq.controller());
            }
            if let Some(ring_pa) = ensure_shared_ring_frame(&SSH_KEY_RING_PHYS) {
                let _ = ipc.register_bootstrap_frame_cap(pd_id, 37, ring_pa);
            }
            let _ = ipc.register_child_thread_cap_in_root(43, pd_id)?;
            let _ = ipc.register_child_caps_in_root(pd_id)?;
        }
        DomainRole::Ssh => {
            ipc.init_ssh_pd_bootstrap_caps(pd_id)?;
            if let Some(ring_pa) = ensure_shared_ring_frame(&NET_SSH_RING_PHYS) {
                let _ = ipc.register_bootstrap_frame_cap(pd_id, 36, ring_pa);
            }
            if let Some(ring_pa) = ensure_shared_ring_frame(&SSH_KEY_RING_PHYS) {
                let _ = ipc.register_bootstrap_frame_cap(pd_id, 37, ring_pa);
            }
            let _ = ipc.register_child_thread_cap_in_root(44, pd_id)?;
            let _ = ipc.register_child_caps_in_root(pd_id)?;
        }
    }
    Ok(())
}

/// Register a newly loaded EL0 protection domain in `DOMAINS`, spawn its scheduler slot, and
/// provision role-scoped bootstrap capabilities in `IPC_STATE`.
///
/// # Errors
/// - [`SysError::SlotOccupied`] if `role == DomainRole::Supervisor` and PD 0 is already active.
/// - [`SysError::OutOfMemory`] if all non-root protection domain slots are occupied.
/// - Any capability provisioning error propagated from `KernelIpcState`.
pub fn register_domain(
    role: DomainRole,
    entry_pc: u64,
    user_sp: u64,
    user_shadow_sp: u64,
    ttbr0: u64,
) -> Result<usize, SysError> {
    let mut table = DOMAINS.lock();
    // Reuse any inactive protection domain slot (`M4`), reserving slot 0 for `DomainRole::Supervisor`.
    let pd_id = if role == DomainRole::Supervisor {
        if table.domains[0].is_some() {
            return Err(SysError::SlotOccupied);
        }
        0
    } else {
        (1..MAX_DOMAINS)
            .find(|&i| table.domains[i].is_none())
            .ok_or(SysError::OutOfMemory)?
    };
    let board_irqs = *BOARD_IRQS.lock();
    {
        let mut ipc = IPC_STATE.lock();
        provision_role_caps(&mut ipc, role, pd_id, ttbr0, board_irqs)?;
    }
    let mut frame = TrapFrame::ZERO;
    frame.x[18] = user_shadow_sp; // AArch64 Shadow Call Stack (`x18`)
    frame.elr_el1 = entry_pc;
    frame.sp_el0 = user_sp;
    frame.spsr_el1 = 0; // EL0t, DAIF unmasked
    table.domains[pd_id] = Some(ActiveDomain {
        role,
        ttbr0,
        wait: WaitState::Runnable,
        exec: ExecutionState::Detached,
        reply_target: None,
        fault_handler: None,
        shadow_sp: user_shadow_sp,
        tpidr_el0: 0,
        frame,
        fp: FpState::ZERO,
    });
    let _ = table.sched.spawn(DEFAULT_PRIORITY);
    if pd_id >= table.count {
        table.count = pd_id + 1;
    }
    Ok(pd_id)
}
