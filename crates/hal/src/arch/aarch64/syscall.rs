//! Pure 64-bit ARMv8 EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-process
//! context switching, and EL0 crash isolation / supervisor recovery.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::ops::{Deref, DerefMut};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "userspace")]
use newos_abi::DomainRoleId;
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, DmaCacheOp, IrqTriggerMode, NOTIFY_WAIT_TIMEOUT, ObjectType,
    RING_PEER_RESET_BIT, Rights, ShutdownStatus, SysError, SyscallNumber,
};
use newos_kernel_core::DomainRole;
use newos_kernel_core::ipc::{KernelIpcState, MAX_ENDPOINTS, MAX_IPC_DOMAINS};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_MASK, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory,
    VSpaceMapper, VirtAddr,
};
use newos_kernel_core::sched::{DEFAULT_PRIORITY, Scheduler};
#[cfg(feature = "userspace")]
use newos_kernel_core::{USER_PQ_STACK_PAGES, USER_STACK_PAGES};

use super::serial;

const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_DOMAINS: usize = MAX_IPC_DOMAINS;
const _: () = assert!(MAX_DOMAINS <= 8);
const MAX_CPUS: usize = 8;
const MAX_DMA_CACHE_LEN: u64 = 64 * 1024;
const TTBR0_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const CNTV_CTL_ENABLE: u64 = 1 << 0;
const CNTV_CTL_ISTATUS: u64 = 1 << 2;

/// IRQ-disabling spinlock protecting kernel globals across EL0 syscalls, EL0 IRQs, and SMP cores.
///
/// Lock hierarchy (always acquire in this order when holding more than one):
/// `DOMAINS` -> `IPC_STATE` -> `RUNTIME_UNTYPED` -> `FRAME_MAPPINGS`.
/// Leaf locks (`IRQ_TABLE`, `PL011_LOCK`) are never held while acquiring `DOMAINS` or `IPC_STATE`.
pub(super) struct IrqSpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `IrqSpinLock` serializes all access with `Acquire`/`Release` atomics and masks local IRQs.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

pub(super) struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    saved_daif: u64,
}

impl<T> IrqSpinLock<T> {
    pub(super) const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(val),
        }
    }

    #[inline]
    pub(super) fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let saved_daif: u64;
        // SAFETY: Saving `DAIF` and masking local IRQs (`daifset #2`) in EL1 prevents same-CPU
        // IRQ re-entrancy deadlocks while the spinlock is held.
        unsafe {
            asm!("mrs {}, daif", out(reg) saved_daif, options(nomem, nostack));
            asm!("msr daifset, #2", options(nomem, nostack));
        }
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        IrqSpinLockGuard {
            lock: self,
            saved_daif,
        }
    }
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: The guard holds exclusive ownership of `self.lock`.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: The guard holds exclusive ownership of `self.lock`.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: Restoring `DAIF` to its pre-lock value in EL1 after releasing the spinlock.
        unsafe {
            asm!("msr daif, {}", in(reg) self.saved_daif, options(nomem, nostack));
        }
    }
}

/// Return `(err, val, badge)` across EL0 `svc #0` in `(x0, x1, x2)` — preserving full 64-bit badges.
#[inline]
fn set_ipc_return(frame: &mut TrapFrame, payload: u64, badge: u64) {
    frame.x[0] = 0;
    frame.x[1] = payload;
    frame.x[2] = badge;
}

#[inline]
fn parse_rights(raw: u64) -> Result<Rights, SysError> {
    if raw > u64::from(u8::MAX) {
        return Err(SysError::InvalidArgument);
    }
    Rights::from_bits(raw as u8).ok_or(SysError::InvalidArgument)
}

#[inline]
fn parse_mint_rights_and_badge(a2: u64, a3: u64) -> Result<(Rights, Option<u64>), SysError> {
    let raw_rights = a2 & !CAP_MINT_SET_BADGE;
    let rights = parse_rights(raw_rights)?;
    let badge = if (a2 & CAP_MINT_SET_BADGE) != 0 {
        Some(a3)
    } else {
        None
    };
    Ok((rights, badge))
}

static YIELD_COUNTER: AtomicU64 = AtomicU64::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
static RNG_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
static RNG_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
static RNG_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
static WDT_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
static WDT_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
static WDT_MMIO_LEN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
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

    fn push(&mut self, phys: u64, virt: u64, len: u64) {
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
static IS_QEMU_VIRT: AtomicBool = AtomicBool::new(false);
static SYS_INFO_PACKED: AtomicU64 = AtomicU64::new(0);
static TIMER_TICK_INTERVAL: AtomicU64 = AtomicU64::new(625_000);
static SYSCALL_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);
static PREEMPT_PENDING: AtomicBool = AtomicBool::new(false);
static IPC_STATE: IrqSpinLock<KernelIpcState> = IrqSpinLock::new(KernelIpcState::new());
static RUNTIME_UNTYPED: IrqSpinLock<UntypedInventory> = IrqSpinLock::new(UntypedInventory::new());
static FRAME_MAPPINGS: IrqSpinLock<FrameMappingTracker<512>> =
    IrqSpinLock::new(FrameMappingTracker::new());

const MAX_GIC_IRQS: usize = 1024;
const MAX_MIP_VECTORS: usize = 64;
const MAX_IRQS: usize = MAX_GIC_IRQS + MAX_MIP_VECTORS;

#[derive(Clone, Copy)]
struct IrqBinding {
    notif_id: u32,
    badge_bit: u8,
    is_mip: bool,
    irq: u16,
}

#[derive(Clone, Copy)]
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
static IRQ_TABLE: IrqSpinLock<[Option<IrqBinding>; MAX_IRQS]> = IrqSpinLock::new([None; MAX_IRQS]);

/// Immutable Limine boot-module ELF64 slice descriptor retained for `DomainRespawn`.
#[derive(Clone, Copy)]
struct BootModuleSlice {
    role: DomainRole,
    ptr: usize,
    len: usize,
}

static BOOT_MODULES: IrqSpinLock<[Option<BootModuleSlice>; MAX_DOMAINS]> =
    IrqSpinLock::new([None; MAX_DOMAINS]);

/// Persistent 4 KiB physical addresses for inter-domain shared-memory `SpscRing` frames.
static NET_SSH_RING_PHYS: AtomicU64 = AtomicU64::new(0);
static SSH_KEY_RING_PHYS: AtomicU64 = AtomicU64::new(0);
static NET_DMA_RING_PHYS: AtomicU64 = AtomicU64::new(0);

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
    let vs = super::paging::Aarch64VSpace::from_current_ttbr1(hhdm);
    vs.zero_frame(&frame);
    let pa = frame.start_addr().raw();
    slot.store(pa, Ordering::Release);
    Some(PhysAddr::new(pa))
}

/// Zero any shared-memory ring frames touched by `role` and signal `RING_PEER_RESET_BIT` on
/// surviving peers so shared `SpscRing` indices never desync across protection domain respawns.
fn reset_shared_rings_for_role(role: DomainRole) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vs = super::paging::Aarch64VSpace::from_current_ttbr1(hhdm);
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

/// Record an immutable boot-module ELF64 slice for runtime `DomainRespawn` supervision.
pub fn register_boot_module(role: DomainRole, elf_bytes: &'static [u8]) {
    let mut mods = BOOT_MODULES.lock();
    for slot in mods.iter_mut() {
        if slot.is_some_and(|m| m.role == role) {
            *slot = Some(BootModuleSlice {
                role,
                ptr: elf_bytes.as_ptr() as usize,
                len: elf_bytes.len(),
            });
            return;
        }
    }
    for slot in mods.iter_mut() {
        if slot.is_none() {
            *slot = Some(BootModuleSlice {
                role,
                ptr: elf_bytes.as_ptr() as usize,
                len: elf_bytes.len(),
            });
            return;
        }
    }
}

fn find_boot_module(role: DomainRole) -> Option<&'static [u8]> {
    let mods = BOOT_MODULES.lock();
    for m in mods.iter().flatten() {
        if m.role == role && m.ptr != 0 && m.len > 0 {
            // SAFETY: Registered exclusively from `&'static [u8]` Limine boot module slices
            // mapped in permanent HHDM physical memory for the lifetime of the kernel.
            return Some(unsafe { core::slice::from_raw_parts(m.ptr as *const u8, m.len) });
        }
    }
    None
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

#[inline]
fn irq_table_index(irq: u16, is_mip: bool) -> Option<usize> {
    if is_mip {
        let v = usize::from(irq);
        (v < MAX_MIP_VECTORS).then_some(MAX_GIC_IRQS + v)
    } else {
        let id = usize::from(irq);
        ((32..1020).contains(&id)).then_some(id)
    }
}

/// Unbind and mask any `IRQ_TABLE` entries whose `IrqHandler` capability is no longer live.
/// Caller holds `IPC_STATE` (or invokes independently); `IRQ_TABLE` is a leaf lock.
fn cleanup_orphaned_irqs(ipc: &KernelIpcState) {
    let mut table = IRQ_TABLE.lock();
    for slot in table.iter_mut() {
        if let Some(binding) = *slot
            && !ipc.has_live_irq_cap(binding.irq, binding.is_mip)
        {
            *slot = None;
            if binding.is_mip {
                super::gic::set_mip_vector_masked(binding.irq as u8, true);
            } else {
                super::gic::disable_irq(u32::from(binding.irq));
            }
        }
    }
}

// SAFETY: `__newos_el0_enter_frame` is defined in `mod.rs` `global_asm!` and restores a valid `TrapFrame` before `eret`.
unsafe extern "C" {
    fn __newos_el0_enter_frame(frame: *const TrapFrame) -> !;
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

/// Full EL0 register trap frame saved on `SP_EL1` by `__newos_sync_el0` (272 bytes, 16B-aligned).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
}

impl TrapFrame {
    const ZERO: Self = Self {
        x: [0; 31],
        sp_el0: 0,
        elr_el1: 0,
        spsr_el1: 0,
    };
}

/// Full AArch64 Advanced SIMD (NEON) & FP register state saved/restored across EL0 context switches.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct FpState {
    fpcr: u64,
    fpsr: u64,
    q: [[u64; 2]; 32],
}

const _: () = assert!(core::mem::size_of::<FpState>() == 528);

impl FpState {
    const ZERO: Self = Self {
        fpcr: 0,
        fpsr: 0,
        q: [[0; 2]; 32],
    };
}

#[inline]
pub(super) fn enable_fp_simd() {
    // SAFETY: Setting `CPACR_EL1.FPEN = 0b11` (bits 21:20) enables FP/NEON in EL1 and EL0
    // so EL0 SIMD instructions and EL1 `save_fp_state`/`restore_fp_state` never trap.
    unsafe {
        let mut cpacr: u64;
        asm!("mrs {}, cpacr_el1", out(reg) cpacr, options(nomem, nostack));
        cpacr |= 0b11 << 20;
        asm!("msr cpacr_el1, {}", "isb", in(reg) cpacr, options(nomem, nostack));
    }
}

#[inline]
fn save_fp_state(dst: &mut FpState) {
    let base = dst as *mut FpState as *mut u8;
    // SAFETY: `dst` is a 16-byte-aligned, exclusively borrowed `FpState` (528 bytes) and
    // `enable_fp_simd()` has unmasked FP/SIMD access in `CPACR_EL1`.
    unsafe {
        asm!(
            ".arch_extension fp",
            "mrs {t0}, fpcr",
            "mrs {t1}, fpsr",
            "stp {t0}, {t1}, [{base}, #0]",
            "stp q0,  q1,  [{base}, #16]",
            "stp q2,  q3,  [{base}, #48]",
            "stp q4,  q5,  [{base}, #80]",
            "stp q6,  q7,  [{base}, #112]",
            "stp q8,  q9,  [{base}, #144]",
            "stp q10, q11, [{base}, #176]",
            "stp q12, q13, [{base}, #208]",
            "stp q14, q15, [{base}, #240]",
            "stp q16, q17, [{base}, #272]",
            "stp q18, q19, [{base}, #304]",
            "stp q20, q21, [{base}, #336]",
            "stp q22, q23, [{base}, #368]",
            "stp q24, q25, [{base}, #400]",
            "stp q26, q27, [{base}, #432]",
            "stp q28, q29, [{base}, #464]",
            "stp q30, q31, [{base}, #496]",
            ".arch_extension nofp",
            base = in(reg) base,
            t0 = out(reg) _,
            t1 = out(reg) _,
            options(nostack),
        );
    }
}

#[inline]
fn restore_fp_state(src: &FpState) {
    let base = src as *const FpState as *const u8;
    // SAFETY: `src` is a 16-byte-aligned, valid `FpState` (528 bytes) and
    // `enable_fp_simd()` has unmasked FP/SIMD access in `CPACR_EL1`.
    unsafe {
        asm!(
            ".arch_extension fp",
            "ldp {t0}, {t1}, [{base}, #0]",
            "msr fpcr, {t0}",
            "msr fpsr, {t1}",
            "ldp q0,  q1,  [{base}, #16]",
            "ldp q2,  q3,  [{base}, #48]",
            "ldp q4,  q5,  [{base}, #80]",
            "ldp q6,  q7,  [{base}, #112]",
            "ldp q8,  q9,  [{base}, #144]",
            "ldp q10, q11, [{base}, #176]",
            "ldp q12, q13, [{base}, #208]",
            "ldp q14, q15, [{base}, #240]",
            "ldp q16, q17, [{base}, #272]",
            "ldp q18, q19, [{base}, #304]",
            "ldp q20, q21, [{base}, #336]",
            "ldp q22, q23, [{base}, #368]",
            "ldp q24, q25, [{base}, #400]",
            "ldp q26, q27, [{base}, #432]",
            "ldp q28, q29, [{base}, #464]",
            "ldp q30, q31, [{base}, #496]",
            ".arch_extension nofp",
            base = in(reg) base,
            t0 = out(reg) _,
            t1 = out(reg) _,
            options(nostack),
        );
    }
}

#[inline]
fn read_tpidr_el0() -> u64 {
    let v: u64;
    // SAFETY: Reading `TPIDR_EL0` in EL1 saves the active EL0 thread pointer (`M7`).
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
fn write_tpidr_el0(v: u64) {
    // SAFETY: Writing `TPIDR_EL0` in EL1 restores the target EL0 thread pointer (`M7`).
    unsafe {
        asm!("msr tpidr_el0, {}", in(reg) v, options(nomem, nostack));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpcWaitState {
    Runnable,
    WaitingReply,
    WaitingRecv,
    WaitingNotif,
    Sleeping,
}

#[derive(Clone, Copy)]
struct FaultRecord {
    role: DomainRole,
    esr: u64,
    elr: u64,
    _far: u64,
}

#[derive(Clone, Copy)]
struct DomainSlot {
    active: bool,
    pending_destroy: bool,
    role: DomainRole,
    ttbr0: u64,
    wait: IpcWaitState,
    wait_ep_id: u32,
    wait_notif_id: u32,
    wait_notif_mask: u64,
    sleep_deadline_ticks: Option<u64>,
    /// Logical CPU currently executing this process in EL0 (`None` when queued/blocked).
    running_on: Option<usize>,
    /// Single-use implicit Reply capability minted on `IpcCall` rendezvous, consumed on `IpcReplyRecv`.
    reply_target: Option<usize>,
    fault_pc: u64,
    fault_sp: u64,
    shadow_sp: u64,
    tpidr_el0: u64,
    frame: TrapFrame,
    fp: FpState,
}

impl DomainSlot {
    const EMPTY: Self = Self {
        active: false,
        pending_destroy: false,
        role: DomainRole::Worker,
        ttbr0: 0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
        wait_notif_id: 0,
        wait_notif_mask: 0,
        sleep_deadline_ticks: None,
        running_on: None,
        reply_target: None,
        fault_pc: 0,
        fault_sp: 0,
        shadow_sp: 0,
        tpidr_el0: 0,
        frame: TrapFrame::ZERO,
        fp: FpState::ZERO,
    };
}

struct DomainTable {
    domains: [DomainSlot; MAX_DOMAINS],
    sched: Scheduler<MAX_DOMAINS>,
    recv_waiters: [u8; MAX_ENDPOINTS],
    reply_waiters: [u8; MAX_ENDPOINTS],
    last_fault: [Option<FaultRecord>; MAX_DOMAINS],
    count: usize,
    cpu_current: [Option<usize>; MAX_CPUS],
}

impl DomainTable {
    const fn new() -> Self {
        Self {
            domains: [DomainSlot::EMPTY; MAX_DOMAINS],
            sched: Scheduler::new(),
            recv_waiters: [0; MAX_ENDPOINTS],
            reply_waiters: [0; MAX_ENDPOINTS],
            last_fault: [None; MAX_DOMAINS],
            count: 0,
            cpu_current: [None; MAX_CPUS],
        }
    }

    #[inline]
    fn current_for_this_cpu(&self) -> Option<usize> {
        let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
        self.cpu_current[cpu]
    }

    #[inline]
    fn has_any_active(&self) -> bool {
        self.domains.iter().any(|p| p.active)
    }

    #[inline]
    fn active_count(&self) -> usize {
        self.domains.iter().filter(|p| p.active).count()
    }

    #[inline]
    fn set_wait_state(&mut self, pd_id: usize, new_state: IpcWaitState, new_ep: u32) {
        if pd_id >= MAX_DOMAINS {
            return;
        }
        let bit = 1u8 << pd_id;
        let old_state = self.domains[pd_id].wait;
        let old_ep = self.domains[pd_id].wait_ep_id as usize;
        if old_ep < MAX_ENDPOINTS {
            match old_state {
                IpcWaitState::WaitingRecv => self.recv_waiters[old_ep] &= !bit,
                IpcWaitState::WaitingReply => self.reply_waiters[old_ep] &= !bit,
                IpcWaitState::Runnable | IpcWaitState::WaitingNotif | IpcWaitState::Sleeping => {}
            }
        }
        self.domains[pd_id].wait = new_state;
        self.domains[pd_id].wait_ep_id = new_ep;
        let new_ep_idx = new_ep as usize;
        if new_ep_idx < MAX_ENDPOINTS {
            match new_state {
                IpcWaitState::WaitingRecv => self.recv_waiters[new_ep_idx] |= bit,
                IpcWaitState::WaitingReply => self.reply_waiters[new_ep_idx] |= bit,
                IpcWaitState::Runnable | IpcWaitState::WaitingNotif | IpcWaitState::Sleeping => {}
            }
        }
        if new_state == IpcWaitState::Runnable && old_state != IpcWaitState::Runnable {
            super::smp::wake_idle_aps();
        }
    }

    #[inline]
    fn pick_next_runnable(&mut self, from: usize) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        // SMP-safe lookup: scan only genuinely `Ready` slots without demoting any
        // thread currently `Running` on another CPU.
        if let Some(next) = self.sched.pick_next_ready(from)
            && next != from
            && self.domains[next].active
            && self.domains[next].wait == IpcWaitState::Runnable
            && self.domains[next].running_on.is_none()
        {
            return Some(next);
        }
        // Fallback linear scan in case a runnable slot was temporarily out of sync.
        for offset in 1..self.count {
            let next = (from + offset) % self.count;
            if next != from
                && self.domains[next].active
                && self.domains[next].wait == IpcWaitState::Runnable
                && self.domains[next].running_on.is_none()
            {
                return Some(next);
            }
        }
        None
    }

    #[inline]
    fn claim_any_runnable(&mut self, cpu_id: usize) -> Option<usize> {
        for pd_id in 0..MAX_DOMAINS {
            if self.domains[pd_id].active
                && self.domains[pd_id].wait == IpcWaitState::Runnable
                && self.domains[pd_id].running_on.is_none()
            {
                self.domains[pd_id].running_on = Some(cpu_id);
                self.cpu_current[cpu_id] = Some(pd_id);
                self.sched.mark_running(pd_id);
                return Some(pd_id);
            }
        }
        None
    }

    #[inline]
    fn has_other_running_cpu(&self, this_cpu: usize) -> bool {
        for (cpu, slot) in self.cpu_current.iter().enumerate() {
            if cpu != this_cpu && slot.is_some() {
                return true;
            }
        }
        false
    }

    #[inline]
    fn find_waiter(&self, state: IpcWaitState, ep_id: u32, exclude: usize) -> Option<usize> {
        let ep = ep_id as usize;
        if ep >= MAX_ENDPOINTS {
            return None;
        }
        let mut mask = match state {
            IpcWaitState::WaitingRecv => self.recv_waiters[ep],
            IpcWaitState::WaitingReply => self.reply_waiters[ep],
            IpcWaitState::Runnable | IpcWaitState::WaitingNotif | IpcWaitState::Sleeping => {
                return None;
            }
        };
        if exclude < MAX_DOMAINS {
            mask &= !(1u8 << exclude);
        }
        if mask == 0 {
            None
        } else {
            Some(mask.trailing_zeros() as usize)
        }
    }
}

static DOMAINS: IrqSpinLock<DomainTable> = IrqSpinLock::new(DomainTable::new());

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

#[inline]
fn mmio_phys_to_virt(phys: u64) -> Option<u64> {
    let base_phys = NET_MMIO_PHYS.load(Ordering::Acquire);
    let base_virt = NET_MMIO_VIRT.load(Ordering::Acquire);
    let len = NET_MMIO_LEN.load(Ordering::Acquire);
    if len > 0 && phys >= base_phys && phys < base_phys.saturating_add(len) {
        return Some(base_virt + (phys - base_phys));
    }
    let rng_phys = RNG_MMIO_PHYS.load(Ordering::Acquire);
    let rng_virt = RNG_MMIO_VIRT.load(Ordering::Acquire);
    let rng_len = RNG_MMIO_LEN.load(Ordering::Acquire);
    if rng_len > 0 && phys >= rng_phys && phys < rng_phys.saturating_add(rng_len) {
        return Some(rng_virt + (phys - rng_phys));
    }
    let wdt_phys = WDT_MMIO_PHYS.load(Ordering::Acquire);
    let wdt_virt = WDT_MMIO_VIRT.load(Ordering::Acquire);
    let wdt_len = WDT_MMIO_LEN.load(Ordering::Acquire);
    if wdt_len > 0 && phys >= wdt_phys && phys < wdt_phys.saturating_add(wdt_len) {
        return Some(wdt_virt + (phys - wdt_phys));
    }
    if let Some(virt) = EXTRA_MMIO_MAPS.lock().translate(phys) {
        return Some(virt);
    }
    // Never fall back to cacheable HHDM for Device MMIO (`H-5`).
    None
}

pub fn set_sys_info(online_cpus: usize, interactive_shell: bool) {
    let packed = ((u64::from(interactive_shell)) << 32) | (online_cpus as u64 & 0xFFFF);
    SYS_INFO_PACKED.store(packed, Ordering::Release);
}

pub fn register_domain(
    role: DomainRole,
    entry_pc: u64,
    user_sp: u64,
    user_shadow_sp: u64,
    ttbr0: u64,
) -> Result<usize, SysError> {
    let mut table = DOMAINS.lock();
    // Reuse any inactive process slot (`M4`), reserving slot 0 for `DomainRole::Supervisor`.
    let pd_id = if role == DomainRole::Supervisor {
        if table.domains[0].active {
            return Err(SysError::SlotOccupied);
        }
        0
    } else {
        (1..MAX_DOMAINS)
            .find(|&i| !table.domains[i].active)
            .ok_or(SysError::OutOfMemory)?
    };
    let mut frame = TrapFrame::ZERO;
    frame.x[18] = user_shadow_sp; // AArch64 Shadow Call Stack (`x18`)
    frame.elr_el1 = entry_pc;
    frame.sp_el0 = user_sp;
    frame.spsr_el1 = 0; // EL0t, DAIF unmasked
    table.domains[pd_id] = DomainSlot {
        active: true,
        pending_destroy: false,
        role,
        ttbr0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
        wait_notif_id: 0,
        wait_notif_mask: 0,
        sleep_deadline_ticks: None,
        running_on: None,
        reply_target: None,
        fault_pc: 0,
        fault_sp: 0,
        shadow_sp: user_shadow_sp,
        tpidr_el0: 0,
        frame,
        fp: FpState::ZERO,
    };
    let _ = table.sched.spawn(DEFAULT_PRIORITY);
    if pd_id >= table.count {
        table.count = pd_id + 1;
    }
    let board_irqs = *BOARD_IRQS.lock();
    let mut ipc = IPC_STATE.lock();
    // Assign capabilities strictly by explicit `DomainRole`, NEVER by spawn order / PD (`N5`).
    match role {
        DomainRole::Supervisor => {
            ipc.bind_bootstrap_vspace(pd_id, PhysAddr::new(ttbr0))?;
            if let Some(irq) = board_irqs.uart {
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 32, irq.irq, irq.is_mip);
            }
        }
        DomainRole::Shell => {
            ipc.init_shell_pd_bootstrap_caps(pd_id)?;
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
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 30, irq.irq, irq.is_mip);
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
            ipc.init_key_pd_bootstrap_caps(pd_id, rng_cap, qemu)?;
            if qemu {
                ipc.bind_bootstrap_vspace(pd_id, PhysAddr::new(ttbr0))?;
            }
            if let Some(irq) = board_irqs.rng {
                let _ = ipc.register_bootstrap_irq_cap(pd_id, 31, irq.irq, irq.is_mip);
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
    Ok(pd_id)
}

#[inline]
fn switch_ttbr0(ttbr0_phys: u64, pd_id: usize) {
    let asid = ((pd_id + 1) as u64) & 0xFFFF;
    let val = (asid << 48) | (ttbr0_phys & TTBR0_ADDR_MASK);
    // SAFETY: `ttbr0_phys` is a verified 4 KiB-aligned EL0 L0 page-table physical address whose
    // user leaf PTEs are tagged with `DESC_NG = 1 << 11`. `TCR_EL1.A1 == 0` routes 16-bit ASID
    // selection through `TTBR0_EL1[63:48]`, isolating per-PD TLB entries without global flushes.
    unsafe {
        asm!(
            "msr ttbr0_el1, {val}",
            "isb",
            val = in(reg) val,
            options(nostack),
        );
    }
}

/// Save `from`'s GPR + `TPIDR_EL0` + NEON/FP state and switch `TTBR0_EL1` + registers to `to`.
#[inline]
fn context_switch(table: &mut DomainTable, from: usize, to: usize, frame: &mut TrapFrame) {
    let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    table.domains[from].frame = *frame;
    table.domains[from].tpidr_el0 = read_tpidr_el0();
    save_fp_state(&mut table.domains[from].fp);
    table.domains[from].running_on = None;
    if table.domains[from].active && table.domains[from].wait == IpcWaitState::Runnable {
        table.sched.mark_ready(from);
    }
    table.domains[to].running_on = Some(cpu);
    table.cpu_current[cpu] = Some(to);
    table.sched.mark_running(to);
    switch_ttbr0(table.domains[to].ttbr0, to);
    write_tpidr_el0(table.domains[to].tpidr_el0);
    restore_fp_state(&table.domains[to].fp);
    *frame = table.domains[to].frame;
}

/// Read the architectural Generic Virtual Counter (`CNTVCT_EL0`), which matches `TimerFreq`
/// (`CNTFRQ_EL0`) and is monotonic across all SMP cores (`P6`).
#[inline]
fn read_cycles() -> u64 {
    read_cntvct()
}

/// Perform PAN-safe, page-table-validated DMA cache maintenance (`dc cvac` / `dc civac`)
/// over an EL0 virtual address range `user_ptr..user_ptr+len` via its HHDM physical alias.
fn handle_dma_cache_op(
    ttbr0: u64,
    user_ptr: u64,
    len: u64,
    op: DmaCacheOp,
) -> Result<u64, SysError> {
    if len == 0 {
        return Ok(0);
    }
    if len > MAX_DMA_CACHE_LEN {
        return Err(SysError::InvalidArgument);
    }
    let end = user_ptr.checked_add(len).ok_or(SysError::InvalidArgument)?;
    if user_ptr == 0 || end >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vspace = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
    let require_write = matches!(op, DmaCacheOp::Invalidate | DmaCacheOp::CleanInvalidate);

    let mut cur = user_ptr;
    while cur < end {
        let page_va_raw = cur & !PAGE_MASK;
        let page_off = cur & PAGE_MASK;
        let chunk = (PAGE_SIZE - page_off).min(end - cur) as usize;
        let page_va = VirtAddr::new_page_aligned(page_va_raw)?;
        let (phys, flags) = vspace.translate(page_va).ok_or(SysError::InvalidArgument)?;
        if !flags.user || (require_write && !flags.writable) {
            return Err(SysError::InsufficientRights);
        }
        let hhdm_va = hhdm.wrapping_add(phys.raw().wrapping_add(page_off));
        match op {
            DmaCacheOp::Clean => super::paging::dma_clean_range(hhdm_va, chunk),
            DmaCacheOp::Invalidate | DmaCacheOp::CleanInvalidate => {
                super::paging::dma_invalidate_range(hhdm_va, chunk);
            }
        }
        cur += chunk as u64;
    }
    Ok(len)
}

#[inline]
pub(crate) fn read_cntfrq() -> u64 {
    let freq: u64;
    // SAFETY: Reading `CNTFRQ_EL0` in EL1 returns the architectural Generic Timer frequency in Hz.
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    freq
}

#[inline]
pub(crate) fn read_cntvct() -> u64 {
    let v: u64;
    // SAFETY: `CNTVCT_EL0` is always readable in EL1.
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

#[inline]
fn read_cntv_ctl() -> u64 {
    let ctl: u64;
    // SAFETY: Reading `CNTV_CTL_EL0` in EL1 checks the Virtual Timer status register.
    unsafe {
        asm!("mrs {}, cntv_ctl_el0", out(reg) ctl, options(nomem, nostack));
    }
    ctl
}

#[inline]
fn arm_virtual_timer(ticks: u64) {
    let clamped = ticks.clamp(10_000, u32::MAX as u64);
    // SAFETY: Programming ARM Generic Virtual Timer (`CNTV_TVAL_EL0` / `CNTV_CTL_EL0`) in EL1.
    unsafe {
        asm!(
            "msr cntv_tval_el0, {tval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            tval = in(reg) clamped,
            ctl = in(reg) CNTV_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

fn init_preempt_timer() {
    let freq: u64;
    // SAFETY: Reading `CNTFRQ_EL0` in EL1 returns the architectural Generic Timer frequency.
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    // 10 ms tick interval (fallback to 625_000 ticks if CNTFRQ_EL0 reports 0).
    let interval = if freq >= 100 { freq / 100 } else { 625_000 };
    TIMER_TICK_INTERVAL.store(interval, Ordering::Release);
    arm_virtual_timer(interval);
}

/// Spectre v1 Consumption of Speculative Data Barrier (`csdb`) after bounds checks.
#[inline(always)]
fn spec_barrier() {
    // SAFETY: `csdb` is an architectural hint-space barrier (NOP on older cores, speculation barrier on v8.2+).
    unsafe {
        asm!("csdb", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
fn disable_virtual_timer() {
    // SAFETY: Masking and disabling `CNTV_CTL_EL0` (`IMASK=1, ENABLE=0`) in EL1 prevents
    // idle cores from taking spurious virtual timer IRQs (`P9`).
    unsafe {
        asm!(
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            ctl = in(reg) 2u64,
            options(nomem, nostack),
        );
    }
}

#[inline]
fn arm_virtual_timer_cval(deadline_ticks: u64) {
    // SAFETY: Programs absolute compare value `CNTV_CVAL_EL0` and unmasks the virtual timer
    // so an idle core parked in `wfi` wakes at `CNTVCT_EL0 >= deadline_ticks`.
    unsafe {
        asm!(
            "msr cntv_cval_el0, {cval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            cval = in(reg) deadline_ticks,
            ctl = in(reg) CNTV_CTL_ENABLE,
            options(nomem, nostack),
        );
    }
}

/// Wake any `WaitingNotif` or `Sleeping` threads whose `sleep_deadline_ticks <= now`.
/// Caller MUST hold `DOMAINS`.
fn wake_expired_timers_locked(table: &mut DomainTable, now: u64) -> bool {
    let mut woke_any = false;
    for pd_id in 0..table.count.min(MAX_DOMAINS) {
        if !table.domains[pd_id].active {
            continue;
        }
        let Some(deadline) = table.domains[pd_id].sleep_deadline_ticks else {
            continue;
        };
        if now < deadline {
            continue;
        }
        match table.domains[pd_id].wait {
            IpcWaitState::WaitingNotif => {
                table.domains[pd_id].frame.x[0] = 0;
                table.domains[pd_id].frame.x[1] = 0;
                table.domains[pd_id].frame.x[2] = NOTIFY_WAIT_TIMEOUT;
                table.domains[pd_id].wait_notif_id = 0;
                table.domains[pd_id].wait_notif_mask = 0;
                table.domains[pd_id].sleep_deadline_ticks = None;
                table.set_wait_state(pd_id, IpcWaitState::Runnable, 0);
                let _ = table.sched.wake_slot(pd_id);
                woke_any = true;
            }
            IpcWaitState::Sleeping => {
                table.domains[pd_id].frame.x[0] = 0;
                table.domains[pd_id].frame.x[1] = 0;
                table.domains[pd_id].frame.x[2] = 0;
                table.domains[pd_id].sleep_deadline_ticks = None;
                table.set_wait_state(pd_id, IpcWaitState::Runnable, 0);
                let _ = table.sched.wake_slot(pd_id);
                woke_any = true;
            }
            _ => {
                table.domains[pd_id].sleep_deadline_ticks = None;
            }
        }
    }
    woke_any
}

/// Wake expired sleeping/timed-out threads from EL1 timer IRQ context and kick idle APs.
pub fn wake_expired_timers() {
    let woke = {
        let mut table = DOMAINS.lock();
        wake_expired_timers_locked(&mut table, read_cntvct())
    };
    if woke {
        super::smp::wake_idle_aps();
    }
}

/// If any thread is blocked in `WaitingNotif` on `notif_id` with a mask intersecting the pending
/// bits, consume the matched bits into its `TrapFrame` and wake it. Caller holds `DOMAINS -> IPC_STATE`.
fn wake_notif_waiter_locked(
    table: &mut DomainTable,
    ipc: &mut KernelIpcState,
    notif_id: u32,
) -> bool {
    for pd_id in 0..table.count.min(MAX_DOMAINS) {
        if table.domains[pd_id].active
            && table.domains[pd_id].wait == IpcWaitState::WaitingNotif
            && table.domains[pd_id].wait_notif_id == notif_id
        {
            let mask = table.domains[pd_id].wait_notif_mask;
            if let Ok(matched) = ipc.notify_consume_mask(notif_id, mask)
                && matched != 0
            {
                table.domains[pd_id].frame.x[0] = 0;
                table.domains[pd_id].frame.x[1] = matched;
                table.domains[pd_id].frame.x[2] = 0;
                table.domains[pd_id].wait_notif_id = 0;
                table.domains[pd_id].wait_notif_mask = 0;
                table.domains[pd_id].sleep_deadline_ticks = None;
                table.set_wait_state(pd_id, IpcWaitState::Runnable, 0);
                let _ = table.sched.wake_slot(pd_id);
                return true;
            }
        }
    }
    false
}

/// Unified EL1/EL0 external SPI dispatch: masks the SPI at the GIC, copies any `IrqBinding` out
/// of leaf lock `IRQ_TABLE` (dropping `IRQ_TABLE` before acquiring `DOMAINS -> IPC_STATE`), signals
/// the bound notification, and wakes any matching `WaitingNotif` thread.
pub fn dispatch_peripheral_spi(irq_id: u32) {
    super::gic::disable_irq(irq_id);
    let binding = irq_table_index(irq_id as u16, false).and_then(|idx| IRQ_TABLE.lock()[idx]);
    let woke = {
        let mut table = DOMAINS.lock();
        let mut ipc = IPC_STATE.lock();
        if let Some(b) = binding {
            let bit = 1u64 << (b.badge_bit & 63);
            let _ = ipc.notify_signal_id(b.notif_id, bit);
            wake_notif_waiter_locked(&mut table, &mut ipc, b.notif_id)
        } else {
            // Unbound peripheral SPI: keep masked at the GIC and drop it rather than
            // injecting spurious bits into notification 0 (shared with worker-pd).
            false
        }
    };
    if woke {
        super::smp::wake_idle_aps();
    }
}

/// Rust handler invoked by `__newos_irq_el0` on hardware IRQs (ARM Generic Timer preemption,
/// timed `SleepUntil`/`NotifyWait` wakeups, and peripheral SPIs delivered via `IrqBind`/`IrqAck`).
pub extern "C" fn irq_el0_dispatch(frame: &mut TrapFrame) {
    let iar = super::gic::acknowledge();
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
            super::smp::wake_idle_aps();
        }
    } else if let Some(id) = irq_id
        && (32..1020).contains(&id)
    {
        dispatch_peripheral_spi(id);
    }
    if let Some(id) = iar {
        super::gic::end_of_interrupt(id);
    }
    // Cross-core SMP `DomainDestroy` handshake: if another core marked our currently running
    // domain `pending_destroy`, immediately deschedule off this core so it can be torn down safely.
    let mut should_park = false;
    {
        let mut table = DOMAINS.lock();
        if let Some(cur) = table.current_for_this_cpu()
            && table.domains[cur].pending_destroy
        {
            let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
            table.domains[cur].frame = *frame;
            save_fp_state(&mut table.domains[cur].fp);
            table.domains[cur].tpidr_el0 = read_tpidr_el0();
            table.domains[cur].running_on = None;
            table.cpu_current[cpu] = None;
            if let Some(next) = table.pick_next_runnable(cur) {
                table.domains[next].running_on = Some(cpu);
                table.cpu_current[cpu] = Some(next);
                switch_ttbr0(table.domains[next].ttbr0, next);
                restore_fp_state(&table.domains[next].fp);
                write_tpidr_el0(table.domains[next].tpidr_el0);
                *frame = table.domains[next].frame;
            } else {
                // SAFETY: Detach the dying domain's `TTBR0_EL1` (and ASID) from this CPU before
                // releasing `DOMAINS.lock()` so `teardown_domain_locked` on another core can
                // safely free/zero the page tables and invalidate the ASID without stale walks.
                unsafe {
                    asm!(
                        "msr ttbr0_el1, xzr",
                        "isb",
                        options(nostack, preserves_flags)
                    );
                }
                should_park = true;
            }
        }
    }
    if should_park {
        park_cpu_until_runnable(frame);
    }
}

/// Page-table-validated, PAN-safe copy from an EL0 buffer in `ttbr0` into an EL1 slice via HHDM.
///
/// Walks `ttbr0` for every 4 KiB page spanned by `user_ptr..user_ptr+count`, rejecting any
/// unmapped or non-EL0 page with `Err(SysError::InvalidArgument)` without risking an EL1 abort.
fn copy_from_user(ttbr0: u64, user_ptr: u64, len: u64, dst: &mut [u8]) -> Result<usize, SysError> {
    if len == 0 {
        return Ok(0);
    }
    let end = user_ptr.checked_add(len).ok_or(SysError::InvalidArgument)?;
    if user_ptr == 0 || end >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    spec_barrier();
    let count = (len as usize).min(dst.len());
    if count == 0 {
        return Ok(0);
    }

    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vspace = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);

    let mut copied = 0usize;
    while copied < count {
        let cur_va = user_ptr + copied as u64;
        let va = VirtAddr::new_canonical(cur_va)?;
        let (pa, flags) = vspace.translate(va).ok_or(SysError::InvalidArgument)?;
        if !flags.user {
            return Err(SysError::InvalidArgument);
        }
        let page_rem = (PAGE_SIZE - (cur_va & PAGE_MASK)) as usize;
        let chunk = (count - copied).min(page_rem);
        let src = hhdm.wrapping_add(pa.raw()) as *const u8;
        // SAFETY: `vspace.translate(va)` verified this EL0 page is mapped and `chunk` does not
        // cross the 4 KiB page boundary. Reading via HHDM avoids touching EL0 VA directly (PAN-safe),
        // and `dst` is an EL1 stack slice disjoint from user physical frames.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(copied), chunk);
        }
        copied += chunk;
    }
    Ok(count)
}

/// Out-of-line `DebugWrite` handler using a 1024-byte EL1 stack buffer with UTF-8
/// char-boundary backup when `user_len > 1024` splits a multi-byte codepoint.
#[inline(never)]
fn handle_debug_write(cur_ttbr0: u64, user_ptr: u64, user_len: u64) -> Result<u64, SysError> {
    let mut buf = [0u8; 1024];
    let n = copy_from_user(cur_ttbr0, user_ptr, user_len, &mut buf)?;
    let valid_len = match core::str::from_utf8(&buf[..n]) {
        Ok(_) => n,
        Err(e)
            if user_len > (buf.len() as u64) && e.error_len().is_none() && e.valid_up_to() > 0 =>
        {
            e.valid_up_to()
        }
        Err(_) => return Err(SysError::InvalidArgument),
    };
    let text = core::str::from_utf8(&buf[..valid_len]).map_err(|_| SysError::InvalidArgument)?;
    let mut s = serial::Pl011::new();
    let _ = s.write_str(text);
    Ok(valid_len as u64)
}

/// Tear down an exiting or fatally faulting non-root process (`M4`):
/// wake any waiting reply caller, unmap & reclaim its tracked mappings, clear its `CSpace`,
/// and recycle its scheduler & process slot. Caller MUST hold `DOMAINS` lock.
fn teardown_domain_locked(table: &mut DomainTable, pd_id: usize) {
    let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    table.domains[pd_id].wait_notif_id = 0;
    table.domains[pd_id].wait_notif_mask = 0;
    table.domains[pd_id].sleep_deadline_ticks = None;
    table.set_wait_state(pd_id, IpcWaitState::Runnable, 0);
    if let Some(client) = table.domains[pd_id].reply_target.take()
        && client < MAX_DOMAINS
        && table.domains[client].active
        && table.domains[client].wait == IpcWaitState::WaitingReply
    {
        table.domains[client].frame.x[0] = SysError::InvalidCapability as u64;
        table.domains[client].frame.x[1] = 0;
        table.domains[client].frame.x[2] = 0;
        table.set_wait_state(client, IpcWaitState::Runnable, 0);
        let _ = table.sched.wake_slot(client);
    }

    let ttbr0 = table.domains[pd_id].ttbr0;
    let dying_role = table.domains[pd_id].role;
    let asid = ((pd_id + 1) as u16).max(1);
    table.domains[pd_id].active = false;
    table.domains[pd_id].running_on = None;
    if table.cpu_current[cpu] == Some(pd_id) {
        table.cpu_current[cpu] = None;
    }
    let _ = table.sched.exit_slot(pd_id);
    if pd_id != 0 {
        table.sched.reclaim_slot(pd_id);
        // Lock order: DOMAINS (held) -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        let mut ipc = IPC_STATE.lock();
        let mut untyped = RUNTIME_UNTYPED.lock();
        let mut mappings = FRAME_MAPPINGS.lock();
        // Clear any buffered `IpcCall` sent by this dying process so endpoints never jam.
        ipc.clear_buffered_calls_from(pd_id);
        // Drain `FRAME_MAPPINGS` entries for `ttbr0` first so shared-frame checks stay accurate,
        // then walk the full EL0 page-table hierarchy (`L0[0..256]` -> `L1` -> `L2` -> `L3`) to
        // zero and reclaim every ELF, stack, shadow-stack, `MapPage`, and page-table frame.
        let mut batch = [None; 8];
        while mappings.drain_for_vspace(PhysAddr::new(ttbr0), &mut batch) > 0 {}
        // Quiesce VirtIO-MMIO DMA engines (`REG_STATUS = 0`) BEFORE reclaiming the dying
        // driver domain's physical frames so QEMU/hardware cannot DMA into freed page tables.
        if IS_QEMU_VIRT.load(Ordering::Acquire) {
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
        let mut vs = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
        vs.reclaim_all_user_frames(|frame, is_table| {
            if is_table {
                let _ = untyped.reclaim_frame(frame);
            } else {
                let pa = frame.start_addr();
                if !ipc.has_live_frame_cap(pa)
                    && !mappings.has_mapping_for_phys(pa)
                    && !mappings.is_dma_pinned(pa)
                {
                    let zeroer = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
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
                let vs = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                vs.zero_frame(&frame);
                mappings.clear_ever_written(phys);
                let _ = untyped.reclaim_frame(frame);
            }
        });
        drop(mappings);
        drop(untyped);
        // Wake any peers blocked on endpoints/notifications that lost their server or last cap (`M19`).
        for other in 0..MAX_DOMAINS {
            if !table.domains[other].active {
                continue;
            }
            let ep_dead = match table.domains[other].wait {
                IpcWaitState::WaitingReply => {
                    !ipc.has_live_endpoint_server(table.domains[other].wait_ep_id)
                }
                IpcWaitState::WaitingRecv => {
                    !ipc.has_live_endpoint_cap(table.domains[other].wait_ep_id)
                }
                _ => false,
            };
            let notif_dead = table.domains[other].wait == IpcWaitState::WaitingNotif
                && !ipc.has_live_notif_cap(table.domains[other].wait_notif_id);
            if ep_dead || notif_dead {
                table.domains[other].frame.x[0] = SysError::InvalidCapability as u64;
                table.domains[other].frame.x[1] = 0;
                table.domains[other].frame.x[2] = 0;
                table.domains[other].wait_notif_id = 0;
                table.domains[other].wait_notif_mask = 0;
                table.domains[other].sleep_deadline_ticks = None;
                table.set_wait_state(other, IpcWaitState::Runnable, 0);
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
        super::paging::tlbi_asid(asid);
    }
}

const MAX_SUPERVISOR_RESPAWNS: u64 = 5;
static SUPERVISOR_RESPAWN_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(not(feature = "userspace"))]
fn respawn_supervisor_fresh_vspace(_frame: &mut TrapFrame) -> bool {
    false
}

/// Reload PD 0 (`supervisor-pd`) from its immutable boot ELF into a brand-new `TTBR0_EL1` VSpace
/// with fresh ASLR slides while preserving PD 0's `CSpace` (zero disruption to running child PDs),
/// reclaiming all frames of the old PD 0 VSpace, and signaling `SUPERVISOR_RESPAWNED_BIT`.
#[cfg(feature = "userspace")]
fn respawn_supervisor_fresh_vspace(frame: &mut TrapFrame) -> bool {
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
    let entropy = super::next_aslr_entropy();
    let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
    let pie_base = 0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
    let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let loaded = {
        let mut untyped = RUNTIME_UNTYPED.lock();
        let root_vs = super::paging::Aarch64VSpace::from_current_ttbr1(hhdm);
        root_vs.new_user_vspace(&mut untyped).and_then(|mut vs| {
            match newos_kernel_core::load_elf64_into_vspace(
                &mut vs,
                elf_bytes,
                &mut untyped,
                pie_base,
                stack_slide,
                shadow_slide,
                USER_STACK_PAGES,
            ) {
                Ok((entry, user_sp, user_shadow_sp, _segs)) => {
                    Ok((entry, user_sp, user_shadow_sp, vs.root_phys()))
                }
                Err(e) => {
                    vs.reclaim_all_user_frames(|fr, _is_table| {
                        let _ = untyped.reclaim_frame(fr);
                    });
                    Err(e)
                }
            }
        })
    };
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
    super::paging::tlbi_asid(1);
    restore_fp_state(&FpState::ZERO);
    write_tpidr_el0(0);

    {
        // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
        let mut table = DOMAINS.lock();
        let old_ttbr0 = table.domains[0].ttbr0;
        table.domains[0].ttbr0 = new_ttbr0;
        table.domains[0].fault_pc = 0;
        table.domains[0].fault_sp = 0;
        table.domains[0].shadow_sp = user_shadow_sp.raw();
        table.domains[0].tpidr_el0 = 0;
        table.domains[0].fp = FpState::ZERO;
        table.domains[0].wait = IpcWaitState::Runnable;
        table.domains[0].wait_ep_id = 0;
        table.domains[0].wait_notif_id = 0;
        table.domains[0].wait_notif_mask = 0;
        table.domains[0].sleep_deadline_ticks = None;
        table.domains[0].frame = new_frame;

        let mut ipc = IPC_STATE.lock();
        let _ = ipc.bind_bootstrap_vspace(0, new_root);
        let _ = ipc.notify_signal_id(1, newos_abi::supervisor_notif::SUPERVISOR_RESPAWNED_BIT);

        let mut untyped = RUNTIME_UNTYPED.lock();
        let mut mappings = FRAME_MAPPINGS.lock();
        let mut batch = [None; 8];
        while mappings.drain_for_vspace(PhysAddr::new(old_ttbr0), &mut batch) > 0 {}
        let mut old_vs = super::paging::Aarch64VSpace::from_root_phys(old_ttbr0, hhdm);
        old_vs.reclaim_all_user_frames(|fr, is_table| {
            if is_table {
                let _ = untyped.reclaim_frame(fr);
            } else {
                let pa = fr.start_addr();
                if !ipc.has_live_frame_cap(pa)
                    && !mappings.has_mapping_for_phys(pa)
                    && !mappings.is_dma_pinned(pa)
                {
                    let zeroer = super::paging::Aarch64VSpace::from_root_phys(old_ttbr0, hhdm);
                    zeroer.zero_frame(&fr);
                    mappings.clear_ever_written(pa);
                    let _ = untyped.reclaim_frame(fr);
                }
            }
        });
    }

    *frame = new_frame;
    let mut s = serial::Pl011::new();
    let _ = writeln!(
        s,
        "[newos-hal] respawned supervisor-pd (pd=0) into fresh TTBR0_EL1 (ttbr0={new_ttbr0:#018x}, attempt={})",
        prev + 1
    );
    true
}

/// Park this CPU in low-power WFI until another runnable EL0 process can be claimed (`P2`/`P9`).
/// Arms `CNTV_CVAL_EL0` with the earliest `sleep_deadline_ticks` across blocked threads before
/// `wfi` so all-idle timed `SleepUntil`/`NotifyWait` callers never deadlock.
fn park_cpu_until_runnable(frame: &mut TrapFrame) {
    let this_cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    disable_virtual_timer();
    loop {
        // Mask IRQs before checking runnable state and entering `wfi` to close the lost-wakeup
        // window (`P9`): on AArch64, `wfi` wakes on any pending IRQ even when `PSTATE.I == 1`.
        // SAFETY: Masking local IRQs in EL1 around the idle check + `wfi`.
        unsafe {
            asm!("msr daifset, #2", options(nomem, nostack));
        }
        let earliest_deadline: Option<u64>;
        {
            let mut t = DOMAINS.lock();
            let _ = wake_expired_timers_locked(&mut t, read_cntvct());
            if let Some(next) = t.claim_any_runnable(this_cpu) {
                super::smp::mark_ap_idle(this_cpu, false);
                switch_ttbr0(t.domains[next].ttbr0, next);
                write_tpidr_el0(t.domains[next].tpidr_el0);
                restore_fp_state(&t.domains[next].fp);
                *frame = t.domains[next].frame;
                drop(t);
                let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
                arm_virtual_timer(interval);
                // Keep IRQs masked until `eret` atomically restores `SPSR_EL1` (`M5`).
                return;
            }
            let mut min_dl: Option<u64> = None;
            for dom in t.domains.iter().take(t.count.min(MAX_DOMAINS)) {
                if dom.active
                    && let Some(dl) = dom.sleep_deadline_ticks
                {
                    min_dl = Some(match min_dl {
                        Some(cur) => cur.min(dl),
                        None => dl,
                    });
                }
            }
            earliest_deadline = min_dl;
            // Publish idle bit while still holding `DOMAINS` so no concurrent wakeup SGI is lost.
            super::smp::mark_ap_idle(this_cpu, true);
        }
        if let Some(deadline) = earliest_deadline {
            arm_virtual_timer_cval(deadline);
        } else {
            disable_virtual_timer();
        }
        // SAFETY: Low-power WFI with IRQs masked (wakes on pending SGI/IRQ/timer), then unmask to service it.
        unsafe {
            asm!(
                "dsb sy",
                "wfi",
                "msr daifclr, #2",
                "isb",
                options(nomem, nostack),
            );
        }
    }
}

/// Rust handler invoked by `__newos_sync_el0` on any synchronous trap from EL0 (`svc #0` or fault).
pub extern "C" fn sync_el0_dispatch(frame: &mut TrapFrame) {
    let esr: u64;
    // SAFETY: Reading `ESR_EL1` in EL1 synchronous exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;

    if ec != 0x15 {
        // Hardware EL0 fault (e.g., `udf #0` illegal instruction EC=0x00, data/insn abort)
        let (cur_pd, rec_pc, rec_sp, rec_shadow_sp) = {
            let table = DOMAINS.lock();
            let Some(cur) = table.current_for_this_cpu() else {
                super::system_off(ShutdownStatus::Failed);
            };
            if cur < MAX_DOMAINS && table.domains[cur].active {
                (
                    cur,
                    table.domains[cur].fault_pc,
                    table.domains[cur].fault_sp,
                    table.domains[cur].shadow_sp,
                )
            } else {
                (cur, 0, 0, 0)
            }
        };
        if rec_pc != 0 && rec_sp != 0 {
            let mut s = serial::Pl011::new();
            let _ = writeln!(
                s,
                "[newos-hal] caught EL0 fault (EC={:#x}, ELR={:#018x}) -> kernel healthy, redirecting to EL0 supervisor",
                ec, frame.elr_el1
            );
            // Signal fault notification in supervisor PD 0
            let _ = IPC_STATE
                .lock()
                .notify_signal_for(0, CapId::BOOTSTRAP_FAULT_NOTIF, 1u64 << 6);
            // Scrub all GPRs and NEON/FP registers, then restore clean Shadow Call Stack (`x18`).
            frame.x = [0; 31];
            frame.x[18] = rec_shadow_sp;
            restore_fp_state(&FpState::ZERO);
            frame.elr_el1 = rec_pc;
            frame.sp_el0 = rec_sp;
            frame.spsr_el1 = 0;
            return;
        }
        // Non-root EL0 fault without self-handler: record fault diagnostics, tear down ONLY the
        // faulting process (reclaiming all frames), signal `1 << cur_pd` on PD 0's
        // `BOOTSTRAP_FAULT_NOTIF` (`notif_id = 1`), and wake PD 0 if blocked in `NotifyWait`.
        if cur_pd != 0 {
            let mut s = serial::Pl011::new();
            let far: u64;
            // SAFETY: Reading `FAR_EL1` in EL1 synchronous fault handler is architectural.
            unsafe {
                core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack, preserves_flags));
            }
            let _ = writeln!(
                s,
                "[newos-hal] isolated EL0 fault (pd={cur_pd}, EC={:#x}, ELR={:#018x}, FAR={:#018x}) -> notifying supervisor-pd",
                ec, frame.elr_el1, far
            );
            let mut table = DOMAINS.lock();
            let role = table.domains[cur_pd].role;
            table.last_fault[cur_pd] = Some(FaultRecord {
                role,
                esr,
                elr: frame.elr_el1,
                _far: far,
            });
            teardown_domain_locked(&mut table, cur_pd);
            {
                let mut ipc = IPC_STATE.lock();
                let _ = ipc.notify_signal_id(1, 1u64 << (cur_pd & 63));
                let _ = wake_notif_waiter_locked(&mut table, &mut ipc, 1);
                if table.sched.ready_count() == 0 {
                    ipc.drain_buffered_call_senders(|client| {
                        if client < MAX_DOMAINS
                            && table.domains[client].active
                            && table.domains[client].wait == IpcWaitState::WaitingReply
                        {
                            table.domains[client].frame.x[0] = SysError::InvalidCapability as u64;
                            table.domains[client].frame.x[1] = 0;
                            table.domains[client].frame.x[2] = 0;
                            table.set_wait_state(client, IpcWaitState::Runnable, 0);
                            let _ = table.sched.wake_slot(client);
                        }
                    });
                }
            }
            super::smp::wake_idle_aps();
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
        let mut s = serial::Pl011::new();
        let _ = writeln!(
            s,
            "[newos-hal] UNHANDLED EL0 FAULT EC={:#x} ELR={:#018x}",
            ec, frame.elr_el1
        );
        super::system_off(ShutdownStatus::Failed);
    }

    // `svc #0` syscall from EL0: x8 = num, x0..x3 = args, return (err, val) in (x0, x1)
    let Some(syscall) = SyscallNumber::from_u64(frame.x[8]) else {
        frame.x[0] = SysError::Unsupported as u64;
        frame.x[1] = 0;
        return;
    };
    spec_barrier();

    let a0 = frame.x[0];
    let a1 = frame.x[1];
    let a2 = frame.x[2];
    let a3 = frame.x[3];
    let Some((cur_pd, cur_ttbr0)) = ({
        let table = DOMAINS.lock();
        table
            .current_for_this_cpu()
            .filter(|&cur| cur < MAX_DOMAINS && table.domains[cur].active)
            .map(|cur| (cur, table.domains[cur].ttbr0))
    }) else {
        // Fail closed if no active process is recorded for this CPU.
        frame.x[0] = SysError::InvalidArgument as u64;
        frame.x[1] = 0;
        frame.x[2] = 0;
        return;
    };

    let mut ipc_badge_out: u64 = 0;
    let result: Result<u64, SysError> = match syscall {
        SyscallNumber::DebugWrite => {
            let allowed =
                IPC_STATE
                    .lock()
                    .validate_console_for(cur_pd, CapId::new(a0), Rights::WRITE);
            allowed.and_then(|()| handle_debug_write(cur_ttbr0, a1, a2))
        }
        SyscallNumber::Yield => {
            let next_count = YIELD_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            frame.x[0] = 0;
            frame.x[1] = next_count;
            PREEMPT_PENDING.store(false, Ordering::Release);

            let mut table = DOMAINS.lock();
            if let Some(next) = table.pick_next_runnable(cur_pd) {
                context_switch(&mut table, cur_pd, next, frame);
            }
            return;
        }
        SyscallNumber::Exit => {
            match IPC_STATE
                .lock()
                .validate_power_for(cur_pd, CapId::new(a0), Rights::WRITE)
            {
                Ok(()) => {
                    let code = if a1 == ShutdownStatus::Success as u64 {
                        ShutdownStatus::Success
                    } else if a1 == ShutdownStatus::Reboot as u64 {
                        ShutdownStatus::Reboot
                    } else {
                        ShutdownStatus::Failed
                    };
                    super::system_off(code)
                }
                Err(e) => Err(e),
            }
        }
        SyscallNumber::NotifySignal => {
            let mut woke_idle = false;
            let res = {
                // Lock order: DOMAINS -> IPC_STATE.
                let mut table = DOMAINS.lock();
                let mut ipc = IPC_STATE.lock();
                match ipc.resolve_notify_signal_for(cur_pd, CapId::new(a0), a1) {
                    Ok((notif_id, effective)) => match ipc.notify_signal_id(notif_id, effective) {
                        Ok(_) => {
                            woke_idle = wake_notif_waiter_locked(&mut table, &mut ipc, notif_id);
                            Ok(0)
                        }
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            };
            if woke_idle {
                super::smp::wake_idle_aps();
            }
            res
        }
        SyscallNumber::NotifyPoll => IPC_STATE.lock().notify_poll_for(cur_pd, CapId::new(a0)),
        SyscallNumber::IpcSend => {
            let mut table = DOMAINS.lock();
            let mut ipc = IPC_STATE.lock();
            match ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::WRITE) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let cur = cur_pd;
                    // Strictly wake only `WaitingRecv` servers — NEVER hijack `WaitingReply` callers.
                    if let Some(peer) = table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur) {
                        set_ipc_return(&mut table.domains[peer].frame, a1, badge);
                        table.set_wait_state(peer, IpcWaitState::Runnable, 0);
                        let _ = table.sched.wake_slot(peer);
                        Ok(0)
                    } else {
                        ipc.ipc_send_resolved(ep_id, badge, a1, None).map(|()| 0)
                    }
                }
            }
        }
        SyscallNumber::IpcRecv => {
            IPC_STATE
                .lock()
                .ipc_recv_for(cur_pd, CapId::new(a0))
                .map(|msg| {
                    ipc_badge_out = msg.badge;
                    msg.payload
                })
        }
        SyscallNumber::IpcCall => {
            let mut table = DOMAINS.lock();
            let mut ipc = IPC_STATE.lock();
            match ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::WRITE) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let cur = cur_pd;
                    if let Some(server) = table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur)
                        && table.domains[server].running_on.is_none()
                    {
                        drop(ipc);
                        // Mint single-use Reply capability on `server` pointing exclusively to `cur`,
                        // failing and waking any stranded previous caller (`M19`).
                        set_ipc_return(&mut table.domains[server].frame, a1, badge);
                        table.set_wait_state(server, IpcWaitState::Runnable, 0);
                        if let Some(prev_client) = table.domains[server].reply_target.replace(cur)
                            && prev_client != cur
                            && prev_client < MAX_DOMAINS
                            && table.domains[prev_client].active
                            && table.domains[prev_client].wait == IpcWaitState::WaitingReply
                        {
                            table.domains[prev_client].frame.x[0] =
                                SysError::InvalidCapability as u64;
                            table.domains[prev_client].frame.x[1] = 0;
                            table.domains[prev_client].frame.x[2] = 0;
                            table.set_wait_state(prev_client, IpcWaitState::Runnable, 0);
                            let _ = table.sched.wake_slot(prev_client);
                        }
                        table.set_wait_state(cur, IpcWaitState::WaitingReply, ep_id);
                        let _ = table.sched.block_slot(cur);
                        let _ = table.sched.wake_slot(server);
                        context_switch(&mut table, cur, server, frame);
                        return;
                    }
                    let this_cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
                    if table.sched.ready_count() > 0 || table.has_other_running_cpu(this_cpu) {
                        match ipc.ipc_send_resolved(ep_id, badge, a1, Some(cur)) {
                            Ok(()) => {
                                table.set_wait_state(cur, IpcWaitState::WaitingReply, ep_id);
                                let _ = table.sched.block_slot(cur);
                                if let Some(next) = table.pick_next_runnable(cur) {
                                    drop(ipc);
                                    context_switch(&mut table, cur, next, frame);
                                    return;
                                }
                                if table.has_other_running_cpu(this_cpu) {
                                    // True SMP blocking IPC: park `cur` in `WaitingReply` and
                                    // release `DOMAINS` so the peer running on another core can
                                    // receive the buffered message and deliver the reply.
                                    table.domains[cur].frame = *frame;
                                    table.domains[cur].tpidr_el0 = read_tpidr_el0();
                                    save_fp_state(&mut table.domains[cur].fp);
                                    table.domains[cur].running_on = None;
                                    table.cpu_current[this_cpu] = None;
                                    drop(ipc);
                                    drop(table);
                                    park_cpu_until_runnable(frame);
                                    return;
                                }
                                // Roll back buffered message so no orphan remains in the endpoint.
                                let _ = ipc.ipc_recv_resolved(ep_id);
                                table.set_wait_state(cur, IpcWaitState::Runnable, 0);
                                let _ = table.sched.wake_slot(cur);
                                table.sched.mark_running(cur);
                                Err(SysError::WouldBlock)
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        Err(SysError::WouldBlock)
                    }
                }
            }
        }
        SyscallNumber::IpcReplyRecv => {
            let mut table = DOMAINS.lock();
            let mut ipc = IPC_STATE.lock();
            let cur = cur_pd;
            // Server receive right (`Rights::READ`) governs `IpcReplyRecv`; replying consumes
            // the kernel-minted single-use `reply_target` capability rather than endpoint `WRITE`.
            match ipc.lookup_endpoint_for(cur_pd, CapId::new(a0), Rights::READ) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let mut fastpath_client = None;
                    if a2 != 0 {
                        // Consume single-use Reply capability minted during `IpcCall` rendezvous.
                        if let Some(client) = table.domains[cur].reply_target.take()
                            && client < MAX_DOMAINS
                            && table.domains[client].active
                            && table.domains[client].wait == IpcWaitState::WaitingReply
                        {
                            set_ipc_return(&mut table.domains[client].frame, a1, badge);
                            table.set_wait_state(client, IpcWaitState::Runnable, 0);
                            let _ = table.sched.wake_slot(client);
                            fastpath_client = Some(client);
                        }
                        // Stale or absent `reply_target`: do not inject reply into request endpoint;
                        // fall through directly into the `recv` phase below.
                    }
                    match ipc.ipc_recv_resolved(ep_id) {
                        Ok((msg, sender_pid)) => {
                            if let Some(caller) = sender_pid
                                && caller < MAX_DOMAINS
                                && table.domains[caller].active
                                && table.domains[caller].wait == IpcWaitState::WaitingReply
                            {
                                // Never silently overwrite an unanswered reply target (`H3`):
                                // fail-and-wake any stranded previous caller first.
                                if let Some(prev_client) =
                                    table.domains[cur].reply_target.replace(caller)
                                    && prev_client != caller
                                    && prev_client < MAX_DOMAINS
                                    && table.domains[prev_client].active
                                    && table.domains[prev_client].wait == IpcWaitState::WaitingReply
                                {
                                    table.domains[prev_client].frame.x[0] =
                                        SysError::InvalidCapability as u64;
                                    table.domains[prev_client].frame.x[1] = 0;
                                    table.domains[prev_client].frame.x[2] = 0;
                                    table.set_wait_state(prev_client, IpcWaitState::Runnable, 0);
                                    let _ = table.sched.wake_slot(prev_client);
                                }
                            }
                            ipc_badge_out = msg.badge;
                            Ok(msg.payload)
                        }
                        Err(SysError::WouldBlock) => {
                            if let Some(client) = fastpath_client
                                && table.domains[client].running_on.is_none()
                            {
                                drop(ipc);
                                table.set_wait_state(cur, IpcWaitState::WaitingRecv, ep_id);
                                let _ = table.sched.block_slot(cur);
                                context_switch(&mut table, cur, client, frame);
                                return;
                            }
                            if table.sched.ready_count() > 0 {
                                table.set_wait_state(cur, IpcWaitState::WaitingRecv, ep_id);
                                let _ = table.sched.block_slot(cur);
                                if let Some(next) = table.pick_next_runnable(cur) {
                                    drop(ipc);
                                    context_switch(&mut table, cur, next, frame);
                                    return;
                                }
                                table.set_wait_state(cur, IpcWaitState::Runnable, 0);
                                let _ = table.sched.wake_slot(cur);
                                table.sched.mark_running(cur);
                            }
                            Err(SysError::WouldBlock)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
        SyscallNumber::ReadCycles => Ok(read_cycles()),
        SyscallNumber::SetFaultHandler => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT || a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                let mut table = DOMAINS.lock();
                table.domains[cur_pd].fault_pc = a0;
                table.domains[cur_pd].fault_sp = a1;
                Ok(0)
            }
        }
        SyscallNumber::MmioRead32 => IPC_STATE
            .lock()
            .validate_mmio_read32_for(cur_pd, CapId::new(a0), a1)
            .and_then(|phys| {
                let virt = mmio_phys_to_virt(phys.raw()).ok_or(SysError::InvalidArgument)?;
                let ptr = virt as *const u32;
                // SAFETY: `validate_mmio_read32_for` verified rights, alignment, and bounds,
                // and `mmio_phys_to_virt` resolved a verified Device-nGnRnE mapping.
                let val = unsafe { read_volatile(ptr) };
                Ok(u64::from(val))
            }),
        SyscallNumber::MmioWrite32 => IPC_STATE
            .lock()
            .validate_mmio_write32_for(cur_pd, CapId::new(a0), a1)
            .and_then(|phys| {
                let virt = mmio_phys_to_virt(phys.raw()).ok_or(SysError::InvalidArgument)?;
                let ptr = virt as *mut u32;
                // SAFETY: `validate_mmio_write32_for` verified WRITE right, alignment, and bounds,
                // and `mmio_phys_to_virt` resolved a verified Device-nGnRnE mapping.
                unsafe { write_volatile(ptr, a2 as u32) };
                Ok(0)
            }),
        SyscallNumber::DebugRead => IPC_STATE
            .lock()
            .validate_console_for(cur_pd, CapId::new(a0), Rights::READ)
            .and_then(|()| match serial::try_read_byte() {
                Some(b) => Ok(u64::from(b)),
                None => Err(SysError::WouldBlock),
            }),
        SyscallNumber::SysInfo => {
            let allowed = IPC_STATE
                .lock()
                .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
            allowed.map(|()| {
                let domain_count = DOMAINS.lock().active_count() as u64;
                let base = SYS_INFO_PACKED.load(Ordering::Acquire);
                base | ((domain_count & 0xFFFF) << 16)
            })
        }
        SyscallNumber::VirtToPhys => {
            if a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                IPC_STATE
                    .lock()
                    .validate_vspace_for(cur_pd, CapId::new(a0), Rights::READ)
                    .and_then(|root| {
                        let root_phys = if root.raw() != 0 {
                            root.raw()
                        } else {
                            cur_ttbr0
                        };
                        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                        let vspace = super::paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
                        VirtAddr::new_canonical(a1).and_then(|va| {
                            vspace
                                .translate(va)
                                .filter(|(_, flags)| flags.user)
                                .map(|(pa, _)| pa.raw())
                                .ok_or(SysError::InvalidArgument)
                        })
                    })
            }
        }
        SyscallNumber::CapMint => {
            parse_mint_rights_and_badge(a2, a3).and_then(|(rights, badge)| {
                IPC_STATE
                    .lock()
                    .cap_mint_for(cur_pd, CapId::new(a0), a1 as usize, rights, badge)
                    .map(CapId::raw)
            })
        }
        SyscallNumber::CapCopy => IPC_STATE
            .lock()
            .cap_copy_for(cur_pd, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapMove => IPC_STATE
            .lock()
            .cap_move_for(cur_pd, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapDelete => {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            let mut ipc = IPC_STATE.lock();
            let res = ipc
                .cap_delete_for_with_frame_reclaim_cb(
                    cur_pd,
                    CapId::new(a0),
                    |phys, can_reclaim| {
                        // Reclaim physical frame if this was the last Frame capability and no
                        // virtual mappings remain (`M3`).
                        if can_reclaim {
                            let mut untyped = RUNTIME_UNTYPED.lock();
                            let mappings = FRAME_MAPPINGS.lock();
                            if !mappings.has_mapping_for_phys(phys)
                                && let Ok(f) = PhysFrame::from_aligned(phys)
                            {
                                let vs =
                                    super::paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                                vs.zero_frame(&f);
                                let _ = untyped.reclaim_frame(f);
                            }
                        }
                    },
                )
                .map(|()| 0);
            if res.is_ok() {
                cleanup_orphaned_irqs(&ipc);
            }
            res
        }
        SyscallNumber::CapRevoke => {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
            let mut table = DOMAINS.lock();
            let mut ipc = IPC_STATE.lock();
            let res = ipc
                .cap_revoke_for_with_frame_reclaim_cb(
                    cur_pd,
                    CapId::new(a0),
                    |phys, can_reclaim| {
                        let mut reclaimed_frame = None;
                        let mut mappings = [None; 8];
                        loop {
                            let n = FRAME_MAPPINGS.lock().drain_for_phys(phys, &mut mappings);
                            if n == 0 {
                                break;
                            }
                            for m in mappings[..n].iter().flatten() {
                                let mut vs = super::paging::Aarch64VSpace::from_root_phys(
                                    m.vspace_root.raw(),
                                    hhdm,
                                );
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
                                let vs =
                                    super::paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                                if let Some(f) = reclaimed_frame {
                                    vs.zero_frame(&f);
                                    let _ = untyped.reclaim_frame(f);
                                } else if let Ok(f) = PhysFrame::from_aligned(phys) {
                                    vs.zero_frame(&f);
                                    let _ = untyped.reclaim_frame(f);
                                }
                            }
                        }
                    },
                )
                .map(|revoked_count| revoked_count as u64);
            // Wake any threads blocked on endpoints or notifications that no longer have any live capability (`M5`).
            if res.is_ok() {
                for pd_id in 0..MAX_DOMAINS {
                    if !table.domains[pd_id].active {
                        continue;
                    }
                    let ep_gone = matches!(
                        table.domains[pd_id].wait,
                        IpcWaitState::WaitingReply | IpcWaitState::WaitingRecv
                    ) && !ipc.has_live_endpoint_cap(table.domains[pd_id].wait_ep_id);
                    let notif_gone = table.domains[pd_id].wait == IpcWaitState::WaitingNotif
                        && !ipc.has_live_notif_cap(table.domains[pd_id].wait_notif_id);
                    if ep_gone || notif_gone {
                        table.domains[pd_id].frame.x[0] = SysError::InvalidCapability as u64;
                        table.domains[pd_id].frame.x[1] = 0;
                        table.domains[pd_id].frame.x[2] = 0;
                        table.domains[pd_id].wait_notif_id = 0;
                        table.domains[pd_id].wait_notif_mask = 0;
                        table.domains[pd_id].sleep_deadline_ticks = None;
                        table.set_wait_state(pd_id, IpcWaitState::Runnable, 0);
                        let _ = table.sched.wake_slot(pd_id);
                    }
                }
                cleanup_orphaned_irqs(&ipc);
            }
            res
        }
        SyscallNumber::CapGrant => {
            parse_mint_rights_and_badge(a2, a3).and_then(|(rights, badge)| {
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
            })
        }
        SyscallNumber::SetPriority => {
            if a1 > u64::from(u8::MAX) {
                Err(SysError::InvalidArgument)
            } else {
                let target =
                    IPC_STATE
                        .lock()
                        .validate_thread_for(cur_pd, CapId::new(a0), Rights::WRITE);
                match target {
                    Err(e) => Err(e),
                    Ok(target_pd) => {
                        let new_prio = a1 as u8;
                        let mut table = DOMAINS.lock();
                        if target_pd >= table.count {
                            Err(SysError::InvalidArgument)
                        } else if cur_pd != 0
                            && table
                                .sched
                                .tcb(cur_pd)
                                .is_none_or(|tcb| new_prio > tcb.priority)
                        {
                            // Prevent unprivileged priority escalation above caller's MCP ceiling.
                            Err(SysError::InsufficientRights)
                        } else {
                            table.sched.set_priority(target_pd, new_prio).map(|()| 0)
                        }
                    }
                }
            }
        }
        SyscallNumber::MapPage => {
            if a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                let vspace_root =
                    IPC_STATE
                        .lock()
                        .validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE);
                match vspace_root {
                    Err(e) => Err(e),
                    Ok(root) => parse_rights(a2).and_then(|rights| {
                        let flags = PageFlags::new_wx(
                            rights.contains(Rights::WRITE),
                            rights.contains(Rights::EXEC),
                            true,
                            false,
                        );
                        match (VirtAddr::new_page_aligned(a1), flags) {
                            (Ok(va), Ok(page_flags)) => {
                                let root_phys = if root.raw() != 0 {
                                    root.raw()
                                } else {
                                    cur_ttbr0
                                };
                                let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                                let mut vspace =
                                    super::paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
                                // Check occupancy BEFORE carving a frame to prevent unnecessary churn.
                                if vspace.translate(va).is_some() {
                                    Err(SysError::SlotOccupied)
                                } else {
                                    let mut untyped = RUNTIME_UNTYPED.lock();
                                    match untyped.retype_frame() {
                                        Ok(frame) => {
                                            vspace.zero_frame(&frame);
                                            let pa = frame.start_addr();
                                            match vspace.map_4k(va, frame, page_flags, &mut untyped)
                                            {
                                                Ok(()) => {
                                                    if let Err(e) =
                                                        FRAME_MAPPINGS.lock().record_with_flags(
                                                            PhysAddr::new(root_phys),
                                                            va,
                                                            pa,
                                                            page_flags.writable,
                                                            page_flags.executable,
                                                        )
                                                    {
                                                        if let Ok(reclaimed) = vspace.unmap_4k(va) {
                                                            let _ =
                                                                untyped.reclaim_frame(reclaimed);
                                                        }
                                                        return Err(e);
                                                    }
                                                    Ok(0)
                                                }
                                                Err(e) => {
                                                    // Reclaim unmapped frame so errors never leak RAM.
                                                    if let Ok(reclaimed) =
                                                        PhysFrame::from_aligned(pa)
                                                    {
                                                        let _ = untyped.reclaim_frame(reclaimed);
                                                    }
                                                    Err(e)
                                                }
                                            }
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                            }
                            _ => Err(SysError::InvalidArgument),
                        }
                    }),
                }
            }
        }
        SyscallNumber::UnmapPage => {
            if a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                match VirtAddr::new_page_aligned(a1) {
                    Err(e) => Err(e),
                    Ok(va) => {
                        // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
                        // Held across PTE mutation to serialize concurrent SMP `MapPage`/`UnmapPage`.
                        let table = DOMAINS.lock();
                        let ipc = IPC_STATE.lock();
                        match ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE) {
                            Err(e) => Err(e),
                            Ok(root) => {
                                let root_phys = if root.raw() != 0 {
                                    root.raw()
                                } else {
                                    cur_ttbr0
                                };
                                let asid = (0..table.count.min(MAX_DOMAINS))
                                    .find(|&p| {
                                        table.domains[p].active
                                            && table.domains[p].ttbr0 == root_phys
                                    })
                                    .map(|p| ((p + 1) as u16).max(1));
                                drop(table);
                                let mut untyped = RUNTIME_UNTYPED.lock();
                                let mut mappings = FRAME_MAPPINGS.lock();
                                let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                                let mut vspace =
                                    super::paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
                                match vspace.unmap_4k_asid_reclaim(va, asid, &mut untyped) {
                                    Ok((frame, is_device)) => {
                                        if !is_device {
                                            let pa = frame.start_addr();
                                            let _ = mappings.remove(PhysAddr::new(root_phys), va);
                                            if !ipc.has_live_frame_cap(pa)
                                                && !mappings.has_mapping_for_phys(pa)
                                                && !mappings.is_dma_pinned(pa)
                                            {
                                                // Zero exclusively reclaimed physical frame immediately (zero-on-free).
                                                vspace.zero_frame(&frame);
                                                mappings.clear_ever_written(pa);
                                                let _ = untyped.reclaim_frame(frame);
                                            }
                                        }
                                        Ok(0)
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                        }
                    }
                }
            }
        }
        SyscallNumber::UntypedRetype => match ObjectType::from_u64(a1) {
            None => Err(SysError::InvalidArgument),
            Some(ObjectType::IrqHandler) => {
                let irq = (a3 & 0xFFFF) as u16;
                let is_mip = ((a3 >> 16) & 1) != 0;
                IPC_STATE
                    .lock()
                    .untyped_retype_irq_for(cur_pd, CapId::new(a0), a2 as usize, irq, is_mip)
                    .map(CapId::raw)
            }
            Some(obj_type) => {
                let cap_res = {
                    let mut ipc = IPC_STATE.lock();
                    let mut untyped = RUNTIME_UNTYPED.lock();
                    let res = ipc.untyped_retype_for(
                        cur_pd,
                        CapId::new(a0),
                        obj_type,
                        a2 as usize,
                        &mut untyped,
                    );
                    // Zero newly retyped Frame before exposing it to EL0.
                    if let Ok(new_cap) = res
                        && obj_type == ObjectType::Frame
                        && let Ok(phys) = ipc.validate_frame_for(cur_pd, new_cap, Rights::NONE)
                        && let Ok(frame_obj) = PhysFrame::from_aligned(phys)
                    {
                        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                        let vs = super::paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                        vs.zero_frame(&frame_obj);
                    }
                    res
                };
                cap_res.map(CapId::raw)
            }
        },
        SyscallNumber::FrameMap => {
            if a2 == 0 || a2 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                parse_rights(a3).and_then(|req_rights| {
                    let mut frame_req = Rights::READ;
                    if req_rights.contains(Rights::WRITE) {
                        frame_req = frame_req.union(Rights::WRITE);
                    }
                    if req_rights.contains(Rights::EXEC) {
                        frame_req = frame_req.union(Rights::EXEC);
                    }
                    let flags = PageFlags::new_wx(
                        req_rights.contains(Rights::WRITE),
                        req_rights.contains(Rights::EXEC),
                        true,
                        false,
                    )?;
                    let va = VirtAddr::new_page_aligned(a2)?;

                    // Hold locks in strict hierarchy (`IPC_STATE` -> `RUNTIME_UNTYPED` -> `FRAME_MAPPINGS`)
                    // across capability validation, W^X anti-aliasing check, and PTE installation
                    // to eliminate the validate-then-map SMP race (`P8`) and W^X aliasing bypass (`M1`).
                    let ipc = IPC_STATE.lock();
                    let root = ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
                    let phys = ipc.validate_frame_for(cur_pd, CapId::new(a1), frame_req)?;
                    let frame_obj = PhysFrame::from_aligned(phys)?;
                    let root_phys = if root.raw() != 0 {
                        root.raw()
                    } else {
                        cur_ttbr0
                    };
                    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                    let mut vspace = super::paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
                    if vspace.translate(va).is_some() {
                        return Err(SysError::SlotOccupied);
                    }
                    let mut untyped = RUNTIME_UNTYPED.lock();
                    let mut mappings = FRAME_MAPPINGS.lock();
                    if mappings.conflicts_wx(phys, flags.writable, flags.executable) {
                        return Err(SysError::InsufficientRights);
                    }
                    vspace.map_4k(va, frame_obj, flags, &mut untyped)?;
                    if let Err(e) = mappings.record_with_flags(
                        PhysAddr::new(root_phys),
                        va,
                        phys,
                        flags.writable,
                        flags.executable,
                    ) {
                        let _ = vspace.unmap_4k(va);
                        return Err(e);
                    }
                    Ok(0)
                })
            }
        }
        SyscallNumber::TimerFreq => Ok(read_cntfrq()),
        SyscallNumber::ThreadExit => {
            if cur_pd == 0 {
                if respawn_supervisor_fresh_vspace(frame) {
                    return;
                }
                super::system_off(ShutdownStatus::Failed);
            }
            let mut table = DOMAINS.lock();
            teardown_domain_locked(&mut table, cur_pd);
            if let Some(next) = table.pick_next_runnable(cur_pd) {
                context_switch(&mut table, cur_pd, next, frame);
                return;
            }
            if table.has_any_active() {
                // Other processes are still running on other cores or blocked (`P2`/`M2`):
                // park this core in idle instead of powering off the machine!
                drop(table);
                park_cpu_until_runnable(frame);
                return;
            }
            drop(table);
            super::system_off(ShutdownStatus::Success);
        }
        SyscallNumber::IrqAck => IPC_STATE
            .lock()
            .validate_irq_for(cur_pd, CapId::new(a0), Rights::WRITE)
            .map(|(irq, is_mip)| {
                if is_mip {
                    super::gic::set_mip_vector_masked(irq as u8, false);
                } else {
                    super::gic::enable_irq(u32::from(irq));
                }
                u64::from(irq)
            }),
        SyscallNumber::DmaCacheOp => match DmaCacheOp::from_u64(a3) {
            Some(op) => IPC_STATE
                .lock()
                .validate_vspace_for(cur_pd, CapId::new(a0), Rights::READ)
                .and_then(|root| {
                    let target_ttbr0 = if root.raw() != 0 {
                        root.raw()
                    } else {
                        cur_ttbr0
                    };
                    handle_dma_cache_op(target_ttbr0, a1, a2, op)
                }),
            None => Err(SysError::InvalidArgument),
        },
        SyscallNumber::CpuFeatures => IPC_STATE
            .lock()
            .validate_power_for(cur_pd, CapId::new(a0), Rights::READ)
            .map(|()| super::cpu_isa_features()),
        SyscallNumber::NotifyWait => {
            let mask = a1;
            let timeout_ns = a2;
            if mask == 0 {
                Err(SysError::InvalidArgument)
            } else {
                // Step 1 (fastpath): validate and consume matching bits under `IPC_STATE`.
                let fast = {
                    let mut ipc = IPC_STATE.lock();
                    ipc.validate_notification_id_for(cur_pd, CapId::new(a0), Rights::READ)
                        .and_then(|nid| ipc.notify_consume_mask(nid, mask).map(|m| (nid, m)))
                };
                match fast {
                    Err(e) => Err(e),
                    Ok((_, matched)) if matched != 0 => Ok(matched),
                    Ok((notif_id, _)) => {
                        let deadline = if timeout_ns > 0 {
                            let freq = read_cntfrq().max(1);
                            let ticks = ((u128::from(timeout_ns) * u128::from(freq))
                                / 1_000_000_000)
                                .max(1) as u64;
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
                            Err(e) => Err(e),
                            Ok(matched) if matched != 0 => Ok(matched),
                            Ok(_) => {
                                table.domains[cur_pd].wait = IpcWaitState::WaitingNotif;
                                table.domains[cur_pd].wait_notif_id = notif_id;
                                table.domains[cur_pd].wait_notif_mask = mask;
                                table.domains[cur_pd].sleep_deadline_ticks = deadline;
                                let _ = table.sched.block_slot(cur_pd);
                                if let Some(next) = table.pick_next_runnable(cur_pd) {
                                    context_switch(&mut table, cur_pd, next, frame);
                                    return;
                                }
                                let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
                                table.domains[cur_pd].frame = *frame;
                                save_fp_state(&mut table.domains[cur_pd].fp);
                                table.domains[cur_pd].tpidr_el0 = read_tpidr_el0();
                                table.domains[cur_pd].running_on = None;
                                table.cpu_current[cpu] = None;
                                drop(table);
                                park_cpu_until_runnable(frame);
                                return;
                            }
                        }
                    }
                }
            }
        }
        SyscallNumber::IrqBind => match IrqTriggerMode::from_u64(a3) {
            None => Err(SysError::InvalidArgument),
            Some(mode) if a2 >= 64 => {
                let _ = mode;
                Err(SysError::InvalidArgument)
            }
            Some(mode) => {
                let badge_bit = a2 as u8;
                // Lock order: IPC_STATE -> IRQ_TABLE (leaf).
                let ipc = IPC_STATE.lock();
                match ipc.validate_irq_for(cur_pd, CapId::new(a0), Rights::WRITE) {
                    Err(e) => Err(e),
                    Ok((irq, is_mip)) => match ipc.validate_notification_id_for(
                        cur_pd,
                        CapId::new(a1),
                        Rights::WRITE,
                    ) {
                        Err(e) => Err(e),
                        Ok(notif_id) => match irq_table_index(irq, is_mip) {
                            None => Err(SysError::InvalidArgument),
                            Some(idx) => {
                                let mut irq_table = IRQ_TABLE.lock();
                                if irq_table[idx].is_some() {
                                    Err(SysError::SlotOccupied)
                                } else {
                                    irq_table[idx] = Some(IrqBinding {
                                        notif_id,
                                        badge_bit,
                                        is_mip,
                                        irq,
                                    });
                                    let edge = mode == IrqTriggerMode::EdgeRising;
                                    if is_mip {
                                        super::gic::set_mip_vector_masked(irq as u8, false);
                                    } else {
                                        super::gic::configure_spi(u32::from(irq), 0x01, edge, 0x80);
                                        super::gic::enable_irq(u32::from(irq));
                                    }
                                    Ok(0)
                                }
                            }
                        },
                    },
                }
            }
        },
        SyscallNumber::SleepUntil => {
            let deadline = a0;
            if read_cntvct() >= deadline {
                Ok(0)
            } else {
                let mut table = DOMAINS.lock();
                table.domains[cur_pd].wait = IpcWaitState::Sleeping;
                table.domains[cur_pd].sleep_deadline_ticks = Some(deadline);
                let _ = table.sched.block_slot(cur_pd);
                if let Some(next) = table.pick_next_runnable(cur_pd) {
                    context_switch(&mut table, cur_pd, next, frame);
                    return;
                }
                let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
                table.domains[cur_pd].frame = *frame;
                save_fp_state(&mut table.domains[cur_pd].fp);
                table.domains[cur_pd].tpidr_el0 = read_tpidr_el0();
                table.domains[cur_pd].running_on = None;
                table.cpu_current[cpu] = None;
                drop(table);
                park_cpu_until_runnable(frame);
                return;
            }
        }
        SyscallNumber::MmioMap => {
            let vaddr = a2;
            if vaddr == 0 || (vaddr & PAGE_MASK) != 0 || vaddr >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                // Lock order: IPC_STATE -> RUNTIME_UNTYPED.
                let ipc = IPC_STATE.lock();
                let mut untyped = RUNTIME_UNTYPED.lock();
                match ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE) {
                    Err(e) => Err(e),
                    Ok(root) => match ipc.validate_mmio_region_for(cur_pd, CapId::new(a1)) {
                        Err(e) => Err(e),
                        Ok((phys, len, writable)) => {
                            if len == 0
                                || (phys.raw() & PAGE_MASK) != 0
                                || (len & PAGE_MASK) != 0
                                || vaddr
                                    .checked_add(len)
                                    .is_none_or(|end| end > USER_ADDR_LIMIT)
                            {
                                Err(SysError::InvalidArgument)
                            } else {
                                match PageFlags::new_wx(writable, false, true, true) {
                                    Err(e) => Err(e),
                                    Ok(flags) => {
                                        let root_phys = if root.raw() != 0 {
                                            root.raw()
                                        } else {
                                            cur_ttbr0
                                        };
                                        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                                        let mut vspace =
                                            super::paging::Aarch64VSpace::from_root_phys(
                                                root_phys, hhdm,
                                            );
                                        let pages = len / PAGE_SIZE;
                                        let mut mapped = 0u64;
                                        let mut err_out = None;
                                        for i in 0..pages {
                                            let off = i * PAGE_SIZE;
                                            let res = VirtAddr::new_page_aligned(vaddr + off)
                                                .and_then(|va| {
                                                    PhysFrame::from_aligned(PhysAddr::new(
                                                        phys.raw() + off,
                                                    ))
                                                    .and_then(|fr| {
                                                        vspace.map_4k(va, fr, flags, &mut untyped)
                                                    })
                                                });
                                            match res {
                                                Ok(()) => mapped += 1,
                                                Err(e) => {
                                                    err_out = Some(e);
                                                    break;
                                                }
                                            }
                                        }
                                        if let Some(e) = err_out {
                                            for i in 0..mapped {
                                                if let Ok(va) = VirtAddr::new_page_aligned(
                                                    vaddr + i * PAGE_SIZE,
                                                ) {
                                                    let _ = vspace.unmap_4k_asid(va, None);
                                                }
                                            }
                                            Err(e)
                                        } else {
                                            Ok(len)
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
        SyscallNumber::DomainRespawn => {
            #[cfg(not(feature = "userspace"))]
            {
                Err(SysError::Unsupported)
            }
            #[cfg(feature = "userspace")]
            {
                let auth =
                    IPC_STATE
                        .lock()
                        .validate_power_for(cur_pd, CapId::new(a0), Rights::WRITE);
                match auth {
                    Err(e) => Err(e),
                    Ok(()) => match DomainRoleId::from_u64(a1) {
                        None | Some(DomainRoleId::Supervisor) => Err(SysError::InvalidArgument),
                        Some(role_id) => {
                            let role = DomainRole::from_abi(role_id);
                            let already_active = {
                                let table = DOMAINS.lock();
                                (0..table.count.min(MAX_DOMAINS)).any(|p| {
                                    table.domains[p].active && table.domains[p].role == role
                                })
                            };
                            if already_active {
                                Err(SysError::SlotOccupied)
                            } else if let Some(elf_bytes) = find_boot_module(role) {
                                let entropy = super::next_aslr_entropy();
                                let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
                                let pie_base =
                                    0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
                                let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
                                let stack_pages = if matches!(
                                    role,
                                    DomainRole::Net | DomainRole::Key | DomainRole::Ssh
                                ) {
                                    USER_PQ_STACK_PAGES
                                } else {
                                    USER_STACK_PAGES
                                };
                                let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                                let loaded = {
                                    let mut untyped = RUNTIME_UNTYPED.lock();
                                    let root_vs =
                                        super::paging::Aarch64VSpace::from_current_ttbr1(hhdm);
                                    root_vs.new_user_vspace(&mut untyped).and_then(|mut vs| {
                                        let load_res = newos_kernel_core::load_elf64_into_vspace(
                                            &mut vs,
                                            elf_bytes,
                                            &mut untyped,
                                            pie_base,
                                            stack_slide,
                                            shadow_slide,
                                            stack_pages,
                                        );
                                        match load_res {
                                            Ok((entry, user_sp, user_shadow_sp, _segs)) => {
                                                Ok((entry, user_sp, user_shadow_sp, vs.root_phys()))
                                            }
                                            Err(e) => {
                                                vs.reclaim_all_user_frames(|fr, _is_table| {
                                                    let _ = untyped.reclaim_frame(fr);
                                                });
                                                Err(e)
                                            }
                                        }
                                    })
                                };
                                match loaded {
                                    Err(e) => Err(e),
                                    Ok((entry, user_sp, user_shadow_sp, root_phys)) => {
                                        let res = register_domain(
                                            role,
                                            entry.raw(),
                                            user_sp.raw(),
                                            user_shadow_sp.raw(),
                                            root_phys.raw(),
                                        );
                                        match res {
                                            Ok(new_pd) => {
                                                super::paging::tlbi_asid(
                                                    ((new_pd + 1) as u16).max(1),
                                                );
                                                reset_shared_rings_for_role(role);
                                                super::smp::wake_idle_aps();
                                                Ok(new_pd as u64)
                                            }
                                            Err(e) => {
                                                let mut untyped = RUNTIME_UNTYPED.lock();
                                                let mut vs =
                                                    super::paging::Aarch64VSpace::from_root_phys(
                                                        root_phys.raw(),
                                                        hhdm,
                                                    );
                                                vs.reclaim_all_user_frames(|fr, _is_table| {
                                                    let _ = untyped.reclaim_frame(fr);
                                                });
                                                Err(e)
                                            }
                                        }
                                    }
                                }
                            } else {
                                Err(SysError::InvalidArgument)
                            }
                        }
                    },
                }
            }
        }
        SyscallNumber::DomainDestroy => {
            let mut table = DOMAINS.lock();
            let target =
                IPC_STATE
                    .lock()
                    .validate_thread_for(cur_pd, CapId::new(a0), Rights::WRITE);
            match target {
                Err(e) => Err(e),
                Ok(target_pd)
                    if target_pd == 0
                        || target_pd >= MAX_DOMAINS
                        || target_pd == cur_pd
                        || !table.domains[target_pd].active =>
                {
                    Err(SysError::InvalidArgument)
                }
                Ok(target_pd) => {
                    if table.domains[target_pd].running_on.is_some() {
                        // Mark `pending_destroy` + block in scheduler, then SGI remote cores so
                        // `irq_el0_dispatch` immediately deschedules `target_pd` off its core.
                        table.domains[target_pd].pending_destroy = true;
                        let _ = table.sched.block_slot(target_pd);
                        drop(table);
                        super::smp::wake_idle_aps();
                        Err(SysError::WouldBlock)
                    } else {
                        teardown_domain_locked(&mut table, target_pd);
                        Ok(0)
                    }
                }
            }
        }
        SyscallNumber::DomainGetFaultInfo => {
            let pd_id = a1 as usize;
            let mut table = DOMAINS.lock();
            let auth = IPC_STATE
                .lock()
                .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
            match auth {
                Err(e) => Err(e),
                Ok(()) if pd_id >= MAX_DOMAINS => Err(SysError::InvalidArgument),
                Ok(()) => match table.last_fault[pd_id].take() {
                    Some(rec) => {
                        let packed =
                            ((rec.role.to_abi() as u64) << 56) | (rec.esr & 0x00FF_FFFF_FFFF_FFFF);
                        ipc_badge_out = rec.elr;
                        Ok(packed)
                    }
                    None => Err(SysError::InvalidArgument),
                },
            }
        }
        SyscallNumber::MemStats => {
            let auth = IPC_STATE
                .lock()
                .validate_power_for(cur_pd, CapId::new(a0), Rights::READ);
            match auth {
                Err(e) => Err(e),
                Ok(()) => {
                    let untyped = RUNTIME_UNTYPED.lock();
                    ipc_badge_out = untyped.reclaimed_count() as u64;
                    Ok(untyped.remaining_frames())
                }
            }
        }
        SyscallNumber::DmaMap => (|| -> Result<u64, SysError> {
            let flags = a2;
            let opt_vaddr = a3;
            let ipc = IPC_STATE.lock();
            let _iospace_id = ipc.validate_iospace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
            let phys =
                ipc.validate_frame_for(cur_pd, CapId::new(a1), Rights::READ.union(Rights::WRITE))?;
            let mut untyped = RUNTIME_UNTYPED.lock();
            let mut mappings = FRAME_MAPPINGS.lock();
            if (flags & newos_abi::DMA_FLAG_NON_CACHEABLE) != 0 && opt_vaddr != 0 {
                if opt_vaddr >= USER_ADDR_LIMIT {
                    return Err(SysError::InvalidArgument);
                }
                let va = VirtAddr::new_page_aligned(opt_vaddr)?;
                if mappings.conflicts_wx(phys, true, false) {
                    return Err(SysError::InsufficientRights);
                }
                let frame_obj = PhysFrame::from_aligned(phys)?;
                let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                let mut vspace = super::paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
                if vspace.translate(va).is_some() {
                    return Err(SysError::SlotOccupied);
                }
                let nc_flags = PageFlags::new_dma_nc(true, true);
                vspace.map_4k(va, frame_obj, nc_flags, &mut untyped)?;
                if let Err(e) =
                    mappings.record_with_flags(PhysAddr::new(cur_ttbr0), va, phys, true, false)
                {
                    let _ = vspace.unmap_4k(va);
                    return Err(e);
                }
            }
            mappings.pin_dma(phys)?;
            Ok(phys.raw())
        })(),
        SyscallNumber::DmaUnmap => {
            let ipc = IPC_STATE.lock();
            let res = ipc
                .validate_iospace_for(cur_pd, CapId::new(a0), Rights::WRITE)
                .and_then(|_| ipc.validate_frame_for(cur_pd, CapId::new(a1), Rights::READ));
            match res {
                Err(e) => Err(e),
                Ok(phys) => {
                    FRAME_MAPPINGS.lock().unpin_dma(phys);
                    Ok(0)
                }
            }
        }
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

    // Sample hardware-latched Virtual Timer status every 64 syscalls (avoiding unconditional
    // `isb` + `mrs cntvct_el0` + `AcqRel swap` on every non-switching syscall exit).
    let check_timer = (SYSCALL_TICK_COUNTER.fetch_add(1, Ordering::Relaxed) & 0x3F) == 0;
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

/// Load Process 0 (`init`)'s isolated `TTBR0_EL1`, signal secondary Cortex-A76 cores
/// to enter the multi-core EL0 scheduler, and enter EL0 via full `TrapFrame` restore
/// (scrubbing all general registers so no kernel pointers leak to EL0).
pub fn start_userspace() -> ! {
    let (ttbr0, tpidr_el0, init_frame) = {
        let mut table = DOMAINS.lock();
        assert!(table.count > 0 && table.domains[0].active);
        table.domains[0].running_on = Some(0);
        table.cpu_current[0] = Some(0);
        table.sched.mark_running(0);
        (
            table.domains[0].ttbr0,
            table.domains[0].tpidr_el0,
            table.domains[0].frame,
        )
    };

    super::paging::ensure_ttbr0_asid_enabled();
    enable_fp_simd();
    switch_ttbr0(ttbr0, 0);
    write_tpidr_el0(tpidr_el0);
    restore_fp_state(&FpState::ZERO);
    init_preempt_timer();
    super::smp::signal_userspace_ready();

    // SAFETY: `init_frame` is a valid zero-scrubbed `TrapFrame` with EL0t `SPSR_EL1 = 0`,
    // valid `elr_el1`, `sp_el0`, and `x18` (SCS). `__newos_el0_enter_frame` restores all
    // registers `x0..x30` before `eret` without leaking kernel pointers.
    unsafe { __newos_el0_enter_frame(&raw const init_frame) }
}

/// Secondary Cortex-A76 core (AP) EL0 scheduler entry.
///
/// Claims any runnable, unassigned EL0 process from `DOMAINS` and enters EL0 via full
/// `TrapFrame` + `TPIDR_EL0` + FP/SIMD restore (`P3`), or parks in low-power `wfi` with
/// the virtual timer disabled (`P9`) until woken by a GICv2 `SGI_RESCHEDULE` IPI.
pub fn ap_enter_scheduler() -> ! {
    let cpu_id = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    super::paging::ensure_ttbr0_asid_enabled();
    enable_fp_simd();
    disable_virtual_timer();

    loop {
        // Mask IRQs before checking runnable state and entering `wfi` to close the lost-wakeup
        // window (`P9`): `wfi` still wakes on pending IRQs/SGIs when `PSTATE.I == 1`.
        // SAFETY: Masking local IRQs in EL1 around the claim check + `wfi`.
        unsafe {
            asm!("msr daifset, #2", options(nomem, nostack));
        }

        let claimed = {
            let mut table = DOMAINS.lock();
            match table.claim_any_runnable(cpu_id) {
                Some(pd_id) => {
                    super::smp::mark_ap_idle(cpu_id, false);
                    let p = &table.domains[pd_id];
                    Some((pd_id, p.ttbr0, p.tpidr_el0, p.frame, p.fp))
                }
                None => {
                    // Publish idle bit while still holding `DOMAINS` so no wakeup SGI is lost.
                    super::smp::mark_ap_idle(cpu_id, true);
                    None
                }
            }
        };

        if let Some((pd_id, ttbr0, tpidr_el0, saved_frame, fp)) = claimed {
            switch_ttbr0(ttbr0, pd_id);
            write_tpidr_el0(tpidr_el0);
            restore_fp_state(&fp);
            init_preempt_timer();
            // SAFETY: Secondary core holds exclusive `running_on = Some(cpu_id)` ownership
            // of `pd_id` and restores the FULL saved `TrapFrame` (`x0..x30`, `sp_el0`, `elr_el1`,
            // `spsr_el1`) via `__newos_el0_enter_frame` (`P3`).
            unsafe { __newos_el0_enter_frame(&raw const saved_frame) }
        }

        // SAFETY: Park idle secondary Cortex-A76 core in low-power WFI until SGI/IRQ wakes it,
        // then unmask IRQs briefly so the GICv2 SGI handler can acknowledge it.
        unsafe {
            asm!(
                "dsb sy",
                "wfi",
                "msr daifclr, #2",
                "isb",
                options(nomem, nostack),
            );
        }
    }
}
