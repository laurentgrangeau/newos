//! Pure 64-bit ARMv8 EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-process
//! context switching, and EL0 crash isolation / supervisor recovery.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::ops::{Deref, DerefMut};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, DmaCacheOp, ObjectType, Rights, ShutdownStatus, SysError,
    SyscallNumber,
};
use newos_kernel_core::ProcessRole;
use newos_kernel_core::ipc::{KernelIpcState, MAX_ENDPOINTS, MAX_IPC_PROCS};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_MASK, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory,
    VSpaceMapper, VirtAddr,
};
use newos_kernel_core::sched::{DEFAULT_PRIORITY, Scheduler};

use super::serial;

const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_PROCS: usize = MAX_IPC_PROCS;
const _: () = assert!(MAX_PROCS <= 8);
const MAX_CPUS: usize = 8;
const MAX_DMA_CACHE_LEN: u64 = 64 * 1024;
const TTBR0_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const CNTV_CTL_ENABLE: u64 = 1 << 0;
const CNTV_CTL_ISTATUS: u64 = 1 << 2;

/// IRQ-disabling spinlock protecting kernel globals across EL0 syscalls, EL0 IRQs, and SMP cores.
///
/// Lock hierarchy (always acquire in this order when holding more than one):
/// `PROCS` -> `IPC_STATE` -> `RUNTIME_UNTYPED` -> `FRAME_MAPPINGS`.
struct IrqSpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `IrqSpinLock` serializes all access with `Acquire`/`Release` atomics and masks local IRQs.
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

struct IrqSpinLockGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    saved_daif: u64,
}

impl<T> IrqSpinLock<T> {
    const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(val),
        }
    }

    #[inline]
    fn lock(&self) -> IrqSpinLockGuard<'_, T> {
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

/// Grant a capability-scoped `MmioRegion` (`R|W`) at `slot` in `init` (PID 0)'s `CSpace`.
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

// SAFETY: `__newos_el0_enter_frame` is defined in `mod.rs` `global_asm!` and restores a valid `TrapFrame` before `eret`.
unsafe extern "C" {
    fn __newos_el0_enter_frame(frame: *const TrapFrame) -> !;
}

/// Install remaining bootstrap `UntypedInventory` for runtime `MapPage`/`UnmapPage` syscalls,
/// binding PID 0's `BOOTSTRAP_UNTYPED` cap to the largest usable physical memory region.
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
}

#[derive(Clone, Copy)]
struct ProcessSlot {
    active: bool,
    ttbr0: u64,
    wait: IpcWaitState,
    wait_ep_id: u32,
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

impl ProcessSlot {
    const EMPTY: Self = Self {
        active: false,
        ttbr0: 0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
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

struct ProcTable {
    procs: [ProcessSlot; MAX_PROCS],
    sched: Scheduler<MAX_PROCS>,
    recv_waiters: [u8; MAX_ENDPOINTS],
    reply_waiters: [u8; MAX_ENDPOINTS],
    count: usize,
    cpu_current: [Option<usize>; MAX_CPUS],
}

impl ProcTable {
    const fn new() -> Self {
        Self {
            procs: [ProcessSlot::EMPTY; MAX_PROCS],
            sched: Scheduler::new(),
            recv_waiters: [0; MAX_ENDPOINTS],
            reply_waiters: [0; MAX_ENDPOINTS],
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
        self.procs.iter().any(|p| p.active)
    }

    #[inline]
    fn active_count(&self) -> usize {
        self.procs.iter().filter(|p| p.active).count()
    }

    #[inline]
    fn set_wait_state(&mut self, pid: usize, new_state: IpcWaitState, new_ep: u32) {
        if pid >= MAX_PROCS {
            return;
        }
        let bit = 1u8 << pid;
        let old_state = self.procs[pid].wait;
        let old_ep = self.procs[pid].wait_ep_id as usize;
        if old_ep < MAX_ENDPOINTS {
            match old_state {
                IpcWaitState::WaitingRecv => self.recv_waiters[old_ep] &= !bit,
                IpcWaitState::WaitingReply => self.reply_waiters[old_ep] &= !bit,
                IpcWaitState::Runnable => {}
            }
        }
        self.procs[pid].wait = new_state;
        self.procs[pid].wait_ep_id = new_ep;
        let new_ep_idx = new_ep as usize;
        if new_ep_idx < MAX_ENDPOINTS {
            match new_state {
                IpcWaitState::WaitingRecv => self.recv_waiters[new_ep_idx] |= bit,
                IpcWaitState::WaitingReply => self.reply_waiters[new_ep_idx] |= bit,
                IpcWaitState::Runnable => {}
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
        for _ in 0..self.count {
            let _ = self.sched.schedule_next()?;
            let next = self.sched.current_slot()?;
            if next != from
                && self.procs[next].active
                && self.procs[next].wait == IpcWaitState::Runnable
                && self.procs[next].running_on.is_none()
            {
                return Some(next);
            }
        }
        None
    }

    #[inline]
    fn claim_any_runnable(&mut self, cpu_id: usize) -> Option<usize> {
        for pid in 0..MAX_PROCS {
            if self.procs[pid].active
                && self.procs[pid].wait == IpcWaitState::Runnable
                && self.procs[pid].running_on.is_none()
            {
                self.procs[pid].running_on = Some(cpu_id);
                self.cpu_current[cpu_id] = Some(pid);
                self.sched.mark_running(pid);
                return Some(pid);
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
            IpcWaitState::Runnable => return None,
        };
        if exclude < MAX_PROCS {
            mask &= !(1u8 << exclude);
        }
        if mask == 0 {
            None
        } else {
            Some(mask.trailing_zeros() as usize)
        }
    }
}

static PROCS: IrqSpinLock<ProcTable> = IrqSpinLock::new(ProcTable::new());

pub fn init(
    hhdm_offset: u64,
    net_mmio: Option<(PhysAddr, u64, u64)>,
    rng_mmio: Option<(PhysAddr, u64, u64)>,
    wdt_mmio: Option<(PhysAddr, u64, u64)>,
    qemu_virt: bool,
    netd_present: bool,
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
    // When `newos-netd` (PID 2) is loaded, omit `BOOTSTRAP_NET_MMIO` from `init` (PID 0)
    // so `netd` is the sole holder of NIC DMA authority.
    let init_net_cap = if netd_present { None } else { cap_region };
    let mut ipc = IPC_STATE.lock();
    let _ = ipc.init_bootstrap_caps(init_net_cap);
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

pub fn register_user_process(
    role: ProcessRole,
    entry_pc: u64,
    user_sp: u64,
    user_shadow_sp: u64,
    ttbr0: u64,
) -> Result<usize, SysError> {
    let mut table = PROCS.lock();
    // Reuse any inactive process slot (`M4`), reserving slot 0 for `ProcessRole::Init`.
    let pid = if role == ProcessRole::Init {
        if table.procs[0].active {
            return Err(SysError::SlotOccupied);
        }
        0
    } else {
        (1..MAX_PROCS)
            .find(|&i| !table.procs[i].active)
            .ok_or(SysError::OutOfMemory)?
    };
    let mut frame = TrapFrame::ZERO;
    frame.x[18] = user_shadow_sp; // AArch64 Shadow Call Stack (`x18`)
    frame.elr_el1 = entry_pc;
    frame.sp_el0 = user_sp;
    frame.spsr_el1 = 0; // EL0t, DAIF unmasked
    table.procs[pid] = ProcessSlot {
        active: true,
        ttbr0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
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
    if pid >= table.count {
        table.count = pid + 1;
    }
    let mut ipc = IPC_STATE.lock();
    // Assign capabilities strictly by explicit `ProcessRole`, NEVER by spawn order / PID (`N5`).
    match role {
        ProcessRole::Init => {
            ipc.bind_bootstrap_vspace(pid, PhysAddr::new(ttbr0))?;
        }
        ProcessRole::Worker => {
            let _ = ipc.init_worker_bootstrap_caps(pid)?;
            let _ = ipc.register_child_caps_in_root(pid)?;
        }
        ProcessRole::Netd => {
            let len = NET_MMIO_LEN.load(Ordering::Acquire);
            let net_cap =
                (len > 0).then(|| (PhysAddr::new(NET_MMIO_PHYS.load(Ordering::Acquire)), len));
            ipc.init_netd_bootstrap_caps(pid, net_cap)?;
            ipc.bind_bootstrap_vspace(pid, PhysAddr::new(ttbr0))?;
            let _ = ipc.register_child_caps_in_root(pid)?;
        }
        ProcessRole::Keyd => {
            let len = RNG_MMIO_LEN.load(Ordering::Acquire);
            let rng_cap =
                (len > 0).then(|| (PhysAddr::new(RNG_MMIO_PHYS.load(Ordering::Acquire)), len));
            let qemu = IS_QEMU_VIRT.load(Ordering::Acquire);
            ipc.init_keyd_bootstrap_caps(pid, rng_cap, qemu)?;
            if qemu {
                ipc.bind_bootstrap_vspace(pid, PhysAddr::new(ttbr0))?;
            }
            let _ = ipc.register_child_caps_in_root(pid)?;
        }
        ProcessRole::Sshd => {
            ipc.init_sshd_bootstrap_caps(pid)?;
            let _ = ipc.register_child_caps_in_root(pid)?;
        }
    }
    Ok(pid)
}

#[inline]
fn switch_ttbr0(ttbr0_phys: u64, pid: usize) {
    let asid = ((pid + 1) as u64) & 0xFFFF;
    let val = (asid << 48) | (ttbr0_phys & TTBR0_ADDR_MASK);
    // SAFETY: `ttbr0_phys` is a verified 4 KiB-aligned EL0 L0 page-table physical address whose
    // user leaf PTEs are tagged with `DESC_NG = 1 << 11`. `TCR_EL1.A1 == 0` routes 16-bit ASID
    // selection through `TTBR0_EL1[63:48]`, isolating per-PID TLB entries without global flushes.
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
fn context_switch(table: &mut ProcTable, from: usize, to: usize, frame: &mut TrapFrame) {
    let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    table.procs[from].frame = *frame;
    table.procs[from].tpidr_el0 = read_tpidr_el0();
    save_fp_state(&mut table.procs[from].fp);
    table.procs[from].running_on = None;
    if table.procs[from].active && table.procs[from].wait == IpcWaitState::Runnable {
        table.sched.mark_ready(from);
    }
    table.procs[to].running_on = Some(cpu);
    table.cpu_current[cpu] = Some(to);
    table.sched.mark_running(to);
    switch_ttbr0(table.procs[to].ttbr0, to);
    write_tpidr_el0(table.procs[to].tpidr_el0);
    restore_fp_state(&table.procs[to].fp);
    *frame = table.procs[to].frame;
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
fn read_cntfrq() -> u64 {
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

/// Rust handler invoked by `__newos_irq_el0` on hardware IRQs (e.g. ARM Generic Timer preemption
/// and peripheral SPIs delivered to EL0 drivers via `BOOTSTRAP_NOTIF` + `IrqAck`).
pub extern "C" fn irq_el0_dispatch(frame: &mut TrapFrame) {
    let iar = super::gic::acknowledge();
    let irq_id = iar.map(|v| v & 0x3FF);
    if (read_cntv_ctl() & CNTV_CTL_ISTATUS) != 0 {
        let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
        arm_virtual_timer(interval);

        let mut table = PROCS.lock();
        if let Some(cur) = table.current_for_this_cpu()
            && table.sched.on_timer_tick_for(cur)
            && let Some(next) = table.pick_next_runnable(cur)
        {
            context_switch(&mut table, cur, next, frame);
            PREEMPT_PENDING.store(false, Ordering::Release);
        }
    } else if let Some(id) = irq_id
        && id >= 32
        && id < 1020
    {
        // External peripheral SPI (`M12`): mask it at the GIC so it does not re-fire until
        // the EL0 driver finishes handling it and calls `IrqAck`, then signal `init`'s notification.
        super::gic::disable_irq(id);
        let bit = 1u64 << (id % 64);
        let _ = IPC_STATE
            .lock()
            .notify_signal_for(0, CapId::BOOTSTRAP_NOTIF, bit);
    }
    if let Some(id) = iar {
        super::gic::end_of_interrupt(id);
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
/// and recycle its scheduler & process slot. Caller MUST hold `PROCS` lock.
fn teardown_process_locked(table: &mut ProcTable, pid: usize) {
    let cpu = (super::get_cpu_id() as usize).min(MAX_CPUS - 1);
    table.set_wait_state(pid, IpcWaitState::Runnable, 0);
    if let Some(client) = table.procs[pid].reply_target.take()
        && client < MAX_PROCS
        && table.procs[client].active
        && table.procs[client].wait == IpcWaitState::WaitingReply
    {
        table.procs[client].frame.x[0] = SysError::InvalidCapability as u64;
        table.procs[client].frame.x[1] = 0;
        table.procs[client].frame.x[2] = 0;
        table.set_wait_state(client, IpcWaitState::Runnable, 0);
        let _ = table.sched.wake_slot(client);
    }

    let ttbr0 = table.procs[pid].ttbr0;
    table.procs[pid].active = false;
    table.procs[pid].running_on = None;
    if table.cpu_current[cpu] == Some(pid) {
        table.cpu_current[cpu] = None;
    }
    let _ = table.sched.exit_slot(pid);
    if pid != 0 {
        table.sched.reclaim_slot(pid);
        // Lock order: PROCS (held) -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        let mut ipc = IPC_STATE.lock();
        let mut untyped = RUNTIME_UNTYPED.lock();
        let mut mappings = FRAME_MAPPINGS.lock();
        let mut batch = [None; 8];
        loop {
            let n = mappings.drain_for_vspace(PhysAddr::new(ttbr0), &mut batch);
            if n == 0 {
                break;
            }
            let mut vs = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
            for m in batch[..n].iter().flatten() {
                if let Ok(frame) = vs.unmap_4k(m.virt)
                    && !ipc.has_live_frame_cap(m.phys)
                    && !mappings.has_mapping_for_phys(m.phys)
                {
                    vs.zero_frame(&frame);
                    let _ = untyped.reclaim_frame(frame);
                }
            }
        }
        let _ = ipc.clear_process_cspace(pid, |phys, can_reclaim| {
            if can_reclaim
                && !mappings.has_mapping_for_phys(phys)
                && let Ok(frame) = PhysFrame::from_aligned(phys)
            {
                let vs = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                vs.zero_frame(&frame);
                let _ = untyped.reclaim_frame(frame);
            }
        });
    }
}

/// Park this CPU in low-power WFI until another runnable EL0 process can be claimed (`P2`/`P9`).
/// Disables the local virtual timer while idle so it never causes a timer-IRQ storm.
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
        {
            let mut t = PROCS.lock();
            if let Some(next) = t.claim_any_runnable(this_cpu) {
                super::smp::mark_ap_idle(this_cpu, false);
                switch_ttbr0(t.procs[next].ttbr0, next);
                write_tpidr_el0(t.procs[next].tpidr_el0);
                restore_fp_state(&t.procs[next].fp);
                *frame = t.procs[next].frame;
                drop(t);
                let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
                arm_virtual_timer(interval);
                // SAFETY: Re-enabling IRQs before returning to EL0.
                unsafe {
                    asm!("msr daifclr, #2", options(nomem, nostack));
                }
                return;
            }
        }
        super::smp::mark_ap_idle(this_cpu, true);
        // SAFETY: Low-power WFI with IRQs masked (wakes on pending SGI/IRQ), then unmask to service it.
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
        let (cur_pid, rec_pc, rec_sp, rec_shadow_sp) = {
            let table = PROCS.lock();
            let Some(cur) = table.current_for_this_cpu() else {
                super::system_off(ShutdownStatus::Failed);
            };
            if cur < MAX_PROCS && table.procs[cur].active {
                (
                    cur,
                    table.procs[cur].fault_pc,
                    table.procs[cur].fault_sp,
                    table.procs[cur].shadow_sp,
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
            // Signal fault notification in supervisor PID 0
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
        // Non-root EL0 fault without self-handler: notify PID 0 supervisor, tear down ONLY the
        // faulting process, and switch to the next runnable process (or idle if others are active).
        if cur_pid != 0 {
            let mut s = serial::Pl011::new();
            let _ = writeln!(
                s,
                "[newos-hal] isolated non-root EL0 fault (pid={cur_pid}, EC={:#x}, ELR={:#018x}) -> notifying supervisor",
                ec, frame.elr_el1
            );
            let _ = IPC_STATE.lock().notify_signal_for(
                0,
                CapId::BOOTSTRAP_FAULT_NOTIF,
                1u64 << (ec.min(63)),
            );
            let mut table = PROCS.lock();
            teardown_process_locked(&mut table, cur_pid);
            if table.sched.ready_count() == 0 {
                // Lock order: `PROCS` -> `IPC_STATE`. No runnable thread remains to ever service
                // a buffered `IpcCall`, so wake any active `WaitingReply` callers with an error.
                let mut ipc = IPC_STATE.lock();
                ipc.drain_buffered_call_senders(|client| {
                    if client < MAX_PROCS
                        && table.procs[client].active
                        && table.procs[client].wait == IpcWaitState::WaitingReply
                    {
                        table.procs[client].frame.x[0] = SysError::InvalidCapability as u64;
                        table.procs[client].frame.x[1] = 0;
                        table.procs[client].frame.x[2] = 0;
                        table.set_wait_state(client, IpcWaitState::Runnable, 0);
                        let _ = table.sched.wake_slot(client);
                    }
                });
            }
            if let Some(next) = table.pick_next_runnable(cur_pid) {
                context_switch(&mut table, cur_pid, next, frame);
                return;
            }
            if table.has_any_active() {
                drop(table);
                park_cpu_until_runnable(frame);
                return;
            }
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
    let Some((cur_pid, cur_ttbr0)) = ({
        let table = PROCS.lock();
        table
            .current_for_this_cpu()
            .filter(|&cur| cur < MAX_PROCS && table.procs[cur].active)
            .map(|cur| (cur, table.procs[cur].ttbr0))
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
                    .validate_console_for(cur_pid, CapId::new(a0), Rights::WRITE);
            allowed.and_then(|()| handle_debug_write(cur_ttbr0, a1, a2))
        }
        SyscallNumber::Yield => {
            let next_count = YIELD_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            frame.x[0] = 0;
            frame.x[1] = next_count;
            PREEMPT_PENDING.store(false, Ordering::Release);

            let mut table = PROCS.lock();
            if let Some(next) = table.pick_next_runnable(cur_pid) {
                context_switch(&mut table, cur_pid, next, frame);
            }
            return;
        }
        SyscallNumber::Exit => {
            match IPC_STATE
                .lock()
                .validate_power_for(cur_pid, CapId::new(a0), Rights::WRITE)
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
        SyscallNumber::NotifySignal => IPC_STATE
            .lock()
            .notify_signal_for(cur_pid, CapId::new(a0), a1)
            .map(|()| 0),
        SyscallNumber::NotifyPoll => IPC_STATE.lock().notify_poll_for(cur_pid, CapId::new(a0)),
        SyscallNumber::IpcSend => {
            let mut table = PROCS.lock();
            let mut ipc = IPC_STATE.lock();
            match ipc.lookup_endpoint_for(cur_pid, CapId::new(a0), Rights::WRITE) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let cur = cur_pid;
                    // Strictly wake only `WaitingRecv` servers — NEVER hijack `WaitingReply` callers.
                    if let Some(peer) = table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur) {
                        set_ipc_return(&mut table.procs[peer].frame, a1, badge);
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
                .ipc_recv_for(cur_pid, CapId::new(a0))
                .map(|msg| {
                    ipc_badge_out = msg.badge;
                    msg.payload
                })
        }
        SyscallNumber::IpcCall => {
            let mut table = PROCS.lock();
            let mut ipc = IPC_STATE.lock();
            match ipc.lookup_endpoint_for(
                cur_pid,
                CapId::new(a0),
                Rights::WRITE.union(Rights::READ),
            ) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let cur = cur_pid;
                    if let Some(server) = table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur)
                        && table.procs[server].running_on.is_none()
                    {
                        drop(ipc);
                        // Mint single-use Reply capability on `server` pointing exclusively to `cur`.
                        set_ipc_return(&mut table.procs[server].frame, a1, badge);
                        table.set_wait_state(server, IpcWaitState::Runnable, 0);
                        table.procs[server].reply_target = Some(cur);
                        table.set_wait_state(cur, IpcWaitState::WaitingReply, ep_id);
                        let _ = table.sched.block_slot(cur);
                        let _ = table.sched.wake_slot(server);
                        table.sched.select_slot(server);
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
                                    // release `PROCS` so the peer running on another core can
                                    // receive the buffered message and deliver the reply.
                                    table.procs[cur].frame = *frame;
                                    table.procs[cur].tpidr_el0 = read_tpidr_el0();
                                    save_fp_state(&mut table.procs[cur].fp);
                                    table.procs[cur].running_on = None;
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
                                table.sched.select_slot(cur);
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
            let mut table = PROCS.lock();
            let mut ipc = IPC_STATE.lock();
            let cur = cur_pid;
            let required = if a2 != 0 {
                Rights::WRITE.union(Rights::READ)
            } else {
                Rights::READ
            };
            match ipc.lookup_endpoint_for(cur_pid, CapId::new(a0), required) {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    let mut fastpath_client = None;
                    if a2 != 0 {
                        // Consume single-use Reply capability minted during `IpcCall` rendezvous.
                        if let Some(client) = table.procs[cur].reply_target.take()
                            && client < MAX_PROCS
                            && table.procs[client].active
                            && table.procs[client].wait == IpcWaitState::WaitingReply
                        {
                            set_ipc_return(&mut table.procs[client].frame, a1, badge);
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
                                && caller < MAX_PROCS
                                && table.procs[caller].active
                                && table.procs[caller].wait == IpcWaitState::WaitingReply
                            {
                                // Never silently overwrite an unanswered reply target (`H3`):
                                // fail-and-wake any stranded previous caller first.
                                if let Some(prev_client) =
                                    table.procs[cur].reply_target.replace(caller)
                                    && prev_client != caller
                                    && prev_client < MAX_PROCS
                                    && table.procs[prev_client].active
                                    && table.procs[prev_client].wait == IpcWaitState::WaitingReply
                                {
                                    table.procs[prev_client].frame.x[0] =
                                        SysError::InvalidCapability as u64;
                                    table.procs[prev_client].frame.x[1] = 0;
                                    table.procs[prev_client].frame.x[2] = 0;
                                    table.set_wait_state(prev_client, IpcWaitState::Runnable, 0);
                                    let _ = table.sched.wake_slot(prev_client);
                                }
                            }
                            ipc_badge_out = msg.badge;
                            Ok(msg.payload)
                        }
                        Err(SysError::WouldBlock) => {
                            if let Some(client) = fastpath_client
                                && table.procs[client].running_on.is_none()
                            {
                                drop(ipc);
                                table.set_wait_state(cur, IpcWaitState::WaitingRecv, ep_id);
                                let _ = table.sched.block_slot(cur);
                                table.sched.select_slot(client);
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
                                table.sched.select_slot(cur);
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
                let mut table = PROCS.lock();
                table.procs[cur_pid].fault_pc = a0;
                table.procs[cur_pid].fault_sp = a1;
                Ok(0)
            }
        }
        SyscallNumber::MmioRead32 => IPC_STATE
            .lock()
            .validate_mmio_read32_for(cur_pid, CapId::new(a0), a1)
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
            .validate_mmio_write32_for(cur_pid, CapId::new(a0), a1)
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
            .validate_console_for(cur_pid, CapId::new(a0), Rights::READ)
            .and_then(|()| match serial::try_read_byte() {
                Some(b) => Ok(u64::from(b)),
                None => Err(SysError::WouldBlock),
            }),
        SyscallNumber::SysInfo => {
            let allowed =
                IPC_STATE
                    .lock()
                    .validate_power_for(cur_pid, CapId::new(a0), Rights::READ);
            allowed.map(|()| {
                let proc_count = PROCS.lock().active_count() as u64;
                let base = SYS_INFO_PACKED.load(Ordering::Acquire);
                base | ((proc_count & 0xFFFF) << 16)
            })
        }
        SyscallNumber::VirtToPhys => {
            if a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                IPC_STATE
                    .lock()
                    .validate_vspace_for(cur_pid, CapId::new(a0), Rights::READ)
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
                    .cap_mint_for(cur_pid, CapId::new(a0), a1 as usize, rights, badge)
                    .map(CapId::raw)
            })
        }
        SyscallNumber::CapCopy => IPC_STATE
            .lock()
            .cap_copy_for(cur_pid, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapMove => IPC_STATE
            .lock()
            .cap_move_for(cur_pid, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapDelete => {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            IPC_STATE
                .lock()
                .cap_delete_for_with_frame_reclaim_cb(
                    cur_pid,
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
                .map(|()| 0)
        }
        SyscallNumber::CapRevoke => {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            // Lock order: PROCS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
            let mut table = PROCS.lock();
            let mut ipc = IPC_STATE.lock();
            let res = ipc
                .cap_revoke_for_with_frame_reclaim_cb(
                    cur_pid,
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
            // Wake any threads blocked on endpoints that no longer have any live capability (`M5`).
            if res.is_ok() {
                for pid in 0..MAX_PROCS {
                    if table.procs[pid].active
                        && table.procs[pid].wait != IpcWaitState::Runnable
                        && !ipc.has_live_endpoint_cap(table.procs[pid].wait_ep_id)
                    {
                        table.procs[pid].frame.x[0] = SysError::InvalidCapability as u64;
                        table.procs[pid].frame.x[1] = 0;
                        table.procs[pid].frame.x[2] = 0;
                        table.set_wait_state(pid, IpcWaitState::Runnable, 0);
                        let _ = table.sched.wake_slot(pid);
                    }
                }
            }
            res
        }
        SyscallNumber::CapGrant => {
            parse_mint_rights_and_badge(a2, a3).and_then(|(rights, badge)| {
                let active_count = PROCS.lock().count;
                IPC_STATE
                    .lock()
                    .cap_grant_between_checked(
                        cur_pid,
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
                        .validate_thread_for(cur_pid, CapId::new(a0), Rights::WRITE);
                match target {
                    Err(e) => Err(e),
                    Ok(target_pid) => {
                        let new_prio = a1 as u8;
                        let mut table = PROCS.lock();
                        if target_pid >= table.count {
                            Err(SysError::InvalidArgument)
                        } else if cur_pid != 0
                            && table
                                .sched
                                .tcb(cur_pid)
                                .is_none_or(|tcb| new_prio > tcb.priority)
                        {
                            // Prevent unprivileged priority escalation above caller's MCP ceiling.
                            Err(SysError::InsufficientRights)
                        } else {
                            table.sched.set_priority(target_pid, new_prio).map(|()| 0)
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
                        .validate_vspace_for(cur_pid, CapId::new(a0), Rights::WRITE);
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
                let vspace_root =
                    IPC_STATE
                        .lock()
                        .validate_vspace_for(cur_pid, CapId::new(a0), Rights::WRITE);
                match vspace_root {
                    Err(e) => Err(e),
                    Ok(root) => match VirtAddr::new_page_aligned(a1) {
                        Ok(va) => {
                            let root_phys = if root.raw() != 0 {
                                root.raw()
                            } else {
                                cur_ttbr0
                            };
                            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                            let mut vspace =
                                super::paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
                            match vspace.unmap_4k(va) {
                                Ok(frame) => {
                                    let pa = frame.start_addr();
                                    // Lock order: IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
                                    let ipc = IPC_STATE.lock();
                                    let mut untyped = RUNTIME_UNTYPED.lock();
                                    let mut mappings = FRAME_MAPPINGS.lock();
                                    let _ = mappings.remove(PhysAddr::new(root_phys), va);
                                    if !ipc.has_live_frame_cap(pa)
                                        && !mappings.has_mapping_for_phys(pa)
                                    {
                                        // Zero exclusively reclaimed physical frame immediately (zero-on-free).
                                        vspace.zero_frame(&frame);
                                        let _ = untyped.reclaim_frame(frame);
                                    }
                                    Ok(0)
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(e),
                    },
                }
            }
        }
        SyscallNumber::UntypedRetype => match ObjectType::from_u64(a1) {
            None => Err(SysError::InvalidArgument),
            Some(obj_type) => {
                let cap_res = {
                    let mut ipc = IPC_STATE.lock();
                    let mut untyped = RUNTIME_UNTYPED.lock();
                    let res = ipc.untyped_retype_for(
                        cur_pid,
                        CapId::new(a0),
                        obj_type,
                        a2 as usize,
                        &mut untyped,
                    );
                    // Zero newly retyped Frame before exposing it to EL0.
                    if let Ok(new_cap) = res
                        && obj_type == ObjectType::Frame
                        && let Ok(phys) = ipc.validate_frame_for(cur_pid, new_cap, Rights::NONE)
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
                    let root = ipc.validate_vspace_for(cur_pid, CapId::new(a0), Rights::WRITE)?;
                    let phys = ipc.validate_frame_for(cur_pid, CapId::new(a1), frame_req)?;
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
            let mut table = PROCS.lock();
            teardown_process_locked(&mut table, cur_pid);
            if let Some(next) = table.pick_next_runnable(cur_pid) {
                context_switch(&mut table, cur_pid, next, frame);
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
            .validate_irq_for(cur_pid, CapId::new(a0), Rights::WRITE)
            .map(|irq| {
                super::gic::enable_irq(u32::from(irq));
                u64::from(irq)
            }),
        SyscallNumber::DmaCacheOp => match DmaCacheOp::from_u64(a3) {
            Some(op) => IPC_STATE
                .lock()
                .validate_vspace_for(cur_pid, CapId::new(a0), Rights::READ)
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
            .validate_power_for(cur_pid, CapId::new(a0), Rights::READ)
            .map(|()| super::cpu_isa_features()),
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
        let mut table = PROCS.lock();
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
        let mut table = PROCS.lock();
        assert!(table.count > 0 && table.procs[0].active);
        table.procs[0].running_on = Some(0);
        table.cpu_current[0] = Some(0);
        table.sched.mark_running(0);
        (
            table.procs[0].ttbr0,
            table.procs[0].tpidr_el0,
            table.procs[0].frame,
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
/// Claims any runnable, unassigned EL0 process from `PROCS` and enters EL0 via full
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
            let mut table = PROCS.lock();
            table.claim_any_runnable(cpu_id).map(|pid| {
                let p = &table.procs[pid];
                (pid, p.ttbr0, p.tpidr_el0, p.frame, p.fp)
            })
        };

        if let Some((pid, ttbr0, tpidr_el0, saved_frame, fp)) = claimed {
            super::smp::mark_ap_idle(cpu_id, false);
            switch_ttbr0(ttbr0, pid);
            write_tpidr_el0(tpidr_el0);
            restore_fp_state(&fp);
            init_preempt_timer();
            // SAFETY: Secondary core holds exclusive `running_on = Some(cpu_id)` ownership
            // of `pid` and restores the FULL saved `TrapFrame` (`x0..x30`, `sp_el0`, `elr_el1`,
            // `spsr_el1`) via `__newos_el0_enter_frame` (`P3`).
            unsafe { __newos_el0_enter_frame(&raw const saved_frame) }
        }

        super::smp::mark_ap_idle(cpu_id, true);
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
