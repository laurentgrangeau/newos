//! Pure 64-bit ARMv8 EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-process
//! context switching, and EL0 crash isolation / supervisor recovery.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::ops::{Deref, DerefMut};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, ObjectType, QemuExitCode, Rights, SysError, SyscallNumber,
};
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
static SYS_INFO_PACKED: AtomicU64 = AtomicU64::new(0);
static TIMER_TICK_INTERVAL: AtomicU64 = AtomicU64::new(625_000);
static SYSCALL_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);
static PREEMPT_PENDING: AtomicBool = AtomicBool::new(false);
static IPC_STATE: IrqSpinLock<KernelIpcState> = IrqSpinLock::new(KernelIpcState::new());
static RUNTIME_UNTYPED: IrqSpinLock<UntypedInventory> = IrqSpinLock::new(UntypedInventory::new());
static FRAME_MAPPINGS: IrqSpinLock<FrameMappingTracker<128>> =
    IrqSpinLock::new(FrameMappingTracker::new());

/// Install remaining bootstrap `UntypedInventory` for runtime `MapPage`/`UnmapPage` syscalls.
pub fn set_untyped_inventory(untyped: UntypedInventory) {
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
    /// Single-use implicit Reply capability minted on `IpcCall` rendezvous, consumed on `IpcReplyRecv`.
    reply_target: Option<usize>,
    fault_pc: u64,
    fault_sp: u64,
    frame: TrapFrame,
}

impl ProcessSlot {
    const EMPTY: Self = Self {
        active: false,
        ttbr0: 0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
        reply_target: None,
        fault_pc: 0,
        fault_sp: 0,
        frame: TrapFrame::ZERO,
    };
}

struct ProcTable {
    procs: [ProcessSlot; MAX_PROCS],
    sched: Scheduler<MAX_PROCS>,
    recv_waiters: [u8; MAX_ENDPOINTS],
    reply_waiters: [u8; MAX_ENDPOINTS],
    count: usize,
    current: usize,
}

impl ProcTable {
    const fn new() -> Self {
        Self {
            procs: [ProcessSlot::EMPTY; MAX_PROCS],
            sched: Scheduler::new(),
            recv_waiters: [0; MAX_ENDPOINTS],
            reply_waiters: [0; MAX_ENDPOINTS],
            count: 0,
            current: 0,
        }
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
    }

    #[inline]
    fn pick_next_runnable(&mut self, from: usize) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        let _ = self.sched.schedule_next()?;
        let next = self.sched.current_slot()?;
        if next != from
            && self.procs[next].active
            && self.procs[next].wait == IpcWaitState::Runnable
        {
            Some(next)
        } else {
            None
        }
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

pub fn init(hhdm_offset: u64, net_mmio: Option<(PhysAddr, u64, u64)>) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Release);
    let cap_region = net_mmio.map(|(phys, virt, len)| {
        NET_MMIO_PHYS.store(phys.raw(), Ordering::Release);
        NET_MMIO_VIRT.store(virt, Ordering::Release);
        NET_MMIO_LEN.store(len, Ordering::Release);
        (phys, len)
    });
    let _ = IPC_STATE.lock().init_bootstrap_caps(cap_region);
}

#[inline]
fn mmio_phys_to_virt(phys: u64) -> Option<u64> {
    let base_phys = NET_MMIO_PHYS.load(Ordering::Acquire);
    let base_virt = NET_MMIO_VIRT.load(Ordering::Acquire);
    let len = NET_MMIO_LEN.load(Ordering::Acquire);
    if len > 0 && phys >= base_phys && phys < base_phys.saturating_add(len) {
        Some(base_virt + (phys - base_phys))
    } else {
        // Never fall back to cacheable HHDM for Device MMIO (`H-5`).
        None
    }
}

pub fn set_sys_info(online_cpus: usize, interactive_shell: bool) {
    let packed = ((u64::from(interactive_shell)) << 32) | (online_cpus as u64 & 0xFFFF);
    SYS_INFO_PACKED.store(packed, Ordering::Release);
}

pub fn register_user_process(entry_pc: u64, user_sp: u64, ttbr0: u64) -> Result<usize, SysError> {
    let mut table = PROCS.lock();
    if table.count >= MAX_PROCS {
        return Err(SysError::OutOfMemory);
    }
    let pid = table.count;
    let mut frame = TrapFrame::ZERO;
    frame.elr_el1 = entry_pc;
    frame.sp_el0 = user_sp;
    frame.spsr_el1 = 0; // EL0t, DAIF unmasked
    table.procs[pid] = ProcessSlot {
        active: true,
        ttbr0,
        wait: IpcWaitState::Runnable,
        wait_ep_id: 0,
        reply_target: None,
        fault_pc: 0,
        fault_sp: 0,
        frame,
    };
    let _ = table.sched.spawn(DEFAULT_PRIORITY);
    table.count += 1;
    let mut ipc = IPC_STATE.lock();
    if pid == 0 {
        let _ = ipc.bind_bootstrap_vspace(0, PhysAddr::new(ttbr0));
    } else {
        let _ = ipc.init_worker_bootstrap_caps(pid);
        let _ = ipc.register_child_caps_in_root(pid);
    }
    Ok(pid)
}

#[inline]
fn switch_ttbr0(ttbr0_phys: u64, pid: usize) {
    let asid = ((pid + 1) as u64) & 0xFF;
    let val = (asid << 48) | (ttbr0_phys & TTBR0_ADDR_MASK);
    // SAFETY: `ttbr0_phys` is a verified 4 KiB-aligned EL0 L0 page-table physical address whose
    // user leaf PTEs are tagged with `DESC_NG = 1 << 11`. `TCR_EL1.A1 == 0` routes ASID selection
    // through `TTBR0_EL1[63:48]`, so each PID (`1..=MAX_PROCS`) isolates its TLB entries without
    // requiring a global `tlbi vmalle1` flush.
    unsafe {
        asm!(
            "msr ttbr0_el1, {val}",
            "isb",
            val = in(reg) val,
            options(nostack),
        );
    }
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

/// Rust handler invoked by `__newos_irq_el0` on hardware IRQs (e.g. ARM Generic Timer preemption).
pub extern "C" fn irq_el0_dispatch(frame: &mut TrapFrame) {
    if (read_cntv_ctl() & CNTV_CTL_ISTATUS) != 0 {
        let interval = TIMER_TICK_INTERVAL.load(Ordering::Acquire);
        arm_virtual_timer(interval);

        let mut table = PROCS.lock();
        if table.sched.on_timer_tick() {
            let cur = table.current;
            if let Some(next) = table.pick_next_runnable(cur) {
                table.procs[cur].frame = *frame;
                table.current = next;
                switch_ttbr0(table.procs[next].ttbr0, next);
                *frame = table.procs[next].frame;
                PREEMPT_PENDING.store(false, Ordering::Release);
            }
        }
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
        let (cur_pid, rec_pc, rec_sp) = {
            let table = PROCS.lock();
            let cur = table.current;
            if cur < table.count {
                (cur, table.procs[cur].fault_pc, table.procs[cur].fault_sp)
            } else {
                (cur, 0, 0)
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
            frame.elr_el1 = rec_pc;
            frame.sp_el0 = rec_sp;
            frame.spsr_el1 = 0;
            return;
        }
        // Non-root EL0 fault without self-handler: notify PID 0 supervisor, wake any WaitingReply
        // client, terminate ONLY the faulting process, and switch to the next runnable process.
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
            table.set_wait_state(cur_pid, IpcWaitState::Runnable, 0);
            if let Some(client) = table.procs[cur_pid].reply_target.take()
                && client < table.count
                && table.procs[client].active
                && table.procs[client].wait == IpcWaitState::WaitingReply
            {
                table.procs[client].frame.x[0] = SysError::InvalidCapability as u64;
                table.procs[client].frame.x[1] = 0;
                table.procs[client].frame.x[2] = 0;
                table.set_wait_state(client, IpcWaitState::Runnable, 0);
                let _ = table.sched.wake_slot(client);
            }
            table.procs[cur_pid].active = false;
            let _ = table.sched.exit_slot(cur_pid);
            if table.sched.ready_count() == 0 {
                // Lock order: `PROCS` -> `IPC_STATE`. No runnable thread remains to ever service
                // a buffered `IpcCall`, so wake any active `WaitingReply` callers with an error.
                let mut ipc = IPC_STATE.lock();
                ipc.drain_buffered_call_senders(|client| {
                    if client < table.count
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
                table.current = next;
                switch_ttbr0(table.procs[next].ttbr0, next);
                *frame = table.procs[next].frame;
                return;
            }
        }
        let mut s = serial::Pl011::new();
        let _ = writeln!(
            s,
            "[newos-hal] UNHANDLED EL0 FAULT EC={:#x} ELR={:#018x}",
            ec, frame.elr_el1
        );
        super::exit_qemu(QemuExitCode::Failed);
    }

    // `svc #0` syscall from EL0: x8 = num, x0..x3 = args, return (err, val) in (x0, x1)
    let Some(syscall) = SyscallNumber::from_u64(frame.x[8]) else {
        frame.x[0] = SysError::Unsupported as u64;
        frame.x[1] = 0;
        return;
    };

    let a0 = frame.x[0];
    let a1 = frame.x[1];
    let a2 = frame.x[2];
    let a3 = frame.x[3];
    let (cur_pid, cur_ttbr0) = {
        let table = PROCS.lock();
        let cur = table.current;
        (cur, table.procs[cur].ttbr0)
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
            let cur = table.current;
            if let Some(next) = table.pick_next_runnable(cur) {
                table.procs[cur].frame = *frame;
                table.current = next;
                switch_ttbr0(table.procs[next].ttbr0, next);
                *frame = table.procs[next].frame;
            }
            return;
        }
        SyscallNumber::Exit => {
            match IPC_STATE
                .lock()
                .validate_power_for(cur_pid, CapId::new(a0), Rights::WRITE)
            {
                Ok(()) => {
                    let code = if a1 == QemuExitCode::Success as u64 {
                        QemuExitCode::Success
                    } else {
                        QemuExitCode::Failed
                    };
                    super::exit_qemu(code)
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
                    let cur = table.current;
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
                    let cur = table.current;
                    if let Some(server) = table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur) {
                        drop(ipc);
                        // Mint single-use Reply capability on `server` pointing exclusively to `cur`.
                        set_ipc_return(&mut table.procs[server].frame, a1, badge);
                        table.set_wait_state(server, IpcWaitState::Runnable, 0);
                        table.procs[server].reply_target = Some(cur);
                        table.set_wait_state(cur, IpcWaitState::WaitingReply, ep_id);
                        let _ = table.sched.block_slot(cur);
                        let _ = table.sched.wake_slot(server);
                        table.sched.select_slot(server);
                        table.procs[cur].frame = *frame;
                        table.current = server;
                        switch_ttbr0(table.procs[server].ttbr0, server);
                        *frame = table.procs[server].frame;
                        return;
                    }
                    if table.sched.ready_count() > 0 {
                        match ipc.ipc_send_resolved(ep_id, badge, a1, Some(cur)) {
                            Ok(()) => {
                                table.set_wait_state(cur, IpcWaitState::WaitingReply, ep_id);
                                let _ = table.sched.block_slot(cur);
                                if let Some(next) = table.pick_next_runnable(cur) {
                                    drop(ipc);
                                    table.procs[cur].frame = *frame;
                                    table.current = next;
                                    switch_ttbr0(table.procs[next].ttbr0, next);
                                    *frame = table.procs[next].frame;
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
            let cur = table.current;
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
                            && client < table.count
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
                                && caller < table.count
                                && table.procs[caller].active
                                && table.procs[caller].wait == IpcWaitState::WaitingReply
                            {
                                table.procs[cur].reply_target = Some(caller);
                            }
                            ipc_badge_out = msg.badge;
                            Ok(msg.payload)
                        }
                        Err(SysError::WouldBlock) => {
                            if let Some(client) = fastpath_client {
                                drop(ipc);
                                table.set_wait_state(cur, IpcWaitState::WaitingRecv, ep_id);
                                let _ = table.sched.block_slot(cur);
                                table.sched.select_slot(client);
                                table.procs[cur].frame = *frame;
                                table.current = client;
                                switch_ttbr0(table.procs[client].ttbr0, client);
                                *frame = table.procs[client].frame;
                                return;
                            }
                            if table.sched.ready_count() > 0 {
                                table.set_wait_state(cur, IpcWaitState::WaitingRecv, ep_id);
                                let _ = table.sched.block_slot(cur);
                                if let Some(next) = table.pick_next_runnable(cur) {
                                    drop(ipc);
                                    table.procs[cur].frame = *frame;
                                    table.current = next;
                                    switch_ttbr0(table.procs[next].ttbr0, next);
                                    *frame = table.procs[next].frame;
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
        SyscallNumber::ReadCycles => Ok(read_cntvct()),
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
                let proc_count = PROCS.lock().count as u64;
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
        SyscallNumber::CapDelete => IPC_STATE
            .lock()
            .cap_delete_for(cur_pid, CapId::new(a0))
            .map(|()| 0),
        SyscallNumber::CapRevoke => {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            IPC_STATE
                .lock()
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
                                if let Some(f) = reclaimed_frame {
                                    let _ = untyped.reclaim_frame(f);
                                } else if let Ok(f) = PhysFrame::from_aligned(phys) {
                                    let _ = untyped.reclaim_frame(f);
                                }
                            }
                        }
                    },
                )
                .map(|revoked_count| revoked_count as u64)
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
                                                    if let Err(e) = FRAME_MAPPINGS.lock().record(
                                                        PhysAddr::new(root_phys),
                                                        va,
                                                        pa,
                                                    ) {
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
                    let frame_req = if req_rights.contains(Rights::WRITE) {
                        Rights::READ.union(Rights::WRITE)
                    } else {
                        Rights::READ
                    };
                    let caps = {
                        let ipc = IPC_STATE.lock();
                        let vs_root =
                            ipc.validate_vspace_for(cur_pid, CapId::new(a0), Rights::WRITE);
                        let fr_phys = ipc.validate_frame_for(cur_pid, CapId::new(a1), frame_req);
                        match (vs_root, fr_phys) {
                            (Ok(r), Ok(p)) => Ok((r, p)),
                            (Err(e), _) | (_, Err(e)) => Err(e),
                        }
                    };
                    match caps {
                        Err(e) => Err(e),
                        Ok((root, phys)) => {
                            let flags = PageFlags::new_wx(
                                req_rights.contains(Rights::WRITE),
                                req_rights.contains(Rights::EXEC),
                                true,
                                false,
                            );
                            match (
                                VirtAddr::new_page_aligned(a2),
                                flags,
                                PhysFrame::from_aligned(phys),
                            ) {
                                (Ok(va), Ok(page_flags), Ok(frame_obj)) => {
                                    let root_phys = if root.raw() != 0 {
                                        root.raw()
                                    } else {
                                        cur_ttbr0
                                    };
                                    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                                    let mut vspace = super::paging::Aarch64VSpace::from_root_phys(
                                        root_phys, hhdm,
                                    );
                                    if vspace.translate(va).is_some() {
                                        Err(SysError::SlotOccupied)
                                    } else {
                                        let mut untyped = RUNTIME_UNTYPED.lock();
                                        vspace
                                            .map_4k(va, frame_obj, page_flags, &mut untyped)
                                            .and_then(|()| {
                                                if let Err(e) = FRAME_MAPPINGS.lock().record(
                                                    PhysAddr::new(root_phys),
                                                    va,
                                                    phys,
                                                ) {
                                                    let _ = vspace.unmap_4k(va);
                                                    return Err(e);
                                                }
                                                Ok(0)
                                            })
                                    }
                                }
                                _ => Err(SysError::InvalidArgument),
                            }
                        }
                    }
                })
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
        let mut table = PROCS.lock();
        let should_preempt = if tick_elapsed {
            table.sched.on_timer_tick()
        } else {
            true
        };
        if should_preempt {
            let cur = table.current;
            if let Some(next) = table.pick_next_runnable(cur) {
                table.procs[cur].frame = *frame;
                table.current = next;
                switch_ttbr0(table.procs[next].ttbr0, next);
                *frame = table.procs[next].frame;
            }
        }
    }
}

/// Load Process 0 (`init`)'s isolated `TTBR0_EL1` and enter EL0 via `eret`.
pub fn start_userspace() -> ! {
    let (ttbr0, entry_pc, user_sp) = {
        let mut table = PROCS.lock();
        assert!(table.count > 0 && table.procs[0].active);
        table.current = 0;
        table.sched.select_slot(0);
        (
            table.procs[0].ttbr0,
            table.procs[0].frame.elr_el1,
            table.procs[0].frame.sp_el0,
        )
    };

    super::paging::ensure_ttbr0_asid_enabled();
    switch_ttbr0(ttbr0, 0);
    init_preempt_timer();

    // SAFETY: `ttbr0` is active, `entry_pc` and `user_sp` point to valid W^X EL0 mappings,
    // and `SPSR_EL1 = 0` transitions cleanly to AArch64 EL0t via `eret`.
    unsafe {
        asm!(
            "msr sp_el0, {user_sp}",
            "msr elr_el1, {entry_pc}",
            "msr spsr_el1, xzr",
            "eret",
            user_sp = in(reg) user_sp,
            entry_pc = in(reg) entry_pc,
            options(noreturn),
        );
    }
}
