//! Pure 64-bit ARMv8 EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-process
//! context switching, and EL0 crash isolation / supervisor recovery.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{CAP_MINT_SET_BADGE, CapId, QemuExitCode, Rights, SysError, SyscallNumber};
use newos_kernel_core::ipc::{KernelIpcState, MAX_IPC_PROCS};
use newos_kernel_core::memory::{PageFlags, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr};
use newos_kernel_core::sched::{DEFAULT_PRIORITY, Scheduler};

use super::serial;

const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_PROCS: usize = MAX_IPC_PROCS;
const TTBR0_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

#[inline]
const fn pack_ipc_msg(badge: u64, payload: u64) -> u64 {
    ((badge & 0xFFFF) << 48) | (payload & 0x0000_FFFF_FFFF_FFFF)
}

static YIELD_COUNTER: AtomicU64 = AtomicU64::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
static SYS_INFO_PACKED: AtomicU64 = AtomicU64::new(0);
static IPC_STATE: SyncUnsafeCell<KernelIpcState> = SyncUnsafeCell::new(KernelIpcState::new());
static RUNTIME_UNTYPED: SyncUnsafeCell<UntypedInventory> =
    SyncUnsafeCell::new(UntypedInventory::new());

/// Install remaining bootstrap `UntypedInventory` for runtime `MapPage`/`UnmapPage` syscalls.
pub fn set_untyped_inventory(untyped: UntypedInventory) {
    // SAFETY: Called once on BSP during boot before entering EL0.
    unsafe {
        *RUNTIME_UNTYPED.get() = untyped;
    }
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
        fault_pc: 0,
        fault_sp: 0,
        frame: TrapFrame::ZERO,
    };
}

struct ProcTable {
    procs: [ProcessSlot; MAX_PROCS],
    sched: Scheduler<MAX_PROCS>,
    count: usize,
    current: usize,
}

impl ProcTable {
    const fn new() -> Self {
        Self {
            procs: [ProcessSlot::EMPTY; MAX_PROCS],
            sched: Scheduler::new(),
            count: 0,
            current: 0,
        }
    }

    #[inline]
    fn pick_next_runnable(&mut self, from: usize) -> Option<usize> {
        if self.count <= 1 {
            return None;
        }
        let _ = self.sched.schedule_next()?;
        let next = self.sched.current_slot()?;
        if next != from && self.procs[next].active && self.procs[next].wait == IpcWaitState::Runnable
        {
            Some(next)
        } else {
            None
        }
    }

    #[inline]
    fn find_waiter(&self, state: IpcWaitState, ep_id: u32, exclude: usize) -> Option<usize> {
        for idx in 0..self.count {
            if idx != exclude
                && self.procs[idx].active
                && self.procs[idx].wait == state
                && self.procs[idx].wait_ep_id == ep_id
            {
                return Some(idx);
            }
        }
        None
    }
}

static PROCS: SyncUnsafeCell<ProcTable> = SyncUnsafeCell::new(ProcTable::new());

pub fn init(hhdm_offset: u64, net_mmio: Option<(PhysAddr, u64, u64)>) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Release);
    let cap_region = net_mmio.map(|(phys, virt, len)| {
        NET_MMIO_PHYS.store(phys.raw(), Ordering::Release);
        NET_MMIO_VIRT.store(virt, Ordering::Release);
        NET_MMIO_LEN.store(len, Ordering::Release);
        (phys, len)
    });
    // SAFETY: Single-core BSP bootstrap before entering EL0.
    unsafe {
        let _ = (*IPC_STATE.get()).init_bootstrap_caps(cap_region);
    }
}

#[inline]
fn mmio_phys_to_virt(phys: u64) -> u64 {
    let base_phys = NET_MMIO_PHYS.load(Ordering::Acquire);
    let base_virt = NET_MMIO_VIRT.load(Ordering::Acquire);
    let len = NET_MMIO_LEN.load(Ordering::Acquire);
    if len > 0 && phys >= base_phys && phys < base_phys + len {
        base_virt + (phys - base_phys)
    } else {
        HHDM_OFFSET.load(Ordering::Acquire).wrapping_add(phys)
    }
}

pub fn set_sys_info(online_cpus: usize, interactive_shell: bool) {
    let packed = ((u64::from(interactive_shell)) << 32) | (online_cpus as u64 & 0xFFFF);
    SYS_INFO_PACKED.store(packed, Ordering::Release);
}

pub fn register_user_process(entry_pc: u64, user_sp: u64, ttbr0: u64) -> Result<usize, SysError> {
    // SAFETY: Called on BSP during boot before entering EL0.
    unsafe {
        let table = &mut *PROCS.get();
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
            fault_pc: 0,
            fault_sp: 0,
            frame,
        };
        let _ = table.sched.spawn(DEFAULT_PRIORITY);
        table.count += 1;
        if pid > 0 {
            let _ = (*IPC_STATE.get()).init_worker_bootstrap_caps(pid);
        }
        Ok(pid)
    }
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
fn read_cntvct() -> u64 {
    let v: u64;
    // SAFETY: `CNTVCT_EL0` is always readable in EL1.
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

fn copy_from_user(user_ptr: u64, len: u64, dst: &mut [u8]) -> Result<usize, SysError> {
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
    let src = user_ptr as *const u8;
    // SAFETY: `user_ptr..user_ptr+count` is non-null, overflow-checked, and strictly within
    // lower-half canonical EL0 user space (`< USER_ADDR_LIMIT`) mapped in active `TTBR0_EL1`,
    // while `dst` is an EL1 kernel stack slice in higher-half `TTBR1_EL1`, so regions are disjoint.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), count);
    }
    Ok(count)
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
        // SAFETY: Synchronous exception runs with interrupts masked on BSP.
        let (cur_pid, rec_pc, rec_sp) = unsafe {
            let table = &*PROCS.get();
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
            // SAFETY: Synchronous exception runs with interrupts masked on BSP.
            unsafe {
                let ipc = &mut *IPC_STATE.get();
                // Signal bit 6 (invalid-instruction fault bit matching x86_64 `#UD` contract)
                let _ = ipc.notify_signal_for(cur_pid, CapId::BOOTSTRAP_FAULT_NOTIF, 1u64 << 6);
            }
            frame.elr_el1 = rec_pc;
            frame.sp_el0 = rec_sp;
            frame.spsr_el1 = 0;
            return;
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
    // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
    let ipc = unsafe { &mut *IPC_STATE.get() };
    let cur_pid = unsafe { (*PROCS.get()).current };

    let result: Result<u64, SysError> = match syscall {
        SyscallNumber::DebugWrite => {
            let mut buf = [0u8; 256];
            copy_from_user(a0, a1, &mut buf).and_then(|n| {
                let text = core::str::from_utf8(&buf[..n]).map_err(|_| SysError::InvalidArgument)?;
                let mut s = serial::Pl011::new();
                let _ = s.write_str(text);
                Ok(n as u64)
            })
        }
        SyscallNumber::Yield => {
            let next_count = YIELD_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            frame.x[0] = 0;
            frame.x[1] = next_count;

            // SAFETY: Priority + round-robin switch across runnable hardware `TTBR0_EL1` VSpaces.
            unsafe {
                let table = &mut *PROCS.get();
                let cur = table.current;
                if let Some(next) = table.pick_next_runnable(cur) {
                    table.procs[cur].frame = *frame;
                    table.current = next;
                    switch_ttbr0(table.procs[next].ttbr0, next);
                    *frame = table.procs[next].frame;
                }
            }
            return;
        }
        SyscallNumber::Exit => {
            let code = if a0 == QemuExitCode::Success as u64 {
                QemuExitCode::Success
            } else {
                QemuExitCode::Failed
            };
            super::exit_qemu(code)
        }
        SyscallNumber::NotifySignal => ipc.notify_signal_for(cur_pid, CapId::new(a0), a1).map(|()| 0),
        SyscallNumber::NotifyPoll => ipc.notify_poll_for(cur_pid, CapId::new(a0)),
        SyscallNumber::IpcSend => {
            if let Ok((ep_id, badge)) =
                ipc.lookup_endpoint_for(cur_pid, CapId::new(a0), Rights::WRITE)
            {
                // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                let woken = unsafe {
                    let table = &mut *PROCS.get();
                    let cur = table.current;
                    let waiter = table
                        .find_waiter(IpcWaitState::WaitingRecv, ep_id, cur)
                        .or_else(|| table.find_waiter(IpcWaitState::WaitingReply, ep_id, cur));
                    if let Some(peer) = waiter {
                        table.procs[peer].frame.x[0] = 0;
                        table.procs[peer].frame.x[1] = pack_ipc_msg(badge, a1);
                        table.procs[peer].wait = IpcWaitState::Runnable;
                        table.procs[peer].wait_ep_id = 0;
                        let _ = table.sched.wake_slot(peer);
                        true
                    } else {
                        false
                    }
                };
                if woken {
                    Ok(0)
                } else {
                    ipc.ipc_send_for(cur_pid, CapId::new(a0), a1).map(|()| 0)
                }
            } else {
                ipc.ipc_send_for(cur_pid, CapId::new(a0), a1).map(|()| 0)
            }
        }
        SyscallNumber::IpcRecv => ipc
            .ipc_recv_for(cur_pid, CapId::new(a0))
            .map(|msg| pack_ipc_msg(msg.badge, msg.payload)),
        SyscallNumber::IpcCall => {
            let resolved =
                ipc.lookup_endpoint_for(cur_pid, CapId::new(a0), Rights::WRITE.union(Rights::READ));
            match resolved {
                Err(e) => Err(e),
                Ok((ep_id, badge)) => {
                    // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                    unsafe {
                        let table = &mut *PROCS.get();
                        let cur = table.current;
                        if let Some(server) =
                            table.find_waiter(IpcWaitState::WaitingRecv, ep_id, cur)
                        {
                            table.procs[server].frame.x[0] = 0;
                            table.procs[server].frame.x[1] = pack_ipc_msg(badge, a1);
                            table.procs[server].wait = IpcWaitState::Runnable;
                            table.procs[server].wait_ep_id = 0;
                            table.procs[cur].wait = IpcWaitState::WaitingReply;
                            table.procs[cur].wait_ep_id = ep_id;
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
                            match ipc.ipc_send_for(cur_pid, CapId::new(a0), a1) {
                                Ok(()) => {
                                    table.procs[cur].wait = IpcWaitState::WaitingReply;
                                    table.procs[cur].wait_ep_id = ep_id;
                                    let _ = table.sched.block_slot(cur);
                                    if let Some(next) = table.pick_next_runnable(cur) {
                                        table.procs[cur].frame = *frame;
                                        table.current = next;
                                        switch_ttbr0(table.procs[next].ttbr0, next);
                                        *frame = table.procs[next].frame;
                                        return;
                                    }
                                    table.procs[cur].wait = IpcWaitState::Runnable;
                                    table.procs[cur].wait_ep_id = 0;
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
        }
        SyscallNumber::IpcReplyRecv => {
            if a2 != 0 {
                let resolved = ipc.lookup_endpoint_for(
                    cur_pid,
                    CapId::new(a0),
                    Rights::WRITE.union(Rights::READ),
                );
                match resolved {
                    Err(e) => Err(e),
                    Ok((ep_id, badge)) => {
                        // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                        unsafe {
                            let table = &mut *PROCS.get();
                            let cur = table.current;
                            if let Some(client) =
                                table.find_waiter(IpcWaitState::WaitingReply, ep_id, cur)
                            {
                                table.procs[client].frame.x[0] = 0;
                                table.procs[client].frame.x[1] = pack_ipc_msg(badge, a1);
                                table.procs[client].wait = IpcWaitState::Runnable;
                                table.procs[client].wait_ep_id = 0;
                                table.procs[cur].wait = IpcWaitState::WaitingRecv;
                                table.procs[cur].wait_ep_id = ep_id;
                                let _ = table.sched.block_slot(cur);
                                let _ = table.sched.wake_slot(client);
                                table.sched.select_slot(client);
                                table.procs[cur].frame = *frame;
                                table.current = client;
                                switch_ttbr0(table.procs[client].ttbr0, client);
                                *frame = table.procs[client].frame;
                                return;
                            }
                            // No client parked in WaitingReply (e.g., legacy IpcSend/IpcRecv client):
                            // buffer the reply, then park in WaitingRecv instead of falling through
                            // into ipc_recv on the same endpoint (which would self-consume the reply).
                            match ipc.ipc_send_for(cur_pid, CapId::new(a0), a1) {
                                Ok(()) => {
                                    if table.sched.ready_count() > 0 {
                                        table.procs[cur].wait = IpcWaitState::WaitingRecv;
                                        table.procs[cur].wait_ep_id = ep_id;
                                        let _ = table.sched.block_slot(cur);
                                        if let Some(next) = table.pick_next_runnable(cur) {
                                            table.procs[cur].frame = *frame;
                                            table.current = next;
                                            switch_ttbr0(table.procs[next].ttbr0, next);
                                            *frame = table.procs[next].frame;
                                            return;
                                        }
                                        table.procs[cur].wait = IpcWaitState::Runnable;
                                        table.procs[cur].wait_ep_id = 0;
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
            } else {
                match ipc.ipc_recv_for(cur_pid, CapId::new(a0)) {
                    Ok(msg) => Ok(pack_ipc_msg(msg.badge, msg.payload)),
                    Err(SysError::WouldBlock) => {
                        let resolved = ipc.lookup_endpoint_for(cur_pid, CapId::new(a0), Rights::READ);
                        match resolved {
                            Err(e) => Err(e),
                            Ok((ep_id, _)) => {
                                // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                                unsafe {
                                    let table = &mut *PROCS.get();
                                    let cur = table.current;
                                    if table.sched.ready_count() > 0 {
                                        table.procs[cur].wait = IpcWaitState::WaitingRecv;
                                        table.procs[cur].wait_ep_id = ep_id;
                                        let _ = table.sched.block_slot(cur);
                                        if let Some(next) = table.pick_next_runnable(cur) {
                                            table.procs[cur].frame = *frame;
                                            table.current = next;
                                            switch_ttbr0(table.procs[next].ttbr0, next);
                                            *frame = table.procs[next].frame;
                                            return;
                                        }
                                        table.procs[cur].wait = IpcWaitState::Runnable;
                                        table.procs[cur].wait_ep_id = 0;
                                        let _ = table.sched.wake_slot(cur);
                                        table.sched.select_slot(cur);
                                    }
                                }
                                Err(SysError::WouldBlock)
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
        SyscallNumber::ReadCycles => Ok(read_cntvct()),
        SyscallNumber::SetFaultHandler => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT || a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                unsafe {
                    let table = &mut *PROCS.get();
                    table.procs[cur_pid].fault_pc = a0;
                    table.procs[cur_pid].fault_sp = a1;
                }
                Ok(0)
            }
        }
        SyscallNumber::MmioRead32 => ipc
            .validate_mmio_read32_for(cur_pid, CapId::new(a0), a1)
            .map(|phys| {
                let ptr = mmio_phys_to_virt(phys.raw()) as *const u32;
                // SAFETY: `validate_mmio_read32_for` verified rights, alignment, and bounds.
                let val = unsafe { read_volatile(ptr) };
                u64::from(val)
            }),
        SyscallNumber::MmioWrite32 => ipc
            .validate_mmio_write32_for(cur_pid, CapId::new(a0), a1)
            .map(|phys| {
                let ptr = mmio_phys_to_virt(phys.raw()) as *mut u32;
                // SAFETY: `validate_mmio_write32_for` verified WRITE right, alignment, and bounds.
                unsafe { write_volatile(ptr, a2 as u32) };
                0
            }),
        SyscallNumber::DebugRead => match serial::try_read_byte() {
            Some(b) => Ok(u64::from(b)),
            None => Err(SysError::WouldBlock),
        },
        SyscallNumber::SysInfo => {
            // SAFETY: Reading `PROCS.count` with interrupts masked on BSP.
            let proc_count = unsafe { (*PROCS.get()).count as u64 };
            let base = SYS_INFO_PACKED.load(Ordering::Acquire);
            Ok(base | ((proc_count & 0xFFFF) << 16))
        }
        SyscallNumber::VirtToPhys => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                use newos_kernel_core::memory::{VSpaceMapper, VirtAddr};
                // SAFETY: Reading active process's `ttbr0` with interrupts masked on BSP.
                let ttbr0 = unsafe {
                    let table = &*PROCS.get();
                    table.procs[table.current].ttbr0
                };
                let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                let vspace = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                VirtAddr::new_canonical(a0).and_then(|va| {
                    vspace
                        .translate(va)
                        .filter(|(_, flags)| flags.user)
                        .map(|(pa, _)| pa.raw())
                        .ok_or(SysError::InvalidArgument)
                })
            }
        }
        SyscallNumber::CapMint => {
            let rights = Rights::from_bits_truncate(a2 as u8);
            let badge = if (a2 & CAP_MINT_SET_BADGE) != 0 {
                Some(a3)
            } else {
                None
            };
            ipc.cap_mint_for(cur_pid, CapId::new(a0), a1 as usize, rights, badge)
                .map(CapId::raw)
        }
        SyscallNumber::CapCopy => ipc
            .cap_copy_for(cur_pid, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapMove => ipc
            .cap_move_for(cur_pid, CapId::new(a0), a1 as usize)
            .map(CapId::raw),
        SyscallNumber::CapDelete => ipc.cap_delete_for(cur_pid, CapId::new(a0)).map(|()| 0),
        SyscallNumber::CapRevoke => ipc
            .cap_revoke_for(cur_pid, CapId::new(a0))
            .map(|n| n as u64),
        SyscallNumber::CapGrant => {
            let target_pid = a0 as usize;
            let active_count = unsafe { (*PROCS.get()).count };
            if target_pid >= active_count {
                Err(SysError::InvalidArgument)
            } else {
                let rights = Rights::from_bits_truncate(a2 as u8);
                let badge = if (a2 & CAP_MINT_SET_BADGE) != 0 {
                    Some(a3)
                } else {
                    None
                };
                ipc.cap_grant_between(cur_pid, target_pid, CapId::new(a1), rights, badge)
                    .map(CapId::raw)
            }
        }
        SyscallNumber::SetPriority => {
            let target_pid = if a0 == u64::MAX { cur_pid } else { a0 as usize };
            if target_pid != cur_pid && cur_pid != 0 {
                Err(SysError::InsufficientRights)
            } else if a1 > u64::from(u8::MAX) {
                Err(SysError::InvalidArgument)
            } else {
                // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                unsafe {
                    let table = &mut *PROCS.get();
                    if target_pid >= table.count {
                        Err(SysError::InvalidArgument)
                    } else {
                        table.sched.set_priority(target_pid, a1 as u8).map(|()| 0)
                    }
                }
            }
        }
        SyscallNumber::MapPage => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                let rights = Rights::from_bits_truncate(a1 as u8);
                let flags = PageFlags::new_wx(
                    rights.contains(Rights::WRITE),
                    rights.contains(Rights::EXEC),
                    true,
                    false,
                );
                match (VirtAddr::new_page_aligned(a0), flags) {
                    (Ok(va), Ok(page_flags)) => {
                        let ttbr0 = unsafe {
                            let table = &*PROCS.get();
                            table.procs[table.current].ttbr0
                        };
                        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                        let mut vspace = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                        // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                        let untyped = unsafe { &mut *RUNTIME_UNTYPED.get() };
                        match untyped.retype_frame() {
                            Ok(frame) => {
                                vspace.zero_frame(&frame);
                                let pa = frame.start_addr().raw();
                                match vspace.map_4k(va, frame, page_flags, untyped) {
                                    Ok(()) => Ok(pa),
                                    Err(e) => Err(e),
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => Err(SysError::InvalidArgument),
                }
            }
        }
        SyscallNumber::UnmapPage => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                match VirtAddr::new_page_aligned(a0) {
                    Ok(va) => {
                        let ttbr0 = unsafe {
                            let table = &*PROCS.get();
                            table.procs[table.current].ttbr0
                        };
                        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
                        let mut vspace = super::paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
                        match vspace.unmap_4k(va) {
                            Ok(frame) => {
                                // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
                                let untyped = unsafe { &mut *RUNTIME_UNTYPED.get() };
                                let _ = untyped.reclaim_frame(frame);
                                Ok(0)
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
    };

    match result {
        Ok(val) => {
            frame.x[0] = 0;
            frame.x[1] = val;
        }
        Err(e) => {
            frame.x[0] = e as u64;
            frame.x[1] = 0;
        }
    }
}

/// Load Process 0 (`init`)'s isolated `TTBR0_EL1` and enter EL0 via `eret`.
pub fn start_userspace() -> ! {
    // SAFETY: `PROCS[0]` was registered with valid EL0 `TTBR0_EL1`, entry PC, and stack SP.
    let (ttbr0, entry_pc, user_sp) = unsafe {
        let table = &mut *PROCS.get();
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
