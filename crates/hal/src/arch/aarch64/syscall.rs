//! Pure 64-bit ARMv8 EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-process
//! context switching, and EL0 crash isolation / supervisor recovery.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{CapId, QemuExitCode, SysError, SyscallNumber};
use newos_kernel_core::ipc::KernelIpcState;
use newos_kernel_core::memory::PhysAddr;

use super::serial;

const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_PROCS: usize = 4;

static YIELD_COUNTER: AtomicU64 = AtomicU64::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
static NET_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
static SYS_INFO_PACKED: AtomicU64 = AtomicU64::new(0);
static FAULT_RECOVERY_PC: AtomicU64 = AtomicU64::new(0);
static FAULT_RECOVERY_SP: AtomicU64 = AtomicU64::new(0);
static IPC_STATE: SyncUnsafeCell<KernelIpcState> = SyncUnsafeCell::new(KernelIpcState::new());

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

#[derive(Clone, Copy)]
struct ProcessSlot {
    active: bool,
    ttbr0: u64,
    frame: TrapFrame,
}

impl ProcessSlot {
    const EMPTY: Self = Self {
        active: false,
        ttbr0: 0,
        frame: TrapFrame::ZERO,
    };
}

struct ProcTable {
    procs: [ProcessSlot; MAX_PROCS],
    count: usize,
    current: usize,
}

impl ProcTable {
    const fn new() -> Self {
        Self {
            procs: [ProcessSlot::EMPTY; MAX_PROCS],
            count: 0,
            current: 0,
        }
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
            frame,
        };
        table.count += 1;
        Ok(pid)
    }
}

#[inline]
fn switch_ttbr0(ttbr0: u64) {
    // SAFETY: `ttbr0` is a verified 4 KiB-aligned EL0 L0 page-table physical address;
    // `TTBR1_EL1` (kernel) remains untouched and `tlbi vmalle1` flushes stale EL0 TLB entries.
    unsafe {
        asm!(
            "msr ttbr0_el1, {ttbr0}",
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            ttbr0 = in(reg) ttbr0,
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
    let src = user_ptr as *const u8;
    // SAFETY: `user_ptr..user_ptr+count` is validated strictly within canonical EL0 user space
    // mapped in the currently active `TTBR0_EL1`.
    unsafe {
        for (i, slot) in dst.iter_mut().take(count).enumerate() {
            *slot = read_volatile(src.add(i));
        }
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
        let rec_pc = FAULT_RECOVERY_PC.load(Ordering::Acquire);
        let rec_sp = FAULT_RECOVERY_SP.load(Ordering::Acquire);
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
                let _ = ipc.notify_signal(CapId::BOOTSTRAP_FAULT_NOTIF, 1u64 << 6);
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
    // SAFETY: EL1 synchronous handler runs with DAIF masked on BSP.
    let ipc = unsafe { &mut *IPC_STATE.get() };

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
            let next_count = YIELD_COUNTER.fetch_add(1, Ordering::AcqRel) + 1;
            frame.x[0] = 0;
            frame.x[1] = next_count;

            // SAFETY: Cooperative round-robin switch across isolated hardware `TTBR0_EL1` VSpaces.
            unsafe {
                let table = &mut *PROCS.get();
                if table.count > 1 {
                    let cur = table.current;
                    let next = (cur + 1) % table.count;
                    table.procs[cur].frame = *frame;
                    table.current = next;
                    switch_ttbr0(table.procs[next].ttbr0);
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
        SyscallNumber::NotifySignal => ipc.notify_signal(CapId::new(a0), a1).map(|()| 0),
        SyscallNumber::NotifyPoll => ipc.notify_poll(CapId::new(a0)),
        SyscallNumber::IpcSend => ipc.ipc_send(CapId::new(a0), a1).map(|()| 0),
        SyscallNumber::IpcRecv => ipc.ipc_recv(CapId::new(a0)).map(|msg| {
            ((msg.badge & 0xFFFF) << 48) | (msg.payload & 0x0000_FFFF_FFFF_FFFF)
        }),
        SyscallNumber::ReadCycles => Ok(read_cntvct()),
        SyscallNumber::SetFaultHandler => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT || a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                FAULT_RECOVERY_PC.store(a0, Ordering::Release);
                FAULT_RECOVERY_SP.store(a1, Ordering::Release);
                Ok(0)
            }
        }
        SyscallNumber::MmioRead32 => ipc.validate_mmio_read32(CapId::new(a0), a1).map(|phys| {
            let ptr = mmio_phys_to_virt(phys.raw()) as *const u32;
            // SAFETY: `validate_mmio_read32` verified rights, alignment, and bounds.
            let val = unsafe { read_volatile(ptr) };
            u64::from(val)
        }),
        SyscallNumber::MmioWrite32 => ipc.validate_mmio_write32(CapId::new(a0), a1).map(|phys| {
            let ptr = mmio_phys_to_virt(phys.raw()) as *mut u32;
            // SAFETY: `validate_mmio_write32` verified WRITE right, alignment, and bounds.
            unsafe { write_volatile(ptr, frame.x[2] as u32) };
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
        (
            table.procs[0].ttbr0,
            table.procs[0].frame.elr_el1,
            table.procs[0].frame.sp_el0,
        )
    };

    switch_ttbr0(ttbr0);

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
