//! Pure 64-bit `syscall`/`sysretq` fast entry, multi-process hardware `CR3` context switching,
//! SMAP-safe user copy, Ring-3 fault recovery, and capability-scoped MMIO.

use core::arch::{asm, naked_asm};
use core::cell::SyncUnsafeCell;
use core::fmt::Write;
use core::ptr::read_volatile;
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{CapId, QemuExitCode, SysError, SyscallNumber};
use newos_kernel_core::ipc::KernelIpcState;

use super::{gdt, percpu, serial};

const IA32_EFER_MSR: u32 = 0xC000_0080;
const IA32_STAR_MSR: u32 = 0xC000_0081;
const IA32_LSTAR_MSR: u32 = 0xC000_0082;
const IA32_FMASK_MSR: u32 = 0xC000_0084;

const EFER_SCE: u64 = 1 << 0;
// Mask IF (bit 9), DF (bit 10), and AC (bit 18, enforces SMAP on Ring-0 entry)
const SYSCALL_FMASK: u64 = (1 << 9) | (1 << 10) | (1 << 18);

const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
const MAX_PROCS: usize = 4;

static YIELD_COUNTER: AtomicU64 = AtomicU64::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static FAULT_RECOVERY_RIP: AtomicU64 = AtomicU64::new(0);
static FAULT_RECOVERY_RSP: AtomicU64 = AtomicU64::new(0);
static IPC_STATE: SyncUnsafeCell<KernelIpcState> = SyncUnsafeCell::new(KernelIpcState::new());

/// Hardware register frame saved on the Ring-0 kernel stack by `syscall_entry`.
///
/// Exact 12-word (96-byte, 16-byte aligned) layout matching push/pop order in `syscall_entry`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallFrame {
    pub rdi: u64,
    pub rax: u64,
    pub rdx: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl SyscallFrame {
    const ZERO: Self = Self {
        rdi: 0,
        rax: 0,
        rdx: 0,
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        rip: 0,
        rflags: 0x202,
        rsp: 0,
    };
}

#[derive(Clone, Copy)]
struct ProcessSlot {
    active: bool,
    cr3: u64,
    frame: SyscallFrame,
}

impl ProcessSlot {
    const EMPTY: Self = Self {
        active: false,
        cr3: 0,
        frame: SyscallFrame::ZERO,
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

fn program_syscall_msrs() {
    let star: u64 = ((gdt::KERNEL_DS as u64) << 48) | ((gdt::KERNEL_CS as u64) << 32);
    let lstar: u64 = syscall_entry as *const () as u64;

    // SAFETY: Programming architectural x86_64 syscall MSRs in Ring 0 with verified GDT selectors.
    unsafe {
        let efer = percpu::rdmsr(IA32_EFER_MSR);
        percpu::wrmsr(IA32_EFER_MSR, efer | EFER_SCE);
        percpu::wrmsr(IA32_STAR_MSR, star);
        percpu::wrmsr(IA32_LSTAR_MSR, lstar);
        percpu::wrmsr(IA32_FMASK_MSR, SYSCALL_FMASK);
    }
}

/// Enable 64-bit `syscall`/`sysretq` MSRs on BSP and install `init`'s bootstrap IPC capabilities.
pub fn init(hhdm_offset: u64) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Release);
    program_syscall_msrs();

    // SAFETY: Initializing single-core bootstrap IPC state before entering Ring 3.
    unsafe {
        let _ = (*IPC_STATE.get()).init_bootstrap_caps();
    }
}

/// Enable 64-bit `syscall`/`sysretq` MSRs on a secondary (AP) CPU.
pub fn init_ap() {
    program_syscall_msrs();
}

/// Register an isolated Ring-3 process `(entry_rip, user_rsp, cr3)` in the kernel process table.
pub fn register_user_process(entry_rip: u64, user_rsp: u64, cr3: u64) -> Result<usize, SysError> {
    // SAFETY: Called on BSP during boot before entering Ring 3.
    unsafe {
        let table = &mut *PROCS.get();
        if table.count >= MAX_PROCS {
            return Err(SysError::OutOfMemory);
        }
        let pid = table.count;
        let mut frame = SyscallFrame::ZERO;
        frame.rip = entry_rip;
        frame.rsp = user_rsp;
        frame.rflags = 0x202; // IF=1, reserved bit 1=1
        table.procs[pid] = ProcessSlot {
            active: true,
            cr3,
            frame,
        };
        table.count += 1;
        Ok(pid)
    }
}

/// Called from Ring-0 IDT exception handlers when a fault originates in Ring 3 (`CPL == 3`).
pub fn try_recover_user_fault(vector: u8) -> Option<(u64, u64)> {
    let rip = FAULT_RECOVERY_RIP.load(Ordering::Acquire);
    let rsp = FAULT_RECOVERY_RSP.load(Ordering::Acquire);
    if rip == 0 || rsp == 0 {
        return None;
    }

    // SAFETY: Exception handlers run with `IF=0` (interrupt gate) on BSP.
    unsafe {
        let ipc = &mut *IPC_STATE.get();
        let _ = ipc.notify_signal(CapId::BOOTSTRAP_FAULT_NOTIF, 1u64 << (vector as u64));
    }
    Some((rip, rsp))
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is always safe to execute in Ring 0 on x86_64.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
fn write_cr3(cr3: u64) {
    // SAFETY: `cr3` is a verified 4 KiB-aligned PML4 physical address sharing kernel higher-half mappings.
    unsafe {
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Low-level 64-bit `syscall` entry stub saving a full `SyscallFrame` for `CR3` context switches.
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    // SAFETY: Entered directly by CPU `syscall` instruction from Ring 3 with `IA32_FMASK` applied.
    naked_asm!(
        "swapgs",
        "mov gs:[24], rsp",
        "mov rsp, gs:[16]",
        // Push 12-word (96-byte, 16-byte aligned) `SyscallFrame`
        "push qword ptr gs:[24]", // rsp
        "push r11",               // rflags
        "push rcx",               // rip
        "push rbx",               // rbx
        "push rbp",               // rbp
        "push r12",               // r12
        "push r13",               // r13
        "push r14",               // r14
        "push r15",               // r15
        "push rdx",               // rdx
        "push rax",               // rax (syscall number on entry, error on return)
        "push rdi",               // rdi
        // Call `rust_syscall_dispatch(frame: rdi, a0: rsi, a1: rdx, a2: rcx, a3: r8)`
        "mov r8, r10",
        "mov rcx, rdx",
        "mov rdx, rsi",
        "mov rsi, rdi",
        "mov rdi, rsp",
        "call {dispatch}",
        // Restore (possibly context-switched!) `SyscallFrame` and return to Ring 3
        "pop rdi",
        "pop rax",
        "pop rdx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop rcx",
        "pop r11",
        "pop rsp",
        "swapgs",
        "sysretq",
        dispatch = sym rust_syscall_dispatch,
    );
}

/// SMAP-safe bounded copy from a canonical Ring-3 user slice into a Ring-0 stack buffer.
fn copy_from_user_smap(user_ptr: u64, len: u64, dst: &mut [u8]) -> Result<usize, SysError> {
    if len == 0 {
        return Ok(0);
    }
    let end = user_ptr.checked_add(len).ok_or(SysError::InvalidArgument)?;
    if user_ptr == 0 || end >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let count = (len as usize).min(dst.len());
    let src = user_ptr as *const u8;

    // SAFETY: `user_ptr..user_ptr+count` is validated strictly within canonical Ring-3 user space.
    // `stac`/`clac` temporarily bracket the copy so SMAP remains strictly enforced everywhere else.
    unsafe {
        asm!("stac", options(nomem, nostack));
        for (i, slot) in dst.iter_mut().take(count).enumerate() {
            *slot = read_volatile(src.add(i));
        }
        asm!("clac", options(nomem, nostack));
    }
    Ok(count)
}

extern "C" fn rust_syscall_dispatch(
    frame: &mut SyscallFrame,
    a0: u64,
    a1: u64,
    _a2: u64,
    _a3: u64,
) {
    let Some(syscall) = SyscallNumber::from_u64(frame.rax) else {
        frame.rax = SysError::Unsupported as u64;
        frame.rdx = 0;
        return;
    };

    // SAFETY: `syscall_entry` runs with `IF=0` on BSP, giving exclusive access to `IPC_STATE` & `PROCS`.
    let ipc = unsafe { &mut *IPC_STATE.get() };

    let result: Result<u64, SysError> = match syscall {
        SyscallNumber::DebugWrite => {
            let mut buf = [0u8; 256];
            copy_from_user_smap(a0, a1, &mut buf).and_then(|n| {
                let text = core::str::from_utf8(&buf[..n]).map_err(|_| SysError::InvalidArgument)?;
                let mut s = serial::SerialPort::new();
                let _ = s.write_str(text);
                Ok(n as u64)
            })
        }
        SyscallNumber::Yield => {
            let next_count = YIELD_COUNTER.fetch_add(1, Ordering::AcqRel) + 1;
            // Write return values into the yielding process's frame before context-switching
            frame.rax = 0;
            frame.rdx = next_count;

            // SAFETY: Single-core BSP cooperative round-robin switch across isolated CR3 address spaces.
            unsafe {
                let table = &mut *PROCS.get();
                if table.count > 1 {
                    let cur = table.current;
                    let next = (cur + 1) % table.count;
                    table.procs[cur].frame = *frame;
                    table.current = next;
                    write_cr3(table.procs[next].cr3);
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
        SyscallNumber::ReadCycles => Ok(rdtsc()),
        SyscallNumber::SetFaultHandler => {
            if a0 == 0 || a0 >= USER_ADDR_LIMIT || a1 == 0 || a1 >= USER_ADDR_LIMIT {
                Err(SysError::InvalidArgument)
            } else {
                FAULT_RECOVERY_RIP.store(a0, Ordering::Release);
                FAULT_RECOVERY_RSP.store(a1, Ordering::Release);
                Ok(0)
            }
        }
        SyscallNumber::MmioRead32 => ipc.validate_mmio_read32(CapId::new(a0), a1).map(|phys| {
            let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
            let ptr = hhdm.wrapping_add(phys.raw()) as *const u32;
            // SAFETY: `validate_mmio_read32` verified rights, alignment, and bounds.
            let val = unsafe { read_volatile(ptr) };
            u64::from(val)
        }),
    };

    match result {
        Ok(val) => {
            frame.rax = 0;
            frame.rdx = val;
        }
        Err(e) => {
            frame.rax = e as u64;
            frame.rdx = 0;
        }
    }
}

/// Load Process 0 (`init`)'s isolated `CR3` and enter Ring 3 via `swapgs` + `iretq`.
pub fn start_userspace() -> ! {
    // SAFETY: `PROCS[0]` was registered with valid Ring-3 `VSpace`, entry RIP, and stack RSP.
    let (cr3, entry_rip, user_rsp) = unsafe {
        let table = &mut *PROCS.get();
        assert!(table.count > 0 && table.procs[0].active);
        table.current = 0;
        (
            table.procs[0].cr3,
            table.procs[0].frame.rip,
            table.procs[0].frame.rsp,
        )
    };

    write_cr3(cr3);

    let user_cs = u64::from(gdt::USER_CS);
    let user_ds = u64::from(gdt::USER_DS);
    let user_rflags: u64 = 0x202;

    // SAFETY: `cr3` is loaded, `entry_rip` and `user_rsp` point to valid W^X Ring-3 mappings,
    // and `swapgs` stashes `&PerCpu` in `IA32_KERNEL_GS_BASE` before `iretq` drops CPL to 3.
    unsafe {
        asm!(
            "cli",
            "swapgs",
            "push {user_ds}",
            "push {user_rsp}",
            "push {user_rflags}",
            "push {user_cs}",
            "push {entry_rip}",
            "iretq",
            user_ds = in(reg) user_ds,
            user_rsp = in(reg) user_rsp,
            user_rflags = in(reg) user_rflags,
            user_cs = in(reg) user_cs,
            entry_rip = in(reg) entry_rip,
            options(noreturn),
        );
    }
}
