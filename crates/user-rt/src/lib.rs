#![no_std]
#![feature(sync_unsafe_cell)]

//! Safe Ring-3 userspace runtime & syscall SDK for NewOS.
//!
//! Confines the minimal 64-bit `syscall` assembly trampoline inside this crate so
//! all userspace services (`init`, drivers, apps) can enforce `#![forbid(unsafe_code)]`.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::{self, Write};
use newos_abi::{CapId, QemuExitCode, SysError, SyscallNumber};

const RECOVERY_STACK_SIZE: usize = 8 * 1024;

#[repr(C, align(16))]
struct RecoveryStack([u8; RECOVERY_STACK_SIZE]);

static SUPERVISOR_RECOVERY_STACK: SyncUnsafeCell<RecoveryStack> =
    SyncUnsafeCell::new(RecoveryStack([0; RECOVERY_STACK_SIZE]));

#[inline]
fn raw_syscall(num: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    let err: u64;
    let val: u64;
    // SAFETY: Executing the 64-bit `syscall` instruction in Ring 3 transfers control to the
    // kernel's `IA32_LSTAR` handler, returning `(err, val)` in `(rax, rdx)` while clobbering
    // `rcx` and `r11`.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") num as u64 => err,
            in("rdi") a0,
            in("rsi") a1,
            inlateout("rdx") a2 => val,
            in("r10") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    if err == 0 {
        Ok(val)
    } else {
        Err(SysError::from_u64(err).unwrap_or(SysError::Unsupported))
    }
}

/// Write a UTF-8 diagnostic message to the microkernel's early debug console.
pub fn debug_log(msg: &str) -> Result<usize, SysError> {
    raw_syscall(
        SyscallNumber::DebugWrite,
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
        0,
    )
    .map(|n| n as usize)
}

/// Safe `core::fmt::Write` adapter for formatted Ring-3 diagnostics.
pub struct DebugConsole;

impl Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = debug_log(s);
        Ok(())
    }
}

/// Yield the current thread's remaining time slice.
pub fn yield_now() -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::Yield, 0, 0, 0, 0)
}

/// Bitwise-OR `badge` into a 64-bit kernel `Notification` capability.
pub fn notify_signal(cap: CapId, badge: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::NotifySignal, cap.raw(), badge, 0, 0).map(|_| ())
}

/// Atomically read and clear the 64-bit signal word of a `Notification` capability.
pub fn notify_poll(cap: CapId) -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::NotifyPoll, cap.raw(), 0, 0, 0)
}

/// Send a register-only fastpath IPC payload to an `Endpoint` capability.
pub fn ipc_send(cap: CapId, payload: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::IpcSend, cap.raw(), payload, 0, 0).map(|_| ())
}

/// Receive a pending fastpath IPC `(badge, payload)` pair from an `Endpoint` capability.
pub fn ipc_recv(cap: CapId) -> Result<(u64, u64), SysError> {
    let packed = raw_syscall(SyscallNumber::IpcRecv, cap.raw(), 0, 0, 0)?;
    let badge = packed >> 48;
    let payload = packed & 0x0000_FFFF_FFFF_FFFF;
    Ok((badge, payload))
}

/// Read the CPU monotonic cycle counter (`rdtsc`) via syscall.
pub fn read_cycles() -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::ReadCycles, 0, 0, 0, 0)
}

/// Register a Ring-3 supervisor recovery entry point invoked if a Ring-3 hardware fault occurs.
pub fn set_fault_handler(handler: extern "C" fn() -> !) -> Result<(), SysError> {
    // SAFETY: Computes the 16-byte-aligned top address of the static Ring-3 recovery stack.
    let stack_top = unsafe {
        SUPERVISOR_RECOVERY_STACK
            .get()
            .cast::<u8>()
            .add(RECOVERY_STACK_SIZE) as u64
    };
    raw_syscall(
        SyscallNumber::SetFaultHandler,
        handler as *const () as u64,
        stack_top,
        0,
        0,
    )
    .map(|_| ())
}

/// Perform a capability-scoped 32-bit MMIO read through an `MmioRegion` capability.
pub fn mmio_read32(mmio_cap: CapId, byte_offset: u64) -> Result<u32, SysError> {
    raw_syscall(SyscallNumber::MmioRead32, mmio_cap.raw(), byte_offset, 0, 0).map(|v| v as u32)
}

/// Deliberately trigger a Ring-3 hardware `#UD` (Invalid Opcode) exception for crash-isolation testing.
pub fn trigger_user_fault() -> ! {
    // SAFETY: Intentionally executes `ud2` in Ring 3 so the microkernel's Ring-3 fault
    // isolation and supervisor recovery path can be verified end-to-end.
    unsafe {
        asm!("ud2", options(noreturn));
    }
}

/// Exit the root task cleanly with `code`.
pub fn exit(code: QemuExitCode) -> ! {
    let _ = raw_syscall(SyscallNumber::Exit, code as u64, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Define a Ring-3 userspace `_start` entry point delegating to a `#![forbid(unsafe_code)]` `fn() -> !`.
#[macro_export]
macro_rules! entry {
    ($path:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            let main_fn: fn() -> ! = $path;
            main_fn()
        }
    };
}
