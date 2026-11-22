#![no_std]
#![feature(sync_unsafe_cell)]

//! Safe Ring-3 userspace runtime & syscall SDK for NewOS.
//!
//! Confines the minimal 64-bit `syscall` assembly trampoline inside this crate so
//! all userspace services (`init`, drivers, apps) can enforce `#![forbid(unsafe_code)]`.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{CapId, QemuExitCode, SysError, SyscallNumber};

const DEBUG_WRITE_MAX: usize = 256;
const SYS_INFO_UNCACHED: u64 = u64::MAX;
static SYS_INFO_CACHE: AtomicU64 = AtomicU64::new(SYS_INFO_UNCACHED);

const RECOVERY_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct RecoveryStack([u8; RECOVERY_STACK_SIZE]);

static SUPERVISOR_RECOVERY_STACK: SyncUnsafeCell<RecoveryStack> =
    SyncUnsafeCell::new(RecoveryStack([0; RECOVERY_STACK_SIZE]));

#[inline]
fn raw_syscall(num: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    let err: u64;
    let val: u64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Executing 64-bit `syscall` in Ring 3 transfers control to `IA32_LSTAR`,
    // returning `(err, val)` in `(rax, rdx)`.
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
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Executing `svc #0` in EL0 traps to `VBAR_EL1`, returning `(err, val)` in `(x0, x1)`.
    unsafe {
        asm!(
            "svc #0",
            in("x8") num as u64,
            inlateout("x0") a0 => err,
            inlateout("x1") a1 => val,
            in("x2") a2,
            in("x3") a3,
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

/// Write an entire UTF-8 string to the debug console, chunking at `<= 256`B UTF-8 char boundaries.
pub fn debug_write_all(mut s: &str) -> Result<(), SysError> {
    while !s.is_empty() {
        let mut end = s.len().min(DEBUG_WRITE_MAX);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            return Err(SysError::InvalidArgument);
        }
        let written = debug_log(&s[..end])?;
        if written == 0 || written > end || !s.is_char_boundary(written) {
            return Err(SysError::InvalidArgument);
        }
        s = &s[written..];
    }
    Ok(())
}

/// Safe `core::fmt::Write` adapter for formatted Ring-3 diagnostics.
pub struct DebugConsole;

impl Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        debug_write_all(s).map_err(|_| fmt::Error)
    }
}

/// Fixed-size stack-buffered `core::fmt::Write` console (`no_alloc`, zero `unsafe`).
///
/// Coalesces `write!`/`writeln!` fragments into `<= N`-byte `DebugWrite` syscalls and
/// flushes automatically on `Drop` (call `flush()` explicitly before diverging calls).
pub struct BufferedConsole<const N: usize = 256> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> BufferedConsole<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            pos: 0,
        }
    }

    pub fn flush(&mut self) {
        if self.pos > 0 {
            if let Ok(s) = core::str::from_utf8(&self.buf[..self.pos]) {
                let _ = debug_write_all(s);
            }
            self.pos = 0;
        }
    }
}

impl<const N: usize> Default for BufferedConsole<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Write for BufferedConsole<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.is_empty() {
            return Ok(());
        }
        if N == 0 {
            return debug_write_all(s).map_err(|_| fmt::Error);
        }
        let bytes = s.as_bytes();
        if bytes.len() <= N - self.pos {
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            return Ok(());
        }
        self.flush();
        if bytes.len() >= N {
            debug_write_all(s).map_err(|_| fmt::Error)
        } else {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.pos = bytes.len();
            Ok(())
        }
    }
}

impl<const N: usize> Drop for BufferedConsole<N> {
    fn drop(&mut self) {
        self.flush();
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

#[inline]
const fn unpack_ipc_msg(packed: u64) -> (u64, u64) {
    (packed >> 48, packed & 0x0000_FFFF_FFFF_FFFF)
}

/// Receive a pending fastpath IPC `(badge, payload)` pair from an `Endpoint` capability.
pub fn ipc_recv(cap: CapId) -> Result<(u64, u64), SysError> {
    let packed = raw_syscall(SyscallNumber::IpcRecv, cap.raw(), 0, 0, 0)?;
    Ok(unpack_ipc_msg(packed))
}

/// Synchronous send+receive fastpath (`IpcCall`) in a single client syscall.
pub fn ipc_call(ep: CapId, payload: u64) -> Result<(u64, u64), SysError> {
    let packed = raw_syscall(SyscallNumber::IpcCall, ep.raw(), payload, 0, 0)?;
    Ok(unpack_ipc_msg(packed))
}

/// Combined reply + wait-for-next-request fastpath (`IpcReplyRecv`) in a single server syscall.
pub fn ipc_reply_recv(
    ep: CapId,
    reply_payload: u64,
    has_reply: bool,
) -> Result<(u64, u64), SysError> {
    let packed = raw_syscall(
        SyscallNumber::IpcReplyRecv,
        ep.raw(),
        reply_payload,
        u64::from(has_reply),
        0,
    )?;
    Ok(unpack_ipc_msg(packed))
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

/// Perform a capability-scoped 32-bit MMIO write through an `MmioRegion` capability.
pub fn mmio_write32(mmio_cap: CapId, byte_offset: u64, val: u32) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::MmioWrite32,
        mmio_cap.raw(),
        byte_offset,
        u64::from(val),
        0,
    )
    .map(|_| ())
}

/// Translate a Ring-3 reference's virtual address in the caller's `VSpace` to its physical address
/// for Ring-3 DMA ring programming (zero `unsafe` in Ring-3 drivers).
pub fn virt_to_phys<T>(value: &T) -> Result<u64, SysError> {
    let va = (value as *const T) as u64;
    raw_syscall(SyscallNumber::VirtToPhys, va, 0, 0, 0)
}

/// Deliberately trigger a Ring-3/EL0 hardware invalid-instruction exception for crash-isolation testing.
pub fn trigger_user_fault() -> ! {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Intentionally executes `ud2` in Ring 3 for crash-isolation verification.
    unsafe {
        asm!("ud2", options(noreturn));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Intentionally executes `udf #0` in EL0 for crash-isolation verification.
    unsafe {
        asm!("udf #0", options(noreturn));
    }
}

/// Read-only system summary returned by `sys_info()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysInfo {
    pub online_cpus: u16,
    pub proc_count: u16,
    pub interactive_shell: bool,
}

/// Non-blocking 1-byte read from the debug serial console (`Err(WouldBlock)` if no input).
pub fn debug_read_byte() -> Result<u8, SysError> {
    raw_syscall(SyscallNumber::DebugRead, 0, 0, 0, 0).map(|b| b as u8)
}

#[inline]
const fn decode_sys_info(raw: u64) -> SysInfo {
    SysInfo {
        online_cpus: (raw & 0xFFFF) as u16,
        proc_count: ((raw >> 16) & 0xFFFF) as u16,
        interactive_shell: ((raw >> 32) & 1) != 0,
    }
}

/// Read-only microkernel system info (`online_cpus`, `proc_count`, `interactive_shell`).
///
/// Static after boot; cached in an `AtomicU64` after the first successful syscall.
pub fn sys_info() -> SysInfo {
    let cached = SYS_INFO_CACHE.load(Ordering::Relaxed);
    if cached != SYS_INFO_UNCACHED {
        return decode_sys_info(cached);
    }
    match raw_syscall(SyscallNumber::SysInfo, 0, 0, 0, 0) {
        Ok(raw) => {
            SYS_INFO_CACHE.store(raw, Ordering::Relaxed);
            decode_sys_info(raw)
        }
        Err(_) => decode_sys_info(0),
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
