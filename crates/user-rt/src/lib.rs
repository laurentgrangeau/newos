#![no_std]
#![feature(sync_unsafe_cell)]

//! Safe EL0 userspace runtime & `svc #0` syscall SDK for NewOS (Raspberry Pi 5 16 GB, `aarch64`).
//!
//! Confines the minimal 64-bit `svc #0` assembly trampoline inside this crate so
//! all userspace services (`init`, drivers, apps) can enforce `#![forbid(unsafe_code)]`.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, ObjectType, QemuExitCode, Rights, SysError, SyscallNumber,
};

const DEBUG_WRITE_MAX: usize = 256;
const SYS_INFO_UNCACHED: u64 = u64::MAX;
static SYS_INFO_CACHE: AtomicU64 = AtomicU64::new(SYS_INFO_UNCACHED);

const RECOVERY_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct RecoveryStack([u8; RECOVERY_STACK_SIZE]);

static SUPERVISOR_RECOVERY_STACK: SyncUnsafeCell<RecoveryStack> =
    SyncUnsafeCell::new(RecoveryStack([0; RECOVERY_STACK_SIZE]));

#[inline]
fn raw_syscall_full(
    num: SyscallNumber,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> Result<(u64, u64), SysError> {
    let err: u64;
    let val: u64;
    let badge: u64;
    // SAFETY: Executing `svc #0` in EL0 traps to `VBAR_EL1`, returning `(err, val, badge)` in `(x0, x1, x2)`.
    unsafe {
        asm!(
            "svc #0",
            in("x8") num as u64,
            inlateout("x0") a0 => err,
            inlateout("x1") a1 => val,
            inlateout("x2") a2 => badge,
            in("x3") a3,
            options(nostack),
        );
    }
    if err == 0 {
        Ok((val, badge))
    } else {
        Err(SysError::from_u64(err).unwrap_or(SysError::Unsupported))
    }
}

#[inline]
fn raw_syscall(num: SyscallNumber, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, SysError> {
    raw_syscall_full(num, a0, a1, a2, a3).map(|(val, _)| val)
}

/// Write a UTF-8 diagnostic message to the microkernel's early debug console using an explicit `Console` cap.
pub fn debug_log_with_cap(console_cap: CapId, msg: &str) -> Result<usize, SysError> {
    raw_syscall(
        SyscallNumber::DebugWrite,
        console_cap.raw(),
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
    )
    .map(|n| n as usize)
}

/// Write a UTF-8 diagnostic message to the microkernel's early debug console.
pub fn debug_log(msg: &str) -> Result<usize, SysError> {
    debug_log_with_cap(CapId::BOOTSTRAP_CONSOLE, msg)
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

/// Safe `core::fmt::Write` adapter for formatted EL0 diagnostics.
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

/// Receive a pending fastpath IPC `(badge, payload)` pair (full 64-bit badge + 64-bit payload).
pub fn ipc_recv(cap: CapId) -> Result<(u64, u64), SysError> {
    let (payload, badge) = raw_syscall_full(SyscallNumber::IpcRecv, cap.raw(), 0, 0, 0)?;
    Ok((badge, payload))
}

/// Synchronous send+receive fastpath (`IpcCall`) in a single client syscall (full 64-bit badge + payload).
pub fn ipc_call(ep: CapId, payload: u64) -> Result<(u64, u64), SysError> {
    let (reply_payload, badge) = raw_syscall_full(SyscallNumber::IpcCall, ep.raw(), payload, 0, 0)?;
    Ok((badge, reply_payload))
}

/// Combined reply + wait-for-next-request fastpath (`IpcReplyRecv`) in a single server syscall.
pub fn ipc_reply_recv(
    ep: CapId,
    reply_payload: u64,
    has_reply: bool,
) -> Result<(u64, u64), SysError> {
    let (payload, badge) = raw_syscall_full(
        SyscallNumber::IpcReplyRecv,
        ep.raw(),
        reply_payload,
        u64::from(has_reply),
        0,
    )?;
    Ok((badge, payload))
}

/// Read the ARM Generic Timer virtual counter (`CNTVCT_EL0`) via syscall.
pub fn read_cycles() -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::ReadCycles, 0, 0, 0, 0)
}

/// Register an EL0 supervisor recovery entry point invoked if an EL0 hardware fault occurs.
pub fn set_fault_handler(handler: extern "C" fn() -> !) -> Result<(), SysError> {
    // SAFETY: Computes the 16-byte-aligned top address of the static EL0 recovery stack.
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

/// Translate an EL0 reference's virtual address in `vspace_cap` to its physical address
/// for EL0 DMA ring programming (`Rights::READ` on `VSpace` capability).
pub fn virt_to_phys_with_cap<T>(vspace_cap: CapId, value: &T) -> Result<u64, SysError> {
    let va = (value as *const T) as u64;
    raw_syscall(SyscallNumber::VirtToPhys, vspace_cap.raw(), va, 0, 0)
}

/// Translate an EL0 reference's virtual address in `BOOTSTRAP_VSPACE` to its physical address.
pub fn virt_to_phys<T>(value: &T) -> Result<u64, SysError> {
    virt_to_phys_with_cap(CapId::BOOTSTRAP_VSPACE, value)
}

/// Derive a capability in the caller's `CSpace` with attenuated `rights` and optional immutable `badge`.
///
/// Pass `dst_slot = None` to let the kernel choose the first free slot automatically.
pub fn cap_mint(
    src: CapId,
    dst_slot: Option<usize>,
    rights: Rights,
    new_badge: Option<u64>,
) -> Result<CapId, SysError> {
    let (flags, badge) = match new_badge {
        Some(b) => (u64::from(rights.bits()) | CAP_MINT_SET_BADGE, b),
        None => (u64::from(rights.bits()), 0),
    };
    raw_syscall(
        SyscallNumber::CapMint,
        src.raw(),
        dst_slot.unwrap_or(0) as u64,
        flags,
        badge,
    )
    .map(CapId::new)
}

/// Copy a capability verbatim inside the caller's `CSpace`.
pub fn cap_copy(src: CapId, dst_slot: Option<usize>) -> Result<CapId, SysError> {
    raw_syscall(
        SyscallNumber::CapCopy,
        src.raw(),
        dst_slot.unwrap_or(0) as u64,
        0,
        0,
    )
    .map(CapId::new)
}

/// Move a capability to another slot inside the caller's `CSpace`, invalidating `src`.
pub fn cap_move(src: CapId, dst_slot: Option<usize>) -> Result<CapId, SysError> {
    raw_syscall(
        SyscallNumber::CapMove,
        src.raw(),
        dst_slot.unwrap_or(0) as u64,
        0,
        0,
    )
    .map(CapId::new)
}

/// Delete a single capability slot from the caller's `CSpace`.
pub fn cap_delete(cap: CapId) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::CapDelete, cap.raw(), 0, 0, 0).map(|_| ())
}

/// Transitively revoke all CDT descendants derived from `cap` in the caller's `CSpace`.
pub fn cap_revoke(cap: CapId) -> Result<usize, SysError> {
    raw_syscall(SyscallNumber::CapRevoke, cap.raw(), 0, 0, 0).map(|n| n as usize)
}

/// Map a fresh zeroed 4 KiB page at `vaddr` in `vspace_cap` (strict W^X enforced; requires `Rights::WRITE`).
pub fn map_page_with_cap(vspace_cap: CapId, vaddr: u64, rights: Rights) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::MapPage,
        vspace_cap.raw(),
        vaddr,
        u64::from(rights.bits()),
        0,
    )
    .map(|_| ())
}

/// Map a fresh zeroed 4 KiB page at `vaddr` in `BOOTSTRAP_VSPACE` (strict W^X enforced).
pub fn map_page(vaddr: u64, rights: Rights) -> Result<(), SysError> {
    map_page_with_cap(CapId::BOOTSTRAP_VSPACE, vaddr, rights)
}

/// Unmap a 4 KiB page at `vaddr` from `vspace_cap` and reclaim its physical frame (`Rights::WRITE`).
pub fn unmap_page_with_cap(vspace_cap: CapId, vaddr: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::UnmapPage, vspace_cap.raw(), vaddr, 0, 0).map(|_| ())
}

/// Unmap a 4 KiB page at `vaddr` from `BOOTSTRAP_VSPACE` and reclaim its physical frame.
pub fn unmap_page(vaddr: u64) -> Result<(), SysError> {
    unmap_page_with_cap(CapId::BOOTSTRAP_VSPACE, vaddr)
}

/// Retype a kernel object (`Frame`, `Endpoint`, `Notification`) from a designated `Untyped` cap.
pub fn untyped_retype(
    untyped_cap: CapId,
    obj_type: ObjectType,
    dst_slot: Option<usize>,
) -> Result<CapId, SysError> {
    raw_syscall(
        SyscallNumber::UntypedRetype,
        untyped_cap.raw(),
        obj_type as u64,
        dst_slot.unwrap_or(0) as u64,
        0,
    )
    .map(CapId::new)
}

/// Map a designated `Frame` capability into a designated `VSpace` capability (strict W^X enforced).
pub fn frame_map(
    vspace_cap: CapId,
    frame_cap: CapId,
    vaddr: u64,
    rights: Rights,
) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::FrameMap,
        vspace_cap.raw(),
        frame_cap.raw(),
        vaddr,
        u64::from(rights.bits()),
    )
    .map(|_| ())
}

/// Set scheduling priority (`0..=255`, higher value = higher priority) on `thread_cap` (`Rights::WRITE`).
pub fn set_priority(thread_cap: CapId, priority: u8) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::SetPriority,
        thread_cap.raw(),
        u64::from(priority),
        0,
        0,
    )
    .map(|_| ())
}

/// Grant an attenuated capability from the caller's `CSpace` into `dst_cnode_cap` (`Rights::WRITE`).
pub fn cap_grant(
    dst_cnode_cap: CapId,
    src: CapId,
    rights: Rights,
    new_badge: Option<u64>,
) -> Result<CapId, SysError> {
    let (flags, badge) = match new_badge {
        Some(b) => (u64::from(rights.bits()) | CAP_MINT_SET_BADGE, b),
        None => (u64::from(rights.bits()), 0),
    };
    raw_syscall(
        SyscallNumber::CapGrant,
        dst_cnode_cap.raw(),
        src.raw(),
        flags,
        badge,
    )
    .map(CapId::new)
}

/// Deliberately trigger an EL0 hardware invalid-instruction exception (`udf #0`) for crash-isolation testing.
pub fn trigger_user_fault() -> ! {
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

/// Non-blocking 1-byte read from the debug serial console using an explicit `Console` cap (`Rights::READ`).
pub fn debug_read_byte_with_cap(console_cap: CapId) -> Result<u8, SysError> {
    raw_syscall(SyscallNumber::DebugRead, console_cap.raw(), 0, 0, 0).map(|b| b as u8)
}

/// Non-blocking 1-byte read from the debug serial console (`Err(WouldBlock)` if no input).
pub fn debug_read_byte() -> Result<u8, SysError> {
    debug_read_byte_with_cap(CapId::BOOTSTRAP_CONSOLE)
}

#[inline]
const fn decode_sys_info(raw: u64) -> SysInfo {
    SysInfo {
        online_cpus: (raw & 0xFFFF) as u16,
        proc_count: ((raw >> 16) & 0xFFFF) as u16,
        interactive_shell: ((raw >> 32) & 1) != 0,
    }
}

/// Read-only microkernel system info (`online_cpus`, `proc_count`, `interactive_shell`) via `BOOTSTRAP_POWER`.
///
/// Static after boot; cached in an `AtomicU64` after the first successful syscall.
pub fn sys_info() -> SysInfo {
    let cached = SYS_INFO_CACHE.load(Ordering::Relaxed);
    if cached != SYS_INFO_UNCACHED {
        return decode_sys_info(cached);
    }
    match raw_syscall(SyscallNumber::SysInfo, CapId::BOOTSTRAP_POWER.raw(), 0, 0, 0) {
        Ok(raw) => {
            SYS_INFO_CACHE.store(raw, Ordering::Relaxed);
            decode_sys_info(raw)
        }
        Err(_) => decode_sys_info(0),
    }
}

/// Shut down the system cleanly with `code` using an explicit `PowerControl` capability (`Rights::WRITE`).
pub fn exit_with_cap(power_cap: CapId, code: QemuExitCode) -> ! {
    let _ = raw_syscall(SyscallNumber::Exit, power_cap.raw(), code as u64, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Exit the root task cleanly with `code` via `BOOTSTRAP_POWER`.
pub fn exit(code: QemuExitCode) -> ! {
    exit_with_cap(CapId::BOOTSTRAP_POWER, code)
}

/// Define an EL0 userspace `_start` entry point delegating to a `#![forbid(unsafe_code)]` `fn() -> !`.
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
