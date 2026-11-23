#![no_std]

//! Safe EL0 userspace runtime & `svc #0` syscall SDK for NewOS (Raspberry Pi 5 16 GB, `aarch64`).
//!
//! Confines the minimal 64-bit `svc #0` assembly trampoline inside this crate so
//! all userspace services (`init`, drivers, apps) can enforce `#![forbid(unsafe_code)]`.

use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, DmaCacheOp, ObjectType, Rights, ShutdownStatus, SysError,
    SyscallNumber,
};

pub const DEBUG_WRITE_MAX: usize = 1024;
const SYS_INFO_UNCACHED: u64 = u64::MAX;
static SYS_INFO_CACHE: AtomicU64 = AtomicU64::new(SYS_INFO_UNCACHED);
static TIMER_FREQ_CACHE: AtomicU64 = AtomicU64::new(0);

const RECOVERY_STACK_SIZE: usize = 64 * 1024;
const RECOVERY_STACK_WORDS: usize = RECOVERY_STACK_SIZE / core::mem::size_of::<AtomicU64>();

#[repr(C, align(16))]
struct RecoveryStack([AtomicU64; RECOVERY_STACK_WORDS]);

const _: () = assert!(
    core::mem::size_of::<RecoveryStack>() == RECOVERY_STACK_SIZE
        && core::mem::align_of::<RecoveryStack>() == 16
);

/// 64 KiB 16-byte-aligned EL0 recovery stack placed in writable `.bss` (`PF_R | PF_W`) via
/// interior-mutable `AtomicU64` elements (avoiding `.rodata` placement and `SyncUnsafeCell`).
static SUPERVISOR_RECOVERY_STACK: RecoveryStack =
    RecoveryStack([const { AtomicU64::new(0) }; RECOVERY_STACK_WORDS]);

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
    // SAFETY: Executing `svc #0` in EL0 traps synchronously to `VBAR_EL1`. The kernel saves and
    // restores `SP_EL0` and all non-return registers in `TrapFrame`, returning `(err, val, badge)`
    // in `(x0, x1, x2)`. `options(nostack)` holds because neither `svc #0` nor the trap return
    // modifies the EL0 stack pointer.
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

/// Write an entire UTF-8 string to the debug console, chunking at `<= 1024`B (`DEBUG_WRITE_MAX`) UTF-8 char boundaries.
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
pub struct BufferedConsole<const N: usize = DEBUG_WRITE_MAX> {
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

/// Send a UTF-8 log message to the console owner over an `Endpoint` capability
/// (`CapId::BOOTSTRAP_LOG_EP`) using 7-byte register-only fastpath IPC chunks.
///
/// Yields and retries if the endpoint slot is temporarily full (`SysError::WouldBlock`).
pub fn ipc_log_write(ep: CapId, msg: &str) -> Result<usize, SysError> {
    let bytes = msg.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + newos_abi::log_ipc::MAX_CHUNK_BYTES).min(bytes.len());
        let word = newos_abi::log_ipc::encode_chunk(&bytes[offset..end]);
        loop {
            match ipc_send(ep, word) {
                Ok(()) => break,
                Err(SysError::WouldBlock) => {
                    let _ = yield_now();
                }
                Err(e) => return Err(e),
            }
        }
        offset = end;
    }
    Ok(bytes.len())
}

/// Zero-allocation buffered `core::fmt::Write` sink for non-root processes without a direct
/// `Console` capability, routing output over `CapId::BOOTSTRAP_LOG_EP` to `init`.
pub struct IpcLogConsole<const N: usize = 256> {
    ep: CapId,
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> IpcLogConsole<N> {
    pub const fn new(ep: CapId) -> Self {
        Self {
            ep,
            buf: [0u8; N],
            pos: 0,
        }
    }

    pub fn flush(&mut self) {
        if self.pos > 0 {
            if let Ok(s) = core::str::from_utf8(&self.buf[..self.pos]) {
                let _ = ipc_log_write(self.ep, s);
            }
            self.pos = 0;
        }
    }
}

impl<const N: usize> Write for IpcLogConsole<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.is_empty() {
            return Ok(());
        }
        if N == 0 {
            return ipc_log_write(self.ep, s)
                .map(|_| ())
                .map_err(|_| fmt::Error);
        }
        let bytes = s.as_bytes();
        if bytes.len() <= N - self.pos {
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            return Ok(());
        }
        self.flush();
        if bytes.len() >= N {
            ipc_log_write(self.ep, s)
                .map(|_| ())
                .map_err(|_| fmt::Error)
        } else {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.pos = bytes.len();
            Ok(())
        }
    }
}

impl<const N: usize> Drop for IpcLogConsole<N> {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Zero-allocation line reassembler used by the console owner (`init`) to drain
/// 7-byte fastpath IPC log chunks from `CapId::BOOTSTRAP_LOG_EP` into complete lines.
pub struct IpcLogAssembler<const N: usize = 256> {
    buf: [u8; N],
    len: usize,
    active_badge: Option<u64>,
    pending_chunk: [u8; newos_abi::log_ipc::MAX_CHUNK_BYTES],
    pending_off: usize,
    pending_len: usize,
    pending_badge: u64,
    stashed_msg: Option<(u64, u64)>,
}

impl<const N: usize> IpcLogAssembler<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
            active_badge: None,
            pending_chunk: [0u8; newos_abi::log_ipc::MAX_CHUNK_BYTES],
            pending_off: 0,
            pending_len: 0,
            pending_badge: 0,
            stashed_msg: None,
        }
    }

    fn emit_line(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        let badge = self.active_badge.unwrap_or(0);
        let n = self.len.min(out.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.len = 0;
        self.active_badge = None;
        Some((badge, n))
    }

    fn feed_pending_chunk(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        while self.pending_off < self.pending_len {
            let b = self.pending_chunk[self.pending_off];
            self.pending_off += 1;
            if self.active_badge.is_none() {
                self.active_badge = Some(self.pending_badge);
            }
            if b == b'\n' {
                return self.emit_line(out);
            }
            if b == b'\r' {
                continue;
            }
            if self.len < N {
                self.buf[self.len] = b;
                self.len += 1;
            }
            if self.len == N {
                return self.emit_line(out);
            }
        }
        None
    }

    /// Non-blocking poll of `ep` for the next complete log line (excluding `\n`).
    ///
    /// Copies the line into `out` and returns `Some((sender_badge, len))`, or `None`
    /// if no complete line is ready yet.
    pub fn poll_line(&mut self, ep: CapId, out: &mut [u8]) -> Option<(u64, usize)> {
        if let Some(res) = self.feed_pending_chunk(out) {
            return Some(res);
        }

        loop {
            let (badge, payload) = match self.stashed_msg.take() {
                Some(msg) => msg,
                None => match ipc_recv(ep) {
                    Ok(msg) => msg,
                    Err(_) => return None,
                },
            };

            if let Some(cur) = self.active_badge
                && cur != badge
                && self.len > 0
            {
                self.stashed_msg = Some((badge, payload));
                return self.emit_line(out);
            }

            let (chunk, chunk_len) = newos_abi::log_ipc::decode_chunk(payload);
            self.pending_chunk = chunk;
            self.pending_off = 0;
            self.pending_len = chunk_len;
            self.pending_badge = badge;

            if let Some(res) = self.feed_pending_chunk(out) {
                return Some(res);
            }
        }
    }
}

impl<const N: usize> Default for IpcLogAssembler<N> {
    fn default() -> Self {
        Self::new()
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

/// Read the architectural ARM Generic Timer frequency (`CNTFRQ_EL0`) in Hz (cached after first call).
///
/// Falls back to `62_500_000` Hz (QEMU `virt`) if the syscall is unsupported or hardware reports 0.
pub fn timer_freq_hz() -> u64 {
    let cached = TIMER_FREQ_CACHE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let freq = match raw_syscall(SyscallNumber::TimerFreq, 0, 0, 0, 0) {
        Ok(f) if f > 0 => f,
        _ => 62_500_000,
    };
    TIMER_FREQ_CACHE.store(freq, Ordering::Relaxed);
    freq
}

/// Terminate the calling EL0 thread cleanly without requiring a `PowerControl` capability.
pub fn thread_exit() -> ! {
    let _ = raw_syscall(SyscallNumber::ThreadExit, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Acknowledge and unmask a hardware IRQ via a designated `IrqHandler` capability (`Rights::WRITE`).
pub fn irq_ack(irq_cap: CapId) -> Result<u16, SysError> {
    raw_syscall(SyscallNumber::IrqAck, irq_cap.raw(), 0, 0, 0).map(|v| v as u16)
}

/// Register an EL0 supervisor recovery entry point invoked if an EL0 hardware fault occurs.
///
/// The kernel resets `SP_EL0` to the 16-byte-aligned top of `SUPERVISOR_RECOVERY_STACK`
/// before entering `handler`. Safe for single-threaded EL0 processes because any prior frame
/// on the recovery stack is abandoned by the kernel on fault re-entry.
pub fn set_fault_handler(handler: extern "C" fn() -> !) -> Result<(), SysError> {
    let stack_top =
        (&raw const SUPERVISOR_RECOVERY_STACK as usize).wrapping_add(RECOVERY_STACK_SIZE) as u64;
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

/// Perform PAN-safe DMA cache maintenance on `value` via `vspace_cap` (`Rights::READ`).
pub fn dma_cache_op_with_cap<T>(
    vspace_cap: CapId,
    value: &T,
    op: DmaCacheOp,
) -> Result<u64, SysError> {
    let va = (value as *const T) as u64;
    let len = core::mem::size_of::<T>() as u64;
    raw_syscall(
        SyscallNumber::DmaCacheOp,
        vspace_cap.raw(),
        va,
        len,
        op as u64,
    )
}

/// Clean data cache lines (`dc cvac`) for `value` before outbound DMA (Pi 5 RP1/PCIe).
pub fn dma_clean<T>(value: &T) -> Result<u64, SysError> {
    dma_cache_op_with_cap(CapId::BOOTSTRAP_VSPACE, value, DmaCacheOp::Clean)
}

/// Clean & invalidate data cache lines (`dc civac`) for `value` before/after inbound DMA.
pub fn dma_invalidate<T>(value: &T) -> Result<u64, SysError> {
    dma_cache_op_with_cap(CapId::BOOTSTRAP_VSPACE, value, DmaCacheOp::Invalidate)
}

/// Read packed ARMv8.2-A Cortex-A76 ISA feature bitmask & cache/PA geometry (`newos_abi::cpu_isa`).
pub fn cpu_features_with_cap(power_cap: CapId) -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::CpuFeatures, power_cap.raw(), 0, 0, 0)
}

/// Read packed ARMv8.2-A Cortex-A76 ISA feature bitmask via `BOOTSTRAP_POWER`.
pub fn cpu_features() -> Result<u64, SysError> {
    cpu_features_with_cap(CapId::BOOTSTRAP_POWER)
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
    // SAFETY: `udf #0` is a permanently undefined AArch64 instruction that deterministically raises
    // a synchronous EL0 exception trapped by `VBAR_EL1`, which either redirects execution to the
    // registered fault handler or terminates the process; control never returns (`noreturn`).
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
    match raw_syscall(
        SyscallNumber::SysInfo,
        CapId::BOOTSTRAP_POWER.raw(),
        0,
        0,
        0,
    ) {
        Ok(raw) => {
            SYS_INFO_CACHE.store(raw, Ordering::Relaxed);
            decode_sys_info(raw)
        }
        Err(_) => decode_sys_info(0),
    }
}

/// Shut down the system cleanly with `code` using an explicit `PowerControl` capability (`Rights::WRITE`).
pub fn exit_with_cap(power_cap: CapId, code: ShutdownStatus) -> ! {
    let _ = raw_syscall(SyscallNumber::Exit, power_cap.raw(), code as u64, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Exit the root task cleanly with `code` via `BOOTSTRAP_POWER`.
pub fn exit(code: ShutdownStatus) -> ! {
    exit_with_cap(CapId::BOOTSTRAP_POWER, code)
}

/// Reboot the machine cleanly via PSCI `SYSTEM_RESET` (`BOOTSTRAP_POWER`).
pub fn reboot() -> ! {
    exit_with_cap(CapId::BOOTSTRAP_POWER, ShutdownStatus::Reboot)
}

/// Define an EL0 userspace `_start` entry point delegating to a `#![forbid(unsafe_code)]` `fn() -> !`.
#[macro_export]
macro_rules! entry {
    ($path:path) => {
        // SAFETY: `_start` is the unique ELF entry point required by `linker-aarch64.ld`
        // (`ENTRY(_start)`); each userspace binary invokes `entry!` exactly once.
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            let main_fn: fn() -> ! = $path;
            main_fn()
        }
    };
}
