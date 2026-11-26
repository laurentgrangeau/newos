#![no_std]

//! Safe EL0 userspace runtime & `svc #0` syscall SDK for `NewOS` (Raspberry Pi 5 16 GB, `aarch64`).
//!
//! Confines the minimal 64-bit `svc #0` assembly trampoline inside this crate so
//! all userspace services (`supervisor-pd`, drivers, apps) remain free of `unsafe` code.

use core::arch::asm;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{
    CAP_MINT_SET_BADGE, CapId, DmaCacheOp, DomainRoleId, IrqTriggerMode, NOTIFY_WAIT_TIMEOUT,
    ObjectType, Rights, ShutdownStatus, SysError, SyscallNumber,
};

pub const DEBUG_WRITE_MAX: usize = 1024;
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
///
/// # Errors
/// Returns [`SysError`] if `console_cap` lacks `Rights::WRITE` or `msg` is rejected by the kernel.
pub fn debug_log_with_cap(console_cap: CapId, msg: &str) -> Result<usize, SysError> {
    raw_syscall(
        SyscallNumber::DebugWrite,
        console_cap.raw(),
        msg.as_ptr().addr() as u64,
        msg.len() as u64,
        0,
    )
    .and_then(|n| usize::try_from(n).map_err(|_| SysError::InvalidArgument))
}

/// Write a UTF-8 diagnostic message to the microkernel's early debug console.
///
/// # Errors
/// Returns [`SysError`] if `CapId::BOOTSTRAP_CONSOLE` lacks `Rights::WRITE` or the write fails.
pub fn debug_log(msg: &str) -> Result<usize, SysError> {
    debug_log_with_cap(CapId::BOOTSTRAP_CONSOLE, msg)
}

/// Write an entire UTF-8 string to the debug console, chunking at `<= 1024`B (`DEBUG_WRITE_MAX`) UTF-8 char boundaries.
///
/// # Errors
/// Returns [`SysError`] if any chunk fails to write or returns an invalid byte count.
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DebugConsole;

impl Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        debug_write_all(s).map_err(|_| fmt::Error)
    }
}

/// Fixed-size stack-buffered `core::fmt::Write` console.
///
/// Coalesces `write!`/`writeln!` fragments into `<= N`-byte `DebugWrite` syscalls and
/// flushes automatically on `Drop` (call `flush()` explicitly before diverging calls).
pub struct BufferedConsole<const N: usize = DEBUG_WRITE_MAX> {
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> fmt::Debug for BufferedConsole<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferedConsole")
            .field("buffered_bytes", &self.pos)
            .field("capacity", &N)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> BufferedConsole<N> {
    #[must_use]
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
///
/// # Errors
/// Returns [`SysError`] if `ep` is invalid, lacks `Rights::WRITE`, or remains full after retries.
pub fn ipc_log_write(ep: CapId, msg: &str) -> Result<usize, SysError> {
    const MAX_LOG_RETRIES: usize = 512;
    let bytes = msg.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + newos_abi::log_ipc::MAX_CHUNK_BYTES).min(bytes.len());
        let word = newos_abi::log_ipc::encode_chunk(&bytes[offset..end]);
        let mut sent = false;
        for _ in 0..MAX_LOG_RETRIES {
            match ipc_send(ep, word) {
                Ok(()) => {
                    sent = true;
                    break;
                }
                Err(SysError::WouldBlock) => {
                    let _ = yield_now();
                }
                Err(e) => return Err(e),
            }
        }
        if !sent {
            return Err(SysError::WouldBlock);
        }
        offset = end;
    }
    Ok(bytes.len())
}

/// Buffered `core::fmt::Write` sink for isolated protection domains without a direct
/// `Console` capability, routing output over `CapId::BOOTSTRAP_LOG_EP` to `supervisor-pd`.
pub struct IpcLogConsole<const N: usize = 256> {
    ep: CapId,
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize> fmt::Debug for IpcLogConsole<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcLogConsole")
            .field("ep", &self.ep)
            .field("buffered_bytes", &self.pos)
            .field("capacity", &N)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> IpcLogConsole<N> {
    #[must_use]
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

/// Number of concurrent sender reassembly slots in [`IpcLogAssembler`].
const MAX_LOG_ASSEMBLER_SLOTS: usize = 6;

#[derive(Clone, Copy)]
struct ActiveLogSlot<const N: usize> {
    badge: u64,
    len: usize,
    buf: [u8; N],
}

#[derive(Clone, Copy)]
struct PendingChunk {
    bytes: [u8; newos_abi::log_ipc::MAX_CHUNK_BYTES],
    off: usize,
    len: usize,
    badge: u64,
}

/// Per-sender line reassembler for fastpath IPC log chunks (`CapId::BOOTSTRAP_LOG_EP`).
///
/// Used by the console owner (`supervisor-pd`) to drain 7-byte fastpath IPC log chunks into
/// complete lines without interleaving or truncating concurrent protection domains
/// (`worker-pd`, `net-pd`, `key-pd`, `ssh-pd`).
pub struct IpcLogAssembler<const N: usize = 256> {
    slots: [Option<ActiveLogSlot<N>>; MAX_LOG_ASSEMBLER_SLOTS],
    pending: Option<PendingChunk>,
}

impl<const N: usize> fmt::Debug for IpcLogAssembler<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active_slots = self.slots.iter().filter(|s| s.is_some()).count();
        f.debug_struct("IpcLogAssembler")
            .field("active_slots", &active_slots)
            .field("has_pending_chunk", &self.pending.is_some())
            .field("line_capacity", &N)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> IpcLogAssembler<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_LOG_ASSEMBLER_SLOTS],
            pending: None,
        }
    }

    fn emit_slot(&mut self, slot_idx: usize, out: &mut [u8]) -> Option<(u64, usize)> {
        let slot = self.slots[slot_idx].take()?;
        let n = slot.len.min(out.len());
        out[..n].copy_from_slice(&slot.buf[..n]);
        Some((slot.badge, n))
    }

    /// Find the existing slot for `badge` or allocate a free one.
    /// Returns `Err(evict_idx)` if all slots are occupied so the caller can flush `evict_idx` first.
    fn find_or_alloc_slot(&mut self, badge: u64) -> Result<usize, usize> {
        let mut free_idx = None;
        for (i, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(active) if active.badge == badge => return Ok(i),
                None if free_idx.is_none() => free_idx = Some(i),
                _ => {}
            }
        }
        let Some(idx) = free_idx else {
            return Err(0);
        };
        self.slots[idx] = Some(ActiveLogSlot {
            badge,
            len: 0,
            buf: [0; N],
        });
        Ok(idx)
    }

    fn feed_pending_chunk(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        let mut pending = self.pending.take()?;
        let slot_idx = match self.find_or_alloc_slot(pending.badge) {
            Ok(idx) => idx,
            Err(evict_idx) => {
                self.pending = Some(pending);
                return self.emit_slot(evict_idx, out);
            }
        };
        while pending.off < pending.len {
            let b = pending.bytes[pending.off];
            pending.off += 1;
            if b == b'\n' {
                if pending.off < pending.len {
                    self.pending = Some(pending);
                }
                return self.emit_slot(slot_idx, out);
            }
            if b == b'\r' || (b < 0x20 && b != b'\t') || b == 0x7F {
                continue;
            }
            if let Some(slot) = self.slots[slot_idx].as_mut() {
                if slot.len < N {
                    slot.buf[slot.len] = b;
                    slot.len += 1;
                }
                if slot.len == N {
                    if pending.off < pending.len {
                        self.pending = Some(pending);
                    }
                    return self.emit_slot(slot_idx, out);
                }
            }
        }
        None
    }

    /// Drain any remaining bytes from a previously pushed multi-line chunk without performing
    /// syscalls (Sans-I/O).
    ///
    /// Callers using [`Self::push_chunk`] directly should drain `poll_pending` until it returns
    /// `None` before pushing the next chunk so multi-line chunk remainders are never overwritten.
    pub fn poll_pending(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        self.feed_pending_chunk(out)
    }

    /// Feed a single decoded fastpath IPC log chunk `(badge, payload)` into the pure line
    /// reassembler state machine without performing any syscalls (Sans-I/O).
    ///
    /// Copies any completed line into `out` and returns `Some((sender_badge, len))`.
    /// Callers must drain [`Self::poll_pending`] until `None` before pushing another chunk.
    pub fn push_chunk(&mut self, badge: u64, payload: u64, out: &mut [u8]) -> Option<(u64, usize)> {
        let (chunk, chunk_len) = newos_abi::log_ipc::decode_chunk(payload);
        if chunk_len > 0 {
            self.pending = Some(PendingChunk {
                bytes: chunk,
                off: 0,
                len: chunk_len,
                badge,
            });
        }
        self.feed_pending_chunk(out)
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
            let (badge, payload) = ipc_recv(ep).ok()?;
            if let Some(res) = self.push_chunk(badge, payload, out) {
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
///
/// # Errors
/// Returns [`SysError`] if the kernel rejects the `Yield` syscall.
pub fn yield_now() -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::Yield, 0, 0, 0, 0)
}

/// Bitwise-OR `badge` into a 64-bit kernel `Notification` capability.
///
/// # Errors
/// Returns [`SysError`] if `cap` is not a valid `Notification` capability with `Rights::WRITE`.
pub fn notify_signal(cap: CapId, badge: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::NotifySignal, cap.raw(), badge, 0, 0).map(|_| ())
}

/// Atomically read and clear the 64-bit signal word of a `Notification` capability.
///
/// # Errors
/// Returns [`SysError`] if `cap` is not a valid `Notification` capability with `Rights::READ`.
pub fn notify_poll(cap: CapId) -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::NotifyPoll, cap.raw(), 0, 0, 0)
}

/// Send a register-only fastpath IPC payload to an `Endpoint` capability.
///
/// # Errors
/// Returns [`SysError`] if `cap` lacks `Rights::WRITE` or the endpoint buffer is full (`WouldBlock`).
pub fn ipc_send(cap: CapId, payload: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::IpcSend, cap.raw(), payload, 0, 0).map(|_| ())
}

/// Receive a pending fastpath IPC `(badge, payload)` pair (full 64-bit badge + 64-bit payload).
///
/// # Errors
/// Returns [`SysError`] if `cap` lacks `Rights::READ` or no message is pending (`WouldBlock`).
pub fn ipc_recv(cap: CapId) -> Result<(u64, u64), SysError> {
    let (payload, badge) = raw_syscall_full(SyscallNumber::IpcRecv, cap.raw(), 0, 0, 0)?;
    Ok((badge, payload))
}

/// Synchronous send+receive fastpath (`IpcCall`) in a single client syscall (full 64-bit badge + payload).
///
/// # Errors
/// Returns [`SysError`] if `ep` lacks `Rights::WRITE`, the server is unavailable, or the call fails.
pub fn ipc_call(ep: CapId, payload: u64) -> Result<(u64, u64), SysError> {
    let (reply_payload, badge) = raw_syscall_full(SyscallNumber::IpcCall, ep.raw(), payload, 0, 0)?;
    Ok((badge, reply_payload))
}

/// Combined reply + wait-for-next-request fastpath (`IpcReplyRecv`) in a single server syscall.
///
/// # Errors
/// Returns [`SysError`] if `ep` lacks `Rights::READ` or no next request is available (`WouldBlock`).
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
///
/// # Errors
/// Returns [`SysError`] if the kernel rejects the `ReadCycles` syscall.
pub fn read_cycles() -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::ReadCycles, 0, 0, 0, 0)
}

/// Read the architectural ARM Generic Timer frequency (`CNTFRQ_EL0`) in Hz (cached after first call).
///
/// Falls back to `62_500_000` Hz (QEMU `virt`) if the syscall is unsupported or hardware reports 0.
#[must_use]
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
///
/// # Errors
/// Returns [`SysError`] if `irq_cap` is invalid, lacks `Rights::WRITE`, or returns an out-of-range IRQ ID.
pub fn irq_ack(irq_cap: CapId) -> Result<u16, SysError> {
    raw_syscall(SyscallNumber::IrqAck, irq_cap.raw(), 0, 0, 0)
        .and_then(|v| u16::try_from(v).map_err(|_| SysError::InvalidArgument))
}

/// Bind an `IrqHandler` capability (`Rights::WRITE`) to a `Notification` capability (`Rights::WRITE`)
/// at `badge_bit` (`0..=63`) with the given trigger mode.
///
/// # Errors
/// Returns [`SysError`] if capabilities lack `Rights::WRITE`, `badge_bit >= 64`, or the IRQ is already bound.
pub fn irq_bind(
    irq_cap: CapId,
    notif_cap: CapId,
    badge_bit: u8,
    mode: IrqTriggerMode,
) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::IrqBind,
        irq_cap.raw(),
        notif_cap.raw(),
        u64::from(badge_bit),
        mode as u64,
    )
    .map(|_| ())
}

/// Block until `(notification_word & mask) != 0` or `timeout_ns` elapses (`0` = wait forever).
///
/// Returns `(matched_bits, timed_out)`. Rejects `mask == 0` with [`SysError::InvalidArgument`].
///
/// # Errors
/// Returns [`SysError`] if `cap` lacks `Rights::READ` or `mask == 0`.
pub fn notify_wait(cap: CapId, mask: u64, timeout_ns: u64) -> Result<(u64, bool), SysError> {
    raw_syscall_full(SyscallNumber::NotifyWait, cap.raw(), mask, timeout_ns, 0)
        .map(|(bits, flags)| (bits, (flags & NOTIFY_WAIT_TIMEOUT) != 0))
}

/// Block until the monotonic counter `CNTVCT_EL0` reaches `deadline_ticks`.
///
/// # Errors
/// Returns [`SysError`] if the kernel rejects the `SleepUntil` syscall.
pub fn sleep_until(deadline_ticks: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::SleepUntil, deadline_ticks, 0, 0, 0).map(|_| ())
}

/// Sleep for `ms` milliseconds using `CNTVCT_EL0` and `timer_freq_hz()`.
///
/// # Errors
/// Returns [`SysError`] if reading the cycle counter or sleeping fails.
pub fn sleep_ms(ms: u64) -> Result<(), SysError> {
    if ms == 0 {
        return Ok(());
    }
    let freq = timer_freq_hz().max(1);
    let ticks =
        u64::try_from(((u128::from(ms) * u128::from(freq)) / 1_000).max(1)).unwrap_or(u64::MAX);
    let deadline = read_cycles()?.saturating_add(ticks);
    sleep_until(deadline)
}

/// Map an entire page-aligned, page-isolated `MmioRegion` capability into `vspace_cap`
/// (`Rights::WRITE`) at `vaddr` with `Device-nGnRnE` + `UXN` + `PXN`.
///
/// Returns the mapped byte length.
///
/// # Errors
/// Returns [`SysError`] if capabilities are invalid, `vaddr` is misaligned/occupied, or OOM.
pub fn mmio_map(vspace_cap: CapId, mmio_cap: CapId, vaddr: u64) -> Result<u64, SysError> {
    raw_syscall(
        SyscallNumber::MmioMap,
        vspace_cap.raw(),
        mmio_cap.raw(),
        vaddr,
        0,
    )
}

/// Register an EL0 supervisor recovery entry point invoked if an EL0 hardware fault occurs.
///
/// The kernel resets `SP_EL0` to the 16-byte-aligned top of `SUPERVISOR_RECOVERY_STACK`
/// before entering `handler`. Safe for single-threaded EL0 protection domains because any prior
/// frame on the recovery stack is abandoned by the kernel on fault re-entry.
///
/// # Errors
/// Returns [`SysError`] if the kernel rejects the handler or recovery stack address.
pub fn set_fault_handler(handler: extern "C" fn() -> !) -> Result<(), SysError> {
    let stack_top = (&raw const SUPERVISOR_RECOVERY_STACK)
        .addr()
        .wrapping_add(RECOVERY_STACK_SIZE) as u64;
    raw_syscall(
        SyscallNumber::SetFaultHandler,
        (handler as *const ()).addr() as u64,
        stack_top,
        0,
        0,
    )
    .map(|_| ())
}

/// Perform a capability-scoped 32-bit MMIO read through an `MmioRegion` capability.
///
/// # Errors
/// Returns [`SysError`] if `mmio_cap` lacks `Rights::READ`, `byte_offset` is misaligned/out-of-bounds, or the read fails.
pub fn mmio_read32(mmio_cap: CapId, byte_offset: u64) -> Result<u32, SysError> {
    raw_syscall(SyscallNumber::MmioRead32, mmio_cap.raw(), byte_offset, 0, 0)
        .and_then(|v| u32::try_from(v).map_err(|_| SysError::InvalidArgument))
}

/// Perform a capability-scoped 32-bit MMIO write through an `MmioRegion` capability.
///
/// # Errors
/// Returns [`SysError`] if `mmio_cap` lacks `Rights::WRITE` or `byte_offset` is misaligned/out-of-bounds.
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
///
/// # Errors
/// Returns [`SysError`] if `vspace_cap` lacks `Rights::READ` or `value` is not mapped in EL0.
pub fn virt_to_phys_with_cap<T>(vspace_cap: CapId, value: &T) -> Result<u64, SysError> {
    let va = core::ptr::from_ref(value).addr() as u64;
    raw_syscall(SyscallNumber::VirtToPhys, vspace_cap.raw(), va, 0, 0)
}

/// Translate an EL0 reference's virtual address in `BOOTSTRAP_VSPACE` to its physical address.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_VSPACE` lacks `Rights::READ` or `value` is not mapped in EL0.
pub fn virt_to_phys<T>(value: &T) -> Result<u64, SysError> {
    virt_to_phys_with_cap(CapId::BOOTSTRAP_VSPACE, value)
}

/// Perform PAN-safe DMA cache maintenance on `value` via `vspace_cap` (`Rights::READ`).
///
/// # Errors
/// Returns [`SysError`] if `vspace_cap` lacks `Rights::READ` or `value` spans unmapped/unwritable pages.
pub fn dma_cache_op_with_cap<T>(
    vspace_cap: CapId,
    value: &T,
    op: DmaCacheOp,
) -> Result<u64, SysError> {
    let va = core::ptr::from_ref(value).addr() as u64;
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
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_VSPACE` lacks `Rights::READ` or `value` is not mapped in EL0.
pub fn dma_clean<T>(value: &T) -> Result<u64, SysError> {
    dma_cache_op_with_cap(CapId::BOOTSTRAP_VSPACE, value, DmaCacheOp::Clean)
}

/// Clean & invalidate data cache lines (`dc civac`) for `value` before/after inbound DMA.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_VSPACE` lacks `Rights::READ` or `value` is not writable in EL0.
pub fn dma_invalidate<T>(value: &T) -> Result<u64, SysError> {
    dma_cache_op_with_cap(CapId::BOOTSTRAP_VSPACE, value, DmaCacheOp::Invalidate)
}

/// Read packed `ARMv8.2-A` `Cortex-A76` ISA feature bitmask & cache/PA geometry (`newos_abi::cpu_isa`).
///
/// # Errors
/// Returns [`SysError`] if `power_cap` lacks `Rights::READ`.
pub fn cpu_features_with_cap(power_cap: CapId) -> Result<u64, SysError> {
    raw_syscall(SyscallNumber::CpuFeatures, power_cap.raw(), 0, 0, 0)
}

/// Read packed `ARMv8.2-A` `Cortex-A76` ISA feature bitmask via `BOOTSTRAP_POWER`.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_POWER` lacks `Rights::READ`.
pub fn cpu_features() -> Result<u64, SysError> {
    cpu_features_with_cap(CapId::BOOTSTRAP_POWER)
}

/// Derive a capability in the caller's `CSpace` with attenuated `rights` and optional immutable `badge`.
///
/// Pass `dst_slot = None` to let the kernel choose the first free slot automatically.
///
/// # Errors
/// Returns [`SysError`] if `src` is invalid, `rights` exceed `src`, or no destination slot is free.
pub fn cap_mint(
    src: CapId,
    dst_slot: Option<usize>,
    rights: Rights,
    new_badge: Option<u64>,
) -> Result<CapId, SysError> {
    let (flags, badge) = new_badge.map_or_else(
        || (u64::from(rights.bits()), 0),
        |b| (u64::from(rights.bits()) | CAP_MINT_SET_BADGE, b),
    );
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
///
/// # Errors
/// Returns [`SysError`] if `src` is invalid or `dst_slot` is occupied/out-of-range.
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
///
/// # Errors
/// Returns [`SysError`] if `src` is invalid or `dst_slot` is occupied/out-of-range.
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
///
/// # Errors
/// Returns [`SysError`] if `cap` does not refer to a live capability in the caller's `CSpace`.
pub fn cap_delete(cap: CapId) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::CapDelete, cap.raw(), 0, 0, 0).map(|_| ())
}

/// Transitively revoke all CDT descendants derived from `cap` in the caller's `CSpace`.
///
/// # Errors
/// Returns [`SysError`] if `cap` is invalid or the returned count overflows `usize`.
pub fn cap_revoke(cap: CapId) -> Result<usize, SysError> {
    raw_syscall(SyscallNumber::CapRevoke, cap.raw(), 0, 0, 0)
        .and_then(|n| usize::try_from(n).map_err(|_| SysError::InvalidArgument))
}

/// Map a fresh zeroed 4 KiB page at `vaddr` in `vspace_cap` (strict W^X enforced; requires `Rights::WRITE`).
///
/// # Errors
/// Returns [`SysError`] if `vspace_cap` lacks `Rights::WRITE`, `rights` violate W^X, `vaddr` is occupied, or OOM.
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
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_VSPACE` lacks `Rights::WRITE`, `rights` violate W^X, `vaddr` is occupied, or OOM.
pub fn map_page(vaddr: u64, rights: Rights) -> Result<(), SysError> {
    map_page_with_cap(CapId::BOOTSTRAP_VSPACE, vaddr, rights)
}

/// Unmap a 4 KiB page at `vaddr` from `vspace_cap` and reclaim its physical frame (`Rights::WRITE`).
///
/// # Errors
/// Returns [`SysError`] if `vspace_cap` lacks `Rights::WRITE` or `vaddr` is not mapped.
pub fn unmap_page_with_cap(vspace_cap: CapId, vaddr: u64) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::UnmapPage, vspace_cap.raw(), vaddr, 0, 0).map(|_| ())
}

/// Unmap a 4 KiB page at `vaddr` from `BOOTSTRAP_VSPACE` and reclaim its physical frame.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_VSPACE` lacks `Rights::WRITE` or `vaddr` is not mapped.
pub fn unmap_page(vaddr: u64) -> Result<(), SysError> {
    unmap_page_with_cap(CapId::BOOTSTRAP_VSPACE, vaddr)
}

/// Retype a kernel object (`Frame`, `Endpoint`, `Notification`) from a designated `Untyped` cap.
///
/// # Errors
/// Returns [`SysError`] if `untyped_cap` lacks rights, memory is exhausted, or `dst_slot` is occupied.
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
///
/// # Errors
/// Returns [`SysError`] if capabilities lack rights, W^X is violated, `vaddr` is occupied, or OOM.
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

/// Bidirectional pair of lock-free `SpscRing<128>` channels fitting in a single 4 KiB shared frame.
#[derive(Debug)]
#[repr(C, align(4096))]
pub struct SharedRingPair {
    pub a_to_b: newos_abi::ring::SpscRing<128>,
    pub b_to_a: newos_abi::ring::SpscRing<128>,
}

const _: () = assert!(core::mem::size_of::<SharedRingPair>() == 4096);

/// Map a shared 4 KiB `Frame` capability at page-aligned `vaddr` and return a safe shared reference
/// to the interior-mutable `SharedRingPair` backed by atomic operations.
///
/// Callers must pass their active `VSpace` capability (e.g. [`CapId::BOOTSTRAP_VSPACE`]) and
/// never unmap `vaddr` for the lifetime of the protection domain.
///
/// # Errors
/// Returns [`SysError`] if `vaddr` is zero/misaligned or `frame_map` fails.
pub fn map_shared_ring_pair(
    vspace_cap: CapId,
    frame_cap: CapId,
    vaddr: u64,
) -> Result<&'static SharedRingPair, SysError> {
    if (vaddr & 0xFFF) != 0 || vaddr == 0 {
        return Err(SysError::InvalidArgument);
    }
    frame_map(
        vspace_cap,
        frame_cap,
        vaddr,
        Rights::READ.union(Rights::WRITE),
    )?;
    // SAFETY: `frame_map` mapped a 4 KiB RW RAM page at 4 KiB-aligned `vaddr` in the caller's
    // active `VSpace`, and the mapping remains permanently installed for `'static` (never unmapped).
    // `SharedRingPair` is `#[repr(C, align(4096))]`, `size_of == 4096`, and consists solely of
    // interior-mutable atomics (`AtomicUsize` / `AtomicU64`) for which any bit pattern is valid
    // without UB (even when a peer domain has already written to the shared frame) and concurrent
    // cross-domain `&` access is race-free.
    Ok(unsafe { &*(vaddr as *const SharedRingPair) })
}

/// Set scheduling priority (`0..=255`, higher value = higher priority) on `thread_cap` (`Rights::WRITE`).
///
/// # Errors
/// Returns [`SysError`] if `thread_cap` lacks `Rights::WRITE` or `priority` exceeds the caller's MCP ceiling.
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
///
/// # Errors
/// Returns [`SysError`] if capabilities lack rights, `rights` exceed `src`, or the destination `CNode` is full.
pub fn cap_grant(
    dst_cnode_cap: CapId,
    src: CapId,
    rights: Rights,
    new_badge: Option<u64>,
) -> Result<CapId, SysError> {
    let (flags, badge) = new_badge.map_or_else(
        || (u64::from(rights.bits()), 0),
        |b| (u64::from(rights.bits()) | CAP_MINT_SET_BADGE, b),
    );
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
    // registered fault handler or terminates the protection domain; control never returns (`noreturn`).
    unsafe {
        asm!("udf #0", options(noreturn));
    }
}

/// Read-only system summary returned by `sys_info()`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SysInfo {
    pub online_cpus: u16,
    pub domain_count: u16,
    pub interactive_shell: bool,
}

/// Non-blocking 1-byte read from the debug serial console using an explicit `Console` cap (`Rights::READ`).
///
/// # Errors
/// Returns [`SysError`] if `console_cap` lacks `Rights::READ` or no byte is available (`WouldBlock`).
pub fn debug_read_byte_with_cap(console_cap: CapId) -> Result<u8, SysError> {
    raw_syscall(SyscallNumber::DebugRead, console_cap.raw(), 0, 0, 0)
        .and_then(|b| u8::try_from(b).map_err(|_| SysError::InvalidArgument))
}

/// Non-blocking 1-byte read from the debug serial console (`Err(WouldBlock)` if no input).
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_CONSOLE` lacks `Rights::READ` or no byte is available (`WouldBlock`).
pub fn debug_read_byte() -> Result<u8, SysError> {
    debug_read_byte_with_cap(CapId::BOOTSTRAP_CONSOLE)
}

#[inline]
#[allow(clippy::cast_possible_truncation)] // Masked to 16 bits (`& 0xFFFF`).
const fn decode_sys_info(raw: u64) -> SysInfo {
    SysInfo {
        online_cpus: (raw & 0xFFFF) as u16,
        domain_count: ((raw >> 16) & 0xFFFF) as u16,
        interactive_shell: ((raw >> 32) & 1) != 0,
    }
}

/// Read live microkernel system info (`online_cpus`, active `domain_count`, `interactive_shell`)
/// via `BOOTSTRAP_POWER` (`Rights::READ`).
#[must_use]
pub fn sys_info() -> SysInfo {
    decode_sys_info(
        raw_syscall(
            SyscallNumber::SysInfo,
            CapId::BOOTSTRAP_POWER.raw(),
            0,
            0,
            0,
        )
        .unwrap_or(0),
    )
}

/// Respawn an exited/crashed EL0 protection domain from its immutable boot module with fresh ASLR
/// (`BOOTSTRAP_POWER`, `Rights::WRITE`). Returns the new PD ID.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_POWER` lacks `Rights::WRITE`, `role` is already active/unsupported, or OOM.
pub fn domain_respawn(role: DomainRoleId) -> Result<usize, SysError> {
    raw_syscall(
        SyscallNumber::DomainRespawn,
        CapId::BOOTSTRAP_POWER.raw(),
        role as u64,
        0,
        0,
    )
    .and_then(|pd_id| usize::try_from(pd_id).map_err(|_| SysError::InvalidArgument))
}

/// Terminate and tear down a non-supervisor EL0 protection domain via its `Thread` capability (`Rights::WRITE`).
///
/// # Errors
/// Returns [`SysError`] if `thread_cap` lacks `Rights::WRITE`, targets PD 0/self, or must retry (`WouldBlock`).
pub fn domain_destroy(thread_cap: CapId) -> Result<(), SysError> {
    raw_syscall(SyscallNumber::DomainDestroy, thread_cap.raw(), 0, 0, 0).map(|_| ())
}

/// Read and clear the last recorded hardware fault info for `pd_id` (`BOOTSTRAP_POWER`, `Rights::READ`).
///
/// Returns `(role, esr_el1, elr_el1)`.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_POWER` lacks `Rights::READ` or no fault is recorded for `pd_id`.
pub fn domain_get_fault_info(pd_id: usize) -> Result<(DomainRoleId, u64, u64), SysError> {
    let (packed, elr) = raw_syscall_full(
        SyscallNumber::DomainGetFaultInfo,
        CapId::BOOTSTRAP_POWER.raw(),
        pd_id as u64,
        0,
        0,
    )?;
    let role = DomainRoleId::from_u64(packed >> 56).ok_or(SysError::InvalidArgument)?;
    let esr = packed & 0x00FF_FFFF_FFFF_FFFF;
    Ok((role, esr, elr))
}

/// Pin a caller-owned `Frame` capability in `iospace_cap` for hardware DMA (`H2`/`H4`),
/// optionally mapping it as Normal Non-Cacheable (`DMA_FLAG_NON_CACHEABLE`) at `opt_nc_vaddr`.
///
/// # Errors
/// Returns [`SysError`] if capabilities lack rights, W^X is violated, `opt_nc_vaddr` is invalid/occupied, or OOM.
pub fn dma_map(
    iospace_cap: CapId,
    frame_cap: CapId,
    flags: u64,
    opt_nc_vaddr: u64,
) -> Result<u64, SysError> {
    raw_syscall(
        SyscallNumber::DmaMap,
        iospace_cap.raw(),
        frame_cap.raw(),
        flags,
        opt_nc_vaddr,
    )
}

/// Unpin a previously DMA-mapped `Frame` capability from `iospace_cap`.
///
/// # Errors
/// Returns [`SysError`] if `iospace_cap` or `frame_cap` lacks required rights.
pub fn dma_unmap(iospace_cap: CapId, frame_cap: CapId) -> Result<(), SysError> {
    raw_syscall(
        SyscallNumber::DmaUnmap,
        iospace_cap.raw(),
        frame_cap.raw(),
        0,
        0,
    )
    .map(|_| ())
}

/// Read kernel physical memory stats (`BOOTSTRAP_POWER`, `Rights::READ`).
///
/// Returns `(remaining_frames, reclaimed_cache_len)`.
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_POWER` lacks `Rights::READ`.
pub fn mem_stats() -> Result<(u64, u64), SysError> {
    raw_syscall_full(
        SyscallNumber::MemStats,
        CapId::BOOTSTRAP_POWER.raw(),
        0,
        0,
        0,
    )
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

/// Define an EL0 userspace `_start` entry point delegating to a safe `fn() -> !`.
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

/// Forward standard EL0 `ShellHost` syscall methods (`sys_info`, `ipc_*`, `yield_now`,
/// `read_cycles`) directly to `newos_user_rt`.
#[macro_export]
macro_rules! forward_shell_host_syscalls {
    () => {
        fn sys_info(&mut self) -> SysInfo {
            let info = $crate::sys_info();
            SysInfo {
                online_cpus: info.online_cpus,
                domain_count: info.domain_count,
                interactive_shell: info.interactive_shell,
            }
        }

        fn ipc_send(
            &mut self,
            cap: newos_abi::CapId,
            payload: u64,
        ) -> Result<(), newos_abi::SysError> {
            $crate::ipc_send(cap, payload)
        }

        fn ipc_recv(&mut self, cap: newos_abi::CapId) -> Result<(u64, u64), newos_abi::SysError> {
            $crate::ipc_recv(cap)
        }

        fn ipc_call(
            &mut self,
            cap: newos_abi::CapId,
            payload: u64,
        ) -> Result<(u64, u64), newos_abi::SysError> {
            $crate::ipc_call(cap, payload)
        }

        fn yield_now(&mut self) -> Result<u64, newos_abi::SysError> {
            $crate::yield_now()
        }

        fn read_cycles(&mut self) -> Result<u64, newos_abi::SysError> {
            $crate::read_cycles()
        }
    };
}
