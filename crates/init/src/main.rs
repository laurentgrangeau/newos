#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Ring-3 Root Task (`init`) & Crash Supervisor — 100% memory-safe Rust (`#![forbid(unsafe_code)]`).

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, QemuExitCode, SysError};
use newos_user_rt::DebugConsole;

newos_user_rt::entry!(main);

extern "C" fn supervisor_recover() -> ! {
    let mut out = DebugConsole;
    match newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF) {
        Ok(bits) if bits == (1 << 6) => {
            let _ = writeln!(
                out,
                "[init] phase-6 Ring-3 crash isolation & supervisor recovery: OK (fault_bits={:#x})",
                bits
            );
            newos_user_rt::exit(QemuExitCode::Success)
        }
        other => {
            let _ = writeln!(
                out,
                "[init] FAIL: unexpected fault notification bits: {other:?}"
            );
            newos_user_rt::exit(QemuExitCode::Failed)
        }
    }
}

fn main() -> ! {
    let mut out = DebugConsole;
    let _ = writeln!(
        out,
        "[init] hello from Ring 3 (100% safe Rust, forbid_unsafe, isolated CR3 VSpace)!"
    );

    // Phase 4 + Multi-process CR3 IPC ping-pong with isolated Ring-3 `worker` process!
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    if newos_user_rt::ipc_send(CapId::BOOTSTRAP_EP, PING_PAYLOAD).is_err() {
        let _ = writeln!(out, "[init] FAIL: ipc_send to worker failed");
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Yield triggers a hardware CR3 context switch to `worker` (PID 1), which receives
    // PING_PAYLOAD, replies PING_PAYLOAD + 1, and yields back to `init` (PID 0).
    let _ = newos_user_rt::yield_now();

    if newos_user_rt::ipc_recv(CapId::BOOTSTRAP_EP) != Ok((0x5E14, PING_PAYLOAD + 1)) {
        let _ = writeln!(out, "[init] FAIL: missing IPC reply from worker");
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] multi-process isolated CR3 IPC ping-pong with `worker`: OK"
    );

    // Phase 5a: 64-bit kernel `Notification` capability (coalescing + atomic poll).
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 0).is_err()
        || newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 2).is_err()
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0b101)
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0)
    {
        let _ = writeln!(out, "[init] FAIL: Notification capability check failed");
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Phase 5b: Userspace-only lock-free SPSC shared-memory ring paired with Notification wakeup.
    let ring = SpscRing::<16>::new();
    for i in 0..32u64 {
        if ring.try_push(i * 7).is_err() {
            let _ = writeln!(out, "[init] FAIL: SpscRing push failed");
            newos_user_rt::exit(QemuExitCode::Failed);
        }
        let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1);
        if newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(1)
            || ring.try_pop() != Some(i * 7)
        {
            let _ = writeln!(out, "[init] FAIL: SpscRing pop/notify mismatch");
            newos_user_rt::exit(QemuExitCode::Failed);
        }
    }

    // Phase 5c: Real multi-process CR3 context-switch latency benchmark (100 round-trips init<->worker).
    const ROUNDTRIPS: u64 = 100;
    let t0 = newos_user_rt::read_cycles().unwrap_or(0);
    for _ in 0..ROUNDTRIPS {
        let _ = newos_user_rt::yield_now();
    }
    let t1 = newos_user_rt::read_cycles().unwrap_or(0);
    let avg_cycles = t1.saturating_sub(t0) / (ROUNDTRIPS * 2);
    let _ = writeln!(
        out,
        "[init] phase-5 IPC, Notification & CR3 switch self-check: OK (~{avg_cycles} cycles/CR3-switch)"
    );

    // Phase 6a: Verify unauthorized MMIO capability access is rejected cleanly.
    if newos_user_rt::mmio_read32(CapId::NULL, 0) != Err(SysError::InvalidCapability) {
        let _ = writeln!(out, "[init] FAIL: unauthorized MMIO read was not rejected");
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Phase 6b: Register supervisor fault handler and deliberately crash in Ring 3 (`#UD`).
    if newos_user_rt::set_fault_handler(supervisor_recover).is_err() {
        let _ = writeln!(out, "[init] FAIL: set_fault_handler failed");
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] triggering deliberate Ring-3 hardware fault (#UD) to verify crash isolation..."
    );
    newos_user_rt::trigger_user_fault()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[init] PANIC in Ring 3\n");
    newos_user_rt::exit(QemuExitCode::Failed)
}
