#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Ring-3 Root Task (`init`), Crash Supervisor, Content-Addressed Object Store (CAOS),
//! and Post-UNIX Typed Pipeline Shell (`newos-sh`).
//!
//! 100% memory-safe Rust (`#![forbid(unsafe_code)]`, `no_alloc`).

mod caos;
mod shell;

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, QemuExitCode, SysError};
use newos_user_rt::DebugConsole;
use shell::Shell;

newos_user_rt::entry!(main);

extern "C" fn supervisor_recover() -> ! {
    let mut out = DebugConsole;
    let info = newos_user_rt::sys_info();

    match newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF) {
        Ok(bits) if bits != 0 => {
            if info.interactive_shell {
                let _ = writeln!(
                    out,
                    "[init-supervisor] recovered from Ring-3 fault (bits={:#x}) — restarting `newos-sh`!",
                    bits
                );
                let _ = newos_user_rt::set_fault_handler(supervisor_recover);
                let mut sh = Shell::new();
                sh.run_interactive()
            } else if bits == (1 << 6) {
                let _ = writeln!(
                    out,
                    "[init] phase-6 Ring-3 crash isolation & supervisor recovery: OK (fault_bits={:#x})",
                    bits
                );
                newos_user_rt::exit(QemuExitCode::Success)
            } else {
                let _ = writeln!(out, "[init] FAIL: unexpected fault bits {bits:#x}");
                newos_user_rt::exit(QemuExitCode::Failed)
            }
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
    let info = newos_user_rt::sys_info();
    let _ = newos_user_rt::set_fault_handler(supervisor_recover);

    if info.interactive_shell {
        let mut sh = Shell::new();
        sh.run_interactive()
    }

    // Automated self-test mode (`cargo xtask test`)
    let _ = writeln!(
        out,
        "[init] hello from Ring 3 (100% safe Rust, forbid_unsafe, isolated CR3 VSpace)!"
    );

    // Multi-process CR3 IPC ping-pong with isolated Ring-3 `worker` process
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    if newos_user_rt::ipc_send(CapId::BOOTSTRAP_EP, PING_PAYLOAD).is_err() {
        let _ = writeln!(out, "[init] FAIL: ipc_send to worker failed");
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = newos_user_rt::yield_now();
    if newos_user_rt::ipc_recv(CapId::BOOTSTRAP_EP) != Ok((0x5E14, PING_PAYLOAD + 1)) {
        let _ = writeln!(out, "[init] FAIL: missing IPC reply from worker");
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] multi-process isolated CR3 IPC ping-pong with `worker`: OK"
    );

    // 64-bit Notification coalescing + userspace SpscRing check
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 0).is_err()
        || newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 2).is_err()
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0b101)
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0)
    {
        let _ = writeln!(out, "[init] FAIL: Notification capability check failed");
        newos_user_rt::exit(QemuExitCode::Failed);
    }

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

    // Hardware CR3 context-switch latency benchmark
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

    // Ring-3 Post-UNIX CAOS + Typed Pipeline Shell (`newos-sh`) self-check
    let mut sh = Shell::new();
    if let Err(msg) = sh.run_self_test() {
        let _ = writeln!(out, "[init] FAIL: Ring-3 CAOS & typed pipeline self-check: {msg}");
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] Ring-3 CAOS (dedup/rollback/seal) & typed `|` pipeline self-check: OK"
    );

    // Ring-3 Networking: capability-scoped VirtIO-MMIO probe + pure-Rust `smoltcp` IPv4/UDP stack
    let detected_nic =
        newos_net::probe_virtio_net(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
    let mac = detected_nic
        .map(|n| n.mac)
        .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    match newos_net::verify_smoltcp_ring3_stack(mac) {
        Ok(frame_len) => {
            if let Some(nic) = detected_nic {
                let _ = writeln!(
                    out,
                    "[init] Ring-3 VirtIO-net (slot={}, v{}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}) & smoltcp ({frame_len}B frame): OK",
                    nic.slot, nic.version, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                );
            } else {
                let _ = writeln!(
                    out,
                    "[init] Ring-3 smoltcp IPv4/UDP stack ({frame_len}B Ethernet frame, no_alloc, forbid_unsafe): OK"
                );
            }
        }
        Err(msg) => {
            let _ = writeln!(out, "[init] FAIL: Ring-3 smoltcp stack check: {msg}");
            newos_user_rt::exit(QemuExitCode::Failed);
        }
    }

    // Unauthorized MMIO capability rejection
    if newos_user_rt::mmio_read32(CapId::NULL, 0) != Err(SysError::InvalidCapability) {
        let _ = writeln!(out, "[init] FAIL: unauthorized MMIO read was not rejected");
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Deliberate Ring-3 hardware fault (#UD) -> supervisor recovery
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
