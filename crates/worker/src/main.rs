#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Isolated Ring-3 Worker Process (`worker`) — 100% `#![forbid(unsafe_code)]`.
//!
//! Runs in its own hardware `CR3` `VSpace` at the exact same virtual base (`0x400000`)
//! as `init`, communicating solely via capability-checked microkernel `Endpoint` IPC.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, QemuExitCode};
use newos_user_rt::DebugConsole;

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = DebugConsole;
    let _ = writeln!(
        out,
        "[worker] alive in isolated Ring-3 VSpace (vaddr=0x400000, separate CR3)!"
    );

    loop {
        if let Ok((badge, payload)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_EP) {
            let reply = payload.wrapping_add(1);
            let _ = writeln!(
                out,
                "[worker] received IPC (badge={:#x}, payload={:#x}) -> replying {:#x}",
                badge, payload, reply
            );
            let _ = newos_user_rt::ipc_send(CapId::BOOTSTRAP_EP, reply);
        }
        let _ = newos_user_rt::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[worker] PANIC in Ring 3\n");
    newos_user_rt::exit(QemuExitCode::Failed)
}
