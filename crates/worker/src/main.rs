#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Isolated EL0 Worker Process (`worker`) — 100% `#![forbid(unsafe_code)]`.
//!
//! Runs in its own hardware `TTBR0_EL1` `VSpace` at the exact same virtual base (`0x400000`)
//! as `init`, communicating solely via capability-checked microkernel `Endpoint` IPC.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, QemuExitCode, SysError};
use newos_user_rt::BufferedConsole;

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = BufferedConsole::<256>::new();
    let _ = writeln!(
        out,
        "[worker] alive in isolated EL0 VSpace (vaddr=0x400000, separate TTBR0_EL1)!"
    );
    out.flush();

    let mut has_reply = false;
    let mut reply_payload: u64 = 0;

    loop {
        match newos_user_rt::ipc_reply_recv(CapId::BOOTSTRAP_EP, reply_payload, has_reply) {
            Ok((_badge, payload)) => {
                reply_payload = payload.wrapping_add(1);
                has_reply = true;
            }
            Err(SysError::WouldBlock) | Err(_) => {
                has_reply = false;
                let _ = newos_user_rt::yield_now();
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[worker] PANIC in EL0\n");
    newos_user_rt::exit(QemuExitCode::Failed)
}
