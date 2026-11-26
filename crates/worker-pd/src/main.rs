#![no_std]
#![no_main]

//! Isolated EL0 Worker Process (`worker`).
//!
//! Runs in its own hardware `TTBR0_EL1` `VSpace` at the exact same virtual base (`0x400000`)
//! as `supervisor-pd`, communicating solely via capability-checked microkernel `Endpoint` IPC.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, SysError};
use newos_user_rt::IpcLogConsole;

newos_user_rt::entry!(main);

const CHAOS_FAULT_TRIGGER: u64 = 0xDEAD_C0DE;

fn main() -> ! {
    let mut out = IpcLogConsole::<256>::new(CapId::BOOTSTRAP_LOG_EP);
    let _ = writeln!(
        out,
        "[worker] alive in isolated EL0 VSpace (vaddr=0x400000, separate TTBR0_EL1)!"
    );
    out.flush();

    let mut pending_reply: Option<u64> = None;

    loop {
        match newos_user_rt::ipc_reply_recv(
            CapId::BOOTSTRAP_EP,
            pending_reply.unwrap_or(0),
            pending_reply.is_some(),
        ) {
            Ok((_badge, payload)) => {
                if payload == CHAOS_FAULT_TRIGGER {
                    // Deliberate EL0 hardware fault used by Phase 2 chaos-respawn self-tests.
                    newos_user_rt::trigger_user_fault();
                }
                pending_reply = Some(payload.wrapping_add(1));
            }
            Err(SysError::WouldBlock) => {
                pending_reply = None;
                let _ = newos_user_rt::yield_now();
            }
            Err(err) => {
                let _ = writeln!(
                    out,
                    "[worker] fatal IPC error (code={}); exiting IPC loop",
                    err as u64
                );
                out.flush();
                break;
            }
        }
    }

    // Terminate cleanly via `ThreadExit` (no `PowerControl` cap required).
    newos_user_rt::thread_exit()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[worker] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
