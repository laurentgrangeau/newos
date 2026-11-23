#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Modular EL0 Root Task (`newos-init`).
//!
//! - With `feature = "shell"` (default): launches the full Crash Supervisor, CAOS store,
//!   and `newos-sh` typed pipeline shell (with optional networking & SSH auth-gate).
//! - With `--no-default-features`: compiles into a bare minimal EL0 root task with zero
//!   shell, zero networking, zero SSH, and zero crypto dependencies.

#[cfg(feature = "shell")]
mod full;

use core::panic::PanicInfo;
use newos_abi::ShutdownStatus;

newos_user_rt::entry!(entry);

fn entry() -> ! {
    #[cfg(feature = "shell")]
    {
        full::main()
    }
    #[cfg(not(feature = "shell"))]
    {
        minimal_main()
    }
}

#[cfg(not(feature = "shell"))]
fn minimal_main() -> ! {
    use core::fmt::Write;
    let mut out = newos_user_rt::BufferedConsole::<256>::new();
    let _ = writeln!(
        out,
        "[init] minimal EL0 root task online (shell=false, net={}, ssh=false)",
        cfg!(feature = "net"),
    );
    out.flush();

    let interactive = newos_user_rt::sys_info().interactive_shell;
    if !interactive {
        newos_user_rt::exit(ShutdownStatus::Success)
    }
    loop {
        let _ = newos_user_rt::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[init] PANIC in EL0\n");
    newos_user_rt::exit(ShutdownStatus::Failed)
}
