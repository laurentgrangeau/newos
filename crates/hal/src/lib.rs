#![no_std]

//! Minimal, strictly audited Hardware Abstraction Layer (HAL) for NewOS on Raspberry Pi 5 (16 GB, BCM2712).
//!
//! All `unsafe` hardware/bootloader boundary code is isolated inside this crate,
//! exposing safe abstractions to `newos-kernel-core` and `newos-kernel`.

pub mod arch;
pub mod board;
pub mod boot;

use core::fmt::Write;
use newos_abi::ShutdownStatus;
use newos_kernel_core::BootInfo;

pub use arch::Platform;

/// Initialize early ARMv8.2-A hardware (PL011 UART, VBAR_EL1, TPIDR_EL1, SMP) and parse Limine boot info.
pub fn early_init() -> (Platform, BootInfo) {
    arch::early_serial_init();

    if !boot::is_base_revision_supported() {
        let mut serial = arch::early_serial();
        let _ = writeln!(
            serial,
            "[newos-hal] ERROR: unsupported Limine base revision"
        );
        arch::system_off(ShutdownStatus::Failed);
    }

    let mut info = boot::boot_info();
    let platform = Platform::init(&mut info);
    (platform, info)
}

/// Panic handler helper callable from `crates/kernel`.
pub fn handle_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut serial = arch::early_serial_unlocked();
    let _ = writeln!(serial, "[newos-kernel] PANIC: {info}");
    arch::system_off(ShutdownStatus::Failed)
}

/// Define the bootloader entry point (`_start`) and delegate immediately to a
/// Kernel entry function `fn(Platform, BootInfo) -> !`.
#[macro_export]
macro_rules! entry {
    ($path:path) => {
        // SAFETY: Exports the single bootloader entry symbol `_start` required by the kernel linker script.
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            let (platform, info) = $crate::early_init();
            let entry_fn: fn($crate::Platform, newos_kernel_core::BootInfo) -> ! = $path;
            entry_fn(platform, info)
        }
    };
}
