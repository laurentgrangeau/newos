#![no_std]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
#![feature(sync_unsafe_cell)]

//! Minimal, strictly audited Hardware Abstraction Layer (HAL) for NewOS.
//!
//! All `unsafe` hardware/bootloader boundary code is isolated inside this crate,
//! exposing 100% memory-safe abstractions to `newos-kernel-core` and `newos-kernel`.

pub mod arch;
pub mod boot;

use core::fmt::Write;
use newos_abi::QemuExitCode;
use newos_kernel_core::BootInfo;

pub use arch::Platform;

/// Initialize early hardware (serial, GDT/TSS, IDT, per-CPU, APIC) and parse Limine boot info.
pub fn early_init() -> (Platform, BootInfo) {
    arch::early_serial_init();

    if !boot::is_base_revision_supported() {
        let mut serial = arch::early_serial();
        let _ = writeln!(serial, "[newos-hal] ERROR: unsupported Limine base revision");
        arch::exit_qemu(QemuExitCode::Failed);
    }

    let mut info = boot::boot_info();
    let platform = Platform::init(&mut info);
    (platform, info)
}

/// Panic handler helper callable from `#![forbid(unsafe_code)]` `crates/kernel`.
pub fn handle_panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut serial = arch::early_serial();
    let _ = writeln!(serial, "[newos-kernel] PANIC: {info}");
    arch::exit_qemu(QemuExitCode::Failed)
}

/// Define the bootloader entry point (`_start`) and delegate immediately to a
/// 100% safe Rust kernel entry function `fn(Platform, BootInfo) -> !`.
#[macro_export]
macro_rules! entry {
    ($path:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() -> ! {
            let (platform, info) = $crate::early_init();
            let entry_fn: fn($crate::Platform, newos_kernel_core::BootInfo) -> ! = $path;
            entry_fn(platform, info)
        }
    };
}
