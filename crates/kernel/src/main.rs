#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Thin Ring-0 kernel binary wiring `newos-hal` into the 100% safe `newos-kernel-core`.

use core::panic::PanicInfo;
use newos_hal::Platform;
use newos_kernel_core::BootInfo;

newos_hal::entry!(kmain);

fn kmain(mut platform: Platform, info: BootInfo) -> ! {
    newos_kernel_core::boot_early(&mut platform, info)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    newos_hal::handle_panic(info)
}
