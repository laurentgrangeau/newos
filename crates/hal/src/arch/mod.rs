//! Architecture-specific HAL backend for Raspberry Pi 5 (16 GB, BCM2712 Cortex-A76 `aarch64`).

pub mod aarch64;

pub use aarch64::Aarch64Platform as Platform;

pub fn early_serial_init() {}

pub fn early_serial() -> aarch64::serial::Pl011 {
    aarch64::serial::Pl011::new()
}

pub fn exit_qemu(code: newos_abi::QemuExitCode) -> ! {
    aarch64::exit_qemu(code)
}
