//! Architecture-specific HAL backend for Raspberry Pi 5 (16 GB, BCM2712 Cortex-A76 `aarch64`).

pub mod aarch64;

pub use aarch64::Aarch64Platform as Platform;

pub fn early_serial_init() {}

pub fn early_serial() -> aarch64::serial::Pl011 {
    aarch64::serial::Pl011::new()
}

pub fn system_off(code: newos_abi::ShutdownStatus) -> ! {
    aarch64::system_off(code)
}
