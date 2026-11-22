//! Architecture-specific HAL backends (`x86_64` and `aarch64` — pure 64-bit only).

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::X86Platform as Platform;

#[cfg(target_arch = "aarch64")]
pub use aarch64::Aarch64Platform as Platform;

#[cfg(target_arch = "x86_64")]
pub fn early_serial_init() {
    x86_64::serial::init();
}

#[cfg(target_arch = "aarch64")]
pub fn early_serial_init() {}

#[cfg(target_arch = "x86_64")]
pub fn early_serial() -> x86_64::serial::SerialPort {
    x86_64::serial::SerialPort::new()
}

#[cfg(target_arch = "aarch64")]
pub fn early_serial() -> aarch64::serial::Pl011 {
    aarch64::serial::Pl011::new()
}

#[cfg(target_arch = "x86_64")]
pub fn exit_qemu(code: newos_abi::QemuExitCode) -> ! {
    x86_64::exit_qemu(code)
}

#[cfg(target_arch = "aarch64")]
pub fn exit_qemu(code: newos_abi::QemuExitCode) -> ! {
    aarch64::exit_qemu(code)
}
