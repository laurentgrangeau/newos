//! Architecture-specific HAL backends.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::X86Platform as Platform;

#[cfg(target_arch = "x86_64")]
pub fn early_serial_init() {
    x86_64::serial::init();
}

#[cfg(target_arch = "x86_64")]
pub fn early_serial() -> x86_64::serial::SerialPort {
    x86_64::serial::SerialPort::new()
}

#[cfg(target_arch = "x86_64")]
pub fn exit_qemu(code: newos_abi::QemuExitCode) -> ! {
    x86_64::exit_qemu(code)
}
