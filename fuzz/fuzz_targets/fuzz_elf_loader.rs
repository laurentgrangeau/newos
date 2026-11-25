#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_kernel_core::elf::parse_elf64;

fuzz_target!(|data: &[u8]| {
    let _ = parse_elf64(data);
});
