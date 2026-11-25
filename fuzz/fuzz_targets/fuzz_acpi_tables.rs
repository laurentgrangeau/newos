#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_kernel_core::acpi::{
    parse_fadt_arm_boot_arch, parse_gtdt, parse_madt, parse_mcfg, parse_rsdp, parse_spcr,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_rsdp(data);
    let _ = parse_fadt_arm_boot_arch(data);
    let _ = parse_spcr(data);
    let _ = parse_madt(data);
    let _ = parse_gtdt(data);
    let _ = parse_mcfg(data);
});
