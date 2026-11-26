//! ACPI table validators for `AArch64` UEFI.
//!
//! Validates ACPI 2.0+ RSDP, XSDT, FADT (`ARM_BOOT_ARCH`), SPCR (PL011 UART),
//! MADT (GICv2/GICv3 GICD/GICC & CPU count), GTDT (Generic Timer GSIVs),
//! and MCFG (`PCIe` ECAM base) directly from firmware tables.

const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
const FADT_SIGNATURE: [u8; 4] = *b"FACP";
const SPCR_SIGNATURE: [u8; 4] = *b"SPCR";
const MADT_SIGNATURE: [u8; 4] = *b"APIC";
const GTDT_SIGNATURE: [u8; 4] = *b"GTDT";
const MCFG_SIGNATURE: [u8; 4] = *b"MCFG";

/// ACPI SPCR `interface_type` value for ARM PL011 UART.
pub const SPCR_INTERFACE_PL011: u8 = 0x03;

/// `ARM_BOOT_ARCH` bit 0: PSCI is implemented.
pub const ARM_BOOT_PSCI_COMPLIANT: u16 = 1 << 0;
/// `ARM_BOOT_ARCH` bit 1: Use `HVC` instead of `SMC` as the PSCI conduit.
pub const ARM_BOOT_PSCI_USE_HVC: u16 = 1 << 1;

/// Validated ACPI RSDP descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRsdp {
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub rsdt_addr: u32,
    pub xsdt_addr: u64,
}

/// Validated ACPI FADT `ARM_BOOT_ARCH` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmBootArch {
    pub psci_compliant: bool,
    pub psci_use_hvc: bool,
}

/// Validated ACPI SPCR (Serial Port Console Redirection) descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedSpcr {
    pub interface_type: u8,
    pub base_address: u64,
    pub interrupt: u32,
}

/// Validated ACPI MADT (`APIC`) GIC & CPU topology summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedMadt {
    pub gicd_base: u64,
    pub gicc_base: u64,
    pub gic_version: u8,
    pub cpu_count: usize,
}

/// Validated ACPI GTDT (Generic Timer Description Table) interrupt IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedGtdt {
    pub non_secure_el1_gsiv: u32,
    pub el1_virt_timer_gsiv: u32,
}

/// Validated ACPI MCFG (`PCIe` ECAM) first allocation entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedMcfg {
    pub ecam_base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

#[inline]
fn checksum_valid(bytes: &[u8]) -> bool {
    let mut sum = 0u8;
    for &b in bytes {
        sum = sum.wrapping_add(b);
    }
    sum == 0
}

/// Validate an ACPI 1.0 (20-byte) or ACPI 2.0+ (36-byte) RSDP structure.
#[must_use]
pub fn parse_rsdp(bytes: &[u8]) -> Option<ParsedRsdp> {
    if bytes.len() < 20 || bytes[0..8] != RSDP_SIGNATURE {
        return None;
    }
    if !checksum_valid(&bytes[0..20]) {
        return None;
    }
    let revision = bytes[15];
    let mut oem_id = [0u8; 6];
    oem_id.copy_from_slice(&bytes[9..15]);
    let rsdt_addr = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

    let xsdt_addr = if revision >= 2 {
        if bytes.len() < 36 {
            return None;
        }
        let length = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
        if length < 36 || length > bytes.len() || !checksum_valid(&bytes[0..length]) {
            return None;
        }
        u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ])
    } else {
        0
    };

    Some(ParsedRsdp {
        revision,
        oem_id,
        rsdt_addr,
        xsdt_addr,
    })
}

/// Validate an ACPI SDT header (36 bytes minimum) and verify its full table checksum.
#[must_use]
pub fn validate_sdt(bytes: &[u8], expected_sig: &[u8; 4]) -> Option<usize> {
    if bytes.len() < 36 || &bytes[0..4] != expected_sig {
        return None;
    }
    let len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if len < 36 || len > bytes.len() || !checksum_valid(&bytes[0..len]) {
        return None;
    }
    Some(len)
}

/// Parse `ARM_BOOT_ARCH` (offset 129, 2 bytes) from a validated ACPI 5.1+ FADT (`FACP`) table.
#[must_use]
pub fn parse_fadt_arm_boot_arch(bytes: &[u8]) -> Option<ArmBootArch> {
    let len = validate_sdt(bytes, &FADT_SIGNATURE)?;
    // `ARM_BOOT_ARCH` is a 16-bit field at byte offset 129..131 (ACPI 5.1+).
    if len < 131 {
        return None;
    }
    let flags = u16::from_le_bytes([bytes[129], bytes[130]]);
    Some(ArmBootArch {
        psci_compliant: (flags & ARM_BOOT_PSCI_COMPLIANT) != 0,
        psci_use_hvc: (flags & ARM_BOOT_PSCI_USE_HVC) != 0,
    })
}

/// Parse serial console MMIO base and GSIV from a validated ACPI `SPCR` table.
#[must_use]
pub fn parse_spcr(bytes: &[u8]) -> Option<ParsedSpcr> {
    let len = validate_sdt(bytes, &SPCR_SIGNATURE)?;
    if len < 58 {
        return None;
    }
    let interface_type = bytes[36];
    let base_address = u64::from_le_bytes([
        bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
    ]);
    let interrupt = u32::from_le_bytes([bytes[54], bytes[55], bytes[56], bytes[57]]);
    Some(ParsedSpcr {
        interface_type,
        base_address,
        interrupt,
    })
}

/// Parse GIC Distributor/CPU Interface bases, GIC version, and enabled CPU count from ACPI `MADT` (`APIC`).
#[must_use]
pub fn parse_madt(bytes: &[u8]) -> Option<ParsedMadt> {
    let len = validate_sdt(bytes, &MADT_SIGNATURE)?;
    if len < 44 {
        return None;
    }
    let mut distributor_base = 0u64;
    let mut cpu_iface_base = 0u64;
    let mut gic_version = 0u8;
    let mut cpu_count = 0usize;

    let mut off = 44usize;
    while off.checked_add(2).is_some_and(|hdr_end| hdr_end <= len) {
        let entry_type = bytes[off];
        let entry_len = bytes[off + 1] as usize;
        let Some(entry_end) = off.checked_add(entry_len) else {
            break;
        };
        if entry_len < 2 || entry_end > len {
            break;
        }
        match entry_type {
            // GICC (GIC CPU Interface Structure, ACPI 6.x Table 5.36)
            0x0B if entry_len >= 40 => {
                let flags = u32::from_le_bytes([
                    bytes[off + 12],
                    bytes[off + 13],
                    bytes[off + 14],
                    bytes[off + 15],
                ]);
                if (flags & 1) != 0 {
                    cpu_count += 1;
                }
                let base = u64::from_le_bytes([
                    bytes[off + 32],
                    bytes[off + 33],
                    bytes[off + 34],
                    bytes[off + 35],
                    bytes[off + 36],
                    bytes[off + 37],
                    bytes[off + 38],
                    bytes[off + 39],
                ]);
                if cpu_iface_base == 0 && base != 0 {
                    cpu_iface_base = base;
                }
            }
            // GICD (GIC Distributor Structure, ACPI 6.x Table 5.37)
            0x0C if entry_len >= 24 => {
                let base = u64::from_le_bytes([
                    bytes[off + 8],
                    bytes[off + 9],
                    bytes[off + 10],
                    bytes[off + 11],
                    bytes[off + 12],
                    bytes[off + 13],
                    bytes[off + 14],
                    bytes[off + 15],
                ]);
                if distributor_base == 0 && base != 0 {
                    distributor_base = base;
                }
                gic_version = bytes[off + 20];
            }
            _ => {}
        }
        off = entry_end;
    }

    Some(ParsedMadt {
        gicd_base: distributor_base,
        gicc_base: cpu_iface_base,
        gic_version,
        cpu_count,
    })
}

/// Parse ARM Generic Timer GSIV interrupt IDs from a validated ACPI `GTDT` table.
#[must_use]
pub fn parse_gtdt(bytes: &[u8]) -> Option<ParsedGtdt> {
    let len = validate_sdt(bytes, &GTDT_SIGNATURE)?;
    if len < 72 {
        return None;
    }
    let non_secure_el1_gsiv = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
    let el1_virt_timer_gsiv = u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]);
    Some(ParsedGtdt {
        non_secure_el1_gsiv,
        el1_virt_timer_gsiv,
    })
}

/// Parse the first `PCIe` ECAM allocation from a validated ACPI `MCFG` table.
#[must_use]
pub fn parse_mcfg(bytes: &[u8]) -> Option<ParsedMcfg> {
    let len = validate_sdt(bytes, &MCFG_SIGNATURE)?;
    if len < 60 {
        return None;
    }
    let ecam_base = u64::from_le_bytes([
        bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
    ]);
    let segment = u16::from_le_bytes([bytes[52], bytes[53]]);
    let start_bus = bytes[54];
    let end_bus = bytes[55];
    Some(ParsedMcfg {
        ecam_base,
        segment,
        start_bus,
        end_bus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_checksum(buf: &mut [u8], csum_idx: usize) {
        buf[csum_idx] = 0;
        let sum: u8 = buf.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        buf[csum_idx] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn parses_valid_acpi_v2_rsdp_and_rejects_bad_checksum() {
        let mut rsdp = [0u8; 36];
        rsdp[0..8].copy_from_slice(b"RSD PTR ");
        rsdp[9..15].copy_from_slice(b"NEWOS ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x5f0b_1000u64.to_le_bytes());
        set_checksum(&mut rsdp[..20], 8);
        set_checksum(&mut rsdp[..36], 32);

        let parsed = parse_rsdp(&rsdp).expect("valid RSDP v2");
        assert_eq!(parsed.revision, 2);
        assert_eq!(&parsed.oem_id, b"NEWOS ");
        assert_eq!(parsed.xsdt_addr, 0x5f0b_1000);

        // Corrupt extended checksum -> rejected
        rsdp[35] ^= 0xFF;
        assert_eq!(parse_rsdp(&rsdp), None);
    }

    #[test]
    fn parses_fadt_arm_boot_arch_psci_conduit() {
        let mut fadt = [0u8; 276];
        fadt[0..4].copy_from_slice(b"FACP");
        fadt[4..8].copy_from_slice(&276u32.to_le_bytes());
        let arch_flags = ARM_BOOT_PSCI_COMPLIANT | ARM_BOOT_PSCI_USE_HVC;
        fadt[129..131].copy_from_slice(&arch_flags.to_le_bytes());
        set_checksum(&mut fadt, 9);

        let arm = parse_fadt_arm_boot_arch(&fadt).expect("valid FADT");
        assert!(arm.psci_compliant);
        assert!(arm.psci_use_hvc);

        // Flip to SMC conduit
        fadt[129..131].copy_from_slice(&ARM_BOOT_PSCI_COMPLIANT.to_le_bytes());
        set_checksum(&mut fadt, 9);
        let arm_smc = parse_fadt_arm_boot_arch(&fadt).expect("valid FADT SMC");
        assert!(arm_smc.psci_compliant);
        assert!(!arm_smc.psci_use_hvc);
    }

    #[test]
    fn parses_spcr_pl011_uart() {
        let mut spcr = [0u8; 80];
        spcr[0..4].copy_from_slice(b"SPCR");
        spcr[4..8].copy_from_slice(&80u32.to_le_bytes());
        spcr[36] = SPCR_INTERFACE_PL011;
        spcr[44..52].copy_from_slice(&0x0900_0000u64.to_le_bytes());
        spcr[54..58].copy_from_slice(&33u32.to_le_bytes());
        set_checksum(&mut spcr, 9);

        let parsed = parse_spcr(&spcr).expect("valid SPCR");
        assert_eq!(parsed.interface_type, SPCR_INTERFACE_PL011);
        assert_eq!(parsed.base_address, 0x0900_0000);
        assert_eq!(parsed.interrupt, 33);
    }

    #[test]
    fn parses_madt_gicd_gicc_and_cpu_count() {
        // Header (44) + GICD (24) + 2x GICC (76 each) = 220 bytes
        let mut madt = [0u8; 220];
        madt[0..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&220u32.to_le_bytes());

        // GICD at offset 44
        madt[44] = 0x0C;
        madt[45] = 24;
        madt[44 + 8..44 + 16].copy_from_slice(&0x0800_0000u64.to_le_bytes());
        madt[44 + 20] = 2;

        // GICC #0 at offset 68 (enabled)
        madt[68] = 0x0B;
        madt[69] = 76;
        madt[68 + 12..68 + 16].copy_from_slice(&1u32.to_le_bytes());
        madt[68 + 32..68 + 40].copy_from_slice(&0x0801_0000u64.to_le_bytes());

        // GICC #1 at offset 144 (enabled)
        madt[144] = 0x0B;
        madt[145] = 76;
        madt[144 + 12..144 + 16].copy_from_slice(&1u32.to_le_bytes());
        madt[144 + 32..144 + 40].copy_from_slice(&0x0801_0000u64.to_le_bytes());

        set_checksum(&mut madt, 9);

        let parsed = parse_madt(&madt).expect("valid MADT");
        assert_eq!(parsed.gicd_base, 0x0800_0000);
        assert_eq!(parsed.gicc_base, 0x0801_0000);
        assert_eq!(parsed.gic_version, 2);
        assert_eq!(parsed.cpu_count, 2);
    }

    #[test]
    fn parses_gtdt_and_mcfg() {
        let mut gtdt = [0u8; 96];
        gtdt[0..4].copy_from_slice(b"GTDT");
        gtdt[4..8].copy_from_slice(&96u32.to_le_bytes());
        gtdt[56..60].copy_from_slice(&30u32.to_le_bytes());
        gtdt[64..68].copy_from_slice(&27u32.to_le_bytes());
        set_checksum(&mut gtdt, 9);

        let parsed_gtdt = parse_gtdt(&gtdt).expect("valid GTDT");
        assert_eq!(parsed_gtdt.non_secure_el1_gsiv, 30);
        assert_eq!(parsed_gtdt.el1_virt_timer_gsiv, 27);

        let mut mcfg = [0u8; 60];
        mcfg[0..4].copy_from_slice(b"MCFG");
        mcfg[4..8].copy_from_slice(&60u32.to_le_bytes());
        mcfg[44..52].copy_from_slice(&0x40_1000_0000u64.to_le_bytes());
        mcfg[52..54].copy_from_slice(&0u16.to_le_bytes());
        mcfg[54] = 0;
        mcfg[55] = 255;
        set_checksum(&mut mcfg, 9);

        let parsed_mcfg = parse_mcfg(&mcfg).expect("valid MCFG");
        assert_eq!(parsed_mcfg.ecam_base, 0x40_1000_0000);
        assert_eq!(parsed_mcfg.segment, 0);
        assert_eq!(parsed_mcfg.start_bus, 0);
        assert_eq!(parsed_mcfg.end_bus, 255);
    }
}
