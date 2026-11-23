//! Pure 64-bit `aarch64` HAL (ARMv8.2-A / Cortex-A76 / Raspberry Pi 5):
//! `PL011` UART, `VBAR_EL1` vectors, `TPIDR_EL1` per-CPU, 4-level `TTBR0/TTBR1` paging,
//! EL0 `svc #0` + `TTBR0_EL1` multi-process switching, SMP, and PSCI `SYSTEM_OFF`.

pub mod gic;
pub mod paging;
pub mod serial;
pub mod smmu;
pub mod smp;
pub mod syscall;

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use newos_abi::{ShutdownStatus, SysError};
use newos_kernel_core::memory::{CpuSecurityFeatures, PhysAddr, UntypedInventory, VirtAddr};
use newos_kernel_core::{BootInfo, HalPlatform};

const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

static BREAKPOINT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_COUNT: AtomicU64 = AtomicU64::new(0);
static PAN_ENABLED: AtomicBool = AtomicBool::new(false);
static SSBS_ENABLED: AtomicBool = AtomicBool::new(false);
static CSV2_SUPPORTED: AtomicBool = AtomicBool::new(false);
static CSV3_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PAC_SUPPORTED: AtomicBool = AtomicBool::new(false);
static BTI_SUPPORTED: AtomicBool = AtomicBool::new(false);
static MTE_SUPPORTED: AtomicBool = AtomicBool::new(false);
static PSCI_USE_SMC: AtomicBool = AtomicBool::new(false);
static ENTROPY_STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

/// Probe ARMv8.x/v9 CPU security features (`PAN`, `SSBS`, `CSV2`, `CSV3`, `PAC`, `BTI`, `MTE`)
/// and enable hardware `PAN` (ARMv8.1-A) and `SCTLR_EL1.DSSBS` (Spectre v4 mitigation) when present.
fn probe_and_enable_cpu_hardening() {
    let mmfr1: u64;
    let pfr0: u64;
    let pfr1: u64;
    let isar1: u64;
    // SAFETY: Reading architectural ID registers in EL1 inspects hardware mitigation support.
    unsafe {
        asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack));
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nomem, nostack));
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) pfr1, options(nomem, nostack));
        asm!("mrs {}, id_aa64isar1_el1", out(reg) isar1, options(nomem, nostack));
    }
    let has_pan = ((mmfr1 >> 20) & 0xF) != 0;
    let has_csv2 = ((pfr0 >> 56) & 0xF) != 0;
    let has_csv3 = ((pfr0 >> 60) & 0xF) != 0;
    let has_bti = (pfr1 & 0xF) != 0;
    let has_ssbs = ((pfr1 >> 4) & 0xF) != 0;
    let has_mte = ((pfr1 >> 8) & 0xF) != 0;
    let has_pac = (((isar1 >> 4) & 0xF) != 0) || (((isar1 >> 8) & 0xF) != 0);

    if has_pan || has_ssbs {
        // SAFETY: CPU advertises PAN and/or SSBS; clearing `SCTLR_EL1.SPAN` (bit 23) forces
        // `PSTATE.PAN = 1` on EL1 entry, and setting `SCTLR_EL1.DSSBS` (bit 44) enables
        // Speculative Store Bypass Safe on EL1 entry.
        unsafe {
            let mut sctlr: u64;
            asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
            if has_pan {
                sctlr &= !(1u64 << 23);
            }
            if has_ssbs {
                sctlr |= 1u64 << 44;
            }
            asm!("msr sctlr_el1, {}", "isb", in(reg) sctlr, options(nomem, nostack));
            if has_pan {
                asm!("msr pan, #1", "isb", options(nomem, nostack));
            }
        }
    }

    PAN_ENABLED.store(has_pan, Ordering::Release);
    SSBS_ENABLED.store(has_ssbs, Ordering::Release);
    CSV2_SUPPORTED.store(has_csv2, Ordering::Release);
    CSV3_SUPPORTED.store(has_csv3, Ordering::Release);
    PAC_SUPPORTED.store(has_pac, Ordering::Release);
    BTI_SUPPORTED.store(has_bti, Ordering::Release);
    if has_bti {
        paging::enable_bti_guarded_pages();
    }
    MTE_SUPPORTED.store(has_mte, Ordering::Release);
}

// 2 KiB-aligned EL1 exception vector table handling EL1 `brk #0` and EL0 `svc #0` / faults.
global_asm!(
    ".balign 2048",
    ".global __newos_aarch64_vectors",
    "__newos_aarch64_vectors:",
    // Current EL with SP0 (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Current EL with SPx (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_irq_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch64 (4 x 128B) -> EL0 `svc #0` / faults & EL0 IRQ preemption!
    ".balign 128", "b __newos_sync_el0",
    ".balign 128", "b __newos_irq_el0",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch32 (unused — pure 64-bit only!)
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    "__newos_sync_el1:",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x16, x17, [sp, #-16]!",
    "stp x18, xzr, [sp, #-16]!",
    "stp x29, x30, [sp, #-16]!",
    "bl {sync_el1}",
    "ldp x29, x30, [sp], #16",
    "ldp x18, xzr, [sp], #16",
    "ldp x16, x17, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x8,  x9,  [sp], #16",
    "ldp x6,  x7,  [sp], #16",
    "ldp x4,  x5,  [sp], #16",
    "ldp x2,  x3,  [sp], #16",
    "ldp x0,  x1,  [sp], #16",
    "eret",
    "__newos_irq_el1:",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x16, x17, [sp, #-16]!",
    "stp x18, xzr, [sp, #-16]!",
    "stp x29, x30, [sp, #-16]!",
    "bl {irq_el1}",
    "ldp x29, x30, [sp], #16",
    "ldp x18, xzr, [sp], #16",
    "ldp x16, x17, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x8,  x9,  [sp], #16",
    "ldp x6,  x7,  [sp], #16",
    "ldp x4,  x5,  [sp], #16",
    "ldp x2,  x3,  [sp], #16",
    "ldp x0,  x1,  [sp], #16",
    "eret",
    // EL0 synchronous entry: save full 272-byte `TrapFrame` (`x0..x30, sp_el0, elr_el1, spsr_el1`)
    "__newos_sync_el0:",
    "sub sp, sp, #272",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "mrs x9,  sp_el0",
    "stp x30, x9,  [sp, #240]",
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #256]",
    // Spectre-BHB mitigation (Cortex-A76: 24-iteration branch-history clearing loop + ISB)
    "mov x10, #24",
    "1: b 2f",
    "2: subs x10, x10, #1",
    "b.ne 1b",
    "isb",
    "mov x0, sp",
    "bl {sync_el0}",
    "b __newos_el0_restore",
    // EL0 IRQ entry: save full 272-byte `TrapFrame` for preemptive timer context switches
    "__newos_irq_el0:",
    "sub sp, sp, #272",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "mrs x9,  sp_el0",
    "stp x30, x9,  [sp, #240]",
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #256]",
    // Spectre-BHB mitigation (Cortex-A76: 24-iteration branch-history clearing loop + ISB)
    "mov x10, #24",
    "3: b 4f",
    "4: subs x10, x10, #1",
    "b.ne 3b",
    "isb",
    "mov x0, sp",
    "bl {irq_el0}",
    // Restore (possibly TTBR0-switched!) `TrapFrame` and return to EL0 via `eret`
    "__newos_el0_restore:",
    "ldp x10, x11, [sp, #256]",
    "msr elr_el1, x10",
    "msr spsr_el1, x11",
    "ldp x30, x9,  [sp, #240]",
    "msr sp_el0, x9",
    "ldp x28, x29, [sp, #224]",
    "ldp x26, x27, [sp, #208]",
    "ldp x24, x25, [sp, #192]",
    "ldp x22, x23, [sp, #176]",
    "ldp x20, x21, [sp, #160]",
    "ldp x18, x19, [sp, #144]",
    "ldp x16, x17, [sp, #128]",
    "ldp x14, x15, [sp, #112]",
    "ldp x12, x13, [sp, #96]",
    "ldp x10, x11, [sp, #80]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x0,  x1,  [sp, #0]",
    "add sp, sp, #272",
    "eret",
    "__newos_unhandled_el1:",
    "b __newos_unhandled_el1",
    sync_el1 = sym aarch64_sync_el1_handler,
    irq_el1 = sym aarch64_irq_el1_handler,
    sync_el0 = sym syscall::sync_el0_dispatch,
    irq_el0 = sym syscall::irq_el0_dispatch,
);

// SAFETY: `__newos_aarch64_vectors` is defined by the `global_asm!` block above as a
// 2 KiB-aligned EL1 exception vector table.
unsafe extern "C" {
    static __newos_aarch64_vectors: u8;
}

extern "C" fn aarch64_irq_el1_handler() {
    if let Some(iar) = gic::acknowledge() {
        let irq_id = iar & 0x3FF;
        if irq_id == gic::SGI_RESCHEDULE && get_cpu_id() != 0 {
            smp::record_ap_sgi_ack();
        }
        gic::end_of_interrupt(iar);
    }
}

extern "C" fn aarch64_sync_el1_handler() {
    let esr: u64;
    let elr: u64;
    // SAFETY: Reading `ESR_EL1` and `ELR_EL1` inside EL1 synchronous exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
        asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;
    if ec == 0x3C {
        BREAKPOINT_COUNT.fetch_add(1, Ordering::Release);
        // SAFETY: Advancing `ELR_EL1` by 4 skips the `brk #0` instruction cleanly.
        unsafe {
            asm!("msr elr_el1, {}", in(reg) elr + 4, options(nomem, nostack));
        }
        return;
    }

    let mut s = serial::Pl011::new();
    let _ = writeln!(
        s,
        "[newos-hal] AArch64 sync exception EC={:#x} ELR={:#018x}",
        ec, elr
    );
    system_off(ShutdownStatus::Failed)
}

pub fn install_vectors() {
    let addr = (&raw const __newos_aarch64_vectors) as u64;
    // SAFETY: Limine enters `_start` on aarch64 with `SPSel = 0` (`SP_EL0` active, `SP_EL1 = 0`).
    // Switch to `SP_EL1` with the active stack pointer and install `VBAR_EL1`.
    unsafe {
        asm!(
            "mov x9, sp",
            "msr spsel, #1",
            "mov sp, x9",
            "msr vbar_el1, {vbar}",
            "isb",
            vbar = in(reg) addr,
            out("x9") _,
            options(nostack),
        );
    }
}

pub fn set_cpu_id(id: u64) {
    // SAFETY: Writing logical CPU ID into EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) id, options(nomem, nostack));
    }
}

pub fn get_cpu_id() -> u64 {
    let id: u64;
    // SAFETY: Reading EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) id, options(nomem, nostack));
    }
    id
}

/// Power off cleanly via PSCI `SYSTEM_OFF` (`smc #0` on Raspberry Pi 5 ATF/UEFI, `hvc #0` on QEMU `virt`).
pub fn system_off(code: ShutdownStatus) -> ! {
    let mut s = serial::Pl011::new();
    match code {
        ShutdownStatus::Success => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=OK)");
        }
        ShutdownStatus::Failed => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=FAIL)");
        }
    }
    let use_smc = PSCI_USE_SMC.load(Ordering::Acquire);
    // SAFETY: Invoking ARM PSCI `SYSTEM_OFF` (0x8400_0008) over the board's PSCI conduit
    // (`smc #0` on RPi5 ATF/EL3, `hvc #0` on QEMU `virt` EL1) cleanly powers down the system.
    unsafe {
        if use_smc {
            asm!("smc #0", in("x0") PSCI_SYSTEM_OFF, options(nomem, nostack));
        } else {
            asm!("hvc #0", in("x0") PSCI_SYSTEM_OFF, options(nomem, nostack));
        }
    }
    loop {
        // SAFETY: Fallback low-power WFI loop if PSCI is unavailable.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

pub struct Aarch64Platform {
    serial: serial::Pl011,
    vspace: paging::Aarch64VSpace,
    online_cpus: usize,
}

#[derive(Default)]
struct AcpiHardware {
    psci_use_hvc: Option<bool>,
    spcr_uart_base: Option<u64>,
    gicd_base: Option<u64>,
    gicc_base: Option<u64>,
    gic_version: u8,
    madt_cpus: usize,
    virt_timer_irq: Option<u32>,
    ecam_base: Option<u64>,
    smmuv3_base: Option<u64>,
}

/// Read `dst.len()` bytes from physical memory `phys_addr` using HHDM if already mapped,
/// or by temporarily mapping each 4 KiB page read-only at `ACPI_SCRATCH_VIRT`.
fn read_phys_bytes(
    vspace: &mut paging::Aarch64VSpace,
    untyped: &mut UntypedInventory,
    hhdm_offset: u64,
    phys_addr: u64,
    dst: &mut [u8],
) -> bool {
    use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
    const ACPI_SCRATCH_VIRT: u64 = 0xffff_b003_0000_0000;

    let Ok(ro_flags) = PageFlags::new_wx(false, false, false, false) else {
        return false;
    };
    let Ok(scratch_va) = VirtAddr::new_page_aligned(ACPI_SCRATCH_VIRT) else {
        return false;
    };

    let mut copied = 0usize;
    while copied < dst.len() {
        let Some(cur_phys) = phys_addr.checked_add(copied as u64) else {
            return false;
        };
        let page_phys = cur_phys & !0xFFF;
        let page_off = (cur_phys & 0xFFF) as usize;
        let chunk = (4096 - page_off).min(dst.len() - copied);

        let hhdm_page = hhdm_offset.wrapping_add(page_phys);
        if hhdm_offset != 0
            && let Ok(hhdm_va) = VirtAddr::new_canonical(hhdm_page)
            && vspace.translate(hhdm_va).is_some()
        {
            // SAFETY: `vspace.translate(hhdm_va)` confirmed this 4 KiB page is mapped in `TTBR1_EL1`.
            let src = unsafe {
                core::slice::from_raw_parts((hhdm_page + page_off as u64) as *const u8, chunk)
            };
            dst[copied..copied + chunk].copy_from_slice(src);
        } else {
            let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(page_phys)) else {
                return false;
            };
            if vspace.map_4k(scratch_va, frame, ro_flags, untyped).is_err() {
                return false;
            }
            // SAFETY: `scratch_va` was just mapped read-only to `frame` in `TTBR1_EL1`.
            let src = unsafe {
                core::slice::from_raw_parts(
                    (ACPI_SCRATCH_VIRT + page_off as u64) as *const u8,
                    chunk,
                )
            };
            dst[copied..copied + chunk].copy_from_slice(src);
            let _ = vspace.unmap_4k(scratch_va);
        }
        copied += chunk;
    }
    true
}

/// Inspect ACPI RSDP -> XSDT -> FADT / SPCR / MADT / GTDT / MCFG from physical memory.
fn probe_acpi_hardware(
    vspace: &mut paging::Aarch64VSpace,
    untyped: &mut UntypedInventory,
    hhdm_offset: u64,
    rsdp_addr: u64,
) -> AcpiHardware {
    let mut hw = AcpiHardware::default();
    if rsdp_addr == 0 {
        return hw;
    }
    let mut rsdp_buf = [0u8; 36];
    if !read_phys_bytes(vspace, untyped, hhdm_offset, rsdp_addr, &mut rsdp_buf) {
        return hw;
    }
    let Some(rsdp) = newos_kernel_core::acpi::parse_rsdp(&rsdp_buf) else {
        return hw;
    };
    if rsdp.xsdt_addr == 0 {
        return hw;
    }

    let mut hdr_buf = [0u8; 36];
    if !read_phys_bytes(vspace, untyped, hhdm_offset, rsdp.xsdt_addr, &mut hdr_buf) {
        return hw;
    }
    let xsdt_len = u32::from_le_bytes([hdr_buf[4], hdr_buf[5], hdr_buf[6], hdr_buf[7]]) as usize;
    let mut xsdt_buf = [0u8; 4096];
    if !(36..=xsdt_buf.len()).contains(&xsdt_len)
        || !read_phys_bytes(
            vspace,
            untyped,
            hhdm_offset,
            rsdp.xsdt_addr,
            &mut xsdt_buf[..xsdt_len],
        )
    {
        return hw;
    }
    let xsdt = &xsdt_buf[..xsdt_len];
    if newos_kernel_core::acpi::validate_sdt(xsdt, b"XSDT").is_none() {
        return hw;
    }

    let mut tbl_buf = [0u8; 4096];
    let mut off = 36usize;
    while off + 8 <= xsdt_len {
        let entry_phys = u64::from_le_bytes([
            xsdt[off],
            xsdt[off + 1],
            xsdt[off + 2],
            xsdt[off + 3],
            xsdt[off + 4],
            xsdt[off + 5],
            xsdt[off + 6],
            xsdt[off + 7],
        ]);
        off += 8;
        if entry_phys == 0 {
            continue;
        }
        if !read_phys_bytes(vspace, untyped, hhdm_offset, entry_phys, &mut hdr_buf) {
            continue;
        }
        let tbl_len = u32::from_le_bytes([hdr_buf[4], hdr_buf[5], hdr_buf[6], hdr_buf[7]]) as usize;
        if !(36..=tbl_buf.len()).contains(&tbl_len) {
            continue;
        }
        match &hdr_buf[0..4] {
            b"FACP" | b"SPCR" | b"APIC" | b"GTDT" | b"MCFG" | b"IORT" => {}
            _ => continue,
        }
        if !read_phys_bytes(
            vspace,
            untyped,
            hhdm_offset,
            entry_phys,
            &mut tbl_buf[..tbl_len],
        ) {
            continue;
        }
        let tbl = &tbl_buf[..tbl_len];
        match &hdr_buf[0..4] {
            b"FACP" => {
                if let Some(arm) = newos_kernel_core::acpi::parse_fadt_arm_boot_arch(tbl)
                    && arm.psci_compliant
                {
                    hw.psci_use_hvc = Some(arm.psci_use_hvc);
                }
            }
            b"SPCR" => {
                if let Some(spcr) = newos_kernel_core::acpi::parse_spcr(tbl)
                    && spcr.interface_type == newos_kernel_core::acpi::SPCR_INTERFACE_PL011
                    && spcr.base_address != 0
                    && (spcr.base_address & 0xFFF) == 0
                {
                    hw.spcr_uart_base = Some(spcr.base_address);
                }
            }
            b"APIC" => {
                if let Some(madt) = newos_kernel_core::acpi::parse_madt(tbl) {
                    if madt.gicd_base != 0 && (madt.gicd_base & 0xFFF) == 0 {
                        hw.gicd_base = Some(madt.gicd_base);
                    }
                    if madt.gicc_base != 0 && (madt.gicc_base & 0xFFF) == 0 {
                        hw.gicc_base = Some(madt.gicc_base);
                    }
                    hw.gic_version = madt.gic_version;
                    hw.madt_cpus = madt.cpu_count;
                }
            }
            b"GTDT" => {
                if let Some(gtdt) = newos_kernel_core::acpi::parse_gtdt(tbl)
                    && gtdt.el1_virt_timer_gsiv != 0
                {
                    hw.virt_timer_irq = Some(gtdt.el1_virt_timer_gsiv);
                }
            }
            b"MCFG" => {
                if let Some(mcfg) = newos_kernel_core::acpi::parse_mcfg(tbl)
                    && mcfg.ecam_base != 0
                {
                    hw.ecam_base = Some(mcfg.ecam_base);
                }
            }
            b"IORT" => {
                if let Some(iort) = newos_kernel_core::acpi::parse_iort(tbl)
                    && iort.smmuv3_base != 0
                    && (iort.smmuv3_base & 0xFFF) == 0
                {
                    hw.smmuv3_base = Some(iort.smmuv3_base);
                }
            }
            _ => {}
        }
    }
    hw
}

impl Aarch64Platform {
    pub fn init(info: &mut BootInfo) -> Self {
        use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
        let mut vspace = paging::Aarch64VSpace::from_current_ttbr1(info.hhdm_offset);

        // Discover hardware dynamically from ACPI (FADT/SPCR/MADT/GTDT/MCFG),
        // falling back to board defaults (Raspberry Pi 5 vs QEMU `virt`).
        let acpi = probe_acpi_hardware(
            &mut vspace,
            &mut info.untyped,
            info.hhdm_offset,
            info.rsdp_addr,
        );

        // Select PL011 MMIO physical base (ACPI SPCR -> board fallback):
        // - Default: Raspberry Pi 5 (16 GB, BCM2712 3-pin JST Debug UART): `0x10_7D00_1000`
        // - Local test harness (`qemu` cmdline): QEMU `virt`: `0x0900_0000`
        const RPI5_UART_PHYS: u64 = 0x10_7D00_1000;
        const QEMU_UART_PHYS: u64 = 0x0900_0000;
        const UART_VIRT: u64 = 0xffff_b000_0000_0000;
        let uart_phys = acpi.spcr_uart_base.unwrap_or(if info.qemu_virt {
            QEMU_UART_PHYS
        } else {
            RPI5_UART_PHYS
        });
        if let Ok(uart_virt) = VirtAddr::new_page_aligned(UART_VIRT)
            && let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(uart_phys))
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && vspace
                .map_4k(uart_virt, frame, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            serial::init_virt(UART_VIRT);
        } else {
            serial::init_virt(info.hhdm_offset.wrapping_add(uart_phys));
        }

        // Map capability-scoped Network Controller MMIO window (4 pages, Device-nGnRnE):
        // - Default: Raspberry Pi 5 (BCM2712 + RP1 Cadence GEM Gigabit Ethernet): `0x1F_0010_0000`
        // - Local test harness (`qemu` cmdline): QEMU `virt` VirtIO-MMIO slots 0..31: `0x0A00_0000`
        const RPI5_RP1_GEM_PHYS: u64 = 0x1F_0010_0000;
        const QEMU_NET_MMIO_PHYS: u64 = 0x0a00_0000;
        const NET_MMIO_VIRT: u64 = 0xffff_b001_0000_0000;
        const NET_MMIO_PAGES: u64 = 4;
        let net_mmio_phys = if info.qemu_virt {
            QEMU_NET_MMIO_PHYS
        } else {
            RPI5_RP1_GEM_PHYS
        };
        let mut net_mmio_mapped = false;
        if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true) {
            net_mmio_mapped = true;
            for p in 0..NET_MMIO_PAGES {
                let off = p * 4096;
                let mapped = VirtAddr::new_page_aligned(NET_MMIO_VIRT + off)
                    .and_then(|va| {
                        PhysFrame::from_aligned(PhysAddr::new(net_mmio_phys + off)).and_then(
                            |frame| vspace.map_4k(va, frame, mmio_flags, &mut info.untyped),
                        )
                    })
                    .is_ok();
                if !mapped {
                    net_mmio_mapped = false;
                    break;
                }
            }
        }
        let net_mmio = if !net_mmio_mapped {
            None
        } else if info.qemu_virt {
            // Scope BOOTSTRAP_NET_MMIO strictly to the single 512-byte VirtIO-Net slot (`C-3`)
            // rather than exposing all 32 VirtIO-MMIO devices on the bus.
            const VIRTIO_MAGIC: u32 = 0x7472_6976;
            const VIRTIO_DEV_NET: u32 = 1;
            const SLOT_STRIDE: u64 = 0x200;
            let mut found = None;
            for slot in 0..32u64 {
                let off = slot * SLOT_STRIDE;
                let base_va = NET_MMIO_VIRT + off;
                // SAFETY: All `NET_MMIO_PAGES` pages of `NET_MMIO_VIRT..NET_MMIO_VIRT + 16 KiB`
                // were verified mapped above as Device-nGnRnE.
                let (magic, dev_id) = unsafe {
                    (
                        core::ptr::read_volatile(base_va as *const u32),
                        core::ptr::read_volatile((base_va + 8) as *const u32),
                    )
                };
                if magic == VIRTIO_MAGIC && dev_id == VIRTIO_DEV_NET {
                    found = Some((PhysAddr::new(net_mmio_phys + off), base_va, SLOT_STRIDE));
                    break;
                }
            }
            found
        } else {
            Some((
                PhysAddr::new(net_mmio_phys),
                NET_MMIO_VIRT,
                NET_MMIO_PAGES * 4096,
            ))
        };

        // Map GICv2 / GIC-400 Distributor & CPU Interface (ACPI MADT -> board fallback):
        // - Default: Raspberry Pi 5 BCM2712 GIC-400: GICD `0x10_7FFF_9000`, GICC `0x10_7FFF_A000`
        // - QEMU `virt` GICv2:                      GICD `0x0800_0000`,    GICC `0x0801_0000`
        const RPI5_GICD_PHYS: u64 = 0x10_7FFF_9000;
        const RPI5_GICC_PHYS: u64 = 0x10_7FFF_A000;
        const QEMU_GICD_PHYS: u64 = 0x0800_0000;
        const QEMU_GICC_PHYS: u64 = 0x0801_0000;
        const GICD_VIRT: u64 = 0xffff_b002_0000_0000;
        const GICC_VIRT: u64 = 0xffff_b002_0000_1000;
        let (default_gicd, default_gicc) = if info.qemu_virt {
            (QEMU_GICD_PHYS, QEMU_GICC_PHYS)
        } else {
            (RPI5_GICD_PHYS, RPI5_GICC_PHYS)
        };
        let gicd_phys = acpi.gicd_base.unwrap_or(default_gicd);
        let gicc_phys = acpi.gicc_base.unwrap_or(default_gicc);
        let virt_timer_irq = acpi.virt_timer_irq.unwrap_or(gic::IRQ_VIRTUAL_TIMER);
        if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && let Ok(gicd_va) = VirtAddr::new_page_aligned(GICD_VIRT)
            && let Ok(gicc_va) = VirtAddr::new_page_aligned(GICC_VIRT)
            && let Ok(gicd_fr) = PhysFrame::from_aligned(PhysAddr::new(gicd_phys))
            && let Ok(gicc_fr) = PhysFrame::from_aligned(PhysAddr::new(gicc_phys))
            && vspace
                .map_4k(gicd_va, gicd_fr, mmio_flags, &mut info.untyped)
                .is_ok()
            && vspace
                .map_4k(gicc_va, gicc_fr, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            gic::init(GICD_VIRT, GICC_VIRT, virt_timer_irq);
        }

        // Select PSCI conduit from ACPI FADT `ARM_BOOT_ARCH` when available; fallback to board default.
        let use_smc = match acpi.psci_use_hvc {
            Some(use_hvc) => !use_hvc,
            None => !info.qemu_virt,
        };
        PSCI_USE_SMC.store(use_smc, Ordering::Release);

        set_cpu_id(0);
        probe_and_enable_cpu_hardening();
        install_vectors();
        syscall::init(info.hhdm_offset, net_mmio);
        let online_cpus = smp::bring_up_aps();
        syscall::set_sys_info(online_cpus, info.interactive_shell);

        // Probe ARM SMMUv3 if advertised by ACPI IORT
        const SMMU_VIRT: u64 = 0xffff_b004_0000_0000;
        let smmu_info = if let Some(smmu_phys) = acpi.smmuv3_base
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && let Ok(smmu_va) = VirtAddr::new_page_aligned(SMMU_VIRT)
            && let Ok(smmu_fr) = PhysFrame::from_aligned(PhysAddr::new(smmu_phys))
            && vspace
                .map_4k(smmu_va, smmu_fr, mmio_flags, &mut info.untyped)
                .is_ok()
        {
            smmu::probe(SMMU_VIRT)
        } else {
            smmu::SmmuInfo::default()
        };

        let mut serial = serial::Pl011::new();
        let _ = writeln!(
            serial,
            "[newos-hal] ACPI/GIC: uart={:#x} gicd={:#x} gicc={:#x} (v{}, cpus={}) timer_irq={} psci={} ecam={:#x} smmuv3={:#x}(s1={},sid={}b) ap_sgi_acks={}",
            uart_phys,
            gicd_phys,
            gicc_phys,
            acpi.gic_version,
            acpi.madt_cpus,
            virt_timer_irq,
            if use_smc { "SMC" } else { "HVC" },
            acpi.ecam_base.unwrap_or(0),
            acpi.smmuv3_base.unwrap_or(0),
            smmu_info.stage1,
            smmu_info.sid_bits,
            smp::ap_sgi_ack_count(),
        );
        Self {
            serial,
            vspace,
            online_cpus,
        }
    }
}

impl Write for Aarch64Platform {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.serial.write_str(s)
    }
}

impl HalPlatform for Aarch64Platform {
    type VSpace = paging::Aarch64VSpace;

    fn arch_name(&self) -> &'static str {
        "aarch64"
    }

    fn security_features(&self) -> CpuSecurityFeatures {
        CpuSecurityFeatures {
            pxn: true,
            uxn: true,
            pan: PAN_ENABLED.load(Ordering::Acquire),
            wx_enforced: true,
            ssbs: SSBS_ENABLED.load(Ordering::Acquire),
            csv2: CSV2_SUPPORTED.load(Ordering::Acquire),
            csv3: CSV3_SUPPORTED.load(Ordering::Acquire),
            pac: PAC_SUPPORTED.load(Ordering::Acquire),
            bti: BTI_SUPPORTED.load(Ordering::Acquire),
            mte: MTE_SUPPORTED.load(Ordering::Acquire),
        }
    }

    fn current_cpu_id(&self) -> u32 {
        get_cpu_id() as u32
    }

    fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    fn trigger_breakpoint(&mut self) {
        // SAFETY: `install_vectors` installed a `brk #0` handler that advances `ELR_EL1 += 4`.
        unsafe {
            asm!("brk #0", options(nomem, nostack));
        }
    }

    fn breakpoint_count(&self) -> u64 {
        BREAKPOINT_COUNT.load(Ordering::Acquire)
    }

    fn arm_oneshot_timer(&mut self, _ticks: u32) {
        let t0 = syscall::read_cntvct();
        for _ in 0..10_000_000u32 {
            if syscall::read_cntvct() != t0 {
                break;
            }
            core::hint::spin_loop();
        }
        TIMER_COUNT.fetch_add(1, Ordering::Release);
    }

    fn timer_count(&self) -> u64 {
        TIMER_COUNT.load(Ordering::Acquire)
    }

    fn enable_interrupts(&mut self) {
        // SAFETY: Unmasking EL1 IRQ bit (`daifclr #2`).
        unsafe {
            asm!("msr daifclr, #2", options(nomem, nostack));
        }
    }
    fn disable_interrupts(&mut self) {
        // SAFETY: Masking EL1 IRQ bit (`daifset #2`).
        unsafe {
            asm!("msr daifset, #2", options(nomem, nostack));
        }
    }
    fn wait_for_interrupt(&mut self) {
        // SAFETY: Low-power wait-for-interrupt instruction in EL1.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }

    fn random_u64(&mut self) -> u64 {
        let mut x = ENTROPY_STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            ^ syscall::read_cntvct();
        // SplitMix64 finalizer for uniform ASLR slide distribution
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    fn vspace_mut(&mut self) -> &mut Self::VSpace {
        &mut self.vspace
    }

    fn create_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self::VSpace, SysError> {
        self.vspace.new_user_vspace(untyped)
    }

    fn probe_mapped_u64(&self, virt: VirtAddr, pattern: u64) -> Result<u64, SysError> {
        paging::probe_mapped_u64(&self.vspace, virt, pattern)
    }

    fn register_user_process(
        &mut self,
        entry: VirtAddr,
        user_sp: VirtAddr,
        user_shadow_sp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError> {
        syscall::register_user_process(
            entry.raw(),
            user_sp.raw(),
            user_shadow_sp.raw(),
            vspace_root.raw(),
        )
    }

    fn install_runtime_untyped(&mut self, untyped: UntypedInventory) {
        syscall::set_untyped_inventory(untyped);
    }

    fn start_userspace(&mut self) -> ! {
        syscall::start_userspace()
    }

    fn exit(&mut self, code: ShutdownStatus) -> ! {
        system_off(code)
    }
}
