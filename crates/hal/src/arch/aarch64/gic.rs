//! Minimal audited ARM `GICv2` / `GIC-400` interrupt controller driver (MMIO Device-nGnRnE).
//!
//! Supports both:
//! - Raspberry Pi 5 (`BCM2712` `GIC-400`): GICD `0x10_7FFF_9000`, GICC `0x10_7FFF_A000`
//! - QEMU `aarch64` `virt` (`GICv2`): GICD `0x0800_0000`, GICC `0x0801_0000`

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// ARM Generic Virtual Timer PPI interrupt ID (standard on `AArch64` `GICv2`/`GIC-400`).
pub const IRQ_VIRTUAL_TIMER: u32 = 27;
/// `GICv2` Software Generated Interrupt (SGI #0) used for cross-core SMP reschedule / wakeup IPIs.
pub const SGI_RESCHEDULE: u32 = 0;

/// Trigger sensitivity for a `GICv2` Shared Peripheral Interrupt (`GICD_ICFGR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Level-sensitive interrupt (`0b00`).
    Level,
    /// Edge-triggered interrupt (`0b10`).
    Edge,
}

/// Host mask state for a `BCM2712` MIP `MSI-X` vector (`0..64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MipMask {
    /// Vector masked (suppressed on ARM host path).
    Masked,
    /// Vector unmasked (delivered to ARM host `GIC-400`).
    Unmasked,
}

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xC00;
const GICD_SGIR: usize = 0xF00;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;
const SPURIOUS_IRQ: u32 = 1023;

// BCM2712 MIP (MSI-X Interrupt Peripheral, physical base `0x10_0013_0000`)
const MIP_INT_CFGL_HOST: usize = 0x20;
const MIP_INT_CFGH_HOST: usize = 0x30;
const MIP_INT_MASKL_HOST: usize = 0x40;
const MIP_INT_MASKH_HOST: usize = 0x50;
const MIP_INT_MASKL_VPU: usize = 0x60;
const MIP_INT_MASKH_VPU: usize = 0x70;
const MIP_INT_STATUSL_HOST: usize = 0x80;
const MIP_INT_STATUSH_HOST: usize = 0x90;

static GICD_VIRT_BASE: AtomicUsize = AtomicUsize::new(0);
static GICC_VIRT_BASE: AtomicUsize = AtomicUsize::new(0);
static MIP_VIRT_BASE: AtomicUsize = AtomicUsize::new(0);
static VIRT_TIMER_IRQ: AtomicU32 = AtomicU32::new(IRQ_VIRTUAL_TIMER);

#[inline]
fn base_addr(base: &AtomicUsize) -> Option<usize> {
    let addr = base.load(Ordering::Acquire);
    (addr != 0).then_some(addr)
}

/// Initialize `GICv2` distributor + BSP CPU interface and unmask the Virtual Timer PPI + SGI #0.
///
/// # Safety
/// `dist_virt` and `cpu_if_virt` must be valid, page-aligned 4 KiB Device-nGnRnE MMIO mappings in
/// `TTBR1_EL1` pointing to the platform's `GICD` and `GICC` register blocks.
pub(super) unsafe fn init(dist_virt: usize, cpu_if_virt: usize, virt_timer_irq: u32) {
    GICD_VIRT_BASE.store(dist_virt, Ordering::Release);
    GICC_VIRT_BASE.store(cpu_if_virt, Ordering::Release);
    VIRT_TIMER_IRQ.store(virt_timer_irq, Ordering::Release);

    // SAFETY: Caller guarantees `dist_virt` and `cpu_if_virt` are mapped as Device-nGnRnE MMIO in `TTBR1_EL1`.
    unsafe {
        write_volatile((dist_virt + GICD_CTLR) as *mut u32, 1);
        write_volatile((cpu_if_virt + GICC_PMR) as *mut u32, 0xFF);
        write_volatile((cpu_if_virt + GICC_CTLR) as *mut u32, 1);
    }
    enable_irq(virt_timer_irq);
    enable_irq(SGI_RESCHEDULE);
}

/// Initialize the banked `GICv2` CPU interface (`GICC`) and per-CPU PPI/SGI enables on an AP core.
pub fn init_secondary() {
    let Some(gicc) = base_addr(&GICC_VIRT_BASE) else {
        return;
    };
    // SAFETY: `GICC` is banked per CPU and mapped as Device-nGnRnE MMIO in shared `TTBR1_EL1`.
    unsafe {
        write_volatile((gicc + GICC_PMR) as *mut u32, 0xFF);
        write_volatile((gicc + GICC_CTLR) as *mut u32, 1);
    }
    let timer_irq = VIRT_TIMER_IRQ.load(Ordering::Acquire);
    enable_irq(timer_irq);
    enable_irq(SGI_RESCHEDULE);
}

/// Return the configured ARM Generic Virtual Timer PPI interrupt ID.
#[must_use]
#[inline]
pub fn virt_timer_irq() -> u32 {
    VIRT_TIMER_IRQ.load(Ordering::Acquire)
}

/// Send a `GICv2` Software Generated Interrupt (`0..16`) to the target CPU bitmask (`bits 0..7`).
pub fn send_sgi(sgi_id: u32, target_cpu_mask: u8) {
    let Some(gicd) = base_addr(&GICD_VIRT_BASE) else {
        return;
    };
    if sgi_id >= 16 || target_cpu_mask == 0 {
        return;
    }
    // GICD_SGIR: TargetListFilter=0b00 (bits 25:24), CPUTargetList (bits 23:16), SGIINTID (bits 3:0)
    let val = (u32::from(target_cpu_mask) << 16) | (sgi_id & 0xF);
    // SAFETY: `GICD_SGIR` (offset `0xF00`) lies within the 4 KiB GICD Device-nGnRnE MMIO page.
    unsafe {
        write_volatile((gicd + GICD_SGIR) as *mut u32, val);
    }
}

/// Enable (unmask) a specific `GICv2` interrupt ID (`0..1020`).
pub fn enable_irq(irq: u32) {
    let Some(gicd) = base_addr(&GICD_VIRT_BASE) else {
        return;
    };
    if irq >= 1020 {
        return;
    }
    let reg_off = GICD_ISENABLER + ((irq / 32) as usize) * 4;
    let bit = 1u32 << (irq % 32);
    // SAFETY: `gicd + reg_off` lies within the 4 KiB GICD MMIO page (`irq < 1020 => off <= 0x17C`).
    unsafe {
        write_volatile((gicd + reg_off) as *mut u32, bit);
    }
}

/// Disable (mask) a specific `GICv2` interrupt ID (`0..1020`).
pub fn disable_irq(irq: u32) {
    let Some(gicd) = base_addr(&GICD_VIRT_BASE) else {
        return;
    };
    if irq >= 1020 {
        return;
    }
    let reg_off = GICD_ICENABLER + ((irq / 32) as usize) * 4;
    let bit = 1u32 << (irq % 32);
    // SAFETY: `gicd + reg_off` lies within the 4 KiB GICD MMIO page (`irq < 1020 => off <= 0x1FC`).
    unsafe {
        write_volatile((gicd + reg_off) as *mut u32, bit);
    }
}

/// Configure a `GICv2` Shared Peripheral Interrupt (`32..1020`) with CPU target mask,
/// trigger mode, and priority byte.
pub fn configure_spi(irq: u32, target_cpu_mask: u8, trigger: TriggerMode, priority: u8) {
    let Some(gicd) = base_addr(&GICD_VIRT_BASE) else {
        return;
    };
    if !(32..1020).contains(&irq) {
        return;
    }
    let word_idx = (irq / 4) as usize;
    let byte_shift = (irq % 4) * 8;
    let byte_mask = !(0xFFu32 << byte_shift);

    let prio_off = GICD_IPRIORITYR + word_idx * 4;
    let targ_off = GICD_ITARGETSR + word_idx * 4;
    let cfg_off = GICD_ICFGR + ((irq / 16) as usize) * 4;
    let cfg_shift = (irq % 16) * 2;
    let mode = match trigger {
        TriggerMode::Edge => 0b10u32,
        TriggerMode::Level => 0b00u32,
    };

    // SAFETY: `prio_off` (<=0x7FC), `targ_off` (<=0xBFC), and `cfg_off` (<=0xCFC) all lie
    // within the 4 KiB Device-nGnRnE GICD MMIO page.
    unsafe {
        let p = read_volatile((gicd + prio_off) as *const u32);
        write_volatile(
            (gicd + prio_off) as *mut u32,
            (p & byte_mask) | (u32::from(priority) << byte_shift),
        );

        let t = read_volatile((gicd + targ_off) as *const u32);
        write_volatile(
            (gicd + targ_off) as *mut u32,
            (t & byte_mask) | (u32::from(target_cpu_mask) << byte_shift),
        );

        let c = read_volatile((gicd + cfg_off) as *const u32);
        write_volatile(
            (gicd + cfg_off) as *mut u32,
            (c & !(0b11u32 << cfg_shift)) | (mode << cfg_shift),
        );
    }
}

/// Initialize the Raspberry Pi 5 `BCM2712` MIP (`MSI-X` Interrupt Peripheral) at `mip_virt`
/// (`0x10_0013_0000`): mask VPU delivery and configure all 64 host `MSI-X` vectors as edge-triggered.
///
/// # Safety
/// `mip_virt` must be a valid, page-aligned 4 KiB Device-nGnRnE MMIO mapping in `TTBR1_EL1`
/// pointing to the `BCM2712` MIP register block (`0x00..0x100`).
pub(super) unsafe fn init_bcm2712_mip(mip_virt: usize) {
    MIP_VIRT_BASE.store(mip_virt, Ordering::Release);
    // SAFETY: Caller guarantees `mip_virt` is mapped as a 4 KiB Device-nGnRnE MMIO page covering `0x00..0x100`.
    unsafe {
        write_volatile((mip_virt + MIP_INT_MASKL_VPU) as *mut u32, 0xFFFF_FFFF);
        write_volatile((mip_virt + MIP_INT_MASKH_VPU) as *mut u32, 0xFFFF_FFFF);
        write_volatile((mip_virt + MIP_INT_CFGL_HOST) as *mut u32, 0xFFFF_FFFF);
        write_volatile((mip_virt + MIP_INT_CFGH_HOST) as *mut u32, 0xFFFF_FFFF);
        // Start with all host MSI-X vectors masked until individual EL0 drivers unmask them.
        write_volatile((mip_virt + MIP_INT_MASKL_HOST) as *mut u32, 0xFFFF_FFFF);
        write_volatile((mip_virt + MIP_INT_MASKH_HOST) as *mut u32, 0xFFFF_FFFF);
    }
}

/// Unmask or mask a `BCM2712` MIP `MSI-X` vector (`0..64`) on the ARM host `GIC-400` path.
pub fn set_mip_vector_masked(vector: u8, mask: MipMask) {
    let Some(mip) = base_addr(&MIP_VIRT_BASE) else {
        return;
    };
    if vector >= 64 {
        return;
    }
    let (off, bit) = if vector < 32 {
        (MIP_INT_MASKL_HOST, 1u32 << vector)
    } else {
        (MIP_INT_MASKH_HOST, 1u32 << (vector - 32))
    };
    // SAFETY: `mip + off` lies within the mapped 4 KiB Device-nGnRnE BCM2712 MIP page.
    unsafe {
        let cur = read_volatile((mip + off) as *const u32);
        let next = match mask {
            MipMask::Masked => cur | bit,
            MipMask::Unmasked => cur & !bit,
        };
        write_volatile((mip + off) as *mut u32, next);
    }
}

/// Read the 64-bit pending host `MSI-X` status bitmap from the `BCM2712` MIP.
#[must_use]
pub fn mip_pending_status() -> u64 {
    let Some(mip) = base_addr(&MIP_VIRT_BASE) else {
        return 0;
    };
    // SAFETY: `MIP_INT_STATUSL_HOST` and `MIP_INT_STATUSH_HOST` lie within the mapped 4 KiB MIP page.
    unsafe {
        let lo = u64::from(read_volatile((mip + MIP_INT_STATUSL_HOST) as *const u32));
        let hi = u64::from(read_volatile((mip + MIP_INT_STATUSH_HOST) as *const u32));
        lo | (hi << 32)
    }
}

/// Acknowledge a pending `GICv2` interrupt, returning `Some(iar)` if non-spurious.
#[must_use]
#[inline]
pub fn acknowledge() -> Option<u32> {
    let gicc = base_addr(&GICC_VIRT_BASE)?;
    // SAFETY: `GICC_IAR` is a valid 32-bit Device-nGnRnE register when GICC is mapped.
    let iar = unsafe { read_volatile((gicc + GICC_IAR) as *const u32) };
    if (iar & 0x3FF) >= SPURIOUS_IRQ {
        None
    } else {
        Some(iar)
    }
}

/// Signal End-Of-Interrupt to the `GICv2` CPU interface for a previously acknowledged `iar`.
#[inline]
pub fn end_of_interrupt(iar: u32) {
    let Some(gicc) = base_addr(&GICC_VIRT_BASE) else {
        return;
    };
    // SAFETY: `GICC_EOIR` is a valid 32-bit Device-nGnRnE register when GICC is mapped.
    unsafe {
        write_volatile((gicc + GICC_EOIR) as *mut u32, iar);
    }
}
