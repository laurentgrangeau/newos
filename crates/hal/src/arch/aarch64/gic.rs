//! Minimal audited ARM GICv2 / GIC-400 interrupt controller driver (MMIO Device-nGnRnE).
//!
//! Supports both:
//! - Raspberry Pi 5 (BCM2712 GIC-400): GICD `0x10_7FFF_9000`, GICC `0x10_7FFF_A000`
//! - QEMU `aarch64` `virt` (GICv2):   GICD `0x0800_0000`,    GICC `0x0801_0000`

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

/// ARM Generic Virtual Timer PPI interrupt ID (standard on AArch64 GICv2/GIC-400).
pub const IRQ_VIRTUAL_TIMER: u32 = 27;
/// GICv2 Software Generated Interrupt (SGI #0) used for cross-core SMP reschedule / wakeup IPIs.
pub const SGI_RESCHEDULE: u32 = 0;

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_SGIR: usize = 0xF00;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;
const SPURIOUS_IRQ: u32 = 1023;

static GICD_VIRT_BASE: AtomicU64 = AtomicU64::new(0);
static GICC_VIRT_BASE: AtomicU64 = AtomicU64::new(0);
static VIRT_TIMER_IRQ: AtomicU64 = AtomicU64::new(IRQ_VIRTUAL_TIMER as u64);

/// Initialize GICv2 distributor + BSP CPU interface and unmask the Virtual Timer PPI + SGI #0.
pub fn init(gicd_virt: u64, gicc_virt: u64, virt_timer_irq: u32) {
    GICD_VIRT_BASE.store(gicd_virt, Ordering::Release);
    GICC_VIRT_BASE.store(gicc_virt, Ordering::Release);
    VIRT_TIMER_IRQ.store(u64::from(virt_timer_irq), Ordering::Release);

    let gicd = gicd_virt as usize;
    let gicc = gicc_virt as usize;
    // SAFETY: `gicd_virt` and `gicc_virt` are mapped as Device-nGnRnE MMIO in `TTBR1_EL1`.
    unsafe {
        write_volatile((gicd + GICD_CTLR) as *mut u32, 1);
        write_volatile((gicc + GICC_PMR) as *mut u32, 0xFF);
        write_volatile((gicc + GICC_CTLR) as *mut u32, 1);
    }
    enable_irq(virt_timer_irq);
    enable_irq(SGI_RESCHEDULE);
}

/// Initialize the banked GICv2 CPU interface (`GICC`) and per-CPU PPI/SGI enables on an AP core.
pub fn init_secondary() {
    let gicc = GICC_VIRT_BASE.load(Ordering::Acquire) as usize;
    if gicc == 0 {
        return;
    }
    // SAFETY: `GICC` is banked per CPU and mapped as Device-nGnRnE MMIO in shared `TTBR1_EL1`.
    unsafe {
        write_volatile((gicc + GICC_PMR) as *mut u32, 0xFF);
        write_volatile((gicc + GICC_CTLR) as *mut u32, 1);
    }
    let timer_irq = VIRT_TIMER_IRQ.load(Ordering::Acquire) as u32;
    enable_irq(timer_irq);
    enable_irq(SGI_RESCHEDULE);
}

/// Send a GICv2 Software Generated Interrupt (`0..16`) to the target CPU bitmask (`bits 0..7`).
pub fn send_sgi(sgi_id: u32, target_cpu_mask: u8) {
    let gicd = GICD_VIRT_BASE.load(Ordering::Acquire) as usize;
    if gicd == 0 || sgi_id >= 16 || target_cpu_mask == 0 {
        return;
    }
    // GICD_SGIR: TargetListFilter=0b00 (bits 25:24), CPUTargetList (bits 23:16), SGIINTID (bits 3:0)
    let val = (u32::from(target_cpu_mask) << 16) | (sgi_id & 0xF);
    // SAFETY: `GICD_SGIR` (offset `0xF00`) lies within the 4 KiB GICD Device-nGnRnE MMIO page.
    unsafe {
        write_volatile((gicd + GICD_SGIR) as *mut u32, val);
    }
}

/// Enable (unmask) a specific GICv2 interrupt ID (`0..1020`).
pub fn enable_irq(irq: u32) {
    let gicd = GICD_VIRT_BASE.load(Ordering::Acquire) as usize;
    if gicd == 0 || irq >= 1020 {
        return;
    }
    let reg_off = GICD_ISENABLER + ((irq / 32) as usize) * 4;
    let bit = 1u32 << (irq % 32);
    // SAFETY: `gicd + reg_off` lies within the 4 KiB GICD MMIO page (`irq < 1020 => off <= 0x17C`).
    unsafe {
        write_volatile((gicd + reg_off) as *mut u32, bit);
    }
}

/// Acknowledge a pending GICv2 interrupt, returning `Some(iar)` if non-spurious.
#[inline]
pub fn acknowledge() -> Option<u32> {
    let gicc = GICC_VIRT_BASE.load(Ordering::Acquire) as usize;
    if gicc == 0 {
        return None;
    }
    // SAFETY: `GICC_IAR` is a valid 32-bit Device-nGnRnE register when GICC is mapped.
    let iar = unsafe { read_volatile((gicc + GICC_IAR) as *const u32) };
    if (iar & 0x3FF) >= SPURIOUS_IRQ {
        None
    } else {
        Some(iar)
    }
}

/// Signal End-Of-Interrupt to the GICv2 CPU interface for a previously acknowledged `iar`.
#[inline]
pub fn end_of_interrupt(iar: u32) {
    let gicc = GICC_VIRT_BASE.load(Ordering::Acquire) as usize;
    if gicc == 0 {
        return;
    }
    // SAFETY: `GICC_EOIR` is a valid 32-bit Device-nGnRnE register when GICC is mapped.
    unsafe {
        write_volatile((gicc + GICC_EOIR) as *mut u32, iar);
    }
}
