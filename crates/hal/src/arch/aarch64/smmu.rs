//! Minimal audited ARM SMMUv3 MMIO probe driver (Device-nGnRnE, ARM IHI 0070G).
//!
//! Discovers SMMUv3 capabilities (`IDR0`, `IDR1`, `CR0`) when an ACPI `IORT` SMMUv3 node
//! is advertised by firmware, preparing the hardware boundary for capability-scoped `IoSpace`
//! DMA isolation (`newos_kernel_core::smmu`).

use core::ptr::read_volatile;
use core::sync::atomic::{AtomicU64, Ordering};

const SMMU_IDR0: usize = 0x000;
const SMMU_IDR1: usize = 0x004;
const SMMU_CR0: usize = 0x020;

static SMMU_VIRT_BASE: AtomicU64 = AtomicU64::new(0);

/// Hardware capabilities probed from ARM SMMUv3 `IDR0`/`IDR1`/`CR0`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmuInfo {
    pub present: bool,
    pub stage1: bool,
    pub stage2: bool,
    pub sid_bits: u8,
    pub enabled: bool,
}

/// Probe an ARM SMMUv3 register page mapped at `smmu_virt` (Device-nGnRnE, 4 KiB).
pub fn probe(smmu_virt: u64) -> SmmuInfo {
    SMMU_VIRT_BASE.store(smmu_virt, Ordering::Release);
    let base = smmu_virt as usize;
    // SAFETY: `smmu_virt` is mapped as a 4 KiB Device-nGnRnE MMIO page in `TTBR1_EL1`
    // covering `SMMU_IDR0` (0x000), `SMMU_IDR1` (0x004), and `SMMU_CR0` (0x020).
    let (idr0, idr1, cr0) = unsafe {
        (
            read_volatile((base + SMMU_IDR0) as *const u32),
            read_volatile((base + SMMU_IDR1) as *const u32),
            read_volatile((base + SMMU_CR0) as *const u32),
        )
    };
    SmmuInfo {
        present: true,
        stage1: (idr0 & (1 << 1)) != 0,
        stage2: (idr0 & (1 << 0)) != 0,
        sid_bits: (idr1 & 0x3F) as u8,
        enabled: (cr0 & 1) != 0,
    }
}
