//! Broadcom BCM2712 IOMMU (`brcm,bcm2712-iommu`) Page-Table & TLB Driver (`#![forbid(unsafe_code)]`).
//!
//! Raspberry Pi 5's BCM2712 SoC does NOT use ARM SMMUv3; instead, VideoCore VII (V3D 7.1),
//! ISP, and HEVC use Broadcom's custom `brcm,bcm2712-iommu` (`0x10_0000_5100`, 4 KiB page table
//! entries encoding 40-bit physical page frame numbers with valid/write permissions).

use crate::GpuMmioTransport;
use newos_abi::SysError;

pub const BCM2712_IOMMU_PAGE_PHYS: u64 = 0x10_0000_5000;
/// Base offset of the IOMMU control registers within the `0x10_0000_5000` page (`0x100`).
pub const IOMMU_BASE_OFF: u64 = 0x100;

pub const REG_IOMMU_CTL: u64 = IOMMU_BASE_OFF;
pub const REG_IOMMU_PT_PA: u64 = IOMMU_BASE_OFF + 0x04;
pub const REG_IOMMU_TLB_FLUSH: u64 = IOMMU_BASE_OFF + 0x08;
pub const REG_IOMMU_ILLEGAL_ADDR: u64 = IOMMU_BASE_OFF + 0x0C;

const IOMMU_CTL_ENABLE: u32 = 1 << 0;
const PTE_VALID: u32 = 1 << 0;
const PTE_WRITEABLE: u32 = 1 << 1;

/// Single 32-bit Broadcom BCM2712 IOMMU 4 KiB page-table entry (`PFN[27:0] << 4 | perms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Bcm2712IommuPte(pub u32);

impl Bcm2712IommuPte {
    pub const INVALID: Self = Self(0);

    /// Encode a 4 KiB-aligned 40-bit physical address (`< 1 TiB`) into a BCM2712 IOMMU PTE.
    pub const fn new(phys_addr: u64, writable: bool) -> Result<Self, SysError> {
        if (phys_addr & 0xFFF) != 0 || (phys_addr >> 40) != 0 {
            return Err(SysError::InvalidArgument);
        }
        let pfn = (phys_addr >> 12) as u32;
        let mut raw = (pfn << 4) | PTE_VALID;
        if writable {
            raw |= PTE_WRITEABLE;
        }
        Ok(Self(raw))
    }

    #[inline]
    pub const fn is_valid(self) -> bool {
        (self.0 & PTE_VALID) != 0
    }

    #[inline]
    pub const fn is_writable(self) -> bool {
        (self.0 & PTE_WRITEABLE) != 0
    }

    #[inline]
    pub const fn phys_addr(self) -> u64 {
        ((self.0 >> 4) as u64) << 12
    }
}

/// Fixed-capacity `no_alloc` BCM2712 IOMMU IOVA translation table (4 KiB granularity).
#[repr(C, align(4096))]
pub struct Bcm2712IommuTable<const PAGES: usize> {
    entries: [Bcm2712IommuPte; PAGES],
}

impl<const PAGES: usize> Default for Bcm2712IommuTable<PAGES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PAGES: usize> Bcm2712IommuTable<PAGES> {
    pub const fn new() -> Self {
        Self {
            entries: [Bcm2712IommuPte::INVALID; PAGES],
        }
    }

    pub fn map_page(
        &mut self,
        iova_page: usize,
        phys_addr: u64,
        writable: bool,
    ) -> Result<(), SysError> {
        if iova_page >= PAGES {
            return Err(SysError::InvalidArgument);
        }
        self.entries[iova_page] = Bcm2712IommuPte::new(phys_addr, writable)?;
        Ok(())
    }

    pub fn unmap_page(&mut self, iova_page: usize) -> Result<(), SysError> {
        if iova_page >= PAGES {
            return Err(SysError::InvalidArgument);
        }
        self.entries[iova_page] = Bcm2712IommuPte::INVALID;
        Ok(())
    }

    pub fn translate(&self, iova_page: usize) -> Option<(u64, bool)> {
        let pte = *self.entries.get(iova_page)?;
        if pte.is_valid() {
            Some((pte.phys_addr(), pte.is_writable()))
        } else {
            None
        }
    }
}

/// Capability-scoped EL0 controller for `brcm,bcm2712-iommu` (`CapId::BOOTSTRAP_IOMMU_MMIO`).
pub struct Bcm2712Iommu<T: GpuMmioTransport> {
    transport: T,
}

impl<T: GpuMmioTransport> Bcm2712Iommu<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Program the 4 KiB-aligned page-table physical base (`pt_phys`), flush TLB, and enable IOMMU.
    pub fn enable(&self, pt_phys: u64) -> Result<(), SysError> {
        if (pt_phys & 0xFFF) != 0 || (pt_phys >> 40) != 0 {
            return Err(SysError::InvalidArgument);
        }
        self.transport
            .write32(REG_IOMMU_PT_PA, (pt_phys >> 12) as u32)?;
        self.transport.write32(REG_IOMMU_TLB_FLUSH, 1)?;
        self.transport.write32(REG_IOMMU_CTL, IOMMU_CTL_ENABLE)
    }

    pub fn flush_tlb(&self) -> Result<(), SysError> {
        self.transport.write32(REG_IOMMU_TLB_FLUSH, 1)
    }

    pub fn illegal_addr(&self) -> Result<u32, SysError> {
        self.transport.read32(REG_IOMMU_ILLEGAL_ADDR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockIommu {
        ctl: RefCell<u32>,
        pt_pa: RefCell<u32>,
        flushes: RefCell<u32>,
    }

    impl GpuMmioTransport for &MockIommu {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_IOMMU_CTL => Ok(*self.ctl.borrow()),
                REG_IOMMU_PT_PA => Ok(*self.pt_pa.borrow()),
                _ => Ok(0),
            }
        }
        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            match offset {
                REG_IOMMU_CTL => *self.ctl.borrow_mut() = val,
                REG_IOMMU_PT_PA => *self.pt_pa.borrow_mut() = val,
                REG_IOMMU_TLB_FLUSH => *self.flushes.borrow_mut() += 1,
                _ => return Err(SysError::InvalidArgument),
            }
            Ok(())
        }
    }

    #[test]
    fn bcm2712_iommu_maps_40bit_pa_and_programs_hardware() {
        let mut tbl: Bcm2712IommuTable<16> = Bcm2712IommuTable::new();
        // 16 GB RAM physical address (> 4 GB, 40-bit PA)
        let pa_high = 0x0003_8000_4000u64;
        tbl.map_page(2, pa_high, true).expect("map 40-bit PA");
        assert_eq!(tbl.translate(2), Some((pa_high, true)));
        assert_eq!(tbl.translate(3), None);

        let mock = MockIommu {
            ctl: RefCell::new(0),
            pt_pa: RefCell::new(0),
            flushes: RefCell::new(0),
        };
        let iommu = Bcm2712Iommu::new(&mock);
        iommu.enable(0x0002_0001_0000).expect("enable iommu");
        assert_eq!(*mock.pt_pa.borrow(), 0x0020_0010);
        assert_eq!(*mock.ctl.borrow(), IOMMU_CTL_ENABLE);
        assert_eq!(*mock.flushes.borrow(), 1);
    }
}
