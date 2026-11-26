//! Broadcom BCM2712 IOMMU (`brcm,bcm2712-iommu`) Page-Table & TLB Driver.
//!
//! Raspberry Pi 5's BCM2712 `SoC` does NOT use ARM `SMMUv3`; instead, `VideoCore` VII (V3D 7.1),
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

/// Validate a 4 KiB-aligned 40-bit physical address (`< 1 TiB`) and return its 28-bit PFN.
#[inline]
const fn phys_to_pfn(phys_addr: u64) -> Result<u32, SysError> {
    if (phys_addr & 0xFFF) != 0 || (phys_addr >> 40) != 0 {
        return Err(SysError::InvalidArgument);
    }
    let shifted = (phys_addr >> 12).to_le_bytes();
    Ok(u32::from_le_bytes([
        shifted[0], shifted[1], shifted[2], shifted[3],
    ]))
}

/// Access permission for a BCM2712 IOMMU 4 KiB page mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuAccess {
    ReadOnly,
    ReadWrite,
}

/// Single 32-bit Broadcom BCM2712 IOMMU 4 KiB page-table entry (`PFN[27:0] << 4 | perms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Bcm2712IommuPte(u32);

impl Default for Bcm2712IommuPte {
    fn default() -> Self {
        Self::INVALID
    }
}

impl Bcm2712IommuPte {
    pub const INVALID: Self = Self(0);

    /// Encode a 4 KiB-aligned 40-bit physical address (`< 1 TiB`) into a BCM2712 IOMMU PTE.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `phys_addr` is not 4 KiB-aligned or exceeds 40 bits.
    pub const fn new(phys_addr: u64, access: IommuAccess) -> Result<Self, SysError> {
        let pfn = match phys_to_pfn(phys_addr) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let mut raw = (pfn << 4) | PTE_VALID;
        if matches!(access, IommuAccess::ReadWrite) {
            raw |= PTE_WRITEABLE;
        }
        Ok(Self(raw))
    }

    /// Return the raw 32-bit hardware PTE encoding.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Return `true` if this PTE is marked valid.
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        (self.0 & PTE_VALID) != 0
    }

    /// Return the decoded [`IommuAccess`] permission of this PTE.
    #[inline]
    #[must_use]
    pub const fn access(self) -> IommuAccess {
        if (self.0 & PTE_WRITEABLE) != 0 {
            IommuAccess::ReadWrite
        } else {
            IommuAccess::ReadOnly
        }
    }

    /// Return `true` if this PTE grants write permission.
    #[inline]
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self.access(), IommuAccess::ReadWrite)
    }

    /// Return the 4 KiB-aligned 40-bit physical address encoded in this PTE.
    #[inline]
    #[must_use]
    pub const fn phys_addr(self) -> u64 {
        ((self.0 >> 4) as u64) << 12
    }
}

/// Fixed-capacity BCM2712 IOMMU IOVA translation table (4 KiB granularity).
#[derive(Debug, PartialEq, Eq)]
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
    /// Construct an empty BCM2712 IOMMU table with all entries set to [`Bcm2712IommuPte::INVALID`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Bcm2712IommuPte::INVALID; PAGES],
        }
    }

    /// Map `iova_page` to `phys_addr` with the requested `access` permissions.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `iova_page >= PAGES` or `phys_addr` is not a
    /// valid 4 KiB-aligned 40-bit physical address.
    pub const fn map_page(
        &mut self,
        iova_page: usize,
        phys_addr: u64,
        access: IommuAccess,
    ) -> Result<(), SysError> {
        if iova_page >= PAGES {
            return Err(SysError::InvalidArgument);
        }
        let pte = match Bcm2712IommuPte::new(phys_addr, access) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        self.entries[iova_page] = pte;
        Ok(())
    }

    /// Unmap `iova_page`, resetting its entry to [`Bcm2712IommuPte::INVALID`].
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `iova_page >= PAGES`.
    pub const fn unmap_page(&mut self, iova_page: usize) -> Result<(), SysError> {
        if iova_page >= PAGES {
            return Err(SysError::InvalidArgument);
        }
        self.entries[iova_page] = Bcm2712IommuPte::INVALID;
        Ok(())
    }

    /// Translate `iova_page`, returning `(phys_addr, access)` if mapped and valid.
    #[must_use]
    pub fn translate(&self, iova_page: usize) -> Option<(u64, IommuAccess)> {
        let pte = *self.entries.get(iova_page)?;
        if pte.is_valid() {
            Some((pte.phys_addr(), pte.access()))
        } else {
            None
        }
    }
}

/// Capability-scoped EL0 controller for `brcm,bcm2712-iommu` (`CapId::BOOTSTRAP_IOMMU_MMIO`).
#[derive(Debug)]
pub struct Bcm2712Iommu<T: GpuMmioTransport> {
    transport: T,
}

impl<T: GpuMmioTransport> Bcm2712Iommu<T> {
    /// Construct a BCM2712 IOMMU controller over `transport`.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Program the 4 KiB-aligned page-table physical base (`pt_phys`), flush TLB, and enable IOMMU.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `pt_phys` is not a 4 KiB-aligned 40-bit physical
    /// address, or a transport [`SysError`] if MMIO writes fail.
    pub fn enable(&self, pt_phys: u64) -> Result<(), SysError> {
        let pt_pfn = phys_to_pfn(pt_phys)?;
        self.transport.write32(REG_IOMMU_PT_PA, pt_pfn)?;
        self.transport.write32(REG_IOMMU_TLB_FLUSH, 1)?;
        self.transport.write32(REG_IOMMU_CTL, IOMMU_CTL_ENABLE)
    }

    /// Trigger a full IOMMU TLB invalidation.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO write fails.
    pub fn flush_tlb(&self) -> Result<(), SysError> {
        self.transport.write32(REG_IOMMU_TLB_FLUSH, 1)
    }

    /// Read the last illegal DMA address latched by the IOMMU fault register.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if the MMIO read fails.
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
        tbl.map_page(2, pa_high, IommuAccess::ReadWrite)
            .expect("map 40-bit PA");
        assert_eq!(tbl.translate(2), Some((pa_high, IommuAccess::ReadWrite)));
        assert_eq!(tbl.translate(3), None);

        tbl.map_page(4, 0x0001_0000_0000, IommuAccess::ReadOnly)
            .expect("map ro");
        assert_eq!(
            tbl.translate(4),
            Some((0x0001_0000_0000, IommuAccess::ReadOnly))
        );
        tbl.unmap_page(4).expect("unmap");
        assert_eq!(tbl.translate(4), None);

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

    #[test]
    fn bcm2712_iommu_rejects_unaligned_or_overflow_addresses_and_oob_pages() {
        assert_eq!(Bcm2712IommuPte::default(), Bcm2712IommuPte::INVALID);
        assert_eq!(Bcm2712IommuPte::INVALID.raw(), 0);
        assert_eq!(
            Bcm2712IommuPte::new(0x1001, IommuAccess::ReadOnly),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            Bcm2712IommuPte::new(1u64 << 40, IommuAccess::ReadWrite),
            Err(SysError::InvalidArgument)
        );

        let mut tbl: Bcm2712IommuTable<4> = Bcm2712IommuTable::default();
        assert_eq!(
            tbl.map_page(4, 0x1000, IommuAccess::ReadOnly),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(tbl.unmap_page(4), Err(SysError::InvalidArgument));

        let mock = MockIommu {
            ctl: RefCell::new(0),
            pt_pa: RefCell::new(0),
            flushes: RefCell::new(0),
        };
        let iommu = Bcm2712Iommu::new(&mock);
        assert_eq!(iommu.enable(0x1004), Err(SysError::InvalidArgument));
        assert_eq!(iommu.enable(1u64 << 40), Err(SysError::InvalidArgument));
    }
}
