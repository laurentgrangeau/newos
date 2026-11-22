//! Pure seL4-style `Untyped` physical memory inventory and safe 4-level `VSpace` traits.
//!
//! Zero kernel heap (`no_alloc`) and 100% `#![forbid(unsafe_code)]`.

use newos_abi::SysError;

/// Standard 4 KiB hardware page size.
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Maximum number of usable physical memory regions tracked at bootstrap.
pub const MAX_UNTYPED_REGIONS: usize = 32;

/// 64-bit physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn new_aligned(raw: u64) -> Result<Self, SysError> {
        if (raw & PAGE_MASK) == 0 {
            Ok(Self(raw))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & PAGE_MASK) == 0
    }

    #[inline]
    pub const fn align_up(self) -> Self {
        Self((self.0.saturating_add(PAGE_MASK)) & !PAGE_MASK)
    }

    #[inline]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !PAGE_MASK)
    }
}

/// 64-bit canonical virtual address (48-bit 4-level paging canonical form).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Construct a canonical 48-bit virtual address.
    #[inline]
    pub const fn new_canonical(raw: u64) -> Result<Self, SysError> {
        let sign_ext = ((raw << 16) as i64 >> 16) as u64;
        if sign_ext == raw {
            Ok(Self(raw))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    pub const fn new_page_aligned(raw: u64) -> Result<Self, SysError> {
        if (raw & PAGE_MASK) != 0 {
            return Err(SysError::InvalidArgument);
        }
        Self::new_canonical(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & PAGE_MASK) == 0
    }
}

/// Owned 4 KiB physical memory frame carved from an `UntypedRegion`.
///
/// Not `Copy`/`Clone` so physical frames cannot be accidentally aliased or double-mapped.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysFrame {
    base: PhysAddr,
}

impl PhysFrame {
    /// Construct an owned frame from a verified 4 KiB-aligned physical address.
    #[inline]
    pub const fn from_aligned(base: PhysAddr) -> Result<Self, SysError> {
        if base.is_page_aligned() {
            Ok(Self { base })
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    pub const fn start_addr(&self) -> PhysAddr {
        self.base
    }
}

/// Single contiguous `Untyped` physical memory region using a seL4-style monotonic watermark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntypedRegion {
    pub base: u64,
    pub len: u64,
    pub watermark: u64,
}

impl UntypedRegion {
    pub const EMPTY: Self = Self {
        base: 0,
        len: 0,
        watermark: 0,
    };

    /// Create a page-aligned `UntypedRegion` from a raw firmware/bootloader memory range.
    pub const fn from_raw(base: u64, len: u64) -> Option<Self> {
        let start = PhysAddr::new(base).align_up().raw();
        let end = PhysAddr::new(base.saturating_add(len)).align_down().raw();
        if end <= start {
            return None;
        }
        Some(Self {
            base: start,
            len: end - start,
            watermark: 0,
        })
    }

    #[inline]
    pub const fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.watermark)
    }

    /// Carve a single 4 KiB `PhysFrame` by advancing the watermark monotonically.
    #[inline]
    pub fn retype_frame(&mut self) -> Result<PhysFrame, SysError> {
        if self.remaining() < PAGE_SIZE {
            return Err(SysError::OutOfMemory);
        }
        let addr = self.base + self.watermark;
        self.watermark += PAGE_SIZE;
        PhysFrame::from_aligned(PhysAddr::new(addr))
    }
}

/// Fixed-capacity, zero-heap inventory of bootstrap `Untyped` physical memory regions.
#[derive(Debug, Clone, Copy)]
pub struct UntypedInventory {
    regions: [UntypedRegion; MAX_UNTYPED_REGIONS],
    count: usize,
    active_region: usize,
    retyped_frames: u64,
}

impl Default for UntypedInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl UntypedInventory {
    pub const fn new() -> Self {
        Self {
            regions: [UntypedRegion::EMPTY; MAX_UNTYPED_REGIONS],
            count: 0,
            active_region: 0,
            retyped_frames: 0,
        }
    }

    /// Register a usable physical memory range from the bootloader memory map.
    pub fn push_raw_region(&mut self, base: u64, len: u64) -> bool {
        if self.count >= MAX_UNTYPED_REGIONS {
            return false;
        }
        let Some(region) = UntypedRegion::from_raw(base, len) else {
            return false;
        };
        self.regions[self.count] = region;
        self.count += 1;
        true
    }

    #[inline]
    pub const fn region_count(&self) -> usize {
        self.count
    }

    #[inline]
    pub const fn retyped_frames(&self) -> u64 {
        self.retyped_frames
    }

    pub fn total_bytes(&self) -> u64 {
        let mut total = 0u64;
        let mut i = 0;
        while i < self.count {
            total = total.saturating_add(self.regions[i].len);
            i += 1;
        }
        total
    }

    pub fn remaining_bytes(&self) -> u64 {
        let mut rem = 0u64;
        let mut i = self.active_region;
        while i < self.count {
            rem = rem.saturating_add(self.regions[i].remaining());
            i += 1;
        }
        rem
    }

    /// Carve one 4 KiB `PhysFrame` from the first `UntypedRegion` with available space.
    #[inline]
    pub fn retype_frame(&mut self) -> Result<PhysFrame, SysError> {
        while self.active_region < self.count {
            if let Ok(frame) = self.regions[self.active_region].retype_frame() {
                self.retyped_frames = self.retyped_frames.saturating_add(1);
                return Ok(frame);
            }
            self.active_region += 1;
        }
        Err(SysError::OutOfMemory)
    }
}

/// Architecture-independent virtual page mapping flags with strict **W^X** enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags {
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
    pub no_cache: bool,
}

impl PageFlags {
    /// Construct W^X-enforced page flags (rejects simultaneous `writable && executable`).
    pub const fn new_wx(
        writable: bool,
        executable: bool,
        user: bool,
        no_cache: bool,
    ) -> Result<Self, SysError> {
        if writable && executable {
            return Err(SysError::InvalidArgument);
        }
        Ok(Self {
            writable,
            executable,
            user,
            no_cache,
        })
    }

    pub const KERNEL_RW: Self = Self {
        writable: true,
        executable: false,
        user: false,
        no_cache: false,
    };

    pub const KERNEL_RO: Self = Self {
        writable: false,
        executable: false,
        user: false,
        no_cache: false,
    };

    pub const KERNEL_RX: Self = Self {
        writable: false,
        executable: true,
        user: false,
        no_cache: false,
    };
}

/// Summary of modern 64-bit hardware memory-protection features enabled by `newos-hal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSecurityFeatures {
    pub wp: bool,
    pub nxe: bool,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
}

/// Safe, architecture-agnostic 4-level page-table interface implemented by `newos-hal`.
pub trait VSpaceMapper {
    /// Return the hardware root physical address of this `VSpace` (`CR3` on `x86_64`).
    fn root_phys(&self) -> PhysAddr;

    /// Map a 4 KiB `PhysFrame` at `virt`, carving any needed intermediate page tables
    /// explicitly from `untyped` (zero kernel heap allocation).
    fn map_4k(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame,
        flags: PageFlags,
        untyped: &mut UntypedInventory,
    ) -> Result<(), SysError>;

    /// Walk the hardware page tables and return the mapped physical address and flags.
    fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, PageFlags)>;

    /// Unmap a 4 KiB page, flush its TLB entry, and return the reclaimed `PhysFrame`.
    fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError>;

    /// Zero a newly retyped, exclusively owned 4 KiB physical frame.
    fn zero_frame(&self, frame: &PhysFrame);

    /// Copy `src` bytes into an owned 4 KiB physical frame at `offset` (`offset + src.len() <= 4096`).
    fn write_frame_bytes(
        &self,
        frame: &PhysFrame,
        offset: usize,
        src: &[u8],
    ) -> Result<(), SysError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untyped_retype_is_monotonic_and_bounded() {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x10_0000, PAGE_SIZE * 2));
        assert_eq!(inv.total_bytes(), PAGE_SIZE * 2);

        let f0 = inv.retype_frame().expect("frame 0");
        let f1 = inv.retype_frame().expect("frame 1");
        assert_eq!(f0.start_addr().raw(), 0x10_0000);
        assert_eq!(f1.start_addr().raw(), 0x10_1000);
        assert_eq!(inv.retype_frame(), Err(SysError::OutOfMemory));
        assert_eq!(inv.remaining_bytes(), 0);
        assert_eq!(inv.retyped_frames(), 2);
    }

    #[test]
    fn page_flags_enforce_wx() {
        assert_eq!(
            PageFlags::new_wx(true, true, false, false),
            Err(SysError::InvalidArgument)
        );
        assert!(PageFlags::new_wx(true, false, true, false).is_ok());
        assert!(PageFlags::new_wx(false, true, true, false).is_ok());
    }

    #[test]
    fn canonical_virt_addr_validation() {
        assert!(VirtAddr::new_page_aligned(0xffff_9000_0000_0000).is_ok());
        assert!(VirtAddr::new_page_aligned(0x0000_7fff_ffff_f000).is_ok());
        // Non-canonical hole address must be rejected
        assert_eq!(
            VirtAddr::new_page_aligned(0x0001_0000_0000_0000),
            Err(SysError::InvalidArgument)
        );
        // Unaligned address must be rejected
        assert_eq!(
            VirtAddr::new_page_aligned(0xffff_9000_0000_0001),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn untyped_cursor_advances_and_handles_late_push() {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x10_0000, PAGE_SIZE));
        assert!(inv.push_raw_region(0x20_0000, PAGE_SIZE));
        assert!(inv.push_raw_region(0x30_0000, PAGE_SIZE));

        assert_eq!(inv.retype_frame().unwrap().start_addr().raw(), 0x10_0000);
        assert_eq!(inv.retype_frame().unwrap().start_addr().raw(), 0x20_0000);
        assert_eq!(inv.retype_frame().unwrap().start_addr().raw(), 0x30_0000);
        assert_eq!(inv.retype_frame(), Err(SysError::OutOfMemory));
        assert_eq!(inv.remaining_bytes(), 0);

        // Late push after cursor reached `count` must immediately serve frames.
        assert!(inv.push_raw_region(0x40_0000, PAGE_SIZE * 2));
        assert_eq!(inv.remaining_bytes(), PAGE_SIZE * 2);
        assert_eq!(inv.retype_frame().unwrap().start_addr().raw(), 0x40_0000);
        assert_eq!(inv.remaining_bytes(), PAGE_SIZE);
        assert_eq!(inv.retype_frame().unwrap().start_addr().raw(), 0x40_1000);
        assert_eq!(inv.remaining_bytes(), 0);
        assert_eq!(inv.retyped_frames(), 5);
    }
}
