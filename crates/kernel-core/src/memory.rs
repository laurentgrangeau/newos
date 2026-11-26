//! `Untyped` physical memory inventory and 4-level `VSpace` traits.
//!
//! Zero kernel heap.

use core::fmt;
use newos_abi::SysError;

/// Standard 4 KiB hardware page size.
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// 2 MiB hardware superpage / huge-page size (`L2` block descriptor on `aarch64`).
pub const HUGE_PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const HUGE_PAGE_MASK_2M: u64 = HUGE_PAGE_SIZE_2M - 1;

/// Maximum number of usable physical memory regions tracked at bootstrap (sized for `RPi5` 16 GB UEFI maps).
pub const MAX_UNTYPED_REGIONS: usize = 64;

/// Fixed-capacity LIFO cache for reclaimed 4 KiB physical frames (4 MiB capacity, 8 KiB inline).
pub const MAX_RECLAIMED_FRAMES: usize = 1024;

/// 64-bit physical address.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    #[inline]
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Construct a 4 KiB page-aligned physical address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `raw` is not 4 KiB-aligned.
    #[inline]
    pub const fn new_aligned(raw: u64) -> Result<Self, SysError> {
        if (raw & PAGE_MASK) == 0 {
            Ok(Self(raw))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & PAGE_MASK) == 0
    }

    #[inline]
    #[must_use]
    pub const fn align_up(self) -> Self {
        Self((self.0.saturating_add(PAGE_MASK)) & !PAGE_MASK)
    }

    #[inline]
    #[must_use]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !PAGE_MASK)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl From<PhysAddr> for u64 {
    #[inline]
    fn from(addr: PhysAddr) -> Self {
        addr.0
    }
}

/// Type-level proof of a 4 KiB page-aligned 64-bit physical address.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PageAlignedPhysAddr(u64);

impl PageAlignedPhysAddr {
    /// Zero physical address (trivially 4 KiB-aligned).
    pub const ZERO: Self = Self(0);

    /// Validate and wrap a 4 KiB page-aligned physical address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `raw` is not 4 KiB-aligned.
    #[inline]
    pub const fn new(raw: u64) -> Result<Self, SysError> {
        if (raw & PAGE_MASK) == 0 {
            Ok(Self(raw))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Validate and wrap a [`PhysAddr`] as 4 KiB page-aligned.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `addr` is not 4 KiB-aligned.
    #[inline]
    pub const fn from_phys(addr: PhysAddr) -> Result<Self, SysError> {
        Self::new(addr.raw())
    }

    #[inline]
    #[must_use]
    pub const fn as_phys(self) -> PhysAddr {
        PhysAddr::new(self.0)
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PageAlignedPhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl From<PageAlignedPhysAddr> for PhysAddr {
    #[inline]
    fn from(addr: PageAlignedPhysAddr) -> Self {
        addr.as_phys()
    }
}

impl TryFrom<PhysAddr> for PageAlignedPhysAddr {
    type Error = SysError;

    #[inline]
    fn try_from(addr: PhysAddr) -> Result<Self, Self::Error> {
        Self::from_phys(addr)
    }
}

/// 64-bit canonical virtual address (48-bit 4-level paging canonical form).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Construct a canonical 48-bit virtual address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `raw` is not in 48-bit canonical form.
    #[inline]
    pub const fn new_canonical(raw: u64) -> Result<Self, SysError> {
        let sign_ext = ((raw << 16).cast_signed() >> 16).cast_unsigned();
        if sign_ext == raw {
            Ok(Self(raw))
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Construct a 4 KiB page-aligned canonical 48-bit virtual address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `raw` is unaligned or non-canonical.
    #[inline]
    pub const fn new_page_aligned(raw: u64) -> Result<Self, SysError> {
        if (raw & PAGE_MASK) != 0 {
            return Err(SysError::InvalidArgument);
        }
        Self::new_canonical(raw)
    }

    #[inline]
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    #[must_use]
    pub const fn is_page_aligned(self) -> bool {
        (self.0 & PAGE_MASK) == 0
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl From<VirtAddr> for u64 {
    #[inline]
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

/// Owned 4 KiB physical memory frame carved from an `UntypedRegion`.
///
/// Not `Copy`/`Clone` so physical frames cannot be accidentally aliased or double-mapped.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysFrame {
    base: PageAlignedPhysAddr,
}

impl PhysFrame {
    /// Construct an owned frame directly from a type-verified 4 KiB-aligned physical address.
    #[inline]
    #[must_use]
    pub const fn from_page_aligned(base: PageAlignedPhysAddr) -> Self {
        Self { base }
    }

    /// Construct an owned frame from a verified 4 KiB-aligned physical address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `base` is not 4 KiB-aligned.
    #[inline]
    pub const fn from_aligned(base: PhysAddr) -> Result<Self, SysError> {
        match PageAlignedPhysAddr::from_phys(base) {
            Ok(aligned) => Ok(Self { base: aligned }),
            Err(e) => Err(e),
        }
    }

    #[inline]
    #[must_use]
    pub const fn start_addr(&self) -> PhysAddr {
        self.base.as_phys()
    }

    #[inline]
    #[must_use]
    pub const fn aligned_addr(&self) -> PageAlignedPhysAddr {
        self.base
    }
}

/// Owned 2 MiB physical superpage carved from an `UntypedRegion`.
///
/// Not `Copy`/`Clone` so huge physical frames cannot be aliased or double-mapped.
#[derive(Debug, PartialEq, Eq)]
pub struct PhysFrame2M {
    base: PhysAddr,
}

impl PhysFrame2M {
    /// Construct an owned 2 MiB frame from a verified 2 MiB-aligned physical address.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `base` is not 2 MiB-aligned.
    #[inline]
    pub const fn from_aligned(base: PhysAddr) -> Result<Self, SysError> {
        if (base.raw() & HUGE_PAGE_MASK_2M) == 0 {
            Ok(Self { base })
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    #[inline]
    #[must_use]
    pub const fn start_addr(&self) -> PhysAddr {
        self.base
    }
}

/// Single contiguous `Untyped` physical memory region using a monotonic watermark.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
    #[must_use]
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
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.watermark)
    }

    /// Carve a single 4 KiB `PhysFrame` by advancing the watermark monotonically.
    ///
    /// # Errors
    /// - [`SysError::OutOfMemory`] if fewer than `PAGE_SIZE` bytes remain or address arithmetic overflows.
    /// - [`SysError::InvalidArgument`] if the region base or watermark is not 4 KiB-aligned.
    #[inline]
    pub fn retype_frame(&mut self) -> Result<PhysFrame, SysError> {
        if self.remaining() < PAGE_SIZE {
            return Err(SysError::OutOfMemory);
        }
        let addr = self
            .base
            .checked_add(self.watermark)
            .ok_or(SysError::OutOfMemory)?;
        let frame = PhysFrame::from_aligned(PhysAddr::new(addr))?;
        self.watermark += PAGE_SIZE;
        Ok(frame)
    }
}

/// Fixed-capacity inventory of bootstrap `Untyped` physical memory regions
/// with a bounded LIFO free-frame cache for reclaimed 4 KiB pages.
///
/// Intentionally NOT `Copy` so a stray copy can never hand out the same physical frames twice.
#[derive(Debug, Clone)]
pub struct UntypedInventory {
    regions: [UntypedRegion; MAX_UNTYPED_REGIONS],
    count: usize,
    active_region: usize,
    retyped_frames: u64,
    reclaimed: [PageAlignedPhysAddr; MAX_RECLAIMED_FRAMES],
    reclaimed_len: usize,
}

impl Default for UntypedInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl UntypedInventory {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: [UntypedRegion::EMPTY; MAX_UNTYPED_REGIONS],
            count: 0,
            active_region: 0,
            retyped_frames: 0,
            reclaimed: [PageAlignedPhysAddr::ZERO; MAX_RECLAIMED_FRAMES],
            reclaimed_len: 0,
        }
    }

    /// Register a usable physical memory range from the bootloader memory map.
    pub const fn push_raw_region(&mut self, base: u64, len: u64) -> bool {
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
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.count
    }

    #[inline]
    #[must_use]
    pub const fn retyped_frames(&self) -> u64 {
        self.retyped_frames
    }

    /// Number of reclaimed 4 KiB frames currently cached for O(1) reuse.
    #[inline]
    #[must_use]
    pub const fn reclaimed_count(&self) -> usize {
        self.reclaimed_len
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        let mut total = 0u64;
        let mut i = 0;
        while i < self.count {
            total = total.saturating_add(self.regions[i].len);
            i += 1;
        }
        total
    }

    #[must_use]
    pub const fn remaining_bytes(&self) -> u64 {
        let mut rem = (self.reclaimed_len as u64).saturating_mul(PAGE_SIZE);
        let mut i = self.active_region;
        while i < self.count {
            rem = rem.saturating_add(self.regions[i].remaining());
            i += 1;
        }
        rem
    }

    /// Remaining allocatable 4 KiB physical frames (untyped regions + reclaimed LIFO cache).
    #[inline]
    #[must_use]
    pub const fn remaining_frames(&self) -> u64 {
        self.remaining_bytes() / PAGE_SIZE
    }

    /// Return an unmapped, exclusively owned 4 KiB `PhysFrame` to the LIFO reuse cache.
    ///
    /// Deduplicates already-cached physical addresses to prevent double-reclaim aliasing.
    /// Returns `true` if cached (or already present), or `false` if the bounded cache is full.
    #[inline]
    #[allow(clippy::needless_pass_by_value)] // Intentional: consumes linear PhysFrame ownership so the caller cannot alias or reuse a reclaimed frame.
    pub const fn reclaim_frame(&mut self, frame: PhysFrame) -> bool {
        let addr = frame.aligned_addr();
        let mut i = 0;
        while i < self.reclaimed_len {
            if self.reclaimed[i].raw() == addr.raw() {
                return true;
            }
            i += 1;
        }
        if self.reclaimed_len >= MAX_RECLAIMED_FRAMES {
            return false;
        }
        self.reclaimed[self.reclaimed_len] = addr;
        self.reclaimed_len += 1;
        true
    }

    /// Return the index of the `UntypedRegion` with the largest remaining capacity, if any.
    #[must_use]
    pub fn largest_region_index(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, region) in self.regions.iter().enumerate().take(self.count) {
            let rem = region.remaining();
            if rem > 0 && best.is_none_or(|(_, best_rem)| rem > best_rem) {
                best = Some((i, rem));
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// Remaining uncarved bytes in a specific `UntypedRegion` (`region_index`).
    #[inline]
    #[must_use]
    pub const fn region_remaining(&self, region_index: usize) -> Option<u64> {
        if region_index < self.count {
            Some(self.regions[region_index].remaining())
        } else {
            None
        }
    }

    /// Carve one 4 KiB `PhysFrame` strictly from the designated `region_index` (`H-3`).
    ///
    /// Enforces designated-authority resource accounting: holding an `Untyped { region_index }`
    /// capability can only ever consume physical memory from that exact region.
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `region_index` is out of range or region alignment is invalid.
    /// - [`SysError::OutOfMemory`] if the designated region has fewer than `PAGE_SIZE` bytes remaining.
    #[inline]
    pub fn retype_frame_in(&mut self, region_index: usize) -> Result<PhysFrame, SysError> {
        if region_index >= self.count {
            return Err(SysError::InvalidArgument);
        }
        let frame = self.regions[region_index].retype_frame()?;
        self.retyped_frames = self.retyped_frames.saturating_add(1);
        Ok(frame)
    }

    /// Carve one 4 KiB `PhysFrame` — reusing a reclaimed frame first, otherwise advancing
    /// the first `UntypedRegion` with available space.
    ///
    /// # Errors
    /// - [`SysError::OutOfMemory`] if neither the reclaimed cache nor any untyped region can supply a frame.
    /// - [`SysError::InvalidArgument`] if an active region has an invalid unaligned base.
    #[inline]
    pub fn retype_frame(&mut self) -> Result<PhysFrame, SysError> {
        if self.reclaimed_len > 0 {
            self.reclaimed_len -= 1;
            let addr = self.reclaimed[self.reclaimed_len];
            self.retyped_frames = self.retyped_frames.saturating_add(1);
            return Ok(PhysFrame::from_page_aligned(addr));
        }
        while self.active_region < self.count {
            match self.regions[self.active_region].retype_frame() {
                Ok(frame) => {
                    self.retyped_frames = self.retyped_frames.saturating_add(1);
                    return Ok(frame);
                }
                Err(SysError::OutOfMemory) => {
                    self.active_region += 1;
                }
                Err(e) => return Err(e),
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Carve one 2 MiB-aligned `PhysFrame2M` superpage from an `UntypedRegion`.
    ///
    /// Any 4 KiB alignment padding skipped before the 2 MiB boundary is pushed into the
    /// reclaimed-frame cache so it can be reused for 4 KiB allocations.
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if no untyped region contains a 2 MiB-aligned span.
    pub fn retype_frame_2m(&mut self) -> Result<PhysFrame2M, SysError> {
        for i in self.active_region..self.count {
            let Some(cur) = self.regions[i].base.checked_add(self.regions[i].watermark) else {
                continue;
            };
            let Some(rounded) = cur.checked_add(HUGE_PAGE_MASK_2M) else {
                continue;
            };
            let aligned = rounded & !HUGE_PAGE_MASK_2M;
            let pad = aligned - cur;
            let Some(needed) = pad.checked_add(HUGE_PAGE_SIZE_2M) else {
                continue;
            };
            if self.regions[i].remaining() >= needed {
                // Recycle any 4 KiB alignment padding frames into the LIFO cache.
                let mut p = cur;
                while p < aligned {
                    if let Ok(pad_frame) = PhysFrame::from_aligned(PhysAddr::new(p)) {
                        let _ = self.reclaim_frame(pad_frame);
                    }
                    p += PAGE_SIZE;
                }
                self.regions[i].watermark += needed;
                self.retyped_frames = self
                    .retyped_frames
                    .saturating_add(HUGE_PAGE_SIZE_2M / PAGE_SIZE);
                return PhysFrame2M::from_aligned(PhysAddr::new(aligned));
            }
        }
        Err(SysError::OutOfMemory)
    }
}

/// Compile-time W^X-enforced page access permissions (simultaneous write + execute is unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageAccess {
    /// Read-only, non-executable.
    ReadOnly,
    /// Read-write, non-executable.
    ReadWrite,
    /// Read-only, executable.
    ReadExecute,
}

/// Privilege level permitted to access a mapped virtual page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PagePrivilege {
    /// EL1 kernel-only mapping.
    Kernel,
    /// EL0 protection-domain accessible mapping.
    User,
}

/// Hardware memory attribute / caching policy for a mapped virtual page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageCachePolicy {
    /// Normal Write-Back Cacheable RAM.
    NormalCacheable,
    /// Device-nGnRnE uncached MMIO mapping.
    DeviceNoCache,
    /// Normal Non-Cacheable (MAIR `0x44`) mapping for coherent DMA descriptor rings.
    NormalNonCacheable,
}

/// Architecture-independent virtual page mapping flags with strict **W^X** enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Intentional transition: legacy pub bool fields retained for M4 (hal) and M6 (tests) compatibility alongside type-safe PageFlags::new.
pub struct PageFlags {
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
    pub no_cache: bool,
    pub dma_nc: bool,
}

impl PageFlags {
    /// Construct W^X-enforced page flags from strongly typed access, privilege, and cache enums.
    #[inline]
    #[must_use]
    pub const fn new(access: PageAccess, privilege: PagePrivilege, cache: PageCachePolicy) -> Self {
        let (writable, executable) = match access {
            PageAccess::ReadOnly => (false, false),
            PageAccess::ReadWrite => (true, false),
            PageAccess::ReadExecute => (false, true),
        };
        let user = matches!(privilege, PagePrivilege::User);
        let (no_cache, dma_nc) = match cache {
            PageCachePolicy::NormalCacheable => (false, false),
            PageCachePolicy::DeviceNoCache => (true, false),
            PageCachePolicy::NormalNonCacheable => (false, true),
        };
        Self {
            writable,
            executable,
            user,
            no_cache,
            dma_nc,
        }
    }

    /// Return the typed W^X access permission represented by these flags.
    #[inline]
    #[must_use]
    pub const fn access(self) -> PageAccess {
        if self.writable {
            PageAccess::ReadWrite
        } else if self.executable {
            PageAccess::ReadExecute
        } else {
            PageAccess::ReadOnly
        }
    }

    /// Return the privilege level represented by these flags.
    #[inline]
    #[must_use]
    pub const fn privilege(self) -> PagePrivilege {
        if self.user {
            PagePrivilege::User
        } else {
            PagePrivilege::Kernel
        }
    }

    /// Return the caching policy represented by these flags.
    #[inline]
    #[must_use]
    pub const fn cache_policy(self) -> PageCachePolicy {
        if self.no_cache {
            PageCachePolicy::DeviceNoCache
        } else if self.dma_nc {
            PageCachePolicy::NormalNonCacheable
        } else {
            PageCachePolicy::NormalCacheable
        }
    }

    /// Construct W^X-enforced page flags (rejects simultaneous `writable && executable`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if both `writable` and `executable` are `true`.
    #[allow(clippy::fn_params_excessive_bools)] // Intentional transition: retained for M4 (hal) and M6 (tests) compatibility; prefer PageFlags::new.
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
            dma_nc: false,
        })
    }

    /// Construct Normal Non-Cacheable (MAIR `0x44`) page flags for DMA descriptor rings (`H4`).
    #[must_use]
    pub const fn new_dma_nc(writable: bool, user: bool) -> Self {
        Self {
            writable,
            executable: false,
            user,
            no_cache: false,
            dma_nc: true,
        }
    }

    pub const KERNEL_RW: Self = Self::new(
        PageAccess::ReadWrite,
        PagePrivilege::Kernel,
        PageCachePolicy::NormalCacheable,
    );

    pub const KERNEL_RO: Self = Self::new(
        PageAccess::ReadOnly,
        PagePrivilege::Kernel,
        PageCachePolicy::NormalCacheable,
    );

    pub const KERNEL_RX: Self = Self::new(
        PageAccess::ReadExecute,
        PagePrivilege::Kernel,
        PageCachePolicy::NormalCacheable,
    );
}

/// Summary of `AArch64` (ARMv8.2-A Cortex-A76) hardware memory-protection & speculative-execution mitigations enabled by `newos-hal`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Intentional: 7 independent EL1 CPU security mitigation flags reported by newos-hal.
pub struct CpuSecurityFeatures {
    pub pxn: bool,
    pub uxn: bool,
    pub pan: bool,
    pub wx_enforced: bool,
    pub ssbs: bool,
    pub csv2: bool,
    pub csv3: bool,
}

/// Safe, architecture-agnostic 4-level page-table interface implemented by `newos-hal`.
pub trait VSpaceMapper {
    /// Return the hardware root physical address of this `VSpace` (`TTBR0_EL1` / `TTBR1_EL1` on `aarch64`).
    fn root_phys(&self) -> PhysAddr;

    /// Map a 4 KiB `PhysFrame` at `virt`, carving any needed intermediate page tables
    /// explicitly from `untyped` (zero kernel heap allocation).
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `virt` is unaligned/non-canonical or `flags` violates W^X.
    /// - [`SysError::OutOfMemory`] if intermediate page-table allocation from `untyped` fails.
    /// - [`SysError::SlotOccupied`] if `virt` is already mapped.
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
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `virt` is unaligned, non-canonical, or not currently mapped.
    fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError>;

    /// Map a 2 MiB `PhysFrame2M` superpage at 2 MiB-aligned `virt`.
    ///
    /// # Errors
    /// - [`SysError::Unsupported`] if the backend does not support 2 MiB superpages.
    /// - [`SysError::InvalidArgument`] or [`SysError::OutOfMemory`] if alignment, flags, or table carving fails.
    fn map_2m(
        &mut self,
        _virt: VirtAddr,
        _frame: PhysFrame2M,
        _flags: PageFlags,
        _untyped: &mut UntypedInventory,
    ) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }

    /// Unmap a 2 MiB superpage, flush its TLB entry, and return the reclaimed `PhysFrame2M`.
    ///
    /// # Errors
    /// - [`SysError::Unsupported`] if the backend does not support 2 MiB superpages.
    /// - [`SysError::InvalidArgument`] if `virt` is not currently mapped as a 2 MiB superpage.
    fn unmap_2m(&mut self, _virt: VirtAddr) -> Result<PhysFrame2M, SysError> {
        Err(SysError::Unsupported)
    }

    /// Zero a newly retyped, exclusively owned 4 KiB physical frame.
    fn zero_frame(&self, frame: &PhysFrame);

    /// Copy `src` bytes into an owned 4 KiB physical frame at `offset` (`offset + src.len() <= 4096`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `offset + src.len() > PAGE_SIZE`.
    fn write_frame_bytes(
        &self,
        frame: &PhysFrame,
        offset: usize,
        src: &[u8],
    ) -> Result<(), SysError>;
}

/// Fixed-capacity reverse-mapping entry linking a physical `Frame` to a `(VSpace, VirtAddr)`
/// along with its W/X permissions to enforce system-wide W^X anti-aliasing (`M1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMapping {
    pub vspace_root: PhysAddr,
    pub virt: VirtAddr,
    pub phys: PhysAddr,
    pub writable: bool,
    pub executable: bool,
}

impl FrameMapping {
    const EMPTY: Self = Self {
        vspace_root: PhysAddr::new(0),
        virt: VirtAddr(0),
        phys: PhysAddr::new(0),
        writable: false,
        executable: false,
    };
}

/// Fixed-capacity reverse-mapping table for physical frame tracking.
///
/// Enables hardware PTE unmap + TLB flush when a `Frame` or parent `Untyped` capability is
/// revoked (`H-3`), and system-wide W^X anti-aliasing checks across all `VSpaces` (`M1`).
pub struct FrameMappingTracker<const MAX_MAPPINGS: usize> {
    entries: [FrameMapping; MAX_MAPPINGS],
    len: usize,
    /// Physical frames that have been mapped `writable` since allocation/zeroing.
    /// Prevents write-then-unmap-then-execute W^X bypasses across time until the frame
    /// is zeroed and reclaimed.
    ever_written: [PhysAddr; MAX_MAPPINGS],
    ever_written_len: usize,
    /// Physical frames currently pinned for hardware DMA (`DmaMap`), preventing reclamation.
    dma_pinned: [PhysAddr; MAX_MAPPINGS],
    dma_pinned_len: usize,
}

impl<const MAX_MAPPINGS: usize> fmt::Debug for FrameMappingTracker<MAX_MAPPINGS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameMappingTracker")
            .field("max_mappings", &MAX_MAPPINGS)
            .field("count", &self.len)
            .field("ever_written_count", &self.ever_written_len)
            .field("dma_pinned_count", &self.dma_pinned_len)
            .finish_non_exhaustive()
    }
}

impl<const MAX_MAPPINGS: usize> Default for FrameMappingTracker<MAX_MAPPINGS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_MAPPINGS: usize> FrameMappingTracker<MAX_MAPPINGS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [FrameMapping::EMPTY; MAX_MAPPINGS],
            len: 0,
            ever_written: [PhysAddr::new(0); MAX_MAPPINGS],
            ever_written_len: 0,
            dma_pinned: [PhysAddr::new(0); MAX_MAPPINGS],
            dma_pinned_len: 0,
        }
    }

    /// Record that `phys` has been mapped writable (enforcing W^X across time).
    #[inline]
    pub fn mark_ever_written(&mut self, phys: PhysAddr) {
        if self.was_ever_written(phys) {
            return;
        }
        if self.ever_written_len < MAX_MAPPINGS {
            self.ever_written[self.ever_written_len] = phys;
            self.ever_written_len += 1;
        }
    }

    /// Return `true` if `phys` has been mapped writable since its last zero-and-reclaim.
    #[inline]
    #[must_use]
    pub fn was_ever_written(&self, phys: PhysAddr) -> bool {
        let mut i = 0;
        while i < self.ever_written_len {
            if self.ever_written[i] == phys {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Clear `phys` from the `ever_written` history (call ONLY after zeroing and reclaiming the frame).
    #[inline]
    pub fn clear_ever_written(&mut self, phys: PhysAddr) {
        let mut i = 0;
        while i < self.ever_written_len {
            if self.ever_written[i] == phys {
                self.ever_written_len -= 1;
                self.ever_written[i] = self.ever_written[self.ever_written_len];
                return;
            }
            i += 1;
        }
    }

    /// Pin `phys` for active DMA (`DmaMap`), preventing physical frame reclamation while pinned.
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if the DMA-pin table is at capacity (`MAX_MAPPINGS`).
    #[inline]
    pub fn pin_dma(&mut self, phys: PhysAddr) -> Result<(), SysError> {
        if self.is_dma_pinned(phys) {
            return Ok(());
        }
        if self.dma_pinned_len >= MAX_MAPPINGS {
            return Err(SysError::OutOfMemory);
        }
        self.dma_pinned[self.dma_pinned_len] = phys;
        self.dma_pinned_len += 1;
        Ok(())
    }

    /// Unpin `phys` from DMA (`DmaUnmap`).
    #[inline]
    pub fn unpin_dma(&mut self, phys: PhysAddr) -> bool {
        let mut i = 0;
        while i < self.dma_pinned_len {
            if self.dma_pinned[i] == phys {
                self.dma_pinned_len -= 1;
                self.dma_pinned[i] = self.dma_pinned[self.dma_pinned_len];
                return true;
            }
            i += 1;
        }
        false
    }

    /// Return `true` if `phys` is currently pinned for hardware DMA.
    #[inline]
    #[must_use]
    pub fn is_dma_pinned(&self, phys: PhysAddr) -> bool {
        let mut i = 0;
        while i < self.dma_pinned_len {
            if self.dma_pinned[i] == phys {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Record a new `(vspace_root, virt) -> phys` mapping in O(1) (defaulting to non-W/non-X flags).
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if the reverse-mapping table is full.
    #[inline]
    pub fn record(
        &mut self,
        vspace_root: PhysAddr,
        virt: VirtAddr,
        phys: PhysAddr,
    ) -> Result<(), SysError> {
        self.record_with_access(vspace_root, virt, phys, PageAccess::ReadOnly)
    }

    /// Record a new `(vspace_root, virt) -> phys` mapping with a compile-time W^X [`PageAccess`] mode.
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if the reverse-mapping table is full.
    #[inline]
    pub fn record_with_access(
        &mut self,
        vspace_root: PhysAddr,
        virt: VirtAddr,
        phys: PhysAddr,
        access: PageAccess,
    ) -> Result<(), SysError> {
        let (writable, executable) = match access {
            PageAccess::ReadOnly => (false, false),
            PageAccess::ReadWrite => (true, false),
            PageAccess::ReadExecute => (false, true),
        };
        self.record_with_flags(vspace_root, virt, phys, writable, executable)
    }

    /// Record a new `(vspace_root, virt) -> phys` mapping with explicit W/X permission flags.
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if both `writable` and `executable` are `true`.
    /// - [`SysError::OutOfMemory`] if the reverse-mapping table is full.
    #[inline]
    pub fn record_with_flags(
        &mut self,
        vspace_root: PhysAddr,
        virt: VirtAddr,
        phys: PhysAddr,
        writable: bool,
        executable: bool,
    ) -> Result<(), SysError> {
        if writable && executable {
            return Err(SysError::InvalidArgument);
        }
        if self.len >= MAX_MAPPINGS {
            return Err(SysError::OutOfMemory);
        }
        self.entries[self.len] = FrameMapping {
            vspace_root,
            virt,
            phys,
            writable,
            executable,
        };
        self.len += 1;
        if writable {
            self.mark_ever_written(phys);
        }
        Ok(())
    }

    /// Return `true` if mapping `phys` with `access` would violate system-wide W^X anti-aliasing.
    #[inline]
    #[must_use]
    pub fn conflicts_wx_access(&self, phys: PhysAddr, access: PageAccess) -> bool {
        match access {
            PageAccess::ReadOnly => false,
            PageAccess::ReadWrite => self.conflicts_wx(phys, true, false),
            PageAccess::ReadExecute => self.conflicts_wx(phys, false, true),
        }
    }

    /// Return `true` if mapping `phys` with `(writable, executable)` would violate system-wide
    /// W^X anti-aliasing against an existing mapping OR a write-then-unmap-then-execute sequence.
    #[inline]
    #[must_use]
    pub fn conflicts_wx(&self, phys: PhysAddr, writable: bool, executable: bool) -> bool {
        if !writable && !executable {
            return false;
        }
        if executable && self.was_ever_written(phys) {
            return true;
        }
        let mut i = 0;
        while i < self.len {
            let m = self.entries[i];
            if m.phys == phys && ((writable && m.executable) || (executable && m.writable)) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Drain up to `out.len()` mappings belonging to `vspace_root` into `out` (used on protection-domain teardown).
    #[inline]
    pub fn drain_for_vspace(
        &mut self,
        vspace_root: PhysAddr,
        out: &mut [Option<FrameMapping>],
    ) -> usize {
        if self.len == 0 || out.is_empty() {
            return 0;
        }
        let mut n = 0usize;
        let mut i = 0usize;
        while i < self.len && n < out.len() {
            if self.entries[i].vspace_root == vspace_root {
                out[n] = Some(self.entries[i]);
                n += 1;
                self.len -= 1;
                self.entries[i] = self.entries[self.len];
            } else {
                i += 1;
            }
        }
        n
    }

    /// Remove a specific `(vspace_root, virt)` mapping entry (e.g., on `UnmapPage`) via swap-remove.
    #[inline]
    pub fn remove(&mut self, vspace_root: PhysAddr, virt: VirtAddr) -> Option<PhysAddr> {
        let mut i = 0;
        while i < self.len {
            let m = self.entries[i];
            if m.vspace_root == vspace_root && m.virt == virt {
                self.len -= 1;
                self.entries[i] = self.entries[self.len];
                return Some(m.phys);
            }
            i += 1;
        }
        None
    }

    /// Drain up to `out.len()` mappings referencing `phys` into `out` (returns count written), used on `CapRevoke`.
    #[inline]
    pub fn drain_for_phys(&mut self, phys: PhysAddr, out: &mut [Option<FrameMapping>]) -> usize {
        if self.len == 0 || out.is_empty() {
            return 0;
        }
        let mut n = 0usize;
        let mut i = 0usize;
        while i < self.len && n < out.len() {
            if self.entries[i].phys == phys {
                out[n] = Some(self.entries[i]);
                n += 1;
                self.len -= 1;
                self.entries[i] = self.entries[self.len];
            } else {
                i += 1;
            }
        }
        n
    }

    /// Return `true` if any active tracked mapping references `phys`.
    #[inline]
    #[must_use]
    pub fn has_mapping_for_phys(&self, phys: PhysAddr) -> bool {
        let mut i = 0;
        while i < self.len {
            if self.entries[i].phys == phys {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Count active tracked mappings in O(1).
    #[inline]
    #[must_use]
    pub const fn count(&self) -> usize {
        self.len
    }
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

    #[test]
    fn frame_reclamation_reuses_freed_frames_and_carves_2m_superpages() {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x10_0000, PAGE_SIZE * 2));

        let f0 = inv.retype_frame().unwrap();
        let f0_addr = f0.start_addr();
        let f1 = inv.retype_frame().unwrap();
        assert_eq!(inv.retype_frame(), Err(SysError::OutOfMemory));
        assert_eq!(inv.remaining_bytes(), 0);

        // Reclaim f0 and verify O(1) LIFO reuse and updated remaining_bytes.
        assert!(inv.reclaim_frame(f0));
        assert_eq!(inv.reclaimed_count(), 1);
        assert_eq!(inv.remaining_bytes(), PAGE_SIZE);
        let reused = inv.retype_frame().unwrap();
        assert_eq!(reused.start_addr(), f0_addr);
        assert_eq!(inv.reclaimed_count(), 0);
        let _ = f1;

        // Carve a 2 MiB superpage from an unaligned region and verify padding frames are reclaimed.
        let mut inv2 = UntypedInventory::new();
        assert!(inv2.push_raw_region(0x20_0000 - PAGE_SIZE * 3, HUGE_PAGE_SIZE_2M + PAGE_SIZE * 3));
        let huge = inv2.retype_frame_2m().unwrap();
        assert_eq!(huge.start_addr().raw(), 0x20_0000);
        assert_eq!(inv2.reclaimed_count(), 3);
        let pad = inv2.retype_frame().unwrap();
        assert_eq!(pad.start_addr().raw(), 0x20_0000 - PAGE_SIZE);
    }

    #[test]
    fn frame_mapping_tracker_records_removes_and_drains_for_phys() {
        let mut tracker = FrameMappingTracker::<8>::new();
        let vs0 = PhysAddr::new(0x10_0000);
        let vs1 = PhysAddr::new(0x20_0000);
        let va0 = VirtAddr::new_page_aligned(0x40_0000).unwrap();
        let va1 = VirtAddr::new_page_aligned(0x50_0000).unwrap();
        let p0 = PhysAddr::new(0x8000_0000);
        let p1 = PhysAddr::new(0x8000_1000);

        tracker.record(vs0, va0, p0).unwrap();
        tracker.record(vs1, va1, p0).unwrap();
        tracker.record(vs0, va1, p1).unwrap();
        assert_eq!(tracker.count(), 3);

        let mut drained = [None; 4];
        let n = tracker.drain_for_phys(p0, &mut drained);
        assert_eq!(n, 2);
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.remove(vs0, va1), Some(p1));
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn untyped_region_overflow_and_unaligned_boundaries() {
        assert_eq!(UntypedRegion::from_raw(0, 0), None);
        assert_eq!(UntypedRegion::from_raw(0x100, PAGE_SIZE - 1), None);
        assert_eq!(UntypedRegion::from_raw(u64::MAX - 10, 100), None);

        // Manually constructed unaligned UntypedRegion must reject alignment without advancing watermark.
        let mut bad_align = UntypedRegion {
            base: 0x1001,
            len: PAGE_SIZE * 2,
            watermark: 0,
        };
        assert_eq!(bad_align.retype_frame(), Err(SysError::InvalidArgument));
        assert_eq!(bad_align.watermark, 0);

        // Manually constructed overflowing UntypedRegion must fail cleanly with OutOfMemory.
        let mut overflow = UntypedRegion {
            base: u64::MAX - PAGE_SIZE + 1,
            len: PAGE_SIZE * 4,
            watermark: PAGE_SIZE,
        };
        assert_eq!(overflow.retype_frame(), Err(SysError::OutOfMemory));
    }

    #[test]
    fn untyped_inventory_dedup_reclaim_capacity_and_2m_overflow() {
        let mut inv = UntypedInventory::new();
        for i in 0..MAX_UNTYPED_REGIONS {
            assert!(inv.push_raw_region((i as u64 + 1) * 0x10_0000, PAGE_SIZE));
        }
        assert!(!inv.push_raw_region(0x8000_0000, PAGE_SIZE));
        assert_eq!(inv.region_remaining(MAX_UNTYPED_REGIONS), None);
        assert_eq!(
            inv.retype_frame_in(MAX_UNTYPED_REGIONS),
            Err(SysError::InvalidArgument)
        );

        // Duplicate reclaim_frame must NOT push the same physical address twice.
        let f_dup1 = PhysFrame::from_aligned(PhysAddr::new(0x9000_0000)).unwrap();
        let f_dup2 = PhysFrame::from_aligned(PhysAddr::new(0x9000_0000)).unwrap();
        assert!(inv.reclaim_frame(f_dup1));
        assert_eq!(inv.reclaimed_count(), 1);
        assert!(inv.reclaim_frame(f_dup2));
        assert_eq!(inv.reclaimed_count(), 1);

        // Fill remaining reclaimed cache up to MAX_RECLAIMED_FRAMES; 65th distinct frame returns false.
        for i in 1..MAX_RECLAIMED_FRAMES {
            let f = PhysFrame::from_aligned(PhysAddr::new(0x9000_0000 + (i as u64) * PAGE_SIZE))
                .unwrap();
            assert!(inv.reclaim_frame(f));
        }
        let overflow_f = PhysFrame::from_aligned(PhysAddr::new(0xA000_0000)).unwrap();
        assert!(!inv.reclaim_frame(overflow_f));

        // retype_frame_2m near u64::MAX must return OutOfMemory without wrapping.
        let mut high = UntypedInventory::new();
        assert!(high.push_raw_region(
            u64::MAX - HUGE_PAGE_SIZE_2M + 1,
            HUGE_PAGE_SIZE_2M - PAGE_SIZE
        ));
        assert_eq!(high.retype_frame_2m(), Err(SysError::OutOfMemory));
    }

    #[test]
    fn frame_mapping_tracker_zero_cap_full_and_multi_batch_drain() {
        let mut zero = FrameMappingTracker::<0>::new();
        let vs = PhysAddr::new(0x10_0000);
        let va = VirtAddr::new_page_aligned(0x40_0000).unwrap();
        let phys = PhysAddr::new(0x8000_0000);
        assert_eq!(zero.record(vs, va, phys), Err(SysError::OutOfMemory));
        assert_eq!(zero.count(), 0);
        assert_eq!(zero.remove(vs, va), None);

        // Record 12 mappings to the same physical frame and drain in batches of 4 until n == 0.
        let mut tracker = FrameMappingTracker::<16>::new();
        for i in 0..12u64 {
            let v = VirtAddr::new_page_aligned(0x40_0000 + i * PAGE_SIZE).unwrap();
            tracker.record(vs, v, phys).unwrap();
        }
        assert_eq!(tracker.count(), 12);
        // Empty output slice drains 0 without losing entries.
        assert_eq!(tracker.drain_for_phys(phys, &mut []), 0);
        assert_eq!(tracker.count(), 12);

        let mut total_drained = 0usize;
        let mut batch = [None; 4];
        loop {
            let n = tracker.drain_for_phys(phys, &mut batch);
            if n == 0 {
                break;
            }
            total_drained += n;
        }
        assert_eq!(total_drained, 12);
        assert_eq!(tracker.count(), 0);
    }

    #[test]
    fn virt_addr_and_phys_frame_canonical_boundaries() {
        assert!(VirtAddr::new_canonical(0x0000_7FFF_FFFF_FFFF).is_ok());
        assert_eq!(
            VirtAddr::new_canonical(0x0000_8000_0000_0000),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            VirtAddr::new_canonical(0xFFFF_7FFF_FFFF_FFFF),
            Err(SysError::InvalidArgument)
        );
        assert!(VirtAddr::new_canonical(0xFFFF_8000_0000_0000).is_ok());
        assert!(PhysFrame2M::from_aligned(PhysAddr::new(HUGE_PAGE_SIZE_2M)).is_ok());
        assert_eq!(
            PhysFrame2M::from_aligned(PhysAddr::new(PAGE_SIZE)),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn frame_mapping_tracker_has_mapping_for_phys_tracks_shared_mappings() {
        let mut tracker = FrameMappingTracker::<8>::new();
        let vs0 = PhysAddr::new(0x10_0000);
        let vs1 = PhysAddr::new(0x20_0000);
        let va0 = VirtAddr::new_page_aligned(0x40_0000).unwrap();
        let va1 = VirtAddr::new_page_aligned(0x40_1000).unwrap();
        let phys_a = PhysAddr::new(0x8000_0000);
        let phys_b = PhysAddr::new(0x8000_1000);

        assert!(!tracker.has_mapping_for_phys(phys_a));
        tracker.record(vs0, va0, phys_a).unwrap();
        tracker.record(vs1, va1, phys_a).unwrap();
        assert!(tracker.has_mapping_for_phys(phys_a));
        assert!(!tracker.has_mapping_for_phys(phys_b));

        assert_eq!(tracker.remove(vs0, va0), Some(phys_a));
        assert!(tracker.has_mapping_for_phys(phys_a));

        assert_eq!(tracker.remove(vs1, va1), Some(phys_a));
        assert!(!tracker.has_mapping_for_phys(phys_a));
    }

    #[test]
    fn untyped_largest_region_index_picks_biggest_remaining() {
        let mut inv = UntypedInventory::new();
        assert_eq!(inv.largest_region_index(), None);
        assert!(inv.push_raw_region(0x10_0000, 4 * PAGE_SIZE));
        assert!(inv.push_raw_region(0x40_0000, 128 * PAGE_SIZE));
        assert!(inv.push_raw_region(0x80_0000, 16 * PAGE_SIZE));
        assert_eq!(inv.largest_region_index(), Some(1));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove W^X exclusivity: `PageFlags::new_wx` NEVER produces a simultaneously writable
    /// and executable mapping for any symbolic input combination.
    #[kani::proof]
    fn page_flags_wx_exclusivity() {
        let writable: bool = kani::any();
        let executable: bool = kani::any();
        let user: bool = kani::any();
        let device: bool = kani::any();

        match PageFlags::new_wx(writable, executable, user, device) {
            Ok(flags) => {
                assert!(!(flags.writable && flags.executable));
                assert_eq!(flags.writable, writable);
                assert_eq!(flags.executable, executable);
            }
            Err(SysError::InvalidArgument) => {
                assert!(writable && executable);
            }
            Err(_) => unreachable!(),
        }
    }

    /// Prove `UntypedInventory::retype_frame` never yields overlapping frames or out-of-bounds
    /// addresses for any valid page-aligned physical region.
    #[kani::proof]
    #[kani::unwind(4)]
    fn untyped_retype_frames_disjoint_and_in_bounds() {
        let base_pages: u64 = kani::any();
        let len_pages: u64 = kani::any();
        kani::assume(base_pages > 0 && base_pages < (1u64 << 32));
        kani::assume((2..=64).contains(&len_pages));

        let base = base_pages * PAGE_SIZE;
        let len = len_pages * PAGE_SIZE;
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(base, len));

        let f1 = inv.retype_frame().unwrap();
        let f2 = inv.retype_frame().unwrap();
        assert_ne!(f1.start_addr(), f2.start_addr());
        assert!(f1.start_addr().raw() >= base && f1.start_addr().raw() + PAGE_SIZE <= base + len);
        assert!(f2.start_addr().raw() >= base && f2.start_addr().raw() + PAGE_SIZE <= base + len);
    }
}

#[cfg(test)]
mod audit_memory_tests {
    use super::*;

    #[test]
    fn wx_rejects_write_then_unmap_then_execute_until_reclaimed() {
        let mut tracker = FrameMappingTracker::<16>::new();
        let root = PhysAddr::new(0x10_0000);
        let va1 = VirtAddr::new_page_aligned(0x4000_0000).unwrap();
        let pa = PhysAddr::new(0x20_0000);

        tracker
            .record_with_flags(root, va1, pa, true, false)
            .unwrap();
        assert_eq!(tracker.remove(root, va1), Some(pa));
        // Even after unmapping the writable view, remapping the same frame EXEC must be denied.
        assert!(tracker.conflicts_wx(pa, false, true));
        // Only after zero-and-reclaim clears `ever_written` may the frame be mapped EXEC.
        tracker.clear_ever_written(pa);
        assert!(!tracker.conflicts_wx(pa, false, true));
    }

    #[test]
    fn dma_pin_prevents_reclaim_until_unpinned() {
        let mut tracker = FrameMappingTracker::<16>::new();
        let pa = PhysAddr::new(0x30_0000);
        assert!(!tracker.is_dma_pinned(pa));
        tracker.pin_dma(pa).unwrap();
        assert!(tracker.is_dma_pinned(pa));
        assert!(tracker.unpin_dma(pa));
        assert!(!tracker.is_dma_pinned(pa));
    }

    #[test]
    fn page_aligned_phys_addr_enforces_alignment_and_conversions() {
        assert_eq!(PageAlignedPhysAddr::ZERO.raw(), 0);
        assert_eq!(PageAlignedPhysAddr::default(), PageAlignedPhysAddr::ZERO);

        let aligned = PageAlignedPhysAddr::new(0x20_0000).expect("aligned address");
        assert_eq!(aligned.raw(), 0x20_0000);
        assert_eq!(aligned.as_phys(), PhysAddr::new(0x20_0000));
        assert_eq!(PhysAddr::from(aligned), PhysAddr::new(0x20_0000));
        assert_eq!(
            PageAlignedPhysAddr::try_from(PhysAddr::new(0x20_0000)),
            Ok(aligned)
        );
        assert_eq!(
            PageAlignedPhysAddr::new(0x20_0001),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            PageAlignedPhysAddr::try_from(PhysAddr::new(0x20_0fff)),
            Err(SysError::InvalidArgument)
        );

        let frame = PhysFrame::from_page_aligned(aligned);
        assert_eq!(frame.aligned_addr(), aligned);
        assert_eq!(frame.start_addr(), PhysAddr::new(0x20_0000));
    }

    #[test]
    fn page_flags_new_enforces_typed_wx_and_cache_policies() {
        let user_rx = PageFlags::new(
            PageAccess::ReadExecute,
            PagePrivilege::User,
            PageCachePolicy::NormalCacheable,
        );
        assert!(!user_rx.writable);
        assert!(user_rx.executable);
        assert!(user_rx.user);
        assert!(!user_rx.no_cache);
        assert!(!user_rx.dma_nc);
        assert_eq!(user_rx.access(), PageAccess::ReadExecute);
        assert_eq!(user_rx.privilege(), PagePrivilege::User);
        assert_eq!(user_rx.cache_policy(), PageCachePolicy::NormalCacheable);

        let mmio_rw = PageFlags::new(
            PageAccess::ReadWrite,
            PagePrivilege::User,
            PageCachePolicy::DeviceNoCache,
        );
        assert!(mmio_rw.writable);
        assert!(!mmio_rw.executable);
        assert!(mmio_rw.no_cache);
        assert!(!mmio_rw.dma_nc);
        assert_eq!(mmio_rw.access(), PageAccess::ReadWrite);
        assert_eq!(mmio_rw.cache_policy(), PageCachePolicy::DeviceNoCache);

        let dma_rw = PageFlags::new(
            PageAccess::ReadWrite,
            PagePrivilege::Kernel,
            PageCachePolicy::NormalNonCacheable,
        );
        assert!(!dma_rw.user);
        assert!(!dma_rw.no_cache);
        assert!(dma_rw.dma_nc);
        assert_eq!(dma_rw.privilege(), PagePrivilege::Kernel);
        assert_eq!(dma_rw.cache_policy(), PageCachePolicy::NormalNonCacheable);
    }

    #[test]
    fn frame_mapping_tracker_debug_and_typed_access_api() {
        use core::fmt::Write as _;

        struct Buf([u8; 160], usize);
        impl core::fmt::Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let n = bytes.len().min(self.0.len() - self.1);
                self.0[self.1..self.1 + n].copy_from_slice(&bytes[..n]);
                self.1 += n;
                Ok(())
            }
        }

        let mut tracker = FrameMappingTracker::<8>::new();
        let root = PhysAddr::new(0x10_0000);
        let va = VirtAddr::new_page_aligned(0x40_0000).expect("valid va");
        let pa = PhysAddr::new(0x80_0000);

        tracker
            .record_with_access(root, va, pa, PageAccess::ReadWrite)
            .expect("record rw");
        assert!(tracker.conflicts_wx_access(pa, PageAccess::ReadExecute));
        assert!(!tracker.conflicts_wx_access(pa, PageAccess::ReadOnly));

        let mut buf = Buf([0; 160], 0);
        write!(&mut buf, "{tracker:?}").expect("format debug");
        let rendered = core::str::from_utf8(&buf.0[..buf.1]).expect("utf8");
        assert!(rendered.contains("FrameMappingTracker"));
        assert!(rendered.contains("count: 1"));
        assert!(rendered.contains(".."));

        // Verify Display and From<Self> for u64 on PhysAddr and VirtAddr.
        assert_eq!(u64::from(pa), 0x80_0000);
        assert_eq!(u64::from(va), 0x40_0000);
        assert_eq!(PhysAddr::default().raw(), 0);
        assert_eq!(VirtAddr::default().raw(), 0);
        assert_eq!(UntypedRegion::default(), UntypedRegion::EMPTY);
        assert!(!CpuSecurityFeatures::default().pxn);
    }
}
