//! Minimal audited 64-bit `ARMv8` 4-level 4 KiB paging (`TTBR1_EL1` kernel & `TTBR0_EL1` user).

use core::arch::asm;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use newos_abi::SysError;
use newos_kernel_core::memory::{
    HUGE_PAGE_MASK_2M, PAGE_SIZE, PageAccess, PageCachePolicy, PageFlags, PagePrivilege, PhysAddr,
    PhysFrame, PhysFrame2M, UntypedInventory, VSpaceMapper, VirtAddr,
};

/// Physical backing kind of a newly unmapped 4 KiB leaf PTE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmappedFrameKind {
    /// Normal RAM frame eligible for zeroing and untyped reclamation.
    Ram,
    /// Device MMIO frame (`MmioMap`) that must never be zeroed or reclaimed as RAM.
    DeviceMmio,
}

/// Kind of physical frame yielded during full user `VSpace` teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimedFrameKind {
    /// Non-device 4 KiB user leaf RAM frame.
    LeafRam,
    /// Intermediate L3/L2/L1 or root L0 page-table frame (already zeroed).
    PageTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafGranule {
    Page4K,
    Block2M,
}

const PAGE_SIZE_USIZE: usize = 4096;
const _: () = assert!(PAGE_SIZE_USIZE as u64 == PAGE_SIZE);

const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE_OR_PAGE: u64 = 1 << 1;
const DESC_AF: u64 = 1 << 10; // Access Flag
const DESC_NG: u64 = 1 << 11; // Non-Global (ASID-tagged EL0 entries)
const DESC_SH_INNER: u64 = 0b11 << 8; // Inner Shareable
const DESC_AP_EL0_RW: u64 = 0b01 << 6;
const DESC_AP_EL1_RO: u64 = 0b10 << 6;
const DESC_AP_EL0_RO: u64 = 0b11 << 6;
const DESC_PXN: u64 = 1 << 53; // Privileged Execute Never (SMEP equivalent)
const DESC_UXN: u64 = 1 << 54; // Unprivileged Execute Never (NX for EL0)
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const DESC_2M_ADDR_MASK: u64 = 0x0000_FFFF_FFE0_0000;

static CACHED_DEVICE_MAIR_IDX: AtomicU8 = AtomicU8::new(u8::MAX);
static CACHED_NORMAL_NC_MAIR_IDX: AtomicU8 = AtomicU8::new(u8::MAX);
static DCACHE_LINE_BYTES: AtomicU64 = AtomicU64::new(64);

/// Record the probed architectural D-cache minimum line size (`CTR_EL0.DminLine`, 64 B on `Cortex-A76`).
pub fn set_dcache_line_bytes(bytes: u64) {
    if bytes.is_power_of_two() && (16..=256).contains(&bytes) {
        DCACHE_LINE_BYTES.store(bytes, Ordering::Release);
    }
}

#[inline]
fn device_mair_index() -> u8 {
    let cached = CACHED_DEVICE_MAIR_IDX.load(Ordering::Relaxed);
    if cached != u8::MAX {
        return cached;
    }
    let mair: u64;
    // SAFETY: Reading `MAIR_EL1` in EL1 inspects Limine's immutable boot memory attributes.
    unsafe {
        asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack, preserves_flags));
    }
    let mut found = 0u8;
    let mut fallback = None;
    for idx in 0..8u8 {
        let attr = u8::try_from((mair >> (u64::from(idx) * 8)) & 0xFF).unwrap_or(0);
        if attr == 0x00 {
            found = idx;
            fallback = None;
            break;
        }
        if attr == 0x04 && fallback.is_none() {
            fallback = Some(idx);
        }
    }
    if let Some(fb) = fallback {
        found = fb;
    }
    CACHED_DEVICE_MAIR_IDX.store(found, Ordering::Relaxed);
    found
}

#[inline]
fn normal_nc_mair_index() -> u8 {
    let cached = CACHED_NORMAL_NC_MAIR_IDX.load(Ordering::Relaxed);
    if cached != u8::MAX {
        return cached;
    }
    let mair: u64;
    // SAFETY: Reading `MAIR_EL1` in EL1 inspects Limine's boot memory attributes.
    unsafe {
        asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack, preserves_flags));
    }
    // Look for Normal Outer+Inner Non-Cacheable (`0x44`) in `MAIR_EL1`.
    for idx in 0..8u8 {
        let attr = u8::try_from((mair >> (u64::from(idx) * 8)) & 0xFF).unwrap_or(0);
        if attr == 0x44 {
            CACHED_NORMAL_NC_MAIR_IDX.store(idx, Ordering::Relaxed);
            return idx;
        }
    }
    // Fallback to Device-nGnRnE index if bootloader did not populate a Normal-NC slot.
    let fb = device_mair_index();
    CACHED_NORMAL_NC_MAIR_IDX.store(fb, Ordering::Relaxed);
    fb
}

#[inline]
fn read_ttbr1_phys() -> u64 {
    let ttbr1: u64;
    // SAFETY: Reading `TTBR1_EL1` in EL1 returns the active higher-half L0 page-table base.
    unsafe {
        asm!("mrs {}, ttbr1_el1", out(reg) ttbr1, options(nomem, nostack, preserves_flags));
    }
    ttbr1 & DESC_ADDR_MASK
}

#[inline]
fn tlbi_va(virt: VirtAddr) {
    let page = (virt.raw() >> 12) & 0x0000_0FFF_FFFF_FFFF;
    // SAFETY: Invalidates TLB entries for `virt` across Inner Shareable domain.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vaae1is, {page}",
            "dsb ish",
            "isb",
            page = in(reg) page,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
fn tlbi_va_asid(virt: VirtAddr, asid: u16) {
    let val = (u64::from(asid) << 48) | ((virt.raw() >> 12) & 0x0000_0FFF_FFFF_FFFF);
    // SAFETY: Invalidates TLB entries for `(virt, asid)` across the Inner Shareable domain.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vae1is, {val}",
            "dsb ish",
            "isb",
            val = in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

/// Invalidate all TLB entries tagged with `asid` across the Inner Shareable domain.
#[inline]
pub fn tlbi_asid(asid: u16) {
    let val = u64::from(asid) << 48;
    // SAFETY: `tlbi aside1is` flushes all EL0/EL1 non-global TLB entries for `asid`.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi aside1is, {val}",
            "dsb ish",
            "isb",
            val = in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

/// Ensure `TTBR0_EL1` supplies the active ASID (`TCR_EL1.A1 == 0`), enable 16-bit ASIDs
/// (`TCR_EL1.AS = 1`) when advertised by `ID_AA64MMFR0_EL1.ASIDBits`, and flush stale boot TLBs.
pub fn ensure_ttbr0_asid_enabled() {
    // SAFETY: Configuring `TCR_EL1.A1 = 0`, enabling 16-bit ASIDs when supported by hardware,
    // ensuring `TCR_EL1.IPS` covers >=40-bit PA (required for RPi5 16 GB RAM + BCM2712/RP1 MMIO),
    // and executing a one-time EL1 TLB invalidation before entering EL0 guarantees
    // `TTBR0_EL1[63:48]` tags all `DESC_NG` user mappings.
    unsafe {
        let mmfr0: u64;
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack, preserves_flags));
        let pa_range = mmfr0 & 0xF;
        let supports_16bit_asid = ((mmfr0 >> 4) & 0xF) == 0b0010;

        let mut tcr: u64;
        asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack, preserves_flags));
        let mut new_tcr = tcr & !(1u64 << 22); // A1 = 0 (TTBR0_EL1 defines ASID)
        if supports_16bit_asid {
            new_tcr |= 1u64 << 36; // AS = 1 (16-bit ASID)
        }
        // Ensure `TCR_EL1.IPS` (bits 34:32) is at least 40-bit (0b010) when hardware supports it
        // (Cortex-A76 BCM2712 advertises PARange >= 40-bit; 16 GB RAM + 0x1F_xxxx_xxxx RP1 MMIO need >= 40-bit).
        let cur_ips = (new_tcr >> 32) & 0x7;
        let target_ips = pa_range.min(5); // cap at 48-bit (0b101)
        if target_ips >= 2 && cur_ips < target_ips {
            new_tcr = (new_tcr & !(0x7u64 << 32)) | (target_ips << 32);
        }
        if new_tcr != tcr {
            tcr = new_tcr;
            asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack, preserves_flags));
            asm!("isb", options(nostack, preserves_flags));
        }
        asm!(
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags),
        );
    }
}

/// 4-level 4 KiB `ARMv8` `VSpace` (kernel `TTBR1_EL1` or isolated EL0 `TTBR0_EL1`).
#[derive(Debug)]
pub struct Aarch64VSpace {
    l0_phys: u64,
    hhdm_offset: u64,
}

impl Aarch64VSpace {
    #[must_use]
    pub fn from_current_ttbr1(hhdm_offset: u64) -> Self {
        Self {
            l0_phys: read_ttbr1_phys(),
            hhdm_offset,
        }
    }

    /// Wrap an existing L0 page-table root physical address (e.g. active `TTBR0_EL1`).
    #[must_use]
    pub const fn from_root_phys(l0_phys: u64, hhdm_offset: u64) -> Self {
        Self {
            l0_phys: l0_phys & DESC_ADDR_MASK,
            hhdm_offset,
        }
    }

    /// Allocate a brand-new, empty EL0 `TTBR0_EL1` root L0 table (hardware-isolated from `TTBR1_EL1`).
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if `untyped` cannot supply a 4 KiB physical frame.
    pub fn new_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self, SysError> {
        let l0_frame = untyped.retype_frame()?;
        self.zero_frame(&l0_frame);
        Ok(Self {
            l0_phys: l0_frame.start_addr().raw(),
            hhdm_offset: self.hhdm_offset,
        })
    }

    #[inline]
    const fn table_ptr(&self, phys: u64) -> *mut u64 {
        self.hhdm_offset.wrapping_add(phys) as *mut u64
    }

    #[inline]
    fn read_desc(&self, table_phys: u64, index: usize) -> Result<u64, SysError> {
        if index >= 512 || (table_phys & 0xFFF) != 0 {
            return Err(SysError::InvalidArgument);
        }
        // SAFETY: `table_phys` is 4 KiB-aligned, mapped via HHDM, and `index < 512` keeps
        // the 8-byte descriptor within the 4 KiB translation table page.
        Ok(unsafe { read_volatile(self.table_ptr(table_phys).add(index)) })
    }

    #[inline]
    fn write_desc(&self, table_phys: u64, index: usize, value: u64) -> Result<(), SysError> {
        if index >= 512 || (table_phys & 0xFFF) != 0 {
            return Err(SysError::InvalidArgument);
        }
        // SAFETY: `table_phys` is 4 KiB-aligned, mapped via HHDM, and `index < 512` keeps
        // the 8-byte descriptor within the 4 KiB translation table page.
        unsafe { write_volatile(self.table_ptr(table_phys).add(index), value) };
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)] // Masked to 9 bits (`0..512`), always fits in `usize`.
    const fn indices(virt: VirtAddr) -> [usize; 4] {
        let v = virt.raw();
        [
            ((v >> 39) & 0x1FF) as usize, // L0
            ((v >> 30) & 0x1FF) as usize, // L1
            ((v >> 21) & 0x1FF) as usize, // L2
            ((v >> 12) & 0x1FF) as usize, // L3
        ]
    }

    #[allow(clippy::needless_pass_by_ref_mut)] // Exclusive `&mut self` enforces single-writer access to raw page tables.
    fn unmap_4k_leaf(
        &mut self,
        virt: VirtAddr,
        asid: Option<u16>,
    ) -> Result<(PhysFrame, UnmappedFrameKind, [u64; 3], [usize; 3]), SysError> {
        let [i0, i1, i2, i3] = Self::indices(virt);
        let l1 = self
            .next_table_existing(self.l0_phys, i0)
            .ok_or(SysError::InvalidArgument)?;
        let l2 = self
            .next_table_existing(l1, i1)
            .ok_or(SysError::InvalidArgument)?;
        let l3 = self
            .next_table_existing(l2, i2)
            .ok_or(SysError::InvalidArgument)?;

        let pte = self.read_desc(l3, i3)?;
        if (pte & DESC_VALID) == 0 {
            return Err(SysError::InvalidArgument);
        }

        let dev_idx = u64::from(device_mair_index());
        let attr_idx = (pte >> 2) & 0x7;
        let kind = if attr_idx == dev_idx && dev_idx != 0 {
            UnmappedFrameKind::DeviceMmio
        } else {
            UnmappedFrameKind::Ram
        };

        self.write_desc(l3, i3, 0)?;
        if let Some(a) = asid {
            tlbi_va_asid(virt, a);
        } else {
            tlbi_va(virt);
        }
        let frame = PhysFrame::from_aligned(PhysAddr::new(pte & DESC_ADDR_MASK))?;
        Ok((frame, kind, [l1, l2, l3], [i0, i1, i2]))
    }

    #[allow(clippy::needless_pass_by_ref_mut)] // Exclusive `&mut self` enforces single-writer access to raw page tables.
    fn try_reclaim_empty_table(
        &mut self,
        parent_phys: u64,
        parent_idx: usize,
        child_phys: u64,
        untyped: &mut UntypedInventory,
    ) -> bool {
        if !self.is_table_empty(child_phys) {
            return false;
        }
        let _ = self.write_desc(parent_phys, parent_idx, 0);
        if let Ok(f) = PhysFrame::from_aligned(PhysAddr::new(child_phys)) {
            self.zero_frame(&f);
            let _ = untyped.reclaim_frame(f);
        }
        true
    }

    /// Unmap a 4 KiB page using targeted `tlbi vae1is` when `asid` is provided (or `tlbi vaae1is`
    /// otherwise), returning `(frame, kind)` so device MMIO pages (`MmioMap`) are never zeroed or
    /// reclaimed as RAM.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `virt` is not currently mapped as a valid 4 KiB leaf.
    pub fn unmap_4k_asid(
        &mut self,
        virt: VirtAddr,
        asid: Option<u16>,
    ) -> Result<(PhysFrame, UnmappedFrameKind), SysError> {
        let (frame, kind, _, _) = self.unmap_4k_leaf(virt, asid)?;
        Ok((frame, kind))
    }

    /// Mark a page-aligned EL1 virtual address range (`start_va..end_va`) read-only + NX
    /// in this `VSpace` (used at early boot to lock `PT_GNU_RELRO` `.data.rel.ro` / `.got`).
    pub fn protect_ro_range(&mut self, start_va: u64, end_va: u64) {
        let mut cur = start_va & !0xFFF;
        let end = (end_va.saturating_add(0xFFF)) & !0xFFF;
        while cur < end {
            if let Ok(va) = VirtAddr::new_page_aligned(cur) {
                let [i0, i1, i2, i3] = Self::indices(va);
                if let Some(l1) = self.next_table_existing(self.l0_phys, i0)
                    && let Some(l2) = self.next_table_existing(l1, i1)
                    && let Some(l3) = self.next_table_existing(l2, i2)
                    && let Ok(pte) = self.read_desc(l3, i3)
                    && (pte & DESC_VALID) != 0
                {
                    let ro_pte = (pte & !(0b11 << 6)) | DESC_AP_EL1_RO | DESC_PXN | DESC_UXN;
                    let _ = self.write_desc(l3, i3, ro_pte);
                    tlbi_va(va);
                }
            }
            let Some(next) = cur.checked_add(PAGE_SIZE) else {
                break;
            };
            cur = next;
        }
    }

    /// Return `true` if all 512 entries in page-table `table_phys` have `DESC_VALID == 0`.
    fn is_table_empty(&self, table_phys: u64) -> bool {
        for i in 0..512usize {
            if let Ok(desc) = self.read_desc(table_phys, i)
                && (desc & DESC_VALID) != 0
            {
                return false;
            }
        }
        true
    }

    /// Unmap a 4 KiB page and prune/reclaim any intermediate L3/L2/L1 page-table pages that
    /// become completely empty (zero page-table memory leaks on `UnmapPage`).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `virt` is not currently mapped as a valid 4 KiB leaf.
    pub fn unmap_4k_asid_reclaim(
        &mut self,
        virt: VirtAddr,
        asid: Option<u16>,
        untyped: &mut UntypedInventory,
    ) -> Result<(PhysFrame, UnmappedFrameKind), SysError> {
        let (frame, kind, [l1, l2, l3], [i0, i1, i2]) = self.unmap_4k_leaf(virt, asid)?;
        if self.try_reclaim_empty_table(l2, i2, l3, untyped) {
            if self.try_reclaim_empty_table(l1, i1, l2, untyped) {
                let _ = self.try_reclaim_empty_table(self.l0_phys, i0, l1, untyped);
            }
            if let Some(a) = asid {
                tlbi_asid(a);
            }
        }
        Ok((frame, kind))
    }

    /// Walk the entire user-half (`L0[0..256]`) 4-level page-table hierarchy, clearing every
    /// entry and invoking `on_frame(frame, kind)` for every non-device 4 KiB leaf frame
    /// ([`ReclaimedFrameKind::LeafRam`]) and every L3/L2/L1/L0 page-table frame
    /// ([`ReclaimedFrameKind::PageTable`], already zeroed).
    ///
    /// Caller MUST ensure no CPU is actively executing with this `VSpace` loaded in `TTBR0_EL1`
    /// and MUST follow up with `tlbi_asid(asid)`.
    pub fn reclaim_all_user_frames(
        &mut self,
        mut on_frame: impl FnMut(PhysFrame, ReclaimedFrameKind),
    ) {
        let dev_idx = u64::from(device_mair_index());
        for i0 in 0..256usize {
            let Ok(l0_desc) = self.read_desc(self.l0_phys, i0) else {
                continue;
            };
            if (l0_desc & DESC_VALID) == 0 || (l0_desc & DESC_TABLE_OR_PAGE) == 0 {
                continue;
            }
            let l1_phys = l0_desc & DESC_ADDR_MASK;
            let _ = self.write_desc(self.l0_phys, i0, 0);

            for i1 in 0..512usize {
                let Ok(l1_desc) = self.read_desc(l1_phys, i1) else {
                    continue;
                };
                if (l1_desc & DESC_VALID) == 0 || (l1_desc & DESC_TABLE_OR_PAGE) == 0 {
                    continue;
                }
                let l2_phys = l1_desc & DESC_ADDR_MASK;
                let _ = self.write_desc(l1_phys, i1, 0);

                for i2 in 0..512usize {
                    let Ok(l2_desc) = self.read_desc(l2_phys, i2) else {
                        continue;
                    };
                    if (l2_desc & DESC_VALID) == 0 || (l2_desc & DESC_TABLE_OR_PAGE) == 0 {
                        continue;
                    }
                    let l3_phys = l2_desc & DESC_ADDR_MASK;
                    let _ = self.write_desc(l2_phys, i2, 0);

                    for i3 in 0..512usize {
                        let Ok(pte) = self.read_desc(l3_phys, i3) else {
                            continue;
                        };
                        if (pte & DESC_VALID) == 0 {
                            continue;
                        }
                        let _ = self.write_desc(l3_phys, i3, 0);
                        let attr_idx = (pte >> 2) & 0x7;
                        let is_device = attr_idx == dev_idx && dev_idx != 0;
                        if !is_device
                            && let Ok(frame) =
                                PhysFrame::from_aligned(PhysAddr::new(pte & DESC_ADDR_MASK))
                        {
                            on_frame(frame, ReclaimedFrameKind::LeafRam);
                        }
                    }

                    if let Ok(l3_fr) = PhysFrame::from_aligned(PhysAddr::new(l3_phys)) {
                        self.zero_frame(&l3_fr);
                        on_frame(l3_fr, ReclaimedFrameKind::PageTable);
                    }
                }

                if let Ok(l2_fr) = PhysFrame::from_aligned(PhysAddr::new(l2_phys)) {
                    self.zero_frame(&l2_fr);
                    on_frame(l2_fr, ReclaimedFrameKind::PageTable);
                }
            }

            if let Ok(l1_fr) = PhysFrame::from_aligned(PhysAddr::new(l1_phys)) {
                self.zero_frame(&l1_fr);
                on_frame(l1_fr, ReclaimedFrameKind::PageTable);
            }
        }

        if let Ok(l0_fr) = PhysFrame::from_aligned(PhysAddr::new(self.l0_phys)) {
            self.zero_frame(&l0_fr);
            on_frame(l0_fr, ReclaimedFrameKind::PageTable);
        }
    }

    fn next_table_or_create(
        &self,
        table_phys: u64,
        index: usize,
        untyped: &mut UntypedInventory,
    ) -> Result<u64, SysError> {
        let entry = self.read_desc(table_phys, index)?;

        if (entry & DESC_VALID) != 0 {
            if (entry & DESC_TABLE_OR_PAGE) == 0 {
                return Err(SysError::SlotOccupied);
            }
            return Ok(entry & DESC_ADDR_MASK);
        }

        let frame = untyped.retype_frame()?;
        self.zero_frame(&frame);
        let next_phys = frame.start_addr().raw() & DESC_ADDR_MASK;
        self.write_desc(
            table_phys,
            index,
            next_phys | DESC_VALID | DESC_TABLE_OR_PAGE,
        )?;
        Ok(next_phys)
    }

    fn encode_leaf_attrs(flags: PageFlags, granule: LeafGranule) -> u64 {
        let mut bits = DESC_VALID | DESC_AF | DESC_SH_INNER;
        match flags.cache_policy() {
            PageCachePolicy::NormalCacheable => {}
            PageCachePolicy::DeviceNoCache => {
                bits |= u64::from(device_mair_index()) << 2;
            }
            PageCachePolicy::NormalNonCacheable => {
                if granule == LeafGranule::Page4K {
                    bits |= u64::from(normal_nc_mair_index()) << 2;
                }
            }
        }

        let is_user = flags.privilege() == PagePrivilege::User;
        let is_writable = flags.access() == PageAccess::ReadWrite;
        match (is_user, is_writable) {
            (false, true) => {} // AP=00: EL1 RW (Global)
            (false, false) => bits |= DESC_AP_EL1_RO,
            (true, true) => bits |= DESC_AP_EL0_RW | DESC_NG,
            (true, false) => bits |= DESC_AP_EL0_RO | DESC_NG,
        }

        match (flags.access(), flags.privilege()) {
            (PageAccess::ReadExecute, PagePrivilege::User) => {
                // EL0 executable pages are NEVER executable by EL1 (hardware PXN)
                bits |= DESC_PXN;
            }
            (PageAccess::ReadExecute, PagePrivilege::Kernel) => {
                bits |= DESC_UXN;
            }
            (PageAccess::ReadOnly | PageAccess::ReadWrite, _) => {
                bits |= DESC_PXN | DESC_UXN;
            }
        }
        bits
    }

    fn decode_leaf_flags(desc: u64, dev_idx: u8) -> PageFlags {
        let ap = (desc >> 6) & 0b11;
        let privilege = if (ap & 0b01) != 0 {
            PagePrivilege::User
        } else {
            PagePrivilege::Kernel
        };
        let writable = (ap & 0b10) == 0;
        let executable = match privilege {
            PagePrivilege::User => (desc & DESC_UXN) == 0,
            PagePrivilege::Kernel => (desc & DESC_PXN) == 0,
        };
        let access = if writable {
            PageAccess::ReadWrite
        } else if executable {
            PageAccess::ReadExecute
        } else {
            PageAccess::ReadOnly
        };

        let attr_idx = (desc >> 2) & 0x7;
        let dev_u64 = u64::from(dev_idx);
        let nc_u64 = u64::from(normal_nc_mair_index());
        let cache = if attr_idx == dev_u64 && dev_u64 != 0 {
            PageCachePolicy::DeviceNoCache
        } else if attr_idx == nc_u64 && nc_u64 != 0 {
            PageCachePolicy::NormalNonCacheable
        } else {
            PageCachePolicy::NormalCacheable
        };

        PageFlags::new(access, privilege, cache)
    }

    fn next_table_existing(&self, table_phys: u64, index: usize) -> Option<u64> {
        let entry = self.read_desc(table_phys, index).ok()?;
        if (entry & (DESC_VALID | DESC_TABLE_OR_PAGE)) == (DESC_VALID | DESC_TABLE_OR_PAGE) {
            Some(entry & DESC_ADDR_MASK)
        } else {
            None
        }
    }
}

impl VSpaceMapper for Aarch64VSpace {
    fn root_phys(&self) -> PhysAddr {
        PhysAddr::new(self.l0_phys)
    }

    fn map_4k(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame,
        flags: PageFlags,
        untyped: &mut UntypedInventory,
    ) -> Result<(), SysError> {
        if !virt.is_page_aligned() {
            return Err(SysError::InvalidArgument);
        }

        let [i0, i1, i2, i3] = Self::indices(virt);
        let l1 = self.next_table_or_create(self.l0_phys, i0, untyped)?;
        let l2 = self.next_table_or_create(l1, i1, untyped)?;
        let l3 = self.next_table_or_create(l2, i2, untyped)?;

        if (self.read_desc(l3, i3)? & DESC_VALID) != 0 {
            return Err(SysError::SlotOccupied);
        }

        let pte = (frame.start_addr().raw() & DESC_ADDR_MASK)
            | DESC_TABLE_OR_PAGE
            | Self::encode_leaf_attrs(flags, LeafGranule::Page4K);

        self.write_desc(l3, i3, pte)?;
        tlbi_va(virt);
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        let [i0, i1, i2, i3] = Self::indices(virt);
        let l1 = self.next_table_existing(self.l0_phys, i0)?;
        let l2 = self.next_table_existing(l1, i1)?;

        let l2_desc = self.read_desc(l2, i2).ok()?;
        if (l2_desc & DESC_VALID) == 0 {
            return None;
        }
        let dev_idx = device_mair_index();
        if (l2_desc & DESC_TABLE_OR_PAGE) == 0 {
            // Level-2 2 MiB Block descriptor
            let phys =
                PhysAddr::new((l2_desc & DESC_2M_ADDR_MASK) | (virt.raw() & HUGE_PAGE_MASK_2M));
            return Some((phys, Self::decode_leaf_flags(l2_desc, dev_idx)));
        }

        let l3 = l2_desc & DESC_ADDR_MASK;
        let pte = self.read_desc(l3, i3).ok()?;
        if (pte & DESC_VALID) == 0 {
            return None;
        }
        let phys = PhysAddr::new((pte & DESC_ADDR_MASK) | (virt.raw() & 0xFFF));
        Some((phys, Self::decode_leaf_flags(pte, dev_idx)))
    }

    fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError> {
        let (frame, _kind) = self.unmap_4k_asid(virt, None)?;
        Ok(frame)
    }

    fn map_2m(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame2M,
        flags: PageFlags,
        untyped: &mut UntypedInventory,
    ) -> Result<(), SysError> {
        if (virt.raw() & HUGE_PAGE_MASK_2M) != 0 {
            return Err(SysError::InvalidArgument);
        }

        let [i0, i1, i2, _] = Self::indices(virt);
        let l1 = self.next_table_or_create(self.l0_phys, i0, untyped)?;
        let l2 = self.next_table_or_create(l1, i1, untyped)?;

        if (self.read_desc(l2, i2)? & DESC_VALID) != 0 {
            return Err(SysError::SlotOccupied);
        }

        // L2 Block descriptor: bit 0 = 1 (Valid), bit 1 = 0 (Block, not Table).
        let desc = (frame.start_addr().raw() & DESC_2M_ADDR_MASK)
            | Self::encode_leaf_attrs(flags, LeafGranule::Block2M);

        self.write_desc(l2, i2, desc)?;
        tlbi_va(virt);
        Ok(())
    }

    fn unmap_2m(&mut self, virt: VirtAddr) -> Result<PhysFrame2M, SysError> {
        if (virt.raw() & HUGE_PAGE_MASK_2M) != 0 {
            return Err(SysError::InvalidArgument);
        }
        let [i0, i1, i2, _] = Self::indices(virt);
        let l1 = self
            .next_table_existing(self.l0_phys, i0)
            .ok_or(SysError::InvalidArgument)?;
        let l2 = self
            .next_table_existing(l1, i1)
            .ok_or(SysError::InvalidArgument)?;

        let desc = self.read_desc(l2, i2)?;
        if (desc & (DESC_VALID | DESC_TABLE_OR_PAGE)) != DESC_VALID {
            return Err(SysError::InvalidArgument);
        }

        self.write_desc(l2, i2, 0)?;
        tlbi_va(virt);
        PhysFrame2M::from_aligned(PhysAddr::new(desc & DESC_2M_ADDR_MASK))
    }

    fn zero_frame(&self, frame: &PhysFrame) {
        let ptr = self.hhdm_offset.wrapping_add(frame.start_addr().raw()) as *mut u8;
        // SAFETY: `frame` is a newly retyped, exclusively owned 4 KiB physical frame mapped via HHDM.
        unsafe {
            write_bytes(ptr, 0, PAGE_SIZE_USIZE);
        }
    }

    fn write_frame_bytes(
        &self,
        frame: &PhysFrame,
        offset: usize,
        src: &[u8],
    ) -> Result<(), SysError> {
        let end = offset
            .checked_add(src.len())
            .ok_or(SysError::InvalidArgument)?;
        if end > PAGE_SIZE_USIZE {
            return Err(SysError::InvalidArgument);
        }
        let dst = self.hhdm_offset.wrapping_add(frame.start_addr().raw()) as *mut u8;
        // SAFETY: `frame` is exclusively owned and `offset + src.len() <= 4096`.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.add(offset), src.len());
        }
        Ok(())
    }
}

/// Clean data cache lines to Point of Coherency (`dc cvac`) before outbound DMA.
pub fn dma_clean_range(start_va: u64, len: usize) {
    let cache_line = DCACHE_LINE_BYTES.load(Ordering::Acquire).max(16);
    let mut addr = start_va & !(cache_line - 1);
    let end = start_va.saturating_add(len as u64);
    // SAFETY: `dc cvac` cleans cache lines for a valid mapped virtual address range to PoC.
    unsafe {
        while addr < end {
            asm!("dc cvac, {}", in(reg) addr, options(nostack, preserves_flags));
            addr = addr.saturating_add(cache_line);
        }
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Clean & invalidate data cache lines to Point of Coherency (`dc civac`) for inbound DMA.
pub fn dma_invalidate_range(start_va: u64, len: usize) {
    let cache_line = DCACHE_LINE_BYTES.load(Ordering::Acquire).max(16);
    let mut addr = start_va & !(cache_line - 1);
    let end = start_va.saturating_add(len as u64);
    // SAFETY: `dc civac` cleans and invalidates cache lines for a valid mapped virtual address range.
    unsafe {
        while addr < end {
            asm!("dc civac, {}", in(reg) addr, options(nostack, preserves_flags));
            addr = addr.saturating_add(cache_line);
        }
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Write and read back a 64-bit `pattern` at page-aligned EL1-writable virtual address `virt`.
///
/// # Errors
/// - [`SysError::InvalidArgument`] if `virt` is not 4 KiB-aligned or not mapped in `vspace`.
/// - [`SysError::InsufficientRights`] if the mapping is not EL1 `ReadWrite`.
pub fn probe_mapped_u64(
    vspace: &Aarch64VSpace,
    virt: VirtAddr,
    pattern: u64,
) -> Result<u64, SysError> {
    if !virt.is_page_aligned() {
        return Err(SysError::InvalidArgument);
    }
    let (_, flags) = vspace.translate(virt).ok_or(SysError::InvalidArgument)?;
    if flags.access() != PageAccess::ReadWrite || flags.privilege() != PagePrivilege::Kernel {
        return Err(SysError::InsufficientRights);
    }
    let ptr = virt.raw() as *mut u64;
    // SAFETY: `virt` was verified 4 KiB-aligned (thus 8-byte aligned) and `translate`
    // verified it is mapped Valid and EL1 Writable.
    unsafe {
        write_volatile(ptr, pattern);
        Ok(read_volatile(ptr))
    }
}
