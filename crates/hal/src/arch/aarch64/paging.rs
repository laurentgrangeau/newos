//! Minimal audited 64-bit ARMv8 4-level 4 KiB paging (`TTBR1_EL1` kernel & `TTBR0_EL1` user).

use core::arch::asm;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicU8, Ordering};
use newos_abi::SysError;
use newos_kernel_core::memory::{
    HUGE_PAGE_MASK_2M, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, PhysFrame2M, UntypedInventory,
    VSpaceMapper, VirtAddr,
};

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

#[inline]
fn device_mair_index() -> u64 {
    let cached = CACHED_DEVICE_MAIR_IDX.load(Ordering::Relaxed);
    if cached != u8::MAX {
        return u64::from(cached);
    }
    let mair: u64;
    // SAFETY: Reading `MAIR_EL1` in EL1 inspects Limine's immutable boot memory attributes.
    unsafe {
        asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack, preserves_flags));
    }
    let mut found = 0u8;
    for idx in 0..8u8 {
        let attr = ((mair >> (u64::from(idx) * 8)) & 0xFF) as u8;
        if attr == 0x00 || attr == 0x04 {
            found = idx;
            break;
        }
    }
    CACHED_DEVICE_MAIR_IDX.store(found, Ordering::Relaxed);
    u64::from(found)
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

/// Ensure `TTBR0_EL1` supplies the active ASID (`TCR_EL1.A1 == 0`) and flush stale boot TLB entries once.
pub fn ensure_ttbr0_asid_enabled() {
    // SAFETY: Configuring `TCR_EL1.A1 = 0` and executing a one-time EL1 TLB invalidation
    // before entering EL0 guarantees `TTBR0_EL1[63:48]` tags all `DESC_NG` user mappings.
    unsafe {
        let mut tcr: u64;
        asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack, preserves_flags));
        if (tcr & (1u64 << 22)) != 0 {
            tcr &= !(1u64 << 22);
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

/// 4-level 4 KiB ARMv8 `VSpace` (kernel `TTBR1_EL1` or isolated EL0 `TTBR0_EL1`).
pub struct Aarch64VSpace {
    l0_phys: u64,
    hhdm_offset: u64,
}

impl Aarch64VSpace {
    pub fn from_current_ttbr1(hhdm_offset: u64) -> Self {
        Self {
            l0_phys: read_ttbr1_phys(),
            hhdm_offset,
        }
    }

    /// Wrap an existing L0 page-table root physical address (e.g. active `TTBR0_EL1`).
    pub const fn from_root_phys(l0_phys: u64, hhdm_offset: u64) -> Self {
        Self {
            l0_phys: l0_phys & DESC_ADDR_MASK,
            hhdm_offset,
        }
    }

    /// Allocate a brand-new, empty EL0 `TTBR0_EL1` root L0 table (hardware-isolated from `TTBR1_EL1`).
    pub fn new_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self, SysError> {
        let l0_frame = untyped.retype_frame()?;
        self.zero_frame(&l0_frame);
        Ok(Self {
            l0_phys: l0_frame.start_addr().raw(),
            hhdm_offset: self.hhdm_offset,
        })
    }

    #[inline]
    fn table_ptr(&self, phys: u64) -> *mut u64 {
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

    fn indices(virt: VirtAddr) -> [usize; 4] {
        let v = virt.raw();
        [
            ((v >> 39) & 0x1FF) as usize, // L0
            ((v >> 30) & 0x1FF) as usize, // L1
            ((v >> 21) & 0x1FF) as usize, // L2
            ((v >> 12) & 0x1FF) as usize, // L3
        ]
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

    fn next_table_existing(&self, table_phys: u64, index: usize) -> Option<u64> {
        let entry = self.read_desc(table_phys, index).ok()?;
        if (entry & (DESC_VALID | DESC_TABLE_OR_PAGE)) != (DESC_VALID | DESC_TABLE_OR_PAGE) {
            None
        } else {
            Some(entry & DESC_ADDR_MASK)
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
        if flags.writable && flags.executable {
            return Err(SysError::InvalidArgument);
        }
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

        let mut pte = (frame.start_addr().raw() & DESC_ADDR_MASK)
            | DESC_VALID
            | DESC_TABLE_OR_PAGE
            | DESC_AF
            | DESC_SH_INNER;
        if flags.no_cache {
            pte |= device_mair_index() << 2;
        }
        match (flags.user, flags.writable) {
            (false, true) => {} // AP=00: EL1 RW (Global)
            (false, false) => pte |= DESC_AP_EL1_RO,
            (true, true) => pte |= DESC_AP_EL0_RW | DESC_NG,
            (true, false) => pte |= DESC_AP_EL0_RO | DESC_NG,
        }
        if !flags.executable {
            pte |= DESC_PXN | DESC_UXN;
        } else if flags.user {
            // EL0 executable pages are NEVER executable by EL1 (hardware SMEP equivalent)
            pte |= DESC_PXN;
        } else {
            pte |= DESC_UXN;
        }

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
            let ap = (l2_desc >> 6) & 0b11;
            let user = (ap & 0b01) != 0;
            let writable = (ap & 0b10) == 0;
            let executable = if user {
                (l2_desc & DESC_UXN) == 0
            } else {
                (l2_desc & DESC_PXN) == 0
            };
            let attr_idx = (l2_desc >> 2) & 0x7;
            let no_cache = attr_idx == dev_idx && dev_idx != 0;
            let phys =
                PhysAddr::new((l2_desc & DESC_2M_ADDR_MASK) | (virt.raw() & HUGE_PAGE_MASK_2M));
            return Some((
                phys,
                PageFlags {
                    writable,
                    executable,
                    user,
                    no_cache,
                },
            ));
        }

        let l3 = l2_desc & DESC_ADDR_MASK;
        let pte = self.read_desc(l3, i3).ok()?;
        if (pte & DESC_VALID) == 0 {
            return None;
        }

        let ap = (pte >> 6) & 0b11;
        let user = (ap & 0b01) != 0;
        let writable = (ap & 0b10) == 0;
        let executable = if user {
            (pte & DESC_UXN) == 0
        } else {
            (pte & DESC_PXN) == 0
        };
        let attr_idx = (pte >> 2) & 0x7;
        let no_cache = attr_idx == dev_idx && dev_idx != 0;

        let phys = PhysAddr::new((pte & DESC_ADDR_MASK) | (virt.raw() & 0xFFF));
        Some((
            phys,
            PageFlags {
                writable,
                executable,
                user,
                no_cache,
            },
        ))
    }

    fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError> {
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

        self.write_desc(l3, i3, 0)?;
        tlbi_va(virt);
        PhysFrame::from_aligned(PhysAddr::new(pte & DESC_ADDR_MASK))
    }

    fn map_2m(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame2M,
        flags: PageFlags,
        untyped: &mut UntypedInventory,
    ) -> Result<(), SysError> {
        if flags.writable && flags.executable {
            return Err(SysError::InvalidArgument);
        }
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
        let mut desc =
            (frame.start_addr().raw() & DESC_2M_ADDR_MASK) | DESC_VALID | DESC_AF | DESC_SH_INNER;
        if flags.no_cache {
            desc |= device_mair_index() << 2;
        }
        match (flags.user, flags.writable) {
            (false, true) => {}
            (false, false) => desc |= DESC_AP_EL1_RO,
            (true, true) => desc |= DESC_AP_EL0_RW | DESC_NG,
            (true, false) => desc |= DESC_AP_EL0_RO | DESC_NG,
        }
        if !flags.executable {
            desc |= DESC_PXN | DESC_UXN;
        } else if flags.user {
            desc |= DESC_PXN;
        } else {
            desc |= DESC_UXN;
        }

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
            write_bytes(ptr, 0, PAGE_SIZE as usize);
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
        if end > PAGE_SIZE as usize {
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

pub fn probe_mapped_u64(
    vspace: &Aarch64VSpace,
    virt: VirtAddr,
    pattern: u64,
) -> Result<u64, SysError> {
    if !virt.is_page_aligned() {
        return Err(SysError::InvalidArgument);
    }
    let (_, flags) = vspace.translate(virt).ok_or(SysError::InvalidArgument)?;
    if !flags.writable || flags.user {
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
