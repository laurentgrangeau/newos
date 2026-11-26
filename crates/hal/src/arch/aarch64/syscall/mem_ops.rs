//! Memory, MMIO, DMA, and page-table syscall handlers with RAII rollback guards.

use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::Ordering;
use newos_abi::{CapId, DmaCacheOp, Rights, SysError};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_MASK, PAGE_SIZE, PageAccess, PageCachePolicy, PageFlags,
    PagePrivilege, PhysAddr, PhysFrame, UntypedInventory, VSpaceMapper, VirtAddr,
};

use super::arch_state::spec_barrier;
use super::bootstrap::mmio_phys_to_virt;
use super::{
    DOMAINS, FRAME_MAPPINGS, HHDM_OFFSET, IPC_STATE, MAX_DMA_CACHE_LEN, MAX_DOMAINS,
    RUNTIME_UNTYPED, USER_ADDR_LIMIT, domain_asid,
};
use crate::arch::aarch64::paging::{self, UnmappedFrameKind};
use crate::arch::aarch64::serial;

#[inline]
pub(super) const fn resolve_vspace_root(root: PhysAddr, cur_ttbr0: u64) -> u64 {
    if root.raw() != 0 {
        root.raw()
    } else {
        cur_ttbr0
    }
}

/// Convert EL0 capability [`Rights`] to compile-time W^X-enforced [`PageAccess`].
#[inline]
pub(super) const fn rights_to_page_access(rights: Rights) -> Result<PageAccess, SysError> {
    let w = rights.contains(Rights::WRITE);
    let x = rights.contains(Rights::EXEC);
    match (w, x) {
        (true, true) => Err(SysError::InvalidArgument),
        (true, false) => Ok(PageAccess::ReadWrite),
        (false, true) => Ok(PageAccess::ReadExecute),
        (false, false) => Ok(PageAccess::ReadOnly),
    }
}

/// RAII guard for a single newly mapped 4 KiB page; unmaps (and optionally reclaims the frame)
/// on drop unless [`Self::commit`] is called.
struct MappedPageGuard<'a> {
    vspace: &'a mut paging::Aarch64VSpace,
    untyped: Option<&'a mut UntypedInventory>,
    va: VirtAddr,
    committed: bool,
}

impl<'a> MappedPageGuard<'a> {
    const fn new_unmap_only(vspace: &'a mut paging::Aarch64VSpace, va: VirtAddr) -> Self {
        Self {
            vspace,
            untyped: None,
            va,
            committed: false,
        }
    }

    const fn new_with_reclaim(
        vspace: &'a mut paging::Aarch64VSpace,
        untyped: &'a mut UntypedInventory,
        va: VirtAddr,
    ) -> Self {
        Self {
            vspace,
            untyped: Some(untyped),
            va,
            committed: false,
        }
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for MappedPageGuard<'_> {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(reclaimed) = self.vspace.unmap_4k(self.va)
            && let Some(untyped) = self.untyped.as_deref_mut()
        {
            let _ = untyped.reclaim_frame(reclaimed);
        }
    }
}

/// RAII guard for multi-page `MmioMap`; unmaps all pages mapped so far on drop unless
/// [`Self::commit`] is called.
struct MmioMapGuard<'a> {
    vspace: &'a mut paging::Aarch64VSpace,
    vaddr: u64,
    mapped_pages: u64,
    committed: bool,
}

impl<'a> MmioMapGuard<'a> {
    const fn new(vspace: &'a mut paging::Aarch64VSpace, vaddr: u64) -> Self {
        Self {
            vspace,
            vaddr,
            mapped_pages: 0,
            committed: false,
        }
    }

    fn map_next_page(
        &mut self,
        phys_base: u64,
        flags: PageFlags,
        untyped: &mut UntypedInventory,
    ) -> Result<(), SysError> {
        let off = self.mapped_pages * PAGE_SIZE;
        let va = VirtAddr::new_page_aligned(self.vaddr + off)?;
        let fr = PhysFrame::from_aligned(PhysAddr::new(phys_base + off))?;
        self.vspace.map_4k(va, fr, flags, untyped)?;
        self.mapped_pages += 1;
        Ok(())
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for MmioMapGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            for i in 0..self.mapped_pages {
                if let Ok(va) = VirtAddr::new_page_aligned(self.vaddr + i * PAGE_SIZE) {
                    let _ = self.vspace.unmap_4k_asid(va, None);
                }
            }
        }
    }
}

/// RAII guard for optional Normal-Non-Cacheable `DmaMap` PTE + `FRAME_MAPPINGS` entry,
/// ensuring both PTE and tracker record are rolled back if `pin_dma` fails.
struct DmaNcMapGuard<'a> {
    vspace: &'a mut paging::Aarch64VSpace,
    mappings: &'a mut FrameMappingTracker<512>,
    root_phys: PhysAddr,
    va: VirtAddr,
    recorded: bool,
    committed: bool,
}

impl<'a> DmaNcMapGuard<'a> {
    const fn new(
        vspace: &'a mut paging::Aarch64VSpace,
        mappings: &'a mut FrameMappingTracker<512>,
        root_phys: PhysAddr,
        va: VirtAddr,
    ) -> Self {
        Self {
            vspace,
            mappings,
            root_phys,
            va,
            recorded: false,
            committed: false,
        }
    }

    fn record_and_pin(&mut self, phys: PhysAddr) -> Result<(), SysError> {
        self.mappings
            .record_with_access(self.root_phys, self.va, phys, PageAccess::ReadWrite)?;
        self.recorded = true;
        self.mappings.pin_dma(phys)?;
        Ok(())
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for DmaNcMapGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if self.recorded {
                let _ = self.mappings.remove(self.root_phys, self.va);
            }
            let _ = self.vspace.unmap_4k(self.va);
        }
    }
}

/// Page-table-validated, PAN-safe copy from an EL0 buffer in `ttbr0` into an EL1 slice via HHDM.
///
/// Walks `ttbr0` for every 4 KiB page spanned by `user_ptr..user_ptr+count`, rejecting any
/// unmapped or non-EL0 page with `Err(SysError::InvalidArgument)` without risking an EL1 abort.
fn copy_from_user(ttbr0: u64, user_ptr: u64, len: u64, dst: &mut [u8]) -> Result<usize, SysError> {
    if len == 0 {
        return Ok(0);
    }
    let end = user_ptr.checked_add(len).ok_or(SysError::InvalidArgument)?;
    if user_ptr == 0 || end >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    spec_barrier();
    let count = usize::try_from(len).unwrap_or(usize::MAX).min(dst.len());
    if count == 0 {
        return Ok(0);
    }

    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vspace = paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);

    let mut copied = 0usize;
    while copied < count {
        let cur_va = user_ptr + copied as u64;
        let va = VirtAddr::new_canonical(cur_va)?;
        let (pa, flags) = vspace.translate(va).ok_or(SysError::InvalidArgument)?;
        if flags.privilege() != PagePrivilege::User {
            return Err(SysError::InvalidArgument);
        }
        #[allow(clippy::cast_possible_truncation)]
        // `PAGE_SIZE - (cur_va & PAGE_MASK)` is `1..=4096`.
        let page_rem = (PAGE_SIZE - (cur_va & PAGE_MASK)) as usize;
        let chunk = (count - copied).min(page_rem);
        let src = hhdm.wrapping_add(pa.raw()) as *const u8;
        // SAFETY: `vspace.translate(va)` verified this EL0 page is mapped and `chunk` does not
        // cross the 4 KiB page boundary. Reading via HHDM avoids touching EL0 VA directly (PAN-safe),
        // and `dst` is an EL1 stack slice disjoint from user physical frames.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(copied), chunk);
        }
        copied += chunk;
    }
    Ok(count)
}

/// Out-of-line `DebugWrite` handler using a 1024-byte EL1 stack buffer with UTF-8
/// char-boundary backup when `user_len > 1024` splits a multi-byte codepoint.
#[inline(never)]
pub(super) fn handle_debug_write(
    cur_ttbr0: u64,
    user_ptr: u64,
    user_len: u64,
) -> Result<u64, SysError> {
    let mut buf = [0u8; 1024];
    let n = copy_from_user(cur_ttbr0, user_ptr, user_len, &mut buf)?;
    let valid_len = match core::str::from_utf8(&buf[..n]) {
        Ok(_) => n,
        Err(e)
            if user_len > (buf.len() as u64) && e.error_len().is_none() && e.valid_up_to() > 0 =>
        {
            e.valid_up_to()
        }
        Err(_) => return Err(SysError::InvalidArgument),
    };
    let text = core::str::from_utf8(&buf[..valid_len]).map_err(|_| SysError::InvalidArgument)?;
    let mut s = serial::Pl011::new();
    let _ = s.write_str(text);
    Ok(valid_len as u64)
}

/// Perform PAN-safe, page-table-validated DMA cache maintenance (`dc cvac` / `dc civac`)
/// over an EL0 virtual address range `user_ptr..user_ptr+len` via its HHDM physical alias.
pub(super) fn handle_dma_cache_op(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    user_ptr: u64,
    len: u64,
    op_raw: u64,
) -> Result<u64, SysError> {
    let op = DmaCacheOp::from_u64(op_raw).ok_or(SysError::InvalidArgument)?;
    let root = IPC_STATE
        .lock()
        .validate_vspace_for(cur_pd, CapId::new(a0), Rights::READ)?;
    let ttbr0 = resolve_vspace_root(root, cur_ttbr0);
    if len == 0 {
        return Ok(0);
    }
    if len > MAX_DMA_CACHE_LEN {
        return Err(SysError::InvalidArgument);
    }
    let end = user_ptr.checked_add(len).ok_or(SysError::InvalidArgument)?;
    if user_ptr == 0 || end >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vspace = paging::Aarch64VSpace::from_root_phys(ttbr0, hhdm);
    let require_write = matches!(op, DmaCacheOp::Invalidate | DmaCacheOp::CleanInvalidate);

    let mut cur = user_ptr;
    while cur < end {
        let page_va_raw = cur & !PAGE_MASK;
        let page_off = cur & PAGE_MASK;
        #[allow(clippy::cast_possible_truncation)] // `PAGE_SIZE - page_off` is `1..=4096`.
        let chunk = (PAGE_SIZE - page_off).min(end - cur) as usize;
        let page_va = VirtAddr::new_page_aligned(page_va_raw)?;
        let (phys, flags) = vspace.translate(page_va).ok_or(SysError::InvalidArgument)?;
        if flags.privilege() != PagePrivilege::User
            || (require_write && flags.access() != PageAccess::ReadWrite)
        {
            return Err(SysError::InsufficientRights);
        }
        let hhdm_va = hhdm.wrapping_add(phys.raw().wrapping_add(page_off));
        match op {
            DmaCacheOp::Clean => paging::dma_clean_range(hhdm_va, chunk),
            DmaCacheOp::Invalidate | DmaCacheOp::CleanInvalidate => {
                paging::dma_invalidate_range(hhdm_va, chunk);
            }
        }
        cur += chunk as u64;
    }
    Ok(len)
}

pub(super) fn handle_mmio_read32(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let phys = IPC_STATE
        .lock()
        .validate_mmio_read32_for(cur_pd, CapId::new(a0), a1)?;
    let virt = mmio_phys_to_virt(phys.raw()).ok_or(SysError::InvalidArgument)?;
    let ptr = virt as *const u32;
    // SAFETY: `validate_mmio_read32_for` verified rights, alignment, and bounds,
    // and `mmio_phys_to_virt` resolved a verified Device-nGnRnE mapping.
    let val = unsafe { read_volatile(ptr) };
    Ok(u64::from(val))
}

pub(super) fn handle_mmio_write32(
    cur_pd: usize,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Result<u64, SysError> {
    let phys = IPC_STATE
        .lock()
        .validate_mmio_write32_for(cur_pd, CapId::new(a0), a1)?;
    let virt = mmio_phys_to_virt(phys.raw()).ok_or(SysError::InvalidArgument)?;
    let ptr = virt as *mut u32;
    #[allow(clippy::cast_possible_truncation)]
    // `MmioWrite32` writes the low 32 bits of `a2` per ABI.
    let val = a2 as u32;
    // SAFETY: `validate_mmio_write32_for` verified WRITE right, alignment, and bounds,
    // and `mmio_phys_to_virt` resolved a verified Device-nGnRnE mapping.
    unsafe { write_volatile(ptr, val) };
    Ok(0)
}

pub(super) fn handle_virt_to_phys(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
) -> Result<u64, SysError> {
    if a1 == 0 || a1 >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let root = IPC_STATE
        .lock()
        .validate_vspace_for(cur_pd, CapId::new(a0), Rights::READ)?;
    let root_phys = resolve_vspace_root(root, cur_ttbr0);
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let vspace = paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
    let va = VirtAddr::new_canonical(a1)?;
    vspace
        .translate(va)
        .filter(|(_, flags)| flags.privilege() == PagePrivilege::User)
        .map(|(pa, _)| pa.raw())
        .ok_or(SysError::InvalidArgument)
}

pub(super) fn handle_map_page(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    parse_rights: fn(u64) -> Result<Rights, SysError>,
) -> Result<u64, SysError> {
    if a1 == 0 || a1 >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let root = IPC_STATE
        .lock()
        .validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let rights = parse_rights(a2)?;
    let access = rights_to_page_access(rights)?;
    let page_flags = PageFlags::new(
        access,
        PagePrivilege::User,
        PageCachePolicy::NormalCacheable,
    );
    let va = VirtAddr::new_page_aligned(a1)?;

    let root_phys = resolve_vspace_root(root, cur_ttbr0);
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut vspace = paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
    // Check occupancy BEFORE carving a frame to prevent unnecessary churn.
    if vspace.translate(va).is_some() {
        return Err(SysError::SlotOccupied);
    }
    let mut untyped = RUNTIME_UNTYPED.lock();
    let frame = untyped.retype_frame()?;
    vspace.zero_frame(&frame);
    let pa = frame.start_addr();
    if let Err(e) = vspace.map_4k(va, frame, page_flags, &mut untyped) {
        if let Ok(reclaimed) = PhysFrame::from_aligned(pa) {
            let _ = untyped.reclaim_frame(reclaimed);
        }
        return Err(e);
    }
    let guard = MappedPageGuard::new_with_reclaim(&mut vspace, &mut untyped, va);
    FRAME_MAPPINGS
        .lock()
        .record_with_access(PhysAddr::new(root_phys), va, pa, access)?;
    guard.commit();
    Ok(0)
}

pub(super) fn handle_unmap_page(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
) -> Result<u64, SysError> {
    if a1 == 0 || a1 >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let va = VirtAddr::new_page_aligned(a1)?;
    // Lock order: DOMAINS -> IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS.
    // Held across PTE mutation to serialize concurrent SMP `MapPage`/`UnmapPage`.
    let table = DOMAINS.lock();
    let ipc = IPC_STATE.lock();
    let root = ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let root_phys = resolve_vspace_root(root, cur_ttbr0);
    let asid = (0..table.count.min(MAX_DOMAINS))
        .find(|&p| table.domains[p].is_some_and(|d| d.ttbr0 == root_phys))
        .map(domain_asid);
    drop(table);
    let mut untyped = RUNTIME_UNTYPED.lock();
    let mut mappings = FRAME_MAPPINGS.lock();
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut vspace = paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
    let (frame, kind) = vspace.unmap_4k_asid_reclaim(va, asid, &mut untyped)?;
    if kind == UnmappedFrameKind::Ram {
        let pa = frame.start_addr();
        let _ = mappings.remove(PhysAddr::new(root_phys), va);
        if !ipc.has_live_frame_cap(pa)
            && !mappings.has_mapping_for_phys(pa)
            && !mappings.is_dma_pinned(pa)
        {
            // Zero exclusively reclaimed physical frame immediately (zero-on-free).
            vspace.zero_frame(&frame);
            mappings.clear_ever_written(pa);
            let _ = untyped.reclaim_frame(frame);
        }
    }
    Ok(0)
}

pub(super) fn handle_frame_map(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    parse_rights: fn(u64) -> Result<Rights, SysError>,
) -> Result<u64, SysError> {
    if a2 == 0 || a2 >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    let req_rights = parse_rights(a3)?;
    let mut frame_req = Rights::READ;
    if req_rights.contains(Rights::WRITE) {
        frame_req = frame_req.union(Rights::WRITE);
    }
    if req_rights.contains(Rights::EXEC) {
        frame_req = frame_req.union(Rights::EXEC);
    }
    let access = rights_to_page_access(req_rights)?;
    let flags = PageFlags::new(
        access,
        PagePrivilege::User,
        PageCachePolicy::NormalCacheable,
    );
    let va = VirtAddr::new_page_aligned(a2)?;

    // Hold locks in strict hierarchy (`IPC_STATE` -> `RUNTIME_UNTYPED` -> `FRAME_MAPPINGS`)
    // across capability validation, W^X anti-aliasing check, and PTE installation
    // to eliminate the validate-then-map SMP race (`P8`) and W^X aliasing bypass (`M1`).
    let ipc = IPC_STATE.lock();
    let root = ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let phys = ipc.validate_frame_for(cur_pd, CapId::new(a1), frame_req)?;
    let frame_obj = PhysFrame::from_aligned(phys)?;
    let root_phys = resolve_vspace_root(root, cur_ttbr0);
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut vspace = paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
    if vspace.translate(va).is_some() {
        return Err(SysError::SlotOccupied);
    }
    let mut untyped = RUNTIME_UNTYPED.lock();
    let mut mappings = FRAME_MAPPINGS.lock();
    if mappings.conflicts_wx_access(phys, access) {
        return Err(SysError::InsufficientRights);
    }
    vspace.map_4k(va, frame_obj, flags, &mut untyped)?;
    let guard = MappedPageGuard::new_unmap_only(&mut vspace, va);
    mappings.record_with_access(PhysAddr::new(root_phys), va, phys, access)?;
    guard.commit();
    Ok(0)
}

#[allow(clippy::significant_drop_tightening)] // Lock hierarchy holds `IPC_STATE` while mapping under `RUNTIME_UNTYPED`.
pub(super) fn handle_mmio_map(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    vaddr: u64,
) -> Result<u64, SysError> {
    if vaddr == 0 || (vaddr & PAGE_MASK) != 0 || vaddr >= USER_ADDR_LIMIT {
        return Err(SysError::InvalidArgument);
    }
    // Lock order: IPC_STATE -> RUNTIME_UNTYPED.
    let ipc = IPC_STATE.lock();
    let mut untyped = RUNTIME_UNTYPED.lock();
    let root = ipc.validate_vspace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let (phys, len, writable) = ipc.validate_mmio_region_for(cur_pd, CapId::new(a1))?;
    if len == 0
        || (phys.raw() & PAGE_MASK) != 0
        || (len & PAGE_MASK) != 0
        || vaddr
            .checked_add(len)
            .is_none_or(|end| end > USER_ADDR_LIMIT)
    {
        return Err(SysError::InvalidArgument);
    }
    let access = if writable {
        PageAccess::ReadWrite
    } else {
        PageAccess::ReadOnly
    };
    let flags = PageFlags::new(access, PagePrivilege::User, PageCachePolicy::DeviceNoCache);
    let root_phys = resolve_vspace_root(root, cur_ttbr0);
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let mut vspace = paging::Aarch64VSpace::from_root_phys(root_phys, hhdm);
    let pages = len / PAGE_SIZE;
    let mut guard = MmioMapGuard::new(&mut vspace, vaddr);
    for _ in 0..pages {
        guard.map_next_page(phys.raw(), flags, &mut untyped)?;
    }
    guard.commit();
    Ok(len)
}

#[allow(clippy::significant_drop_tightening)] // Lock hierarchy holds `IPC_STATE -> RUNTIME_UNTYPED -> FRAME_MAPPINGS`.
pub(super) fn handle_dma_map(
    cur_pd: usize,
    cur_ttbr0: u64,
    a0: u64,
    a1: u64,
    flags: u64,
    opt_vaddr: u64,
) -> Result<u64, SysError> {
    let ipc = IPC_STATE.lock();
    let _iospace_id = ipc.validate_iospace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let phys = ipc.validate_frame_for(cur_pd, CapId::new(a1), Rights::READ.union(Rights::WRITE))?;
    let mut untyped = RUNTIME_UNTYPED.lock();
    let mut mappings = FRAME_MAPPINGS.lock();
    if (flags & newos_abi::DMA_FLAG_NON_CACHEABLE) != 0 && opt_vaddr != 0 {
        if opt_vaddr >= USER_ADDR_LIMIT {
            return Err(SysError::InvalidArgument);
        }
        let va = VirtAddr::new_page_aligned(opt_vaddr)?;
        if mappings.conflicts_wx_access(phys, PageAccess::ReadWrite) {
            return Err(SysError::InsufficientRights);
        }
        let frame_obj = PhysFrame::from_aligned(phys)?;
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        let mut vspace = paging::Aarch64VSpace::from_root_phys(cur_ttbr0, hhdm);
        if vspace.translate(va).is_some() {
            return Err(SysError::SlotOccupied);
        }
        let nc_flags = PageFlags::new(
            PageAccess::ReadWrite,
            PagePrivilege::User,
            PageCachePolicy::NormalNonCacheable,
        );
        vspace.map_4k(va, frame_obj, nc_flags, &mut untyped)?;
        let mut guard =
            DmaNcMapGuard::new(&mut vspace, &mut mappings, PhysAddr::new(cur_ttbr0), va);
        guard.record_and_pin(phys)?;
        guard.commit();
    } else {
        mappings.pin_dma(phys)?;
    }
    Ok(phys.raw())
}

pub(super) fn handle_dma_unmap(cur_pd: usize, a0: u64, a1: u64) -> Result<u64, SysError> {
    let ipc = IPC_STATE.lock();
    let _iospace_id = ipc.validate_iospace_for(cur_pd, CapId::new(a0), Rights::WRITE)?;
    let phys = ipc.validate_frame_for(cur_pd, CapId::new(a1), Rights::READ)?;
    drop(ipc);
    FRAME_MAPPINGS.lock().unpin_dma(phys);
    Ok(0)
}
