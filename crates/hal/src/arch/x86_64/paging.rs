//! Minimal audited 64-bit 4-level paging (`VSpace`) and modern CPU security hardening (`WP`/`NXE`/`SMEP`/`SMAP`/`UMIP`).

use core::arch::asm;
use core::arch::x86_64::__cpuid_count;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use newos_abi::SysError;
use newos_kernel_core::memory::{
    CpuSecurityFeatures, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory, VSpaceMapper,
    VirtAddr,
};

use super::percpu;

const IA32_EFER_MSR: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;

const CR0_WP: u64 = 1 << 16;

const CR4_UMIP: u64 = 1 << 11;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;

// Hardware x86_64 4-level page-table entry bits
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_HUGE: u64 = 1 << 7;
const PTE_NO_EXECUTE: u64 = 1 << 63;
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Enable modern 64-bit hardware memory protection features (`WP`, `NXE`, `SMEP`, `SMAP`, `UMIP`).
pub fn enable_modern_cpu_features() -> CpuSecurityFeatures {
    // SAFETY: Reading/setting architectural CR0.WP, IA32_EFER.NXE, and CPUID-gated CR4 bits in Ring 0.
    unsafe {
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= CR0_WP;
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));

        let mut efer = percpu::rdmsr(IA32_EFER_MSR);
        efer |= EFER_NXE;
        percpu::wrmsr(IA32_EFER_MSR, efer);

        let leaf7 = __cpuid_count(7, 0);
        let has_smep = (leaf7.ebx & (1 << 7)) != 0;
        let has_smap = (leaf7.ebx & (1 << 20)) != 0;
        let has_umip = (leaf7.ecx & (1 << 2)) != 0;

        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if has_smep {
            cr4 |= CR4_SMEP;
        }
        if has_smap {
            cr4 |= CR4_SMAP;
        }
        if has_umip {
            cr4 |= CR4_UMIP;
        }
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));

        CpuSecurityFeatures {
            wp: true,
            nxe: true,
            smep: has_smep,
            smap: has_smap,
            umip: has_umip,
        }
    }
}

#[inline]
fn read_cr3_phys() -> u64 {
    let cr3: u64;
    // SAFETY: Reading CR3 in Ring 0 returns the active PML4 physical base.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & PTE_ADDR_MASK
}

#[inline]
fn invlpg(virt: VirtAddr) {
    // SAFETY: `invlpg` invalidates the single TLB entry for `virt` with no memory side effects.
    unsafe {
        asm!("invlpg [{}]", in(reg) virt.raw(), options(nostack, preserves_flags));
    }
}

/// Active 4-level `x86_64` virtual address space backed by Limine's Higher-Half Direct Map (HHDM).
pub struct X86VSpace {
    pml4_phys: u64,
    hhdm_offset: u64,
}

impl X86VSpace {
    /// Wrap the active boot PML4 (`CR3`) using Limine's HHDM offset.
    pub fn from_current_cr3(hhdm_offset: u64) -> Self {
        Self {
            pml4_phys: read_cr3_phys(),
            hhdm_offset,
        }
    }

    /// Create a brand-new, isolated 4-level Ring-3 `VSpace` (fresh PML4 carved from `untyped`).
    ///
    /// Lower half (`0..256`) is zeroed for strict process isolation; higher half (`256..512`)
    /// is cloned from the kernel PML4 so Ring-0 syscall/interrupt handlers remain mapped.
    pub fn new_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self, SysError> {
        let pml4_frame = untyped.retype_frame()?;
        self.zero_frame(&pml4_frame);
        let new_pml4_phys = pml4_frame.start_addr().raw();

        let src_table = self.table_ptr(self.pml4_phys);
        let dst_table = self.table_ptr(new_pml4_phys);
        // SAFETY: Both `src_table` (active kernel PML4) and `dst_table` (newly zeroed 4 KiB frame)
        // are valid 512-entry page tables mapped via HHDM. Copying entries 256..512 shares only
        // supervisor higher-half mappings (`PTE_USER == 0`).
        unsafe {
            for idx in 256..512 {
                let entry = read_volatile(src_table.add(idx));
                write_volatile(dst_table.add(idx), entry);
            }
        }

        Ok(Self {
            pml4_phys: new_pml4_phys,
            hhdm_offset: self.hhdm_offset,
        })
    }

    /// Return the physical address of this `VSpace`'s PML4 root (`CR3`).
    #[inline]
    pub const fn root_phys(&self) -> PhysAddr {
        PhysAddr::new(self.pml4_phys)
    }

    #[inline]
    fn table_ptr(&self, phys: u64) -> *mut u64 {
        self.hhdm_offset.wrapping_add(phys) as *mut u64
    }

    pub fn zero_frame(&self, frame: &PhysFrame) {
        let ptr = self.hhdm_offset.wrapping_add(frame.start_addr().raw()) as *mut u8;
        // SAFETY: `frame` is a newly retyped, exclusively owned 4 KiB physical frame mapped via HHDM.
        unsafe {
            write_bytes(ptr, 0, PAGE_SIZE as usize);
        }
    }

    /// Copy `src` bytes into an owned `PhysFrame` at `offset` via HHDM (bounds-checked).
    pub fn write_frame_bytes(
        &self,
        frame: &PhysFrame,
        offset: usize,
        src: &[u8],
    ) -> Result<(), SysError> {
        let end = offset.checked_add(src.len()).ok_or(SysError::InvalidArgument)?;
        if end > PAGE_SIZE as usize {
            return Err(SysError::InvalidArgument);
        }
        let dst = self
            .hhdm_offset
            .wrapping_add(frame.start_addr().raw()) as *mut u8;
        // SAFETY: `frame` is an owned 4 KiB physical page mapped via HHDM and `offset + src.len() <= 4096`.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst.add(offset), src.len());
        }
        Ok(())
    }

    fn next_table_or_create(
        &self,
        table_phys: u64,
        index: usize,
        user: bool,
        untyped: &mut UntypedInventory,
    ) -> Result<u64, SysError> {
        let entry_ptr = unsafe { self.table_ptr(table_phys).add(index) };
        // SAFETY: `table_phys` is a valid 4 KiB-aligned page table accessible via HHDM and `index < 512`.
        let entry = unsafe { read_volatile(entry_ptr) };

        if (entry & PTE_PRESENT) != 0 {
            if (entry & PTE_HUGE) != 0 {
                return Err(SysError::SlotOccupied);
            }
            if user && (entry & PTE_USER) == 0 {
                // SAFETY: Promoting intermediate directory entry to allow user mapping below it.
                unsafe { write_volatile(entry_ptr, entry | PTE_USER) };
            }
            return Ok(entry & PTE_ADDR_MASK);
        }

        let frame = untyped.retype_frame()?;
        self.zero_frame(&frame);
        let next_phys = frame.start_addr().raw();

        let mut flags = PTE_PRESENT | PTE_WRITABLE;
        if user {
            flags |= PTE_USER;
        }
        // SAFETY: `next_phys` points to a freshly zeroed, owned 4 KiB page table.
        unsafe { write_volatile(entry_ptr, next_phys | flags) };
        Ok(next_phys)
    }

    fn next_table_existing(&self, table_phys: u64, index: usize) -> Option<u64> {
        let entry_ptr = unsafe { self.table_ptr(table_phys).add(index) };
        // SAFETY: `table_phys` is a valid 4 KiB-aligned page table accessible via HHDM and `index < 512`.
        let entry = unsafe { read_volatile(entry_ptr) };
        if (entry & PTE_PRESENT) == 0 || (entry & PTE_HUGE) != 0 {
            None
        } else {
            Some(entry & PTE_ADDR_MASK)
        }
    }

    fn indices(virt: VirtAddr) -> [usize; 4] {
        let v = virt.raw();
        [
            ((v >> 39) & 0x1FF) as usize, // PML4
            ((v >> 30) & 0x1FF) as usize, // PDPT
            ((v >> 21) & 0x1FF) as usize, // PD
            ((v >> 12) & 0x1FF) as usize, // PT
        ]
    }
}

impl VSpaceMapper for X86VSpace {
    fn root_phys(&self) -> PhysAddr {
        X86VSpace::root_phys(self)
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

        let [i4, i3, i2, i1] = Self::indices(virt);
        let pdpt = self.next_table_or_create(self.pml4_phys, i4, flags.user, untyped)?;
        let pd = self.next_table_or_create(pdpt, i3, flags.user, untyped)?;
        let pt = self.next_table_or_create(pd, i2, flags.user, untyped)?;

        let pte_ptr = unsafe { self.table_ptr(pt).add(i1) };
        // SAFETY: `pt` is a valid 4 KiB page table accessible via HHDM and `i1 < 512`.
        let existing = unsafe { read_volatile(pte_ptr) };
        if (existing & PTE_PRESENT) != 0 {
            return Err(SysError::SlotOccupied);
        }

        let mut pte = frame.start_addr().raw() | PTE_PRESENT;
        if flags.writable {
            pte |= PTE_WRITABLE;
        }
        if flags.user {
            pte |= PTE_USER;
        }
        if !flags.executable {
            pte |= PTE_NO_EXECUTE;
        }
        if flags.no_cache {
            pte |= PTE_PCD | PTE_PWT;
        }

        // SAFETY: `frame` is an exclusively owned 4 KiB physical page; installing PTE and flushing TLB.
        unsafe { write_volatile(pte_ptr, pte) };
        invlpg(virt);
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
        let [i4, i3, i2, i1] = Self::indices(virt);
        let pdpt = self.next_table_existing(self.pml4_phys, i4)?;
        let pd = self.next_table_existing(pdpt, i3)?;
        let pt = self.next_table_existing(pd, i2)?;

        let pte_ptr = unsafe { self.table_ptr(pt).add(i1) };
        // SAFETY: `pt` is a valid 4 KiB page table accessible via HHDM and `i1 < 512`.
        let pte = unsafe { read_volatile(pte_ptr) };
        if (pte & PTE_PRESENT) == 0 {
            return None;
        }

        let phys = PhysAddr::new((pte & PTE_ADDR_MASK) | (virt.raw() & 0xFFF));
        let flags = PageFlags {
            writable: (pte & PTE_WRITABLE) != 0,
            executable: (pte & PTE_NO_EXECUTE) == 0,
            user: (pte & PTE_USER) != 0,
            no_cache: (pte & PTE_PCD) != 0,
        };
        Some((phys, flags))
    }

    fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysFrame, SysError> {
        let [i4, i3, i2, i1] = Self::indices(virt);
        let pdpt = self
            .next_table_existing(self.pml4_phys, i4)
            .ok_or(SysError::InvalidArgument)?;
        let pd = self
            .next_table_existing(pdpt, i3)
            .ok_or(SysError::InvalidArgument)?;
        let pt = self
            .next_table_existing(pd, i2)
            .ok_or(SysError::InvalidArgument)?;

        let pte_ptr = unsafe { self.table_ptr(pt).add(i1) };
        // SAFETY: `pt` is a valid 4 KiB page table accessible via HHDM and `i1 < 512`.
        let pte = unsafe { read_volatile(pte_ptr) };
        if (pte & PTE_PRESENT) == 0 {
            return Err(SysError::InvalidArgument);
        }

        // SAFETY: Clearing the PTE and invalidating the TLB entry reclaims exclusive frame ownership.
        unsafe { write_volatile(pte_ptr, 0) };
        invlpg(virt);
        PhysFrame::from_aligned(PhysAddr::new(pte & PTE_ADDR_MASK))
    }

    fn zero_frame(&self, frame: &PhysFrame) {
        X86VSpace::zero_frame(self, frame);
    }

    fn write_frame_bytes(
        &self,
        frame: &PhysFrame,
        offset: usize,
        src: &[u8],
    ) -> Result<(), SysError> {
        X86VSpace::write_frame_bytes(self, frame, offset, src)
    }
}

/// Safe diagnostic probe writing and reading back a `u64` in a verified mapped kernel RW page.
pub fn probe_mapped_u64(vspace: &X86VSpace, virt: VirtAddr, pattern: u64) -> Result<u64, SysError> {
    let (_, flags) = vspace.translate(virt).ok_or(SysError::InvalidArgument)?;
    if !flags.writable || flags.user {
        return Err(SysError::InsufficientRights);
    }
    let ptr = virt.raw() as *mut u64;
    // SAFETY: `vspace.translate(virt)` verified `virt` is mapped Present, Writable, Supervisor,
    // and 4 KiB-aligned (`virt.is_page_aligned()`), so a `u64` volatile read/write is sound.
    unsafe {
        write_volatile(ptr, pattern);
        Ok(read_volatile(ptr))
    }
}
