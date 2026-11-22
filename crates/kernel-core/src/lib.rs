#![no_std]
#![forbid(unsafe_code)]

//! Pure, 100% memory-safe, `no_alloc` microkernel core.
//!
//! All hardware interaction is injected via safe traits; this crate contains
//! zero `unsafe` blocks and zero dynamic heap allocations.

pub mod cspace;
pub mod elf;
pub mod ipc;
pub mod memory;
pub mod sched;

use core::fmt::Write;
use cspace::{CNode, CapObject, Capability};
use memory::{
    CpuSecurityFeatures, PAGE_SIZE, PageFlags, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr,
};
use newos_abi::{QemuExitCode, Rights, SysError};

const USER_STACK_BASE: u64 = 0x0000_7fff_f000_0000;
const USER_STACK_PAGES: u64 = 16; // 64 KiB Ring-3 stack

/// Fixed-size, `no_alloc` boot descriptor handed from `newos-hal` to `newos-kernel-core`.
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    pub hhdm_offset: u64,
    pub untyped: UntypedInventory,
    pub cpu_count: usize,
    pub bsp_lapic_id: u32,
    pub x2apic_enabled: bool,
    pub rsdp_addr: u64,
    pub init_module: Option<&'static [u8]>,
    pub worker_module: Option<&'static [u8]>,
    pub interactive_shell: bool,
    pub board_rpi5: bool,
}

impl BootInfo {
    /// Usable memory rounded down to whole MiB for concise boot diagnostics.
    #[inline]
    pub fn usable_mib(&self) -> u64 {
        self.untyped.total_bytes() / (1024 * 1024)
    }
}

/// Architecture-agnostic, 100% safe platform interface implemented by `newos-hal`.
pub trait HalPlatform: Write {
    type VSpace: VSpaceMapper;

    fn arch_name(&self) -> &'static str;
    fn security_features(&self) -> CpuSecurityFeatures;
    fn current_cpu_id(&self) -> u32;
    fn online_cpus(&self) -> usize;
    fn trigger_breakpoint(&mut self);
    fn breakpoint_count(&self) -> u64;
    fn arm_oneshot_timer(&mut self, ticks: u32);
    fn timer_count(&self) -> u64;
    fn enable_interrupts(&mut self);
    fn disable_interrupts(&mut self);
    fn wait_for_interrupt(&mut self);
    fn vspace_mut(&mut self) -> &mut Self::VSpace;
    fn create_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self::VSpace, SysError>;
    fn probe_mapped_u64(&self, virt: VirtAddr, pattern: u64) -> Result<u64, SysError>;
    fn register_user_process(
        &mut self,
        entry: VirtAddr,
        user_rsp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError>;
    fn start_userspace(&mut self) -> !;
    fn exit(&mut self, code: QemuExitCode) -> !;
}

/// Microkernel boot entry: verify Phases 1–3 + SMP, then load isolated Ring-3 `init` & `worker`.
pub fn boot_early<P: HalPlatform>(platform: &mut P, mut info: BootInfo) -> ! {
    let sec = platform.security_features();
    let _ = writeln!(
        platform,
        "[newos] booting pure seL4-style 64-bit Rust microkernel (arch={}, no_alloc, forbid_unsafe_core)",
        platform.arch_name(),
    );
    let _ = writeln!(
        platform,
        "[newos] HHDM={:#018x}, RAM={} MiB ({} untyped regions), SMP={}/{} CPUs online, x2APIC={}, RSDP={:#x}",
        info.hhdm_offset,
        info.usable_mib(),
        info.untyped.region_count(),
        platform.online_cpus(),
        info.cpu_count,
        info.x2apic_enabled,
        info.rsdp_addr,
    );
    let _ = writeln!(
        platform,
        "[newos] CPU hardening: WP={}, NXE={}, SMEP={}, SMAP={}, UMIP={} (bsp_cpu_id={})",
        sec.wp,
        sec.nxe,
        sec.smep,
        sec.smap,
        sec.umip,
        platform.current_cpu_id(),
    );

    if platform.online_cpus() != info.cpu_count {
        let _ = writeln!(platform, "[newos] FAIL: SMP secondary cores did not come online");
        platform.exit(QemuExitCode::Failed);
    }

    // Phase 1: IDT #BP & x2APIC oneshot timer verification
    let before_bp = platform.breakpoint_count();
    platform.trigger_breakpoint();
    if platform.breakpoint_count() != before_bp + 1 {
        let _ = writeln!(platform, "[newos] FAIL: IDT #BP self-check failed");
        platform.exit(QemuExitCode::Failed);
    }

    let before_timer = platform.timer_count();
    platform.arm_oneshot_timer(250_000);
    platform.enable_interrupts();
    while platform.timer_count() == before_timer {
        platform.wait_for_interrupt();
    }
    platform.disable_interrupts();
    let _ = writeln!(
        platform,
        "[newos] phase-1 HAL, SMP & x2APIC self-check: OK (cpus={}, bp={}, timer={})",
        platform.online_cpus(),
        platform.breakpoint_count(),
        platform.timer_count(),
    );

    // Phase 2: Pure seL4 Untyped retype + 4-level VSpace map / probe / unmap verification
    if let Err(err) = verify_phase2_memory(platform, &mut info.untyped) {
        let _ = writeln!(platform, "[newos] FAIL: phase-2 memory self-check: {err:?}");
        platform.exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        platform,
        "[newos] phase-2 Untyped & 4-level VSpace self-check: OK (retyped_frames={}, remaining={} MiB)",
        info.untyped.retyped_frames(),
        info.untyped.remaining_bytes() / (1024 * 1024),
    );

    // Phase 3: Pure seL4 CSpace, Untyped retype, badged minting & transitive CDT revoke
    match verify_phase3_cspace(&mut info.untyped) {
        Ok((occupied, revoked)) => {
            let _ = writeln!(
                platform,
                "[newos] phase-3 CSpace & CDT self-check: OK (active_caps={occupied}, revoked={revoked})",
            );
        }
        Err(err) => {
            let _ = writeln!(platform, "[newos] FAIL: phase-3 CSpace self-check: {err:?}");
            platform.exit(QemuExitCode::Failed);
        }
    }

    // Phase 4+: Load `init` (PID 0) and `worker` (PID 1) into SEPARATE isolated Ring-3 VSpaces!
    let Some(init_bytes) = info.init_module else {
        let _ = writeln!(platform, "[newos] FAIL: missing Limine boot module `newos-init`");
        platform.exit(QemuExitCode::Failed);
    };
    let Some(worker_bytes) = info.worker_module else {
        let _ = writeln!(platform, "[newos] FAIL: missing Limine boot module `newos-worker`");
        platform.exit(QemuExitCode::Failed);
    };

    match spawn_isolated_process(platform, "init", init_bytes, &mut info.untyped)
        .and_then(|_| spawn_isolated_process(platform, "worker", worker_bytes, &mut info.untyped))
    {
        Ok(()) => platform.start_userspace(),
        Err(err) => {
            let _ = writeln!(platform, "[newos] FAIL: failed to spawn Ring-3 processes: {err:?}");
            platform.exit(QemuExitCode::Failed);
        }
    }
}

fn spawn_isolated_process<P: HalPlatform>(
    platform: &mut P,
    name: &str,
    elf_bytes: &[u8],
    untyped: &mut UntypedInventory,
) -> Result<(), SysError> {
    let mut user_vspace = platform.create_user_vspace(untyped)?;
    let (entry, user_rsp, segs) = load_elf64_into_vspace(&mut user_vspace, elf_bytes, untyped)?;
    let root = user_vspace.root_phys();
    let pid = platform.register_user_process(entry, user_rsp, root)?;
    let _ = writeln!(
        platform,
        "[newos] spawned Ring-3 `{name}` (pid={pid}, cr3={:#018x}, entry={:#018x}, segs={segs})",
        root.raw(),
        entry.raw(),
    );
    Ok(())
}

/// Pure `#![forbid(unsafe_code)]`, `no_alloc` ELF64 loader mapping a binary into an isolated `VSpace`.
fn load_elf64_into_vspace<V: VSpaceMapper>(
    vspace: &mut V,
    elf_bytes: &[u8],
    untyped: &mut UntypedInventory,
) -> Result<(VirtAddr, VirtAddr, usize), SysError> {
    let parsed = elf::parse_elf64(elf_bytes)?;

    for seg in parsed.segments() {
        let seg_start = seg.vaddr;
        let seg_end = seg_start
            .checked_add(seg.mem_size)
            .ok_or(SysError::InvalidArgument)?;
        let first_page = seg_start & !memory::PAGE_MASK;
        let last_page = (seg_end.saturating_sub(1)) & !memory::PAGE_MASK;

        let mut page_vaddr = first_page;
        while page_vaddr <= last_page {
            let frame = untyped.retype_frame()?;
            vspace.zero_frame(&frame);

            let page_end = page_vaddr + PAGE_SIZE;
            let file_vaddr_end = seg_start + seg.file_size as u64;
            let copy_start = page_vaddr.max(seg_start);
            let copy_end = page_end.min(file_vaddr_end);

            if copy_end > copy_start {
                let dst_off = (copy_start - page_vaddr) as usize;
                let src_off = seg.file_offset + (copy_start - seg_start) as usize;
                let copy_len = (copy_end - copy_start) as usize;
                let src_slice = elf_bytes
                    .get(src_off..src_off + copy_len)
                    .ok_or(SysError::InvalidArgument)?;
                vspace.write_frame_bytes(&frame, dst_off, src_slice)?;
            }

            let virt = VirtAddr::new_page_aligned(page_vaddr)?;
            vspace.map_4k(virt, frame, seg.flags, untyped)?;
            page_vaddr += PAGE_SIZE;
        }
    }

    // Map 16 KiB Ring-3 stack (USER | RW | NX)
    let stack_flags = PageFlags::new_wx(true, false, true, false)?;
    for page in 0..USER_STACK_PAGES {
        let frame = untyped.retype_frame()?;
        vspace.zero_frame(&frame);
        let virt = VirtAddr::new_page_aligned(USER_STACK_BASE + page * PAGE_SIZE)?;
        vspace.map_4k(virt, frame, stack_flags, untyped)?;
    }

    let user_rsp = VirtAddr::new_canonical(USER_STACK_BASE + USER_STACK_PAGES * PAGE_SIZE)?;
    Ok((parsed.entry, user_rsp, parsed.segment_count()))
}

fn verify_phase2_memory<P: HalPlatform>(
    platform: &mut P,
    untyped: &mut UntypedInventory,
) -> Result<(), SysError> {
    let test_virt = VirtAddr::new_page_aligned(0xffff_a000_0000_0000)?;
    let frame = untyped.retype_frame()?;
    let expected_phys = frame.start_addr();

    platform
        .vspace_mut()
        .map_4k(test_virt, frame, PageFlags::KERNEL_RW, untyped)?;

    let (translated_phys, translated_flags) = platform
        .vspace_mut()
        .translate(test_virt)
        .ok_or(SysError::InvalidArgument)?;
    if translated_phys != expected_phys || !translated_flags.writable || translated_flags.executable
    {
        return Err(SysError::InvalidArgument);
    }

    let pattern = 0xDEAD_BEEF_CAFE_BABEu64;
    let readback = platform.probe_mapped_u64(test_virt, pattern)?;
    if readback != pattern {
        return Err(SysError::InvalidArgument);
    }

    let reclaimed = platform.vspace_mut().unmap_4k(test_virt)?;
    if reclaimed.start_addr() != expected_phys || platform.vspace_mut().translate(test_virt).is_some()
    {
        return Err(SysError::InvalidArgument);
    }

    Ok(())
}

fn verify_phase3_cspace(untyped: &mut UntypedInventory) -> Result<(usize, usize), SysError> {
    let mut cnode = CNode::<64>::new();

    let untyped_cap = cnode.insert_root(Capability::new(
        CapObject::Untyped { region_index: 0 },
        Rights::ALL,
    ))?;
    let ep_cap = cnode.insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))?;

    let frame_cap = cnode.retype_frame_from(untyped_cap, untyped)?;
    let _ = cnode.lookup(frame_cap, Rights::READ.union(Rights::WRITE))?;

    let child_slot = cnode.find_free_slot()?;
    let child = cnode.mint(
        ep_cap,
        child_slot,
        Rights::READ.union(Rights::GRANT),
        Some(0xC0DE),
    )?;
    let grandchild_slot = cnode.find_free_slot()?;
    let grandchild = cnode.copy(child, grandchild_slot)?;

    if cnode.lookup(grandchild, Rights::WRITE) != Err(SysError::InsufficientRights) {
        return Err(SysError::InvalidArgument);
    }
    if cnode.lookup(grandchild, Rights::READ)?.badge != 0xC0DE {
        return Err(SysError::InvalidArgument);
    }

    let revoked = cnode.revoke(ep_cap)?;
    if revoked != 2 {
        return Err(SysError::InvalidArgument);
    }
    if cnode.lookup(grandchild, Rights::NONE) != Err(SysError::InvalidCapability) {
        return Err(SysError::InvalidArgument);
    }

    Ok((cnode.occupied_count(), revoked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_mib_calculation() {
        let mut untyped = UntypedInventory::new();
        assert!(untyped.push_raw_region(0x10_0000, 256 * 1024 * 1024));
        let info = BootInfo {
            hhdm_offset: 0xffff_8000_0000_0000,
            untyped,
            cpu_count: 2,
            bsp_lapic_id: 0,
            x2apic_enabled: true,
            rsdp_addr: 0x000e_0000,
            init_module: None,
            worker_module: None,
            interactive_shell: false,
            board_rpi5: false,
        };
        assert_eq!(info.usable_mib(), 256);
    }
}
