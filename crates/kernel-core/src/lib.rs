#![no_std]

//! Microkernel core.
//!
//! All hardware interaction is injected via safe traits; this crate contains
//! zero `unsafe` blocks and zero dynamic heap allocations.

#[cfg(feature = "acpi")]
pub mod acpi;
pub mod cspace;
#[cfg(feature = "userspace")]
pub mod elf;
pub mod ipc;
pub mod memory;
pub mod sched;

pub use ipc::{IpcMessage, IpcStats, KernelIpcState};

use core::fmt::Write;
use cspace::{CNode, CapObject, Capability};
#[cfg(feature = "userspace")]
use memory::PAGE_SIZE;
use memory::{CpuSecurityFeatures, PageFlags, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr};
use newos_abi::{Rights, ShutdownStatus, SysError};

#[cfg(feature = "userspace")]
const USER_STACK_BASE: u64 = 0x0000_7fff_f000_0000;
#[cfg(feature = "userspace")]
const USER_STACK_PAGES: u64 = 16; // 64 KiB EL0 data stack
/// 1 MiB EL0 data stack for daemons (`newos-netd`, `newos-keyd`, `newos-sshd`)
/// running NIST Level 5 ML-DSA-87 / ML-KEM-1024 lattice math.
pub const USER_PQ_STACK_PAGES: u64 = 256;
#[cfg(feature = "userspace")]
const USER_SHADOW_STACK_BASE: u64 = 0x0000_7fff_e000_0000;
#[cfg(feature = "userspace")]
const USER_SHADOW_STACK_PAGES: u64 = 2; // 8 KiB EL0 Shadow Call Stack (`x18`, grows upward)

/// Linear UEFI GOP / Limine framebuffer geometry discovered at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

/// Fixed-size boot descriptor handed from `newos-hal` to `newos-kernel-core`.
#[derive(Debug, Clone)]
pub struct BootInfo {
    pub hhdm_offset: u64,
    pub kernel_virt_base: u64,
    pub untyped: UntypedInventory,
    pub cpu_count: usize,
    pub rsdp_addr: u64,
    pub framebuffer: Option<FramebufferInfo>,
    pub init_module: Option<&'static [u8]>,
    pub worker_module: Option<&'static [u8]>,
    pub netd_module: Option<&'static [u8]>,
    pub keyd_module: Option<&'static [u8]>,
    pub sshd_module: Option<&'static [u8]>,
    pub interactive_shell: bool,
    pub qemu_virt: bool,
}

impl BootInfo {
    /// Usable memory rounded down to whole MiB for concise boot diagnostics.
    #[inline]
    pub fn usable_mib(&self) -> u64 {
        self.untyped.total_bytes() / (1024 * 1024)
    }
}

/// Explicit bootstrap process role used to assign least-privilege capabilities independently of
/// spawn order / PID (`N5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRole {
    Init,
    Worker,
    Netd,
    Keyd,
    Sshd,
}

/// Architecture-agnostic platform interface implemented by `newos-hal`.
pub trait HalPlatform: Write {
    type VSpace: VSpaceMapper;

    fn arch_name(&self) -> &'static str;
    fn board_name(&self) -> &'static str {
        "generic"
    }
    fn security_features(&self) -> CpuSecurityFeatures;
    /// Return packed ARMv8.2-A ISA feature bitmask + PA width + D-cache line size (`newos_abi::cpu_isa`).
    fn cpu_isa_features(&self) -> u64 {
        0
    }
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
        role: ProcessRole,
        entry: VirtAddr,
        user_sp: VirtAddr,
        user_shadow_sp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError>;
    /// Return a 64-bit entropy word for ASLR stack/PIE randomization (defaults to 0 in mocks).
    fn random_u64(&mut self) -> u64 {
        0
    }
    /// Hand remaining bootstrap `UntypedInventory` to the HAL for runtime `MapPage`/`UnmapPage` syscalls.
    fn install_runtime_untyped(&mut self, _untyped: UntypedInventory) {}
    fn start_userspace(&mut self) -> !;
    fn exit(&mut self, code: ShutdownStatus) -> !;
}

/// Microkernel boot entry: verify Phases 1–3 + SMP, then load isolated EL0 `init` & `worker`.
pub fn boot_early<P: HalPlatform>(platform: &mut P, mut info: BootInfo) -> ! {
    let sec = platform.security_features();
    let board = if platform.board_name() != "generic" {
        platform.board_name()
    } else if info.qemu_virt {
        "qemu-virt-test"
    } else {
        "rpi5-16gb"
    };
    let _ = writeln!(
        platform,
        "[newos] booting microkernel (arch={}, board={}, sched={}, smp={}, userspace={}, elf_attest={}, acpi={})",
        platform.arch_name(),
        board,
        sched::ACTIVE_SCHED_POLICY.as_str(),
        cfg!(feature = "smp"),
        cfg!(feature = "userspace"),
        cfg!(feature = "elf-attestation"),
        cfg!(feature = "acpi"),
    );
    let _ = writeln!(
        platform,
        "[newos] HHDM={:#018x}, KASLR_BASE={:#018x}, RAM={} MiB ({} untyped regions), SMP={}/{} CPUs online, RSDP={:#x}",
        info.hhdm_offset,
        info.kernel_virt_base,
        info.usable_mib(),
        info.untyped.region_count(),
        platform.online_cpus(),
        info.cpu_count,
        info.rsdp_addr,
    );
    let _ = writeln!(
        platform,
        "[newos] CPU hardening: PXN={}, UXN={}, PAN={}, W^X={}, SSBS={}, CSV2={}, CSV3={} (bsp_cpu_id={})",
        sec.pxn,
        sec.uxn,
        sec.pan,
        sec.wx_enforced,
        sec.ssbs,
        sec.csv2,
        sec.csv3,
        platform.current_cpu_id(),
    );
    let isa = platform.cpu_isa_features();
    if isa != 0 {
        use newos_abi::cpu_isa;
        let _ = writeln!(
            platform,
            "[newos] CPU ISA (ARMv8.2-A): PA={}b dcache={}B LSE={} CRC32={} AES={} PMULL={} SHA1={} SHA256={} DOTPROD={} FP16={} ASIMD={} PMUv3={}",
            cpu_isa::pa_bits(isa),
            cpu_isa::dcache_line_bytes(isa),
            (isa & cpu_isa::LSE) != 0,
            (isa & cpu_isa::CRC32) != 0,
            (isa & cpu_isa::AES) != 0,
            (isa & cpu_isa::PMULL) != 0,
            (isa & cpu_isa::SHA1) != 0,
            (isa & cpu_isa::SHA256) != 0,
            (isa & cpu_isa::DOTPROD) != 0,
            (isa & cpu_isa::FP16) != 0,
            (isa & cpu_isa::ASIMD) != 0,
            (isa & cpu_isa::PMUV3) != 0,
        );
    }

    if let Some(fb) = info.framebuffer {
        let _ = writeln!(
            platform,
            "[newos] UEFI GOP Framebuffer: {}x{} @ {}bpp pitch={} phys={:#x}",
            fb.width, fb.height, fb.bpp, fb.pitch, fb.phys_addr,
        );
    }

    #[cfg(feature = "smp")]
    if platform.online_cpus() != info.cpu_count {
        let _ = writeln!(
            platform,
            "[newos] FAIL: SMP secondary cores did not come online"
        );
        platform.exit(ShutdownStatus::Failed);
    }

    // Phase 1: VBAR_EL1 #BRK & ARM Generic Timer verification
    let before_bp = platform.breakpoint_count();
    platform.trigger_breakpoint();
    if platform.breakpoint_count() != before_bp + 1 {
        let _ = writeln!(platform, "[newos] FAIL: VBAR_EL1 brk #0 self-check failed");
        platform.exit(ShutdownStatus::Failed);
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
        "[newos] phase-1 HAL, SMP & Generic Timer self-check: OK (cpus={}, bp={}, timer={})",
        platform.online_cpus(),
        platform.breakpoint_count(),
        platform.timer_count(),
    );

    // Phase 2: Untyped retype + 4-level VSpace map / probe / unmap verification
    if let Err(err) = verify_phase2_memory(platform, &mut info.untyped) {
        let _ = writeln!(platform, "[newos] FAIL: phase-2 memory self-check: {err:?}");
        platform.exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        platform,
        "[newos] phase-2 Untyped & 4-level VSpace self-check: OK (retyped_frames={}, remaining={} MiB)",
        info.untyped.retyped_frames(),
        info.untyped.remaining_bytes() / (1024 * 1024),
    );

    // Phase 3: CSpace, Untyped retype, badged minting & transitive CDT revoke
    match verify_phase3_cspace(&mut info.untyped) {
        Ok((occupied, revoked)) => {
            let _ = writeln!(
                platform,
                "[newos] phase-3 CSpace & CDT self-check: OK (active_caps={occupied}, revoked={revoked})",
            );
        }
        Err(err) => {
            let _ = writeln!(platform, "[newos] FAIL: phase-3 CSpace self-check: {err:?}");
            platform.exit(ShutdownStatus::Failed);
        }
    }

    // Phase 4+: Pure EL1 tinykernel mode (no userspace) OR optional EL0 module bootstrap.
    #[cfg(not(feature = "userspace"))]
    {
        let _ = writeln!(
            platform,
            "[newos] pure EL1 tinykernel boot complete (userspace=false, sched={}, smp={})",
            sched::ACTIVE_SCHED_POLICY.as_str(),
            cfg!(feature = "smp"),
        );
        if info.qemu_virt {
            platform.exit(ShutdownStatus::Success)
        } else {
            loop {
                platform.wait_for_interrupt();
            }
        }
    }

    #[cfg(feature = "userspace")]
    {
        let Some(init_bytes) = info.init_module else {
            let _ = writeln!(
                platform,
                "[newos] no EL0 init module supplied; pure EL1 kernel boot complete"
            );
            if info.qemu_virt {
                platform.exit(ShutdownStatus::Success)
            } else {
                loop {
                    platform.wait_for_interrupt();
                }
            }
        };

        let spawn_result = spawn_isolated_process(
            platform,
            ProcessRole::Init,
            "init",
            init_bytes,
            &mut info.untyped,
        )
        .and_then(|_| {
            if let Some(worker_bytes) = info.worker_module {
                spawn_isolated_process(
                    platform,
                    ProcessRole::Worker,
                    "worker",
                    worker_bytes,
                    &mut info.untyped,
                )?;
            }
            if let Some(netd) = info.netd_module {
                spawn_isolated_process(
                    platform,
                    ProcessRole::Netd,
                    "newos-netd",
                    netd,
                    &mut info.untyped,
                )?;
            }
            if let Some(keyd) = info.keyd_module {
                spawn_isolated_process(
                    platform,
                    ProcessRole::Keyd,
                    "newos-keyd",
                    keyd,
                    &mut info.untyped,
                )?;
            }
            if let Some(sshd) = info.sshd_module {
                spawn_isolated_process(
                    platform,
                    ProcessRole::Sshd,
                    "newos-sshd",
                    sshd,
                    &mut info.untyped,
                )?;
            }
            Ok(())
        });

        match spawn_result {
            Ok(()) => {
                platform.install_runtime_untyped(info.untyped);
                platform.start_userspace()
            }
            Err(err) => {
                let _ = writeln!(
                    platform,
                    "[newos] FAIL: failed to spawn EL0 processes: {err:?}"
                );
                platform.exit(ShutdownStatus::Failed);
            }
        }
    }
}

#[cfg(feature = "userspace")]
fn spawn_isolated_process<P: HalPlatform>(
    platform: &mut P,
    role: ProcessRole,
    name: &str,
    elf_bytes: &[u8],
    untyped: &mut UntypedInventory,
) -> Result<(), SysError> {
    #[cfg(feature = "elf-attestation")]
    let sha_prefix = newos_crypto::sha3::digest_prefix_u64(elf_bytes);
    #[cfg(not(feature = "elf-attestation"))]
    let sha_prefix: u64 = 0;
    let entropy = platform.random_u64();
    let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
    let pie_base = 0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
    let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
    let mut user_vspace = platform.create_user_vspace(untyped)?;
    let stack_pages = if matches!(
        role,
        ProcessRole::Netd | ProcessRole::Keyd | ProcessRole::Sshd
    ) {
        USER_PQ_STACK_PAGES
    } else {
        USER_STACK_PAGES
    };
    let (entry, user_sp, user_shadow_sp, segs) = load_elf64_into_vspace(
        &mut user_vspace,
        elf_bytes,
        untyped,
        pie_base,
        stack_slide,
        shadow_slide,
        stack_pages,
    )?;
    let root = user_vspace.root_phys();
    let pid = platform.register_user_process(role, entry, user_sp, user_shadow_sp, root)?;
    let _ = writeln!(
        platform,
        "[newos] spawned EL0 `{name}` (pid={pid}, role={role:?}, ttbr0={:#018x}, entry={:#018x}, sp={:#018x}, scs={:#018x}, segs={segs}, measured_sha3_512={sha_prefix:#018x})",
        root.raw(),
        entry.raw(),
        user_sp.raw(),
        user_shadow_sp.raw(),
    );
    Ok(())
}

/// ELF64 loader mapping an `ET_EXEC` or PIE `ET_DYN`
/// binary into an isolated `VSpace` with ASLR code/stack/SCS slides and `R_AARCH64_RELATIVE` relocations.
#[cfg(feature = "userspace")]
fn load_elf64_into_vspace<V: VSpaceMapper>(
    vspace: &mut V,
    elf_bytes: &[u8],
    untyped: &mut UntypedInventory,
    pie_base: u64,
    stack_slide: u64,
    shadow_slide: u64,
    stack_pages: u64,
) -> Result<(VirtAddr, VirtAddr, VirtAddr, usize), SysError> {
    let parsed = elf::parse_elf64_with_base(elf_bytes, pie_base)?;

    for seg in parsed.segments() {
        if seg.mem_size == 0 {
            continue;
        }
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

            let page_end = page_vaddr.saturating_add(PAGE_SIZE);
            let file_vaddr_end = seg_start.saturating_add(seg.file_size as u64);
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
            match page_vaddr.checked_add(PAGE_SIZE) {
                Some(next) => page_vaddr = next,
                None => break,
            }
        }
    }

    // Apply `R_AARCH64_RELATIVE` relocations for PIE (`ET_DYN`) binaries before entering EL0.
    if parsed.is_pie {
        parsed.for_each_relative_reloc(elf_bytes, |reloc| {
            let target_va = parsed
                .load_base
                .checked_add(reloc.offset)
                .ok_or(SysError::InvalidArgument)?;
            let va = VirtAddr::new_canonical(target_va)?;
            let (pa, flags) = vspace.translate(va).ok_or(SysError::InvalidArgument)?;
            if !flags.user || !flags.writable {
                return Err(SysError::InsufficientRights);
            }
            let page_pa = PhysAddr::new(pa.raw() & !memory::PAGE_MASK);
            let page_off = (pa.raw() & memory::PAGE_MASK) as usize;
            let frame = memory::PhysFrame::from_aligned(page_pa)?;
            let relocated = (parsed.load_base as i64).wrapping_add(reloc.addend) as u64;
            vspace.write_frame_bytes(&frame, page_off, &relocated.to_le_bytes())
        })?;
    }

    // Map EL0 data stack (USER | RW | UXN/PXN) with ASLR slide and an unmapped 4 KiB guard page
    // immediately below `stack_base` so any stack overflow traps cleanly.
    let stack_base = USER_STACK_BASE.saturating_sub(stack_slide & !memory::PAGE_MASK);
    let guard_va = VirtAddr::new_page_aligned(stack_base.saturating_sub(PAGE_SIZE))?;
    if vspace.translate(guard_va).is_some() {
        return Err(SysError::SlotOccupied);
    }
    let stack_flags = PageFlags::new_wx(true, false, true, false)?;
    for page in 0..stack_pages {
        let frame = untyped.retype_frame()?;
        vspace.zero_frame(&frame);
        let virt = VirtAddr::new_page_aligned(stack_base + page * PAGE_SIZE)?;
        vspace.map_4k(virt, frame, stack_flags, untyped)?;
    }

    let user_sp = VirtAddr::new_canonical(stack_base + stack_pages * PAGE_SIZE)?;

    // Map 8 KiB EL0 Shadow Call Stack (`x18`, grows upward, USER | RW | UXN/PXN) with ASLR slide
    let shadow_base = USER_SHADOW_STACK_BASE.saturating_sub(shadow_slide & !memory::PAGE_MASK);
    for page in 0..USER_SHADOW_STACK_PAGES {
        let frame = untyped.retype_frame()?;
        vspace.zero_frame(&frame);
        let virt = VirtAddr::new_page_aligned(shadow_base + page * PAGE_SIZE)?;
        vspace.map_4k(virt, frame, stack_flags, untyped)?;
    }
    let user_shadow_sp = VirtAddr::new_canonical(shadow_base)?;

    Ok((
        parsed.entry,
        user_sp,
        user_shadow_sp,
        parsed.segment_count(),
    ))
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
    if reclaimed.start_addr() != expected_phys
        || platform.vspace_mut().translate(test_virt).is_some()
    {
        return Err(SysError::InvalidArgument);
    }
    let _ = untyped.reclaim_frame(reclaimed);

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
            kernel_virt_base: 0xffff_ffff_8000_0000,
            untyped,
            cpu_count: 4,
            rsdp_addr: 0x000e_0000,
            framebuffer: None,
            init_module: None,
            worker_module: None,
            netd_module: None,
            keyd_module: None,
            sshd_module: None,
            interactive_shell: false,
            qemu_virt: false,
        };
        assert_eq!(info.usable_mib(), 256);
    }
}
