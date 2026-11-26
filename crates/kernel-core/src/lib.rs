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

use core::fmt::{self, Write};
use cspace::{CNode, CapObject, Capability};
use memory::{CpuSecurityFeatures, PageFlags, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr};
#[cfg(feature = "userspace")]
use memory::{PAGE_SIZE, PageAccess, PageCachePolicy, PagePrivilege};
use newos_abi::{Rights, ShutdownStatus, SysError};

#[cfg(feature = "userspace")]
const USER_STACK_BASE: u64 = 0x0000_7fff_f000_0000;
#[cfg(feature = "userspace")]
pub const USER_STACK_PAGES: u64 = 16; // 64 KiB EL0 data stack
/// 2 MiB EL0 data stack for protection domains (`newos-net-pd`, `newos-key-pd`, `newos-ssh-pd`)
/// running NIST Level 5 ML-DSA-87 / ML-KEM-1024 lattice math (gives headroom in unoptimized debug builds).
pub const USER_PQ_STACK_PAGES: u64 = 512;
#[cfg(feature = "userspace")]
const USER_SHADOW_STACK_BASE: u64 = 0x0000_7fff_e000_0000;
#[cfg(feature = "userspace")]
const USER_SHADOW_STACK_PAGES: u64 = 2; // 8 KiB EL0 Shadow Call Stack (`x18`, grows upward)

/// Linear UEFI GOP / Limine framebuffer geometry discovered at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub supervisor_module: Option<&'static [u8]>,
    pub shell_module: Option<&'static [u8]>,
    pub worker_module: Option<&'static [u8]>,
    pub net_module: Option<&'static [u8]>,
    pub key_module: Option<&'static [u8]>,
    pub ssh_module: Option<&'static [u8]>,
    pub interactive_shell: bool,
    pub qemu_virt: bool,
}

impl BootInfo {
    /// Usable memory rounded down to whole MiB for concise boot diagnostics.
    #[inline]
    #[must_use]
    pub const fn usable_mib(&self) -> u64 {
        self.untyped.total_bytes() / (1024 * 1024)
    }
}

/// Explicit bootstrap protection domain role used to assign least-privilege capabilities
/// independently of spawn order / PD ID (`N5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainRole {
    Supervisor,
    Shell,
    Worker,
    Net,
    Key,
    Ssh,
}

impl DomainRole {
    #[inline]
    #[must_use]
    pub const fn to_abi(self) -> newos_abi::DomainRoleId {
        match self {
            Self::Supervisor => newos_abi::DomainRoleId::Supervisor,
            Self::Shell => newos_abi::DomainRoleId::Shell,
            Self::Worker => newos_abi::DomainRoleId::Worker,
            Self::Net => newos_abi::DomainRoleId::Net,
            Self::Key => newos_abi::DomainRoleId::Key,
            Self::Ssh => newos_abi::DomainRoleId::Ssh,
        }
    }

    #[inline]
    #[must_use]
    pub const fn from_abi(id: newos_abi::DomainRoleId) -> Self {
        match id {
            newos_abi::DomainRoleId::Supervisor => Self::Supervisor,
            newos_abi::DomainRoleId::Shell => Self::Shell,
            newos_abi::DomainRoleId::Worker => Self::Worker,
            newos_abi::DomainRoleId::Net => Self::Net,
            newos_abi::DomainRoleId::Key => Self::Key,
            newos_abi::DomainRoleId::Ssh => Self::Ssh,
        }
    }
}

impl fmt::Display for DomainRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_abi().fmt(f)
    }
}

impl From<DomainRole> for newos_abi::DomainRoleId {
    #[inline]
    fn from(role: DomainRole) -> Self {
        role.to_abi()
    }
}

impl From<newos_abi::DomainRoleId> for DomainRole {
    #[inline]
    fn from(id: newos_abi::DomainRoleId) -> Self {
        Self::from_abi(id)
    }
}

/// Architecture-agnostic platform interface implemented by `newos-hal`.
pub trait HalPlatform: Write {
    type VSpace: VSpaceMapper;

    fn arch_name(&self) -> &'static str;
    /// Optional platform board identifier; returns `None` when not explicitly configured.
    fn board_name(&self) -> Option<&'static str> {
        None
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

    /// Allocate and initialize a fresh EL0 `VSpace` root from `untyped`.
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if `untyped` lacks a free 4 KiB frame for the root table.
    fn create_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self::VSpace, SysError>;

    /// Write and read back `pattern` at mapped kernel virtual address `virt`.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `virt` is not mapped or probe access fails.
    fn probe_mapped_u64(&self, virt: VirtAddr, pattern: u64) -> Result<u64, SysError>;

    /// Register a newly constructed EL0 protection domain with the HAL scheduler and return its PD ID.
    ///
    /// # Errors
    /// - [`SysError::OutOfMemory`] if the HAL domain table is full.
    /// - [`SysError::InvalidArgument`] if entry, stack, or `vspace_root` parameters are invalid.
    fn register_domain(
        &mut self,
        role: DomainRole,
        entry: VirtAddr,
        user_sp: VirtAddr,
        user_shadow_sp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError>;
    /// Return a 64-bit entropy word for ASLR stack/PIE randomization (defaults to 0 in mocks).
    fn random_u64(&mut self) -> u64 {
        0
    }
    /// Record an immutable boot module ELF slice for runtime `DomainRespawn` supervision.
    fn register_boot_module(&mut self, _role: DomainRole, _elf_bytes: &'static [u8]) {}
    /// Hand remaining bootstrap `UntypedInventory` to the HAL for runtime `MapPage`/`UnmapPage` syscalls.
    fn install_runtime_untyped(&mut self, _untyped: UntypedInventory) {}
    fn start_userspace(&mut self) -> !;
    fn exit(&mut self, code: ShutdownStatus) -> !;
}

fn log_boot_banner<P: HalPlatform>(platform: &mut P, info: &BootInfo) {
    let sec = platform.security_features();
    let fallback_board = if info.qemu_virt {
        "qemu-virt-test"
    } else {
        "rpi5-16gb"
    };
    let board = platform.board_name().unwrap_or(fallback_board);
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
}

fn verify_phase1_hal<P: HalPlatform>(platform: &mut P, info: &BootInfo) {
    #[cfg(feature = "smp")]
    if platform.online_cpus() != info.cpu_count {
        let _ = writeln!(
            platform,
            "[newos] FAIL: SMP secondary cores did not come online"
        );
        platform.exit(ShutdownStatus::Failed);
    }
    #[cfg(not(feature = "smp"))]
    let _ = info;

    // VBAR_EL1 #BRK & ARM Generic Timer verification
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
        "[newos] HAL, SMP & timer: OK (cpus={}, bp={}, timer={})",
        platform.online_cpus(),
        platform.breakpoint_count(),
        platform.timer_count(),
    );
}

#[cfg(feature = "userspace")]
fn spawn_all_domains<P: HalPlatform>(
    platform: &mut P,
    supervisor_bytes: &'static [u8],
    info: &mut BootInfo,
) -> Result<(), SysError> {
    spawn_isolated_domain(
        platform,
        DomainRole::Supervisor,
        "newos-supervisor-pd",
        supervisor_bytes,
        &mut info.untyped,
    )?;
    let optional_domains = [
        (DomainRole::Shell, "newos-shell-pd", info.shell_module),
        (DomainRole::Worker, "newos-worker-pd", info.worker_module),
        (DomainRole::Net, "newos-net-pd", info.net_module),
        (DomainRole::Key, "newos-key-pd", info.key_module),
        (DomainRole::Ssh, "newos-ssh-pd", info.ssh_module),
    ];
    for (role, name, module) in optional_domains {
        if let Some(bytes) = module {
            spawn_isolated_domain(platform, role, name, bytes, &mut info.untyped)?;
        }
    }
    Ok(())
}

#[cfg(feature = "userspace")]
fn bootstrap_userspace<P: HalPlatform>(platform: &mut P, mut info: BootInfo) -> ! {
    let Some(supervisor_bytes) = info.supervisor_module else {
        let _ = writeln!(
            platform,
            "[newos] FAIL: userspace feature enabled but no EL0 supervisor-pd module supplied"
        );
        platform.exit(ShutdownStatus::Failed);
    };

    platform.register_boot_module(DomainRole::Supervisor, supervisor_bytes);
    let optional_modules = [
        (DomainRole::Shell, info.shell_module),
        (DomainRole::Worker, info.worker_module),
        (DomainRole::Net, info.net_module),
        (DomainRole::Key, info.key_module),
        (DomainRole::Ssh, info.ssh_module),
    ];
    for (role, module) in optional_modules {
        if let Some(bytes) = module {
            platform.register_boot_module(role, bytes);
        }
    }

    match spawn_all_domains(platform, supervisor_bytes, &mut info) {
        Ok(()) => {
            platform.install_runtime_untyped(info.untyped);
            platform.start_userspace()
        }
        Err(err) => {
            let _ = writeln!(
                platform,
                "[newos] FAIL: failed to spawn EL0 protection domains: {err:?}"
            );
            platform.exit(ShutdownStatus::Failed);
        }
    }
}

/// Microkernel boot entry: verify Phases 1–3 + SMP, then load isolated EL0 protection domains.
pub fn boot_early<P: HalPlatform>(platform: &mut P, mut info: BootInfo) -> ! {
    log_boot_banner(platform, &info);
    verify_phase1_hal(platform, &info);

    // Untyped retype + 4-level VSpace map / probe / unmap verification
    if let Err(err) = verify_phase2_memory(platform, &mut info.untyped) {
        let _ = writeln!(platform, "[newos] FAIL: memory & VSpace: {err:?}");
        platform.exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        platform,
        "[newos] memory & VSpace: OK (retyped_frames={}, remaining={} MiB)",
        info.untyped.retyped_frames(),
        info.untyped.remaining_bytes() / (1024 * 1024),
    );

    // CSpace, Untyped retype, badged minting & transitive CDT revoke
    match verify_phase3_cspace(&mut info.untyped) {
        Ok((occupied, revoked)) => {
            let _ = writeln!(
                platform,
                "[newos] CSpace & CDT: OK (active_caps={occupied}, revoked={revoked})",
            );
        }
        Err(err) => {
            let _ = writeln!(platform, "[newos] FAIL: CSpace & CDT: {err:?}");
            platform.exit(ShutdownStatus::Failed);
        }
    }

    // EL1-only mode (no userspace) OR EL0 module bootstrap.
    #[cfg(not(feature = "userspace"))]
    {
        let _ = writeln!(
            platform,
            "[newos] EL1 boot complete (userspace=false, sched={}, smp={})",
            sched::ACTIVE_SCHED_POLICY.as_str(),
            cfg!(feature = "smp"),
        );
        if info.qemu_virt {
            platform.exit(ShutdownStatus::Success);
        }
        loop {
            platform.wait_for_interrupt();
        }
    }

    #[cfg(feature = "userspace")]
    bootstrap_userspace(platform, info)
}

#[cfg(feature = "userspace")]
fn spawn_isolated_domain<P: HalPlatform>(
    platform: &mut P,
    role: DomainRole,
    name: &str,
    elf_bytes: &[u8],
    untyped: &mut UntypedInventory,
) -> Result<(), SysError> {
    #[cfg(feature = "elf-attestation")]
    let sha_prefix = Some(newos_crypto::sha3::digest_prefix_u64(elf_bytes));
    #[cfg(not(feature = "elf-attestation"))]
    let sha_prefix: Option<u64> = None;
    let entropy = platform.random_u64();
    let stack_slide = (entropy & 0xFF) * PAGE_SIZE;
    let pie_base = 0x0040_0000u64 + (((entropy >> 8) & 0xFF) * PAGE_SIZE);
    let shadow_slide = ((entropy >> 16) & 0xFF) * PAGE_SIZE;
    let mut user_vspace = platform.create_user_vspace(untyped)?;
    let stack_pages = if matches!(role, DomainRole::Net | DomainRole::Key | DomainRole::Ssh) {
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
    let pd_id = platform.register_domain(role, entry, user_sp, user_shadow_sp, root)?;
    if let Some(digest) = sha_prefix {
        let _ = writeln!(
            platform,
            "[newos] spawned EL0 `{name}` (pd={pd_id}, role={role:?}, ttbr0={:#018x}, entry={:#018x}, sp={:#018x}, scs={:#018x}, segs={segs}, measured_sha3_512={digest:#018x})",
            root.raw(),
            entry.raw(),
            user_sp.raw(),
            user_shadow_sp.raw(),
        );
    } else {
        let _ = writeln!(
            platform,
            "[newos] spawned EL0 `{name}` (pd={pd_id}, role={role:?}, ttbr0={:#018x}, entry={:#018x}, sp={:#018x}, scs={:#018x}, segs={segs})",
            root.raw(),
            entry.raw(),
            user_sp.raw(),
            user_shadow_sp.raw(),
        );
    }
    Ok(())
}

/// ELF64 loader mapping an `ET_EXEC` or PIE `ET_DYN`
/// binary into an isolated `VSpace` with ASLR code/stack/SCS slides and `R_AARCH64_RELATIVE` relocations.
///
/// # Errors
/// - [`SysError::InvalidArgument`] if the ELF image, segment bounds, relocations, or canonical addresses are invalid.
/// - [`SysError::Unsupported`] if the ELF image is not a 64-bit `AArch64` `ET_EXEC`/`ET_DYN` binary.
/// - [`SysError::InsufficientRights`] if a PIE relocation targets a non-writable or non-user page.
/// - [`SysError::SlotOccupied`] if the stack guard page is already mapped.
/// - [`SysError::OutOfMemory`] if `untyped` cannot supply frames or page tables.
#[cfg(feature = "userspace")]
pub fn load_elf64_into_vspace<V: VSpaceMapper>(
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
                let dst_off = usize::try_from(copy_start - page_vaddr)
                    .map_err(|_| SysError::InvalidArgument)?;
                let src_delta = usize::try_from(copy_start - seg_start)
                    .map_err(|_| SysError::InvalidArgument)?;
                let src_off = seg
                    .file_offset
                    .checked_add(src_delta)
                    .ok_or(SysError::InvalidArgument)?;
                let copy_len = usize::try_from(copy_end - copy_start)
                    .map_err(|_| SysError::InvalidArgument)?;
                let src_end = src_off
                    .checked_add(copy_len)
                    .ok_or(SysError::InvalidArgument)?;
                let src_slice = elf_bytes
                    .get(src_off..src_end)
                    .ok_or(SysError::InvalidArgument)?;
                vspace.write_frame_bytes(&frame, dst_off, src_slice)?;
            }

            let virt = VirtAddr::new_page_aligned(page_vaddr)?;
            vspace.map_4k(virt, frame, seg.flags, untyped)?;
            let Some(next) = page_vaddr.checked_add(PAGE_SIZE) else {
                break;
            };
            page_vaddr = next;
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
            let relocated = parsed.load_base.wrapping_add_signed(reloc.addend);
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
    let stack_flags = PageFlags::new(
        PageAccess::ReadWrite,
        PagePrivilege::User,
        PageCachePolicy::NormalCacheable,
    );
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
            supervisor_module: None,
            shell_module: None,
            worker_module: None,
            net_module: None,
            key_module: None,
            ssh_module: None,
            interactive_shell: false,
            qemu_virt: false,
        };
        assert_eq!(info.usable_mib(), 256);
    }

    #[test]
    fn domain_role_from_into_display_round_trips() {
        struct Buf([u8; 32], usize);
        impl Write for Buf {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let bytes = s.as_bytes();
                let n = bytes.len().min(self.0.len() - self.1);
                self.0[self.1..self.1 + n].copy_from_slice(&bytes[..n]);
                self.1 += n;
                Ok(())
            }
        }

        let roles = [
            DomainRole::Supervisor,
            DomainRole::Shell,
            DomainRole::Worker,
            DomainRole::Net,
            DomainRole::Key,
            DomainRole::Ssh,
        ];
        for role in roles {
            let abi: newos_abi::DomainRoleId = role.into();
            assert_eq!(abi, role.to_abi());
            assert_eq!(DomainRole::from(abi), role);
            assert_eq!(DomainRole::from_abi(abi), role);

            let mut role_buf = Buf([0; 32], 0);
            let mut abi_buf = Buf([0; 32], 0);
            write!(&mut role_buf, "{role}").expect("format role");
            write!(&mut abi_buf, "{abi}").expect("format abi");
            assert_eq!(&role_buf.0[..role_buf.1], &abi_buf.0[..abi_buf.1]);
        }
    }

    #[test]
    fn hal_platform_default_board_name_is_none() {
        struct DummyVSpace;
        impl VSpaceMapper for DummyVSpace {
            fn root_phys(&self) -> PhysAddr {
                PhysAddr::new(0)
            }
            fn map_4k(
                &mut self,
                _virt: VirtAddr,
                _frame: memory::PhysFrame,
                _flags: PageFlags,
                _untyped: &mut UntypedInventory,
            ) -> Result<(), SysError> {
                Ok(())
            }
            fn translate(&self, _virt: VirtAddr) -> Option<(PhysAddr, PageFlags)> {
                None
            }
            fn unmap_4k(&mut self, _virt: VirtAddr) -> Result<memory::PhysFrame, SysError> {
                Err(SysError::InvalidArgument)
            }
            fn zero_frame(&self, _frame: &memory::PhysFrame) {}
            fn write_frame_bytes(
                &self,
                _frame: &memory::PhysFrame,
                _offset: usize,
                _src: &[u8],
            ) -> Result<(), SysError> {
                Ok(())
            }
        }

        struct DummyPlatform(DummyVSpace);
        impl Write for DummyPlatform {
            fn write_str(&mut self, _s: &str) -> fmt::Result {
                Ok(())
            }
        }
        impl HalPlatform for DummyPlatform {
            type VSpace = DummyVSpace;
            fn arch_name(&self) -> &'static str {
                "aarch64"
            }
            fn security_features(&self) -> CpuSecurityFeatures {
                CpuSecurityFeatures::default()
            }
            fn current_cpu_id(&self) -> u32 {
                0
            }
            fn online_cpus(&self) -> usize {
                1
            }
            fn trigger_breakpoint(&mut self) {}
            fn breakpoint_count(&self) -> u64 {
                0
            }
            fn arm_oneshot_timer(&mut self, _ticks: u32) {}
            fn timer_count(&self) -> u64 {
                0
            }
            fn enable_interrupts(&mut self) {}
            fn disable_interrupts(&mut self) {}
            fn wait_for_interrupt(&mut self) {}
            fn vspace_mut(&mut self) -> &mut Self::VSpace {
                &mut self.0
            }
            fn create_user_vspace(
                &self,
                _untyped: &mut UntypedInventory,
            ) -> Result<Self::VSpace, SysError> {
                Ok(DummyVSpace)
            }
            fn probe_mapped_u64(&self, _virt: VirtAddr, _pattern: u64) -> Result<u64, SysError> {
                Ok(0)
            }
            fn register_domain(
                &mut self,
                _role: DomainRole,
                _entry: VirtAddr,
                _user_sp: VirtAddr,
                _user_shadow_sp: VirtAddr,
                _vspace_root: PhysAddr,
            ) -> Result<usize, SysError> {
                Ok(0)
            }
            fn start_userspace(&mut self) -> ! {
                unreachable!()
            }
            fn exit(&mut self, _code: ShutdownStatus) -> ! {
                unreachable!()
            }
        }

        let platform = DummyPlatform(DummyVSpace);
        assert_eq!(platform.board_name(), None);
    }
}
