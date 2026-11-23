//! Limine boot protocol requests and response extraction.

use limine::memmap::MEMMAP_USABLE;
use limine::request::{
    ExecutableAddressRequest, ExecutableFileRequest, FramebufferRequest, HhdmRequest,
    MemmapRequest, ModulesRequest, MpRequest, MpResponse, RsdpRequest,
};
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};
use newos_kernel_core::memory::UntypedInventory;
use newos_kernel_core::{BootInfo, FramebufferInfo};

const MP_FLAGS: u64 = 0;

// SAFETY: Limine scans `.requests_start_marker` in the bare-metal ELF image.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests_start_marker"))]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `BaseRevision`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(3);

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `HhdmRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `MemmapRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static MEMORY_MAP_REQUEST: MemmapRequest = MemmapRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `MpRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static MP_REQUEST: MpRequest = MpRequest::new(MP_FLAGS);

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `RsdpRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `ModulesRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static MODULES_REQUEST: ModulesRequest = ModulesRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `ExecutableFileRequest`.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static EXEC_FILE_REQUEST: ExecutableFileRequest = ExecutableFileRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `ExecutableAddressRequest` (KASLR base).
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static EXEC_ADDR_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();

// SAFETY: Limine scans `.requests` in the bare-metal ELF image for `FramebufferRequest` (UEFI GOP).
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests"))]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

// SAFETY: Limine scans `.requests_end_marker` in the bare-metal ELF image.
#[used]
#[cfg_attr(target_os = "none", unsafe(link_section = ".requests_end_marker"))]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Returns `true` if the bootloader supports our requested Limine base revision.
pub fn is_base_revision_supported() -> bool {
    BASE_REVISION.is_supported()
}

/// Expose Limine's Multi-Processing response for SMP secondary core bring-up.
pub fn mp_response() -> Option<&'static MpResponse> {
    MP_REQUEST.response()
}

/// Extract a boot descriptor and bootstrap `UntypedInventory` from Limine.
pub fn boot_info() -> BootInfo {
    // If Limine fails to provide an HHDM response, `hhdm_offset` stays 0 and `Aarch64Platform::new`
    // halts via `system_off(ShutdownStatus::Failed)` rather than panicking before UART init.
    let hhdm_offset = HHDM_REQUEST.response().map(|resp| resp.offset).unwrap_or(0);
    let kernel_virt_base = EXEC_ADDR_REQUEST
        .response()
        .map(|resp| resp.virtual_base)
        .unwrap_or(0);

    let mut untyped = UntypedInventory::new();
    if let Some(mmap) = MEMORY_MAP_REQUEST.response() {
        for entry in mmap.entries() {
            if entry.type_ == MEMMAP_USABLE {
                untyped.push_raw_region(entry.base, entry.length);
            }
        }
    }

    let cpu_count = MP_REQUEST.response().map(|mp| mp.cpus().len()).unwrap_or(1);

    let rsdp_addr = RSDP_REQUEST
        .response()
        .map(|r| r.address as u64)
        .unwrap_or(0);

    let framebuffer = FRAMEBUFFER_REQUEST.response().and_then(|resp| {
        resp.framebuffers().first().map(|fb| FramebufferInfo {
            phys_addr: (fb.address() as u64).saturating_sub(hhdm_offset),
            width: fb.width as u32,
            height: fb.height as u32,
            pitch: fb.pitch as u32,
            bpp: fb.bpp,
            red_shift: fb.red_mask_shift,
            green_shift: fb.green_mask_shift,
            blue_shift: fb.blue_mask_shift,
        })
    });

    let mut init_module = None;
    let mut worker_module = None;
    let mut netd_module = None;
    let mut keyd_module = None;
    let mut sshd_module = None;
    if let Some(resp) = MODULES_REQUEST.response() {
        for file in resp.modules() {
            let path = file.path();
            if path.ends_with("newos-init") {
                init_module = Some(file.data());
            } else if path.ends_with("newos-worker") {
                worker_module = Some(file.data());
            } else if path.ends_with("newos-netd") {
                netd_module = Some(file.data());
            } else if path.ends_with("newos-keyd") {
                keyd_module = Some(file.data());
            } else if path.ends_with("newos-sshd") {
                sshd_module = Some(file.data());
            }
        }
    }

    let cmdline = EXEC_FILE_REQUEST
        .response()
        .map(|resp| resp.executable_file().cmdline())
        .unwrap_or("");
    let interactive_shell = cmdline.contains("interactive");
    let qemu_virt = cmdline.contains("qemu");

    BootInfo {
        hhdm_offset,
        kernel_virt_base,
        untyped,
        cpu_count,
        rsdp_addr,
        framebuffer,
        init_module,
        worker_module,
        netd_module,
        keyd_module,
        sshd_module,
        interactive_shell,
        qemu_virt,
    }
}
