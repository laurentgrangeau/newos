//! Limine boot protocol requests and safe `no_alloc` response extraction.

use limine::memmap::MEMMAP_USABLE;
use limine::request::{
    ExecutableFileRequest, HhdmRequest, MemmapRequest, ModulesRequest, MpRequest, MpResponse,
    RsdpRequest,
};
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};
use newos_kernel_core::BootInfo;
use newos_kernel_core::memory::UntypedInventory;

const MP_FLAGS: u64 = 0;

// SAFETY: Limine scans the `.requests_start_marker`, `.requests`, and
// `.requests_end_marker` ELF sections defined in the kernel linker script.
#[used]
#[unsafe(link_section = ".requests_start_marker")]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(3);

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMORY_MAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MP_REQUEST: MpRequest = MpRequest::new(MP_FLAGS);

#[used]
#[unsafe(link_section = ".requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MODULES_REQUEST: ModulesRequest = ModulesRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static EXEC_FILE_REQUEST: ExecutableFileRequest = ExecutableFileRequest::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Returns `true` if the bootloader supports our requested Limine base revision.
pub fn is_base_revision_supported() -> bool {
    BASE_REVISION.is_supported()
}

/// Expose Limine's Multi-Processing response for SMP secondary core bring-up.
pub fn mp_response() -> Option<&'static MpResponse> {
    MP_REQUEST.response()
}

/// Extract a safe, `no_alloc` boot descriptor and bootstrap `UntypedInventory` from Limine.
pub fn boot_info() -> BootInfo {
    let hhdm_offset = HHDM_REQUEST
        .response()
        .map(|resp| resp.offset)
        .unwrap_or(0);

    let mut untyped = UntypedInventory::new();
    if let Some(mmap) = MEMORY_MAP_REQUEST.response() {
        for entry in mmap.entries() {
            if entry.type_ == MEMMAP_USABLE {
                untyped.push_raw_region(entry.base, entry.length);
            }
        }
    }

    let cpu_count = MP_REQUEST
        .response()
        .map(|mp| mp.cpus().len())
        .unwrap_or(1);

    let rsdp_addr = RSDP_REQUEST
        .response()
        .map(|r| r.address as u64)
        .unwrap_or(0);

    let mut init_module = None;
    let mut worker_module = None;
    if let Some(resp) = MODULES_REQUEST.response() {
        for file in resp.modules() {
            let path = file.path();
            if path.ends_with("newos-init") {
                init_module = Some(file.data());
            } else if path.ends_with("newos-worker") {
                worker_module = Some(file.data());
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
        untyped,
        cpu_count,
        rsdp_addr,
        init_module,
        worker_module,
        interactive_shell,
        qemu_virt,
    }
}
