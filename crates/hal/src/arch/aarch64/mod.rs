//! Pure 64-bit `aarch64` HAL (ARMv8.2-A / Cortex-A76 / Raspberry Pi 5):
//! `PL011` UART, `VBAR_EL1` vectors, `TPIDR_EL1` per-CPU, 4-level `TTBR0/TTBR1` paging,
//! EL0 `svc #0` + `TTBR0_EL1` multi-process switching, SMP, and PSCI `SYSTEM_OFF`.

pub mod paging;
pub mod serial;
pub mod smp;
pub mod syscall;

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{QemuExitCode, SysError};
use newos_kernel_core::memory::{CpuSecurityFeatures, PhysAddr, UntypedInventory, VirtAddr};
use newos_kernel_core::{BootInfo, HalPlatform};

const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

static BREAKPOINT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_COUNT: AtomicU64 = AtomicU64::new(0);

// 2 KiB-aligned EL1 exception vector table handling EL1 `brk #0` and EL0 `svc #0` / faults.
global_asm!(
    ".balign 2048",
    ".global __newos_aarch64_vectors",
    "__newos_aarch64_vectors:",
    // Current EL with SP0 (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Current EL with SPx (4 x 128B)
    ".balign 128", "b __newos_sync_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch64 (4 x 128B) -> EL0 `svc #0` and EL0 fault isolation!
    ".balign 128", "b __newos_sync_el0",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    // Lower EL using AArch32 (unused — pure 64-bit only!)
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    ".balign 128", "b __newos_unhandled_el1",
    "__newos_sync_el1:",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x16, x17, [sp, #-16]!",
    "stp x18, xzr, [sp, #-16]!",
    "stp x29, x30, [sp, #-16]!",
    "bl {sync_el1}",
    "ldp x29, x30, [sp], #16",
    "ldp x18, xzr, [sp], #16",
    "ldp x16, x17, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x8,  x9,  [sp], #16",
    "ldp x6,  x7,  [sp], #16",
    "ldp x4,  x5,  [sp], #16",
    "ldp x2,  x3,  [sp], #16",
    "ldp x0,  x1,  [sp], #16",
    "eret",
    // EL0 synchronous entry: save full 272-byte `TrapFrame` (`x0..x30, sp_el0, elr_el1, spsr_el1`)
    "__newos_sync_el0:",
    "sub sp, sp, #272",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "mrs x9,  sp_el0",
    "stp x30, x9,  [sp, #240]",
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #256]",
    "mov x0, sp",
    "bl {sync_el0}",
    // Restore (possibly TTBR0-switched!) `TrapFrame` and return to EL0 via `eret`
    "ldp x10, x11, [sp, #256]",
    "msr elr_el1, x10",
    "msr spsr_el1, x11",
    "ldp x30, x9,  [sp, #240]",
    "msr sp_el0, x9",
    "ldp x28, x29, [sp, #224]",
    "ldp x26, x27, [sp, #208]",
    "ldp x24, x25, [sp, #192]",
    "ldp x22, x23, [sp, #176]",
    "ldp x20, x21, [sp, #160]",
    "ldp x18, x19, [sp, #144]",
    "ldp x16, x17, [sp, #128]",
    "ldp x14, x15, [sp, #112]",
    "ldp x12, x13, [sp, #96]",
    "ldp x10, x11, [sp, #80]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x0,  x1,  [sp, #0]",
    "add sp, sp, #272",
    "eret",
    "__newos_unhandled_el1:",
    "b __newos_unhandled_el1",
    sync_el1 = sym aarch64_sync_el1_handler,
    sync_el0 = sym syscall::sync_el0_dispatch,
);

unsafe extern "C" {
    static __newos_aarch64_vectors: u8;
}

extern "C" fn aarch64_sync_el1_handler() {
    let esr: u64;
    let elr: u64;
    // SAFETY: Reading `ESR_EL1` and `ELR_EL1` inside EL1 synchronous exception handler.
    unsafe {
        asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
        asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;
    if ec == 0x3C {
        BREAKPOINT_COUNT.fetch_add(1, Ordering::Release);
        // SAFETY: Advancing `ELR_EL1` by 4 skips the `brk #0` instruction cleanly.
        unsafe {
            asm!("msr elr_el1, {}", in(reg) elr + 4, options(nomem, nostack));
        }
        return;
    }

    let mut s = serial::Pl011::new();
    let _ = writeln!(s, "[newos-hal] AArch64 sync exception EC={:#x} ELR={:#018x}", ec, elr);
    exit_qemu(QemuExitCode::Failed)
}

pub fn install_vectors() {
    let addr = (&raw const __newos_aarch64_vectors) as u64;
    // SAFETY: Limine enters `_start` on aarch64 with `SPSel = 0` (`SP_EL0` active, `SP_EL1 = 0`).
    // Switch to `SP_EL1` with the active stack pointer and install `VBAR_EL1`.
    unsafe {
        asm!(
            "mov x9, sp",
            "msr spsel, #1",
            "mov sp, x9",
            "msr vbar_el1, {vbar}",
            "isb",
            vbar = in(reg) addr,
            out("x9") _,
            options(nostack),
        );
    }
}

pub fn set_cpu_id(id: u64) {
    // SAFETY: Writing logical CPU ID into EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) id, options(nomem, nostack));
    }
}

pub fn get_cpu_id() -> u64 {
    let id: u64;
    // SAFETY: Reading EL1-private `TPIDR_EL1`.
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) id, options(nomem, nostack));
    }
    id
}

/// Power off cleanly via PSCI `SYSTEM_OFF` (`hvc #0`, works on QEMU `virt` and Pi 5 UEFI).
pub fn exit_qemu(code: QemuExitCode) -> ! {
    let mut s = serial::Pl011::new();
    match code {
        QemuExitCode::Success => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=OK)");
        }
        QemuExitCode::Failed => {
            let _ = writeln!(s, "[newos-aarch64] PSCI SYSTEM_OFF (status=FAIL)");
        }
    }
    // SAFETY: Invoking ARM PSCI `SYSTEM_OFF` (0x8400_0008) cleanly powers down the VM/board.
    unsafe {
        asm!("hvc #0", in("x0") PSCI_SYSTEM_OFF, options(nomem, nostack));
    }
    loop {
        // SAFETY: Fallback low-power WFI loop if PSCI is unavailable.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

pub struct Aarch64Platform {
    serial: serial::Pl011,
    vspace: paging::Aarch64VSpace,
    online_cpus: usize,
}

impl Aarch64Platform {
    pub fn init(info: &mut BootInfo) -> Self {
        use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
        let mut vspace = paging::Aarch64VSpace::from_current_ttbr1(info.hhdm_offset);

        // Select PL011 MMIO physical base:
        // - Raspberry Pi 5 (BCM2712 3-pin JST Debug UART): `0x10_7D00_1000`
        // - QEMU `virt`: `0x0900_0000`
        const QEMU_UART_PHYS: u64 = 0x0900_0000;
        const RPI5_UART_PHYS: u64 = 0x10_7D00_1000;
        const UART_VIRT: u64 = 0xffff_b000_0000_0000;
        let uart_phys = if info.board_rpi5 {
            RPI5_UART_PHYS
        } else {
            QEMU_UART_PHYS
        };
        if let Ok(uart_virt) = VirtAddr::new_page_aligned(UART_VIRT)
            && let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(uart_phys))
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && vspace.map_4k(uart_virt, frame, mmio_flags, &mut info.untyped).is_ok()
        {
            serial::init_virt(UART_VIRT);
        } else {
            serial::init_virt(info.hhdm_offset.wrapping_add(uart_phys));
        }

        // Map QEMU `virt` VirtIO-MMIO window (0x0a00_0000..0x0a00_4000) only when not on bare-metal Pi 5.
        let net_mmio = if !info.board_rpi5 {
            const VIRTIO_MMIO_PHYS: u64 = 0x0a00_0000;
            const VIRTIO_MMIO_VIRT: u64 = 0xffff_b001_0000_0000;
            const VIRTIO_MMIO_PAGES: u64 = 4;
            if let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true) {
                for p in 0..VIRTIO_MMIO_PAGES {
                    let off = p * 4096;
                    if let Ok(va) = VirtAddr::new_page_aligned(VIRTIO_MMIO_VIRT + off)
                        && let Ok(frame) =
                            PhysFrame::from_aligned(PhysAddr::new(VIRTIO_MMIO_PHYS + off))
                    {
                        let _ = vspace.map_4k(va, frame, mmio_flags, &mut info.untyped);
                    }
                }
            }
            Some((
                PhysAddr::new(VIRTIO_MMIO_PHYS),
                VIRTIO_MMIO_VIRT,
                VIRTIO_MMIO_PAGES * 4096,
            ))
        } else {
            None
        };

        set_cpu_id(0);
        install_vectors();
        syscall::init(info.hhdm_offset, net_mmio);
        let online_cpus = smp::bring_up_aps();
        syscall::set_sys_info(online_cpus, info.interactive_shell);
        Self {
            serial: serial::Pl011::new(),
            vspace,
            online_cpus,
        }
    }
}

impl Write for Aarch64Platform {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.serial.write_str(s)
    }
}

impl HalPlatform for Aarch64Platform {
    type VSpace = paging::Aarch64VSpace;

    fn arch_name(&self) -> &'static str {
        "aarch64"
    }

    fn security_features(&self) -> CpuSecurityFeatures {
        CpuSecurityFeatures {
            wp: true,
            nxe: true,
            smep: true,
            smap: true,
            umip: true,
        }
    }

    fn current_cpu_id(&self) -> u32 {
        get_cpu_id() as u32
    }

    fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    fn trigger_breakpoint(&mut self) {
        // SAFETY: `install_vectors` installed a `brk #0` handler that advances `ELR_EL1 += 4`.
        unsafe {
            asm!("brk #0", options(nomem, nostack));
        }
    }

    fn breakpoint_count(&self) -> u64 {
        BREAKPOINT_COUNT.load(Ordering::Acquire)
    }

    fn arm_oneshot_timer(&mut self, _ticks: u32) {
        let t0: u64;
        // SAFETY: `CNTVCT_EL0` is always readable in EL1 on ARMv8.
        unsafe {
            asm!("isb", "mrs {}, cntvct_el0", out(reg) t0, options(nomem, nostack));
        }
        let mut t1 = t0;
        for _ in 0..10_000_000u32 {
            // SAFETY: `CNTVCT_EL0` is always readable in EL1 on ARMv8.
            unsafe {
                asm!("isb", "mrs {}, cntvct_el0", out(reg) t1, options(nomem, nostack));
            }
            if t1 != t0 {
                break;
            }
            core::hint::spin_loop();
        }
        TIMER_COUNT.fetch_add(1, Ordering::Release);
    }

    fn timer_count(&self) -> u64 {
        TIMER_COUNT.load(Ordering::Acquire)
    }

    fn enable_interrupts(&mut self) {}
    fn disable_interrupts(&mut self) {}
    fn wait_for_interrupt(&mut self) {}

    fn vspace_mut(&mut self) -> &mut Self::VSpace {
        &mut self.vspace
    }

    fn create_user_vspace(&self, untyped: &mut UntypedInventory) -> Result<Self::VSpace, SysError> {
        self.vspace.new_user_vspace(untyped)
    }

    fn probe_mapped_u64(&self, virt: VirtAddr, pattern: u64) -> Result<u64, SysError> {
        paging::probe_mapped_u64(&self.vspace, virt, pattern)
    }

    fn register_user_process(
        &mut self,
        entry: VirtAddr,
        user_rsp: VirtAddr,
        vspace_root: PhysAddr,
    ) -> Result<usize, SysError> {
        syscall::register_user_process(entry.raw(), user_rsp.raw(), vspace_root.raw())
    }

    fn start_userspace(&mut self) -> ! {
        syscall::start_userspace()
    }

    fn exit(&mut self, code: QemuExitCode) -> ! {
        exit_qemu(code)
    }
}
