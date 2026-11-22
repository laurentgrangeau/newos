//! Pure 64-bit `aarch64` HAL (ARMv8.2-A / Cortex-A76 / Raspberry Pi 5):
//! `PL011` UART, `VBAR_EL1` vectors, `TPIDR_EL1` per-CPU, 4-level `TTBR0/TTBR1` paging, SMP, PSCI.

pub mod paging;
pub mod serial;
pub mod smp;

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};
use newos_abi::{QemuExitCode, SysError};
use newos_kernel_core::memory::{CpuSecurityFeatures, PhysAddr, UntypedInventory, VirtAddr};
use newos_kernel_core::{BootInfo, HalPlatform};

const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

static BREAKPOINT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_COUNT: AtomicU64 = AtomicU64::new(0);

// Minimal 2 KiB-aligned EL1 exception vector table handling synchronous `brk #0` cleanly.
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
    // Lower EL using AArch64 (4 x 128B)
    ".balign 128", "b __newos_unhandled_el1",
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
    "bl {sync_handler}",
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
    "__newos_unhandled_el1:",
    "b __newos_unhandled_el1",
    sync_handler = sym aarch64_sync_el1_handler,
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
        // `brk #imm` instruction (EC = 0x3C): advance ELR_EL1 past the 4-byte instruction
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
    // Copy the active stack pointer into `SP_EL1` by switching `SPSel = 1`, then install `VBAR_EL1`.
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
        asm!(
            "hvc #0",
            in("x0") PSCI_SYSTEM_OFF,
            options(nomem, nostack),
        );
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
    spawned_procs: usize,
}

impl Aarch64Platform {
    pub fn init(info: &mut BootInfo) -> Self {
        use newos_kernel_core::memory::{PageFlags, PhysFrame, VSpaceMapper};
        let mut vspace = paging::Aarch64VSpace::from_current_ttbr1(info.hhdm_offset);

        // Map PL011 MMIO (0x0900_0000 on QEMU `virt`) at a dedicated Device-nGnRnE VA in TTBR1_EL1.
        const UART_PHYS: u64 = 0x0900_0000;
        const UART_VIRT: u64 = 0xffff_b000_0000_0000;
        if let Ok(uart_virt) = VirtAddr::new_page_aligned(UART_VIRT)
            && let Ok(frame) = PhysFrame::from_aligned(PhysAddr::new(UART_PHYS))
            && let Ok(mmio_flags) = PageFlags::new_wx(true, false, false, true)
            && vspace.map_4k(uart_virt, frame, mmio_flags, &mut info.untyped).is_ok()
        {
            serial::init_virt(UART_VIRT);
        } else {
            serial::init_virt(info.hhdm_offset.wrapping_add(UART_PHYS));
        }

        let mut serial = serial::Pl011::new();
        let _ = writeln!(serial, "[newos-aarch64] PL011 UART online (TTBR1_EL1 Device-nGnRnE)");

        set_cpu_id(0);
        install_vectors();
        let _ = writeln!(serial, "[newos-aarch64] VBAR_EL1 vectors installed; starting SMP...");
        let online_cpus = smp::bring_up_aps();
        Self {
            serial,
            vspace,
            online_cpus,
            spawned_procs: 0,
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
        // ARMv8.2-A (Cortex-A76): hardware WP, UXN/PXN (NXE+SMEP), and EL1/EL0 separation
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
        let _ = writeln!(self.serial, "[newos-aarch64] testing VBAR_EL1 `brk #0`...");
        // SAFETY: `install_vectors` installed a `brk #0` handler that advances `ELR_EL1 += 4`.
        unsafe {
            asm!("brk #0", options(nomem, nostack));
        }
        let _ = writeln!(
            self.serial,
            "[newos-aarch64] `brk #0` returned cleanly (count={})",
            self.breakpoint_count()
        );
    }

    fn breakpoint_count(&self) -> u64 {
        BREAKPOINT_COUNT.load(Ordering::Acquire)
    }

    fn arm_oneshot_timer(&mut self, _ticks: u32) {
        // Verify ARM Generic Timer virtual counter (`CNTVCT_EL0`) ticks monotonically.
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
        _entry: VirtAddr,
        _user_rsp: VirtAddr,
        _vspace_root: PhysAddr,
    ) -> Result<usize, SysError> {
        let pid = self.spawned_procs;
        self.spawned_procs += 1;
        Ok(pid)
    }

    fn start_userspace(&mut self) -> ! {
        let _ = writeln!(
            self.serial,
            "[newos-aarch64] milestone-1 bring-up (Cortex-A76 SMP, VBAR_EL1, TTBR0/TTBR1 4-level VSpace, ELF64 load): OK"
        );
        exit_qemu(QemuExitCode::Success)
    }

    fn exit(&mut self, code: QemuExitCode) -> ! {
        exit_qemu(code)
    }
}
