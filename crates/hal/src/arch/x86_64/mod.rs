//! Minimal audited 64-bit `x86_64` HAL: GDT/TSS, IDT, per-CPU, x2APIC, SMP, 4-level paging, syscall.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod paging;
pub mod percpu;
pub mod serial;
pub mod smp;
pub mod syscall;

use core::arch::asm;
use core::fmt::{self, Write};
use newos_abi::{QemuExitCode, SysError};
use newos_kernel_core::memory::{CpuSecurityFeatures, PhysAddr, UntypedInventory, VirtAddr};
use newos_kernel_core::{BootInfo, HalPlatform};

const QEMU_DEBUG_EXIT_PORT: u16 = 0xF4;

/// Exit QEMU via `isa-debug-exit`, falling back to an infinite `cli; hlt` loop on real hardware.
pub fn exit_qemu(code: QemuExitCode) -> ! {
    // SAFETY: Writing to QEMU's `isa-debug-exit` I/O port 0xF4 terminates the VM cleanly.
    unsafe {
        serial::outl(QEMU_DEBUG_EXIT_PORT, code as u32);
    }
    loop {
        // SAFETY: Executing `cli; hlt` in Ring 0 safely parks the CPU without UB.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Safe 64-bit `x86_64` platform handle exposed to `newos-kernel-core`.
pub struct X86Platform {
    serial: serial::SerialPort,
    security: CpuSecurityFeatures,
    vspace: paging::X86VSpace,
    online_cpus: usize,
}

impl X86Platform {
    /// Initialize BSP GDT/TSS, IDT, per-CPU `IA32_GS_BASE`, x2APIC, modern CPU hardening,
    /// 64-bit `syscall`/`sysretq`, boot all SMP secondary cores, and wrap kernel `VSpace`.
    pub fn init(info: &BootInfo) -> Self {
        gdt::init_cpu(0);
        idt::init();
        percpu::init_cpu(0, info.bsp_lapic_id);
        apic::init(info.x2apic_enabled);
        let security = paging::enable_modern_cpu_features();
        syscall::init(info.hhdm_offset);
        let online_cpus = smp::bring_up_aps();
        syscall::set_sys_info(online_cpus, info.interactive_shell);
        let vspace = paging::X86VSpace::from_current_cr3(info.hhdm_offset);
        Self {
            serial: serial::SerialPort::new(),
            security,
            vspace,
            online_cpus,
        }
    }
}

impl Write for X86Platform {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.serial.write_str(s)
    }
}

impl HalPlatform for X86Platform {
    type VSpace = paging::X86VSpace;

    fn arch_name(&self) -> &'static str {
        "x86_64"
    }

    fn security_features(&self) -> CpuSecurityFeatures {
        self.security
    }

    fn current_cpu_id(&self) -> u32 {
        percpu::current_cpu_id()
    }

    fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    fn trigger_breakpoint(&mut self) {
        // SAFETY: `idt::init` installed a valid `#BP` handler that returns cleanly.
        unsafe {
            asm!("int3", options(nomem, nostack));
        }
    }

    fn breakpoint_count(&self) -> u64 {
        idt::breakpoint_count()
    }

    fn arm_oneshot_timer(&mut self, ticks: u32) {
        apic::arm_oneshot_timer(ticks);
    }

    fn timer_count(&self) -> u64 {
        idt::timer_count()
    }

    fn enable_interrupts(&mut self) {
        // SAFETY: IDT and x2APIC are initialized and legacy PIC is masked.
        unsafe {
            asm!("sti", options(nomem, nostack));
        }
    }

    fn disable_interrupts(&mut self) {
        // SAFETY: Clearing IF in Ring 0 is always safe.
        unsafe {
            asm!("cli", options(nomem, nostack));
        }
    }

    fn wait_for_interrupt(&mut self) {
        // SAFETY: `hlt` in Ring 0 halts until the next enabled interrupt arrives.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }

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
