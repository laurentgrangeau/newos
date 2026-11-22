//! Per-CPU local storage backed by `IA32_GS_BASE` / `IA32_KERNEL_GS_BASE` and Ring-0 syscall stacks.

use core::arch::asm;
use core::cell::SyncUnsafeCell;

use super::gdt::{self, MAX_CPUS};

const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

const KERNEL_STACK_SIZE: usize = 32 * 1024;

#[repr(C, align(16))]
struct KernelStack([u8; KERNEL_STACK_SIZE]);

impl KernelStack {
    const fn new() -> Self {
        Self([0; KERNEL_STACK_SIZE])
    }
}

/// Cache-line-aligned per-CPU control block.
///
/// Field offsets are fixed via `#[repr(C)]` so `gs:[offset]` reads in `syscall_entry` are exact:
/// - `0`: `self_addr`
/// - `8`: `cpu_id`
/// - `12`: `lapic_id`
/// - `16`: `kernel_rsp`
/// - `24`: `user_rsp_scratch`
#[repr(C, align(64))]
pub struct PerCpu {
    pub self_addr: u64,
    pub cpu_id: u32,
    pub lapic_id: u32,
    pub kernel_rsp: u64,
    pub user_rsp_scratch: u64,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            self_addr: 0,
            cpu_id: 0,
            lapic_id: 0,
            kernel_rsp: 0,
            user_rsp_scratch: 0,
        }
    }
}

static KERNEL_STACKS: SyncUnsafeCell<[KernelStack; MAX_CPUS]> =
    SyncUnsafeCell::new([const { KernelStack::new() }; MAX_CPUS]);
static PERCPUS: SyncUnsafeCell<[PerCpu; MAX_CPUS]> =
    SyncUnsafeCell::new([const { PerCpu::new() }; MAX_CPUS]);

/// Write a 64-bit Model-Specific Register (MSR).
///
/// # Safety
/// Caller must ensure `msr` is valid on the current CPU and `val` upholds CPU invariants.
#[inline]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    // SAFETY: Caller guarantees MSR validity.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a 64-bit Model-Specific Register (MSR).
///
/// # Safety
/// Caller must ensure `msr` is readable on the current CPU.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: Caller guarantees MSR validity.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Initialize per-CPU `IA32_GS_BASE`, `IA32_KERNEL_GS_BASE`, and `TSS.rsp[0]` for `cpu_id`.
pub fn init_cpu(cpu_id: usize, lapic_id: u32) {
    assert!(cpu_id < MAX_CPUS);
    // SAFETY: Each CPU exclusively initializes its own `cpu_id` slot before enabling interrupts.
    unsafe {
        let stack_top = (&raw mut (*KERNEL_STACKS.get())[cpu_id])
            .cast::<u8>()
            .add(KERNEL_STACK_SIZE) as u64;
        let ptr = &raw mut (*PERCPUS.get())[cpu_id];
        (*ptr).self_addr = ptr as u64;
        (*ptr).cpu_id = cpu_id as u32;
        (*ptr).lapic_id = lapic_id;
        (*ptr).kernel_rsp = stack_top;
        (*ptr).user_rsp_scratch = 0;

        gdt::set_kernel_rsp0(cpu_id, stack_top);
        wrmsr(IA32_GS_BASE, ptr as u64);
        wrmsr(IA32_KERNEL_GS_BASE, 0);
    }
}

/// Read the logical `cpu_id` of the currently executing CPU directly from `gs:[8]`.
#[inline]
pub fn current_cpu_id() -> u32 {
    let id: u32;
    // SAFETY: `init_cpu` installed a valid `PerCpu` pointer into `IA32_GS_BASE`,
    // and `cpu_id` is a `u32` at fixed offset 8 (`#[repr(C)]`).
    unsafe {
        asm!("mov {:e}, gs:[8]", out(reg) id, options(readonly, nostack, preserves_flags));
    }
    id
}
