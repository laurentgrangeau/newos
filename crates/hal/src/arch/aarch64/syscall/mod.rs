//! Pure 64-bit `ARMv8` EL0 `svc #0` syscall dispatch, isolated `TTBR0_EL1` multi-domain
//! context switching, and EL0 crash isolation / supervisor recovery.

mod arch_state;
mod bootstrap;
mod dispatch;
mod domain;
mod irq;
mod lifecycle;
mod lock;
mod mem_ops;

use core::sync::atomic::{AtomicBool, AtomicU64};
use newos_kernel_core::ipc::{KernelIpcState, MAX_IPC_DOMAINS};
use newos_kernel_core::memory::{FrameMappingTracker, UntypedInventory};

pub use arch_state::TrapFrame;
pub(super) use arch_state::enable_fp_simd;
pub(crate) use arch_state::{read_cntfrq, read_cntvct};
pub use bootstrap::{
    init, register_board_irqs, register_boot_module, register_domain, register_extra_mmio_mapping,
    register_init_mmio_cap, set_sys_info, set_untyped_inventory,
};
pub use dispatch::sync_el0_dispatch;
pub use domain::{ap_enter_scheduler, start_userspace};
pub use irq::{dispatch_peripheral_spi, irq_el0_dispatch, wake_expired_timers};
pub(super) use lock::IrqSpinLock;

pub(super) const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;
pub(super) const MAX_DOMAINS: usize = MAX_IPC_DOMAINS;
const _: () = assert!(MAX_DOMAINS <= 8);
pub(super) const MAX_CPUS: usize = 8;
pub(super) const MAX_DMA_CACHE_LEN: u64 = 64 * 1024;
pub(super) const TTBR0_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
pub(super) const CNTV_CTL_ENABLE: u64 = 1 << 0;
pub(super) const CNTV_CTL_ISTATUS: u64 = 1 << 2;

pub(super) static YIELD_COUNTER: AtomicU64 = AtomicU64::new(0);
pub(super) static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
pub(super) static NET_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
pub(super) static NET_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
pub(super) static NET_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
pub(super) static RNG_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
pub(super) static RNG_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
pub(super) static RNG_MMIO_LEN: AtomicU64 = AtomicU64::new(0);
pub(super) static WDT_MMIO_PHYS: AtomicU64 = AtomicU64::new(0);
pub(super) static WDT_MMIO_VIRT: AtomicU64 = AtomicU64::new(0);
pub(super) static WDT_MMIO_LEN: AtomicU64 = AtomicU64::new(0);

pub(super) static IS_QEMU_VIRT: AtomicBool = AtomicBool::new(false);
pub(super) static SYS_INFO_PACKED: AtomicU64 = AtomicU64::new(0);
pub(super) static TIMER_TICK_INTERVAL: AtomicU64 = AtomicU64::new(625_000);
pub(super) static SYSCALL_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);
pub(super) static PREEMPT_PENDING: AtomicBool = AtomicBool::new(false);

static DOMAINS: IrqSpinLock<domain::DomainTable> = IrqSpinLock::new(domain::DomainTable::new());
pub(super) static IPC_STATE: IrqSpinLock<KernelIpcState> = IrqSpinLock::new(KernelIpcState::new());
pub(super) static RUNTIME_UNTYPED: IrqSpinLock<UntypedInventory> =
    IrqSpinLock::new(UntypedInventory::new());
pub(super) static FRAME_MAPPINGS: IrqSpinLock<FrameMappingTracker<512>> =
    IrqSpinLock::new(FrameMappingTracker::new());

/// Convert a bounded domain slot index (`0..MAX_DOMAINS <= 8`) into its non-zero 16-bit ASID.
#[inline]
#[allow(clippy::cast_possible_truncation)] // `pd_id < MAX_DOMAINS <= 8`, so `pd_id + 1 <= 8` fits in `u16`.
pub(super) const fn domain_asid(pd_id: usize) -> u16 {
    (pd_id + 1) as u16
}

/// Return the current logical CPU index clamped to `0..MAX_CPUS`.
#[inline]
pub(super) fn current_cpu_idx() -> usize {
    usize::try_from(super::get_cpu_id())
        .unwrap_or(MAX_CPUS - 1)
        .min(MAX_CPUS - 1)
}
