//! Per-CPU `x86_64` Global Descriptor Table (GDT) and Task State Segment (TSS) with IST stacks.

use core::arch::asm;
use core::cell::SyncUnsafeCell;
use core::mem::size_of;

pub const MAX_CPUS: usize = 8;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18 | 3;
pub const USER_CS: u16 = 0x20 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

/// IST index (1-based in IDT gate descriptor) for Double Fault (`#DF`).
pub const DOUBLE_FAULT_IST_INDEX: u8 = 1;
/// IST index (1-based in IDT gate descriptor) for NMI.
pub const NMI_IST_INDEX: u8 = 2;

const IST_STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

impl IstStack {
    const fn new() -> Self {
        Self([0; IST_STACK_SIZE])
    }
}

/// Hardware 64-bit Task State Segment (`#[repr(C, packed)]`, 104 bytes).
#[repr(C, packed)]
struct TaskStateSegment {
    _reserved0: u32,
    rsp: [u64; 3],
    _reserved1: u64,
    ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
}

const _: () = assert!(size_of::<TaskStateSegment>() == 104);

impl TaskStateSegment {
    const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp: [0; 3],
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// 7 x 64-bit slots: Null, Kernel CS, Kernel DS, User DS, User CS, and 128-bit TSS (2 slots).
#[repr(C, align(16))]
struct GdtTable([u64; 7]);

impl GdtTable {
    const fn template() -> Self {
        Self([
            0x0000_0000_0000_0000, // 0x00: Null
            0x00AF_9A00_0000_FFFF, // 0x08: Kernel 64-bit Code (DPL=0, L=1, P=1, R=1)
            0x00CF_9200_0000_FFFF, // 0x10: Kernel Data (DPL=0, P=1, W=1)
            0x00CF_F200_0000_FFFF, // 0x18: User Data (DPL=3, P=1, W=1) — ordered for sysretq
            0x00AF_FA00_0000_FFFF, // 0x20: User 64-bit Code (DPL=3, L=1, P=1, R=1)
            0x0000_0000_0000_0000, // 0x28: TSS low
            0x0000_0000_0000_0000, // 0x30: TSS high
        ])
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static DOUBLE_FAULT_STACKS: SyncUnsafeCell<[IstStack; MAX_CPUS]> =
    SyncUnsafeCell::new([const { IstStack::new() }; MAX_CPUS]);
static NMI_STACKS: SyncUnsafeCell<[IstStack; MAX_CPUS]> =
    SyncUnsafeCell::new([const { IstStack::new() }; MAX_CPUS]);
static TSSS: SyncUnsafeCell<[TaskStateSegment; MAX_CPUS]> =
    SyncUnsafeCell::new([const { TaskStateSegment::new() }; MAX_CPUS]);
static GDTS: SyncUnsafeCell<[GdtTable; MAX_CPUS]> =
    SyncUnsafeCell::new([const { GdtTable::template() }; MAX_CPUS]);

fn tss_descriptor(tss_addr: u64) -> (u64, u64) {
    let limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let low = (limit & 0xFFFF)
        | ((tss_addr & 0x00FF_FFFF) << 16)
        | (0x89u64 << 40) // Present, 64-bit Available TSS (type = 0x9)
        | (((limit >> 16) & 0xF) << 48)
        | (((tss_addr >> 24) & 0xFF) << 56);
    let high = tss_addr >> 32;
    (low, high)
}

/// Update `TSS.rsp[0]` for `cpu_id` to its Ring-0 kernel stack.
pub fn set_kernel_rsp0(cpu_id: usize, rsp0: u64) {
    assert!(cpu_id < MAX_CPUS);
    // SAFETY: Each CPU exclusively owns its `TSSS[cpu_id]` slot during init.
    unsafe {
        (*TSSS.get())[cpu_id].rsp[0] = rsp0;
    }
}

/// Initialize the per-CPU GDT & TSS for `cpu_id`, reload segment registers, and load TR.
pub fn init_cpu(cpu_id: usize) {
    assert!(cpu_id < MAX_CPUS);
    // SAFETY: Each CPU initializes only its own `cpu_id` slot before enabling interrupts.
    unsafe {
        let df_top = (&raw mut (*DOUBLE_FAULT_STACKS.get())[cpu_id])
            .cast::<u8>()
            .add(IST_STACK_SIZE) as u64;
        let nmi_top = (&raw mut (*NMI_STACKS.get())[cpu_id])
            .cast::<u8>()
            .add(IST_STACK_SIZE) as u64;

        let tss = &raw mut (*TSSS.get())[cpu_id];
        (*tss).ist[0] = df_top;
        (*tss).ist[1] = nmi_top;

        let (tss_low, tss_high) = tss_descriptor(tss as u64);
        let gdt = &raw mut (*GDTS.get())[cpu_id];
        (*gdt).0[5] = tss_low;
        (*gdt).0[6] = tss_high;

        let gdtr = DescriptorTablePointer {
            limit: (size_of::<GdtTable>() - 1) as u16,
            base: gdt as u64,
        };

        asm!(
            "lgdt [{gdtr}]",
            "push {kcs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {kds:x}",
            "mov es, {kds:x}",
            "mov ss, {kds:x}",
            "mov fs, {zero:x}",
            "mov gs, {zero:x}",
            "ltr {tss:x}",
            gdtr = in(reg) &gdtr,
            kcs = const KERNEL_CS as u64,
            kds = in(reg) KERNEL_DS as u64,
            zero = in(reg) 0u64,
            tss = in(reg) TSS_SELECTOR as u64,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );
    }
}
