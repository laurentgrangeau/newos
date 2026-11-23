//! QEMU `aarch64` `virt` machine board descriptor (test & emulation harness).

use super::{BoardDescriptor, MmioRegion};

pub const QEMU_VIRT_AARCH64: BoardDescriptor = BoardDescriptor {
    name: "qemu-virt-test",
    arch: "aarch64",
    uart: MmioRegion::new(0x0900_0000, 0x1000),
    gicd: MmioRegion::new(0x0800_0000, 0x1000),
    gicc: MmioRegion::new(0x0801_0000, 0x1000),
    psci_use_smc: false,
    is_virtio_bus: true,
    net_mmio: Some(MmioRegion::new(0x0A00_0000, 4 * 4096)),
    rng_mmio: Some(MmioRegion::new(0x0A00_0000, 4 * 4096)),
    wdt_mmio: None,
};
