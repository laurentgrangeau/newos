//! Raspberry Pi 5 (16 GB, BCM2712 Cortex-A76 + RP1 Southbridge) board descriptor.

use super::{BoardDescriptor, MmioRegion};

pub const RPI5_BCM2712: BoardDescriptor = BoardDescriptor {
    name: "rpi5-16gb",
    arch: "aarch64",
    uart: MmioRegion::new(0x10_7D00_1000, 0x1000),
    gicd: MmioRegion::new(0x10_7FFF_9000, 0x1000),
    gicc: MmioRegion::new(0x10_7FFF_A000, 0x1000),
    psci_use_smc: true,
    is_virtio_bus: false,
    net_mmio: Some(MmioRegion::new(0x1F_0010_0000, 4 * 4096)),
    rng_mmio: Some(MmioRegion::new(0x10_7D20_8000, 0x28)),
    wdt_mmio: Some(MmioRegion::new(0x10_7D20_0000, 0x100)),
};
