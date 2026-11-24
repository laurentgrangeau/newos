//! Pluggable Board / SoC Hardware Descriptors (`newos-hal::board`).
//!
//! Decouples board-specific MMIO physical addresses, interrupt controllers, and PSCI
//! conduits from CPU architecture code so new boards or SoCs can be added cleanly.

#[cfg(feature = "board-qemu-virt")]
pub mod qemu_virt;
#[cfg(feature = "board-rpi5")]
pub mod rpi5;

/// Physical MMIO window owned by a board peripheral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRegion {
    pub phys_base: u64,
    pub size: u64,
}

impl MmioRegion {
    pub const fn new(phys_base: u64, size: u64) -> Self {
        Self { phys_base, size }
    }
}

/// Hardware interrupt line owned by a board peripheral (GIC SPI or BCM2712 MIP MSI-X).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqLine {
    pub irq: u16,
    pub is_mip: bool,
}

impl IrqLine {
    pub const fn gic(irq: u16) -> Self {
        Self { irq, is_mip: false }
    }

    pub const fn mip(vector: u16) -> Self {
        Self {
            irq: vector,
            is_mip: true,
        }
    }
}

/// Static hardware description of a target board / SoC.
#[derive(Debug, Clone, Copy)]
pub struct BoardDescriptor {
    pub name: &'static str,
    pub arch: &'static str,
    pub uart: MmioRegion,
    pub gicd: MmioRegion,
    pub gicc: MmioRegion,
    pub psci_use_smc: bool,
    pub is_virtio_bus: bool,
    pub net_mmio: Option<MmioRegion>,
    pub rng_mmio: Option<MmioRegion>,
    pub wdt_mmio: Option<MmioRegion>,
    pub net_irq: Option<IrqLine>,
    pub rng_irq: Option<IrqLine>,
    pub uart_irq: Option<IrqLine>,
}

/// Select the active compiled-in [`BoardDescriptor`] based on runtime cmdline hints.
pub fn select_board(qemu_hint: bool) -> &'static BoardDescriptor {
    #[cfg(all(feature = "board-rpi5", feature = "board-qemu-virt"))]
    {
        if qemu_hint {
            &qemu_virt::QEMU_VIRT_AARCH64
        } else {
            &rpi5::RPI5_BCM2712
        }
    }
    #[cfg(all(feature = "board-rpi5", not(feature = "board-qemu-virt")))]
    {
        let _ = qemu_hint;
        &rpi5::RPI5_BCM2712
    }
    #[cfg(all(not(feature = "board-rpi5"), feature = "board-qemu-virt"))]
    {
        let _ = qemu_hint;
        &qemu_virt::QEMU_VIRT_AARCH64
    }
    #[cfg(all(not(feature = "board-rpi5"), not(feature = "board-qemu-virt")))]
    {
        compile_error!(
            "Enable at least one board feature in newos-hal (e.g. `board-rpi5` or `board-qemu-virt`)."
        );
    }
}
