//! PCIe ECAM Configuration Space Enumerator, BAR Decoder & MSI-X Capability Walker.
//!
//! Runs 100% in EL0 (`#![forbid(unsafe_code)]`, `no_alloc`) via `CapId::BOOTSTRAP_PCIE_ECAM_MMIO`.

use crate::StorageMmioTransport;
use newos_abi::SysError;

pub const PCI_REG_VENDOR_DEVICE: u16 = 0x00;
pub const PCI_REG_COMMAND_STATUS: u16 = 0x04;
pub const PCI_REG_CLASS_REV: u16 = 0x08;
pub const PCI_REG_HEADER_TYPE: u16 = 0x0C;
pub const PCI_REG_BAR0: u16 = 0x10;
pub const PCI_REG_CAP_PTR: u16 = 0x34;

pub const PCI_CMD_MEM_SPACE: u32 = 1 << 1;
pub const PCI_CMD_BUS_MASTER: u32 = 1 << 2;
pub const PCI_STATUS_CAP_LIST: u32 = 1 << 20;
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

/// Well-known PCI class/subclass for NVMe controllers (`01:08:02`).
pub const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
pub const PCI_PROGIF_NVME: u8 = 0x02;

/// Compute the PCIe ECAM byte offset for `(bus, dev, func, reg_offset)`.
#[inline]
pub const fn ecam_offset(bus: u8, dev: u8, func: u8, reg_offset: u16) -> Result<u64, SysError> {
    if dev >= 32 || func >= 8 || reg_offset >= 4096 || (reg_offset & 3) != 0 {
        return Err(SysError::InvalidArgument);
    }
    Ok(((bus as u64) << 20) | ((dev as u64) << 15) | ((func as u64) << 12) | (reg_offset as u64))
}

/// Discovered PCIe function metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcieDeviceInfo {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bar0_phys: u64,
    pub msix_cap_offset: Option<u8>,
}

impl PcieDeviceInfo {
    #[inline]
    pub const fn is_nvme(&self) -> bool {
        self.class_code == PCI_CLASS_MASS_STORAGE
            && self.subclass == PCI_SUBCLASS_NVM
            && self.prog_if == PCI_PROGIF_NVME
    }
}

/// Capability-scoped EL0 PCIe ECAM enumerator.
pub struct PcieEcam<T: StorageMmioTransport> {
    transport: T,
}

impl<T: StorageMmioTransport> PcieEcam<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn read_u32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> Result<u32, SysError> {
        self.transport.read32(ecam_offset(bus, dev, func, reg)?)
    }

    pub fn write_u32(
        &self,
        bus: u8,
        dev: u8,
        func: u8,
        reg: u16,
        val: u32,
    ) -> Result<(), SysError> {
        self.transport
            .write32(ecam_offset(bus, dev, func, reg)?, val)
    }

    /// Probe a single `(bus, dev, func)` slot, decoding 32/64-bit BAR0 and MSI-X capability offset.
    pub fn probe_function(&self, bus: u8, dev: u8, func: u8) -> Option<PcieDeviceInfo> {
        let vd = self.read_u32(bus, dev, func, PCI_REG_VENDOR_DEVICE).ok()?;
        let vendor_id = (vd & 0xFFFF) as u16;
        if vendor_id == 0xFFFF || vendor_id == 0x0000 {
            return None;
        }
        let device_id = ((vd >> 16) & 0xFFFF) as u16;
        let class_rev = self.read_u32(bus, dev, func, PCI_REG_CLASS_REV).ok()?;
        let prog_if = ((class_rev >> 8) & 0xFF) as u8;
        let subclass = ((class_rev >> 16) & 0xFF) as u8;
        let class_code = ((class_rev >> 24) & 0xFF) as u8;

        // Decode BAR0 (supports 32-bit and 64-bit memory BARs)
        let bar0_lo = self.read_u32(bus, dev, func, PCI_REG_BAR0).unwrap_or(0);
        let bar0_phys = if (bar0_lo & 1) == 0 && ((bar0_lo >> 1) & 0x3) == 0b10 {
            let bar0_hi = self.read_u32(bus, dev, func, PCI_REG_BAR0 + 4).unwrap_or(0);
            u64::from(bar0_lo & !0xF) | (u64::from(bar0_hi) << 32)
        } else {
            u64::from(bar0_lo & !0xF)
        };

        // Walk PCI capability list for MSI-X (`cap_id == 0x11`)
        let cmd_status = self
            .read_u32(bus, dev, func, PCI_REG_COMMAND_STATUS)
            .unwrap_or(0);
        let mut msix_cap_offset = None;
        if (cmd_status & PCI_STATUS_CAP_LIST) != 0 {
            let mut ptr =
                (self.read_u32(bus, dev, func, PCI_REG_CAP_PTR).unwrap_or(0) & 0xFC) as u8;
            for _ in 0..48u8 {
                if ptr < 0x40 {
                    break;
                }
                let cap = self.read_u32(bus, dev, func, u16::from(ptr)).unwrap_or(0);
                let cap_id = (cap & 0xFF) as u8;
                let next = ((cap >> 8) & 0xFC) as u8;
                if cap_id == PCI_CAP_ID_MSIX {
                    msix_cap_offset = Some(ptr);
                    break;
                }
                if next == ptr {
                    break;
                }
                ptr = next;
            }
        }

        Some(PcieDeviceInfo {
            bus,
            dev,
            func,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            bar0_phys,
            msix_cap_offset,
        })
    }

    /// Enable Memory Space + Bus Mastering on `(bus, dev, func)` for DMA-capable devices (NVMe/Hailo).
    pub fn enable_bus_master(&self, bus: u8, dev: u8, func: u8) -> Result<(), SysError> {
        let cur = self.read_u32(bus, dev, func, PCI_REG_COMMAND_STATUS)?;
        self.write_u32(
            bus,
            dev,
            func,
            PCI_REG_COMMAND_STATUS,
            cur | PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER,
        )
    }

    /// Enumerate `bus` (`dev 0..max_devs`, `func 0`), writing discovered devices into `out`.
    pub fn scan_bus(&self, bus: u8, max_devs: u8, out: &mut [Option<PcieDeviceInfo>]) -> usize {
        let mut found = 0usize;
        for dev in 0..max_devs.min(32) {
            if found >= out.len() {
                break;
            }
            if let Some(info) = self.probe_function(bus, dev, 0) {
                out[found] = Some(info);
                found += 1;
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockEcam {
        cmd_written: RefCell<u32>,
    }

    impl StorageMmioTransport for &MockEcam {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            // Device 0 on Bus 0 = NVMe SSD (64-bit BAR0 at 0x1B_0000_0000, MSI-X cap at 0x50)
            match offset {
                0x00 => Ok(0x5016_144D), // Samsung NVMe
                0x04 => Ok(PCI_STATUS_CAP_LIST),
                0x08 => Ok((0x01 << 24) | (0x08 << 16) | (0x02 << 8)),
                0x10 => Ok(0x0000_0004), // 64-bit memory BAR
                0x14 => Ok(0x0000_001B),
                0x34 => Ok(0x50),
                0x50 => Ok(u32::from(PCI_CAP_ID_MSIX)),
                _ => Ok(0xFFFF_FFFF),
            }
        }
        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == 0x04 {
                *self.cmd_written.borrow_mut() = val;
            }
            Ok(())
        }
    }

    #[test]
    fn ecam_discovers_nvme_64bit_bar_and_msix_cap() {
        let mock = MockEcam {
            cmd_written: RefCell::new(0),
        };
        let ecam = PcieEcam::new(&mock);
        let mut devs = [None; 4];
        let n = ecam.scan_bus(0, 4, &mut devs);
        assert_eq!(n, 1);
        let d = devs[0].expect("nvme device");
        assert!(d.is_nvme());
        assert_eq!(d.bar0_phys, 0x0000_001B_0000_0000);
        assert_eq!(d.msix_cap_offset, Some(0x50));

        ecam.enable_bus_master(0, 0, 0).expect("enable bm");
        assert_ne!(
            *mock.cmd_written.borrow() & (PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER),
            0
        );
    }
}
