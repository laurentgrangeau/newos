//! Raspberry Pi AI HAT+ / AI Kit (Hailo-8 / Hailo-8L / Hailo-10H) PCIe NPU Driver (`#![forbid(unsafe_code)]`).
//!
//! Targets external Hailo AI accelerators attached to the Raspberry Pi 5 PCIe 2.0 x1 FFC slot,
//! providing PCIe device identification, BAR control status probing, and aligned vDMA descriptor
//! ring submission (`no_alloc`).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;

/// Hailo Technologies PCIe Vendor ID.
pub const HAILO_VENDOR_ID: u16 = 0x1E60;
/// Hailo-8 (26 TOPS) & Hailo-8L (13 TOPS) PCIe Device ID (Raspberry Pi AI Kit / AI HAT+).
pub const HAILO8_DEVICE_ID: u16 = 0x2864;
/// Hailo-10H PCIe Device ID (Raspberry Pi AI HAT+ 2).
pub const HAILO10H_DEVICE_ID: u16 = 0x45C4;

// Hailo PCIe BAR control & vDMA register offsets
pub const REG_HAILO_FW_STATUS: u64 = 0x0000;
pub const REG_HAILO_VDMA_CTRL: u64 = 0x0010;
pub const REG_HAILO_VDMA_DESC_ADDR_LO: u64 = 0x0014;
pub const REG_HAILO_VDMA_DESC_ADDR_HI: u64 = 0x0018;
pub const REG_HAILO_VDMA_DEPTH_DOORBELL: u64 = 0x001C;

pub const HAILO_FW_READY_BIT: u32 = 1 << 0;
pub const HAILO_VDMA_ENABLE_BIT: u32 = 1 << 0;

const VDMA_RING_SIZE: usize = 16;

/// Capability-scoped MMIO + DMA transport for an external Hailo PCIe NPU.
pub trait HailoTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}

/// Identified Hailo NPU silicon family on the Raspberry Pi 5 PCIe x1 FFC connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HailoModel {
    Hailo8Or8L,
    Hailo10H,
}

impl HailoModel {
    pub const fn from_pci_ids(vendor_id: u16, device_id: u16) -> Option<Self> {
        if vendor_id != HAILO_VENDOR_ID {
            return None;
        }
        match device_id {
            HAILO8_DEVICE_ID => Some(Self::Hailo8Or8L),
            HAILO10H_DEVICE_ID => Some(Self::Hailo10H),
            _ => None,
        }
    }
}

/// 16-byte Hailo vDMA scatter-gather descriptor.
#[repr(C, align(16))]
pub struct HailoVdmaDesc {
    phys_addr: AtomicU64,
    byte_len: AtomicU32,
    ctrl: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<HailoVdmaDesc>() == 16);

impl HailoVdmaDesc {
    const fn zero() -> Self {
        Self {
            phys_addr: AtomicU64::new(0),
            byte_len: AtomicU32::new(0),
            ctrl: AtomicU32::new(0),
        }
    }
}

/// Static 4 KiB-aligned `no_alloc` Hailo vDMA descriptor ring.
#[repr(C, align(4096))]
pub struct HailoVdmaRing {
    descs: [HailoVdmaDesc; VDMA_RING_SIZE],
}

impl Default for HailoVdmaRing {
    fn default() -> Self {
        Self::new()
    }
}

impl HailoVdmaRing {
    pub const fn new() -> Self {
        Self {
            descs: [const { HailoVdmaDesc::zero() }; VDMA_RING_SIZE],
        }
    }
}

/// Capability-scoped EL0 Hailo-8/8L/10H PCIe NPU driver.
pub struct HailoNpu<'a, T: HailoTransport> {
    transport: T,
    ring: &'a HailoVdmaRing,
    pub model: HailoModel,
    tail: usize,
}

impl<'a, T: HailoTransport> HailoNpu<'a, T> {
    /// Initialize a discovered Hailo NPU, verify firmware-ready status, and bind its vDMA ring.
    pub fn init(
        transport: T,
        ring: &'a HailoVdmaRing,
        vendor_id: u16,
        device_id: u16,
    ) -> Result<Self, SysError> {
        let model = HailoModel::from_pci_ids(vendor_id, device_id).ok_or(SysError::Unsupported)?;
        let fw_status = transport.read32(REG_HAILO_FW_STATUS)?;
        if (fw_status & HAILO_FW_READY_BIT) == 0 {
            return Err(SysError::WouldBlock);
        }

        let ring_phys = transport.virt_to_phys(ring)?;
        transport.dma_clean(ring)?;
        transport.write32(REG_HAILO_VDMA_DESC_ADDR_LO, ring_phys as u32)?;
        transport.write32(REG_HAILO_VDMA_DESC_ADDR_HI, (ring_phys >> 32) as u32)?;
        transport.write32(REG_HAILO_VDMA_CTRL, HAILO_VDMA_ENABLE_BIT)?;

        Ok(Self {
            transport,
            ring,
            model,
            tail: 0,
        })
    }

    /// Enqueue a tensor DMA buffer (`tensor_phys`, `byte_len`) onto the Hailo vDMA ring
    /// and ring the hardware doorbell.
    pub fn enqueue_vdma_transfer(
        &mut self,
        tensor_phys: u64,
        byte_len: u32,
        is_host_to_device: bool,
    ) -> Result<(), SysError> {
        if tensor_phys == 0 || byte_len == 0 {
            return Err(SysError::InvalidArgument);
        }
        let slot = self.tail;
        let desc = &self.ring.descs[slot];
        desc.phys_addr.store(tensor_phys, Ordering::Relaxed);
        desc.byte_len.store(byte_len, Ordering::Relaxed);
        let dir_bit = if is_host_to_device { 1u32 << 1 } else { 0 };
        desc.ctrl.store(1 | dir_bit, Ordering::Release);
        fence(Ordering::SeqCst);
        self.transport.dma_clean(desc)?;

        self.tail = (slot + 1) % VDMA_RING_SIZE;
        self.transport
            .write32(REG_HAILO_VDMA_DEPTH_DOORBELL, self.tail as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockHailo {
        enabled: RefCell<bool>,
        doorbells: RefCell<u32>,
    }

    impl HailoTransport for &MockHailo {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_HAILO_FW_STATUS => Ok(HAILO_FW_READY_BIT),
                _ => Ok(0),
            }
        }
        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == REG_HAILO_VDMA_CTRL {
                *self.enabled.borrow_mut() = (val & HAILO_VDMA_ENABLE_BIT) != 0;
            } else if offset == REG_HAILO_VDMA_DEPTH_DOORBELL {
                *self.doorbells.borrow_mut() += 1;
            }
            Ok(())
        }
        fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError> {
            Ok((value as *const T as usize) as u64)
        }
    }

    #[test]
    fn hailo_identifies_ai_hat_and_submits_vdma_tensor_transfer() {
        assert_eq!(HailoModel::from_pci_ids(0x1234, 0x5678), None);
        assert_eq!(
            HailoModel::from_pci_ids(HAILO_VENDOR_ID, HAILO8_DEVICE_ID),
            Some(HailoModel::Hailo8Or8L)
        );
        assert_eq!(
            HailoModel::from_pci_ids(HAILO_VENDOR_ID, HAILO10H_DEVICE_ID),
            Some(HailoModel::Hailo10H)
        );

        let ring = HailoVdmaRing::new();
        let mock = MockHailo {
            enabled: RefCell::new(false),
            doorbells: RefCell::new(0),
        };
        let mut npu =
            HailoNpu::init(&mock, &ring, HAILO_VENDOR_ID, HAILO8_DEVICE_ID).expect("hailo init");
        assert!(*mock.enabled.borrow());
        npu.enqueue_vdma_transfer(0x0001_0000_0000, 4096, true)
            .expect("vdma submit");
        assert_eq!(*mock.doorbells.borrow(), 1);
    }
}
