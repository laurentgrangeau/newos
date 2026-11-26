//! Raspberry Pi AI HAT+ / AI Kit (Hailo-8 / Hailo-8L / Hailo-10H) `PCIe` NPU Driver.
//!
//! Targets external Hailo AI accelerators attached to the Raspberry Pi 5 `PCIe` 2.0 `x1` FFC slot,
//! providing `PCIe` device identification, BAR control status probing, and aligned vDMA descriptor
//! ring submission.

use core::num::{NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;

/// Hailo Technologies `PCIe` Vendor ID.
pub const HAILO_VENDOR_ID: u16 = 0x1E60;
/// Hailo-8 (26 TOPS) & Hailo-8L (13 TOPS) `PCIe` Device ID (Raspberry Pi AI Kit / AI HAT+).
pub const HAILO8_DEVICE_ID: u16 = 0x2864;
/// Hailo-10H `PCIe` Device ID (Raspberry Pi AI HAT+ 2).
pub const HAILO10H_DEVICE_ID: u16 = 0x45C4;

// Hailo PCIe BAR control & vDMA register offsets
pub const REG_HAILO_FW_STATUS: u64 = 0x0000;
pub const REG_HAILO_VDMA_CTRL: u64 = 0x0010;
pub const REG_HAILO_VDMA_DESC_ADDR_LO: u64 = 0x0014;
pub const REG_HAILO_VDMA_DESC_ADDR_HI: u64 = 0x0018;
pub const REG_HAILO_VDMA_DEPTH_DOORBELL: u64 = 0x001C;

pub const HAILO_FW_READY_BIT: u32 = 1 << 0;
pub const HAILO_VDMA_ENABLE_BIT: u32 = 1 << 0;

const VDMA_RING_SIZE_U8: u8 = 16;
const VDMA_RING_SIZE: usize = VDMA_RING_SIZE_U8 as usize;

const _: () = assert!(VDMA_RING_SIZE == VDMA_RING_SIZE_U8 as usize);

#[inline]
const fn split_u64(val: u64) -> (u32, u32) {
    let bytes = val.to_le_bytes();
    (
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    )
}

/// Capability-scoped MMIO + DMA transport for an external Hailo `PCIe` NPU.
pub trait HailoTransport {
    /// Read a 32-bit BAR register at `offset`.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit BAR register at `offset`.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;

    /// Translate an EL0 DMA descriptor ring reference into its physical address.
    ///
    /// # Errors
    /// Returns [`SysError`] if translation fails or is unsupported.
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    /// Clean data cache lines covering `value` before NPU DMA reads.
    ///
    /// # Errors
    /// Returns [`SysError`] if the cache maintenance syscall fails.
    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}

/// Identified Hailo NPU silicon family on the Raspberry Pi 5 `PCIe` `x1` FFC connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HailoModel {
    Hailo8Or8L,
    Hailo10H,
}

impl HailoModel {
    /// Identify a Hailo NPU silicon family from `PCIe` `(vendor_id, device_id)`.
    #[must_use]
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

impl core::fmt::Display for HailoModel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hailo8Or8L => f.write_str("Hailo-8/8L"),
            Self::Hailo10H => f.write_str("Hailo-10H"),
        }
    }
}

/// Direction of a Hailo vDMA tensor scatter-gather transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdmaDirection {
    DeviceToHost,
    HostToDevice,
}

/// 16-byte Hailo vDMA scatter-gather descriptor.
#[derive(Debug)]
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

/// Static 4 KiB-aligned Hailo vDMA descriptor ring.
#[derive(Debug)]
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
    /// Create a zero-initialized 4 KiB-aligned Hailo vDMA descriptor ring.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descs: [const { HailoVdmaDesc::zero() }; VDMA_RING_SIZE],
        }
    }
}

/// Capability-scoped EL0 Hailo-8/8L/10H `PCIe` NPU driver.
#[derive(Debug)]
pub struct HailoNpu<'a, T: HailoTransport> {
    transport: T,
    ring: &'a HailoVdmaRing,
    pub model: HailoModel,
    tail: u8,
}

impl<'a, T: HailoTransport> HailoNpu<'a, T> {
    /// Initialize a discovered Hailo NPU, verify firmware-ready status, and bind its vDMA ring.
    ///
    /// # Errors
    /// Returns [`SysError::Unsupported`] if `(vendor_id, device_id)` is not a supported Hailo NPU,
    /// [`SysError::WouldBlock`] if the NPU firmware is not yet ready, or a transport [`SysError`].
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
        let (ring_lo, ring_hi) = split_u64(ring_phys);
        transport.dma_clean(ring)?;
        transport.write32(REG_HAILO_VDMA_DESC_ADDR_LO, ring_lo)?;
        transport.write32(REG_HAILO_VDMA_DESC_ADDR_HI, ring_hi)?;
        transport.write32(REG_HAILO_VDMA_CTRL, HAILO_VDMA_ENABLE_BIT)?;

        Ok(Self {
            transport,
            ring,
            model,
            tail: 0,
        })
    }

    /// Enqueue a non-zero tensor DMA buffer (`tensor_phys`, `byte_len`) onto the Hailo vDMA ring
    /// and ring the hardware doorbell.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if DMA cache clean or doorbell MMIO write fails.
    pub fn enqueue_vdma_transfer(
        &mut self,
        tensor_phys: NonZeroU64,
        byte_len: NonZeroU32,
        direction: VdmaDirection,
    ) -> Result<(), SysError> {
        let slot = usize::from(self.tail);
        let desc = &self.ring.descs[slot];
        desc.phys_addr.store(tensor_phys.get(), Ordering::Relaxed);
        desc.byte_len.store(byte_len.get(), Ordering::Relaxed);
        let dir_bit = match direction {
            VdmaDirection::HostToDevice => 1u32 << 1,
            VdmaDirection::DeviceToHost => 0,
        };
        desc.ctrl.store(1 | dir_bit, Ordering::Release);
        fence(Ordering::SeqCst);
        self.transport.dma_clean(desc)?;

        self.tail = (self.tail + 1) % VDMA_RING_SIZE_U8;
        self.transport
            .write32(REG_HAILO_VDMA_DEPTH_DOORBELL, u32::from(self.tail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockHailo {
        fw_ready: bool,
        enabled: RefCell<bool>,
        doorbells: RefCell<u32>,
    }

    impl HailoTransport for &MockHailo {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_HAILO_FW_STATUS => Ok(if self.fw_ready { HAILO_FW_READY_BIT } else { 0 }),
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
            Ok(core::ptr::from_ref::<T>(value).addr() as u64)
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
            fw_ready: true,
            enabled: RefCell::new(false),
            doorbells: RefCell::new(0),
        };
        let mut npu =
            HailoNpu::init(&mock, &ring, HAILO_VENDOR_ID, HAILO8_DEVICE_ID).expect("hailo init");
        assert!(*mock.enabled.borrow());
        let phys = NonZeroU64::new(0x0001_0000_0000).expect("non-zero phys");
        let len = NonZeroU32::new(4096).expect("non-zero len");
        npu.enqueue_vdma_transfer(phys, len, VdmaDirection::HostToDevice)
            .expect("vdma h2d");
        assert_eq!(ring.descs[0].ctrl.load(Ordering::Acquire), 0b11);
        npu.enqueue_vdma_transfer(phys, len, VdmaDirection::DeviceToHost)
            .expect("vdma d2h");
        assert_eq!(ring.descs[1].ctrl.load(Ordering::Acquire), 0b01);
        assert_eq!(*mock.doorbells.borrow(), 2);
    }

    #[test]
    fn hailo_init_rejects_unknown_id_or_unready_fw_and_wraps_ring() {
        let ring = HailoVdmaRing::default();
        let ready_mock = MockHailo {
            fw_ready: true,
            enabled: RefCell::new(false),
            doorbells: RefCell::new(0),
        };
        assert_eq!(
            HailoNpu::init(&ready_mock, &ring, 0x1234, 0x5678).err(),
            Some(SysError::Unsupported)
        );

        let unready_mock = MockHailo {
            fw_ready: false,
            enabled: RefCell::new(false),
            doorbells: RefCell::new(0),
        };
        assert_eq!(
            HailoNpu::init(&unready_mock, &ring, HAILO_VENDOR_ID, HAILO10H_DEVICE_ID).err(),
            Some(SysError::WouldBlock)
        );

        let mut npu = HailoNpu::init(&ready_mock, &ring, HAILO_VENDOR_ID, HAILO10H_DEVICE_ID)
            .expect("hailo10h init");
        let phys = NonZeroU64::new(0x2000).expect("non-zero phys");
        let len = NonZeroU32::new(256).expect("non-zero len");
        for _ in 0..VDMA_RING_SIZE {
            npu.enqueue_vdma_transfer(phys, len, VdmaDirection::HostToDevice)
                .expect("enqueue");
        }
        assert_eq!(*ready_mock.doorbells.borrow(), u32::from(VDMA_RING_SIZE_U8));
    }
}
