//! Modern VirtIO 1.0+ (v2) MMIO Entropy Device (`virtio-rng-device`, `device_id == 4`)
//! running in EL0 for QEMU `aarch64` `virt`.

use crate::{EntropySource, RngError, RngTransport};
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering, fence};

pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976; // "virt"
pub const VIRTIO_DEVICE_RNG: u32 = 4;

const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
const REG_QUEUE_DEVICE_LOW: u64 = 0x0A0;
const REG_QUEUE_DEVICE_HIGH: u64 = 0x0A4;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

const VRING_DESC_F_WRITE: u16 = 2;
const QUEUE_SIZE: usize = 4;
const ENTROPY_BUF_LEN: usize = 64;
const MAX_POLL_ITERS: u32 = 500_000;

#[repr(C, align(16))]
struct VirtqDesc {
    addr: AtomicU64,
    len: AtomicU32,
    flags: AtomicU16,
    next: AtomicU16,
}

impl VirtqDesc {
    const fn new() -> Self {
        Self {
            addr: AtomicU64::new(0),
            len: AtomicU32::new(0),
            flags: AtomicU16::new(0),
            next: AtomicU16::new(0),
        }
    }
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags: AtomicU16,
    idx: AtomicU16,
    ring: [AtomicU16; QUEUE_SIZE],
    used_event: AtomicU16,
}

impl VirtqAvail {
    const fn new() -> Self {
        Self {
            flags: AtomicU16::new(0),
            idx: AtomicU16::new(0),
            ring: [const { AtomicU16::new(0) }; QUEUE_SIZE],
            used_event: AtomicU16::new(0),
        }
    }
}

#[repr(C, align(4))]
struct VirtqUsedElem {
    id: AtomicU32,
    len: AtomicU32,
}

impl VirtqUsedElem {
    const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            len: AtomicU32::new(0),
        }
    }
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags: AtomicU16,
    idx: AtomicU16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
    avail_event: AtomicU16,
}

impl VirtqUsed {
    const fn new() -> Self {
        Self {
            flags: AtomicU16::new(0),
            idx: AtomicU16::new(0),
            ring: [const { VirtqUsedElem::new() }; QUEUE_SIZE],
            avail_event: AtomicU16::new(0),
        }
    }
}

/// Static page-aligned EL0 DMA region for `VirtioRngDevice` (`Sync` via atomics, zero `unsafe`).
#[repr(C, align(4096))]
pub struct VirtioRngDma {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    used: VirtqUsed,
    buf: [AtomicU8; ENTROPY_BUF_LEN],
}

impl Default for VirtioRngDma {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioRngDma {
    pub const fn new() -> Self {
        Self {
            desc: [const { VirtqDesc::new() }; QUEUE_SIZE],
            avail: VirtqAvail::new(),
            used: VirtqUsed::new(),
            buf: [const { AtomicU8::new(0) }; ENTROPY_BUF_LEN],
        }
    }
}

/// Live EL0 VirtIO 1.0+ (v2) MMIO RNG driver (`device_id == 4`).
pub struct VirtioRngDevice<'a, T: RngTransport> {
    transport: T,
    dma: &'a VirtioRngDma,
    buf_phys: u64,
    avail_idx: u16,
    last_used_idx: u16,
}

impl<'a, T: RngTransport> VirtioRngDevice<'a, T> {
    /// Initialize a scoped VirtIO-RNG v2 MMIO device (capability already scoped to the single slot).
    pub fn init(transport: T, dma: &'a VirtioRngDma) -> Result<Self, RngError> {
        let magic = transport.read32(REG_MAGIC).map_err(RngError::Sys)?;
        let version = transport.read32(REG_VERSION).map_err(RngError::Sys)?;
        let device_id = transport.read32(REG_DEVICE_ID).map_err(RngError::Sys)?;
        if magic != VIRTIO_MMIO_MAGIC || device_id != VIRTIO_DEVICE_RNG || version < 2 {
            return Err(RngError::DeviceNotFound);
        }

        // Reset -> ACKNOWLEDGE -> DRIVER
        transport.write32(REG_STATUS, 0).map_err(RngError::Sys)?;
        let mut status = STATUS_ACKNOWLEDGE;
        transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;
        status |= STATUS_DRIVER;
        transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;

        // Negotiate VIRTIO_F_VERSION_1 (bit 32 -> word 1 bit 0)
        transport
            .write32(REG_DEVICE_FEATURES_SEL, 0)
            .map_err(RngError::Sys)?;
        let _ = transport
            .read32(REG_DEVICE_FEATURES)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_DEVICE_FEATURES_SEL, 1)
            .map_err(RngError::Sys)?;
        let dev_hi = transport
            .read32(REG_DEVICE_FEATURES)
            .map_err(RngError::Sys)?;
        if (dev_hi & 1) == 0 {
            return Err(RngError::HardwareFault);
        }
        transport
            .write32(REG_DRIVER_FEATURES_SEL, 0)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_DRIVER_FEATURES, 0)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_DRIVER_FEATURES_SEL, 1)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_DRIVER_FEATURES, 1)
            .map_err(RngError::Sys)?;

        status |= STATUS_FEATURES_OK;
        transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;
        let post_status = transport.read32(REG_STATUS).map_err(RngError::Sys)?;
        if (post_status & STATUS_FEATURES_OK) == 0 {
            return Err(RngError::HardwareFault);
        }

        // Configure single virtqueue 0 (`requestq`)
        transport.write32(REG_QUEUE_SEL, 0).map_err(RngError::Sys)?;
        let max_q = transport.read32(REG_QUEUE_NUM_MAX).map_err(RngError::Sys)?;
        if (max_q as usize) < QUEUE_SIZE {
            return Err(RngError::HardwareFault);
        }
        transport
            .write32(REG_QUEUE_NUM, QUEUE_SIZE as u32)
            .map_err(RngError::Sys)?;

        let desc_phys = transport.virt_to_phys(&dma.desc).map_err(RngError::Sys)?;
        let avail_phys = transport.virt_to_phys(&dma.avail).map_err(RngError::Sys)?;
        let used_phys = transport.virt_to_phys(&dma.used).map_err(RngError::Sys)?;
        let buf_phys = transport.virt_to_phys(&dma.buf).map_err(RngError::Sys)?;

        dma.avail.flags.store(0, Ordering::Relaxed);
        dma.avail.idx.store(0, Ordering::Relaxed);
        dma.used.flags.store(0, Ordering::Relaxed);
        dma.used.idx.store(0, Ordering::Relaxed);

        transport
            .write32(REG_QUEUE_DESC_LOW, desc_phys as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_DRIVER_LOW, avail_phys as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_DRIVER_HIGH, (avail_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_DEVICE_LOW, used_phys as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_DEVICE_HIGH, (used_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        transport
            .write32(REG_QUEUE_READY, 1)
            .map_err(RngError::Sys)?;

        status |= STATUS_DRIVER_OK;
        transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;

        Ok(Self {
            transport,
            dma,
            buf_phys,
            avail_idx: 0,
            last_used_idx: 0,
        })
    }

    fn pull_chunk(&mut self, len: usize) -> Result<usize, RngError> {
        let req_len = len.min(ENTROPY_BUF_LEN);
        if req_len == 0 {
            return Ok(0);
        }

        // Populate descriptor 0 (device-writable)
        self.dma.desc[0]
            .addr
            .store(self.buf_phys, Ordering::Relaxed);
        self.dma.desc[0]
            .len
            .store(req_len as u32, Ordering::Relaxed);
        self.dma.desc[0]
            .flags
            .store(VRING_DESC_F_WRITE, Ordering::Relaxed);
        self.dma.desc[0].next.store(0, Ordering::Relaxed);

        let slot = (self.avail_idx as usize) % QUEUE_SIZE;
        self.dma.avail.ring[slot].store(0, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.dma.avail.idx.store(self.avail_idx, Ordering::Release);
        fence(Ordering::SeqCst);

        self.transport
            .write32(REG_QUEUE_NOTIFY, 0)
            .map_err(RngError::Sys)?;

        for _ in 0..MAX_POLL_ITERS {
            let used_idx = self.dma.used.idx.load(Ordering::Acquire);
            if used_idx != self.last_used_idx {
                let used_slot = (self.last_used_idx as usize) % QUEUE_SIZE;
                let got = (self.dma.used.ring[used_slot].len.load(Ordering::Acquire) as usize)
                    .min(req_len);
                self.last_used_idx = used_idx;
                if got == 0 {
                    return Err(RngError::HardwareFault);
                }
                return Ok(got);
            }
            core::hint::spin_loop();
        }
        // Timeout: reset AND re-initialize the device so timed-out DMA descriptors are never
        // left in flight and subsequent handshakes recover automatically (`M16`).
        let _ = self.reinit_hardware();
        Err(RngError::HardwareTimeout)
    }

    fn reinit_hardware(&mut self) -> Result<(), RngError> {
        self.transport
            .write32(REG_STATUS, 0)
            .map_err(RngError::Sys)?;
        self.dma.avail.flags.store(0, Ordering::Relaxed);
        self.dma.avail.idx.store(0, Ordering::Release);
        self.dma.used.flags.store(0, Ordering::Relaxed);
        self.dma.used.idx.store(0, Ordering::Release);
        self.avail_idx = 0;
        self.last_used_idx = 0;

        let mut status = STATUS_ACKNOWLEDGE;
        self.transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;
        status |= STATUS_DRIVER;
        self.transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;

        self.transport
            .write32(REG_DRIVER_FEATURES_SEL, 0)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_DRIVER_FEATURES, 0)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_DRIVER_FEATURES_SEL, 1)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_DRIVER_FEATURES, 1)
            .map_err(RngError::Sys)?;

        status |= STATUS_FEATURES_OK;
        self.transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;
        if (self.transport.read32(REG_STATUS).map_err(RngError::Sys)? & STATUS_FEATURES_OK) == 0 {
            return Err(RngError::HardwareFault);
        }

        self.transport
            .write32(REG_QUEUE_SEL, 0)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_NUM, QUEUE_SIZE as u32)
            .map_err(RngError::Sys)?;

        let desc_phys = self
            .transport
            .virt_to_phys(&self.dma.desc)
            .map_err(RngError::Sys)?;
        let avail_phys = self
            .transport
            .virt_to_phys(&self.dma.avail)
            .map_err(RngError::Sys)?;
        let used_phys = self
            .transport
            .virt_to_phys(&self.dma.used)
            .map_err(RngError::Sys)?;

        self.transport
            .write32(REG_QUEUE_DESC_LOW, desc_phys as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_DRIVER_LOW, avail_phys as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_DRIVER_HIGH, (avail_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_DEVICE_LOW, used_phys as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_DEVICE_HIGH, (used_phys >> 32) as u32)
            .map_err(RngError::Sys)?;
        self.transport
            .write32(REG_QUEUE_READY, 1)
            .map_err(RngError::Sys)?;

        status |= STATUS_DRIVER_OK;
        self.transport
            .write32(REG_STATUS, status)
            .map_err(RngError::Sys)?;
        Ok(())
    }
}

impl<T: RngTransport> EntropySource for VirtioRngDevice<'_, T> {
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        let mut offset = 0;
        while offset < dst.len() {
            let got = self.pull_chunk(dst.len() - offset)?;
            for i in 0..got {
                let byte = self.dma.buf[i].swap(0, Ordering::AcqRel);
                dst[offset + i] = byte;
            }
            offset += got;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use newos_abi::SysError;

    struct MockVirtioRngTransport<'a> {
        magic: u32,
        version: u32,
        device_id: u32,
        queue_max: u32,
        status: AtomicU32,
        dma: &'a VirtioRngDma,
        respond_on_notify: bool,
    }

    impl RngTransport for MockVirtioRngTransport<'_> {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_MAGIC => Ok(self.magic),
                REG_VERSION => Ok(self.version),
                REG_DEVICE_ID => Ok(self.device_id),
                REG_DEVICE_FEATURES => Ok(1),
                REG_QUEUE_NUM_MAX => Ok(self.queue_max),
                REG_STATUS => Ok(self.status.load(Ordering::Relaxed)),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            match offset {
                REG_STATUS => self.status.store(val, Ordering::Relaxed),
                REG_QUEUE_NOTIFY if self.respond_on_notify => {
                    // Simulate QEMU VirtIO-RNG device filling the descriptor buffer
                    let used_idx = self.dma.used.idx.load(Ordering::Relaxed);
                    let slot = (used_idx as usize) % QUEUE_SIZE;
                    let req_len = (self.dma.desc[0].len.load(Ordering::Relaxed) as usize)
                        .min(ENTROPY_BUF_LEN);
                    for (i, slot_b) in self.dma.buf.iter().enumerate().take(req_len) {
                        slot_b.store(
                            ((i * 37 + used_idx as usize * 13 + 7) & 0xFF) as u8,
                            Ordering::Relaxed,
                        );
                    }
                    self.dma.used.ring[slot].id.store(0, Ordering::Relaxed);
                    self.dma.used.ring[slot]
                        .len
                        .store(req_len as u32, Ordering::Relaxed);
                    self.dma
                        .used
                        .idx
                        .store(used_idx.wrapping_add(1), Ordering::Release);
                }
                _ => {}
            }
            Ok(())
        }

        fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError> {
            Ok((value as *const T as usize) as u64)
        }
    }

    #[test]
    fn virtio_rng_init_rejects_bad_magic_version_and_device_id() {
        let dma = VirtioRngDma::new();
        let bad_magic = MockVirtioRngTransport {
            magic: 0x1234,
            version: 2,
            device_id: VIRTIO_DEVICE_RNG,
            queue_max: QUEUE_SIZE as u32,
            status: AtomicU32::new(0),
            dma: &dma,
            respond_on_notify: true,
        };
        assert_eq!(
            VirtioRngDevice::init(bad_magic, &dma).err(),
            Some(RngError::DeviceNotFound)
        );

        let bad_dev = MockVirtioRngTransport {
            magic: VIRTIO_MMIO_MAGIC,
            version: 2,
            device_id: 1, // virtio-net, not rng
            queue_max: QUEUE_SIZE as u32,
            status: AtomicU32::new(0),
            dma: &dma,
            respond_on_notify: true,
        };
        assert_eq!(
            VirtioRngDevice::init(bad_dev, &dma).err(),
            Some(RngError::DeviceNotFound)
        );

        let legacy_ver = MockVirtioRngTransport {
            magic: VIRTIO_MMIO_MAGIC,
            version: 1,
            device_id: VIRTIO_DEVICE_RNG,
            queue_max: QUEUE_SIZE as u32,
            status: AtomicU32::new(0),
            dma: &dma,
            respond_on_notify: true,
        };
        assert_eq!(
            VirtioRngDevice::init(legacy_ver, &dma).err(),
            Some(RngError::DeviceNotFound)
        );
    }

    #[test]
    fn virtio_rng_fills_multi_chunk_entropy_and_scrubs_dma_buf() {
        let dma = VirtioRngDma::new();
        let transport = MockVirtioRngTransport {
            magic: VIRTIO_MMIO_MAGIC,
            version: 2,
            device_id: VIRTIO_DEVICE_RNG,
            queue_max: QUEUE_SIZE as u32,
            status: AtomicU32::new(0),
            dma: &dma,
            respond_on_notify: true,
        };
        let mut dev = VirtioRngDevice::init(transport, &dma).expect("virtio-rng init");
        // Empty fill succeeds cleanly
        dev.fill_entropy(&mut []).expect("empty fill");

        // Multi-chunk (> 64 B) fill exercises multiple virtqueue descriptors
        let mut out = [0u8; 96];
        dev.fill_entropy(&mut out).expect("96B fill");
        assert!(out.iter().any(|&b| b != 0));
        // DMA buffer must be scrubbed to zero after reading
        assert!(dma.buf.iter().all(|b| b.load(Ordering::Relaxed) == 0));
    }
}
