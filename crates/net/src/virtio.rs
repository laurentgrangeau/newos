//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Modern VirtIO 1.0+ (v2) MMIO Network Driver.
//!
//! Runs 100% in EL0 using capability-scoped `MmioRead32`/`MmioWrite32` and `VirtToPhys`.
//! Every DMA ring and packet buffer is page-aligned (`<= 4096B`) so it never crosses a page boundary.

use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

const QUEUE_SIZE: usize = 8;
const VIRTIO_NET_HDR_LEN: usize = 12;
const PKT_BUF_SIZE: usize = 2048; // Divides 4096 evenly -> never crosses a 4 KiB page boundary!

// Modern VirtIO-MMIO v2 register offsets
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_INTERRUPT_STATUS: u64 = 0x060;
const REG_INTERRUPT_ACK: u64 = 0x064;
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

const DESC_F_WRITE: u16 = 2;

/// Capability-scoped MMIO + DMA translation transport injected by EL0 `user-rt`.
pub trait VirtioTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
    fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError>;
}

#[repr(C)]
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

#[repr(C, align(4096))]
struct DescTable([VirtqDesc; QUEUE_SIZE]);

#[repr(C, align(4096))]
struct AvailRing {
    flags: AtomicU16,
    idx: AtomicU16,
    ring: [AtomicU16; QUEUE_SIZE],
    used_event: AtomicU16,
}

#[repr(C)]
struct UsedElem {
    id: AtomicU32,
    len: AtomicU32,
}

impl UsedElem {
    const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            len: AtomicU32::new(0),
        }
    }
}

#[repr(C, align(4096))]
struct UsedRing {
    flags: AtomicU16,
    idx: AtomicU16,
    ring: [UsedElem; QUEUE_SIZE],
    avail_event: AtomicU16,
}

#[repr(C, align(2048))]
struct PacketBuf([AtomicU8; PKT_BUF_SIZE]);

impl PacketBuf {
    const fn new() -> Self {
        Self([const { AtomicU8::new(0) }; PKT_BUF_SIZE])
    }
}

/// Static DMA memory backing RX and TX split virtqueues (`#![forbid(unsafe_code)]`, `no_alloc`).
pub struct VirtioNetDma {
    rx_desc: DescTable,
    rx_avail: AvailRing,
    rx_used: UsedRing,
    tx_desc: DescTable,
    tx_avail: AvailRing,
    tx_used: UsedRing,
    rx_bufs: [PacketBuf; QUEUE_SIZE],
    tx_bufs: [PacketBuf; QUEUE_SIZE],
}

impl VirtioNetDma {
    pub const fn new() -> Self {
        Self {
            rx_desc: DescTable([const { VirtqDesc::new() }; QUEUE_SIZE]),
            rx_avail: AvailRing {
                flags: AtomicU16::new(0),
                idx: AtomicU16::new(0),
                ring: [const { AtomicU16::new(0) }; QUEUE_SIZE],
                used_event: AtomicU16::new(0),
            },
            rx_used: UsedRing {
                flags: AtomicU16::new(0),
                idx: AtomicU16::new(0),
                ring: [const { UsedElem::new() }; QUEUE_SIZE],
                avail_event: AtomicU16::new(0),
            },
            tx_desc: DescTable([const { VirtqDesc::new() }; QUEUE_SIZE]),
            tx_avail: AvailRing {
                flags: AtomicU16::new(0),
                idx: AtomicU16::new(0),
                ring: [const { AtomicU16::new(0) }; QUEUE_SIZE],
                used_event: AtomicU16::new(0),
            },
            tx_used: UsedRing {
                flags: AtomicU16::new(0),
                idx: AtomicU16::new(0),
                ring: [const { UsedElem::new() }; QUEUE_SIZE],
                avail_event: AtomicU16::new(0),
            },
            rx_bufs: [const { PacketBuf::new() }; QUEUE_SIZE],
            tx_bufs: [const { PacketBuf::new() }; QUEUE_SIZE],
        }
    }
}

impl Default for VirtioNetDma {
    fn default() -> Self {
        Self::new()
    }
}

/// Live EL0 VirtIO 1.0+ (v2) network device implementing `smoltcp::phy::Device`.
pub struct VirtioNetDevice<'a, T: VirtioTransport> {
    transport: T,
    slot_base: u64,
    dma: &'a VirtioNetDma,
    rx_last_used: u16,
    tx_next_desc: u16,
    rx_scratch: [u8; 1600],
    tx_scratch: [u8; 1600],
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl<'a, T: VirtioTransport> VirtioNetDevice<'a, T> {
    /// Initialize a modern VirtIO-MMIO v2 network device at `slot` and arm RX/TX virtqueues.
    pub fn init(transport: T, slot: u8, dma: &'a VirtioNetDma) -> Result<Self, &'static str> {
        let base = u64::from(slot) * 0x200;

        // 1. Reset device
        transport
            .write32(base + REG_STATUS, 0)
            .map_err(|_| "virtio reset failed")?;

        // 2. Acknowledge + Driver
        transport
            .write32(base + REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER)
            .map_err(|_| "virtio status ack failed")?;

        // 3. Negotiate minimal VirtIO 1.0+ features: VIRTIO_NET_F_MAC (bit 5) + VIRTIO_F_VERSION_1 (bit 32)
        transport
            .write32(base + REG_DRIVER_FEATURES_SEL, 0)
            .map_err(|_| "features sel 0 failed")?;
        transport
            .write32(base + REG_DRIVER_FEATURES, 1 << 5)
            .map_err(|_| "features 0 write failed")?;
        transport
            .write32(base + REG_DRIVER_FEATURES_SEL, 1)
            .map_err(|_| "features sel 1 failed")?;
        transport
            .write32(base + REG_DRIVER_FEATURES, 1 << 0) // bit 32 = VIRTIO_F_VERSION_1
            .map_err(|_| "features 1 write failed")?;

        // 4. FEATURES_OK handshake
        transport
            .write32(
                base + REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            )
            .map_err(|_| "features ok write failed")?;
        let status = transport
            .read32(base + REG_STATUS)
            .map_err(|_| "status read failed")?;
        if (status & STATUS_FEATURES_OK) == 0 {
            return Err("virtio device rejected FEATURES_OK");
        }

        // 5. Configure Queue 0 (RX) and Queue 1 (TX)
        setup_queue(
            &transport,
            base,
            0,
            &dma.rx_desc,
            &dma.rx_avail,
            &dma.rx_used,
        )?;
        setup_queue(
            &transport,
            base,
            1,
            &dma.tx_desc,
            &dma.tx_avail,
            &dma.tx_used,
        )?;

        // 6. Populate all RX buffers and publish to RX avail ring
        for i in 0..QUEUE_SIZE {
            let paddr = transport
                .virt_to_phys(&dma.rx_bufs[i])
                .map_err(|_| "rx buf virt_to_phys failed")?;
            dma.rx_desc.0[i].addr.store(paddr, Ordering::Relaxed);
            dma.rx_desc.0[i]
                .len
                .store(PKT_BUF_SIZE as u32, Ordering::Relaxed);
            dma.rx_desc.0[i]
                .flags
                .store(DESC_F_WRITE, Ordering::Relaxed);
            dma.rx_desc.0[i].next.store(0, Ordering::Relaxed);
            dma.rx_avail.ring[i].store(i as u16, Ordering::Relaxed);
        }
        fence(Ordering::Release);
        dma.rx_avail.idx.store(QUEUE_SIZE as u16, Ordering::Release);

        // 7. DRIVER_OK -> device is live!
        transport
            .write32(
                base + REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            )
            .map_err(|_| "driver ok failed")?;

        // Kick RX queue so device can begin DMA'ing incoming frames immediately
        let _ = transport.write32(base + REG_QUEUE_NOTIFY, 0);

        Ok(Self {
            transport,
            slot_base: base,
            dma,
            rx_last_used: 0,
            tx_next_desc: 0,
            rx_scratch: [0; 1600],
            tx_scratch: [0; 1600],
            rx_packets: 0,
            tx_packets: 0,
        })
    }

    fn ack_interrupts(&self) {
        if let Ok(isr) = self.transport.read32(self.slot_base + REG_INTERRUPT_STATUS)
            && isr != 0
        {
            let _ = self
                .transport
                .write32(self.slot_base + REG_INTERRUPT_ACK, isr);
        }
    }
}

fn setup_queue<T: VirtioTransport>(
    transport: &T,
    base: u64,
    queue_idx: u32,
    desc: &DescTable,
    avail: &AvailRing,
    used: &UsedRing,
) -> Result<(), &'static str> {
    transport
        .write32(base + REG_QUEUE_SEL, queue_idx)
        .map_err(|_| "queue sel failed")?;
    let max = transport
        .read32(base + REG_QUEUE_NUM_MAX)
        .map_err(|_| "queue max read failed")?;
    if max < QUEUE_SIZE as u32 {
        return Err("virtqueue max size too small");
    }
    transport
        .write32(base + REG_QUEUE_NUM, QUEUE_SIZE as u32)
        .map_err(|_| "queue num write failed")?;

    let desc_pa = transport
        .virt_to_phys(desc)
        .map_err(|_| "desc virt_to_phys failed")?;
    let avail_pa = transport
        .virt_to_phys(avail)
        .map_err(|_| "avail virt_to_phys failed")?;
    let used_pa = transport
        .virt_to_phys(used)
        .map_err(|_| "used virt_to_phys failed")?;

    transport
        .write32(base + REG_QUEUE_DESC_LOW, desc_pa as u32)
        .map_err(|_| "desc low failed")?;
    transport
        .write32(base + REG_QUEUE_DESC_HIGH, (desc_pa >> 32) as u32)
        .map_err(|_| "desc high failed")?;
    transport
        .write32(base + REG_QUEUE_DRIVER_LOW, avail_pa as u32)
        .map_err(|_| "driver low failed")?;
    transport
        .write32(base + REG_QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32)
        .map_err(|_| "driver high failed")?;
    transport
        .write32(base + REG_QUEUE_DEVICE_LOW, used_pa as u32)
        .map_err(|_| "device low failed")?;
    transport
        .write32(base + REG_QUEUE_DEVICE_HIGH, (used_pa >> 32) as u32)
        .map_err(|_| "device high failed")?;
    transport
        .write32(base + REG_QUEUE_READY, 1)
        .map_err(|_| "queue ready failed")?;
    Ok(())
}

pub struct VirtioRxToken<'a> {
    frame: &'a [u8],
}

impl RxToken for VirtioRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.frame)
    }
}

pub struct VirtioTxToken<'a, T: VirtioTransport> {
    transport: &'a T,
    slot_base: u64,
    dma: &'a VirtioNetDma,
    desc_idx: u16,
    scratch: &'a mut [u8; 1600],
    tx_packets: &'a mut u64,
}

impl<T: VirtioTransport> TxToken for VirtioTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let frame_len = len.min(self.scratch.len());
        let res = f(&mut self.scratch[..frame_len]);

        let idx = (self.desc_idx as usize) % QUEUE_SIZE;
        let tx_buf = &self.dma.tx_bufs[idx];

        // Prepend 12-byte zeroed `virtio_net_hdr_v1` + Ethernet frame
        for b in tx_buf.0.iter().take(VIRTIO_NET_HDR_LEN) {
            b.store(0, Ordering::Relaxed);
        }
        for (i, &byte) in self.scratch[..frame_len].iter().enumerate() {
            tx_buf.0[VIRTIO_NET_HDR_LEN + i].store(byte, Ordering::Relaxed);
        }

        if let Ok(paddr) = self.transport.virt_to_phys(tx_buf) {
            self.dma.tx_desc.0[idx].addr.store(paddr, Ordering::Relaxed);
            self.dma.tx_desc.0[idx]
                .len
                .store((VIRTIO_NET_HDR_LEN + frame_len) as u32, Ordering::Relaxed);
            self.dma.tx_desc.0[idx].flags.store(0, Ordering::Relaxed);
            self.dma.tx_desc.0[idx].next.store(0, Ordering::Relaxed);

            let avail_idx = self.dma.tx_avail.idx.load(Ordering::Relaxed);
            self.dma.tx_avail.ring[(avail_idx as usize) % QUEUE_SIZE]
                .store(idx as u16, Ordering::Relaxed);
            fence(Ordering::Release);
            self.dma
                .tx_avail
                .idx
                .store(avail_idx.wrapping_add(1), Ordering::Release);
            let _ = self.transport.write32(self.slot_base + REG_QUEUE_NOTIFY, 1);
            *self.tx_packets = self.tx_packets.saturating_add(1);
        }

        res
    }
}

impl<T: VirtioTransport> Device for VirtioNetDevice<'_, T> {
    type RxToken<'a>
        = VirtioRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = VirtioTxToken<'a, T>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.ack_interrupts();
        let used_idx = self.dma.rx_used.idx.load(Ordering::Acquire);
        if used_idx == self.rx_last_used {
            return None;
        }
        fence(Ordering::Acquire);

        let ring_slot = (self.rx_last_used as usize) % QUEUE_SIZE;
        let desc_id = self.dma.rx_used.ring[ring_slot].id.load(Ordering::Relaxed) as usize;
        let total_len = self.dma.rx_used.ring[ring_slot].len.load(Ordering::Relaxed) as usize;
        self.rx_last_used = self.rx_last_used.wrapping_add(1);

        let frame_len = total_len
            .saturating_sub(VIRTIO_NET_HDR_LEN)
            .min(self.rx_scratch.len());
        let rx_buf = &self.dma.rx_bufs[desc_id % QUEUE_SIZE];
        for (i, dst) in self.rx_scratch[..frame_len].iter_mut().enumerate() {
            *dst = rx_buf.0[VIRTIO_NET_HDR_LEN + i].load(Ordering::Relaxed);
        }

        // Immediately recycle RX descriptor back to the device
        let avail_idx = self.dma.rx_avail.idx.load(Ordering::Relaxed);
        self.dma.rx_avail.ring[(avail_idx as usize) % QUEUE_SIZE]
            .store((desc_id % QUEUE_SIZE) as u16, Ordering::Relaxed);
        fence(Ordering::Release);
        self.dma
            .rx_avail
            .idx
            .store(avail_idx.wrapping_add(1), Ordering::Release);
        let _ = self.transport.write32(self.slot_base + REG_QUEUE_NOTIFY, 0);
        self.rx_packets = self.rx_packets.saturating_add(1);

        let tx_desc = self.tx_next_desc;
        self.tx_next_desc = self.tx_next_desc.wrapping_add(1);

        Some((
            VirtioRxToken {
                frame: &self.rx_scratch[..frame_len],
            },
            VirtioTxToken {
                transport: &self.transport,
                slot_base: self.slot_base,
                dma: self.dma,
                desc_idx: tx_desc,
                scratch: &mut self.tx_scratch,
                tx_packets: &mut self.tx_packets,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.ack_interrupts();
        let tx_desc = self.tx_next_desc;
        self.tx_next_desc = self.tx_next_desc.wrapping_add(1);
        Some(VirtioTxToken {
            transport: &self.transport,
            slot_base: self.slot_base,
            dma: self.dma,
            desc_idx: tx_desc,
            scratch: &mut self.tx_scratch,
            tx_packets: &mut self.tx_packets,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps
    }
}
