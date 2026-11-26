//! Modern `VirtIO` 1.0+ (v2) MMIO Network Driver.
//!
//! Runs in EL0 using capability-scoped `MmioRead32`/`MmioWrite32` and `VirtToPhys`.
//! Every DMA ring and packet buffer is page-aligned (`<= 4096B`) so it never crosses a page boundary.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering, fence};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::{NetError, phys_hi32, phys_lo32};

const QUEUE_SIZE: usize = 32;
const QUEUE_SIZE_U16: u16 = 32;
const QUEUE_SIZE_U32: u32 = 32;
const VIRTIO_NET_HDR_LEN: usize = 12;
const PKT_BUF_SIZE: usize = 2048; // Divides 4096 evenly -> never crosses a 4 KiB page boundary!
const PKT_BUF_SIZE_U32: u32 = 2048;
const PKT_BUF_WORDS: usize = PKT_BUF_SIZE / 8;

const _: () = {
    assert!(QUEUE_SIZE == QUEUE_SIZE_U16 as usize);
    assert!(QUEUE_SIZE == QUEUE_SIZE_U32 as usize);
    assert!(PKT_BUF_SIZE == PKT_BUF_SIZE_U32 as usize);
};

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

/// Re-exported from crate root for backward compatibility.
pub use crate::MmioDmaTransport;

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
struct PacketBuf([AtomicU64; PKT_BUF_WORDS]);

impl PacketBuf {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; PKT_BUF_WORDS])
    }

    /// Write 12-byte zeroed `virtio_net_hdr_v1` followed by `frame` using 64-bit word strides.
    #[inline]
    fn write_virtio_tx(&self, frame: &[u8]) {
        self.0[0].store(0, Ordering::Relaxed);
        // Word 1 holds bytes 8..11 (zero header) + frame[0..4]
        let mut w1 = [0u8; 8];
        let first = frame.len().min(4);
        w1[4..4 + first].copy_from_slice(&frame[..first]);
        self.0[1].store(u64::from_le_bytes(w1), Ordering::Relaxed);
        let rest = &frame[first..];
        let full_words = rest.len() / 8;
        for i in 0..full_words {
            let off = i * 8;
            let val = u64::from_le_bytes([
                rest[off],
                rest[off + 1],
                rest[off + 2],
                rest[off + 3],
                rest[off + 4],
                rest[off + 5],
                rest[off + 6],
                rest[off + 7],
            ]);
            self.0[2 + i].store(val, Ordering::Relaxed);
        }
        let rem = rest.len() & 7;
        if rem > 0 {
            let mut tail = [0u8; 8];
            tail[..rem].copy_from_slice(&rest[full_words * 8..]);
            self.0[2 + full_words].store(u64::from_le_bytes(tail), Ordering::Relaxed);
        }
    }

    /// Read `dst.len()` Ethernet frame bytes starting at offset 12 (`VIRTIO_NET_HDR_LEN`).
    #[inline]
    fn read_virtio_rx(&self, dst: &mut [u8]) {
        if dst.is_empty() {
            return;
        }
        let w1 = self.0[1].load(Ordering::Relaxed).to_le_bytes();
        let first = dst.len().min(4);
        dst[..first].copy_from_slice(&w1[4..4 + first]);
        let rest = &mut dst[first..];
        let full_words = rest.len() / 8;
        for i in 0..full_words {
            let bytes = self.0[2 + i].load(Ordering::Relaxed).to_le_bytes();
            let off = i * 8;
            rest[off..off + 8].copy_from_slice(&bytes);
        }
        let rem = rest.len() & 7;
        if rem > 0 {
            let bytes = self.0[2 + full_words].load(Ordering::Relaxed).to_le_bytes();
            rest[full_words * 8..].copy_from_slice(&bytes[..rem]);
        }
    }
}

/// Static DMA memory backing RX and TX split virtqueues.
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

impl core::fmt::Debug for VirtioNetDma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetDma")
            .field("queue_size", &QUEUE_SIZE)
            .field("pkt_buf_size", &PKT_BUF_SIZE)
            .finish_non_exhaustive()
    }
}

impl VirtioNetDma {
    #[must_use]
    // Intentional: `#![no_std]` zero-alloc DMA backing store evaluated into `.bss` `static`s.
    #[allow(clippy::large_stack_arrays)]
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

/// Live EL0 `VirtIO` 1.0+ (v2) network device implementing `smoltcp::phy::Device`.
pub struct VirtioNetDevice<'a, T: MmioDmaTransport> {
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

impl<T: MmioDmaTransport> core::fmt::Debug for VirtioNetDevice<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioNetDevice")
            .field("slot_base", &self.slot_base)
            .field("rx_last_used", &self.rx_last_used)
            .field("tx_next_desc", &self.tx_next_desc)
            .field("rx_packets", &self.rx_packets)
            .field("tx_packets", &self.tx_packets)
            .finish_non_exhaustive()
    }
}

impl<'a, T: MmioDmaTransport> VirtioNetDevice<'a, T> {
    /// Initialize a modern `VirtIO`-MMIO v2 network device at `slot` and arm RX/TX virtqueues.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::MmioFailed`], [`NetError::DmaTranslateFailed`],
    /// [`NetError::VirtioFeaturesRejected`], or [`NetError::VirtqueueTooSmall`] if initialization
    /// fails.
    pub fn init(transport: T, slot: u8, dma: &'a VirtioNetDma) -> Result<Self, NetError> {
        let base = u64::from(slot) * 0x200;

        // 1. Reset device
        transport
            .write32(base + REG_STATUS, 0)
            .map_err(NetError::MmioFailed)?;

        // 2. Acknowledge + Driver
        transport
            .write32(base + REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER)
            .map_err(NetError::MmioFailed)?;

        // 3. Negotiate minimal VirtIO 1.0+ features: VIRTIO_NET_F_MAC (bit 5) + VIRTIO_F_VERSION_1 (bit 32)
        transport
            .write32(base + REG_DRIVER_FEATURES_SEL, 0)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(base + REG_DRIVER_FEATURES, 1 << 5)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(base + REG_DRIVER_FEATURES_SEL, 1)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(base + REG_DRIVER_FEATURES, 1 << 0) // bit 32 = VIRTIO_F_VERSION_1
            .map_err(NetError::MmioFailed)?;

        // 4. FEATURES_OK handshake
        transport
            .write32(
                base + REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
            )
            .map_err(NetError::MmioFailed)?;
        let status = transport
            .read32(base + REG_STATUS)
            .map_err(NetError::MmioFailed)?;
        if (status & STATUS_FEATURES_OK) == 0 {
            return Err(NetError::VirtioFeaturesRejected);
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

        // 5b. Zero all four ring indices before publishing descriptors so re-initialization
        // never sees stale used/avail entries from a previous session (`H6`).
        dma.rx_avail.idx.store(0, Ordering::Release);
        dma.rx_used.idx.store(0, Ordering::Release);
        dma.tx_avail.idx.store(0, Ordering::Release);
        dma.tx_used.idx.store(0, Ordering::Release);
        fence(Ordering::SeqCst);

        // 6. Populate all RX buffers and publish to RX avail ring
        for i_u16 in 0..QUEUE_SIZE_U16 {
            let i = usize::from(i_u16);
            let paddr = transport
                .virt_to_phys(&dma.rx_bufs[i])
                .map_err(NetError::DmaTranslateFailed)?;
            dma.rx_desc.0[i].addr.store(paddr, Ordering::Relaxed);
            dma.rx_desc.0[i]
                .len
                .store(PKT_BUF_SIZE_U32, Ordering::Relaxed);
            dma.rx_desc.0[i]
                .flags
                .store(DESC_F_WRITE, Ordering::Relaxed);
            dma.rx_desc.0[i].next.store(0, Ordering::Relaxed);
            dma.rx_avail.ring[i].store(i_u16, Ordering::Relaxed);
        }
        fence(Ordering::Release);
        dma.rx_avail.idx.store(QUEUE_SIZE_U16, Ordering::Release);

        // 7. DRIVER_OK -> device is live!
        transport
            .write32(
                base + REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            )
            .map_err(NetError::MmioFailed)?;

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

    /// Acknowledge and clear pending `VirtIO`-MMIO interrupt status bits.
    pub fn ack_interrupts(&self) {
        if let Ok(isr) = self.transport.read32(self.slot_base + REG_INTERRUPT_STATUS)
            && isr != 0
        {
            let _ = self
                .transport
                .write32(self.slot_base + REG_INTERRUPT_ACK, isr);
        }
    }
}

impl<T: MmioDmaTransport> crate::IrqAckDevice for VirtioNetDevice<'_, T> {
    fn ack_interrupts(&self) {
        VirtioNetDevice::ack_interrupts(self);
    }
}

fn setup_queue<T: MmioDmaTransport>(
    transport: &T,
    base: u64,
    queue_idx: u32,
    desc: &DescTable,
    avail: &AvailRing,
    used: &UsedRing,
) -> Result<(), NetError> {
    transport
        .write32(base + REG_QUEUE_SEL, queue_idx)
        .map_err(NetError::MmioFailed)?;
    let max = transport
        .read32(base + REG_QUEUE_NUM_MAX)
        .map_err(NetError::MmioFailed)?;
    if max < QUEUE_SIZE_U32 {
        return Err(NetError::VirtqueueTooSmall);
    }
    transport
        .write32(base + REG_QUEUE_NUM, QUEUE_SIZE_U32)
        .map_err(NetError::MmioFailed)?;

    let desc_pa = transport
        .virt_to_phys(desc)
        .map_err(NetError::DmaTranslateFailed)?;
    let avail_pa = transport
        .virt_to_phys(avail)
        .map_err(NetError::DmaTranslateFailed)?;
    let used_pa = transport
        .virt_to_phys(used)
        .map_err(NetError::DmaTranslateFailed)?;

    transport
        .write32(base + REG_QUEUE_DESC_LOW, phys_lo32(desc_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_DESC_HIGH, phys_hi32(desc_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_DRIVER_LOW, phys_lo32(avail_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_DRIVER_HIGH, phys_hi32(avail_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_DEVICE_LOW, phys_lo32(used_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_DEVICE_HIGH, phys_hi32(used_pa))
        .map_err(NetError::MmioFailed)?;
    transport
        .write32(base + REG_QUEUE_READY, 1)
        .map_err(NetError::MmioFailed)?;
    Ok(())
}

fn wait_tx_slot_free(dma: &VirtioNetDma) -> bool {
    let avail_idx = dma.tx_avail.idx.load(Ordering::Acquire);
    for _ in 0..100_000u32 {
        let used_idx = dma.tx_used.idx.load(Ordering::Acquire);
        if (avail_idx.wrapping_sub(used_idx) as usize) < QUEUE_SIZE {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

pub struct VirtioRxToken<'a> {
    frame: &'a [u8],
}

impl core::fmt::Debug for VirtioRxToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioRxToken")
            .field("frame_len", &self.frame.len())
            .finish_non_exhaustive()
    }
}

impl RxToken for VirtioRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.frame)
    }
}

pub struct VirtioTxToken<'a, T: MmioDmaTransport> {
    transport: &'a T,
    slot_base: u64,
    dma: &'a VirtioNetDma,
    desc_idx: u16,
    scratch: &'a mut [u8; 1600],
    tx_packets: &'a mut u64,
}

impl<T: MmioDmaTransport> core::fmt::Debug for VirtioTxToken<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioTxToken")
            .field("slot_base", &self.slot_base)
            .field("desc_idx", &self.desc_idx)
            .finish_non_exhaustive()
    }
}

impl<T: MmioDmaTransport> TxToken for VirtioTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let frame_len = len.min(self.scratch.len());
        let res = f(&mut self.scratch[..frame_len]);

        let idx_u16 = self.desc_idx % QUEUE_SIZE_U16;
        let idx = usize::from(idx_u16);
        let tx_buf = &self.dma.tx_bufs[idx];

        // Wait (bounded) if all TX ring slots are still in flight so we never overwrite a
        // buffer owned by the VirtIO device (`M9`). Drop packet instead of corrupting DMA if still full.
        if !wait_tx_slot_free(self.dma) {
            return res;
        }

        // Prepend 12-byte zeroed `virtio_net_hdr_v1` + Ethernet frame (64-bit word-stride)
        tx_buf.write_virtio_tx(&self.scratch[..frame_len]);

        if let Ok(paddr) = self.transport.virt_to_phys(tx_buf) {
            let total_len =
                u32::try_from(VIRTIO_NET_HDR_LEN + frame_len).unwrap_or(PKT_BUF_SIZE_U32);
            self.dma.tx_desc.0[idx].addr.store(paddr, Ordering::Relaxed);
            self.dma.tx_desc.0[idx]
                .len
                .store(total_len, Ordering::Relaxed);
            self.dma.tx_desc.0[idx].flags.store(0, Ordering::Relaxed);
            self.dma.tx_desc.0[idx].next.store(0, Ordering::Relaxed);

            let avail_idx = self.dma.tx_avail.idx.load(Ordering::Relaxed);
            self.dma.tx_avail.ring[(avail_idx as usize) % QUEUE_SIZE]
                .store(idx_u16, Ordering::Relaxed);
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

impl<T: MmioDmaTransport> Device for VirtioNetDevice<'_, T> {
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
        rx_buf.read_virtio_rx(&mut self.rx_scratch[..frame_len]);

        // Immediately recycle RX descriptor back to the device
        let avail_idx = self.dma.rx_avail.idx.load(Ordering::Relaxed);
        let desc_slot_u16 = u16::try_from(desc_id % QUEUE_SIZE).unwrap_or(0);
        self.dma.rx_avail.ring[(avail_idx as usize) % QUEUE_SIZE]
            .store(desc_slot_u16, Ordering::Relaxed);
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
        let avail_idx = self.dma.tx_avail.idx.load(Ordering::Acquire);
        let used_idx = self.dma.tx_used.idx.load(Ordering::Acquire);
        if (avail_idx.wrapping_sub(used_idx) as usize) >= QUEUE_SIZE {
            return None;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use newos_abi::SysError;

    struct MockVirtioTransport {
        queue_max: u32,
        status: AtomicU32,
    }

    impl MmioDmaTransport for MockVirtioTransport {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset & 0x1FF {
                REG_QUEUE_NUM_MAX => Ok(self.queue_max),
                REG_STATUS => Ok(self.status.load(Ordering::Relaxed)),
                REG_INTERRUPT_STATUS => Ok(1),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if (offset & 0x1FF) == REG_STATUS {
                self.status.store(val, Ordering::Relaxed);
            }
            Ok(())
        }

        fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
            Ok(core::ptr::from_ref::<T>(r) as usize as u64)
        }
    }

    #[test]
    fn packet_buf_virtio_hdr_tx_rx_roundtrip_various_lengths() {
        let buf = PacketBuf::new();
        for len in [0usize, 1, 4, 7, 13, 60, 127, 512, 1514] {
            let mut frame = [0u8; 1514];
            for (i, b) in frame[..len].iter_mut().enumerate() {
                *b = (i * 31 + 17).to_le_bytes()[0];
            }
            buf.write_virtio_tx(&frame[..len]);
            let mut out = [0u8; 1514];
            buf.read_virtio_rx(&mut out[..len]);
            assert_eq!(&out[..len], &frame[..len]);
        }
    }

    #[test]
    fn virtio_net_init_tx_queue_full_and_rx_recycle() {
        // Queue too small must fail init cleanly
        let dma = VirtioNetDma::new();
        let bad_transport = MockVirtioTransport {
            queue_max: 4,
            status: AtomicU32::new(0),
        };
        assert_eq!(
            VirtioNetDevice::init(bad_transport, 0, &dma).err(),
            Some(NetError::VirtqueueTooSmall)
        );

        // Valid init
        let transport = MockVirtioTransport {
            queue_max: QUEUE_SIZE_U32,
            status: AtomicU32::new(0),
        };
        let mut dev = VirtioNetDevice::init(transport, 0, &dma).expect("virtio init");
        assert_eq!(dev.capabilities().medium, Medium::Ethernet);
        assert!(dev.receive(Instant::ZERO).is_none());

        // Fill all QUEUE_SIZE TX descriptors -> next transmit returns None
        for i in 0..QUEUE_SIZE {
            let tx = dev.transmit(Instant::ZERO).expect("tx slot available");
            tx.consume(64, |b| b.fill(i.to_le_bytes()[0]));
        }
        assert!(dev.transmit(Instant::ZERO).is_none());

        // Advance tx_used -> transmit becomes available again
        dma.tx_used.idx.store(1, Ordering::Release);
        assert!(dev.transmit(Instant::ZERO).is_some());

        // Simulate device delivering an RX frame in descriptor 0
        let payload = [0xC3u8; 42];
        dma.rx_bufs[0].write_virtio_tx(&payload);
        dma.rx_used.ring[0].id.store(0, Ordering::Relaxed);
        dma.rx_used.ring[0].len.store(
            u32::try_from(VIRTIO_NET_HDR_LEN + payload.len()).expect("rx len fits in u32"),
            Ordering::Relaxed,
        );
        dma.rx_used.idx.store(1, Ordering::Release);

        let (rx, _tx) = dev.receive(Instant::ZERO).expect("rx frame delivered");
        rx.consume(|bytes| {
            assert_eq!(bytes, &payload[..]);
        });
    }

    #[test]
    fn virtio_init_returns_structured_errors() {
        struct RejectFeaturesTransport;
        impl MmioDmaTransport for RejectFeaturesTransport {
            fn read32(&self, _offset: u64) -> Result<u32, SysError> {
                Ok(STATUS_ACKNOWLEDGE | STATUS_DRIVER)
            }
            fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
                Ok(())
            }
            fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
                Ok(core::ptr::from_ref::<T>(r) as usize as u64)
            }
        }

        struct FailMmioTransport;
        impl MmioDmaTransport for FailMmioTransport {
            fn read32(&self, _offset: u64) -> Result<u32, SysError> {
                Err(SysError::InvalidCapability)
            }
            fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
                Err(SysError::InvalidCapability)
            }
            fn virt_to_phys<T>(&self, _r: &T) -> Result<u64, SysError> {
                Err(SysError::InvalidCapability)
            }
        }

        let dma = VirtioNetDma::new();
        assert_eq!(
            VirtioNetDevice::init(RejectFeaturesTransport, 0, &dma).err(),
            Some(NetError::VirtioFeaturesRejected)
        );
        assert_eq!(
            VirtioNetDevice::init(FailMmioTransport, 0, &dma).err(),
            Some(NetError::MmioFailed(SysError::InvalidCapability))
        );
    }
}
