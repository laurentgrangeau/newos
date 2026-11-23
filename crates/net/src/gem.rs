//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 RP1 Cadence GEM (`macb`) Driver.
//!
//! Targets the Cadence GEM Gigabit Ethernet controller inside the Raspberry Pi 5 RP1 southbridge
//! (MMIO physical base `0x1F_0010_0000`, module ID `0x0007_0109`), running 100% in EL0
//! via capability-scoped `MmioRead32`/`MmioWrite32` and `VirtToPhys`.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering, fence};
use newos_abi::SysError;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::virtio::MmioDmaTransport;

const RING_SIZE: usize = 8;
const PKT_BUF_SIZE: usize = 2048; // Divides 4096 evenly -> never crosses a 4 KiB page boundary!

// Cadence GEM (MACB) MMIO register offsets
pub const REG_NCR: u64 = 0x0000;
pub const REG_NCFGR: u64 = 0x0004;
pub const REG_NSR: u64 = 0x0008;
pub const REG_DMACFG: u64 = 0x0010;
pub const REG_TSR: u64 = 0x0014;
pub const REG_RBQP: u64 = 0x0018;
pub const REG_TBQP: u64 = 0x001C;
pub const REG_RSR: u64 = 0x0020;
pub const REG_IDR: u64 = 0x002C;
pub const REG_SA1B: u64 = 0x0088;
pub const REG_SA1T: u64 = 0x008C;
pub const REG_MID: u64 = 0x00FC;
pub const REG_TBQPH: u64 = 0x04C8;
pub const REG_RBQPH: u64 = 0x04D4;

// NCR bits
const NCR_RXEN: u32 = 1 << 2;
const NCR_TXEN: u32 = 1 << 3;
const NCR_MPE: u32 = 1 << 4;
const NCR_TSTART: u32 = 1 << 9;

// NCFGR bits
const NCFGR_SPD: u32 = 1 << 0;
const NCFGR_FD: u32 = 1 << 1;
const NCFGR_GIGE: u32 = 1 << 10;
const NCFGR_RFCS: u32 = 1 << 17;

// DMACFG bits: INCR16 burst (0x10) | full RX/TX SRAM (0x7 << 8) | 2048B RX buf (32 << 16) | 64-bit DMA (1 << 30)
const DMACFG_64BIT_2K: u32 = 0x10 | (0x7 << 8) | ((PKT_BUF_SIZE as u32 / 64) << 16) | (1 << 30);

// 64-bit RX descriptor flags (in `addr_lo`)
const RX_USED: u32 = 1 << 0;
const RX_WRAP: u32 = 1 << 1;
const RX_LEN_MASK: u32 = 0x1FFF;

// 64-bit TX descriptor flags (in `ctrl`)
const TX_LAST: u32 = 1 << 15;
const TX_WRAP: u32 = 1 << 30;
const TX_USED: u32 = 1 << 31;

/// Discovered Raspberry Pi 5 RP1 Cadence GEM Gigabit Ethernet controller metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GemInfo {
    pub module_id: u32,
    pub revision: u16,
    pub mac: [u8; 6],
}

/// Probe the capability-scoped MMIO window for a Cadence GEM / MACB controller (`REG_MID`).
pub fn probe_cadence_gem<F>(mut read32: F) -> Option<GemInfo>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    let mid = read32(REG_MID).ok()?;
    let id = (mid >> 16) & 0xFFFF;
    // Raspberry Pi 5 RP1 Cadence GEM_GXL module ID (`0x0007`, rev `0x0007_0109`).
    if id != 0x0007 {
        return None;
    }
    let sa1b = read32(REG_SA1B).unwrap_or(0).to_le_bytes();
    let sa1t = read32(REG_SA1T).unwrap_or(0).to_le_bytes();
    let mut mac = [sa1b[0], sa1b[1], sa1b[2], sa1b[3], sa1t[0], sa1t[1]];
    if mac == [0; 6] || mac == [0xFF; 6] {
        // Fallback locally-administered MAC if firmware did not pre-program SA1
        mac = [0x02, 0x5E, 0x14, 0x00, 0x05, 0x16];
    }
    Some(GemInfo {
        module_id: mid,
        revision: (mid & 0xFFFF) as u16,
        mac,
    })
}

#[repr(C)]
struct GemDesc64 {
    addr_lo: AtomicU32,
    ctrl: AtomicU32,
    addr_hi: AtomicU32,
    reserved: AtomicU32,
}

impl GemDesc64 {
    const fn new() -> Self {
        Self {
            addr_lo: AtomicU32::new(0),
            ctrl: AtomicU32::new(0),
            addr_hi: AtomicU32::new(0),
            reserved: AtomicU32::new(0),
        }
    }
}

#[repr(C, align(4096))]
struct GemDescRing([GemDesc64; RING_SIZE]);

#[repr(C, align(2048))]
struct GemPacketBuf([AtomicU8; PKT_BUF_SIZE]);

impl GemPacketBuf {
    const fn new() -> Self {
        Self([const { AtomicU8::new(0) }; PKT_BUF_SIZE])
    }
}

/// Static 64-bit DMA descriptor rings & packet buffers for RP1 Cadence GEM (`#![forbid(unsafe_code)]`).
pub struct GemDma {
    rx_ring: GemDescRing,
    tx_ring: GemDescRing,
    rx_bufs: [GemPacketBuf; RING_SIZE],
    tx_bufs: [GemPacketBuf; RING_SIZE],
}

impl Default for GemDma {
    fn default() -> Self {
        Self::new()
    }
}

impl GemDma {
    pub const fn new() -> Self {
        Self {
            rx_ring: GemDescRing([const { GemDesc64::new() }; RING_SIZE]),
            tx_ring: GemDescRing([const { GemDesc64::new() }; RING_SIZE]),
            rx_bufs: [const { GemPacketBuf::new() }; RING_SIZE],
            tx_bufs: [const { GemPacketBuf::new() }; RING_SIZE],
        }
    }
}

/// Live EL0 RP1 Cadence GEM Gigabit Ethernet `smoltcp::phy::Device`.
pub struct GemNetDevice<'a, T: MmioDmaTransport> {
    transport: T,
    dma: &'a GemDma,
    rx_idx: usize,
    tx_idx: usize,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl<'a, T: MmioDmaTransport> GemNetDevice<'a, T> {
    pub fn init(transport: T, info: GemInfo, dma: &'a GemDma) -> Result<Self, &'static str> {
        // 1. Disable RX/TX & mask interrupts while configuring DMA rings
        transport
            .write32(REG_NCR, NCR_MPE)
            .map_err(|_| "gem ncr disable failed")?;
        transport
            .write32(REG_IDR, 0xFFFF_FFFF)
            .map_err(|_| "gem idr failed")?;
        transport
            .write32(REG_TSR, 0xFFFF_FFFF)
            .map_err(|_| "gem tsr clear failed")?;
        transport
            .write32(REG_RSR, 0xFFFF_FFFF)
            .map_err(|_| "gem rsr clear failed")?;

        // 2. Program MAC address into SA1B/SA1T
        let sa1b = u32::from_le_bytes([info.mac[0], info.mac[1], info.mac[2], info.mac[3]]);
        let sa1t = u32::from_le_bytes([info.mac[4], info.mac[5], 0, 0]);
        transport
            .write32(REG_SA1B, sa1b)
            .map_err(|_| "gem sa1b failed")?;
        transport
            .write32(REG_SA1T, sa1t)
            .map_err(|_| "gem sa1t failed")?;

        // 3. Configure 64-bit DMA mode with 2 KiB RX buffers
        transport
            .write32(REG_DMACFG, DMACFG_64BIT_2K)
            .map_err(|_| "gem dmacfg failed")?;

        // 4. Populate 64-bit RX descriptors (owned by GEM hardware: RX_USED = 0)
        for i in 0..RING_SIZE {
            let phys = transport
                .virt_to_phys(&dma.rx_bufs[i])
                .map_err(|_| "gem rx buf virt_to_phys failed")?;
            let wrap = if i + 1 == RING_SIZE { RX_WRAP } else { 0 };
            dma.rx_ring.0[i]
                .addr_hi
                .store((phys >> 32) as u32, Ordering::Relaxed);
            dma.rx_ring.0[i].ctrl.store(0, Ordering::Relaxed);
            dma.rx_ring.0[i].reserved.store(0, Ordering::Relaxed);
            dma.rx_ring.0[i]
                .addr_lo
                .store(((phys as u32) & !0x3) | wrap, Ordering::Release);
        }

        // 5. Populate 64-bit TX descriptors (owned by CPU initially: TX_USED = 1)
        for i in 0..RING_SIZE {
            let phys = transport
                .virt_to_phys(&dma.tx_bufs[i])
                .map_err(|_| "gem tx buf virt_to_phys failed")?;
            let wrap = if i + 1 == RING_SIZE { TX_WRAP } else { 0 };
            dma.tx_ring.0[i]
                .addr_lo
                .store(phys as u32, Ordering::Relaxed);
            dma.tx_ring.0[i]
                .addr_hi
                .store((phys >> 32) as u32, Ordering::Relaxed);
            dma.tx_ring.0[i].reserved.store(0, Ordering::Relaxed);
            dma.tx_ring.0[i]
                .ctrl
                .store(TX_USED | wrap, Ordering::Release);
        }
        fence(Ordering::SeqCst);

        // 6. Program 64-bit RX and TX ring base addresses
        let rx_ring_phys = transport
            .virt_to_phys(&dma.rx_ring)
            .map_err(|_| "gem rx_ring virt_to_phys failed")?;
        let tx_ring_phys = transport
            .virt_to_phys(&dma.tx_ring)
            .map_err(|_| "gem tx_ring virt_to_phys failed")?;
        transport
            .write32(REG_RBQP, rx_ring_phys as u32)
            .map_err(|_| "gem rbqp failed")?;
        transport
            .write32(REG_RBQPH, (rx_ring_phys >> 32) as u32)
            .map_err(|_| "gem rbqph failed")?;
        transport
            .write32(REG_TBQP, tx_ring_phys as u32)
            .map_err(|_| "gem tbqp failed")?;
        transport
            .write32(REG_TBQPH, (tx_ring_phys >> 32) as u32)
            .map_err(|_| "gem tbqph failed")?;

        // 7. Preserve firmware PHY/RGMII config in NCFGR while enabling Full-Duplex + Gigabit + FCS strip
        let prev_ncfgr = transport.read32(REG_NCFGR).unwrap_or(0);
        let ncfgr = prev_ncfgr | NCFGR_SPD | NCFGR_FD | NCFGR_GIGE | NCFGR_RFCS;
        transport
            .write32(REG_NCFGR, ncfgr)
            .map_err(|_| "gem ncfgr failed")?;

        // 8. Enable RX + TX + MDIO
        transport
            .write32(REG_NCR, NCR_RXEN | NCR_TXEN | NCR_MPE)
            .map_err(|_| "gem ncr enable failed")?;

        Ok(Self {
            transport,
            dma,
            rx_idx: 0,
            tx_idx: 0,
            rx_packets: 0,
            tx_packets: 0,
        })
    }

    fn send_frame(&mut self, frame: &[u8]) {
        let len = frame.len().min(PKT_BUF_SIZE);
        let slot = self.tx_idx;
        let buf = &self.dma.tx_bufs[slot].0;
        for (i, &b) in frame[..len].iter().enumerate() {
            buf[i].store(b, Ordering::Relaxed);
        }
        let wrap = if slot + 1 == RING_SIZE { TX_WRAP } else { 0 };
        fence(Ordering::SeqCst);
        // Clear TX_USED (bit 31) and set TX_LAST + length so GEM transmits the frame
        self.dma.tx_ring.0[slot]
            .ctrl
            .store((len as u32) | TX_LAST | wrap, Ordering::Release);
        fence(Ordering::SeqCst);

        let _ = self
            .transport
            .write32(REG_NCR, NCR_RXEN | NCR_TXEN | NCR_MPE | NCR_TSTART);
        self.tx_idx = (slot + 1) % RING_SIZE;
        self.tx_packets += 1;
    }
}

pub struct GemRxToken<'a> {
    buf: &'a GemPacketBuf,
    desc: &'a GemDesc64,
    frame_len: usize,
}

impl RxToken for GemRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut local = [0u8; 1536];
        let n = self.frame_len.min(local.len());
        for (i, dst) in local[..n].iter_mut().enumerate() {
            *dst = self.buf.0[i].load(Ordering::Relaxed);
        }
        let res = f(&local[..n]);
        // Recycle RX descriptor back to GEM hardware by clearing RX_USED (bit 0)
        fence(Ordering::SeqCst);
        let prev = self.desc.addr_lo.load(Ordering::Relaxed);
        self.desc.addr_lo.store(prev & !RX_USED, Ordering::Release);
        res
    }
}

pub struct GemTxToken<'a, 'b, T: MmioDmaTransport> {
    dev: &'a mut GemNetDevice<'b, T>,
}

impl<T: MmioDmaTransport> TxToken for GemTxToken<'_, '_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut local = [0u8; 1536];
        let n = len.min(local.len());
        let res = f(&mut local[..n]);
        self.dev.send_frame(&local[..n]);
        res
    }
}

impl<'b, T: MmioDmaTransport> Device for GemNetDevice<'b, T> {
    type RxToken<'a>
        = GemRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = GemTxToken<'a, 'b, T>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        fence(Ordering::SeqCst);
        let slot = self.rx_idx;
        let desc = &self.dma.rx_ring.0[slot];
        let addr_lo = desc.addr_lo.load(Ordering::Acquire);
        if (addr_lo & RX_USED) == 0 {
            return None;
        }
        let ctrl = desc.ctrl.load(Ordering::Acquire);
        let frame_len = (ctrl & RX_LEN_MASK) as usize;
        self.rx_idx = (slot + 1) % RING_SIZE;
        self.rx_packets += 1;

        if frame_len == 0 || frame_len > PKT_BUF_SIZE {
            desc.addr_lo.store(addr_lo & !RX_USED, Ordering::Release);
            return None;
        }

        let rx = GemRxToken {
            buf: &self.dma.rx_bufs[slot],
            desc,
            frame_len,
        };
        let tx = GemTxToken { dev: self };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let slot = self.tx_idx;
        let ctrl = self.dma.tx_ring.0[slot].ctrl.load(Ordering::Acquire);
        if (ctrl & TX_USED) == 0 {
            // Descriptor still in flight
            return None;
        }
        Some(GemTxToken { dev: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps
    }
}
