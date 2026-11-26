//! Raspberry Pi 5 RP1 Cadence GEM (`macb`) Driver.
//!
//! Targets the Cadence GEM Gigabit Ethernet controller inside the Raspberry Pi 5 RP1 southbridge
//! (MMIO physical base `0x1F_0010_0000`, module ID `0x0007_0109`), running in EL0
//! via capability-scoped `MmioRead32`/`MmioWrite32` and `VirtToPhys`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;
use smoltcp::phy::{
    Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
};
use smoltcp::time::Instant;

use crate::{MmioDmaTransport, NetError, phys_hi32, phys_lo32};

const RING_SIZE: usize = 32;
const PKT_BUF_SIZE: usize = 2048; // Divides 4096 evenly -> never crosses a 4 KiB page boundary!
const PKT_BUF_SIZE_U32: u32 = 2048;
const _: () = assert!(PKT_BUF_SIZE == PKT_BUF_SIZE_U32 as usize);
const PKT_BUF_WORDS: usize = PKT_BUF_SIZE / 8;

// Cadence GEM (MACB) MMIO register offsets
pub const REG_NCR: u64 = 0x0000;
pub const REG_NCFGR: u64 = 0x0004;
pub const REG_NSR: u64 = 0x0008;
pub const REG_DMACFG: u64 = 0x0010;
pub const REG_TSR: u64 = 0x0014;
pub const REG_RBQP: u64 = 0x0018;
pub const REG_TBQP: u64 = 0x001C;
pub const REG_RSR: u64 = 0x0020;
pub const REG_ISR: u64 = 0x0024;
pub const REG_IER: u64 = 0x0028;
pub const REG_IDR: u64 = 0x002C;
pub const REG_MAN: u64 = 0x0034;
pub const REG_SA1B: u64 = 0x0088;
pub const REG_SA1T: u64 = 0x008C;
pub const REG_MID: u64 = 0x00FC;
pub const REG_TBQPH: u64 = 0x04C8;
pub const REG_RBQPH: u64 = 0x04D4;

// ISR / IER bits (RX complete + TX complete)
const ISR_RCOMP: u32 = 1 << 1;
const ISR_TCOMP: u32 = 1 << 7;
// NCFGR / DMACFG hardware checksum offload bits
const NCFGR_RXCOEN: u32 = 1 << 24;
const DMACFG_TXCOEN: u32 = 1 << 11;

// NSR bits
const NSR_IDLE: u32 = 1 << 2;

// IEEE 802.3 Clause 22 MDIO constants (BCM54213PE PHY on Raspberry Pi 5 is at address 1)
pub const RPI5_PHY_ADDR: u8 = 1;
pub const MII_BMSR: u8 = 0x01;
pub const BMSR_LSTATUS: u16 = 1 << 2;
const MAN_CLAUSE22_READ: u32 = (1 << 30) | (0b10 << 28) | (0b10 << 16);

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
const DMACFG_64BIT_2K: u32 = 0x10 | (0x7 << 8) | ((PKT_BUF_SIZE_U32 / 64) << 16) | (1 << 30);

// 64-bit RX descriptor flags (in `addr_lo`)
const RX_USED: u32 = 1 << 0;
const RX_WRAP: u32 = 1 << 1;
const RX_LEN_MASK: u32 = 0x1FFF;

// 64-bit TX descriptor flags (in `ctrl`)
const TX_LAST: u32 = 1 << 15;
const TX_WRAP: u32 = 1 << 30;
const TX_USED: u32 = 1 << 31;

/// Cache-coherency mode for Cadence GEM DMA descriptor rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RingCoherency {
    NonCoherent,
    Coherent,
}

impl RingCoherency {
    #[inline]
    const fn needs_cache_maintenance(self) -> bool {
        matches!(self, Self::NonCoherent)
    }
}

/// Discovered Raspberry Pi 5 RP1 Cadence GEM Gigabit Ethernet controller metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    let sa1_bottom = read32(REG_SA1B).unwrap_or(0).to_le_bytes();
    let sa1_top = read32(REG_SA1T).unwrap_or(0).to_le_bytes();
    let mut mac = [
        sa1_bottom[0],
        sa1_bottom[1],
        sa1_bottom[2],
        sa1_bottom[3],
        sa1_top[0],
        sa1_top[1],
    ];
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
struct GemPacketBuf([AtomicU64; PKT_BUF_WORDS]);

impl GemPacketBuf {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; PKT_BUF_WORDS])
    }

    #[inline]
    fn write_bytes(&self, src: &[u8]) {
        let full_words = src.len() / 8;
        for (w, slot) in self.0.iter().enumerate().take(full_words) {
            let off = w * 8;
            let val = u64::from_le_bytes([
                src[off],
                src[off + 1],
                src[off + 2],
                src[off + 3],
                src[off + 4],
                src[off + 5],
                src[off + 6],
                src[off + 7],
            ]);
            slot.store(val, Ordering::Relaxed);
        }
        let rem = src.len() & 7;
        if rem > 0 {
            let mut tail = [0u8; 8];
            tail[..rem].copy_from_slice(&src[full_words * 8..]);
            self.0[full_words].store(u64::from_le_bytes(tail), Ordering::Relaxed);
        }
    }

    #[inline]
    fn read_bytes(&self, dst: &mut [u8]) {
        let full_words = dst.len() / 8;
        for (w, slot) in self.0.iter().enumerate().take(full_words) {
            let bytes = slot.load(Ordering::Relaxed).to_le_bytes();
            let off = w * 8;
            dst[off..off + 8].copy_from_slice(&bytes);
        }
        let rem = dst.len() & 7;
        if rem > 0 {
            let bytes = self.0[full_words].load(Ordering::Relaxed).to_le_bytes();
            dst[full_words * 8..].copy_from_slice(&bytes[..rem]);
        }
    }
}

/// Static 64-bit DMA descriptor rings & packet buffers for RP1 Cadence GEM.
pub struct GemDma {
    rx_ring: GemDescRing,
    tx_ring: GemDescRing,
    rx_bufs: [GemPacketBuf; RING_SIZE],
    tx_bufs: [GemPacketBuf; RING_SIZE],
}

impl core::fmt::Debug for GemDma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GemDma")
            .field("ring_size", &RING_SIZE)
            .field("pkt_buf_size", &PKT_BUF_SIZE)
            .finish_non_exhaustive()
    }
}

impl Default for GemDma {
    fn default() -> Self {
        Self::new()
    }
}

impl GemDma {
    #[must_use]
    // Intentional: `#![no_std]` zero-alloc DMA backing store evaluated into `.bss` `static`s.
    #[allow(clippy::large_stack_arrays)]
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
    /// When `RingCoherency::Coherent`, `rx_ring`/`tx_ring` live in Normal Non-Cacheable DMA
    /// memory (`DmaMap` with `DMA_FLAG_NON_CACHEABLE`), skipping descriptor cache maintenance (`H4`).
    ring_coherency: RingCoherency,
    rx_idx: usize,
    tx_idx: usize,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl<T: MmioDmaTransport> core::fmt::Debug for GemNetDevice<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GemNetDevice")
            .field("ring_coherency", &self.ring_coherency)
            .field("rx_idx", &self.rx_idx)
            .field("tx_idx", &self.tx_idx)
            .field("rx_packets", &self.rx_packets)
            .field("tx_packets", &self.tx_packets)
            .finish_non_exhaustive()
    }
}

impl<'a, T: MmioDmaTransport> GemNetDevice<'a, T> {
    /// Initialize Cadence GEM with non-coherent DMA descriptor rings (explicit cache maintenance).
    ///
    /// # Errors
    ///
    /// Returns [`NetError::MmioFailed`] or [`NetError::DmaTranslateFailed`] if register programming
    /// or DMA physical address translation fails.
    pub fn init(transport: T, info: GemInfo, dma: &'a GemDma) -> Result<Self, NetError> {
        Self::init_inner(transport, info, dma, RingCoherency::NonCoherent)
    }

    /// Initialize Cadence GEM with hardware-coherent / Normal Non-Cacheable descriptor rings (`H4`),
    /// eliminating shared-cache-line descriptor overwrite hazards on non-coherent ARM64 DMA.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::MmioFailed`] or [`NetError::DmaTranslateFailed`] if register programming
    /// or DMA physical address translation fails.
    pub fn init_coherent(transport: T, info: GemInfo, dma: &'a GemDma) -> Result<Self, NetError> {
        Self::init_inner(transport, info, dma, RingCoherency::Coherent)
    }

    fn init_inner(
        transport: T,
        info: GemInfo,
        dma: &'a GemDma,
        ring_coherency: RingCoherency,
    ) -> Result<Self, NetError> {
        // 1. Disable RX/TX & mask interrupts while configuring DMA rings
        transport
            .write32(REG_NCR, NCR_MPE)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_IDR, 0xFFFF_FFFF)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_TSR, 0xFFFF_FFFF)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_RSR, 0xFFFF_FFFF)
            .map_err(NetError::MmioFailed)?;

        // 2. Program MAC address into SA1B/SA1T
        let sa1_bottom = u32::from_le_bytes([info.mac[0], info.mac[1], info.mac[2], info.mac[3]]);
        let sa1_top = u32::from_le_bytes([info.mac[4], info.mac[5], 0, 0]);
        transport
            .write32(REG_SA1B, sa1_bottom)
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_SA1T, sa1_top)
            .map_err(NetError::MmioFailed)?;

        // 3. Configure 64-bit DMA mode with 2 KiB RX buffers + TX hardware checksum offload
        transport
            .write32(REG_DMACFG, DMACFG_64BIT_2K | DMACFG_TXCOEN)
            .map_err(NetError::MmioFailed)?;

        // 4. Populate 64-bit RX descriptors (owned by GEM hardware: RX_USED = 0)
        for i in 0..RING_SIZE {
            let phys = transport
                .virt_to_phys(&dma.rx_bufs[i])
                .map_err(NetError::DmaTranslateFailed)?;
            let wrap = if i + 1 == RING_SIZE { RX_WRAP } else { 0 };
            dma.rx_ring.0[i]
                .addr_hi
                .store(phys_hi32(phys), Ordering::Relaxed);
            dma.rx_ring.0[i].ctrl.store(0, Ordering::Relaxed);
            dma.rx_ring.0[i].reserved.store(0, Ordering::Relaxed);
            dma.rx_ring.0[i]
                .addr_lo
                .store((phys_lo32(phys) & !0x3) | wrap, Ordering::Release);
        }

        // 5. Populate 64-bit TX descriptors (owned by CPU initially: TX_USED = 1)
        for i in 0..RING_SIZE {
            let phys = transport
                .virt_to_phys(&dma.tx_bufs[i])
                .map_err(NetError::DmaTranslateFailed)?;
            let wrap = if i + 1 == RING_SIZE { TX_WRAP } else { 0 };
            dma.tx_ring.0[i]
                .addr_lo
                .store(phys_lo32(phys), Ordering::Relaxed);
            dma.tx_ring.0[i]
                .addr_hi
                .store(phys_hi32(phys), Ordering::Relaxed);
            dma.tx_ring.0[i].reserved.store(0, Ordering::Relaxed);
            dma.tx_ring.0[i]
                .ctrl
                .store(TX_USED | wrap, Ordering::Release);
        }
        fence(Ordering::SeqCst);
        // Flush initial DMA descriptor rings & invalidate RX packet buffers for non-coherent RP1 DMA.
        if ring_coherency.needs_cache_maintenance() {
            let _ = transport.dma_clean(&dma.rx_ring);
            let _ = transport.dma_clean(&dma.tx_ring);
            for buf in &dma.rx_bufs {
                let _ = transport.dma_invalidate(buf);
            }
        }

        // 6. Program 64-bit RX and TX ring base addresses
        let rx_ring_phys = transport
            .virt_to_phys(&dma.rx_ring)
            .map_err(NetError::DmaTranslateFailed)?;
        let tx_ring_phys = transport
            .virt_to_phys(&dma.tx_ring)
            .map_err(NetError::DmaTranslateFailed)?;
        transport
            .write32(REG_RBQP, phys_lo32(rx_ring_phys))
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_RBQPH, phys_hi32(rx_ring_phys))
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_TBQP, phys_lo32(tx_ring_phys))
            .map_err(NetError::MmioFailed)?;
        transport
            .write32(REG_TBQPH, phys_hi32(tx_ring_phys))
            .map_err(NetError::MmioFailed)?;

        // 7. Preserve firmware PHY/RGMII config in NCFGR while enabling Full-Duplex + Gigabit + FCS strip + RX CSUM offload
        let prev_ncfgr = transport.read32(REG_NCFGR).unwrap_or(0);
        let _ = transport.write32(REG_NCFGR, prev_ncfgr | NCFGR_RXCOEN);
        // Enable RX/TX completion interrupts for IRQ-driven EL0 `net-pd` wakeup
        let _ = transport.write32(REG_IER, ISR_RCOMP | ISR_TCOMP);
        let ncfgr = prev_ncfgr | NCFGR_SPD | NCFGR_FD | NCFGR_GIGE | NCFGR_RFCS;
        transport
            .write32(REG_NCFGR, ncfgr)
            .map_err(NetError::MmioFailed)?;

        // 8. Enable RX + TX + MDIO
        transport
            .write32(REG_NCR, NCR_RXEN | NCR_TXEN | NCR_MPE)
            .map_err(NetError::MmioFailed)?;

        let dev = Self {
            transport,
            dma,
            ring_coherency,
            rx_idx: 0,
            tx_idx: 0,
            rx_packets: 0,
            tx_packets: 0,
        };
        // Query PHY link status via Clause 22 MDIO during initialization (`P11`);
        // best-effort so unit tests and pre-link boot continue cleanly.
        let _ = dev.phy_link_up(1);
        Ok(dev)
    }

    /// Perform an IEEE 802.3 Clause 22 MDIO register read on `phy_addr` (`0..=31`).
    ///
    /// # Errors
    ///
    /// Returns [`SysError::InvalidArgument`] if `phy_addr > 31` or `reg_addr > 31`,
    /// [`SysError::WouldBlock`] if the MDIO bus does not become idle, or an underlying MMIO error.
    pub fn mdio_read(&self, phy_addr: u8, reg_addr: u8) -> Result<u16, SysError> {
        if phy_addr > 31 || reg_addr > 31 {
            return Err(SysError::InvalidArgument);
        }
        for _ in 0..10_000u32 {
            if (self.transport.read32(REG_NSR)? & NSR_IDLE) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        let cmd = MAN_CLAUSE22_READ | (u32::from(phy_addr) << 23) | (u32::from(reg_addr) << 18);
        self.transport.write32(REG_MAN, cmd)?;
        for _ in 0..10_000u32 {
            if (self.transport.read32(REG_NSR)? & NSR_IDLE) != 0 {
                return Ok((self.transport.read32(REG_MAN)? & 0xFFFF) as u16);
            }
            core::hint::spin_loop();
        }
        Err(SysError::WouldBlock)
    }

    /// Check whether the Ethernet PHY reports an active link (IEEE 802.3 BMSR latched twice).
    ///
    /// # Errors
    ///
    /// Propagates any [`SysError`] returned by [`Self::mdio_read`].
    pub fn phy_link_up(&self, phy_addr: u8) -> Result<bool, SysError> {
        let _ = self.mdio_read(phy_addr, MII_BMSR)?;
        let bmsr = self.mdio_read(phy_addr, MII_BMSR)?;
        Ok((bmsr & BMSR_LSTATUS) != 0)
    }

    /// Acknowledge and clear pending Cadence GEM RX/TX interrupt status bits.
    pub fn ack_interrupts(&self) {
        let _ = self.transport.read32(REG_ISR);
    }
}

fn wait_tx_slot_ready<T: MmioDmaTransport>(
    transport: &T,
    dma: &GemDma,
    ring_coherency: RingCoherency,
    slot: usize,
) -> bool {
    for _ in 0..100_000u32 {
        if ring_coherency.needs_cache_maintenance() {
            let _ = transport.dma_invalidate(&dma.tx_ring.0[slot]);
        }
        if (dma.tx_ring.0[slot].ctrl.load(Ordering::Acquire) & TX_USED) != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

impl<T: MmioDmaTransport> crate::IrqAckDevice for GemNetDevice<'_, T> {
    fn ack_interrupts(&self) {
        GemNetDevice::ack_interrupts(self);
    }
}

pub struct GemRxToken<'a> {
    buf: &'a GemPacketBuf,
    desc: &'a GemDesc64,
    frame_len: usize,
}

impl core::fmt::Debug for GemRxToken<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GemRxToken")
            .field("frame_len", &self.frame_len)
            .finish_non_exhaustive()
    }
}

impl Drop for GemRxToken<'_> {
    fn drop(&mut self) {
        // Recycle RX descriptor back to GEM hardware by clearing RX_USED (bit 0).
        // Executed in `Drop` so descriptor ownership is returned even if `consume()` is skipped or unwinds.
        fence(Ordering::SeqCst);
        let prev = self.desc.addr_lo.load(Ordering::Relaxed);
        self.desc.addr_lo.store(prev & !RX_USED, Ordering::Release);
    }
}

impl RxToken for GemRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut local = [0u8; 1536];
        let n = self.frame_len.min(local.len());
        self.buf.read_bytes(&mut local[..n]);
        f(&local[..n])
    }
}

pub struct GemTxToken<'a, T: MmioDmaTransport> {
    transport: &'a T,
    dma: &'a GemDma,
    ring_coherency: RingCoherency,
    tx_idx: &'a mut usize,
    tx_packets: &'a mut u64,
}

impl<T: MmioDmaTransport> core::fmt::Debug for GemTxToken<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GemTxToken")
            .field("ring_coherency", &self.ring_coherency)
            .field("tx_idx", &*self.tx_idx)
            .finish_non_exhaustive()
    }
}

impl<T: MmioDmaTransport> GemTxToken<'_, T> {
    fn send_frame(self, frame: &[u8]) {
        let len = frame.len().min(PKT_BUF_SIZE);
        let slot = *self.tx_idx;
        // Wait (bounded) until the hardware sets `TX_USED` on this descriptor so we never
        // overwrite a TX buffer while DMA still owns it (`M9`).
        if !wait_tx_slot_ready(self.transport, self.dma, self.ring_coherency, slot) {
            return;
        }
        self.dma.tx_bufs[slot].write_bytes(&frame[..len]);
        let wrap = if slot + 1 == RING_SIZE { TX_WRAP } else { 0 };
        fence(Ordering::SeqCst);
        if self.ring_coherency.needs_cache_maintenance()
            && self.transport.dma_clean(&self.dma.tx_bufs[slot]).is_err()
        {
            return;
        }
        let len_u32 = u32::try_from(len).unwrap_or(PKT_BUF_SIZE_U32);
        // Clear TX_USED (bit 31) and set TX_LAST + length so GEM transmits the frame.
        self.dma.tx_ring.0[slot]
            .ctrl
            .store(len_u32 | TX_LAST | wrap, Ordering::Release);
        fence(Ordering::SeqCst);
        if self.ring_coherency.needs_cache_maintenance()
            && self.transport.dma_clean(&self.dma.tx_ring.0[slot]).is_err()
        {
            return;
        }

        let _ = self
            .transport
            .write32(REG_NCR, NCR_RXEN | NCR_TXEN | NCR_MPE | NCR_TSTART);
        *self.tx_idx = (slot + 1) % RING_SIZE;
        *self.tx_packets += 1;
    }
}

impl<T: MmioDmaTransport> TxToken for GemTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut local = [0u8; 1536];
        let n = len.min(local.len());
        let res = f(&mut local[..n]);
        self.send_frame(&local[..n]);
        res
    }
}

impl<T: MmioDmaTransport> Device for GemNetDevice<'_, T> {
    type RxToken<'a>
        = GemRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = GemTxToken<'a, T>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let _ = self.transport.read32(REG_ISR);
        let prev_slot = (self.rx_idx + RING_SIZE - 1) % RING_SIZE;
        if self.ring_coherency.needs_cache_maintenance() {
            let _ = self.transport.dma_clean(&self.dma.rx_ring.0[prev_slot]);
        }

        fence(Ordering::SeqCst);
        let slot = self.rx_idx;
        let desc = &self.dma.rx_ring.0[slot];
        if self.ring_coherency.needs_cache_maintenance() {
            let _ = self.transport.dma_invalidate(desc);
        }
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
            if self.ring_coherency.needs_cache_maintenance() {
                let _ = self.transport.dma_clean(desc);
            }
            return None;
        }

        if self.ring_coherency.needs_cache_maintenance() {
            let _ = self.transport.dma_invalidate(&self.dma.rx_bufs[slot]);
        }

        let rx = GemRxToken {
            buf: &self.dma.rx_bufs[slot],
            desc,
            frame_len,
        };
        let tx = GemTxToken {
            transport: &self.transport,
            dma: self.dma,
            ring_coherency: self.ring_coherency,
            tx_idx: &mut self.tx_idx,
            tx_packets: &mut self.tx_packets,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let slot = self.tx_idx;
        if self.ring_coherency.needs_cache_maintenance() {
            let _ = self.transport.dma_invalidate(&self.dma.tx_ring.0[slot]);
        }
        let ctrl = self.dma.tx_ring.0[slot].ctrl.load(Ordering::Acquire);
        if (ctrl & TX_USED) == 0 {
            // Descriptor still in flight
            return None;
        }
        Some(GemTxToken {
            transport: &self.transport,
            dma: self.dma,
            ring_coherency: self.ring_coherency,
            tx_idx: &mut self.tx_idx,
            tx_packets: &mut self.tx_packets,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        let mut csum = ChecksumCapabilities::default();
        csum.ipv4 = Checksum::None;
        csum.tcp = Checksum::None;
        csum.udp = Checksum::None;
        caps.checksum = csum;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGemTransport {
        mid: u32,
        phy_bmsr: u16,
    }

    impl MmioDmaTransport for MockGemTransport {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_MID => Ok(self.mid),
                REG_NSR => Ok(NSR_IDLE),
                REG_MAN => Ok(u32::from(self.phy_bmsr)),
                REG_ISR => Ok(ISR_RCOMP | ISR_TCOMP),
                _ => Ok(0),
            }
        }

        fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
            Ok(())
        }

        fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
            Ok(core::ptr::from_ref::<T>(r) as usize as u64)
        }
    }

    #[test]
    fn probe_cadence_gem_validates_module_id_and_fallback_mac() {
        // Non-GEM module ID rejected
        assert!(probe_cadence_gem(|_| Ok(0x1234_0000)).is_none());
        // MMIO error rejected
        assert!(probe_cadence_gem(|_| Err(SysError::InvalidCapability)).is_none());

        // Valid GEM ID with all-zero SA1 uses locally-administered fallback MAC
        let info = probe_cadence_gem(|off| match off {
            REG_MID => Ok(0x0007_0109),
            _ => Ok(0),
        })
        .expect("valid GEM");
        assert_eq!(info.revision, 0x0109);
        assert_eq!(info.mac, [0x02, 0x5E, 0x14, 0x00, 0x05, 0x16]);

        // Valid GEM ID with programmed SA1 preserves MAC
        let info2 = probe_cadence_gem(|off| match off {
            REG_MID => Ok(0x0007_0109),
            REG_SA1B => Ok(u32::from_le_bytes([0xDC, 0xA6, 0x32, 0x11])),
            REG_SA1T => Ok(u32::from_le_bytes([0x22, 0x33, 0x00, 0x00])),
            _ => Ok(0),
        })
        .expect("valid GEM with SA1");
        assert_eq!(info2.mac, [0xDC, 0xA6, 0x32, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn gem_init_mdio_tx_rx_and_bad_length_drop() {
        let dma = GemDma::new();
        let info = GemInfo {
            module_id: 0x0007_0109,
            revision: 0x0109,
            mac: [0x02, 0x5E, 0x14, 0x00, 0x05, 0x16],
        };
        let transport = MockGemTransport {
            mid: 0x0007_0109,
            phy_bmsr: BMSR_LSTATUS,
        };
        let mut dev = GemNetDevice::init(transport, info, &dma).expect("gem init");
        assert_eq!(dev.capabilities().medium, Medium::Ethernet);
        assert_eq!(dev.phy_link_up(RPI5_PHY_ADDR), Ok(true));

        // No RX frame ready yet
        assert!(dev.receive(Instant::ZERO).is_none());

        // Transmit a 64-byte frame through TxToken
        let tx = dev.transmit(Instant::ZERO).expect("tx slot ready");
        tx.consume(64, |buf| buf.fill(0xAB));

        // Inject a zero-length RX descriptor -> dropped cleanly without panic
        let old_addr0 = dma.rx_ring.0[0].addr_lo.load(Ordering::Relaxed);
        dma.rx_ring.0[0].ctrl.store(0, Ordering::Relaxed);
        dma.rx_ring.0[0]
            .addr_lo
            .store(old_addr0 | RX_USED, Ordering::Release);
        assert!(dev.receive(Instant::ZERO).is_none());

        // Inject a valid 60-byte RX frame into slot 1 -> received cleanly
        let sample = [0x5Au8; 60];
        dma.rx_bufs[1].write_bytes(&sample);
        let old_addr1 = dma.rx_ring.0[1].addr_lo.load(Ordering::Relaxed);
        dma.rx_ring.0[1].ctrl.store(60, Ordering::Relaxed);
        dma.rx_ring.0[1]
            .addr_lo
            .store(old_addr1 | RX_USED, Ordering::Release);
        let (rx, _tx) = dev.receive(Instant::ZERO).expect("valid RX frame");
        rx.consume(|bytes| {
            assert_eq!(bytes.len(), 60);
            assert!(bytes.iter().all(|&b| b == 0x5A));
        });
    }

    #[test]
    fn gem_init_coherent_and_mmio_error_propagation() {
        struct CountingTransport {
            fail_mmio: bool,
            fail_dma: bool,
            cache_ops: AtomicU32,
        }
        impl MmioDmaTransport for &CountingTransport {
            fn read32(&self, offset: u64) -> Result<u32, SysError> {
                match offset {
                    REG_NSR => Ok(NSR_IDLE),
                    REG_MAN => Ok(u32::from(BMSR_LSTATUS)),
                    _ => Ok(0),
                }
            }
            fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
                if self.fail_mmio {
                    Err(SysError::InvalidCapability)
                } else {
                    Ok(())
                }
            }
            fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
                if self.fail_dma {
                    Err(SysError::InvalidArgument)
                } else {
                    Ok(core::ptr::from_ref::<T>(r) as usize as u64)
                }
            }
            fn dma_clean<T>(&self, _r: &T) -> Result<(), SysError> {
                self.cache_ops.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn dma_invalidate<T>(&self, _r: &T) -> Result<(), SysError> {
                self.cache_ops.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let dma = GemDma::new();
        let info = GemInfo {
            module_id: 0x0007_0109,
            revision: 0x0109,
            mac: [0x02, 0x5E, 0x14, 0x00, 0x05, 0x16],
        };

        // 1. MMIO failure propagates NetError::MmioFailed(SysError)
        let mmio_fail = CountingTransport {
            fail_mmio: true,
            fail_dma: false,
            cache_ops: AtomicU32::new(0),
        };
        assert_eq!(
            GemNetDevice::init(&mmio_fail, info, &dma).err(),
            Some(NetError::MmioFailed(SysError::InvalidCapability))
        );

        // 2. DMA failure propagates NetError::DmaTranslateFailed(SysError)
        let dma_fail = CountingTransport {
            fail_mmio: false,
            fail_dma: true,
            cache_ops: AtomicU32::new(0),
        };
        assert_eq!(
            GemNetDevice::init(&dma_fail, info, &dma).err(),
            Some(NetError::DmaTranslateFailed(SysError::InvalidArgument))
        );

        // 3. init_coherent skips cache maintenance and GemRxToken recycles RX_USED on Drop
        let ok_t = CountingTransport {
            fail_mmio: false,
            fail_dma: false,
            cache_ops: AtomicU32::new(0),
        };
        let mut dev = GemNetDevice::init_coherent(&ok_t, info, &dma).expect("coherent init");
        assert_eq!(ok_t.cache_ops.load(Ordering::Relaxed), 0);

        let old_addr0 = dma.rx_ring.0[0].addr_lo.load(Ordering::Relaxed);
        dma.rx_ring.0[0].ctrl.store(60, Ordering::Relaxed);
        dma.rx_ring.0[0]
            .addr_lo
            .store(old_addr0 | RX_USED, Ordering::Release);
        {
            let (_rx, _tx) = dev.receive(Instant::ZERO).expect("rx token");
            // Drop `_rx` without calling `consume()` -> RAII Drop must clear RX_USED!
        }
        assert_eq!(
            dma.rx_ring.0[0].addr_lo.load(Ordering::Acquire) & RX_USED,
            0
        );
        assert_eq!(ok_t.cache_ops.load(Ordering::Relaxed), 0);
    }
}
