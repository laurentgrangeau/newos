#![no_std]

//! Raspberry Pi 5 RP1 Dual xHCI USB 3.0 / 2.0 Driver.
//!
//! Targets the two Synopsys xHCI 1.1+ host controllers inside the RP1 southbridge:
//! - `xHCI0`: `0x1F_0020_0000` (`CapId::BOOTSTRAP_XHCI0_MMIO`, 1x USB 3.0 + 1x USB 2.0)
//! - `xHCI1`: `0x1F_0030_0000` (`CapId::BOOTSTRAP_XHCI1_MMIO`, 1x USB 3.0 + 1x USB 2.0)

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;

pub const RP1_XHCI0_PHYS: u64 = 0x1F_0020_0000;
pub const RP1_XHCI1_PHYS: u64 = 0x1F_0030_0000;

// xHCI Capability Register Offsets
pub const CAP_CAPLENGTH_HCIVERSION: u64 = 0x00;
pub const CAP_HCSPARAMS1: u64 = 0x04;
pub const CAP_DBOFF: u64 = 0x14;
pub const CAP_RTSOFF: u64 = 0x18;

// xHCI Operational Register Offsets (relative to `cap_length`)
pub const OP_USBCMD: u64 = 0x00;
pub const OP_USBSTS: u64 = 0x04;
pub const OP_CRCR_LO: u64 = 0x18;
pub const OP_CRCR_HI: u64 = 0x1C;
pub const OP_DCBAAP_LO: u64 = 0x30;
pub const OP_DCBAAP_HI: u64 = 0x34;
pub const OP_CONFIG: u64 = 0x38;
pub const OP_PORTSC_BASE: u64 = 0x400;
pub const OP_PORTSC_STRIDE: u64 = 0x10;

// Interrupter 0 Runtime Register Offsets (relative to `rtsoff + 0x20`)
const IR_ERSTSZ: u64 = 0x08;
const IR_ERSTBA_LO: u64 = 0x10;
const IR_ERSTBA_HI: u64 = 0x14;
const IR_ERDP_LO: u64 = 0x18;
const IR_ERDP_HI: u64 = 0x1C;

const USBCMD_RS: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;

const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
const PORTSC_PR: u32 = 1 << 4; // Port Reset
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK: u32 = 0xF;

const TRB_TYPE_ENABLE_SLOT: u32 = 9 << 10;
const MAX_POLL: u32 = 100_000;
const RING_TRBS_U32: u32 = 16;
const RING_TRBS: usize = RING_TRBS_U32 as usize;

const _: () = assert!(RING_TRBS == RING_TRBS_U32 as usize);

#[inline]
const fn split_u64(val: u64) -> (u32, u32) {
    let bytes = val.to_le_bytes();
    (
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    )
}

/// Capability-scoped MMIO + DMA transport injected by EL0 `user-rt` or mock tests.
pub trait XhciTransport {
    /// Read a 32-bit register at `offset` within the scoped xHCI MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit register at `offset` within the scoped xHCI MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;

    /// Translate an EL0 DMA buffer reference into its physical address.
    ///
    /// # Errors
    /// Returns [`SysError`] if translation fails or is unsupported.
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    /// Clean data cache lines covering `value` before DMA device reads.
    ///
    /// # Errors
    /// Returns [`SysError`] if the cache maintenance syscall fails.
    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }

    /// Invalidate data cache lines covering `value` after DMA device writes.
    ///
    /// # Errors
    /// Returns [`SysError`] if the cache maintenance syscall fails.
    fn dma_invalidate<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}

/// 16-byte xHCI Transfer Request Block (`TRB`).
#[derive(Debug)]
#[repr(C)]
pub struct Trb {
    param_lo: AtomicU32,
    param_hi: AtomicU32,
    status: AtomicU32,
    control: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<Trb>() == 16);

impl Trb {
    const fn zero() -> Self {
        Self {
            param_lo: AtomicU32::new(0),
            param_hi: AtomicU32::new(0),
            status: AtomicU32::new(0),
            control: AtomicU32::new(0),
        }
    }
}

/// 16-byte Event Ring Segment Table Entry (`ERSTE`).
#[derive(Debug)]
#[repr(C)]
struct ErstEntry {
    ring_base: AtomicU64,
    ring_size: AtomicU32,
    rsvd: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<ErstEntry>() == 16);

#[derive(Debug)]
#[repr(C, align(4096))]
struct DcbaaPage([AtomicU64; 64]);

#[derive(Debug)]
#[repr(C, align(64))]
struct TrbRing([Trb; RING_TRBS]);

#[derive(Debug)]
#[repr(C, align(64))]
struct ErstPage([ErstEntry; 1]);

/// Static aligned DMA structures for an RP1 xHCI controller.
#[derive(Debug)]
pub struct XhciDma {
    dcbaa: DcbaaPage,
    cmd_ring: TrbRing,
    event_ring: TrbRing,
    erst: ErstPage,
}

impl Default for XhciDma {
    fn default() -> Self {
        Self::new()
    }
}

impl XhciDma {
    /// Create zero-initialized aligned DMA structures for an RP1 xHCI controller.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dcbaa: DcbaaPage([const { AtomicU64::new(0) }; 64]),
            cmd_ring: TrbRing([const { Trb::zero() }; RING_TRBS]),
            event_ring: TrbRing([const { Trb::zero() }; RING_TRBS]),
            erst: ErstPage([ErstEntry {
                ring_base: AtomicU64::new(0),
                ring_size: AtomicU32::new(0),
                rsvd: AtomicU32::new(0),
            }]),
        }
    }
}

/// Decoded xHCI Root Hub port speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    FullSpeed,
    LowSpeed,
    HighSpeed,
    SuperSpeed,
    SuperSpeedPlus,
    Unknown(u8),
}

impl UsbSpeed {
    /// Decode the USB speed protocol field from a raw xHCI `PORTSC` register value.
    #[must_use]
    pub const fn from_portsc(raw: u32) -> Self {
        match ((raw >> PORTSC_SPEED_SHIFT) & PORTSC_SPEED_MASK) as u8 {
            1 => Self::FullSpeed,
            2 => Self::LowSpeed,
            3 => Self::HighSpeed,
            4 => Self::SuperSpeed,
            5 => Self::SuperSpeedPlus,
            other => Self::Unknown(other),
        }
    }
}

impl core::fmt::Display for UsbSpeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FullSpeed => f.write_str("Full-Speed (12 Mbps)"),
            Self::LowSpeed => f.write_str("Low-Speed (1.5 Mbps)"),
            Self::HighSpeed => f.write_str("High-Speed (480 Mbps)"),
            Self::SuperSpeed => f.write_str("SuperSpeed (5 Gbps)"),
            Self::SuperSpeedPlus => f.write_str("SuperSpeedPlus (10 Gbps)"),
            Self::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

/// Snapshot of a single xHCI Root Hub port (`PORTSC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortInfo {
    pub port_index: u8,
    pub connected: bool,
    pub enabled: bool,
    pub speed: UsbSpeed,
}

/// Capability-scoped EL0 RP1 xHCI 1.1+ USB 3.0 / 2.0 host controller driver.
#[derive(Debug)]
pub struct Rp1Xhci<'a, T: XhciTransport> {
    transport: T,
    dma: &'a XhciDma,
    cap_len: u64,
    dboff: u64,
    rtsoff: u64,
    pub hci_version: u16,
    pub max_slots: u8,
    pub max_ports: u8,
    cmd_enqueue: usize,
    cmd_cycle: bool,
}

impl<'a, T: XhciTransport> Rp1Xhci<'a, T> {
    /// Halt, reset, program DCBAA/Command Ring/Event Ring, and start an RP1 xHCI controller.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `cap_len < 0x20`, [`SysError::WouldBlock`] if the
    /// controller fails to clear CNR, halt, or complete reset within `MAX_POLL` iterations, or a
    /// transport [`SysError`].
    pub fn init(transport: T, dma: &'a XhciDma) -> Result<Self, SysError> {
        let cap0 = transport.read32(CAP_CAPLENGTH_HCIVERSION)?;
        let cap_len = u64::from(cap0 & 0xFF);
        let hci_version = ((cap0 >> 16) & 0xFFFF) as u16;
        if cap_len < 0x20 {
            return Err(SysError::InvalidArgument);
        }
        let hcs1 = transport.read32(CAP_HCSPARAMS1)?;
        let max_slots = (hcs1 & 0xFF) as u8;
        let max_ports = ((hcs1 >> 24) & 0xFF) as u8;
        let dboff = u64::from(transport.read32(CAP_DBOFF)? & !0x3);
        let rtsoff = u64::from(transport.read32(CAP_RTSOFF)? & !0x1F);

        // 1. Wait until Controller Not Ready (CNR) clears, then halt & reset
        let mut cnr_clear = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(cap_len + OP_USBSTS)? & USBSTS_CNR) == 0 {
                cnr_clear = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !cnr_clear {
            return Err(SysError::WouldBlock);
        }
        let cmd = transport.read32(cap_len + OP_USBCMD)?;
        transport.write32(cap_len + OP_USBCMD, cmd & !USBCMD_RS)?;
        let mut halted = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(cap_len + OP_USBSTS)? & USBSTS_HCH) != 0 {
                halted = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !halted {
            return Err(SysError::WouldBlock);
        }
        transport.write32(cap_len + OP_USBCMD, USBCMD_HCRST)?;
        let mut reset_done = false;
        for _ in 0..MAX_POLL {
            let c = transport.read32(cap_len + OP_USBCMD)?;
            let s = transport.read32(cap_len + OP_USBSTS)?;
            if (c & USBCMD_HCRST) == 0 && (s & USBSTS_CNR) == 0 {
                reset_done = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !reset_done {
            return Err(SysError::WouldBlock);
        }

        // 2. Program MaxSlotsEn, DCBAAP, Command Ring (RCS=1), and Interrupter 0 Event Ring
        let slots = max_slots.min(32);
        transport.write32(cap_len + OP_CONFIG, u32::from(slots))?;
        let dcbaa_phys = transport.virt_to_phys(&dma.dcbaa)?;
        let cmd_phys = transport.virt_to_phys(&dma.cmd_ring)?;
        let evt_phys = transport.virt_to_phys(&dma.event_ring)?;
        let erst_phys = transport.virt_to_phys(&dma.erst)?;

        dma.erst.0[0].ring_base.store(evt_phys, Ordering::Relaxed);
        dma.erst.0[0]
            .ring_size
            .store(RING_TRBS_U32, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        transport.dma_clean(&dma.dcbaa)?;
        transport.dma_clean(&dma.cmd_ring)?;
        transport.dma_clean(&dma.erst)?;

        let (dcbaa_lo, dcbaa_hi) = split_u64(dcbaa_phys);
        let (cmd_lo, cmd_hi) = split_u64(cmd_phys);
        let (evt_lo, evt_hi) = split_u64(evt_phys);
        let (erst_lo, erst_hi) = split_u64(erst_phys);

        transport.write32(cap_len + OP_DCBAAP_LO, dcbaa_lo)?;
        transport.write32(cap_len + OP_DCBAAP_HI, dcbaa_hi)?;
        transport.write32(cap_len + OP_CRCR_LO, cmd_lo | 1)?; // RCS = 1
        transport.write32(cap_len + OP_CRCR_HI, cmd_hi)?;

        let ir0 = rtsoff + 0x20;
        transport.write32(ir0 + IR_ERSTSZ, 1)?;
        transport.write32(ir0 + IR_ERDP_LO, evt_lo)?;
        transport.write32(ir0 + IR_ERDP_HI, evt_hi)?;
        transport.write32(ir0 + IR_ERSTBA_LO, erst_lo)?;
        transport.write32(ir0 + IR_ERSTBA_HI, erst_hi)?;

        // 3. Start xHCI controller (USBCMD.RS = 1)
        transport.write32(cap_len + OP_USBCMD, USBCMD_RS)?;

        Ok(Self {
            transport,
            dma,
            cap_len,
            dboff,
            rtsoff,
            hci_version,
            max_slots: slots,
            max_ports,
            cmd_enqueue: 0,
            cmd_cycle: true,
        })
    }

    /// Enqueue an `EnableSlot` command TRB and ring Host Controller Doorbell 0.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if DMA cache clean or doorbell MMIO write fails.
    pub fn ring_enable_slot(&mut self) -> Result<(), SysError> {
        let idx = self.cmd_enqueue;
        let trb = &self.dma.cmd_ring.0[idx];
        trb.param_lo.store(0, Ordering::Relaxed);
        trb.param_hi.store(0, Ordering::Relaxed);
        trb.status.store(0, Ordering::Relaxed);
        let cycle_bit = u32::from(self.cmd_cycle);
        trb.control
            .store(TRB_TYPE_ENABLE_SLOT | cycle_bit, Ordering::Release);
        fence(Ordering::SeqCst);
        self.transport.dma_clean(trb)?;
        self.cmd_enqueue = (idx + 1) % (RING_TRBS - 1);
        if self.cmd_enqueue == 0 {
            self.cmd_cycle = !self.cmd_cycle;
        }
        self.transport.write32(self.dboff, 0)
    }

    /// Issue a USB port reset (`PORTSC.PR`) on 0-based `port_idx`.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `port_idx >= self.max_ports`, or a transport
    /// [`SysError`].
    pub fn reset_port(&self, port_idx: u8) -> Result<(), SysError> {
        if port_idx >= self.max_ports {
            return Err(SysError::InvalidArgument);
        }
        let off = self.cap_len + OP_PORTSC_BASE + u64::from(port_idx) * OP_PORTSC_STRIDE;
        let cur = self.transport.read32(off)?;
        self.transport.write32(off, (cur & !PORTSC_PED) | PORTSC_PR)
    }

    /// Scan all Root Hub ports (`0..max_ports.min(out.len())`) and report connection & speed.
    ///
    /// # Errors
    /// Returns a transport [`SysError`] if any `PORTSC` MMIO read fails.
    pub fn scan_ports(&self, out: &mut [Option<PortInfo>]) -> Result<usize, SysError> {
        let mut scanned = 0usize;
        for (port_idx, slot) in (0..self.max_ports).zip(out.iter_mut()) {
            let off = self.cap_len + OP_PORTSC_BASE + u64::from(port_idx) * OP_PORTSC_STRIDE;
            let ps = self.transport.read32(off)?;
            *slot = Some(PortInfo {
                port_index: port_idx,
                connected: (ps & PORTSC_CCS) != 0,
                enabled: (ps & PORTSC_PED) != 0,
                speed: UsbSpeed::from_portsc(ps),
            });
            scanned += 1;
        }
        Ok(scanned)
    }

    /// Return the xHCI Runtime Register Space offset (`RTSOFF`).
    #[inline]
    #[must_use]
    pub const fn runtime_offset(&self) -> u64 {
        self.rtsoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockXhci {
        running: RefCell<bool>,
        doorbell_rings: RefCell<u32>,
    }

    impl XhciTransport for &MockXhci {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                CAP_CAPLENGTH_HCIVERSION => Ok((0x0110 << 16) | 0x20), // xHCI 1.1, cap_len=0x20
                CAP_HCSPARAMS1 => Ok((2 << 24) | 32),                  // 2 ports, 32 slots
                CAP_DBOFF => Ok(0x2000),
                CAP_RTSOFF => Ok(0x1000),
                o if o == 0x20 + OP_USBCMD => {
                    Ok(if *self.running.borrow() { USBCMD_RS } else { 0 })
                }
                o if o == 0x20 + OP_USBSTS => Ok(if *self.running.borrow() {
                    0
                } else {
                    USBSTS_HCH
                }),
                // Port 0: USB 3.0 SuperSpeed connected & enabled
                o if o == 0x20 + OP_PORTSC_BASE => Ok(PORTSC_CCS | PORTSC_PED | (4 << 10)),
                // Port 1: USB 2.0 HighSpeed disconnected
                o if o == 0x20 + OP_PORTSC_BASE + OP_PORTSC_STRIDE => Ok(3 << 10),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == 0x20 + OP_USBCMD {
                *self.running.borrow_mut() = (val & USBCMD_RS) != 0;
            } else if offset == 0x2000 {
                *self.doorbell_rings.borrow_mut() += 1;
            }
            Ok(())
        }

        fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError> {
            Ok(core::ptr::from_ref::<T>(value).addr() as u64)
        }
    }

    #[test]
    fn xhci_init_scans_usb3_superspeed_port_and_rings_enable_slot() {
        let dma = XhciDma::new();
        let mock = MockXhci {
            running: RefCell::new(false),
            doorbell_rings: RefCell::new(0),
        };
        let mut xhci = Rp1Xhci::init(&mock, &dma).expect("xhci init");
        assert_eq!(xhci.hci_version, 0x0110);
        assert_eq!(xhci.max_ports, 2);
        assert!(*mock.running.borrow());

        let mut ports = [None; 4];
        let n = xhci.scan_ports(&mut ports).expect("scan ports");
        assert_eq!(n, 2);
        assert_eq!(
            ports[0],
            Some(PortInfo {
                port_index: 0,
                connected: true,
                enabled: true,
                speed: UsbSpeed::SuperSpeed,
            })
        );
        assert!(!ports[1].expect("port 1 present").connected);

        xhci.ring_enable_slot().expect("enable slot");
        assert_eq!(*mock.doorbell_rings.borrow(), 1);
    }

    #[test]
    fn xhci_rejects_bad_cap_len_timeouts_oob_port_and_wraps_cmd_ring() {
        struct FaultXhci {
            cap0: u32,
            usbsts: u32,
            usbcmd: u32,
        }
        impl XhciTransport for FaultXhci {
            fn read32(&self, offset: u64) -> Result<u32, SysError> {
                match offset {
                    CAP_CAPLENGTH_HCIVERSION => Ok(self.cap0),
                    CAP_HCSPARAMS1 => Ok((2 << 24) | 16),
                    o if o == 0x20 + OP_USBSTS => Ok(self.usbsts),
                    o if o == 0x20 + OP_USBCMD => Ok(self.usbcmd),
                    _ => Ok(0),
                }
            }
            fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
                Ok(())
            }
            fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError> {
                Ok(core::ptr::from_ref::<T>(value).addr() as u64)
            }
        }

        let dma = XhciDma::new();
        // cap_len < 0x20 -> InvalidArgument
        assert_eq!(
            Rp1Xhci::init(
                FaultXhci {
                    cap0: 0x10,
                    usbsts: USBSTS_HCH,
                    usbcmd: 0,
                },
                &dma
            )
            .err(),
            Some(SysError::InvalidArgument)
        );
        // CNR never clears -> WouldBlock
        assert_eq!(
            Rp1Xhci::init(
                FaultXhci {
                    cap0: 0x20,
                    usbsts: USBSTS_CNR,
                    usbcmd: 0,
                },
                &dma
            )
            .err(),
            Some(SysError::WouldBlock)
        );
        // HCH never sets -> WouldBlock
        assert_eq!(
            Rp1Xhci::init(
                FaultXhci {
                    cap0: 0x20,
                    usbsts: 0,
                    usbcmd: 0,
                },
                &dma
            )
            .err(),
            Some(SysError::WouldBlock)
        );
        // HCRST never clears -> WouldBlock
        assert_eq!(
            Rp1Xhci::init(
                FaultXhci {
                    cap0: 0x20,
                    usbsts: USBSTS_HCH,
                    usbcmd: USBCMD_HCRST,
                },
                &dma
            )
            .err(),
            Some(SysError::WouldBlock)
        );

        // Reset port OOB + ring wrap-around toggling cmd_cycle
        let mock = MockXhci {
            running: RefCell::new(false),
            doorbell_rings: RefCell::new(0),
        };
        let mut xhci = Rp1Xhci::init(&mock, &dma).expect("xhci init");
        assert_eq!(xhci.reset_port(2), Err(SysError::InvalidArgument));
        xhci.reset_port(0).expect("reset port 0");
        for _ in 0..RING_TRBS {
            xhci.ring_enable_slot().expect("ring wrap");
        }
        assert_eq!(*mock.doorbell_rings.borrow(), RING_TRBS_U32);
        // First wrapped TRB (index 0) should now have cycle bit 0
        assert_eq!(dma.cmd_ring.0[0].control.load(Ordering::Acquire) & 1, 0);

        // UsbSpeed::from_portsc covers all 6 variants
        assert_eq!(UsbSpeed::from_portsc(1 << 10), UsbSpeed::FullSpeed);
        assert_eq!(UsbSpeed::from_portsc(2 << 10), UsbSpeed::LowSpeed);
        assert_eq!(UsbSpeed::from_portsc(3 << 10), UsbSpeed::HighSpeed);
        assert_eq!(UsbSpeed::from_portsc(4 << 10), UsbSpeed::SuperSpeed);
        assert_eq!(UsbSpeed::from_portsc(5 << 10), UsbSpeed::SuperSpeedPlus);
        assert_eq!(UsbSpeed::from_portsc(7 << 10), UsbSpeed::Unknown(7));
    }
}
