//! Pure `#![forbid(unsafe_code)]`, `no_alloc` ARM SMMUv3 (`IoSpace`) DMA isolation model.
//!
//! Encodes ARM IHI 0070G architectural 64-byte Stream Table Entries (`Ste`), 64-byte Stage-1
//! Context Descriptors (`ContextDescriptor`), and 16-byte Command Queue entries (`SmmuCmd`),
//! plus a capability-scoped `IoSpaceTable` enforcing default-deny (`STE_ABORT`) DMA isolation.

use crate::memory::{PAGE_MASK, PhysAddr};
use newos_abi::SysError;

/// ARM SMMUv3 64-byte Stream Table Entry (ARM IHI 0070G Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct Ste {
    pub dw: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<Ste>() == 64);

impl Ste {
    /// Default-deny STE (`V = 1`, `Config = 0b000`): aborts all DMA transactions from this stream.
    pub const ABORT: Self = Self {
        dw: [1, 0, 0, 0, 0, 0, 0, 0],
    };

    /// Construct a Stage-1 translating STE pointing to a 64-byte-aligned `ContextDescriptor`.
    ///
    /// - `V = 1`, `Config = 0b101` (Stage-1 translate, Stage-2 bypass)
    /// - `S1DSS = 0b10` (use CD[0] for non-substream traffic), Inner Shareable WB cacheable
    /// - `EATS = 0` (PCIe ATS untranslated bypass disabled)
    pub fn stage1_translate(cd_phys: PhysAddr) -> Result<Self, SysError> {
        let addr = cd_phys.raw();
        if addr == 0 || (addr & 0x3F) != 0 || (addr >> 52) != 0 {
            return Err(SysError::InvalidArgument);
        }
        let dw0 = 1u64 | (0b101u64 << 1) | (addr & 0x000F_FFFF_FFFF_FFC0);
        let dw1 = 0b10u64 | (0b01u64 << 4) | (0b01u64 << 6) | (0b11u64 << 8);
        Ok(Self {
            dw: [dw0, dw1, 0, 0, 0, 0, 0, 0],
        })
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        (self.dw[0] & 1) != 0
    }

    #[inline]
    pub const fn config(&self) -> u8 {
        ((self.dw[0] >> 1) & 0x7) as u8
    }

    #[inline]
    pub const fn s1_context_ptr(&self) -> u64 {
        self.dw[0] & 0x000F_FFFF_FFFF_FFC0
    }
}

/// ARM SMMUv3 64-byte Stage-1 Context Descriptor (ARM IHI 0070G Section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct ContextDescriptor {
    pub dw: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<ContextDescriptor>() == 64);

impl ContextDescriptor {
    pub const INVALID: Self = Self { dw: [0; 8] };

    /// Construct a valid 48-bit, 4 KiB-granule AArch64 Stage-1 CD bound to `ttb0_phys` and `domain_id`.
    pub fn new_stage1(ttb0_phys: PhysAddr, domain_id: u16) -> Result<Self, SysError> {
        let root = ttb0_phys.raw();
        if root == 0 || (root & PAGE_MASK) != 0 || (root >> 52) != 0 {
            return Err(SysError::InvalidArgument);
        }
        // T0SZ=16 (48-bit IOVA), TG0=0 (4 KiB), IR0/OR0=WBWA (0b01), SH0=ISH (0b11),
        // EPD1=1 (disable TTBR1), V=1, IPS=0b101 (48-bit PA), AA64=1, ASET=1, ASID=domain_id.
        let dw0 = 16u64
            | (0b01u64 << 8)
            | (0b01u64 << 10)
            | (0b11u64 << 12)
            | (1u64 << 30)
            | (1u64 << 31)
            | (0b101u64 << 32)
            | (1u64 << 41)
            | (1u64 << 47)
            | (u64::from(domain_id) << 48);
        let dw1 = root & 0x000F_FFFF_FFFF_FFF0;
        let dw3 = 0x0000_0000_0000_00FFu64; // MAIR0: Attr0=Normal WBWA, Attr1=Device-nGnRnE
        Ok(Self {
            dw: [dw0, dw1, 0, dw3, 0, 0, 0, 0],
        })
    }

    #[inline]
    pub const fn asid(&self) -> u16 {
        (self.dw[0] >> 48) as u16
    }

    #[inline]
    pub const fn ttb0(&self) -> u64 {
        self.dw[1] & 0x000F_FFFF_FFFF_FFF0
    }
}

/// ARM SMMUv3 16-byte Command Queue Entry (ARM IHI 0070G Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct SmmuCmd {
    pub dw: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<SmmuCmd>() == 16);

impl SmmuCmd {
    pub const OP_CFGI_STE: u8 = 0x03;
    pub const OP_CFGI_ALL: u8 = 0x04;
    pub const OP_TLBI_NH_ASID: u8 = 0x11;
    pub const OP_CMD_SYNC: u8 = 0x46;

    #[inline]
    pub const fn cfgi_ste(stream_id: u32, leaf: bool) -> Self {
        Self {
            dw: [
                (Self::OP_CFGI_STE as u64) | ((stream_id as u64) << 32),
                if leaf { 1 } else { 0 },
            ],
        }
    }

    #[inline]
    pub const fn cfgi_all() -> Self {
        Self {
            dw: [Self::OP_CFGI_ALL as u64, 31],
        }
    }

    #[inline]
    pub const fn tlbi_nh_asid(asid: u16) -> Self {
        Self {
            dw: [(Self::OP_TLBI_NH_ASID as u64) | ((asid as u64) << 48), 0],
        }
    }

    #[inline]
    pub const fn cmd_sync() -> Self {
        Self {
            dw: [Self::OP_CMD_SYNC as u64, 0],
        }
    }

    #[inline]
    pub const fn opcode(&self) -> u8 {
        (self.dw[0] & 0xFF) as u8
    }
}

/// Capability-scoped DMA `IoSpace` domain entry bound to a PCIe/platform `stream_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoSpaceDomain {
    pub domain_id: u16,
    pub stream_id: u32,
    pub ttbr0_phys: PhysAddr,
    pub active: bool,
}

/// Fixed-size, `no_alloc` table tracking capability-scoped SMMUv3 `IoSpace` domains.
pub struct IoSpaceTable<const MAX_DOMAINS: usize> {
    domains: [Option<IoSpaceDomain>; MAX_DOMAINS],
}

impl<const MAX_DOMAINS: usize> Default for IoSpaceTable<MAX_DOMAINS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_DOMAINS: usize> IoSpaceTable<MAX_DOMAINS> {
    pub const fn new() -> Self {
        Self {
            domains: [None; MAX_DOMAINS],
        }
    }

    /// Bind a unique `domain_id` and `stream_id` to a 4 KiB-aligned Stage-1 IOVA page-table root.
    pub fn bind_stream(
        &mut self,
        domain_id: u16,
        stream_id: u32,
        ttbr0_phys: PhysAddr,
    ) -> Result<ContextDescriptor, SysError> {
        let cd = ContextDescriptor::new_stage1(ttbr0_phys, domain_id)?;
        let mut free_slot = None;
        for (idx, slot) in self.domains.iter().enumerate() {
            match slot {
                Some(d) if d.domain_id == domain_id || d.stream_id == stream_id => {
                    return Err(SysError::SlotOccupied);
                }
                None if free_slot.is_none() => free_slot = Some(idx),
                _ => {}
            }
        }
        let idx = free_slot.ok_or(SysError::OutOfMemory)?;
        self.domains[idx] = Some(IoSpaceDomain {
            domain_id,
            stream_id,
            ttbr0_phys,
            active: true,
        });
        Ok(cd)
    }

    /// Unbind `domain_id`, returning the `stream_id` whose STE must be reverted to `Ste::ABORT`
    /// and invalidated via `SmmuCmd::cfgi_ste` + `SmmuCmd::tlbi_nh_asid` + `SmmuCmd::cmd_sync`.
    pub fn unbind_domain(&mut self, domain_id: u16) -> Option<u32> {
        for slot in &mut self.domains {
            if let Some(d) = *slot
                && d.domain_id == domain_id
            {
                *slot = None;
                return Some(d.stream_id);
            }
        }
        None
    }

    pub fn lookup(&self, domain_id: u16) -> Option<IoSpaceDomain> {
        self.domains
            .iter()
            .flatten()
            .copied()
            .find(|d| d.domain_id == domain_id)
    }

    pub fn active_count(&self) -> usize {
        self.domains.iter().filter(|d| d.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ste_and_cd_encode_arm_smmuv3_stage1_correctly() {
        assert!(Ste::ABORT.is_valid());
        assert_eq!(Ste::ABORT.config(), 0b000);

        // Unaligned CD pointer rejected
        assert_eq!(
            Ste::stage1_translate(PhysAddr::new(0x4000_0020)),
            Err(SysError::InvalidArgument)
        );
        let ste = Ste::stage1_translate(PhysAddr::new(0x4000_0040)).expect("64B-aligned CD");
        assert!(ste.is_valid());
        assert_eq!(ste.config(), 0b101);
        assert_eq!(ste.s1_context_ptr(), 0x4000_0040);

        let cd = ContextDescriptor::new_stage1(PhysAddr::new(0x4010_0000), 7).expect("4K TTBR0");
        assert_eq!(cd.asid(), 7);
        assert_eq!(cd.ttb0(), 0x4010_0000);
        assert_eq!(
            ContextDescriptor::new_stage1(PhysAddr::new(0x4010_0080), 7),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn iospace_table_enforces_unique_streams_and_clean_teardown() {
        let mut tbl: IoSpaceTable<4> = IoSpaceTable::new();
        let cd = tbl
            .bind_stream(1, 0x0100, PhysAddr::new(0x5000_0000))
            .expect("bind domain 1");
        assert_eq!(cd.asid(), 1);
        assert_eq!(tbl.active_count(), 1);

        // Duplicate stream_id or domain_id rejected
        assert_eq!(
            tbl.bind_stream(2, 0x0100, PhysAddr::new(0x5001_0000)),
            Err(SysError::SlotOccupied)
        );
        assert_eq!(
            tbl.bind_stream(1, 0x0200, PhysAddr::new(0x5001_0000)),
            Err(SysError::SlotOccupied)
        );

        let sid = tbl.unbind_domain(1).expect("unbind domain 1");
        assert_eq!(sid, 0x0100);
        assert_eq!(tbl.active_count(), 0);
        assert_eq!(tbl.lookup(1), None);

        let cmd1 = SmmuCmd::cfgi_ste(sid, true);
        let cmd2 = SmmuCmd::tlbi_nh_asid(1);
        let cmd3 = SmmuCmd::cmd_sync();
        assert_eq!(cmd1.opcode(), SmmuCmd::OP_CFGI_STE);
        assert_eq!(cmd2.opcode(), SmmuCmd::OP_TLBI_NH_ASID);
        assert_eq!(cmd3.opcode(), SmmuCmd::OP_CMD_SYNC);
    }
}
