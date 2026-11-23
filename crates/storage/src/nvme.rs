//! NVMe 1.4 PCIe SSD Block Driver (`#![forbid(unsafe_code)]`, `no_alloc`).
//!
//! Targets NVMe SSDs attached to the Raspberry Pi 5 PCIe 2.0 x1 FFC connector, using
//! 4 KiB-aligned Submission/Completion Queues and PRP1 data buffers with `dma_clean`/`dma_invalidate`.

use crate::{BlockDevice, SECTOR_SIZE, StorageDmaTransport};
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering, fence};
use newos_abi::SysError;

pub const REG_CAP_LO: u64 = 0x00;
pub const REG_CAP_HI: u64 = 0x04;
pub const REG_VS: u64 = 0x08;
pub const REG_CC: u64 = 0x14;
pub const REG_CSTS: u64 = 0x1C;
pub const REG_AQA: u64 = 0x24;
pub const REG_ASQ_LO: u64 = 0x28;
pub const REG_ASQ_HI: u64 = 0x2C;
pub const REG_ACQ_LO: u64 = 0x30;
pub const REG_ACQ_HI: u64 = 0x34;
pub const REG_DOORBELL_BASE: u64 = 0x1000;

const CC_EN: u32 = 1 << 0;
const CC_IOSQES_64B: u32 = 6 << 16; // 2^6 = 64 B SQE
const CC_IOCQES_16B: u32 = 4 << 20; // 2^4 = 16 B CQE
const CSTS_RDY: u32 = 1 << 0;

const ADMIN_OP_CREATE_IOSQ: u8 = 0x01;
const ADMIN_OP_CREATE_IOCQ: u8 = 0x05;
const NVM_OP_WRITE: u8 = 0x01;
const NVM_OP_READ: u8 = 0x02;

const QUEUE_DEPTH: usize = 8;
const MAX_POLL: u32 = 100_000;

/// 64-byte NVMe Submission Queue Entry (`SQE`).
#[repr(C)]
pub struct NvmeSqe {
    cdw0: AtomicU32,
    nsid: AtomicU32,
    rsvd: [AtomicU32; 2],
    mptr: AtomicU64,
    prp1: AtomicU64,
    prp2: AtomicU64,
    cdw10: AtomicU32,
    cdw11: AtomicU32,
    cdw12: AtomicU32,
    cdw13: AtomicU32,
    cdw14: AtomicU32,
    cdw15: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<NvmeSqe>() == 64);

impl NvmeSqe {
    const fn zero() -> Self {
        Self {
            cdw0: AtomicU32::new(0),
            nsid: AtomicU32::new(0),
            rsvd: [AtomicU32::new(0), AtomicU32::new(0)],
            mptr: AtomicU64::new(0),
            prp1: AtomicU64::new(0),
            prp2: AtomicU64::new(0),
            cdw10: AtomicU32::new(0),
            cdw11: AtomicU32::new(0),
            cdw12: AtomicU32::new(0),
            cdw13: AtomicU32::new(0),
            cdw14: AtomicU32::new(0),
            cdw15: AtomicU32::new(0),
        }
    }
}

/// 16-byte NVMe Completion Queue Entry (`CQE`).
#[repr(C)]
pub struct NvmeCqe {
    dw0: AtomicU32,
    dw1: AtomicU32,
    sq_head_id: AtomicU32,
    cid: AtomicU16,
    status: AtomicU16,
}

const _: () = assert!(core::mem::size_of::<NvmeCqe>() == 16);

impl NvmeCqe {
    const fn zero() -> Self {
        Self {
            dw0: AtomicU32::new(0),
            dw1: AtomicU32::new(0),
            sq_head_id: AtomicU32::new(0),
            cid: AtomicU16::new(0),
            status: AtomicU16::new(0),
        }
    }
}

#[repr(C, align(4096))]
struct SqPage([NvmeSqe; QUEUE_DEPTH]);

#[repr(C, align(4096))]
struct CqPage([NvmeCqe; QUEUE_DEPTH]);

#[repr(C, align(4096))]
struct DataPage([AtomicU8; 4096]);

/// Static 4 KiB-aligned `no_alloc` DMA queues & PRP1 data page for NVMe 1.4.
pub struct NvmeDma {
    admin_sq: SqPage,
    admin_cq: CqPage,
    io_sq: SqPage,
    io_cq: CqPage,
    data_page: DataPage,
}

impl Default for NvmeDma {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeDma {
    pub const fn new() -> Self {
        Self {
            admin_sq: SqPage([const { NvmeSqe::zero() }; QUEUE_DEPTH]),
            admin_cq: CqPage([const { NvmeCqe::zero() }; QUEUE_DEPTH]),
            io_sq: SqPage([const { NvmeSqe::zero() }; QUEUE_DEPTH]),
            io_cq: CqPage([const { NvmeCqe::zero() }; QUEUE_DEPTH]),
            data_page: DataPage([const { AtomicU8::new(0) }; 4096]),
        }
    }
}

/// Capability-scoped EL0 NVMe 1.4 PCIe SSD driver.
pub struct NvmeController<'a, T: StorageDmaTransport> {
    transport: T,
    dma: &'a NvmeDma,
    dstrd_bytes: u64,
    admin_sq_tail: usize,
    admin_cq_head: usize,
    admin_phase: bool,
    io_sq_tail: usize,
    io_cq_head: usize,
    io_phase: bool,
    next_cid: u16,
    nsid: u32,
    sectors: u64,
}

impl<'a, T: StorageDmaTransport> NvmeController<'a, T> {
    /// Reset, enable, and create I/O CQ/SQ #1 on an NVMe 1.4 controller.
    pub fn init(transport: T, dma: &'a NvmeDma, sectors: u64) -> Result<Self, SysError> {
        let cap_hi = transport.read32(REG_CAP_HI)?;
        let dstrd = cap_hi & 0xF;
        let dstrd_bytes = 4u64 << dstrd;

        // 1. Disable controller and wait for CSTS.RDY == 0 (fail on timeout, `P12`)
        transport.write32(REG_CC, 0)?;
        let mut disabled = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(REG_CSTS)? & CSTS_RDY) == 0 {
                disabled = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !disabled {
            return Err(SysError::WouldBlock);
        }

        // 2. Program Admin Queue Attributes & 64-bit ASQ/ACQ physical bases
        let qsize = (QUEUE_DEPTH as u32) - 1;
        transport.write32(REG_AQA, (qsize << 16) | qsize)?;
        let asq_phys = transport.virt_to_phys(&dma.admin_sq)?;
        let acq_phys = transport.virt_to_phys(&dma.admin_cq)?;
        transport.write32(REG_ASQ_LO, asq_phys as u32)?;
        transport.write32(REG_ASQ_HI, (asq_phys >> 32) as u32)?;
        transport.write32(REG_ACQ_LO, acq_phys as u32)?;
        transport.write32(REG_ACQ_HI, (acq_phys >> 32) as u32)?;

        // 3. Enable controller (64B SQE, 16B CQE, 4 KiB page size) and wait for CSTS.RDY == 1
        transport.write32(REG_CC, CC_EN | CC_IOSQES_64B | CC_IOCQES_16B)?;
        let mut ready = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(REG_CSTS)? & CSTS_RDY) != 0 {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            return Err(SysError::WouldBlock);
        }

        let mut ctrl = Self {
            transport,
            dma,
            dstrd_bytes,
            admin_sq_tail: 0,
            admin_cq_head: 0,
            admin_phase: true,
            io_sq_tail: 0,
            io_cq_head: 0,
            io_phase: true,
            next_cid: 1,
            nsid: 1,
            sectors,
        };

        // 4. Create I/O Completion Queue #1 and Submission Queue #1
        let iocq_phys = ctrl.transport.virt_to_phys(&dma.io_cq)?;
        let iosq_phys = ctrl.transport.virt_to_phys(&dma.io_sq)?;
        ctrl.submit_admin(
            ADMIN_OP_CREATE_IOCQ,
            iocq_phys,
            ((qsize) << 16) | 1,
            1, // PC=1 (physically contiguous)
        )?;
        ctrl.submit_admin(
            ADMIN_OP_CREATE_IOSQ,
            iosq_phys,
            ((qsize) << 16) | 1,
            (1 << 16) | 1, // CQID=1, PC=1
        )?;

        Ok(ctrl)
    }

    #[inline]
    fn sq_doorbell(&self, qid: u64) -> u64 {
        REG_DOORBELL_BASE + (2 * qid) * self.dstrd_bytes
    }

    #[inline]
    fn cq_doorbell(&self, qid: u64) -> u64 {
        REG_DOORBELL_BASE + (2 * qid + 1) * self.dstrd_bytes
    }

    fn submit_admin(
        &mut self,
        opcode: u8,
        prp1: u64,
        cdw10: u32,
        cdw11: u32,
    ) -> Result<(), SysError> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let slot = self.admin_sq_tail;
        let sqe = &self.dma.admin_sq.0[slot];
        sqe.cdw0.store(
            u32::from(opcode) | (u32::from(cid) << 16),
            Ordering::Relaxed,
        );
        sqe.nsid.store(0, Ordering::Relaxed);
        sqe.prp1.store(prp1, Ordering::Relaxed);
        sqe.prp2.store(0, Ordering::Relaxed);
        sqe.cdw10.store(cdw10, Ordering::Relaxed);
        sqe.cdw11.store(cdw11, Ordering::Relaxed);
        sqe.cdw12.store(0, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        self.transport.dma_clean(sqe)?;

        self.admin_sq_tail = (slot + 1) % QUEUE_DEPTH;
        self.transport
            .write32(self.sq_doorbell(0), self.admin_sq_tail as u32)?;

        let cqe = &self.dma.admin_cq.0[self.admin_cq_head];
        for _ in 0..MAX_POLL {
            self.transport.dma_invalidate(cqe)?;
            let status = cqe.status.load(Ordering::Acquire);
            if ((status & 1) != 0) == self.admin_phase {
                let err_code = status >> 1;
                self.admin_cq_head = (self.admin_cq_head + 1) % QUEUE_DEPTH;
                if self.admin_cq_head == 0 {
                    self.admin_phase = !self.admin_phase;
                }
                self.transport
                    .write32(self.cq_doorbell(0), self.admin_cq_head as u32)?;
                return if err_code == 0 {
                    Ok(())
                } else {
                    Err(SysError::InvalidArgument)
                };
            }
            core::hint::spin_loop();
        }
        Err(SysError::WouldBlock)
    }

    fn submit_io(&mut self, opcode: u8, lba: u64) -> Result<(), SysError> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let prp1 = self.transport.virt_to_phys(&self.dma.data_page)?;
        let slot = self.io_sq_tail;
        let sqe = &self.dma.io_sq.0[slot];
        sqe.cdw0.store(
            u32::from(opcode) | (u32::from(cid) << 16),
            Ordering::Relaxed,
        );
        sqe.nsid.store(self.nsid, Ordering::Relaxed);
        sqe.prp1.store(prp1, Ordering::Relaxed);
        sqe.prp2.store(0, Ordering::Relaxed);
        sqe.cdw10.store(lba as u32, Ordering::Relaxed);
        sqe.cdw11.store((lba >> 32) as u32, Ordering::Relaxed);
        sqe.cdw12.store(0, Ordering::Relaxed); // NLB = 0 => 1 logical block (512 B)
        fence(Ordering::SeqCst);
        self.transport.dma_clean(sqe)?;

        self.io_sq_tail = (slot + 1) % QUEUE_DEPTH;
        self.transport
            .write32(self.sq_doorbell(1), self.io_sq_tail as u32)?;

        for _ in 0..MAX_POLL {
            let cqe = &self.dma.io_cq.0[self.io_cq_head];
            self.transport.dma_invalidate(cqe)?;
            let status = cqe.status.load(Ordering::Acquire);
            if ((status & 1) != 0) == self.io_phase {
                let got_cid = cqe.cid.load(Ordering::Acquire);
                let err_code = status >> 1;
                self.io_cq_head = (self.io_cq_head + 1) % QUEUE_DEPTH;
                if self.io_cq_head == 0 {
                    self.io_phase = !self.io_phase;
                }
                self.transport
                    .write32(self.cq_doorbell(1), self.io_cq_head as u32)?;
                // Discard stale completions from previously timed-out commands (`P12`).
                if got_cid != cid {
                    continue;
                }
                return if err_code == 0 {
                    Ok(())
                } else {
                    Err(SysError::InvalidArgument)
                };
            }
            core::hint::spin_loop();
        }
        Err(SysError::WouldBlock)
    }
}

impl<T: StorageDmaTransport> BlockDevice for NvmeController<'_, T> {
    fn block_count(&self) -> u64 {
        self.sectors
    }

    fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError> {
        if lba >= self.sectors {
            return Err(SysError::InvalidArgument);
        }
        self.transport.dma_invalidate(&self.dma.data_page)?;
        self.submit_io(NVM_OP_READ, lba)?;
        self.transport.dma_invalidate(&self.dma.data_page)?;
        for (i, byte) in dst.iter_mut().enumerate() {
            *byte = self.dma.data_page.0[i].load(Ordering::Acquire);
        }
        Ok(())
    }

    fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError> {
        if lba >= self.sectors {
            return Err(SysError::InvalidArgument);
        }
        for (i, &byte) in src.iter().enumerate() {
            self.dma.data_page.0[i].store(byte, Ordering::Relaxed);
        }
        fence(Ordering::SeqCst);
        self.transport.dma_clean(&self.dma.data_page)?;
        self.submit_io(NVM_OP_WRITE, lba)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageMmioTransport;
    use core::cell::RefCell;

    struct MockNvme<'a> {
        dma: &'a NvmeDma,
        enabled: RefCell<bool>,
        admin_idx: RefCell<usize>,
        io_idx: RefCell<usize>,
        stored: RefCell<[u8; SECTOR_SIZE]>,
    }

    impl StorageMmioTransport for &MockNvme<'_> {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_CAP_HI => Ok(0), // dstrd = 0 -> 4 B stride
                REG_CSTS => Ok(if *self.enabled.borrow() { CSTS_RDY } else { 0 }),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == REG_CC {
                *self.enabled.borrow_mut() = (val & CC_EN) != 0;
            } else if offset == REG_DOORBELL_BASE {
                // Admin SQ doorbell -> mark Admin CQE complete (phase = 1, status = 0)
                let mut idx = self.admin_idx.borrow_mut();
                self.dma.admin_cq.0[*idx].status.store(1, Ordering::Release);
                *idx = (*idx + 1) % QUEUE_DEPTH;
            } else if offset == REG_DOORBELL_BASE + 8 {
                // I/O SQ #1 doorbell -> execute mock read/write & post I/O CQE
                let mut idx = self.io_idx.borrow_mut();
                let cdw0 = self.dma.io_sq.0[*idx].cdw0.load(Ordering::Acquire);
                let op = (cdw0 & 0xFF) as u8;
                let cid = (cdw0 >> 16) as u16;
                if op == NVM_OP_WRITE {
                    let mut buf = self.stored.borrow_mut();
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = self.dma.data_page.0[i].load(Ordering::Acquire);
                    }
                } else if op == NVM_OP_READ {
                    let buf = self.stored.borrow();
                    for (i, &b) in buf.iter().enumerate() {
                        self.dma.data_page.0[i].store(b, Ordering::Release);
                    }
                }
                self.dma.io_cq.0[*idx].cid.store(cid, Ordering::Release);
                self.dma.io_cq.0[*idx].status.store(1, Ordering::Release);
                *idx = (*idx + 1) % QUEUE_DEPTH;
            }
            Ok(())
        }
    }

    impl StorageDmaTransport for &MockNvme<'_> {
        fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError> {
            Ok((value as *const T as usize) as u64)
        }
    }

    #[test]
    fn nvme_init_creates_io_queues_and_roundtrips_sector() {
        let dma = NvmeDma::new();
        let mock = MockNvme {
            dma: &dma,
            enabled: RefCell::new(false),
            admin_idx: RefCell::new(0),
            io_idx: RefCell::new(0),
            stored: RefCell::new([0; SECTOR_SIZE]),
        };
        let mut nvme = NvmeController::init(&mock, &dma, 2048).expect("nvme init");
        let mut tx = [0u8; SECTOR_SIZE];
        tx[0..4].copy_from_slice(b"NVME");
        nvme.write_block(3, &tx).expect("nvme write");

        let mut rx = [0u8; SECTOR_SIZE];
        nvme.read_block(3, &mut rx).expect("nvme read");
        assert_eq!(rx, tx);
    }
}
