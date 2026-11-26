//! Raspberry Pi 5 (BCM2712) microSD SDHCI 3.0 / SDR104 Block Driver.
//!
//! Physical MMIO base: `0x10_00ff_f000` (4 KiB, `CapId::BOOTSTRAP_SDHCI_MMIO`).

use crate::{BlockDevice, SECTOR_SIZE, StorageMmioTransport};
use newos_abi::SysError;

pub const BCM2712_SDHCI_PHYS: u64 = 0x10_00ff_f000;

// Standard SDHCI 3.0 Register Offsets
pub const REG_BLK_SIZE_COUNT: u64 = 0x04;
pub const REG_ARGUMENT: u64 = 0x08;
pub const REG_XFER_CMD: u64 = 0x0C;
pub const REG_RESPONSE0: u64 = 0x10;
pub const REG_BUFFER_DATA: u64 = 0x20;
pub const REG_PRESENT_STATE: u64 = 0x24;
pub const REG_HOST_CTRL: u64 = 0x28;
pub const REG_CLK_RESET: u64 = 0x2C;
pub const REG_INT_STATUS: u64 = 0x30;
pub const REG_INT_STATUS_EN: u64 = 0x34;
pub const REG_CAPABILITIES: u64 = 0x40;

const PSTATE_CMD_INHIBIT: u32 = 1 << 0;
const PSTATE_DAT_INHIBIT: u32 = 1 << 1;
const PSTATE_CARD_INSERTED: u32 = 1 << 16;

const INT_CMD_COMPLETE: u32 = 1 << 0;
const INT_XFER_COMPLETE: u32 = 1 << 1;
const INT_BUF_WRITE_READY: u32 = 1 << 4;
const INT_BUF_READ_READY: u32 = 1 << 5;
const INT_ERROR_MASK: u32 = 0xFFFF_8000;

const SW_RESET_ALL: u32 = 1 << 24;
const CLK_INT_EN: u32 = 1 << 0;
const CLK_INT_STABLE: u32 = 1 << 1;
const CLK_SD_EN: u32 = 1 << 2;

const XFER_READ: u32 = 1 << 4;
const CMD_RESP_48: u32 = 0b10 << 16;
const CMD_RESP_136: u32 = 0b01 << 16;
const CMD_DATA_PRESENT: u32 = 1 << 21;

const SECTOR_SIZE_U32: u32 = 512;
const _: () = assert!(SECTOR_SIZE == SECTOR_SIZE_U32 as usize);

const MAX_POLL: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardAddressing {
    /// Standard-capacity SDSC card (byte-addressed).
    Byte,
    /// High/extended-capacity SDHC/SDXC card (512-byte block-addressed).
    Block,
}

/// Capability-scoped EL0 BCM2712 microSD SDHCI driver.
#[derive(Debug)]
pub struct Bcm2712Sdhci<T: StorageMmioTransport> {
    transport: T,
    rca: u32,
    addressing: CardAddressing,
    sectors: u64,
}

impl<T: StorageMmioTransport> Bcm2712Sdhci<T> {
    /// Reset the SDHCI host controller, bring up an inserted SD/SDHC/SDXC card, and select it.
    ///
    /// # Errors
    /// Returns [`SysError::WouldBlock`] if the controller reset, clock stabilization, card
    /// presence, or card initialization times out; [`SysError::InvalidArgument`] if the card
    /// reports an error; or a transport [`SysError`].
    pub fn init(transport: T, fallback_sectors: u64) -> Result<Self, SysError> {
        // 1. Software reset all
        transport.write32(REG_CLK_RESET, SW_RESET_ALL)?;
        let mut reset_done = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(REG_CLK_RESET)? & SW_RESET_ALL) == 0 {
                reset_done = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !reset_done {
            return Err(SysError::WouldBlock);
        }

        // 2. Check card presence
        if (transport.read32(REG_PRESENT_STATE)? & PSTATE_CARD_INSERTED) == 0 {
            return Err(SysError::WouldBlock);
        }

        // 3. Enable internal clock, wait stable, enable SD clock + power (3.3V)
        transport.write32(REG_HOST_CTRL, 0x0F << 8)?; // 3.3V bus power on
        transport.write32(REG_CLK_RESET, CLK_INT_EN | (0x40 << 8))?;
        let mut clk_stable = false;
        for _ in 0..MAX_POLL {
            if (transport.read32(REG_CLK_RESET)? & CLK_INT_STABLE) != 0 {
                clk_stable = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !clk_stable {
            return Err(SysError::WouldBlock);
        }
        transport.write32(REG_CLK_RESET, CLK_INT_EN | CLK_SD_EN | (0x40 << 8))?;
        transport.write32(REG_INT_STATUS_EN, 0xFFFF_FFFF)?;
        transport.write32(REG_INT_STATUS, 0xFFFF_FFFF)?;

        let mut dev = Self {
            transport,
            rca: 0,
            addressing: CardAddressing::Block,
            sectors: fallback_sectors,
        };

        // 4. SD initialization sequence: CMD0 -> CMD8 -> ACMD41 -> CMD2 -> CMD3 -> CMD7
        dev.send_cmd(0, 0, 0)?;
        let _ = dev.send_cmd(8, 0x0000_01AA, CMD_RESP_48)?;
        let mut ocr = 0u32;
        for _ in 0..1000u32 {
            dev.send_cmd(55, 0, CMD_RESP_48)?;
            ocr = dev.send_cmd(41, 0x40FF_8000, CMD_RESP_48)?;
            if (ocr & (1 << 31)) != 0 {
                break;
            }
        }
        if (ocr & (1 << 31)) == 0 {
            return Err(SysError::WouldBlock);
        }
        dev.addressing = if (ocr & (1 << 30)) != 0 {
            CardAddressing::Block
        } else {
            CardAddressing::Byte
        };
        let _ = dev.send_cmd(2, 0, CMD_RESP_136)?;
        let r6 = dev.send_cmd(3, 0, CMD_RESP_48)?;
        dev.rca = r6 & 0xFFFF_0000;
        let _ = dev.send_cmd(7, dev.rca, CMD_RESP_48)?;
        if dev.addressing == CardAddressing::Byte {
            let _ = dev.send_cmd(16, SECTOR_SIZE_U32, CMD_RESP_48)?;
        }
        Ok(dev)
    }

    fn send_cmd(&self, cmd_idx: u8, arg: u32, flags: u32) -> Result<u32, SysError> {
        let mut ready = false;
        for _ in 0..MAX_POLL {
            let ps = self.transport.read32(REG_PRESENT_STATE)?;
            if (ps & (PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT)) == 0 {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            return Err(SysError::WouldBlock);
        }
        self.transport.write32(REG_INT_STATUS, 0xFFFF_FFFF)?;
        self.transport.write32(REG_ARGUMENT, arg)?;
        let cmd_word = (u32::from(cmd_idx) << 24) | flags;
        self.transport.write32(REG_XFER_CMD, cmd_word)?;

        for _ in 0..MAX_POLL {
            let st = self.transport.read32(REG_INT_STATUS)?;
            if (st & INT_ERROR_MASK) != 0 {
                self.transport.write32(REG_INT_STATUS, st)?;
                return Err(SysError::InvalidArgument);
            }
            if (st & INT_CMD_COMPLETE) != 0 {
                self.transport.write32(REG_INT_STATUS, INT_CMD_COMPLETE)?;
                return self.transport.read32(REG_RESPONSE0);
            }
            core::hint::spin_loop();
        }
        Err(SysError::WouldBlock)
    }

    fn wait_int(&self, mask: u32) -> Result<(), SysError> {
        for _ in 0..MAX_POLL {
            let st = self.transport.read32(REG_INT_STATUS)?;
            if (st & INT_ERROR_MASK) != 0 {
                self.transport.write32(REG_INT_STATUS, st)?;
                return Err(SysError::InvalidArgument);
            }
            if (st & mask) != 0 {
                self.transport.write32(REG_INT_STATUS, mask)?;
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SysError::WouldBlock)
    }
}

impl<T: StorageMmioTransport> BlockDevice for Bcm2712Sdhci<T> {
    fn block_count(&self) -> u64 {
        self.sectors
    }

    fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError> {
        if lba >= self.sectors {
            return Err(SysError::InvalidArgument);
        }
        let arg = match self.addressing {
            CardAddressing::Block => u32::try_from(lba).map_err(|_| SysError::InvalidArgument)?,
            CardAddressing::Byte => u32::try_from(lba.saturating_mul(u64::from(SECTOR_SIZE_U32)))
                .map_err(|_| SysError::InvalidArgument)?,
        };
        self.transport
            .write32(REG_BLK_SIZE_COUNT, (1 << 16) | SECTOR_SIZE_U32)?;
        let _ = self.send_cmd(17, arg, CMD_RESP_48 | CMD_DATA_PRESENT | XFER_READ)?;
        self.wait_int(INT_BUF_READ_READY)?;
        for chunk in dst.as_chunks_mut::<4>().0 {
            let w = self.transport.read32(REG_BUFFER_DATA)?.to_le_bytes();
            chunk.copy_from_slice(&w);
        }
        self.wait_int(INT_XFER_COMPLETE)
    }

    fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError> {
        if lba >= self.sectors {
            return Err(SysError::InvalidArgument);
        }
        let arg = match self.addressing {
            CardAddressing::Block => u32::try_from(lba).map_err(|_| SysError::InvalidArgument)?,
            CardAddressing::Byte => u32::try_from(lba.saturating_mul(u64::from(SECTOR_SIZE_U32)))
                .map_err(|_| SysError::InvalidArgument)?,
        };
        self.transport
            .write32(REG_BLK_SIZE_COUNT, (1 << 16) | SECTOR_SIZE_U32)?;
        let _ = self.send_cmd(24, arg, CMD_RESP_48 | CMD_DATA_PRESENT)?;
        self.wait_int(INT_BUF_WRITE_READY)?;
        for chunk in src.as_chunks::<4>().0 {
            let w = u32::from_le_bytes(*chunk);
            self.transport.write32(REG_BUFFER_DATA, w)?;
        }
        self.wait_int(INT_XFER_COMPLETE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct MockSdhci {
        last_cmd: RefCell<u8>,
        sector: RefCell<[u32; 128]>,
        word_idx: RefCell<usize>,
    }

    impl MockSdhci {
        fn new() -> Self {
            Self {
                last_cmd: RefCell::new(0),
                sector: RefCell::new([0; 128]),
                word_idx: RefCell::new(0),
            }
        }
    }

    impl StorageMmioTransport for &MockSdhci {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_CLK_RESET => Ok(CLK_INT_STABLE),
                REG_PRESENT_STATE => Ok(PSTATE_CARD_INSERTED),
                REG_INT_STATUS => Ok(INT_CMD_COMPLETE
                    | INT_XFER_COMPLETE
                    | INT_BUF_READ_READY
                    | INT_BUF_WRITE_READY),
                REG_RESPONSE0 => match *self.last_cmd.borrow() {
                    41 => Ok((1 << 31) | (1 << 30)), // Ready + SDHC/SDXC
                    3 => Ok(0x1234_0000),            // RCA
                    _ => Ok(0),
                },
                REG_BUFFER_DATA => {
                    let mut idx = self.word_idx.borrow_mut();
                    let w = self.sector.borrow()[*idx % 128];
                    *idx += 1;
                    Ok(w)
                }
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == REG_XFER_CMD {
                *self.last_cmd.borrow_mut() = ((val >> 24) & 0x3F) as u8;
                *self.word_idx.borrow_mut() = 0;
            } else if offset == REG_BUFFER_DATA {
                let mut idx = self.word_idx.borrow_mut();
                self.sector.borrow_mut()[*idx % 128] = val;
                *idx += 1;
            }
            Ok(())
        }
    }

    #[test]
    fn sdhci_initializes_and_roundtrips_512b_sector() {
        let mock = MockSdhci::new();
        let mut sd = Bcm2712Sdhci::init(&mock, 1024).expect("sdhci init");
        assert_eq!(sd.block_count(), 1024);

        let mut tx = [0u8; SECTOR_SIZE];
        tx[0..4].copy_from_slice(b"RPI5");
        tx[508..512].copy_from_slice(b"SDHC");
        sd.write_block(7, &tx).expect("write sector");

        let mut rx = [0u8; SECTOR_SIZE];
        sd.read_block(7, &mut rx).expect("read sector");
        assert_eq!(rx, tx);
    }

    #[test]
    fn sdhci_init_returns_would_block_on_absent_card_or_timeout() {
        struct StuckSdhci {
            clk_reset: u32,
            present_state: u32,
        }
        impl StorageMmioTransport for StuckSdhci {
            fn read32(&self, offset: u64) -> Result<u32, SysError> {
                match offset {
                    REG_CLK_RESET => Ok(self.clk_reset),
                    REG_PRESENT_STATE => Ok(self.present_state),
                    _ => Ok(0),
                }
            }
            fn write32(&self, _offset: u64, _val: u32) -> Result<(), SysError> {
                Ok(())
            }
        }

        // SW_RESET_ALL never clears -> WouldBlock
        assert_eq!(
            Bcm2712Sdhci::init(
                StuckSdhci {
                    clk_reset: SW_RESET_ALL,
                    present_state: PSTATE_CARD_INSERTED,
                },
                1024
            )
            .err(),
            Some(SysError::WouldBlock)
        );

        // Card absent -> WouldBlock
        assert_eq!(
            Bcm2712Sdhci::init(
                StuckSdhci {
                    clk_reset: CLK_INT_STABLE,
                    present_state: 0,
                },
                1024
            )
            .err(),
            Some(SysError::WouldBlock)
        );

        // CLK_INT_STABLE never sets -> WouldBlock
        assert_eq!(
            Bcm2712Sdhci::init(
                StuckSdhci {
                    clk_reset: 0,
                    present_state: PSTATE_CARD_INSERTED,
                },
                1024
            )
            .err(),
            Some(SysError::WouldBlock)
        );
    }
}
