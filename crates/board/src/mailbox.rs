//! Raspberry Pi 5 (BCM2712) `VideoCore` Property Mailbox Driver.
//!
//! Physical MMIO page: `0x10_7C01_3000` (Mailbox registers start at offset `0x880`).
//! Uses a 16-byte-aligned property buffer with explicit `dma_clean`/`dma_invalidate`.

use crate::MmioDmaTransport;
use core::sync::atomic::{AtomicU32, Ordering, fence};
use newos_abi::SysError;

/// Page-aligned physical base of the BCM2712 `VideoCore` Mailbox MMIO window.
pub const BCM2712_MBOX_PAGE_PHYS: u64 = 0x10_7C01_3000;
/// Byte offset of Mailbox 0 within the `0x10_7C01_3000` page (`0x10_7C01_3880`).
pub const MBOX_BASE_OFF: u64 = 0x880;

pub const REG_MBOX0_READ: u64 = MBOX_BASE_OFF;
pub const REG_MBOX0_STATUS: u64 = MBOX_BASE_OFF + 0x18;
pub const REG_MBOX1_WRITE: u64 = MBOX_BASE_OFF + 0x20;
pub const REG_MBOX1_STATUS: u64 = MBOX_BASE_OFF + 0x38;

pub const MBOX_STATUS_FULL: u32 = 1 << 31;
pub const MBOX_STATUS_EMPTY: u32 = 1 << 30;
pub const MBOX_CHANNEL_PROP: u32 = 8;
pub const MBOX_RESPONSE_OK: u32 = 0x8000_0000;

// Standard Raspberry Pi VideoCore Property Tags
pub const TAG_GET_FIRMWARE_REV: u32 = 0x0000_0001;
pub const TAG_GET_BOARD_MODEL: u32 = 0x0001_0001;
pub const TAG_GET_BOARD_REV: u32 = 0x0001_0002;
pub const TAG_GET_BOARD_SERIAL: u32 = 0x0001_0004;
pub const TAG_GET_ARM_MEMORY: u32 = 0x0001_0005;
pub const TAG_SET_POWER_STATE: u32 = 0x0002_8001;
pub const TAG_GET_CLOCK_RATE: u32 = 0x0003_0002;
pub const TAG_GET_TEMPERATURE: u32 = 0x0003_0006;

const MAX_POLL_ITERS: u32 = 200_000;

/// Power domain state for `VideoCore` `TAG_SET_POWER_STATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Off,
    On,
}

impl PowerState {
    /// Return `true` if this power domain state is [`Self::On`].
    #[inline]
    #[must_use]
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }
}

/// 16-byte-aligned static DMA buffer for `VideoCore` Property Mailbox messages.
#[derive(Debug)]
#[repr(C, align(16))]
pub struct MailboxBuf {
    words: [AtomicU32; 16],
}

impl Default for MailboxBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl MailboxBuf {
    /// Create a zero-initialized 16-byte-aligned property mailbox buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            words: [const { AtomicU32::new(0) }; 16],
        }
    }

    #[inline]
    fn set(&self, idx: usize, val: u32) {
        self.words[idx].store(val, Ordering::Relaxed);
    }

    #[inline]
    fn get(&self, idx: usize) -> u32 {
        self.words[idx].load(Ordering::Acquire)
    }
}

/// Capability-scoped EL0 driver for the BCM2712 `VideoCore` Property Mailbox.
#[derive(Debug)]
pub struct VideoCoreMailbox<'a, T: MmioDmaTransport> {
    transport: T,
    buf: &'a MailboxBuf,
}

impl<'a, T: MmioDmaTransport> VideoCoreMailbox<'a, T> {
    /// Construct a `VideoCore` Property Mailbox driver bound to `transport` and static `buf`.
    #[must_use]
    pub const fn new(transport: T, buf: &'a MailboxBuf) -> Self {
        Self { transport, buf }
    }

    /// Execute a single-tag property call with `req_words` payload (up to 4 words),
    /// returning the first two response `u32` words.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidArgument`] if `req_words.len() > 4`, `resp_len_bytes > 16`, or
    /// the DMA buffer physical address is unaligned / above 4 GiB; [`SysError::WouldBlock`] on
    /// TX/RX FIFO poll timeout; [`SysError::Unsupported`] if the firmware rejects the tag; or a
    /// transport [`SysError`].
    pub fn call_tag(
        &self,
        tag: u32,
        req_words: &[u32],
        resp_len_bytes: u32,
    ) -> Result<(u32, u32), SysError> {
        if req_words.len() > 4 || resp_len_bytes > 16 {
            return Err(SysError::InvalidArgument);
        }
        let val_words = req_words.len().max((resp_len_bytes as usize).div_ceil(4));
        let total_words = 6 + val_words; // header(2) + tag_hdr(3) + val_words + end_tag(1)
        let total_bytes = u32::try_from(total_words * 4).map_err(|_| SysError::InvalidArgument)?;
        let val_bytes = u32::try_from(val_words * 4).map_err(|_| SysError::InvalidArgument)?;
        let req_bytes =
            u32::try_from(req_words.len() * 4).map_err(|_| SysError::InvalidArgument)?;

        self.buf.set(0, total_bytes);
        self.buf.set(1, 0); // request code
        self.buf.set(2, tag);
        self.buf.set(3, val_bytes);
        self.buf.set(4, req_bytes);
        for i in 0..val_words {
            self.buf.set(5 + i, req_words.get(i).copied().unwrap_or(0));
        }
        self.buf.set(5 + val_words, 0); // end tag

        fence(Ordering::SeqCst);
        self.transport.dma_clean(self.buf)?;

        let phys = self.transport.virt_to_phys(self.buf)?;
        let phys32 = u32::try_from(phys).map_err(|_| SysError::InvalidArgument)?;
        if (phys32 & 0xF) != 0 {
            // VideoCore mailbox requires a 16-byte-aligned 32-bit bus/physical address.
            return Err(SysError::InvalidArgument);
        }
        let msg = (phys32 & !0xF) | MBOX_CHANNEL_PROP;

        // Drain any stale/late replies from Mailbox 0 RX FIFO before sending a new request (`P12`).
        for _ in 0..16u32 {
            if (self.transport.read32(REG_MBOX0_STATUS)? & MBOX_STATUS_EMPTY) != 0 {
                break;
            }
            let _ = self.transport.read32(REG_MBOX0_READ)?;
        }

        // Wait for Mailbox 1 TX FIFO to have space
        let mut ready = false;
        for _ in 0..MAX_POLL_ITERS {
            if (self.transport.read32(REG_MBOX1_STATUS)? & MBOX_STATUS_FULL) == 0 {
                ready = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ready {
            return Err(SysError::WouldBlock);
        }
        self.transport.write32(REG_MBOX1_WRITE, msg)?;

        // Poll Mailbox 0 RX FIFO for matching channel 8 response and verify tag/status (`P12`).
        for _ in 0..MAX_POLL_ITERS {
            if (self.transport.read32(REG_MBOX0_STATUS)? & MBOX_STATUS_EMPTY) != 0 {
                core::hint::spin_loop();
                continue;
            }
            let reply = self.transport.read32(REG_MBOX0_READ)?;
            if reply == msg {
                self.transport.dma_invalidate(self.buf)?;
                fence(Ordering::SeqCst);
                if self.buf.get(1) != MBOX_RESPONSE_OK || self.buf.get(2) != tag {
                    return Err(SysError::Unsupported);
                }
                return Ok((self.buf.get(5), self.buf.get(6)));
            }
        }
        Err(SysError::WouldBlock)
    }

    /// Query the `VideoCore` firmware revision.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_firmware_revision(&self) -> Result<u32, SysError> {
        Ok(self.call_tag(TAG_GET_FIRMWARE_REV, &[], 4)?.0)
    }

    /// Query the Raspberry Pi board model identifier.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_board_model(&self) -> Result<u32, SysError> {
        Ok(self.call_tag(TAG_GET_BOARD_MODEL, &[], 4)?.0)
    }

    /// Query the Raspberry Pi board revision code.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_board_revision(&self) -> Result<u32, SysError> {
        Ok(self.call_tag(TAG_GET_BOARD_REV, &[], 4)?.0)
    }

    /// Query the 64-bit board serial number.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_board_serial(&self) -> Result<u64, SysError> {
        let (lo, hi) = self.call_tag(TAG_GET_BOARD_SERIAL, &[], 8)?;
        Ok(u64::from(lo) | (u64::from(hi) << 32))
    }

    /// Return `(base_addr, size_bytes)` of low ARM memory reported by `VideoCore`.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_arm_memory(&self) -> Result<(u32, u32), SysError> {
        self.call_tag(TAG_GET_ARM_MEMORY, &[], 8)
    }

    /// Query `SoC` temperature in milli-degrees Celsius (e.g., `48_500` = 48.5 °C).
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_soc_temperature_millic(&self) -> Result<u32, SysError> {
        Ok(self.call_tag(TAG_GET_TEMPERATURE, &[0], 8)?.1)
    }

    /// Query hardware clock rate in Hz for `clock_id` (e.g., `3` = ARM, `4` = Core).
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn get_clock_rate_hz(&self, clock_id: u32) -> Result<u32, SysError> {
        Ok(self.call_tag(TAG_GET_CLOCK_RATE, &[clock_id], 8)?.1)
    }

    /// Set `VideoCore` power domain state (`wait = true`) and return the resulting state.
    ///
    /// # Errors
    /// Returns [`SysError`] if the mailbox transaction fails.
    pub fn set_power_state(
        &self,
        device_id: u32,
        state: PowerState,
    ) -> Result<PowerState, SysError> {
        let bits = match state {
            PowerState::On => 0b11,  // bit 0 = ON, bit 1 = WAIT
            PowerState::Off => 0b10, // bit 0 = OFF, bit 1 = WAIT
        };
        let (_, resp) = self.call_tag(TAG_SET_POWER_STATE, &[device_id, bits], 8)?;
        Ok(if (resp & 1) != 0 {
            PowerState::On
        } else {
            PowerState::Off
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MmioTransport;
    use core::cell::RefCell;

    struct MockMailbox<'a> {
        buf: &'a MailboxBuf,
        dma_phys: u64,
        last_msg: RefCell<u32>,
        cleans: RefCell<u32>,
        invalidates: RefCell<u32>,
    }

    impl MmioTransport for &MockMailbox<'_> {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                REG_MBOX1_STATUS | REG_MBOX0_STATUS => Ok(0),
                REG_MBOX0_READ => Ok(*self.last_msg.borrow()),
                _ => Err(SysError::InvalidArgument),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == REG_MBOX1_WRITE {
                *self.last_msg.borrow_mut() = val;
                let tag = self.buf.get(2);
                self.buf.set(1, MBOX_RESPONSE_OK);
                match tag {
                    TAG_GET_BOARD_REV => self.buf.set(5, 0x00D0_4171), // RPi 5 16GB rev
                    TAG_GET_TEMPERATURE => self.buf.set(6, 47_250),
                    TAG_GET_BOARD_SERIAL => {
                        self.buf.set(5, 0x1234_5678);
                        self.buf.set(6, 0xABCD_0001);
                    }
                    TAG_SET_POWER_STATE => {
                        let req_bits = self.buf.get(6);
                        self.buf.set(6, req_bits & 1);
                    }
                    _ => {}
                }
                return Ok(());
            }
            Err(SysError::InvalidArgument)
        }
    }

    impl MmioDmaTransport for &MockMailbox<'_> {
        fn virt_to_phys<T>(&self, _value: &T) -> Result<u64, SysError> {
            Ok(self.dma_phys)
        }

        fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
            *self.cleans.borrow_mut() += 1;
            Ok(())
        }

        fn dma_invalidate<T>(&self, _value: &T) -> Result<(), SysError> {
            *self.invalidates.borrow_mut() += 1;
            Ok(())
        }
    }

    #[test]
    fn mailbox_queries_revision_temperature_and_serial_with_dma_coherency() {
        let buf = MailboxBuf::new();
        let mock = MockMailbox {
            buf: &buf,
            dma_phys: 0x0010_0000,
            last_msg: RefCell::new(0),
            cleans: RefCell::new(0),
            invalidates: RefCell::new(0),
        };
        let mbox = VideoCoreMailbox::new(&mock, &buf);
        assert_eq!(mbox.get_board_revision(), Ok(0x00D0_4171));
        assert_eq!(mbox.get_soc_temperature_millic(), Ok(47_250));
        assert_eq!(mbox.get_board_serial(), Ok(0xABCD_0001_1234_5678));
        assert_eq!(*mock.cleans.borrow(), 3);
        assert_eq!(*mock.invalidates.borrow(), 3);
    }

    #[test]
    fn mailbox_power_state_and_argument_validation() {
        let buf = MailboxBuf::new();
        let mock = MockMailbox {
            buf: &buf,
            dma_phys: 0x0010_0000,
            last_msg: RefCell::new(0),
            cleans: RefCell::new(0),
            invalidates: RefCell::new(0),
        };
        let mbox = VideoCoreMailbox::new(&mock, &buf);

        let on = mbox.set_power_state(3, PowerState::On).expect("power on");
        assert_eq!(on, PowerState::On);
        assert!(on.is_on());

        let off = mbox.set_power_state(3, PowerState::Off).expect("power off");
        assert_eq!(off, PowerState::Off);
        assert!(!off.is_on());

        // Oversized req_words / resp_len_bytes rejected
        assert_eq!(
            mbox.call_tag(TAG_GET_BOARD_REV, &[1, 2, 3, 4, 5], 4),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            mbox.call_tag(TAG_GET_BOARD_REV, &[], 20),
            Err(SysError::InvalidArgument)
        );

        // Unaligned or >32-bit DMA physical address rejected
        let unaligned = MockMailbox {
            buf: &buf,
            dma_phys: 0x0010_0004,
            last_msg: RefCell::new(0),
            cleans: RefCell::new(0),
            invalidates: RefCell::new(0),
        };
        assert_eq!(
            VideoCoreMailbox::new(&unaligned, &buf).get_board_revision(),
            Err(SysError::InvalidArgument)
        );

        let high_phys = MockMailbox {
            buf: &buf,
            dma_phys: 1u64 << 32,
            last_msg: RefCell::new(0),
            cleans: RefCell::new(0),
            invalidates: RefCell::new(0),
        };
        assert_eq!(
            VideoCoreMailbox::new(&high_phys, &buf).get_board_revision(),
            Err(SysError::InvalidArgument)
        );
    }
}
