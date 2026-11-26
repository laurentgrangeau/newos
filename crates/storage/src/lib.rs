#![no_std]

//! Raspberry Pi 5 `PCIe` & Block Storage Suite.
//!
//! - [`pcie`]: `PCIe` ECAM configuration space enumerator, BAR decoder, and MSI-X capability walker
//! - [`sdhci`]: BCM2712 microSD SDHCI 3.0 / SDR104 block driver (`0x10_00ff_f000`)
//! - [`nvme`]: `NVMe` 1.4 `PCIe` SSD block driver (for Raspberry Pi 5 `PCIe` 2.0 `x1` FFC connector)

#[cfg(feature = "nvme")]
pub mod nvme;
#[cfg(feature = "pcie")]
pub mod pcie;
#[cfg(feature = "sdhci")]
pub mod sdhci;

use newos_abi::SysError;

/// Standard 512-byte logical block size.
pub const SECTOR_SIZE: usize = 512;

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait StorageMmioTransport {
    /// Read a 32-bit register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write a 32-bit register at `offset` within the scoped MMIO window.
    ///
    /// # Errors
    /// Returns [`SysError`] if the capability is missing or `offset` is out of bounds.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Capability-scoped MMIO + DMA translation & cache-coherency transport (for `NVMe`).
pub trait StorageDmaTransport: StorageMmioTransport {
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

/// Unified 512-byte sector block device trait (implemented by SDHCI & `NVMe`).
pub trait BlockDevice {
    /// Return the total number of 512-byte logical blocks on this device.
    fn block_count(&self) -> u64;

    /// Read a single 512-byte logical block at `lba` into `dst`.
    ///
    /// # Errors
    /// Returns [`SysError`] if `lba` is out of bounds or the underlying device I/O fails.
    fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError>;

    /// Write a single 512-byte logical block from `src` to `lba`.
    ///
    /// # Errors
    /// Returns [`SysError`] if `lba` is out of bounds or the underlying device I/O fails.
    fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError>;
}

#[cfg(feature = "caos-snapshot")]
const SNAPSHOT_MAGIC: [u8; 4] = *b"CAOS";

/// Persist a serialized CAOS snapshot payload starting at `start_lba` with a 16-byte header
/// (`magic = "CAOS"`, `len: u32`, `sha3_prefix: u64`) followed by payload bytes across 512 B sectors.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `payload.len()` exceeds `u32::MAX` or overflows,
/// [`SysError::OutOfMemory`] if the device lacks space from `start_lba`, or a block device
/// [`SysError`].
#[cfg(feature = "caos-snapshot")]
pub fn write_caos_snapshot<D: BlockDevice>(
    dev: &mut D,
    start_lba: u64,
    payload: &[u8],
) -> Result<u64, SysError> {
    let payload_len_u32 = u32::try_from(payload.len()).map_err(|_| SysError::InvalidArgument)?;
    let total_bytes = 16usize
        .checked_add(payload.len())
        .ok_or(SysError::InvalidArgument)?;
    let sectors = total_bytes.div_ceil(SECTOR_SIZE) as u64;
    let end_lba = start_lba
        .checked_add(sectors)
        .ok_or(SysError::OutOfMemory)?;
    if end_lba > dev.block_count() {
        return Err(SysError::OutOfMemory);
    }

    let digest = newos_crypto::sha3::digest_prefix_u64(payload);
    let mut header = [0u8; 16];
    header[0..4].copy_from_slice(&SNAPSHOT_MAGIC);
    header[4..8].copy_from_slice(&payload_len_u32.to_le_bytes());
    header[8..16].copy_from_slice(&digest.to_le_bytes());

    let mut written = 0usize;
    for s in 0..sectors {
        let mut block = [0u8; SECTOR_SIZE];
        let off = if s == 0 {
            block[0..16].copy_from_slice(&header);
            16
        } else {
            0
        };
        let remain = payload.len().saturating_sub(written);
        let take = (SECTOR_SIZE - off).min(remain);
        if take > 0 {
            block[off..off + take].copy_from_slice(&payload[written..written + take]);
            written += take;
        }
        dev.write_block(start_lba + s, &block)?;
    }
    Ok(sectors)
}

/// Read and SHA3-512-verify a CAOS snapshot from `start_lba` into `dst`, returning payload length.
///
/// # Errors
/// Returns [`SysError::InvalidArgument`] if `start_lba` is out of bounds, the magic header is
/// invalid, the snapshot spans past the end of the device, or the SHA3-512 digest mismatches;
/// [`SysError::OutOfMemory`] if `dst` is too small; or a block device [`SysError`].
#[cfg(feature = "caos-snapshot")]
pub fn read_caos_snapshot<D: BlockDevice>(
    dev: &mut D,
    start_lba: u64,
    dst: &mut [u8],
) -> Result<usize, SysError> {
    if start_lba >= dev.block_count() {
        return Err(SysError::InvalidArgument);
    }
    let mut first = [0u8; SECTOR_SIZE];
    dev.read_block(start_lba, &mut first)?;
    if first[0..4] != SNAPSHOT_MAGIC {
        return Err(SysError::InvalidArgument);
    }
    let payload_len = u32::from_le_bytes([first[4], first[5], first[6], first[7]]) as usize;
    let expected_digest = u64::from_le_bytes([
        first[8], first[9], first[10], first[11], first[12], first[13], first[14], first[15],
    ]);
    if payload_len > dst.len() {
        return Err(SysError::OutOfMemory);
    }
    let total_bytes = 16usize
        .checked_add(payload_len)
        .ok_or(SysError::InvalidArgument)?;
    let sectors = total_bytes.div_ceil(SECTOR_SIZE) as u64;
    let end_lba = start_lba
        .checked_add(sectors)
        .ok_or(SysError::InvalidArgument)?;
    if end_lba > dev.block_count() {
        return Err(SysError::InvalidArgument);
    }

    let first_take = (SECTOR_SIZE - 16).min(payload_len);
    dst[..first_take].copy_from_slice(&first[16..16 + first_take]);
    let mut read = first_take;
    for s in 1..sectors {
        let mut block = [0u8; SECTOR_SIZE];
        dev.read_block(start_lba + s, &mut block)?;
        let take = SECTOR_SIZE.min(payload_len - read);
        dst[read..read + take].copy_from_slice(&block[..take]);
        read += take;
    }

    if newos_crypto::sha3::digest_prefix_u64(&dst[..payload_len]) != expected_digest {
        return Err(SysError::InvalidArgument);
    }
    Ok(payload_len)
}

#[cfg(test)]
#[cfg(feature = "caos-snapshot")]
mod tests {
    use super::*;

    struct MemDisk<const N: usize> {
        sectors: [[u8; SECTOR_SIZE]; N],
    }

    impl<const N: usize> BlockDevice for MemDisk<N> {
        fn block_count(&self) -> u64 {
            N as u64
        }
        fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError> {
            let idx = usize::try_from(lba).map_err(|_| SysError::InvalidArgument)?;
            if idx >= N {
                return Err(SysError::InvalidArgument);
            }
            *dst = self.sectors[idx];
            Ok(())
        }
        fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError> {
            let idx = usize::try_from(lba).map_err(|_| SysError::InvalidArgument)?;
            if idx >= N {
                return Err(SysError::InvalidArgument);
            }
            self.sectors[idx] = *src;
            Ok(())
        }
    }

    #[test]
    fn caos_snapshot_block_roundtrip_and_tamper_detection() {
        let mut disk = MemDisk {
            sectors: [[0u8; SECTOR_SIZE]; 4],
        };
        let payload = [0xA5u8; 700]; // Spans 2 sectors (16 + 700 = 716 B)
        let used = write_caos_snapshot(&mut disk, 1, &payload).expect("write snapshot");
        assert_eq!(used, 2);

        let mut out = [0u8; 1024];
        let len = read_caos_snapshot(&mut disk, 1, &mut out).expect("read snapshot");
        assert_eq!(len, 700);
        assert_eq!(&out[..len], &payload);

        // Flip 1 bit on disk -> SHA3-512 integrity check rejects corrupted snapshot
        disk.sectors[2][10] ^= 0x01;
        assert_eq!(
            read_caos_snapshot(&mut disk, 1, &mut out),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn caos_snapshot_rejects_bad_magic_small_buffer_and_oob_lba() {
        let mut disk = MemDisk {
            sectors: [[0u8; SECTOR_SIZE]; 4],
        };
        let payload = [0x5Au8; 64];
        write_caos_snapshot(&mut disk, 0, &payload).expect("write snapshot");

        // Insufficient destination buffer -> OutOfMemory
        let mut small = [0u8; 32];
        assert_eq!(
            read_caos_snapshot(&mut disk, 0, &mut small),
            Err(SysError::OutOfMemory)
        );

        // Out-of-bounds start_lba -> InvalidArgument
        let mut ok_buf = [0u8; 128];
        assert_eq!(
            read_caos_snapshot(&mut disk, 4, &mut ok_buf),
            Err(SysError::InvalidArgument)
        );

        // Bad magic header -> InvalidArgument
        disk.sectors[0][0] = b'X';
        assert_eq!(
            read_caos_snapshot(&mut disk, 0, &mut ok_buf),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn caos_snapshot_rejects_u64_max_lba_overflow_without_panic() {
        struct MaxLbaDisk {
            header_block: [u8; SECTOR_SIZE],
        }

        impl BlockDevice for MaxLbaDisk {
            fn block_count(&self) -> u64 {
                u64::MAX
            }
            fn read_block(
                &mut self,
                lba: u64,
                dst: &mut [u8; SECTOR_SIZE],
            ) -> Result<(), SysError> {
                if lba == u64::MAX - 1 {
                    *dst = self.header_block;
                    Ok(())
                } else {
                    Err(SysError::InvalidArgument)
                }
            }
            fn write_block(&mut self, _lba: u64, _src: &[u8; SECTOR_SIZE]) -> Result<(), SysError> {
                Ok(())
            }
        }

        let mut header_block = [0u8; SECTOR_SIZE];
        header_block[0..4].copy_from_slice(&SNAPSHOT_MAGIC);
        header_block[4..8].copy_from_slice(&1200u32.to_le_bytes());

        let mut disk = MaxLbaDisk { header_block };

        // write_caos_snapshot: start_lba = u64::MAX, 500 B payload (2 sectors) -> OutOfMemory
        let payload = [0xABu8; 500];
        assert_eq!(
            write_caos_snapshot(&mut disk, u64::MAX, &payload),
            Err(SysError::OutOfMemory)
        );

        // read_caos_snapshot: start_lba = u64::MAX - 1, 1200 B header (3 sectors) -> InvalidArgument
        let mut out = [0u8; 2048];
        assert_eq!(
            read_caos_snapshot(&mut disk, u64::MAX - 1, &mut out),
            Err(SysError::InvalidArgument)
        );
    }
}
