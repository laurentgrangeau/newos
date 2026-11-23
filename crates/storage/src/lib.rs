#![no_std]
#![forbid(unsafe_code)]

//! Pure `#![forbid(unsafe_code)]`, `no_alloc` Raspberry Pi 5 PCIe & Block Storage Suite.
//!
//! - [`pcie`]: PCIe ECAM configuration space enumerator, BAR decoder, and MSI-X capability walker
//! - [`sdhci`]: BCM2712 microSD SDHCI 3.0 / SDR104 block driver (`0x10_00ff_f000`)
//! - [`nvme`]: NVMe 1.4 PCIe SSD block driver (for Raspberry Pi 5 PCIe 2.0 x1 FFC connector)

pub mod nvme;
pub mod pcie;
pub mod sdhci;

use newos_abi::SysError;

/// Standard 512-byte logical block size.
pub const SECTOR_SIZE: usize = 512;

/// Capability-scoped 32-bit MMIO transport injected by EL0 `user-rt` or mock tests.
pub trait StorageMmioTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError>;
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;
}

/// Capability-scoped MMIO + DMA translation & cache-coherency transport (for NVMe).
pub trait StorageDmaTransport: StorageMmioTransport {
    fn virt_to_phys<T>(&self, value: &T) -> Result<u64, SysError>;

    fn dma_clean<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }

    fn dma_invalidate<T>(&self, _value: &T) -> Result<(), SysError> {
        Ok(())
    }
}

/// Unified `no_alloc` 512-byte sector block device trait (implemented by SDHCI & NVMe).
pub trait BlockDevice {
    fn block_count(&self) -> u64;
    fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError>;
    fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError>;
}

const SNAPSHOT_MAGIC: [u8; 4] = *b"CAOS";

/// Persist a serialized CAOS snapshot payload starting at `start_lba` with a 16-byte header
/// (`magic = "CAOS"`, `len: u32`, `sha3_prefix: u64`) followed by payload bytes across 512 B sectors.
pub fn write_caos_snapshot<D: BlockDevice>(
    dev: &mut D,
    start_lba: u64,
    payload: &[u8],
) -> Result<u64, SysError> {
    let total_bytes = 16usize
        .checked_add(payload.len())
        .ok_or(SysError::InvalidArgument)?;
    let sectors = total_bytes.div_ceil(SECTOR_SIZE) as u64;
    if start_lba.saturating_add(sectors) > dev.block_count() {
        return Err(SysError::OutOfMemory);
    }

    let digest = newos_abi::sha3::digest_prefix_u64(payload);
    let mut header = [0u8; 16];
    header[0..4].copy_from_slice(&SNAPSHOT_MAGIC);
    header[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[8..16].copy_from_slice(&digest.to_le_bytes());

    let mut written = 0usize;
    for s in 0..sectors {
        let mut block = [0u8; SECTOR_SIZE];
        let mut off = 0usize;
        if s == 0 {
            block[0..16].copy_from_slice(&header);
            off = 16;
        }
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
    let sectors = (16 + payload_len).div_ceil(SECTOR_SIZE) as u64;
    if start_lba.saturating_add(sectors) > dev.block_count() {
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

    if newos_abi::sha3::digest_prefix_u64(&dst[..payload_len]) != expected_digest {
        return Err(SysError::InvalidArgument);
    }
    Ok(payload_len)
}

#[cfg(test)]
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
}
