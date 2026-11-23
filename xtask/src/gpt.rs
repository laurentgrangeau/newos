//! Pure-Rust UEFI GPT + Protective MBR disk image builder (zero external dependencies).
//!
//! Wraps a FAT32 EFI System Partition (ESP) image into a standard 512-byte-sector GPT disk
//! with an EFI System Partition (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`) aligned at 1 MiB (LBA 2048).

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub const SECTOR_SIZE: u64 = 512;
pub const ESP_START_LBA: u64 = 2048; // 1 MiB alignment
const GPT_ENTRY_COUNT: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const GPT_ARRAY_BYTES: usize = (GPT_ENTRY_COUNT as usize) * (GPT_ENTRY_SIZE as usize);
const GPT_ARRAY_SECTORS: u64 = (GPT_ARRAY_BYTES as u64) / SECTOR_SIZE; // 32 sectors

/// UEFI EFI System Partition Type GUID: `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` (mixed-endian).
const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];

/// Deterministic Disk GUID (`4E45574F-5344-4953-8B00-000000000001`).
const DISK_GUID: [u8; 16] = [
    0x4F, 0x57, 0x45, 0x4E, 0x53, 0x44, 0x53, 0x49, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Deterministic ESP Partition GUID (`4E45574F-5345-4553-8B00-000000000002`).
const PART_GUID: [u8; 16] = [
    0x4F, 0x57, 0x45, 0x4E, 0x45, 0x53, 0x53, 0x45, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// Standard IEEE 802.3 CRC32 used by UEFI GPT headers and partition entry arrays.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Compute the byte size of the FAT32 ESP partition for a given total GPT disk size in bytes.
pub fn esp_partition_bytes(total_disk_bytes: u64) -> Result<u64, String> {
    if !total_disk_bytes.is_multiple_of(SECTOR_SIZE) {
        return Err("GPT disk size must be a multiple of 512 bytes".to_string());
    }
    let total_sectors = total_disk_bytes / SECTOR_SIZE;
    let overhead_tail = GPT_ARRAY_SECTORS + 1; // 32 backup entry sectors + 1 backup header sector
    if total_sectors <= ESP_START_LBA + overhead_tail + 64 {
        return Err("GPT disk image is too small for a FAT32 ESP".to_string());
    }
    let last_usable_lba = total_sectors - overhead_tail - 1;
    let esp_sectors = last_usable_lba - ESP_START_LBA + 1;
    Ok(esp_sectors * SECTOR_SIZE)
}

fn build_protective_mbr(total_sectors: u64) -> [u8; 512] {
    let mut mbr = [0u8; 512];
    let size_lba = (total_sectors.saturating_sub(1)).min(u64::from(u32::MAX)) as u32;
    // Partition entry 0 at offset 446: type 0xEE (GPT Protective)
    mbr[446] = 0x00;
    mbr[447..450].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[450] = 0xEE;
    mbr[451..454].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    mbr[454..458].copy_from_slice(&1u32.to_le_bytes());
    mbr[458..462].copy_from_slice(&size_lba.to_le_bytes());
    // Boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

fn build_partition_array(first_lba: u64, last_lba: u64, label: &str) -> Vec<u8> {
    let mut array = vec![0u8; GPT_ARRAY_BYTES];
    let entry = &mut array[0..GPT_ENTRY_SIZE as usize];
    entry[0..16].copy_from_slice(&ESP_TYPE_GUID);
    entry[16..32].copy_from_slice(&PART_GUID);
    entry[32..40].copy_from_slice(&first_lba.to_le_bytes());
    entry[40..48].copy_from_slice(&last_lba.to_le_bytes());
    entry[48..56].copy_from_slice(&0u64.to_le_bytes());
    for (i, ch) in label.encode_utf16().take(35).enumerate() {
        let off = 56 + i * 2;
        entry[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }
    array
}

fn build_gpt_header(
    my_lba: u64,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    partition_entry_lba: u64,
    entries_crc32: u32,
) -> [u8; 512] {
    let mut hdr = [0u8; 512];
    hdr[0..8].copy_from_slice(b"EFI PART");
    hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // GPT Revision 1.0
    hdr[12..16].copy_from_slice(&92u32.to_le_bytes()); // HeaderSize
    hdr[24..32].copy_from_slice(&my_lba.to_le_bytes());
    hdr[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    hdr[40..48].copy_from_slice(&first_usable_lba.to_le_bytes());
    hdr[48..56].copy_from_slice(&last_usable_lba.to_le_bytes());
    hdr[56..72].copy_from_slice(&DISK_GUID);
    hdr[72..80].copy_from_slice(&partition_entry_lba.to_le_bytes());
    hdr[80..84].copy_from_slice(&GPT_ENTRY_COUNT.to_le_bytes());
    hdr[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
    hdr[88..92].copy_from_slice(&entries_crc32.to_le_bytes());

    let header_crc = crc32(&hdr[0..92]);
    hdr[16..20].copy_from_slice(&header_crc.to_le_bytes());
    hdr
}

/// Assemble a complete UEFI GPT disk image at `out_path` by placing the formatted FAT32 ESP
/// partition image (`esp_path`) at LBA 2048 (1 MiB) and writing Protective MBR + Primary/Backup GPT.
pub fn write_gpt_disk_image(
    out_path: &Path,
    esp_path: &Path,
    total_disk_bytes: u64,
    label: &str,
) -> Result<(), String> {
    let expected_esp = esp_partition_bytes(total_disk_bytes)?;
    let esp_meta = std::fs::metadata(esp_path)
        .map_err(|e| format!("failed to stat ESP {}: {e}", esp_path.display()))?;
    if esp_meta.len() != expected_esp {
        return Err(format!(
            "ESP size mismatch: expected {expected_esp} bytes, got {}",
            esp_meta.len()
        ));
    }

    let total_sectors = total_disk_bytes / SECTOR_SIZE;
    let backup_header_lba = total_sectors - 1;
    let backup_entries_lba = backup_header_lba - GPT_ARRAY_SECTORS;
    let last_usable_lba = backup_entries_lba - 1;

    let mbr = build_protective_mbr(total_sectors);
    let entries = build_partition_array(ESP_START_LBA, last_usable_lba, label);
    let entries_crc = crc32(&entries);
    let primary_hdr = build_gpt_header(
        1,
        backup_header_lba,
        ESP_START_LBA,
        last_usable_lba,
        2,
        entries_crc,
    );
    let backup_hdr = build_gpt_header(
        backup_header_lba,
        1,
        ESP_START_LBA,
        last_usable_lba,
        backup_entries_lba,
        entries_crc,
    );

    let mut out = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path)
        .map_err(|e| format!("failed to create GPT disk {}: {e}", out_path.display()))?;
    out.set_len(total_disk_bytes)
        .map_err(|e| format!("failed to size GPT disk: {e}"))?;

    // LBA 0: Protective MBR
    out.seek(SeekFrom::Start(0))
        .and_then(|_| out.write_all(&mbr))
        .map_err(|e| format!("write MBR: {e}"))?;
    // LBA 1: Primary GPT Header
    out.seek(SeekFrom::Start(SECTOR_SIZE))
        .and_then(|_| out.write_all(&primary_hdr))
        .map_err(|e| format!("write primary GPT header: {e}"))?;
    // LBA 2..33: Primary Partition Entry Array
    out.seek(SeekFrom::Start(2 * SECTOR_SIZE))
        .and_then(|_| out.write_all(&entries))
        .map_err(|e| format!("write primary GPT entries: {e}"))?;
    // LBA 2048..last_usable_lba: FAT32 ESP
    out.seek(SeekFrom::Start(ESP_START_LBA * SECTOR_SIZE))
        .map_err(|e| format!("seek ESP: {e}"))?;
    let mut esp_file =
        File::open(esp_path).map_err(|e| format!("open ESP {}: {e}", esp_path.display()))?;
    std::io::copy(&mut esp_file, &mut out).map_err(|e| format!("copy ESP into GPT: {e}"))?;
    // Backup Partition Entry Array
    out.seek(SeekFrom::Start(backup_entries_lba * SECTOR_SIZE))
        .and_then(|_| out.write_all(&entries))
        .map_err(|e| format!("write backup GPT entries: {e}"))?;
    // Backup GPT Header
    out.seek(SeekFrom::Start(backup_header_lba * SECTOR_SIZE))
        .and_then(|_| out.write_all(&backup_hdr))
        .map_err(|e| format!("write backup GPT header: {e}"))?;

    out.flush().map_err(|e| format!("flush GPT disk: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn gpt_headers_have_valid_signatures_and_crcs() {
        let total_bytes = 64 * 1024 * 1024;
        let total_sectors = total_bytes / SECTOR_SIZE;
        let backup_lba = total_sectors - 1;
        let backup_entries_lba = backup_lba - GPT_ARRAY_SECTORS;
        let last_usable = backup_entries_lba - 1;

        let entries = build_partition_array(ESP_START_LBA, last_usable, "NEWOS ESP");
        let entries_crc = crc32(&entries);
        let primary = build_gpt_header(1, backup_lba, ESP_START_LBA, last_usable, 2, entries_crc);
        assert_eq!(&primary[0..8], b"EFI PART");
        let stored_crc = u32::from_le_bytes([primary[16], primary[17], primary[18], primary[19]]);
        let mut check = primary;
        check[16..20].fill(0);
        assert_eq!(crc32(&check[0..92]), stored_crc);
    }
}
