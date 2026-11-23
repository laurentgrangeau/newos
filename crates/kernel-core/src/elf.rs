//! Pure, `#![forbid(unsafe_code)]`, `no_alloc` 64-bit ELF64 parser for bootstrapping `init`.
//!
//! Only the single EL0 root task (`init`) is parsed by EL1; all subsequent
//! processes and ELF binaries are loaded by userspace services.

use crate::memory::{PageFlags, VirtAddr};
use newos_abi::SysError;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;

const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;

/// Maximum `PT_LOAD` segments supported in the bootstrap `init` ELF64 image.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// Validated `PT_LOAD` segment from a 64-bit EL0 ELF64 executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: usize,
    pub file_size: usize,
    pub flags: PageFlags,
}

/// Parsed 64-bit EL0 ELF64 executable metadata (`no_alloc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedElf64 {
    pub entry: VirtAddr,
    segments: [Option<LoadSegment>; MAX_LOAD_SEGMENTS],
    segment_count: usize,
}

impl ParsedElf64 {
    pub fn segments(&self) -> impl Iterator<Item = &LoadSegment> {
        self.segments[..self.segment_count]
            .iter()
            .filter_map(Option::as_ref)
    }

    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }
}

#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16, SysError> {
    let end = off.checked_add(2).ok_or(SysError::InvalidArgument)?;
    let slice: [u8; 2] = bytes
        .get(off..end)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u16::from_le_bytes(slice))
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, SysError> {
    let end = off.checked_add(4).ok_or(SysError::InvalidArgument)?;
    let slice: [u8; 4] = bytes
        .get(off..end)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u32::from_le_bytes(slice))
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> Result<u64, SysError> {
    let end = off.checked_add(8).ok_or(SysError::InvalidArgument)?;
    let slice: [u8; 8] = bytes
        .get(off..end)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u64::from_le_bytes(slice))
}

/// Validate and parse a 64-bit little-endian AArch64 ELF64 binary enforcing strict W^X
/// and canonical lower-half EL0 addresses (`< 0x0000_8000_0000_0000`).
pub fn parse_elf64(bytes: &[u8]) -> Result<ParsedElf64, SysError> {
    if bytes.len() < 64 || bytes[0..4] != ELF_MAGIC {
        return Err(SysError::InvalidArgument);
    }
    if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
        return Err(SysError::Unsupported);
    }

    let e_type = read_u16_le(bytes, 16)?;
    let e_machine = read_u16_le(bytes, 18)?;
    if e_type != ET_EXEC || e_machine != EM_AARCH64 {
        return Err(SysError::Unsupported);
    }

    let entry_raw = read_u64_le(bytes, 24)?;
    if entry_raw >= 0x0000_8000_0000_0000 {
        return Err(SysError::InvalidArgument);
    }
    let entry = VirtAddr::new_canonical(entry_raw)?;

    let phoff = usize::try_from(read_u64_le(bytes, 32)?).map_err(|_| SysError::InvalidArgument)?;
    let phentsize = read_u16_le(bytes, 54)? as usize;
    let phnum = read_u16_le(bytes, 56)? as usize;
    if phentsize < 56 {
        return Err(SysError::InvalidArgument);
    }

    let mut segments = [None; MAX_LOAD_SEGMENTS];
    let mut segment_count = 0usize;

    for i in 0..phnum {
        let off = phoff
            .checked_add(i.checked_mul(phentsize).ok_or(SysError::InvalidArgument)?)
            .ok_or(SysError::InvalidArgument)?;
        let ph_end = off
            .checked_add(phentsize)
            .ok_or(SysError::InvalidArgument)?;
        if ph_end > bytes.len() {
            return Err(SysError::InvalidArgument);
        }
        let p_type = read_u32_le(bytes, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        if segment_count >= MAX_LOAD_SEGMENTS {
            return Err(SysError::OutOfMemory);
        }

        let p_flags = read_u32_le(bytes, off + 4)?;
        let p_offset =
            usize::try_from(read_u64_le(bytes, off + 8)?).map_err(|_| SysError::InvalidArgument)?;
        let p_vaddr = read_u64_le(bytes, off + 16)?;
        let p_filesz = usize::try_from(read_u64_le(bytes, off + 32)?)
            .map_err(|_| SysError::InvalidArgument)?;
        let p_memsz = read_u64_le(bytes, off + 40)?;

        if p_memsz < p_filesz as u64 {
            return Err(SysError::InvalidArgument);
        }
        let end_file = p_offset
            .checked_add(p_filesz)
            .ok_or(SysError::InvalidArgument)?;
        if end_file > bytes.len() {
            return Err(SysError::InvalidArgument);
        }
        let end_vaddr = p_vaddr
            .checked_add(p_memsz)
            .ok_or(SysError::InvalidArgument)?;
        if end_vaddr >= 0x0000_8000_0000_0000 {
            return Err(SysError::InvalidArgument);
        }

        // Strict W^X enforced for EL0 segments
        let writable = (p_flags & PF_W) != 0;
        let executable = (p_flags & PF_X) != 0;
        let flags = PageFlags::new_wx(writable, executable, true, false)?;

        segments[segment_count] = Some(LoadSegment {
            vaddr: p_vaddr,
            mem_size: p_memsz,
            file_offset: p_offset,
            file_size: p_filesz,
            flags,
        });
        segment_count += 1;
    }

    if segment_count == 0 {
        return Err(SysError::InvalidArgument);
    }

    Ok(ParsedElf64 {
        entry,
        segments,
        segment_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_magic_and_32bit_elf() {
        assert_eq!(parse_elf64(&[]), Err(SysError::InvalidArgument));
        assert_eq!(parse_elf64(&[0u8; 64]), Err(SysError::InvalidArgument));

        let mut elf32 = [0u8; 64];
        elf32[0..4].copy_from_slice(&ELF_MAGIC);
        elf32[4] = 1; // ELFCLASS32 — must be rejected!
        elf32[5] = ELFDATA2LSB;
        assert_eq!(parse_elf64(&elf32), Err(SysError::Unsupported));
    }

    fn make_valid_header(entry: u64, phoff: u64, phentsize: u16, phnum: u16) -> [u8; 64] {
        let mut hdr = [0u8; 64];
        hdr[0..4].copy_from_slice(&ELF_MAGIC);
        hdr[4] = ELFCLASS64;
        hdr[5] = ELFDATA2LSB;
        hdr[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        hdr[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        hdr[24..32].copy_from_slice(&entry.to_le_bytes());
        hdr[32..40].copy_from_slice(&phoff.to_le_bytes());
        hdr[54..56].copy_from_slice(&phentsize.to_le_bytes());
        hdr[56..58].copy_from_slice(&phnum.to_le_bytes());
        hdr
    }

    fn write_load_phdr(
        buf: &mut [u8],
        off: usize,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    ) {
        buf[off..off + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&p_flags.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&p_offset.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&p_vaddr.to_le_bytes());
        buf[off + 32..off + 40].copy_from_slice(&p_filesz.to_le_bytes());
        buf[off + 40..off + 48].copy_from_slice(&p_memsz.to_le_bytes());
    }

    #[test]
    fn rejects_overflowing_phoff_and_phentsize() {
        // phoff near u64::MAX must not panic on checked_add.
        let hdr = make_valid_header(0x40_0000, u64::MAX - 1, 56, 1);
        assert_eq!(parse_elf64(&hdr), Err(SysError::InvalidArgument));

        // phentsize < 56 rejected.
        let hdr_small = make_valid_header(0x40_0000, 64, 55, 1);
        assert_eq!(parse_elf64(&hdr_small), Err(SysError::InvalidArgument));

        // phentsize large enough to overflow phoff + i * phentsize.
        let hdr_mul = make_valid_header(0x40_0000, 64, u16::MAX, u16::MAX);
        assert_eq!(parse_elf64(&hdr_mul), Err(SysError::InvalidArgument));
    }

    #[test]
    fn rejects_wx_non_canonical_memsz_and_too_many_segments() {
        // Non-canonical / upper-half entry point.
        let hdr_hi = make_valid_header(0x0000_8000_0000_0000, 64, 56, 1);
        assert_eq!(parse_elf64(&hdr_hi), Err(SysError::InvalidArgument));

        // Valid 1-segment RX ELF passes.
        let mut img = [0u8; 64 + 56 * 9];
        img[..64].copy_from_slice(&make_valid_header(0x40_0000, 64, 56, 1));
        write_load_phdr(&mut img, 64, PF_X, 0, 0x40_0000, 64, 64);
        let parsed = parse_elf64(&img).unwrap();
        assert_eq!(parsed.segment_count(), 1);
        assert_eq!(parsed.entry.raw(), 0x40_0000);

        // W^X violation (PF_W | PF_X) rejected.
        write_load_phdr(&mut img, 64, PF_W | PF_X, 0, 0x40_0000, 64, 64);
        assert_eq!(parse_elf64(&img), Err(SysError::InvalidArgument));

        // p_memsz < p_filesz rejected.
        write_load_phdr(&mut img, 64, PF_W, 0, 0x40_0000, 64, 32);
        assert_eq!(parse_elf64(&img), Err(SysError::InvalidArgument));

        // More than MAX_LOAD_SEGMENTS (9) rejected with OutOfMemory.
        img[..64].copy_from_slice(&make_valid_header(0x40_0000, 64, 56, 9));
        for i in 0..9 {
            write_load_phdr(
                &mut img,
                64 + i * 56,
                PF_W,
                0,
                0x40_0000 + (i as u64) * 0x1000,
                16,
                16,
            );
        }
        assert_eq!(parse_elf64(&img), Err(SysError::OutOfMemory));

        // Zero PT_LOAD segments rejected.
        img[..64].copy_from_slice(&make_valid_header(0x40_0000, 64, 56, 0));
        assert_eq!(parse_elf64(&img), Err(SysError::InvalidArgument));
    }
}
