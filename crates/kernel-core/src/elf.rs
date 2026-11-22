//! Pure, `#![forbid(unsafe_code)]`, `no_alloc` 64-bit ELF64 parser for bootstrapping `init`.
//!
//! Only the single Ring-3 root task (`init`) is parsed by Ring 0; all subsequent
//! processes and ELF binaries are loaded by userspace services.

use crate::memory::{PageFlags, VirtAddr};
use newos_abi::SysError;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;

const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;

/// Maximum `PT_LOAD` segments supported in the bootstrap `init` ELF64 image.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// Validated `PT_LOAD` segment from a 64-bit Ring-3 ELF64 executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: usize,
    pub file_size: usize,
    pub flags: PageFlags,
}

/// Parsed 64-bit Ring-3 ELF64 executable metadata (`no_alloc`).
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
    let slice: [u8; 2] = bytes
        .get(off..off + 2)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u16::from_le_bytes(slice))
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, SysError> {
    let slice: [u8; 4] = bytes
        .get(off..off + 4)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u32::from_le_bytes(slice))
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> Result<u64, SysError> {
    let slice: [u8; 8] = bytes
        .get(off..off + 8)
        .ok_or(SysError::InvalidArgument)?
        .try_into()
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(u64::from_le_bytes(slice))
}

/// Validate and parse a 64-bit little-endian x86_64 ELF64 binary enforcing strict W^X
/// and canonical lower-half Ring-3 addresses (`< 0x0000_8000_0000_0000`).
pub fn parse_elf64(bytes: &[u8]) -> Result<ParsedElf64, SysError> {
    if bytes.len() < 64 || bytes[0..4] != ELF_MAGIC {
        return Err(SysError::InvalidArgument);
    }
    if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
        return Err(SysError::Unsupported);
    }

    let e_type = read_u16_le(bytes, 16)?;
    let e_machine = read_u16_le(bytes, 18)?;
    if e_type != ET_EXEC || e_machine != EM_X86_64 {
        return Err(SysError::Unsupported);
    }

    let entry_raw = read_u64_le(bytes, 24)?;
    if entry_raw >= 0x0000_8000_0000_0000 {
        return Err(SysError::InvalidArgument);
    }
    let entry = VirtAddr::new_canonical(entry_raw)?;

    let phoff = read_u64_le(bytes, 32)? as usize;
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
        let p_type = read_u32_le(bytes, off)?;
        if p_type != PT_LOAD {
            continue;
        }
        if segment_count >= MAX_LOAD_SEGMENTS {
            return Err(SysError::OutOfMemory);
        }

        let p_flags = read_u32_le(bytes, off + 4)?;
        let p_offset = read_u64_le(bytes, off + 8)? as usize;
        let p_vaddr = read_u64_le(bytes, off + 16)?;
        let p_filesz = read_u64_le(bytes, off + 32)? as usize;
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

        // Strict W^X enforced for Ring-3 segments
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
        assert_eq!(parse_elf64(&[0u8; 64]), Err(SysError::InvalidArgument));

        let mut elf32 = [0u8; 64];
        elf32[0..4].copy_from_slice(&ELF_MAGIC);
        elf32[4] = 1; // ELFCLASS32 — must be rejected!
        elf32[5] = ELFDATA2LSB;
        assert_eq!(parse_elf64(&elf32), Err(SysError::Unsupported));
    }
}
