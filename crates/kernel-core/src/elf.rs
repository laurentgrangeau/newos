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
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const R_AARCH64_RELATIVE: u32 = 1027;

const PF_X: u32 = 1 << 0;
const PF_W: u32 = 1 << 1;

/// Maximum `PT_LOAD` segments supported in the bootstrap `init` ELF64 image.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// A single validated `R_AARCH64_RELATIVE` relocation (`*(load_base + offset) = load_base + addend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativeReloc {
    pub offset: u64,
    pub addend: i64,
}

/// Validated `PT_LOAD` segment from a 64-bit EL0 ELF64 executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_offset: usize,
    pub file_size: usize,
    pub flags: PageFlags,
}

/// Parsed 64-bit EL0 ELF64 executable metadata (`no_alloc`, supports `ET_EXEC` and PIE `ET_DYN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedElf64 {
    pub entry: VirtAddr,
    pub is_pie: bool,
    pub load_base: u64,
    segments: [Option<LoadSegment>; MAX_LOAD_SEGMENTS],
    segment_count: usize,
    /// Validated `(file_start, file_end, entry_size)` for streaming `DT_RELA` relocations.
    rela_table: Option<(usize, usize, usize)>,
    reloc_count: usize,
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

    pub const fn reloc_count(&self) -> usize {
        self.reloc_count
    }

    /// Stream every `R_AARCH64_RELATIVE` relocation directly from `bytes` (`no_alloc`, unbounded).
    pub fn for_each_relative_reloc<F>(&self, bytes: &[u8], mut f: F) -> Result<usize, SysError>
    where
        F: FnMut(RelativeReloc) -> Result<(), SysError>,
    {
        let Some((start, end, ent)) = self.rela_table else {
            return Ok(0);
        };
        if ent < 24 {
            return Err(SysError::InvalidArgument);
        }
        let mut applied = 0usize;
        let mut off = start;
        while let Some(next_off) = off.checked_add(ent) {
            if next_off > end {
                break;
            }
            let r_offset = read_u64_le(bytes, off)?;
            let r_info = read_u64_le(bytes, off.checked_add(8).ok_or(SysError::InvalidArgument)?)?;
            let r_addend =
                read_u64_le(bytes, off.checked_add(16).ok_or(SysError::InvalidArgument)?)? as i64;
            if (r_info as u32) == R_AARCH64_RELATIVE {
                f(RelativeReloc {
                    offset: r_offset,
                    addend: r_addend,
                })?;
                applied += 1;
            }
            off = next_off;
        }
        Ok(applied)
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

/// Validate and parse a 64-bit little-endian AArch64 ELF64 binary (`ET_EXEC` or PIE `ET_DYN`)
/// enforcing strict W^X and canonical lower-half EL0 addresses (`< 0x0000_8000_0000_0000`).
pub fn parse_elf64(bytes: &[u8]) -> Result<ParsedElf64, SysError> {
    parse_elf64_with_base(bytes, 0)
}

/// Validate and parse an `ET_EXEC` or PIE `ET_DYN` ELF64 binary with an optional ASLR `pie_base`
/// slide applied to `ET_DYN` virtual addresses and `R_AARCH64_RELATIVE` relocations.
pub fn parse_elf64_with_base(bytes: &[u8], pie_base: u64) -> Result<ParsedElf64, SysError> {
    if bytes.len() < 64 || bytes[0..4] != ELF_MAGIC {
        return Err(SysError::InvalidArgument);
    }
    if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
        return Err(SysError::Unsupported);
    }

    let e_type = read_u16_le(bytes, 16)?;
    let e_machine = read_u16_le(bytes, 18)?;
    if (e_type != ET_EXEC && e_type != ET_DYN) || e_machine != EM_AARCH64 {
        return Err(SysError::Unsupported);
    }
    let is_pie = e_type == ET_DYN;
    let load_base = if is_pie { pie_base } else { 0 };
    if (load_base & 0xFFF) != 0 {
        return Err(SysError::InvalidArgument);
    }

    let entry_raw = read_u64_le(bytes, 24)?
        .checked_add(load_base)
        .ok_or(SysError::InvalidArgument)?;
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
    let mut dyn_range: Option<(usize, usize)> = None;

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
        if p_type == PT_DYNAMIC && is_pie {
            let d_off = usize::try_from(read_u64_le(bytes, off + 8)?)
                .map_err(|_| SysError::InvalidArgument)?;
            let d_sz = usize::try_from(read_u64_le(bytes, off + 32)?)
                .map_err(|_| SysError::InvalidArgument)?;
            let d_end = d_off.checked_add(d_sz).ok_or(SysError::InvalidArgument)?;
            if d_end > bytes.len() {
                return Err(SysError::InvalidArgument);
            }
            dyn_range = Some((d_off, d_sz));
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }
        if segment_count >= MAX_LOAD_SEGMENTS {
            return Err(SysError::OutOfMemory);
        }

        let p_flags = read_u32_le(bytes, off + 4)?;
        let p_offset =
            usize::try_from(read_u64_le(bytes, off + 8)?).map_err(|_| SysError::InvalidArgument)?;
        let p_vaddr = read_u64_le(bytes, off + 16)?
            .checked_add(load_base)
            .ok_or(SysError::InvalidArgument)?;
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

    let mut rela_table = None;
    let mut reloc_count = 0usize;
    if let Some((d_off, d_sz)) = dyn_range {
        let mut rela_vaddr: Option<u64> = None;
        let mut rela_sz: u64 = 0;
        let mut rela_ent: u64 = 24;
        let mut cur = d_off;
        while cur + 16 <= d_off + d_sz {
            let tag = read_u64_le(bytes, cur)?;
            let val = read_u64_le(bytes, cur + 8)?;
            cur += 16;
            match tag {
                DT_NULL => break,
                DT_RELA => rela_vaddr = Some(val),
                DT_RELASZ => rela_sz = val,
                DT_RELAENT => rela_ent = val,
                _ => {}
            }
        }
        if let Some(rv) = rela_vaddr
            && rela_sz > 0
        {
            if rela_ent < 24 {
                return Err(SysError::InvalidArgument);
            }
            let target_va = rv.checked_add(load_base).ok_or(SysError::InvalidArgument)?;
            // Translate `DT_RELA` vaddr into file offset via parsed `PT_LOAD` segments.
            let mut rela_file_off = None;
            for seg in segments[..segment_count].iter().flatten() {
                let seg_file_end = seg.vaddr.saturating_add(seg.file_size as u64);
                if target_va >= seg.vaddr && target_va < seg_file_end {
                    let delta = (target_va - seg.vaddr) as usize;
                    rela_file_off = seg.file_offset.checked_add(delta);
                    break;
                }
            }
            let start = rela_file_off.ok_or(SysError::InvalidArgument)?;
            let total = usize::try_from(rela_sz).map_err(|_| SysError::InvalidArgument)?;
            let ent = usize::try_from(rela_ent).map_err(|_| SysError::InvalidArgument)?;
            let end = start.checked_add(total).ok_or(SysError::InvalidArgument)?;
            if end > bytes.len() {
                return Err(SysError::InvalidArgument);
            }
            let mut off = start;
            while let Some(next_off) = off.checked_add(ent) {
                if next_off > end {
                    break;
                }
                let r_info =
                    read_u64_le(bytes, off.checked_add(8).ok_or(SysError::InvalidArgument)?)?;
                if (r_info as u32) == R_AARCH64_RELATIVE {
                    reloc_count += 1;
                }
                off = next_off;
            }
            rela_table = Some((start, end, ent));
        }
    }

    Ok(ParsedElf64 {
        entry,
        is_pie,
        load_base,
        segments,
        segment_count,
        rela_table,
        reloc_count,
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

    #[test]
    fn parses_pie_et_dyn_with_aslr_slide_and_relative_reloc() {
        let mut img = [0u8; 512];
        let mut hdr = make_valid_header(0x100, 64, 56, 2);
        hdr[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        img[..64].copy_from_slice(&hdr);

        // Segment 0: PT_LOAD (RW, vaddr=0, offset=0, filesz=512, memsz=512)
        write_load_phdr(&mut img, 64, PF_W, 0, 0, 512, 512);

        // Segment 1: PT_DYNAMIC at offset 256, len 64
        let dyn_ph = 64 + 56;
        img[dyn_ph..dyn_ph + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        img[dyn_ph + 8..dyn_ph + 16].copy_from_slice(&256u64.to_le_bytes());
        img[dyn_ph + 32..dyn_ph + 40].copy_from_slice(&64u64.to_le_bytes());

        // Dynamic table at offset 256: DT_RELA=320, DT_RELASZ=24, DT_RELAENT=24, DT_NULL
        img[256..264].copy_from_slice(&DT_RELA.to_le_bytes());
        img[264..272].copy_from_slice(&320u64.to_le_bytes());
        img[272..280].copy_from_slice(&DT_RELASZ.to_le_bytes());
        img[280..288].copy_from_slice(&24u64.to_le_bytes());
        img[288..296].copy_from_slice(&DT_RELAENT.to_le_bytes());
        img[296..304].copy_from_slice(&24u64.to_le_bytes());
        img[304..312].copy_from_slice(&DT_NULL.to_le_bytes());

        // Single R_AARCH64_RELATIVE entry at offset 320: offset=0x180, info=1027, addend=0x200
        img[320..328].copy_from_slice(&0x180u64.to_le_bytes());
        img[328..336].copy_from_slice(&u64::from(R_AARCH64_RELATIVE).to_le_bytes());
        img[336..344].copy_from_slice(&0x200i64.to_le_bytes());

        let parsed = parse_elf64_with_base(&img, 0x0080_0000).unwrap();
        assert!(parsed.is_pie);
        assert_eq!(parsed.load_base, 0x0080_0000);
        assert_eq!(parsed.entry.raw(), 0x0080_0100);
        assert_eq!(parsed.reloc_count(), 1);
        let mut seen = None;
        let applied = parsed
            .for_each_relative_reloc(&img, |r| {
                seen = Some(r);
                Ok(())
            })
            .unwrap();
        assert_eq!(applied, 1);
        assert_eq!(
            seen,
            Some(RelativeReloc {
                offset: 0x180,
                addend: 0x200
            })
        );
    }
}
