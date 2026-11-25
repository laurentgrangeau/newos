//! SSHv2 binary wire encoding/decoding helpers.
//!
//! ```
//! use newos_ssh_proto::wire::{WireReader, WireWriter};
//!
//! let mut buf = [0u8; 32];
//! let mut w = WireWriter::new(&mut buf);
//! w.write_u32(42).unwrap();
//! w.write_str("ssh-mldsa87").unwrap();
//! let len = w.len();
//!
//! let mut r = WireReader::new(&buf[..len]);
//! assert_eq!(r.read_u32(), Ok(42));
//! assert_eq!(r.read_str(), Ok("ssh-mldsa87"));
//! ```

use crate::SshError;

/// Maximum SSH binary packet body size (12 KiB — accommodates ML-KEM-1024 + ML-DSA-87 KEX
/// and userauth frames while keeping EL0 buffers strictly bounded).
pub const MAX_PACKET_BODY: usize = 12_288;

/// Cursor-based SSH binary reader (RFC 4251).
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn read_u8(&mut self) -> Result<u8, SshError> {
        if self.pos >= self.buf.len() {
            return Err(SshError::MalformedPacket);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_bool(&mut self) -> Result<bool, SshError> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_u32(&mut self) -> Result<u32, SshError> {
        let s = self.read_exact(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_exact(&mut self, len: usize) -> Result<&'a [u8], SshError> {
        let end = self.pos.checked_add(len).ok_or(SshError::MalformedPacket)?;
        if end > self.buf.len() {
            return Err(SshError::MalformedPacket);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_string(&mut self) -> Result<&'a [u8], SshError> {
        let len = self.read_u32()? as usize;
        self.read_exact(len)
    }

    pub fn read_str(&mut self) -> Result<&'a str, SshError> {
        let bytes = self.read_string()?;
        core::str::from_utf8(bytes).map_err(|_| SshError::MalformedPacket)
    }
}

/// Fixed-buffer SSH binary writer (RFC 4251).
pub struct WireWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> WireWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.pos
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), SshError> {
        if self.pos >= self.buf.len() {
            return Err(SshError::PacketTooLarge);
        }
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }

    pub fn write_bool(&mut self, v: bool) -> Result<(), SshError> {
        self.write_u8(u8::from(v))
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), SshError> {
        self.write_raw(&v.to_be_bytes())
    }

    pub fn write_raw(&mut self, bytes: &[u8]) -> Result<(), SshError> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(SshError::PacketTooLarge)?;
        if end > self.buf.len() {
            return Err(SshError::PacketTooLarge);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub fn write_string(&mut self, bytes: &[u8]) -> Result<(), SshError> {
        self.write_u32(bytes.len() as u32)?;
        self.write_raw(bytes)
    }

    pub fn write_str(&mut self, s: &str) -> Result<(), SshError> {
        self.write_string(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_primitives_and_strings() {
        let mut buf = [0u8; 64];
        let mut w = WireWriter::new(&mut buf);
        assert!(w.is_empty());
        w.write_u8(0xAB).unwrap();
        w.write_bool(true).unwrap();
        w.write_bool(false).unwrap();
        w.write_u32(0x1234_5678).unwrap();
        w.write_string(b"").unwrap();
        w.write_str("mlkem1024-sha3-512").unwrap();
        w.write_raw(&[1, 2, 3]).unwrap();
        let written = w.len();
        assert!(!w.is_empty());

        let mut r = WireReader::new(&buf[..written]);
        assert_eq!(r.remaining(), written);
        assert_eq!(r.read_u8(), Ok(0xAB));
        assert_eq!(r.read_bool(), Ok(true));
        assert_eq!(r.read_bool(), Ok(false));
        assert_eq!(r.read_u32(), Ok(0x1234_5678));
        assert_eq!(r.read_string(), Ok(&[][..]));
        assert_eq!(r.read_str(), Ok("mlkem1024-sha3-512"));
        assert_eq!(r.read_exact(3), Ok(&[1, 2, 3][..]));
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.read_u8(), Err(SshError::MalformedPacket));
    }

    #[test]
    fn wire_reader_rejects_truncated_and_overflow_lengths() {
        // Empty buffer rejects every read
        let mut empty = WireReader::new(&[]);
        assert_eq!(empty.read_u8(), Err(SshError::MalformedPacket));
        assert_eq!(empty.read_bool(), Err(SshError::MalformedPacket));
        assert_eq!(empty.read_u32(), Err(SshError::MalformedPacket));
        assert_eq!(empty.read_string(), Err(SshError::MalformedPacket));
        assert_eq!(empty.read_str(), Err(SshError::MalformedPacket));
        assert_eq!(empty.read_exact(0), Ok(&[][..]));
        assert_eq!(empty.read_exact(1), Err(SshError::MalformedPacket));

        // Truncated u32 (only 3 bytes)
        let mut short_u32 = WireReader::new(&[0, 0, 1]);
        assert_eq!(short_u32.read_u32(), Err(SshError::MalformedPacket));

        // Length prefix larger than remaining buffer
        let mut overlong = WireReader::new(&[0, 0, 0, 10, b'a', b'b']);
        assert_eq!(overlong.read_string(), Err(SshError::MalformedPacket));

        // u32::MAX length prefix (must not wrap/panic)
        let mut max_len = WireReader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(max_len.read_string(), Err(SshError::MalformedPacket));

        // read_exact(usize::MAX) after advancing 1 byte (checked_add overflow guard)
        let mut overflow = WireReader::new(&[0x01, 0x02]);
        assert_eq!(overflow.read_u8(), Ok(0x01));
        assert_eq!(
            overflow.read_exact(usize::MAX),
            Err(SshError::MalformedPacket)
        );
    }

    #[test]
    fn wire_reader_rejects_invalid_utf8_and_non_zero_bool_is_true() {
        // Non-zero byte decodes as true per RFC 4251 Section 5
        let mut r = WireReader::new(&[0x42, 0x00]);
        assert_eq!(r.read_bool(), Ok(true));
        assert_eq!(r.read_bool(), Ok(false));

        // Invalid UTF-8 string
        let bad_utf8 = [0, 0, 0, 2, 0xFF, 0xFE];
        let mut r2 = WireReader::new(&bad_utf8);
        assert_eq!(r2.read_str(), Err(SshError::MalformedPacket));
    }

    #[test]
    fn wire_writer_rejects_buffer_overflow_cleanly() {
        let mut buf = [0u8; 4];
        let mut w = WireWriter::new(&mut buf);
        assert_eq!(w.write_raw(&[1, 2, 3, 4, 5]), Err(SshError::PacketTooLarge));
        assert_eq!(w.len(), 0);

        // String whose length prefix fits (4 bytes) but payload does not
        assert_eq!(w.write_string(b"a"), Err(SshError::PacketTooLarge));

        // Exact capacity fill succeeds, then next write fails
        let mut buf2 = [0u8; 4];
        let mut w2 = WireWriter::new(&mut buf2);
        assert_eq!(w2.write_u32(0xDEAD_BEEF), Ok(()));
        assert_eq!(w2.write_u8(1), Err(SshError::PacketTooLarge));
        assert_eq!(w2.len(), 4);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(20)]
    fn wire_reader_never_panics_on_arbitrary_16_bytes() {
        let data: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= data.len());
        let mut r = WireReader::new(&data[..len]);
        let _ = r.read_u8();
        let _ = r.read_u32();
        let _ = r.read_string();
    }
}
