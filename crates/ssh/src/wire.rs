//! Zero-allocation SSHv2 binary wire encoding/decoding helpers (`#![forbid(unsafe_code)]`).

use crate::SshError;

/// Maximum SSH binary packet body size (12 KiB — accommodates ML-KEM-1024 + ML-DSA-87 KEX
/// and userauth frames while keeping EL0 buffers strictly bounded).
pub const MAX_PACKET_BODY: usize = 12_288;

/// Cursor-based zero-copy SSH binary reader (RFC 4251).
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
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SshError::MalformedPacket)?;
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

/// Fixed-buffer zero-allocation SSH binary writer (RFC 4251).
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
