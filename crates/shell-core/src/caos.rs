//! Capability-Scoped Content-Addressed Object Store (CAOS).
//!
//! EL0 content-addressed storage:
//! - Every blob is **immutable** and addressed by its 64-bit content hash (`ObjHash`),
//!   providing automatic deduplication, lock-free reads, and zero in-place corruption.
//! - Mutable state exists only as explicit named **Refs** (`@name -> ObjHash`) with
//!   atomic rollback (`prev_hash`) and irreversible capability attenuation (`seal` -> read-only).
//! - No global `/` namespace, no `cd`, no `../../` path traversal, no ambient authority.

use core::num::{NonZeroU8, NonZeroU64};
use newos_abi::Rights;

pub const MAX_OBJECTS: usize = 24;
pub const MAX_REFS: usize = 16;
pub const MAX_BLOB_SIZE: usize = 128;
pub const MAX_REF_NAME: usize = 24;

const _: () = {
    assert!(MAX_OBJECTS <= u8::MAX as usize);
    assert!(MAX_OBJECTS <= 32);
    assert!(MAX_REFS <= u8::MAX as usize);
    assert!(MAX_BLOB_SIZE <= u8::MAX as usize);
    assert!(MAX_REF_NAME <= u8::MAX as usize);
};

/// Deterministic 64-bit cryptographic content address (FIPS 202 SHA3-512 prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ObjHash(pub u64);

impl ObjHash {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn hash_bytes(bytes: &[u8]) -> Self {
        #[cfg(feature = "sha3")]
        let mut h = newos_abi::sha3::digest_prefix_u64(bytes);
        #[cfg(not(feature = "sha3"))]
        let mut h = {
            // Non-cryptographic FNV-1a 64-bit content hash for zero-crypto build profiles.
            let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
            let mut i = 0;
            while i < bytes.len() {
                acc ^= bytes[i] as u64;
                acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
                i += 1;
            }
            acc
        };
        if h == 0 {
            h = 1;
        }
        Self(h)
    }

    #[must_use]
    pub fn parse_hex(s: &str) -> Option<Self> {
        let stripped = s
            .strip_prefix("obj:")
            .or_else(|| s.strip_prefix("0x"))
            .unwrap_or(s);
        u64::from_str_radix(stripped, 16).ok().map(Self)
    }
}

impl core::fmt::Display for ObjHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "obj:{:016x}", self.0)
    }
}

impl From<u64> for ObjHash {
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<ObjHash> for u64 {
    fn from(hash: ObjHash) -> Self {
        hash.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreError {
    NotFound,
    NoSpace,
    TooLarge,
    InvalidName,
    ReadOnly,
    NoPreviousVersion,
    CorruptSnapshot,
    HashCollision,
}

impl StoreError {
    /// Return the canonical short error name for shell diagnostics and `Display`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NotFound",
            Self::NoSpace => "NoSpace",
            Self::TooLarge => "TooLarge",
            Self::InvalidName => "InvalidName",
            Self::ReadOnly => "ReadOnly",
            Self::NoPreviousVersion => "NoPreviousVersion",
            Self::CorruptSnapshot => "CorruptSnapshot",
            Self::HashCollision => "HashCollision",
        }
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for StoreError {}

/// Public alias for `StoreError` per `newos-shell-core` interface contract.
pub type CaosError = StoreError;

const fn checked_len_u8(len: usize) -> u8 {
    assert!(len <= u8::MAX as usize);
    len.to_le_bytes()[0]
}

const MOTD_BYTES: &[u8] = b"NewOS microkernel";
const GUIDE_BYTES: &[u8] =
    b"Try: `put \"hello\" | save @note`, `objects | where size > 20`, `domains | where id == 1`";
const MOTD_HASH: ObjHash = ObjHash::hash_bytes(MOTD_BYTES);
const GUIDE_HASH: ObjHash = ObjHash::hash_bytes(GUIDE_BYTES);

const fn pad_blob(bytes: &[u8]) -> [u8; MAX_BLOB_SIZE] {
    let mut data = [0u8; MAX_BLOB_SIZE];
    let mut i = 0;
    while i < bytes.len() {
        data[i] = bytes[i];
        i += 1;
    }
    data
}

#[derive(Clone, Copy)]
struct RefSlot {
    target: ObjHash,
    prev: Option<NonZeroU64>,
    name: [u8; MAX_REF_NAME],
    name_len: NonZeroU8,
    rights: Rights,
}

const _: () =
    assert!(core::mem::size_of::<RefSlot>() == 48 && core::mem::size_of::<Option<RefSlot>>() == 48);

impl RefSlot {
    const fn sealed_static(raw_name: &[u8], target: ObjHash) -> Self {
        assert!(!raw_name.is_empty() && raw_name.len() <= MAX_REF_NAME);
        let mut name = [0u8; MAX_REF_NAME];
        let mut i = 0;
        while i < raw_name.len() {
            name[i] = raw_name[i];
            i += 1;
        }
        let Some(name_len) = NonZeroU8::new(checked_len_u8(raw_name.len())) else {
            unreachable!();
        };
        Self {
            target,
            prev: None,
            name,
            name_len,
            rights: Rights::READ,
        }
    }

    #[inline]
    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len.get() as usize]
    }

    #[inline]
    fn prev_hash(&self) -> Option<ObjHash> {
        self.prev.map(|nz| ObjHash(nz.get()))
    }
}

const BOOT_MOTD_DATA: [u8; MAX_BLOB_SIZE] = pad_blob(MOTD_BYTES);
const BOOT_GUIDE_DATA: [u8; MAX_BLOB_SIZE] = pad_blob(GUIDE_BYTES);
const BOOT_MOTD_REF: RefSlot = RefSlot::sealed_static(b"motd", MOTD_HASH);
const BOOT_GUIDE_REF: RefSlot = RefSlot::sealed_static(b"guide", GUIDE_HASH);

/// Validated CAOS reference name (1..=`MAX_REF_NAME` bytes, no control/whitespace/`@`).
#[derive(Clone, Copy)]
struct RefName<'a> {
    name: &'a str,
    len_nz: NonZeroU8,
}

impl<'a> RefName<'a> {
    fn parse(raw: &'a str) -> Option<Self> {
        Self::parse_strict(raw.strip_prefix('@').unwrap_or(raw))
    }

    fn parse_strict(name: &'a str) -> Option<Self> {
        if name.is_empty()
            || name.len() > MAX_REF_NAME
            || name
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || c == '@')
        {
            return None;
        }
        let len_nz = u8::try_from(name.len()).ok().and_then(NonZeroU8::new)?;
        Some(Self { name, len_nz })
    }

    #[inline]
    const fn as_bytes(self) -> &'a [u8] {
        self.name.as_bytes()
    }

    #[inline]
    const fn len_non_zero(self) -> NonZeroU8 {
        self.len_nz
    }
}

/// Snapshot metadata for an immutable object (emitted directly as a typed shell `Record`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    pub hash: ObjHash,
    pub size: usize,
}

/// Snapshot metadata for a capability-gated named Ref (emitted as a typed shell `Record`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefMeta {
    pub target: ObjHash,
    pub prev_hash: Option<NonZeroU64>,
    pub name: [u8; MAX_REF_NAME],
    pub name_len: u8,
    pub writable: bool,
}

const _: () = assert!(core::mem::size_of::<RefMeta>() == 48);

impl RefMeta {
    #[must_use]
    #[inline]
    pub fn name_str(&self) -> &str {
        let len = usize::from(self.name_len).min(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("?")
    }

    #[must_use]
    #[inline]
    pub const fn prev(&self) -> Option<ObjHash> {
        match self.prev_hash {
            Some(nz) => Some(ObjHash(nz.get())),
            None => None,
        }
    }
}

/// EL0 Content-Addressed Object Store.
///
/// Structure-of-Arrays (`SoA`) layout concentrates all live `ObjHash` entries into 3 cache lines
/// (`hashes: [ObjHash; 24]`) and uses `Option`-backed lazy initialization to avoid zeroing
/// unused 128-byte blob payloads in `ObjectStore::new()`.
pub struct ObjectStore {
    hashes: [ObjHash; MAX_OBJECTS],
    refs: [Option<RefSlot>; MAX_REFS],
    used_mask: u32,
    object_count: u8,
    ref_count: u8,
    sizes: [u8; MAX_OBJECTS],
    data: [Option<[u8; MAX_BLOB_SIZE]>; MAX_OBJECTS],
}

impl core::fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectStore")
            .field("object_count", &self.object_count)
            .field("ref_count", &self.ref_count)
            .finish_non_exhaustive()
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore {
    #[must_use]
    pub const fn new() -> Self {
        let mut hashes = [ObjHash::ZERO; MAX_OBJECTS];
        hashes[0] = MOTD_HASH;
        hashes[1] = GUIDE_HASH;

        let mut sizes = [0u8; MAX_OBJECTS];
        sizes[0] = checked_len_u8(MOTD_BYTES.len());
        sizes[1] = checked_len_u8(GUIDE_BYTES.len());

        let mut data = [None; MAX_OBJECTS];
        data[0] = Some(BOOT_MOTD_DATA);
        data[1] = Some(BOOT_GUIDE_DATA);

        let mut refs = [None; MAX_REFS];
        refs[0] = Some(BOOT_MOTD_REF); // `@motd` is sealed read-only at boot!
        refs[1] = Some(BOOT_GUIDE_REF);

        Self {
            hashes,
            refs,
            used_mask: 0b11,
            object_count: 2,
            ref_count: 2,
            sizes,
            data,
        }
    }

    #[inline]
    fn find_blob_idx(&self, hash: ObjHash) -> Option<usize> {
        let mut mask = self.used_mask;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if self.hashes[idx] == hash {
                return Some(idx);
            }
        }
        None
    }

    /// Store an immutable byte slice; automatically deduplicates identical content.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TooLarge`] if `bytes.len() > MAX_BLOB_SIZE`,
    /// [`StoreError::HashCollision`] if an existing blob shares the hash with different content,
    /// or [`StoreError::NoSpace`] if the store is full.
    pub fn put(&mut self, bytes: &[u8]) -> Result<ObjHash, StoreError> {
        if bytes.len() > MAX_BLOB_SIZE {
            return Err(StoreError::TooLarge);
        }
        let hash = ObjHash::hash_bytes(bytes);

        // Content deduplication & collision rejection: L1-dense scan over `hashes`.
        if let Some(idx) = self.find_blob_idx(hash) {
            if let Some(buf) = &self.data[idx]
                && &buf[..self.sizes[idx] as usize] == bytes
            {
                return Ok(hash);
            }
            return Err(StoreError::HashCollision);
        }

        if self.object_count as usize >= MAX_OBJECTS {
            return Err(StoreError::NoSpace);
        }
        let idx = (!self.used_mask).trailing_zeros() as usize;
        if idx >= MAX_OBJECTS {
            return Err(StoreError::NoSpace);
        }
        let size_u8 = u8::try_from(bytes.len()).map_err(|_| StoreError::TooLarge)?;
        self.hashes[idx] = hash;
        self.sizes[idx] = size_u8;
        let buf = self.data[idx].insert([0u8; MAX_BLOB_SIZE]);
        buf[..bytes.len()].copy_from_slice(bytes);
        self.used_mask |= 1u32 << idx;
        self.object_count += 1;
        Ok(hash)
    }

    /// Lock-free immutable lookup by `ObjHash`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if no object with `hash` exists in the store.
    pub fn get_by_hash(&self, hash: ObjHash) -> Result<&[u8], StoreError> {
        let idx = self.find_blob_idx(hash).ok_or(StoreError::NotFound)?;
        let buf = self.data[idx].as_ref().ok_or(StoreError::NotFound)?;
        Ok(&buf[..self.sizes[idx] as usize])
    }

    /// Resolve `@ref_name` or `obj:<hex>` to `(ObjHash, &[u8])`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if the reference or hash is unknown, or
    /// [`StoreError::ReadOnly`] if the reference lacks `READ` rights.
    pub fn get_any(&self, spec: &str) -> Result<(ObjHash, &[u8]), StoreError> {
        if let Some(name) = spec.strip_prefix('@') {
            let name_bytes = name.as_bytes();
            for r in self.refs[..self.ref_count as usize].iter().flatten() {
                if r.name_bytes() == name_bytes {
                    if !r.rights.contains(Rights::READ) {
                        return Err(StoreError::ReadOnly);
                    }
                    return Ok((r.target, self.get_by_hash(r.target)?));
                }
            }
            Err(StoreError::NotFound)
        } else {
            let hash = ObjHash::parse_hex(spec).ok_or(StoreError::NotFound)?;
            Ok((hash, self.get_by_hash(hash)?))
        }
    }

    /// Atomically bind or update `@name -> target` (recording `prev` for instant rollback).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidName`] for malformed names, [`StoreError::NotFound`] if
    /// `target` does not exist, [`StoreError::ReadOnly`] if an existing ref is sealed, or
    /// [`StoreError::NoSpace`] if the ref table is full.
    pub fn set_ref(&mut self, raw_name: &str, target: ObjHash) -> Result<(), StoreError> {
        let ref_name = RefName::parse(raw_name).ok_or(StoreError::InvalidName)?;
        let _ = self.get_by_hash(target)?;

        // Update existing ref if writable (single-pass bounded scan over live packed refs)
        let name_bytes = ref_name.as_bytes();
        let ref_count = self.ref_count as usize;
        for r in self.refs[..ref_count].iter_mut().flatten() {
            if r.name_bytes() == name_bytes {
                if !r.rights.contains(Rights::WRITE) {
                    return Err(StoreError::ReadOnly);
                }
                if r.target != target {
                    r.prev = NonZeroU64::new(r.target.0);
                    r.target = target;
                }
                return Ok(());
            }
        }

        // Create new ref with READ | WRITE in O(1)
        if ref_count >= MAX_REFS {
            return Err(StoreError::NoSpace);
        }
        let mut slot_name = [0u8; MAX_REF_NAME];
        slot_name[..name_bytes.len()].copy_from_slice(name_bytes);
        self.refs[ref_count] = Some(RefSlot {
            target,
            prev: None,
            name: slot_name,
            name_len: ref_name.len_non_zero(),
            rights: Rights::READ.union(Rights::WRITE),
        });
        self.ref_count += 1;
        Ok(())
    }

    /// Irreversibly attenuate a ref's rights to `READ`-only (cannot be escalated back!).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if no ref with `raw_name` exists.
    pub fn seal_ref(&mut self, raw_name: &str) -> Result<(), StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        let name_bytes = name.as_bytes();
        for r in self.refs[..self.ref_count as usize].iter_mut().flatten() {
            if r.name_bytes() == name_bytes {
                r.rights = r.rights.attenuate(Rights::READ);
                return Ok(());
            }
        }
        Err(StoreError::NotFound)
    }

    /// Atomically roll back a writable ref to its previous immutable `ObjHash`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if the ref does not exist, [`StoreError::ReadOnly`] if
    /// sealed, or [`StoreError::NoPreviousVersion`] if no previous target was recorded.
    pub fn rollback_ref(&mut self, raw_name: &str) -> Result<ObjHash, StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        let name_bytes = name.as_bytes();
        for r in self.refs[..self.ref_count as usize].iter_mut().flatten() {
            if r.name_bytes() == name_bytes {
                if !r.rights.contains(Rights::WRITE) {
                    return Err(StoreError::ReadOnly);
                }
                let prev = ObjHash(r.prev.take().ok_or(StoreError::NoPreviousVersion)?.get());
                r.target = prev;
                return Ok(prev);
            }
        }
        Err(StoreError::NotFound)
    }

    #[must_use]
    #[inline]
    pub const fn object_count(&self) -> usize {
        self.object_count as usize
    }

    #[inline]
    pub fn for_each_object(&self, mut f: impl FnMut(ObjectMeta)) {
        let mut mask = self.used_mask & ((1u32 << MAX_OBJECTS) - 1);
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if idx < MAX_OBJECTS {
                f(ObjectMeta {
                    hash: self.hashes[idx],
                    size: self.sizes[idx] as usize,
                });
            }
        }
    }

    #[inline]
    pub fn for_each_ref(&self, mut f: impl FnMut(RefMeta)) {
        for r in self.refs[..self.ref_count as usize].iter().flatten() {
            f(RefMeta {
                target: r.target,
                prev_hash: r.prev,
                name: r.name,
                name_len: r.name_len.get(),
                writable: r.rights.contains(Rights::WRITE),
            });
        }
    }

    pub const fn collect_objects(&self, out: &mut [Option<ObjectMeta>]) -> usize {
        let mut n = 0usize;
        let mut mask = self.used_mask;
        while mask != 0 && n < out.len() {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            out[n] = Some(ObjectMeta {
                hash: self.hashes[idx],
                size: self.sizes[idx] as usize,
            });
            n += 1;
        }
        n
    }

    pub fn collect_refs(&self, out: &mut [Option<RefMeta>]) -> usize {
        let n = (self.ref_count as usize).min(out.len());
        let mut count = 0usize;
        for r in self.refs[..n].iter().flatten() {
            out[count] = Some(RefMeta {
                target: r.target,
                prev_hash: r.prev,
                name: r.name,
                name_len: r.name_len.get(),
                writable: r.rights.contains(Rights::WRITE),
            });
            count += 1;
        }
        count
    }

    /// Mark-and-sweep garbage collection: reclaim all immutable blobs not reachable
    /// from any active Ref's `target` or `prev` rollback pointer.
    ///
    /// Returns the number of reclaimed object slots.
    pub fn gc(&mut self) -> usize {
        let mut reclaimed = 0u8;
        let mut mask = self.used_mask;
        let ref_count = self.ref_count as usize;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let hash = self.hashes[idx];
            let reachable = self.refs[..ref_count]
                .iter()
                .flatten()
                .any(|r| r.target == hash || r.prev_hash() == Some(hash));
            if !reachable {
                self.used_mask &= !(1u32 << idx);
                self.hashes[idx] = ObjHash::ZERO;
                self.sizes[idx] = 0;
                self.data[idx] = None;
                reclaimed += 1;
            }
        }
        self.object_count -= reclaimed;
        usize::from(reclaimed)
    }

    /// Serialize the entire CAOS store into a crash-safe, checksummed binary snapshot
    /// suitable for writing to a block device (`VirtIO-blk` / `NVMe` / SD).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoSpace`] if `out` is too small, or
    /// [`StoreError::CorruptSnapshot`] if internal slot metadata is inconsistent.
    pub fn encode_snapshot(&self, out: &mut [u8]) -> Result<usize, StoreError> {
        let mut pos = 0usize;
        let mut push = |bytes: &[u8]| -> Result<(), StoreError> {
            let end = pos.checked_add(bytes.len()).ok_or(StoreError::NoSpace)?;
            if end > out.len() {
                return Err(StoreError::NoSpace);
            }
            out[pos..end].copy_from_slice(bytes);
            pos = end;
            Ok(())
        };

        // Header: magic "CAOS" (4B) + version u8 (1B) + object_count u8 (1B) + ref_count u8 (1B) + pad (1B)
        push(b"CAOS")?;
        push(&[1u8, self.object_count, self.ref_count, 0u8])?;

        let mut mask = self.used_mask;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let size = self.sizes[idx] as usize;
            let data = self.data[idx].as_ref().ok_or(StoreError::CorruptSnapshot)?;
            push(&self.hashes[idx].0.to_le_bytes())?;
            push(&u16::from(self.sizes[idx]).to_le_bytes())?;
            push(&data[..size])?;
        }

        for r in self.refs[..self.ref_count as usize].iter().flatten() {
            push(&[r.name_len.get(), r.rights.bits()])?;
            push(r.name_bytes())?;
            push(&r.target.0.to_le_bytes())?;
            push(&r.prev.map_or(0u64, NonZeroU64::get).to_le_bytes())?;
        }

        drop(push);
        let checksum = ObjHash::hash_bytes(&out[..pos]);
        let end = pos.checked_add(8).ok_or(StoreError::NoSpace)?;
        if end > out.len() {
            return Err(StoreError::NoSpace);
        }
        out[pos..end].copy_from_slice(&checksum.0.to_le_bytes());
        Ok(end)
    }

    fn take_snapshot_slice<'a>(
        bytes: &'a [u8],
        pos: &mut usize,
        body_len: usize,
        len: usize,
    ) -> Result<&'a [u8], StoreError> {
        let end = pos.checked_add(len).ok_or(StoreError::CorruptSnapshot)?;
        if end > body_len {
            return Err(StoreError::CorruptSnapshot);
        }
        let slice = &bytes[*pos..end];
        *pos = end;
        Ok(slice)
    }

    fn decode_snapshot_blobs(
        store: &mut Self,
        bytes: &[u8],
        pos: &mut usize,
        body_len: usize,
        obj_count: usize,
    ) -> Result<(), StoreError> {
        for i in 0..obj_count {
            let hash = ObjHash(u64::from_le_bytes(
                Self::take_snapshot_slice(bytes, pos, body_len, 8)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ));
            let size = u16::from_le_bytes(
                Self::take_snapshot_slice(bytes, pos, body_len, 2)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ) as usize;
            if size > MAX_BLOB_SIZE {
                return Err(StoreError::CorruptSnapshot);
            }
            let size_u8 = u8::try_from(size).map_err(|_| StoreError::CorruptSnapshot)?;
            let data = Self::take_snapshot_slice(bytes, pos, body_len, size)?;
            if ObjHash::hash_bytes(data) != hash {
                return Err(StoreError::CorruptSnapshot);
            }
            // Reject duplicate blob hashes in snapshot (`M-4`).
            if store.hashes[..i].contains(&hash) {
                return Err(StoreError::CorruptSnapshot);
            }
            store.hashes[i] = hash;
            store.sizes[i] = size_u8;
            let buf = store.data[i].insert([0u8; MAX_BLOB_SIZE]);
            buf[..size].copy_from_slice(data);
        }
        Ok(())
    }

    fn decode_snapshot_refs(
        store: &mut Self,
        bytes: &[u8],
        pos: &mut usize,
        body_len: usize,
        obj_count: usize,
        ref_count: usize,
    ) -> Result<(), StoreError> {
        for i in 0..ref_count {
            let hdr = Self::take_snapshot_slice(bytes, pos, body_len, 2)?;
            let name_len = hdr[0] as usize;
            if (hdr[1] & !Rights::ALL.bits()) != 0 {
                return Err(StoreError::CorruptSnapshot);
            }
            let rights = Rights::from_bits_truncate(hdr[1]);
            let name_len_nz = NonZeroU8::new(hdr[0]).ok_or(StoreError::CorruptSnapshot)?;
            if name_len > MAX_REF_NAME {
                return Err(StoreError::CorruptSnapshot);
            }
            let name = Self::take_snapshot_slice(bytes, pos, body_len, name_len)?;
            let name_str = core::str::from_utf8(name).map_err(|_| StoreError::CorruptSnapshot)?;
            if RefName::parse_strict(name_str).is_none() {
                return Err(StoreError::CorruptSnapshot);
            }
            // Reject duplicate ref names (`M-4`).
            if store.refs[..i]
                .iter()
                .flatten()
                .any(|prev| prev.name_bytes() == name)
            {
                return Err(StoreError::CorruptSnapshot);
            }
            // Reject tampered snapshots that unseal immutable boot refs (`@motd`, `@guide`).
            if (name == b"motd" || name == b"guide") && rights.contains(Rights::WRITE) {
                return Err(StoreError::CorruptSnapshot);
            }
            let target = ObjHash(u64::from_le_bytes(
                Self::take_snapshot_slice(bytes, pos, body_len, 8)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ));
            let prev_raw = u64::from_le_bytes(
                Self::take_snapshot_slice(bytes, pos, body_len, 8)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            );
            let prev = NonZeroU64::new(prev_raw);
            // Verify referential integrity: `target` and `prev` must exist in `store.hashes` (`M-4`).
            if !store.hashes[..obj_count].contains(&target) {
                return Err(StoreError::CorruptSnapshot);
            }
            if let Some(p) = prev
                && !store.hashes[..obj_count].contains(&ObjHash(p.get()))
            {
                return Err(StoreError::CorruptSnapshot);
            }
            let mut slot_name = [0u8; MAX_REF_NAME];
            slot_name[..name_len].copy_from_slice(name);
            store.refs[i] = Some(RefSlot {
                target,
                prev,
                name: slot_name,
                name_len: name_len_nz,
                rights,
            });
        }
        Ok(())
    }

    /// Verify checksum and restore an `ObjectStore` from a serialized binary snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptSnapshot`] if the header, checksum, counts, ref names,
    /// rights, or referential integrity fail validation.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < 16 || &bytes[0..4] != b"CAOS" || bytes[4] != 1 || bytes[7] != 0 {
            return Err(StoreError::CorruptSnapshot);
        }
        let body_len = bytes.len() - 8;
        let expected_crc = u64::from_le_bytes(
            bytes[body_len..]
                .try_into()
                .map_err(|_| StoreError::CorruptSnapshot)?,
        );
        if ObjHash::hash_bytes(&bytes[..body_len]).0 != expected_crc {
            return Err(StoreError::CorruptSnapshot);
        }

        let obj_count_u8 = bytes[5];
        let ref_count_u8 = bytes[6];
        let obj_count = usize::from(obj_count_u8);
        let ref_count = usize::from(ref_count_u8);
        if obj_count > MAX_OBJECTS || ref_count > MAX_REFS {
            return Err(StoreError::CorruptSnapshot);
        }

        let used_mask = if obj_count == 0 {
            0
        } else {
            (1u32 << obj_count) - 1
        };
        let mut store = Self {
            hashes: [ObjHash::ZERO; MAX_OBJECTS],
            refs: [None; MAX_REFS],
            used_mask,
            object_count: obj_count_u8,
            ref_count: ref_count_u8,
            sizes: [0u8; MAX_OBJECTS],
            data: [None; MAX_OBJECTS],
        };

        let mut pos = 8usize;
        Self::decode_snapshot_blobs(&mut store, bytes, &mut pos, body_len, obj_count)?;
        Self::decode_snapshot_refs(&mut store, bytes, &mut pos, body_len, obj_count, ref_count)?;

        if pos != body_len {
            return Err(StoreError::CorruptSnapshot);
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_seeds_are_present_and_sealed() {
        let mut store = ObjectStore::new();
        assert_eq!(store.object_count(), 2);

        let (h_motd, motd) = store.get_any("@motd").unwrap();
        assert!(motd.starts_with(b"NewOS"));
        assert_eq!(store.get_by_hash(h_motd).unwrap(), motd);

        let (_, guide) = store.get_any("@guide").unwrap();
        assert!(guide.starts_with(b"Try:"));

        let h_new = store.put(b"tamper").unwrap();
        assert_eq!(store.set_ref("@motd", h_new), Err(CaosError::ReadOnly));
        assert_eq!(store.set_ref("guide", h_new), Err(CaosError::ReadOnly));
    }

    #[test]
    fn put_deduplicates_and_enforces_limits() {
        let mut store = ObjectStore::new();
        let h1 = store.put(b"duplicate payload").unwrap();
        let h2 = store.put(b"duplicate payload").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.object_count(), 3);

        let too_big = [0xAAu8; MAX_BLOB_SIZE + 1];
        assert_eq!(store.put(&too_big), Err(StoreError::TooLarge));

        // Fill remaining slots (MAX_OBJECTS - 3)
        for i in 0..(MAX_OBJECTS - 3) {
            let b = u8::try_from(i).expect("slot index fits in u8");
            let payload = [b; 4];
            store.put(&payload).unwrap();
        }
        assert_eq!(store.object_count(), MAX_OBJECTS);
        assert_eq!(store.put(b"overflow"), Err(StoreError::NoSpace));
    }

    #[test]
    fn ref_update_rollback_and_seal_semantics() {
        let mut store = ObjectStore::new();
        let h1 = store.put(b"v1").unwrap();
        let h2 = store.put(b"v2").unwrap();

        assert_eq!(store.set_ref("", h1), Err(StoreError::InvalidName));
        assert_eq!(
            store.set_ref("abcdefghijklmnopqrstuvwxyz", h1),
            Err(StoreError::InvalidName)
        );
        assert_eq!(
            store.set_ref("ghost", ObjHash(0xdead_beef)),
            Err(StoreError::NotFound)
        );

        store.set_ref("@cfg", h1).unwrap();
        assert_eq!(
            store.rollback_ref("@cfg"),
            Err(StoreError::NoPreviousVersion)
        );

        store.set_ref("@cfg", h2).unwrap();
        assert_eq!(store.get_any("@cfg").unwrap(), (h2, b"v2".as_slice()));

        let rolled = store.rollback_ref("@cfg").unwrap();
        assert_eq!(rolled, h1);
        assert_eq!(store.get_any("@cfg").unwrap(), (h1, b"v1".as_slice()));
        assert_eq!(
            store.rollback_ref("@cfg"),
            Err(StoreError::NoPreviousVersion)
        );

        store.seal_ref("@cfg").unwrap();
        assert_eq!(store.set_ref("@cfg", h2), Err(StoreError::ReadOnly));
        assert_eq!(store.rollback_ref("@cfg"), Err(StoreError::ReadOnly));
        assert_eq!(store.seal_ref("@missing"), Err(StoreError::NotFound));
    }

    #[test]
    fn collect_objects_and_refs_matches_store_state() {
        let store = ObjectStore::default();
        let mut objs = [None; MAX_OBJECTS];
        let obj_n = store.collect_objects(&mut objs);
        assert_eq!(obj_n, 2);

        let mut refs = [None; MAX_REFS];
        let ref_n = store.collect_refs(&mut refs);
        assert_eq!(ref_n, 2);
        assert_eq!(refs[0].unwrap().name_str(), "motd");
        assert!(!refs[0].unwrap().writable);
        assert_eq!(refs[1].unwrap().name_str(), "guide");
        assert!(!refs[1].unwrap().writable);

        let mut visited_objs = 0usize;
        store.for_each_object(|meta| {
            assert_eq!(meta.hash, objs[visited_objs].unwrap().hash);
            assert_eq!(meta.size, objs[visited_objs].unwrap().size);
            visited_objs += 1;
        });
        assert_eq!(visited_objs, obj_n);

        let mut visited_refs = 0usize;
        store.for_each_ref(|meta| {
            assert_eq!(meta.name_str(), refs[visited_refs].unwrap().name_str());
            assert_eq!(meta.target, refs[visited_refs].unwrap().target);
            visited_refs += 1;
        });
        assert_eq!(visited_refs, ref_n);
    }

    #[test]
    fn const_hash_matches_runtime_and_boot_seeds() {
        const H_EMPTY: ObjHash = ObjHash::hash_bytes(b"");
        const H_HELLO: ObjHash = ObjHash::hash_bytes(b"hello newos");
        assert_eq!(H_EMPTY, ObjHash::hash_bytes(b""));
        assert_eq!(H_HELLO, ObjHash::hash_bytes(b"hello newos"));
        assert_ne!(H_EMPTY, ObjHash::ZERO);
        assert_eq!(MOTD_HASH, ObjHash::hash_bytes(MOTD_BYTES));
        assert_eq!(GUIDE_HASH, ObjHash::hash_bytes(GUIDE_BYTES));
        // Content hash vector check (FIPS 202 SHA3-512 when `sha3` enabled, FNV-1a otherwise)
        #[cfg(feature = "sha3")]
        assert_eq!(ObjHash::hash_bytes(b"abc"), ObjHash(0xb751_850b_1a57_168a));
        #[cfg(not(feature = "sha3"))]
        assert_eq!(ObjHash::hash_bytes(b"abc"), ObjHash(0xe71f_a219_0541_574b));
    }

    #[test]
    fn gc_reclaims_unreferenced_blobs_while_preserving_rollback_targets() {
        let mut store = ObjectStore::new();
        let orphan = store.put(b"orphan blob").unwrap();
        let v1 = store.put(b"version 1").unwrap();
        let v2 = store.put(b"version 2").unwrap();
        store.set_ref("@doc", v1).unwrap();
        store.set_ref("@doc", v2).unwrap(); // v1 is now prev rollback target!

        assert_eq!(store.object_count(), 5); // motd, guide, orphan, v1, v2
        assert_eq!(store.gc(), 1); // only `orphan` is reclaimed
        assert_eq!(store.object_count(), 4);
        assert_eq!(store.get_by_hash(orphan), Err(StoreError::NotFound));
        assert_eq!(store.get_by_hash(v1), Ok(&b"version 1"[..]));
        assert_eq!(store.get_by_hash(v2), Ok(&b"version 2"[..]));

        // Rollback still succeeds after GC, and next GC reclaims v2!
        assert_eq!(store.rollback_ref("@doc"), Ok(v1));
        assert_eq!(store.gc(), 1);
        assert_eq!(store.get_by_hash(v2), Err(StoreError::NotFound));
        assert_eq!(store.get_any("@doc"), Ok((v1, &b"version 1"[..])));
    }

    #[test]
    fn snapshot_encode_decode_roundtrip_and_corruption_detection() {
        let mut store = ObjectStore::new();
        let v1 = store.put(b"alpha").unwrap();
        let v2 = store.put(b"beta").unwrap();
        store.set_ref("@cfg", v1).unwrap();
        store.set_ref("@cfg", v2).unwrap();
        store.seal_ref("@cfg").unwrap();

        let mut buf = [0u8; 4096];
        let written = store.encode_snapshot(&mut buf).unwrap();
        let restored = ObjectStore::decode_snapshot(&buf[..written]).unwrap();

        assert_eq!(restored.object_count(), store.object_count());
        assert_eq!(restored.get_any("@motd"), store.get_any("@motd"));
        assert_eq!(restored.get_any("@cfg"), Ok((v2, &b"beta"[..])));
        // Sealed read-only rights preserved across persistence roundtrip
        let mut restored = restored;
        assert_eq!(restored.set_ref("@cfg", v1), Err(StoreError::ReadOnly));

        // Single-bit corruption is detected and rejected!
        buf[written / 2] ^= 0x01;
        assert!(matches!(
            ObjectStore::decode_snapshot(&buf[..written]),
            Err(StoreError::CorruptSnapshot)
        ));
    }

    #[test]
    fn decode_snapshot_rejects_dangling_refs_and_unsealed_boot_refs() {
        // Craft a checksummed snapshot with a dangling ref target hash (0xDEAD_BEEF).
        let mut raw = [0u8; 256];
        let mut pos = 0usize;
        let mut push = |b: &[u8]| {
            raw[pos..pos + b.len()].copy_from_slice(b);
            pos += b.len();
        };
        push(b"CAOS");
        push(&[1u8, 0u8, 1u8, 0u8]); // 0 blobs, 1 ref
        push(&[4u8, Rights::READ.bits()]); // name_len=4, READ
        push(b"note");
        push(&0xDEAD_BEEFu64.to_le_bytes()); // dangling target
        push(&0u64.to_le_bytes()); // prev = None
        drop(push);
        let crc = ObjHash::hash_bytes(&raw[..pos]);
        raw[pos..pos + 8].copy_from_slice(&crc.0.to_le_bytes());
        assert!(matches!(
            ObjectStore::decode_snapshot(&raw[..pos + 8]),
            Err(StoreError::CorruptSnapshot)
        ));

        // Craft a checksummed snapshot that tries to unseal `@motd` to WRITE.
        let mut store = ObjectStore::new();
        store.refs[0].as_mut().unwrap().rights = Rights::READ.union(Rights::WRITE);
        let mut buf = [0u8; 4096];
        let written = store.encode_snapshot(&mut buf).unwrap();
        assert!(matches!(
            ObjectStore::decode_snapshot(&buf[..written]),
            Err(StoreError::CorruptSnapshot)
        ));
    }

    fn finalize_snapshot(raw: &mut [u8], body_len: usize) -> usize {
        let crc = ObjHash::hash_bytes(&raw[..body_len]);
        raw[body_len..body_len + 8].copy_from_slice(&crc.0.to_le_bytes());
        body_len + 8
    }

    #[test]
    fn set_ref_rejects_invalid_characters_whitespace_and_embedded_at() {
        let mut store = ObjectStore::new();
        let h = store.put(b"payload").unwrap();

        let invalid_names = [
            "",
            "@",
            "@@foo",
            "foo@bar",
            "foo bar",
            "foo\tbar",
            "foo\nbar",
            "foo\rbar",
            "foo\0bar",
            "foo\x1bbar",
            "foo\x7fbar",
            "abcdefghijklmnopqrstuvwxy", // 25 bytes = MAX_REF_NAME + 1
        ];
        for bad in invalid_names {
            assert_eq!(
                store.set_ref(bad, h),
                Err(StoreError::InvalidName),
                "expected InvalidName for {bad:?}"
            );
        }

        // Exact boundary length (MAX_REF_NAME = 24 bytes) succeeds.
        let max_name = "abcdefghijklmnopqrstuvwx";
        assert_eq!(max_name.len(), MAX_REF_NAME);
        assert_eq!(store.set_ref(max_name, h), Ok(()));
        assert_eq!(
            store.get_any("@abcdefghijklmnopqrstuvwx"),
            Ok((h, &b"payload"[..]))
        );
    }

    #[test]
    fn decode_snapshot_rejects_nonzero_pad_byte_and_unknown_rights() {
        let store = ObjectStore::new();
        let mut buf = [0u8; 4096];
        let written = store.encode_snapshot(&mut buf).unwrap();
        let body_len = written - 8;

        // Non-zero header pad byte at index 7 must be rejected even with valid checksum.
        let mut bad_pad = buf;
        bad_pad[7] = 1;
        let len = finalize_snapshot(&mut bad_pad, body_len);
        assert!(matches!(
            ObjectStore::decode_snapshot(&bad_pad[..len]),
            Err(StoreError::CorruptSnapshot)
        ));

        // Unknown rights bits in ref header must be rejected even with valid checksum.
        for bad_bits in [Rights::READ.bits() | 0x80, 0x20, 0xFF] {
            let mut raw = [0u8; 256];
            let mut pos = 0usize;
            let mut push = |b: &[u8]| {
                raw[pos..pos + b.len()].copy_from_slice(b);
                pos += b.len();
            };
            let blob = b"ok";
            let hash = ObjHash::hash_bytes(blob);
            push(b"CAOS");
            push(&[1u8, 1u8, 1u8, 0u8]);
            push(&hash.0.to_le_bytes());
            push(
                &u16::try_from(blob.len())
                    .expect("len fits in u16")
                    .to_le_bytes(),
            );
            push(blob);
            push(&[4u8, bad_bits]);
            push(b"note");
            push(&hash.0.to_le_bytes());
            push(&0u64.to_le_bytes());
            drop(push);
            let total = finalize_snapshot(&mut raw, pos);
            assert!(
                matches!(
                    ObjectStore::decode_snapshot(&raw[..total]),
                    Err(StoreError::CorruptSnapshot)
                ),
                "expected CorruptSnapshot for rights bits {bad_bits:#x}"
            );
        }
    }

    #[test]
    fn decode_snapshot_rejects_malformed_ref_names_and_boundary_counts() {
        let blob = b"data";
        let blob_len_u16 = u16::try_from(blob.len()).expect("len fits in u16");
        let hash = ObjHash::hash_bytes(blob);

        // Malformed ref names (control char, whitespace, embedded '@')
        for bad_name in [b"a\x1bb".as_slice(), b"a b".as_slice(), b"a@b".as_slice()] {
            let mut raw = [0u8; 256];
            let mut pos = 0usize;
            let mut push = |b: &[u8]| {
                raw[pos..pos + b.len()].copy_from_slice(b);
                pos += b.len();
            };
            push(b"CAOS");
            push(&[1u8, 1u8, 1u8, 0u8]);
            push(&hash.0.to_le_bytes());
            push(&blob_len_u16.to_le_bytes());
            push(blob);
            push(&[
                u8::try_from(bad_name.len()).expect("len fits in u8"),
                Rights::READ.bits(),
            ]);
            push(bad_name);
            push(&hash.0.to_le_bytes());
            push(&0u64.to_le_bytes());
            drop(push);
            let total = finalize_snapshot(&mut raw, pos);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }

        // Truncated snapshot (< 16 bytes)
        assert!(matches!(
            ObjectStore::decode_snapshot(b"CAOS\x01\x00\x00\x00"),
            Err(StoreError::CorruptSnapshot)
        ));

        // obj_count > MAX_OBJECTS and ref_count > MAX_REFS
        let over_obj = u8::try_from(MAX_OBJECTS + 1).expect("MAX_OBJECTS + 1 fits in u8");
        let over_ref = u8::try_from(MAX_REFS + 1).expect("MAX_REFS + 1 fits in u8");
        for (oc, rc) in [(over_obj, 0), (0, over_ref)] {
            let mut raw = [0u8; 32];
            raw[0..4].copy_from_slice(b"CAOS");
            raw[4..8].copy_from_slice(&[1, oc, rc, 0]);
            let total = finalize_snapshot(&mut raw, 8);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }

        // blob size > MAX_BLOB_SIZE
        {
            let mut raw = [0u8; 64];
            raw[0..4].copy_from_slice(b"CAOS");
            raw[4..8].copy_from_slice(&[1, 1, 0, 0]);
            raw[8..16].copy_from_slice(&hash.0.to_le_bytes());
            let over_blob =
                u16::try_from(MAX_BLOB_SIZE + 1).expect("MAX_BLOB_SIZE + 1 fits in u16");
            raw[16..18].copy_from_slice(&over_blob.to_le_bytes());
            let total = finalize_snapshot(&mut raw, 18);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }

        // Trailing extra bytes after valid body
        {
            let mut raw = [0u8; 64];
            raw[0..4].copy_from_slice(b"CAOS");
            raw[4..8].copy_from_slice(&[1, 0, 0, 0]);
            raw[8] = 0x99;
            let total = finalize_snapshot(&mut raw, 9);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }
    }

    #[test]
    fn decode_snapshot_rejects_duplicates_and_dangling_prev_hash() {
        let blob = b"data";
        let blob_len_u16 = u16::try_from(blob.len()).expect("len fits in u16");
        let hash = ObjHash::hash_bytes(blob);

        // Duplicate blob hash
        {
            let mut raw = [0u8; 128];
            let mut pos = 0usize;
            let mut push = |b: &[u8]| {
                raw[pos..pos + b.len()].copy_from_slice(b);
                pos += b.len();
            };
            push(b"CAOS");
            push(&[1u8, 2u8, 0u8, 0u8]);
            for _ in 0..2 {
                push(&hash.0.to_le_bytes());
                push(&blob_len_u16.to_le_bytes());
                push(blob);
            }
            drop(push);
            let total = finalize_snapshot(&mut raw, pos);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }

        // Duplicate ref name
        {
            let mut raw = [0u8; 128];
            let mut pos = 0usize;
            let mut push = |b: &[u8]| {
                raw[pos..pos + b.len()].copy_from_slice(b);
                pos += b.len();
            };
            push(b"CAOS");
            push(&[1u8, 1u8, 2u8, 0u8]);
            push(&hash.0.to_le_bytes());
            push(&blob_len_u16.to_le_bytes());
            push(blob);
            for _ in 0..2 {
                push(&[3u8, Rights::READ.bits()]);
                push(b"dup");
                push(&hash.0.to_le_bytes());
                push(&0u64.to_le_bytes());
            }
            drop(push);
            let total = finalize_snapshot(&mut raw, pos);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }

        // Dangling prev hash
        {
            let mut raw = [0u8; 128];
            let mut pos = 0usize;
            let mut push = |b: &[u8]| {
                raw[pos..pos + b.len()].copy_from_slice(b);
                pos += b.len();
            };
            push(b"CAOS");
            push(&[1u8, 1u8, 1u8, 0u8]);
            push(&hash.0.to_le_bytes());
            push(&blob_len_u16.to_le_bytes());
            push(blob);
            push(&[4u8, Rights::READ.bits()]);
            push(b"prev");
            push(&hash.0.to_le_bytes());
            push(&0xBAD0_C0DEu64.to_le_bytes());
            drop(push);
            let total = finalize_snapshot(&mut raw, pos);
            assert!(matches!(
                ObjectStore::decode_snapshot(&raw[..total]),
                Err(StoreError::CorruptSnapshot)
            ));
        }
    }

    #[test]
    fn blob_size_exact_boundary_and_gc_reuse_slots() {
        let mut store = ObjectStore::new();
        let exact = [0x55u8; MAX_BLOB_SIZE];
        let h_exact = store.put(&exact).unwrap();
        assert_eq!(store.get_by_hash(h_exact), Ok(&exact[..]));
        assert_eq!(
            store.put(&[0x55u8; MAX_BLOB_SIZE + 1]),
            Err(StoreError::TooLarge)
        );
        store.set_ref("@exact", h_exact).unwrap();

        // Fill all remaining slots up to MAX_OBJECTS.
        let remaining = MAX_OBJECTS - store.object_count();
        for i in 0..remaining {
            let b = u8::try_from(i).expect("slot index fits in u8");
            let payload = [0xA0u8, b, b.wrapping_mul(3)];
            store.put(&payload).unwrap();
        }
        assert_eq!(store.object_count(), MAX_OBJECTS);
        assert_eq!(store.put(b"full"), Err(StoreError::NoSpace));

        // GC reclaims all unreferenced blobs; freed `used_mask` slots can be reused up to MAX_OBJECTS.
        assert_eq!(store.gc(), remaining);
        assert_eq!(store.object_count(), 3); // motd, guide, exact
        for i in 0..remaining {
            let b = u8::try_from(i).expect("slot index fits in u8");
            let payload = [0xB0u8, b, b.wrapping_mul(5)];
            let h = store.put(&payload).unwrap();
            assert_eq!(store.get_by_hash(h), Ok(&payload[..]));
        }
        assert_eq!(store.object_count(), MAX_OBJECTS);

        // Snapshot encode/decode roundtrip preserves full store accurately.
        let mut snap = [0u8; 4096];
        let n = store.encode_snapshot(&mut snap).unwrap();
        let restored = ObjectStore::decode_snapshot(&snap[..n]).unwrap();
        assert_eq!(restored.object_count(), MAX_OBJECTS);
        assert_eq!(restored.get_any("@exact"), Ok((h_exact, &exact[..])));
    }

    #[test]
    fn store_error_display_and_core_error_trait() {
        extern crate std;
        use core::error::Error as _;
        use std::format;

        let cases = [
            (StoreError::NotFound, "NotFound"),
            (StoreError::NoSpace, "NoSpace"),
            (StoreError::TooLarge, "TooLarge"),
            (StoreError::InvalidName, "InvalidName"),
            (StoreError::ReadOnly, "ReadOnly"),
            (StoreError::NoPreviousVersion, "NoPreviousVersion"),
            (StoreError::CorruptSnapshot, "CorruptSnapshot"),
            (StoreError::HashCollision, "HashCollision"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.as_str(), expected);
            assert_eq!(format!("{err}"), expected);
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn obj_hash_display_and_from_conversions() {
        extern crate std;
        use std::format;

        let raw = 0x0123_4567_89ab_cdef_u64;
        let hash = ObjHash::from(raw);
        assert_eq!(u64::from(hash), raw);
        assert_eq!(format!("{hash}"), "obj:0123456789abcdef");
    }

    #[test]
    fn public_meta_and_store_debug_eq() {
        extern crate std;
        use std::format;

        let store = ObjectStore::new();
        let store_dbg = format!("{store:?}");
        assert!(store_dbg.contains("ObjectStore"));
        assert!(store_dbg.contains("object_count: 2"));

        let mut objs = [None; MAX_OBJECTS];
        assert_eq!(store.collect_objects(&mut objs), 2);
        let first_obj = objs[0].expect("boot object 0");
        assert_eq!(first_obj, first_obj);
        assert!(format!("{first_obj:?}").contains("ObjectMeta"));

        let mut refs = [None; MAX_REFS];
        assert_eq!(store.collect_refs(&mut refs), 2);
        let first_ref = refs[0].expect("boot ref 0");
        assert_eq!(first_ref, first_ref);
        assert!(format!("{first_ref:?}").contains("RefMeta"));
    }
}
