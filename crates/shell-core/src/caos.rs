//! Capability-Scoped Content-Addressed Object Store (CAOS) — `#![forbid(unsafe_code)]`, `no_alloc`.
//!
//! Post-UNIX storage living 100% in EL0:
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

/// Deterministic 64-bit cryptographic content address (FIPS 180-4 SHA-256 prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ObjHash(pub u64);

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const fn sha256_compress(mut state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    let mut i = 0;
    while i < 16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        i += 1;
    }
    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    let mut j = 0;
    while j < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[j])
            .wrapping_add(w[j]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        j += 1;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
    state
}

impl ObjHash {
    pub const ZERO: Self = Self(0);

    pub const fn hash_bytes(bytes: &[u8]) -> Self {
        let mut state: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let mut pos = 0;
        while pos + 64 <= bytes.len() {
            let mut block = [0u8; 64];
            let mut k = 0;
            while k < 64 {
                block[k] = bytes[pos + k];
                k += 1;
            }
            state = sha256_compress(state, &block);
            pos += 64;
        }
        let rem = bytes.len() - pos;
        let mut tail = [0u8; 64];
        let mut k = 0;
        while k < rem {
            tail[k] = bytes[pos + k];
            k += 1;
        }
        tail[rem] = 0x80;
        if rem >= 56 {
            state = sha256_compress(state, &tail);
            tail = [0u8; 64];
        }
        let bit_len = (bytes.len() as u64).wrapping_mul(8);
        let len_be = bit_len.to_be_bytes();
        let mut m = 0;
        while m < 8 {
            tail[56 + m] = len_be[m];
            m += 1;
        }
        state = sha256_compress(state, &tail);
        let mut h = ((state[0] as u64) << 32) | (state[1] as u64);
        if h == 0 {
            h = 1;
        }
        Self(h)
    }

    pub fn parse_hex(s: &str) -> Option<Self> {
        let stripped = s
            .strip_prefix("obj:")
            .or_else(|| s.strip_prefix("0x"))
            .unwrap_or(s);
        u64::from_str_radix(stripped, 16).ok().map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Public alias for `StoreError` per `newos-shell-core` interface contract.
pub type CaosError = StoreError;

const MOTD_BYTES: &[u8] = b"NewOS: pure seL4-style 64-bit Rust microkernel (post-UNIX CAOS)";
const GUIDE_BYTES: &[u8] =
    b"Try: `put \"hello\" | save @note`, `objects | where size > 20`, `procs | where pid == 1`";
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
        let mut name = [0u8; MAX_REF_NAME];
        let mut i = 0;
        while i < raw_name.len() {
            name[i] = raw_name[i];
            i += 1;
        }
        let name_len = match NonZeroU8::new(raw_name.len() as u8) {
            Some(n) => n,
            None => NonZeroU8::MIN,
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

#[inline]
fn is_valid_ref_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_REF_NAME
        && !name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '@')
}

/// Snapshot metadata for an immutable object (emitted directly as a typed shell `Record`).
#[derive(Clone, Copy)]
pub struct ObjectMeta {
    pub hash: ObjHash,
    pub size: usize,
}

/// Snapshot metadata for a capability-gated named Ref (emitted as a typed shell `Record`).
#[derive(Clone, Copy)]
pub struct RefMeta {
    pub target: ObjHash,
    pub prev_hash: Option<NonZeroU64>,
    pub name: [u8; MAX_REF_NAME],
    pub name_len: u8,
    pub writable: bool,
}

const _: () = assert!(core::mem::size_of::<RefMeta>() == 48);

impl RefMeta {
    #[inline]
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("?")
    }

    #[inline]
    pub const fn prev(&self) -> Option<ObjHash> {
        match self.prev_hash {
            Some(nz) => Some(ObjHash(nz.get())),
            None => None,
        }
    }
}

/// EL0 Content-Addressed Object Store (`no_alloc`, `#![forbid(unsafe_code)]`).
///
/// Structure-of-Arrays (SoA) layout concentrates all live `ObjHash` entries into 3 cache lines
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

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore {
    pub const fn new() -> Self {
        let mut hashes = [ObjHash::ZERO; MAX_OBJECTS];
        hashes[0] = MOTD_HASH;
        hashes[1] = GUIDE_HASH;

        let mut sizes = [0u8; MAX_OBJECTS];
        sizes[0] = MOTD_BYTES.len() as u8;
        sizes[1] = GUIDE_BYTES.len() as u8;

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
        self.hashes[idx] = hash;
        self.sizes[idx] = bytes.len() as u8;
        let buf = self.data[idx].insert([0u8; MAX_BLOB_SIZE]);
        buf[..bytes.len()].copy_from_slice(bytes);
        self.used_mask |= 1u32 << idx;
        self.object_count += 1;
        Ok(hash)
    }

    /// Lock-free immutable lookup by `ObjHash`.
    pub fn get_by_hash(&self, hash: ObjHash) -> Result<&[u8], StoreError> {
        let idx = self.find_blob_idx(hash).ok_or(StoreError::NotFound)?;
        let buf = self.data[idx].as_ref().ok_or(StoreError::NotFound)?;
        Ok(&buf[..self.sizes[idx] as usize])
    }

    /// Resolve `@ref_name` or `obj:<hex>` to `(ObjHash, &[u8])`.
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
    pub fn set_ref(&mut self, raw_name: &str, target: ObjHash) -> Result<(), StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        if !is_valid_ref_name(name) {
            return Err(StoreError::InvalidName);
        }
        let _ = self.get_by_hash(target)?;

        // Update existing ref if writable (single-pass bounded scan over live packed refs)
        let name_bytes = name.as_bytes();
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
        let name_len = NonZeroU8::new(name_bytes.len() as u8).ok_or(StoreError::InvalidName)?;
        let mut slot_name = [0u8; MAX_REF_NAME];
        slot_name[..name_bytes.len()].copy_from_slice(name_bytes);
        self.refs[ref_count] = Some(RefSlot {
            target,
            prev: None,
            name: slot_name,
            name_len,
            rights: Rights::READ.union(Rights::WRITE),
        });
        self.ref_count += 1;
        Ok(())
    }

    /// Irreversibly attenuate a ref's rights to `READ`-only (cannot be escalated back!).
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

    #[inline]
    pub fn object_count(&self) -> usize {
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

    pub fn collect_objects(&self, out: &mut [Option<ObjectMeta>]) -> usize {
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
        let mut reclaimed = 0usize;
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
        self.object_count -= reclaimed as u8;
        reclaimed
    }

    /// Serialize the entire CAOS store into a crash-safe, checksummed binary snapshot
    /// suitable for writing to a block device (VirtIO-blk / NVMe / SD).
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
            push(&(size as u16).to_le_bytes())?;
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

    /// Verify checksum and restore an `ObjectStore` from a serialized binary snapshot.
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

        let obj_count = bytes[5] as usize;
        let ref_count = bytes[6] as usize;
        if obj_count > MAX_OBJECTS || ref_count > MAX_REFS {
            return Err(StoreError::CorruptSnapshot);
        }

        let mut pos = 8usize;
        let mut take = |len: usize| -> Result<&[u8], StoreError> {
            let end = pos.checked_add(len).ok_or(StoreError::CorruptSnapshot)?;
            if end > body_len {
                return Err(StoreError::CorruptSnapshot);
            }
            let slice = &bytes[pos..end];
            pos = end;
            Ok(slice)
        };

        let used_mask = if obj_count == 0 {
            0
        } else {
            (1u32 << obj_count) - 1
        };
        let mut store = Self {
            hashes: [ObjHash::ZERO; MAX_OBJECTS],
            refs: [None; MAX_REFS],
            used_mask,
            object_count: obj_count as u8,
            ref_count: ref_count as u8,
            sizes: [0u8; MAX_OBJECTS],
            data: [None; MAX_OBJECTS],
        };

        for i in 0..obj_count {
            let hash = ObjHash(u64::from_le_bytes(
                take(8)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ));
            let size = u16::from_le_bytes(
                take(2)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ) as usize;
            if size > MAX_BLOB_SIZE {
                return Err(StoreError::CorruptSnapshot);
            }
            let data = take(size)?;
            if ObjHash::hash_bytes(data) != hash {
                return Err(StoreError::CorruptSnapshot);
            }
            // Reject duplicate blob hashes in snapshot (`M-4`).
            if store.hashes[..i].contains(&hash) {
                return Err(StoreError::CorruptSnapshot);
            }
            store.hashes[i] = hash;
            store.sizes[i] = size as u8;
            let buf = store.data[i].insert([0u8; MAX_BLOB_SIZE]);
            buf[..size].copy_from_slice(data);
        }

        for i in 0..ref_count {
            let hdr = take(2)?;
            let name_len = hdr[0] as usize;
            if (hdr[1] & !Rights::ALL.bits()) != 0 {
                return Err(StoreError::CorruptSnapshot);
            }
            let rights = Rights::from_bits_truncate(hdr[1]);
            let name_len_nz = NonZeroU8::new(hdr[0]).ok_or(StoreError::CorruptSnapshot)?;
            if name_len > MAX_REF_NAME {
                return Err(StoreError::CorruptSnapshot);
            }
            let name = take(name_len)?;
            let name_str = core::str::from_utf8(name).map_err(|_| StoreError::CorruptSnapshot)?;
            if !is_valid_ref_name(name_str) {
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
                take(8)?
                    .try_into()
                    .map_err(|_| StoreError::CorruptSnapshot)?,
            ));
            let prev_raw = u64::from_le_bytes(
                take(8)?
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
        assert!(motd.starts_with(b"NewOS:"));
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
            let payload = [i as u8; 4];
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
        // FIPS 180-4 SHA-256("abc") prefix check
        assert_eq!(ObjHash::hash_bytes(b"abc"), ObjHash(0xba78_16bf_8f01_cfea));
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
            push(&(blob.len() as u16).to_le_bytes());
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
            push(&(blob.len() as u16).to_le_bytes());
            push(blob);
            push(&[bad_name.len() as u8, Rights::READ.bits()]);
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
        for (oc, rc) in [(MAX_OBJECTS as u8 + 1, 0), (0, MAX_REFS as u8 + 1)] {
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
            raw[16..18].copy_from_slice(&((MAX_BLOB_SIZE + 1) as u16).to_le_bytes());
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
                push(&(blob.len() as u16).to_le_bytes());
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
            push(&(blob.len() as u16).to_le_bytes());
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
            push(&(blob.len() as u16).to_le_bytes());
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
            let payload = [0xA0u8, i as u8, (i * 3) as u8];
            store.put(&payload).unwrap();
        }
        assert_eq!(store.object_count(), MAX_OBJECTS);
        assert_eq!(store.put(b"full"), Err(StoreError::NoSpace));

        // GC reclaims all unreferenced blobs; freed `used_mask` slots can be reused up to MAX_OBJECTS.
        assert_eq!(store.gc(), remaining);
        assert_eq!(store.object_count(), 3); // motd, guide, exact
        for i in 0..remaining {
            let payload = [0xB0u8, i as u8, (i * 5) as u8];
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
}
