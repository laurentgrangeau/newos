//! Capability-Scoped Content-Addressed Object Store (CAOS) — `#![forbid(unsafe_code)]`, `no_alloc`.
//!
//! Post-UNIX storage living 100% in Ring 3:
//! - Every blob is **immutable** and addressed by its 64-bit content hash (`ObjHash`),
//!   providing automatic deduplication, lock-free reads, and zero in-place corruption.
//! - Mutable state exists only as explicit named **Refs** (`@name -> ObjHash`) with
//!   atomic rollback (`prev_hash`) and irreversible capability attenuation (`seal` -> read-only).
//! - No global `/` namespace, no `cd`, no `../../` path traversal, no ambient authority.

use newos_abi::Rights;

const MAX_OBJECTS: usize = 24;
const MAX_REFS: usize = 16;
const MAX_BLOB_SIZE: usize = 128;
const MAX_REF_NAME: usize = 24;

/// Deterministic 64-bit content address (FNV-1a 64-bit + avalanche finalizer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ObjHash(pub u64);

impl ObjHash {
    pub const ZERO: Self = Self(0);

    pub fn hash_bytes(bytes: &[u8]) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // Murmur3-style avalanche finalizer for uniform 64-bit distribution
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^= h >> 33;
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
}

#[derive(Clone, Copy)]
struct BlobSlot {
    used: bool,
    hash: ObjHash,
    data: [u8; MAX_BLOB_SIZE],
    size: usize,
}

impl BlobSlot {
    const EMPTY: Self = Self {
        used: false,
        hash: ObjHash::ZERO,
        data: [0; MAX_BLOB_SIZE],
        size: 0,
    };
}

#[derive(Clone, Copy)]
struct RefSlot {
    used: bool,
    name: [u8; MAX_REF_NAME],
    name_len: usize,
    target: ObjHash,
    prev: Option<ObjHash>,
    rights: Rights,
}

impl RefSlot {
    const EMPTY: Self = Self {
        used: false,
        name: [0; MAX_REF_NAME],
        name_len: 0,
        target: ObjHash::ZERO,
        prev: None,
        rights: Rights::NONE,
    };

    fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }
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
    pub name: [u8; MAX_REF_NAME],
    pub name_len: usize,
    pub target: ObjHash,
    pub prev: Option<ObjHash>,
    pub writable: bool,
}

impl RefMeta {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }
}

/// Ring-3 Content-Addressed Object Store (`no_alloc`, `#![forbid(unsafe_code)]`).
pub struct ObjectStore {
    blobs: [BlobSlot; MAX_OBJECTS],
    refs: [RefSlot; MAX_REFS],
}

impl ObjectStore {
    pub fn new() -> Self {
        let mut store = Self {
            blobs: [BlobSlot::EMPTY; MAX_OBJECTS],
            refs: [RefSlot::EMPTY; MAX_REFS],
        };
        // Seed two immutable boot objects + capability-gated refs
        if let Ok(h) = store.put(b"NewOS: pure seL4-style 64-bit Rust microkernel (post-UNIX CAOS)")
        {
            let _ = store.set_ref("motd", h);
            let _ = store.seal_ref("motd"); // `@motd` is sealed read-only at boot!
        }
        if let Ok(h) = store.put(b"Try: `put \"hello\" | save @note`, `objects | where size > 20`, `procs | where pid == 1`")
        {
            let _ = store.set_ref("guide", h);
            let _ = store.seal_ref("guide");
        }
        store
    }

    /// Store an immutable byte slice; automatically deduplicates identical content.
    pub fn put(&mut self, bytes: &[u8]) -> Result<ObjHash, StoreError> {
        if bytes.len() > MAX_BLOB_SIZE {
            return Err(StoreError::TooLarge);
        }
        let hash = ObjHash::hash_bytes(bytes);

        // Content deduplication: if an identical blob already exists, return its hash immediately.
        for slot in &self.blobs {
            if slot.used && slot.hash == hash && &slot.data[..slot.size] == bytes {
                return Ok(hash);
            }
        }

        for slot in &mut self.blobs {
            if !slot.used {
                slot.used = true;
                slot.hash = hash;
                slot.data[..bytes.len()].copy_from_slice(bytes);
                slot.size = bytes.len();
                return Ok(hash);
            }
        }
        Err(StoreError::NoSpace)
    }

    /// Lock-free immutable lookup by `ObjHash`.
    pub fn get_by_hash(&self, hash: ObjHash) -> Result<&[u8], StoreError> {
        for slot in &self.blobs {
            if slot.used && slot.hash == hash {
                return Ok(&slot.data[..slot.size]);
            }
        }
        Err(StoreError::NotFound)
    }

    /// Resolve `@ref_name` or `obj:<hex>` to `(ObjHash, &[u8])`.
    pub fn get_any(&self, spec: &str) -> Result<(ObjHash, &[u8]), StoreError> {
        if let Some(name) = spec.strip_prefix('@') {
            for r in &self.refs {
                if r.used && r.name_str() == name {
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
        if name.is_empty() || name.len() > MAX_REF_NAME {
            return Err(StoreError::InvalidName);
        }
        let _ = self.get_by_hash(target)?;

        // Update existing ref if writable
        for r in &mut self.refs {
            if r.used && r.name_str() == name {
                if !r.rights.contains(Rights::WRITE) {
                    return Err(StoreError::ReadOnly);
                }
                if r.target != target {
                    r.prev = Some(r.target);
                    r.target = target;
                }
                return Ok(());
            }
        }

        // Create new ref with READ | WRITE
        for r in &mut self.refs {
            if !r.used {
                r.used = true;
                r.name[..name.len()].copy_from_slice(name.as_bytes());
                r.name_len = name.len();
                r.target = target;
                r.prev = None;
                r.rights = Rights::READ.union(Rights::WRITE);
                return Ok(());
            }
        }
        Err(StoreError::NoSpace)
    }

    /// Irreversibly attenuate a ref's rights to `READ`-only (cannot be escalated back!).
    pub fn seal_ref(&mut self, raw_name: &str) -> Result<(), StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        for r in &mut self.refs {
            if r.used && r.name_str() == name {
                r.rights = r.rights.attenuate(Rights::READ);
                return Ok(());
            }
        }
        Err(StoreError::NotFound)
    }

    /// Atomically roll back a writable ref to its previous immutable `ObjHash`.
    pub fn rollback_ref(&mut self, raw_name: &str) -> Result<ObjHash, StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        for r in &mut self.refs {
            if r.used && r.name_str() == name {
                if !r.rights.contains(Rights::WRITE) {
                    return Err(StoreError::ReadOnly);
                }
                let prev = r.prev.take().ok_or(StoreError::NoPreviousVersion)?;
                r.target = prev;
                return Ok(prev);
            }
        }
        Err(StoreError::NotFound)
    }

    pub fn object_count(&self) -> usize {
        self.blobs.iter().filter(|b| b.used).count()
    }

    pub fn collect_objects(&self, out: &mut [Option<ObjectMeta>]) -> usize {
        let mut n = 0usize;
        for b in &self.blobs {
            if b.used && n < out.len() {
                out[n] = Some(ObjectMeta {
                    hash: b.hash,
                    size: b.size,
                });
                n += 1;
            }
        }
        n
    }

    pub fn collect_refs(&self, out: &mut [Option<RefMeta>]) -> usize {
        let mut n = 0usize;
        for r in &self.refs {
            if r.used && n < out.len() {
                out[n] = Some(RefMeta {
                    name: r.name,
                    name_len: r.name_len,
                    target: r.target,
                    prev: r.prev,
                    writable: r.rights.contains(Rights::WRITE),
                });
                n += 1;
            }
        }
        n
    }
}
