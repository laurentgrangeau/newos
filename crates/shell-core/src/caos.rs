//! Capability-Scoped Content-Addressed Object Store (CAOS) — `#![forbid(unsafe_code)]`, `no_alloc`.
//!
//! Post-UNIX storage living 100% in Ring 3:
//! - Every blob is **immutable** and addressed by its 64-bit content hash (`ObjHash`),
//!   providing automatic deduplication, lock-free reads, and zero in-place corruption.
//! - Mutable state exists only as explicit named **Refs** (`@name -> ObjHash`) with
//!   atomic rollback (`prev_hash`) and irreversible capability attenuation (`seal` -> read-only).
//! - No global `/` namespace, no `cd`, no `../../` path traversal, no ambient authority.

use newos_abi::Rights;

pub const MAX_OBJECTS: usize = 24;
pub const MAX_REFS: usize = 16;
pub const MAX_BLOB_SIZE: usize = 128;
pub const MAX_REF_NAME: usize = 24;

/// Deterministic 64-bit content address (FNV-1a 64-bit + avalanche finalizer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ObjHash(pub u64);

impl ObjHash {
    pub const ZERO: Self = Self(0);

    pub const fn hash_bytes(bytes: &[u8]) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut i = 0;
        while i < bytes.len() {
            h ^= bytes[i] as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
            i += 1;
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

/// Public alias for `StoreError` per `newos-shell-core` interface contract.
pub type CaosError = StoreError;

const MOTD_BYTES: &[u8] = b"NewOS: pure seL4-style 64-bit Rust microkernel (post-UNIX CAOS)";
const GUIDE_BYTES: &[u8] =
    b"Try: `put \"hello\" | save @note`, `objects | where size > 20`, `procs | where pid == 1`";
const MOTD_HASH: ObjHash = ObjHash::hash_bytes(MOTD_BYTES);
const GUIDE_HASH: ObjHash = ObjHash::hash_bytes(GUIDE_BYTES);

#[derive(Clone, Copy)]
struct BlobSlot {
    hash: ObjHash,
    data: [u8; MAX_BLOB_SIZE],
    size: usize,
}

impl BlobSlot {
    const EMPTY: Self = Self {
        hash: ObjHash::ZERO,
        data: [0; MAX_BLOB_SIZE],
        size: 0,
    };

    const fn from_static(hash: ObjHash, bytes: &[u8]) -> Self {
        let mut data = [0u8; MAX_BLOB_SIZE];
        let mut i = 0;
        while i < bytes.len() {
            data[i] = bytes[i];
            i += 1;
        }
        Self {
            hash,
            data,
            size: bytes.len(),
        }
    }
}

#[derive(Clone, Copy)]
struct RefSlot {
    name: [u8; MAX_REF_NAME],
    name_len: usize,
    target: ObjHash,
    prev: Option<ObjHash>,
    rights: Rights,
}

impl RefSlot {
    const EMPTY: Self = Self {
        name: [0; MAX_REF_NAME],
        name_len: 0,
        target: ObjHash::ZERO,
        prev: None,
        rights: Rights::NONE,
    };

    const fn sealed_static(raw_name: &[u8], target: ObjHash) -> Self {
        let mut name = [0u8; MAX_REF_NAME];
        let mut i = 0;
        while i < raw_name.len() {
            name[i] = raw_name[i];
            i += 1;
        }
        Self {
            name,
            name_len: raw_name.len(),
            target,
            prev: None,
            rights: Rights::READ,
        }
    }

    #[inline]
    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

const BOOT_MOTD_BLOB: BlobSlot = BlobSlot::from_static(MOTD_HASH, MOTD_BYTES);
const BOOT_GUIDE_BLOB: BlobSlot = BlobSlot::from_static(GUIDE_HASH, GUIDE_BYTES);
const BOOT_MOTD_REF: RefSlot = RefSlot::sealed_static(b"motd", MOTD_HASH);
const BOOT_GUIDE_REF: RefSlot = RefSlot::sealed_static(b"guide", GUIDE_HASH);

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
    object_count: usize,
    ref_count: usize,
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore {
    pub fn new() -> Self {
        let mut blobs = [BlobSlot::EMPTY; MAX_OBJECTS];
        blobs[0] = BOOT_MOTD_BLOB;
        blobs[1] = BOOT_GUIDE_BLOB;

        let mut refs = [RefSlot::EMPTY; MAX_REFS];
        refs[0] = BOOT_MOTD_REF; // `@motd` is sealed read-only at boot!
        refs[1] = BOOT_GUIDE_REF;

        Self {
            blobs,
            refs,
            object_count: 2,
            ref_count: 2,
        }
    }

    /// Store an immutable byte slice; automatically deduplicates identical content.
    pub fn put(&mut self, bytes: &[u8]) -> Result<ObjHash, StoreError> {
        if bytes.len() > MAX_BLOB_SIZE {
            return Err(StoreError::TooLarge);
        }
        let hash = ObjHash::hash_bytes(bytes);

        // Content deduplication: single-pass bounded scan over live packed blobs.
        for slot in &self.blobs[..self.object_count] {
            if slot.hash == hash && &slot.data[..slot.size] == bytes {
                return Ok(hash);
            }
        }

        if self.object_count >= MAX_OBJECTS {
            return Err(StoreError::NoSpace);
        }
        let slot = &mut self.blobs[self.object_count];
        slot.hash = hash;
        slot.data[..bytes.len()].copy_from_slice(bytes);
        slot.size = bytes.len();
        self.object_count += 1;
        Ok(hash)
    }

    /// Lock-free immutable lookup by `ObjHash`.
    pub fn get_by_hash(&self, hash: ObjHash) -> Result<&[u8], StoreError> {
        for slot in &self.blobs[..self.object_count] {
            if slot.hash == hash {
                return Ok(&slot.data[..slot.size]);
            }
        }
        Err(StoreError::NotFound)
    }

    /// Resolve `@ref_name` or `obj:<hex>` to `(ObjHash, &[u8])`.
    pub fn get_any(&self, spec: &str) -> Result<(ObjHash, &[u8]), StoreError> {
        if let Some(name) = spec.strip_prefix('@') {
            let name_bytes = name.as_bytes();
            for r in &self.refs[..self.ref_count] {
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
        if name.is_empty() || name.len() > MAX_REF_NAME {
            return Err(StoreError::InvalidName);
        }
        let _ = self.get_by_hash(target)?;

        // Update existing ref if writable (single-pass bounded scan over live packed refs)
        let name_bytes = name.as_bytes();
        for r in &mut self.refs[..self.ref_count] {
            if r.name_bytes() == name_bytes {
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

        // Create new ref with READ | WRITE in O(1)
        if self.ref_count >= MAX_REFS {
            return Err(StoreError::NoSpace);
        }
        let r = &mut self.refs[self.ref_count];
        r.name[..name_bytes.len()].copy_from_slice(name_bytes);
        r.name_len = name_bytes.len();
        r.target = target;
        r.prev = None;
        r.rights = Rights::READ.union(Rights::WRITE);
        self.ref_count += 1;
        Ok(())
    }

    /// Irreversibly attenuate a ref's rights to `READ`-only (cannot be escalated back!).
    pub fn seal_ref(&mut self, raw_name: &str) -> Result<(), StoreError> {
        let name = raw_name.strip_prefix('@').unwrap_or(raw_name);
        let name_bytes = name.as_bytes();
        for r in &mut self.refs[..self.ref_count] {
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
        for r in &mut self.refs[..self.ref_count] {
            if r.name_bytes() == name_bytes {
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

    #[inline]
    pub fn object_count(&self) -> usize {
        self.object_count
    }

    pub fn for_each_object(&self, mut f: impl FnMut(ObjectMeta)) {
        for b in &self.blobs[..self.object_count] {
            f(ObjectMeta {
                hash: b.hash,
                size: b.size,
            });
        }
    }

    pub fn for_each_ref(&self, mut f: impl FnMut(RefMeta)) {
        for r in &self.refs[..self.ref_count] {
            f(RefMeta {
                name: r.name,
                name_len: r.name_len,
                target: r.target,
                prev: r.prev,
                writable: r.rights.contains(Rights::WRITE),
            });
        }
    }

    pub fn collect_objects(&self, out: &mut [Option<ObjectMeta>]) -> usize {
        let n = self.object_count.min(out.len());
        for (dst, b) in out[..n].iter_mut().zip(&self.blobs[..n]) {
            *dst = Some(ObjectMeta {
                hash: b.hash,
                size: b.size,
            });
        }
        n
    }

    pub fn collect_refs(&self, out: &mut [Option<RefMeta>]) -> usize {
        let n = self.ref_count.min(out.len());
        for (dst, r) in out[..n].iter_mut().zip(&self.refs[..n]) {
            *dst = Some(RefMeta {
                name: r.name,
                name_len: r.name_len,
                target: r.target,
                prev: r.prev,
                writable: r.rights.contains(Rights::WRITE),
            });
        }
        n
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
        assert_eq!(store.rollback_ref("@cfg"), Err(StoreError::NoPreviousVersion));

        store.set_ref("@cfg", h2).unwrap();
        assert_eq!(store.get_any("@cfg").unwrap(), (h2, b"v2".as_slice()));

        let rolled = store.rollback_ref("@cfg").unwrap();
        assert_eq!(rolled, h1);
        assert_eq!(store.get_any("@cfg").unwrap(), (h1, b"v1".as_slice()));
        assert_eq!(store.rollback_ref("@cfg"), Err(StoreError::NoPreviousVersion));

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
    }
}
