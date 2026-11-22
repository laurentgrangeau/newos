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

        // Content deduplication & collision rejection: single-pass bounded scan over live packed blobs.
        for slot in &self.blobs[..self.object_count] {
            if slot.hash == hash {
                if &slot.data[..slot.size] == bytes {
                    return Ok(hash);
                }
                return Err(StoreError::HashCollision);
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

    /// Mark-and-sweep garbage collection: reclaim all immutable blobs not reachable
    /// from any active Ref's `target` or `prev` rollback pointer.
    ///
    /// Returns the number of reclaimed object slots.
    pub fn gc(&mut self) -> usize {
        let mut write_idx = 0usize;
        let orig_count = self.object_count;
        for read_idx in 0..orig_count {
            let hash = self.blobs[read_idx].hash;
            let reachable = self.refs[..self.ref_count]
                .iter()
                .any(|r| r.target == hash || r.prev == Some(hash));
            if reachable {
                if write_idx != read_idx {
                    self.blobs[write_idx] = self.blobs[read_idx];
                }
                write_idx += 1;
            }
        }
        for slot in &mut self.blobs[write_idx..orig_count] {
            *slot = BlobSlot::EMPTY;
        }
        self.object_count = write_idx;
        orig_count - write_idx
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
        push(&[1u8, self.object_count as u8, self.ref_count as u8, 0u8])?;

        for b in &self.blobs[..self.object_count] {
            push(&b.hash.0.to_le_bytes())?;
            push(&(b.size as u16).to_le_bytes())?;
            push(&b.data[..b.size])?;
        }

        for r in &self.refs[..self.ref_count] {
            push(&[r.name_len as u8, r.rights.bits()])?;
            push(&r.name[..r.name_len])?;
            push(&r.target.0.to_le_bytes())?;
            push(&r.prev.map_or(0u64, |p| p.0).to_le_bytes())?;
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
        if bytes.len() < 16 || &bytes[0..4] != b"CAOS" || bytes[4] != 1 {
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
            let end = pos
                .checked_add(len)
                .ok_or(StoreError::CorruptSnapshot)?;
            if end > body_len {
                return Err(StoreError::CorruptSnapshot);
            }
            let slice = &bytes[pos..end];
            pos = end;
            Ok(slice)
        };

        let mut store = Self {
            blobs: [BlobSlot::EMPTY; MAX_OBJECTS],
            object_count: obj_count,
            refs: [RefSlot::EMPTY; MAX_REFS],
            ref_count,
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
            if store.blobs[..i].iter().any(|prev| prev.hash == hash) {
                return Err(StoreError::CorruptSnapshot);
            }
            let b = &mut store.blobs[i];
            b.hash = hash;
            b.size = size;
            b.data[..size].copy_from_slice(data);
        }

        for i in 0..ref_count {
            let hdr = take(2)?;
            let name_len = hdr[0] as usize;
            let rights = Rights::from_bits_truncate(hdr[1]);
            if name_len == 0 || name_len > MAX_REF_NAME {
                return Err(StoreError::CorruptSnapshot);
            }
            let name = take(name_len)?;
            if core::str::from_utf8(name).is_err() {
                return Err(StoreError::CorruptSnapshot);
            }
            // Reject duplicate ref names (`M-4`).
            if store.refs[..i].iter().any(|prev| prev.name_bytes() == name) {
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
            let prev = if prev_raw == 0 {
                None
            } else {
                Some(ObjHash(prev_raw))
            };
            // Verify referential integrity: `target` and `prev` must exist in `store.blobs` (`M-4`).
            if !store.blobs[..obj_count].iter().any(|b| b.hash == target) {
                return Err(StoreError::CorruptSnapshot);
            }
            if let Some(p) = prev
                && !store.blobs[..obj_count].iter().any(|b| b.hash == p)
            {
                return Err(StoreError::CorruptSnapshot);
            }
            let r = &mut store.refs[i];
            r.name[..name_len].copy_from_slice(name);
            r.name_len = name_len;
            r.rights = rights;
            r.target = target;
            r.prev = prev;
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
        store.refs[0].rights = Rights::READ.union(Rights::WRITE);
        let mut buf = [0u8; 4096];
        let written = store.encode_snapshot(&mut buf).unwrap();
        assert!(matches!(
            ObjectStore::decode_snapshot(&buf[..written]),
            Err(StoreError::CorruptSnapshot)
        ));
    }
}
