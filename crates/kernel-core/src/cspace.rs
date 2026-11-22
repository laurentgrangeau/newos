//! Pure seL4-style Capability Space (`CSpace`) and inline Capability Derivation Tree (CDT).
//!
//! 100% `#![forbid(unsafe_code)]`, zero kernel heap (`no_alloc`), generational `CapId` handles,
//! non-escalating rights attenuation, immutable badging, and transitive `revoke`.

use crate::memory::{PhysAddr, UntypedInventory};
use newos_abi::{CapId, ObjectType, Rights, SysError};

/// Typed kernel object referenced by an unforgeable capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapObject {
    Untyped { region_index: u16 },
    Frame { phys: PhysAddr },
    VSpace { root_phys: PhysAddr },
    CNode { id: u32 },
    Thread { id: u32 },
    Endpoint { id: u32 },
    Notification { id: u32 },
    IrqHandler { irq: u16 },
    MmioRegion { phys: PhysAddr, len: u64 },
}

impl CapObject {
    #[inline]
    pub const fn object_type(self) -> ObjectType {
        match self {
            Self::Untyped { .. } => ObjectType::Untyped,
            Self::Frame { .. } => ObjectType::Frame,
            Self::VSpace { .. } => ObjectType::VSpace,
            Self::CNode { .. } => ObjectType::CNode,
            Self::Thread { .. } => ObjectType::Thread,
            Self::Endpoint { .. } => ObjectType::Endpoint,
            Self::Notification { .. } => ObjectType::Notification,
            Self::IrqHandler { .. } => ObjectType::IrqHandler,
            Self::MmioRegion { .. } => ObjectType::MmioRegion,
        }
    }
}

/// Unforgeable capability entry combining a kernel object, attenuated rights, and optional badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub object: CapObject,
    pub rights: Rights,
    pub badge: u64,
}

impl Capability {
    #[inline]
    pub const fn new(object: CapObject, rights: Rights) -> Self {
        Self {
            object,
            rights,
            badge: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CapSlot {
    cap: Option<Capability>,
    generation: u32,
    parent: Option<usize>,
}

impl CapSlot {
    const EMPTY: Self = Self {
        cap: None,
        generation: 1,
        parent: None,
    };

    #[inline(always)]
    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
    }
}

#[inline(always)]
const fn encode_cap_id(slot: usize, generation: u32) -> CapId {
    CapId::new(((generation as u64) << 32) | (slot as u32 as u64))
}

#[inline(always)]
const fn decode_cap_id(id: CapId) -> (usize, u32) {
    let raw = id.raw();
    let slot = (raw & 0xFFFF_FFFF) as usize;
    let generation = (raw >> 32) as u32;
    (slot, generation)
}

/// Fixed-capacity, `no_alloc` capability table with inline Capability Derivation Tree (CDT).
///
/// Slot `0` is permanently reserved for `CapId::NULL`.
pub struct CNode<const SLOTS: usize> {
    slots: [CapSlot; SLOTS],
    occupied_mask: u64,
    derived_mask: u64,
}

impl<const SLOTS: usize> Default for CNode<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> CNode<SLOTS> {
    const VALID_MASK: u64 = if SLOTS <= 1 {
        0
    } else if SLOTS >= 64 {
        !1u64
    } else {
        ((1u64 << SLOTS) - 1) & !1u64
    };

    pub const fn new() -> Self {
        Self {
            slots: [CapSlot::EMPTY; SLOTS],
            occupied_mask: 0,
            derived_mask: 0,
        }
    }

    /// Find the first free slot index (`1..SLOTS`).
    #[inline(always)]
    pub fn find_free_slot(&self) -> Result<usize, SysError> {
        let free = Self::VALID_MASK & !self.occupied_mask;
        if free != 0 {
            return Ok(free.trailing_zeros() as usize);
        }
        if SLOTS > 64 {
            for (idx, slot) in self.slots.iter().enumerate().skip(64) {
                if slot.cap.is_none() {
                    return Ok(idx);
                }
            }
        }
        Err(SysError::OutOfMemory)
    }

    #[inline(always)]
    fn validate_cap(&self, id: CapId) -> Result<(usize, &Capability), SysError> {
        let (idx, generation) = decode_cap_id(id);
        if idx == 0 || idx >= SLOTS {
            return Err(SysError::InvalidCapability);
        }
        let slot = &self.slots[idx];
        if slot.generation != generation {
            return Err(SysError::InvalidCapability);
        }
        let cap = slot.cap.as_ref().ok_or(SysError::InvalidCapability)?;
        Ok((idx, cap))
    }

    #[inline]
    fn insert_at(
        &mut self,
        dst_slot: usize,
        cap: Capability,
        parent: Option<usize>,
    ) -> Result<CapId, SysError> {
        if dst_slot == 0 || dst_slot >= SLOTS {
            return Err(SysError::InvalidArgument);
        }
        if self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }
        self.slots[dst_slot].cap = Some(cap);
        self.slots[dst_slot].parent = parent;
        if dst_slot < 64 {
            let bit = 1u64 << dst_slot;
            self.occupied_mask |= bit;
            if parent.is_some() {
                self.derived_mask |= bit;
            }
        }
        Ok(encode_cap_id(dst_slot, self.slots[dst_slot].generation))
    }

    /// Insert a root capability (e.g. during bootstrap) into the first free slot.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, SysError> {
        let dst = self.find_free_slot()?;
        self.insert_at(dst, cap, None)
    }

    /// Resolve a `CapId` and verify it carries at least `required` rights.
    #[inline(always)]
    pub fn lookup(&self, id: CapId, required: Rights) -> Result<&Capability, SysError> {
        let (_, cap) = self.validate_cap(id)?;
        if !cap.rights.contains(required) {
            return Err(SysError::InsufficientRights);
        }
        Ok(cap)
    }

    /// Derive a new capability with strictly attenuated rights and an optional immutable badge.
    #[inline]
    pub fn mint(
        &mut self,
        src: CapId,
        dst_slot: usize,
        rights_mask: Rights,
        new_badge: Option<u64>,
    ) -> Result<CapId, SysError> {
        let (src_idx, src_cap) = {
            let (idx, cap) = self.validate_cap(src)?;
            (idx, *cap)
        };

        if !src_cap.rights.contains(Rights::GRANT) {
            return Err(SysError::InsufficientRights);
        }

        let badge = match new_badge {
            None => src_cap.badge,
            Some(b) => {
                // seL4 invariant: once a capability is badged, its badge cannot be altered.
                if src_cap.badge != 0 {
                    return Err(SysError::InsufficientRights);
                }
                b
            }
        };

        let derived = Capability {
            object: src_cap.object,
            rights: src_cap.rights.attenuate(rights_mask),
            badge,
        };
        self.insert_at(dst_slot, derived, Some(src_idx))
    }

    /// Copy a capability verbatim into `dst_slot` (requires `Rights::GRANT`).
    #[inline]
    pub fn copy(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        self.mint(src, dst_slot, Rights::ALL, None)
    }

    /// Move a capability to `dst_slot`, invalidating the old `CapId` and preserving CDT links.
    pub fn move_cap(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        let (src_idx, _) = self.validate_cap(src)?;
        if dst_slot == 0 || dst_slot >= SLOTS {
            return Err(SysError::InvalidArgument);
        }
        if dst_slot == src_idx || self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }

        let cap = self.slots[src_idx]
            .cap
            .take()
            .ok_or(SysError::InvalidCapability)?;
        let parent = self.slots[src_idx].parent.take();
        self.slots[src_idx].bump_generation();
        if src_idx < 64 {
            let bit = 1u64 << src_idx;
            self.occupied_mask &= !bit;
            self.derived_mask &= !bit;
        }

        // Reparent any direct CDT children from `src_idx` to `dst_slot`.
        if SLOTS <= 64 {
            let mut scan = self.derived_mask;
            while scan != 0 {
                let idx = scan.trailing_zeros() as usize;
                scan &= scan - 1;
                if self.slots[idx].parent == Some(src_idx) {
                    self.slots[idx].parent = Some(dst_slot);
                }
            }
        } else {
            for slot in &mut self.slots[1..SLOTS] {
                if slot.cap.is_some() && slot.parent == Some(src_idx) {
                    slot.parent = Some(dst_slot);
                }
            }
        }

        self.insert_at(dst_slot, cap, parent)
    }

    /// Delete a single capability slot (without revoking its descendants).
    pub fn delete(&mut self, id: CapId) -> Result<(), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        let parent = self.slots[idx].parent.take();
        self.slots[idx].cap = None;
        self.slots[idx].bump_generation();
        if idx < 64 {
            let bit = 1u64 << idx;
            self.occupied_mask &= !bit;
            self.derived_mask &= !bit;
        }

        // Preserve CDT ancestry by reparenting direct children to the deleted slot's parent.
        if SLOTS <= 64 {
            let mut scan = self.derived_mask;
            while scan != 0 {
                let child_idx = scan.trailing_zeros() as usize;
                scan &= scan - 1;
                if self.slots[child_idx].parent == Some(idx) {
                    self.slots[child_idx].parent = parent;
                    if parent.is_none() {
                        self.derived_mask &= !(1u64 << child_idx);
                    }
                }
            }
        } else {
            for child_idx in 1..SLOTS {
                if self.slots[child_idx].cap.is_some() && self.slots[child_idx].parent == Some(idx)
                {
                    self.slots[child_idx].parent = parent;
                    if parent.is_none() && child_idx < 64 {
                        self.derived_mask &= !(1u64 << child_idx);
                    }
                }
            }
        }
        Ok(())
    }

    /// Transitively revoke all descendants derived from `id` (leaving `id` itself intact).
    ///
    /// Requires `Rights::REVOKE`. Uses an iterative, zero-heap fixed-point scan over `SLOTS`.
    pub fn revoke(&mut self, id: CapId) -> Result<usize, SysError> {
        let (root_idx, root_rights) = {
            let (idx, cap) = self.validate_cap(id)?;
            (idx, cap.rights)
        };
        if !root_rights.contains(Rights::REVOKE) {
            return Err(SysError::InsufficientRights);
        }

        if SLOTS <= 64 {
            let mut candidates = self.derived_mask & !(1u64 << root_idx);
            let mut marked = 0u64;
            let mut frontier = 1u64 << root_idx;
            while frontier != 0 && candidates != 0 {
                let mut next_frontier = 0u64;
                let mut active = frontier;
                let mut scan = candidates;
                while scan != 0 {
                    let idx = scan.trailing_zeros() as usize;
                    let bit = 1u64 << idx;
                    scan &= !bit;
                    if let Some(p) = self.slots[idx].parent
                        && (active & (1u64 << p)) != 0
                    {
                        marked |= bit;
                        next_frontier |= bit;
                        active |= bit;
                        candidates &= !bit;
                    }
                }
                frontier = next_frontier;
            }

            if marked == 0 {
                return Ok(0);
            }
            self.occupied_mask &= !marked;
            self.derived_mask &= !marked;
            let revoked_count = marked.count_ones() as usize;
            let mut clear = marked;
            while clear != 0 {
                let idx = clear.trailing_zeros() as usize;
                clear &= clear - 1;
                self.slots[idx].cap = None;
                self.slots[idx].parent = None;
                self.slots[idx].bump_generation();
            }
            return Ok(revoked_count);
        }

        let mut marked = [false; SLOTS];
        let mut changed = true;
        while changed {
            changed = false;
            for idx in 1..SLOTS {
                if marked[idx] || self.slots[idx].cap.is_none() {
                    continue;
                }
                if let Some(p) = self.slots[idx].parent
                    && (p == root_idx || marked[p])
                {
                    marked[idx] = true;
                    changed = true;
                }
            }
        }

        let mut revoked_count = 0usize;
        for (idx, should_revoke) in marked.iter().enumerate().skip(1) {
            if *should_revoke {
                self.slots[idx].cap = None;
                self.slots[idx].parent = None;
                self.slots[idx].bump_generation();
                if idx < 64 {
                    let bit = 1u64 << idx;
                    self.occupied_mask &= !bit;
                    self.derived_mask &= !bit;
                }
                revoked_count += 1;
            }
        }
        Ok(revoked_count)
    }

    /// Pure seL4 `Untyped` -> `Frame` retype: verifies `untyped_cap` carries `Rights::WRITE`,
    /// carves a 4 KiB physical frame from `inv`, and installs a derived `Frame` capability.
    pub fn retype_frame_from(
        &mut self,
        untyped_cap: CapId,
        inv: &mut UntypedInventory,
    ) -> Result<CapId, SysError> {
        let (parent_idx, cap) = {
            let (idx, cap) = self.validate_cap(untyped_cap)?;
            (idx, *cap)
        };

        if !matches!(cap.object, CapObject::Untyped { .. }) {
            return Err(SysError::InvalidArgument);
        }
        if !cap.rights.contains(Rights::WRITE) {
            return Err(SysError::InsufficientRights);
        }

        let dst_slot = self.find_free_slot()?;
        let frame = inv.retype_frame()?;
        let frame_cap = Capability::new(
            CapObject::Frame {
                phys: frame.start_addr(),
            },
            Rights::ALL,
        );
        self.insert_at(dst_slot, frame_cap, Some(parent_idx))
    }

    /// Count currently occupied capability slots.
    #[inline]
    pub fn occupied_count(&self) -> usize {
        if SLOTS <= 64 {
            self.occupied_mask.count_ones() as usize
        } else {
            self.occupied_mask.count_ones() as usize
                + self.slots[64..].iter().filter(|s| s.cap.is_some()).count()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::PAGE_SIZE;

    #[test]
    fn lookup_rejects_null_and_stale_generation() {
        let mut cnode = CNode::<16>::new();
        assert_eq!(
            cnode.lookup(CapId::NULL, Rights::NONE),
            Err(SysError::InvalidCapability)
        );

        let cap = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
            .expect("insert");
        assert!(cnode.lookup(cap, Rights::READ).is_ok());

        cnode.delete(cap).expect("delete");
        assert_eq!(
            cnode.lookup(cap, Rights::NONE),
            Err(SysError::InvalidCapability)
        );

        // Re-using the same slot must still reject the stale CapId due to generation bump
        let cap2 = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
            .expect("reinsert");
        assert_ne!(cap, cap2);
        assert_eq!(
            cnode.lookup(cap, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn mint_attenuates_rights_and_forbids_escalation() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(
                CapObject::Endpoint { id: 7 },
                Rights::READ.union(Rights::GRANT),
            ))
            .expect("root");

        // Trying to mint with Rights::ALL must still only yield READ (never WRITE/EXEC/REVOKE)
        let child = cnode
            .mint(root, 2, Rights::READ.union(Rights::WRITE), Some(0x42))
            .expect("mint");
        let resolved = cnode.lookup(child, Rights::READ).expect("lookup");
        assert_eq!(resolved.badge, 0x42);
        assert!(!resolved.rights.contains(Rights::WRITE));
        assert!(!resolved.rights.contains(Rights::GRANT));

        // Child lacks GRANT so further minting must fail
        assert_eq!(
            cnode.mint(child, 3, Rights::READ, None),
            Err(SysError::InsufficientRights)
        );
    }

    #[test]
    fn mint_enforces_badge_immutability() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(CapObject::Notification { id: 3 }, Rights::ALL))
            .expect("root");
        let badged = cnode
            .mint(root, 2, Rights::ALL, Some(0xAA))
            .expect("first badge");

        // Attempting to re-badge an already badged capability must fail
        assert_eq!(
            cnode.mint(badged, 3, Rights::READ, Some(0xBB)),
            Err(SysError::InsufficientRights)
        );

        // Copying without changing badge preserves 0xAA
        let copied = cnode.copy(badged, 3).expect("copy");
        assert_eq!(cnode.lookup(copied, Rights::READ).unwrap().badge, 0xAA);
    }

    #[test]
    fn move_invalidates_old_cap_and_preserves_children() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 9 }, Rights::ALL))
            .expect("root");
        let child = cnode.copy(root, 2).expect("child");

        let moved = cnode.move_cap(root, 5).expect("move");
        assert_eq!(
            cnode.lookup(root, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert!(cnode.lookup(moved, Rights::REVOKE).is_ok());

        // Revoking the moved parent must still transitively revoke `child`
        assert_eq!(cnode.revoke(moved), Ok(1));
        assert_eq!(
            cnode.lookup(child, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn revoke_cascades_to_all_descendants_only() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
            .expect("root");
        let unrelated = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
            .expect("unrelated");

        let child = cnode.copy(root, 3).expect("child");
        let grandchild = cnode.mint(child, 4, Rights::READ, Some(1)).expect("grandchild");

        assert_eq!(cnode.revoke(root), Ok(2));
        assert!(cnode.lookup(root, Rights::ALL).is_ok());
        assert!(cnode.lookup(unrelated, Rights::ALL).is_ok());
        assert_eq!(
            cnode.lookup(child, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            cnode.lookup(grandchild, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn retype_frame_from_untyped_cap_creates_derived_frame_cap() {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x20_0000, PAGE_SIZE * 2));

        let mut cnode = CNode::<16>::new();
        let untyped = cnode
            .insert_root(Capability::new(
                CapObject::Untyped { region_index: 0 },
                Rights::ALL,
            ))
            .expect("untyped root");

        let frame_cap = cnode
            .retype_frame_from(untyped, &mut inv)
            .expect("retype frame");
        let resolved = cnode.lookup(frame_cap, Rights::READ).expect("lookup frame");
        assert_eq!(resolved.object.object_type(), ObjectType::Frame);

        // Revoking the Untyped capability cascades to the derived Frame capability
        assert_eq!(cnode.revoke(untyped), Ok(1));
        assert_eq!(
            cnode.lookup(frame_cap, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn cnode_edge_sizes_zero_one_sixty_four_and_over_sixty_four() {
        let c0 = CNode::<0>::new();
        assert_eq!(c0.find_free_slot(), Err(SysError::OutOfMemory));
        assert_eq!(c0.occupied_count(), 0);
        assert_eq!(c0.lookup(CapId::new(1), Rights::NONE), Err(SysError::InvalidCapability));

        let c1 = CNode::<1>::new();
        assert_eq!(c1.find_free_slot(), Err(SysError::OutOfMemory));
        assert_eq!(c1.occupied_count(), 0);

        // CNode::<64> has 63 usable slots (1..=63).
        let mut c64 = CNode::<64>::new();
        let mut caps64 = [CapId::NULL; 63];
        for (i, slot_cap) in caps64.iter_mut().enumerate() {
            *slot_cap = c64
                .insert_root(Capability::new(CapObject::Endpoint { id: i as u32 }, Rights::ALL))
                .expect("fill c64");
        }
        assert_eq!(c64.occupied_count(), 63);
        assert_eq!(c64.find_free_slot(), Err(SysError::OutOfMemory));

        // Delete slot 1 and slot 63, then re-allocate.
        c64.delete(caps64[0]).unwrap();
        c64.delete(caps64[62]).unwrap();
        assert_eq!(c64.occupied_count(), 61);
        assert_eq!(c64.find_free_slot(), Ok(1));
        let _ = c64
            .insert_root(Capability::new(CapObject::Endpoint { id: 100 }, Rights::ALL))
            .unwrap();
        assert_eq!(c64.find_free_slot(), Ok(63));

        // CNode::<80> fallback exercises slots >= 64 and cross-boundary revoke.
        let mut c80 = CNode::<80>::new();
        let root = c80
            .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
            .unwrap();
        for i in 1..63 {
            let _ = c80
                .insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))
                .unwrap();
        }
        assert_eq!(c80.find_free_slot(), Ok(64));
        let child64 = c80.copy(root, 64).unwrap();
        let grandchild70 = c80.copy(child64, 70).unwrap();
        assert_eq!(c80.occupied_count(), 65);
        assert_eq!(c80.revoke(root), Ok(2));
        assert_eq!(c80.occupied_count(), 63);
        assert_eq!(c80.lookup(child64, Rights::NONE), Err(SysError::InvalidCapability));
        assert_eq!(c80.lookup(grandchild70, Rights::NONE), Err(SysError::InvalidCapability));
    }

    #[test]
    fn revoke_out_of_order_deep_chain_and_delete_reparenting() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
            .unwrap(); // slot 1
        // Out-of-order descending slot indices: root(1) -> child(10) -> grandchild(3) -> great_grandchild(2).
        let child = cnode.copy(root, 10).unwrap();
        let grandchild = cnode.copy(child, 3).unwrap();
        let great_grandchild = cnode.copy(grandchild, 2).unwrap();

        assert_eq!(cnode.revoke(root), Ok(3));
        assert_eq!(cnode.lookup(child, Rights::NONE), Err(SysError::InvalidCapability));
        assert_eq!(cnode.lookup(grandchild, Rights::NONE), Err(SysError::InvalidCapability));
        assert_eq!(cnode.lookup(great_grandchild, Rights::NONE), Err(SysError::InvalidCapability));
        assert_eq!(cnode.occupied_count(), 1);

        // Test delete(child) reparents grandchild to root so revoke(root) still revokes grandchild.
        let child2 = cnode.copy(root, 8).unwrap();
        let grandchild2 = cnode.copy(child2, 4).unwrap();
        cnode.delete(child2).unwrap();
        assert_eq!(cnode.revoke(root), Ok(1));
        assert_eq!(cnode.lookup(grandchild2, Rights::NONE), Err(SysError::InvalidCapability));

        // Test delete(root) promotes child to root so revoking unrelated caps never touches it.
        let other = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
            .unwrap();
        let promoted = cnode.copy(root, 9).unwrap();
        cnode.delete(root).unwrap();
        assert_eq!(cnode.revoke(other), Ok(0));
        assert!(cnode.lookup(promoted, Rights::ALL).is_ok());
    }
}
