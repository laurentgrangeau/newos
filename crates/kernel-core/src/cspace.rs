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

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
    }
}

#[inline]
const fn encode_cap_id(slot: usize, generation: u32) -> CapId {
    CapId::new(((generation as u64) << 32) | (slot as u32 as u64))
}

#[inline]
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
}

impl<const SLOTS: usize> Default for CNode<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> CNode<SLOTS> {
    pub const fn new() -> Self {
        Self {
            slots: [CapSlot::EMPTY; SLOTS],
        }
    }

    /// Find the first free slot index (`1..SLOTS`).
    pub fn find_free_slot(&self) -> Result<usize, SysError> {
        for (idx, slot) in self.slots.iter().enumerate().skip(1) {
            if slot.cap.is_none() {
                return Ok(idx);
            }
        }
        Err(SysError::OutOfMemory)
    }

    fn validate_slot_for_cap(&self, id: CapId) -> Result<usize, SysError> {
        if id.is_null() {
            return Err(SysError::InvalidCapability);
        }
        let (idx, generation) = decode_cap_id(id);
        if idx == 0 || idx >= SLOTS {
            return Err(SysError::InvalidCapability);
        }
        let slot = &self.slots[idx];
        if slot.cap.is_none() || slot.generation != generation {
            return Err(SysError::InvalidCapability);
        }
        Ok(idx)
    }

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
        Ok(encode_cap_id(dst_slot, self.slots[dst_slot].generation))
    }

    /// Insert a root capability (e.g. during bootstrap) into the first free slot.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, SysError> {
        let dst = self.find_free_slot()?;
        self.insert_at(dst, cap, None)
    }

    /// Resolve a `CapId` and verify it carries at least `required` rights.
    pub fn lookup(&self, id: CapId, required: Rights) -> Result<&Capability, SysError> {
        let idx = self.validate_slot_for_cap(id)?;
        let cap = self.slots[idx]
            .cap
            .as_ref()
            .ok_or(SysError::InvalidCapability)?;
        if !cap.rights.contains(required) {
            return Err(SysError::InsufficientRights);
        }
        Ok(cap)
    }

    /// Derive a new capability with strictly attenuated rights and an optional immutable badge.
    pub fn mint(
        &mut self,
        src: CapId,
        dst_slot: usize,
        rights_mask: Rights,
        new_badge: Option<u64>,
    ) -> Result<CapId, SysError> {
        let src_idx = self.validate_slot_for_cap(src)?;
        let src_cap = self.slots[src_idx]
            .cap
            .ok_or(SysError::InvalidCapability)?;

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
    pub fn copy(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        self.mint(src, dst_slot, Rights::ALL, None)
    }

    /// Move a capability to `dst_slot`, invalidating the old `CapId` and preserving CDT links.
    pub fn move_cap(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        let src_idx = self.validate_slot_for_cap(src)?;
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

        // Reparent any direct CDT children from `src_idx` to `dst_slot`.
        for slot in &mut self.slots[1..SLOTS] {
            if slot.cap.is_some() && slot.parent == Some(src_idx) {
                slot.parent = Some(dst_slot);
            }
        }

        self.insert_at(dst_slot, cap, parent)
    }

    /// Delete a single capability slot (without revoking its descendants).
    pub fn delete(&mut self, id: CapId) -> Result<(), SysError> {
        let idx = self.validate_slot_for_cap(id)?;
        let parent = self.slots[idx].parent.take();
        self.slots[idx].cap = None;
        self.slots[idx].bump_generation();

        // Preserve CDT ancestry by reparenting direct children to the deleted slot's parent.
        for slot in &mut self.slots[1..SLOTS] {
            if slot.cap.is_some() && slot.parent == Some(idx) {
                slot.parent = parent;
            }
        }
        Ok(())
    }

    /// Transitively revoke all descendants derived from `id` (leaving `id` itself intact).
    ///
    /// Requires `Rights::REVOKE`. Uses an iterative, zero-heap fixed-point scan over `SLOTS`.
    pub fn revoke(&mut self, id: CapId) -> Result<usize, SysError> {
        let root_idx = self.validate_slot_for_cap(id)?;
        let root_cap = self.slots[root_idx]
            .cap
            .ok_or(SysError::InvalidCapability)?;
        if !root_cap.rights.contains(Rights::REVOKE) {
            return Err(SysError::InsufficientRights);
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
        let parent_idx = self.validate_slot_for_cap(untyped_cap)?;
        let cap = self.slots[parent_idx]
            .cap
            .ok_or(SysError::InvalidCapability)?;

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
    pub fn occupied_count(&self) -> usize {
        self.slots[1..SLOTS]
            .iter()
            .filter(|s| s.cap.is_some())
            .count()
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
}
