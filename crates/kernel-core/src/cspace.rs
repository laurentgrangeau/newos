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
    Console,
    PowerControl,
    IoSpace { domain_id: u16 },
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
            Self::Console => ObjectType::Console,
            Self::PowerControl => ObjectType::PowerControl,
            Self::IoSpace { .. } => ObjectType::IoSpace,
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

/// Cross-`CNode` CDT parent link identifying the `(cnode_id, slot)` that granted a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalParent {
    pub cnode_id: u16,
    pub slot: u16,
}

#[derive(Debug, Clone, Copy)]
struct CapSlot {
    cap: Option<Capability>,
    generation: u32,
    parent: u16,   // 0 = None (slot 0 is permanently reserved for CapId::NULL)
    ext_cnode: u8, // external CNode ID when ext_slot != 0
    ext_slot: u8,  // 0 = None (slot 0 is permanently reserved for CapId::NULL)
}

const _: () = assert!(core::mem::size_of::<CapSlot>() <= 48);

impl CapSlot {
    const EMPTY: Self = Self {
        cap: None,
        generation: 1,
        parent: 0,
        ext_cnode: 0,
        ext_slot: 0,
    };

    #[inline(always)]
    fn parent_slot(&self) -> Option<usize> {
        (self.parent != 0).then_some(self.parent as usize)
    }

    #[inline(always)]
    fn take_parent_slot(&mut self) -> Option<usize> {
        let p = self.parent_slot();
        self.parent = 0;
        p
    }

    #[inline(always)]
    fn external_parent(&self) -> Option<ExternalParent> {
        (self.ext_slot != 0).then_some(ExternalParent {
            cnode_id: self.ext_cnode as u16,
            slot: self.ext_slot as u16,
        })
    }

    #[inline(always)]
    fn set_external_parent(&mut self, ext: Option<ExternalParent>) -> Result<(), SysError> {
        match ext {
            None => {
                self.ext_cnode = 0;
                self.ext_slot = 0;
                Ok(())
            }
            Some(ep)
                if ep.cnode_id <= u8::MAX as u16 && ep.slot != 0 && ep.slot <= u8::MAX as u16 =>
            {
                self.ext_cnode = ep.cnode_id as u8;
                self.ext_slot = ep.slot as u8;
                Ok(())
            }
            Some(_) => Err(SysError::InvalidArgument),
        }
    }

    #[inline(always)]
    fn take_external_parent(&mut self) -> Option<ExternalParent> {
        let ext = self.external_parent();
        self.ext_cnode = 0;
        self.ext_slot = 0;
        ext
    }

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
    has_children_mask: u64,
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
            has_children_mask: 0,
        }
    }

    /// Return `true` if any live slot in this `CNode` holds a `CapObject::Frame { phys }` capability.
    #[inline]
    pub fn has_live_frame_cap(&self, phys: PhysAddr) -> bool {
        let mut mask = self.occupied_mask;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if let Some(cap) = &self.slots[idx].cap
                && cap.object == (CapObject::Frame { phys })
            {
                return true;
            }
        }
        if SLOTS > 64 {
            for slot in self.slots.iter().skip(64) {
                if let Some(cap) = &slot.cap
                    && cap.object == (CapObject::Frame { phys })
                {
                    return true;
                }
            }
        }
        false
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
        if dst_slot == 0 || dst_slot >= SLOTS || dst_slot > u16::MAX as usize {
            return Err(SysError::InvalidArgument);
        }
        let parent_u16 = match parent {
            None => 0u16,
            Some(p) if p != 0 && p <= u16::MAX as usize => p as u16,
            Some(_) => return Err(SysError::InvalidArgument),
        };
        if self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }
        self.slots[dst_slot].cap = Some(cap);
        self.slots[dst_slot].parent = parent_u16;
        self.slots[dst_slot].ext_cnode = 0;
        self.slots[dst_slot].ext_slot = 0;
        if dst_slot < 64 {
            let bit = 1u64 << dst_slot;
            self.occupied_mask |= bit;
            if parent.is_some() {
                self.derived_mask |= bit;
            }
        }
        if let Some(p) = parent
            && p < 64
        {
            self.has_children_mask |= 1u64 << p;
        }
        Ok(encode_cap_id(dst_slot, self.slots[dst_slot].generation))
    }

    /// Insert a cross-process granted capability with an explicit `ExternalParent` CDT link.
    pub fn insert_external_derived(
        &mut self,
        cap: Capability,
        ext_parent: ExternalParent,
    ) -> Result<CapId, SysError> {
        if ext_parent.cnode_id > u8::MAX as u16
            || ext_parent.slot == 0
            || ext_parent.slot > u8::MAX as u16
        {
            return Err(SysError::InvalidArgument);
        }
        let dst = self.find_free_slot()?;
        let id = self.insert_at(dst, cap, None)?;
        self.slots[dst].set_external_parent(Some(ext_parent))?;
        Ok(id)
    }

    /// Return the slot index of a valid `CapId` (for CDT parent tracking).
    #[inline]
    pub fn slot_index(&self, id: CapId) -> Result<usize, SysError> {
        let (idx, _) = self.validate_cap(id)?;
        Ok(idx)
    }

    /// Inspect `(intra_parent_slot, external_parent)` of a valid `CapId`.
    #[inline]
    pub fn parent_info(
        &self,
        id: CapId,
    ) -> Result<(usize, Option<usize>, Option<ExternalParent>), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        Ok((
            idx,
            self.slots[idx].parent_slot(),
            self.slots[idx].external_parent(),
        ))
    }

    /// Reparent any slots in this `CNode` whose `external_parent == Some(old)` to `new`.
    pub fn reparent_external_children(&mut self, old: ExternalParent, new: Option<ExternalParent>) {
        if SLOTS <= 1 {
            return;
        }
        for slot in &mut self.slots[1..SLOTS] {
            if slot.cap.is_some()
                && slot.external_parent() == Some(old)
                && slot.set_external_parent(new).is_err()
            {
                slot.ext_cnode = 0;
                slot.ext_slot = 0;
            }
        }
    }

    /// Insert a root capability (e.g. during bootstrap) into the first free slot.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, SysError> {
        let dst = self.find_free_slot()?;
        self.insert_at(dst, cap, None)
    }

    /// Insert a root capability into an explicit slot index (`1..SLOTS`), ensuring deterministic
    /// bootstrap `CapId`s even when optional hardware capabilities (e.g. `BOOTSTRAP_NET_MMIO`) are absent.
    pub fn insert_root_at(&mut self, dst_slot: usize, cap: Capability) -> Result<CapId, SysError> {
        self.insert_at(dst_slot, cap, None)
    }

    /// Bind the hardware root physical address on an existing `CapObject::VSpace` capability during boot.
    pub fn bind_vspace_root(&mut self, id: CapId, root_phys: PhysAddr) -> Result<(), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        let Some(cap) = self.slots[idx].cap.as_mut() else {
            return Err(SysError::InvalidCapability);
        };
        match &mut cap.object {
            CapObject::VSpace {
                root_phys: slot_root,
            } => {
                *slot_root = root_phys;
                Ok(())
            }
            _ => Err(SysError::InvalidArgument),
        }
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
            Some(0) => {
                // Badge 0 is the unbadged sentinel; reject explicit Some(0) to prevent re-badging.
                return Err(SysError::InvalidArgument);
            }
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
        if dst_slot == 0 || dst_slot >= SLOTS || dst_slot > u16::MAX as usize {
            return Err(SysError::InvalidArgument);
        }
        if dst_slot == src_idx || self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }

        let cap = self.slots[src_idx]
            .cap
            .take()
            .ok_or(SysError::InvalidCapability)?;
        let parent = self.slots[src_idx].take_parent_slot();
        let ext_parent = self.slots[src_idx].take_external_parent();
        self.slots[src_idx].bump_generation();
        if src_idx < 64 {
            let bit = 1u64 << src_idx;
            self.occupied_mask &= !bit;
            self.derived_mask &= !bit;
        }

        // Reparent any direct CDT children from `src_idx` to `dst_slot`.
        if SLOTS <= 64 {
            let src_bit = 1u64 << src_idx;
            if (self.has_children_mask & src_bit) != 0 {
                let mut scan = self.derived_mask;
                while scan != 0 {
                    let idx = scan.trailing_zeros() as usize;
                    scan &= scan - 1;
                    if self.slots[idx].parent_slot() == Some(src_idx) {
                        self.slots[idx].parent = dst_slot as u16;
                    }
                }
                self.has_children_mask &= !src_bit;
                self.has_children_mask |= 1u64 << dst_slot;
            }
        } else {
            let mut moved_any = false;
            for slot in &mut self.slots[1..SLOTS] {
                if slot.cap.is_some() && slot.parent_slot() == Some(src_idx) {
                    slot.parent = dst_slot as u16;
                    moved_any = true;
                }
            }
            if src_idx < 64 {
                self.has_children_mask &= !(1u64 << src_idx);
            }
            if moved_any && dst_slot < 64 {
                self.has_children_mask |= 1u64 << dst_slot;
            }
        }

        let new_id = self.insert_at(dst_slot, cap, parent)?;
        self.slots[dst_slot].set_external_parent(ext_parent)?;
        Ok(new_id)
    }

    /// Delete a single capability slot (without revoking its descendants).
    pub fn delete(&mut self, id: CapId) -> Result<(), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        let parent = self.slots[idx].take_parent_slot();
        let ext_parent = self.slots[idx].take_external_parent();
        self.slots[idx].cap = None;
        self.slots[idx].bump_generation();
        if idx < 64 {
            let bit = 1u64 << idx;
            self.occupied_mask &= !bit;
            self.derived_mask &= !bit;
        }

        // Preserve CDT ancestry by reparenting direct children to the deleted slot's parent.
        let parent_u16 = parent.unwrap_or(0) as u16;
        if SLOTS <= 64 {
            let idx_bit = 1u64 << idx;
            if (self.has_children_mask & idx_bit) != 0 {
                self.has_children_mask &= !idx_bit;
                let mut reparented_to_parent = false;
                let mut scan = self.derived_mask;
                while scan != 0 {
                    let child_idx = scan.trailing_zeros() as usize;
                    scan &= scan - 1;
                    if self.slots[child_idx].parent_slot() == Some(idx) {
                        self.slots[child_idx].parent = parent_u16;
                        if parent.is_none() {
                            let _ = self.slots[child_idx].set_external_parent(ext_parent);
                            self.derived_mask &= !(1u64 << child_idx);
                        } else {
                            reparented_to_parent = true;
                        }
                    }
                }
                if reparented_to_parent && let Some(p) = parent {
                    self.has_children_mask |= 1u64 << p;
                }
            }
        } else {
            if idx < 64 {
                self.has_children_mask &= !(1u64 << idx);
            }
            let mut reparented_to_parent = false;
            for child_idx in 1..SLOTS {
                if self.slots[child_idx].cap.is_some()
                    && self.slots[child_idx].parent_slot() == Some(idx)
                {
                    self.slots[child_idx].parent = parent_u16;
                    if parent.is_none() {
                        let _ = self.slots[child_idx].set_external_parent(ext_parent);
                        if child_idx < 64 {
                            self.derived_mask &= !(1u64 << child_idx);
                        }
                    } else {
                        reparented_to_parent = true;
                    }
                }
            }
            if reparented_to_parent
                && let Some(p) = parent
                && p < 64
            {
                self.has_children_mask |= 1u64 << p;
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
            let root_bit = 1u64 << root_idx;
            if (self.has_children_mask & root_bit) == 0 {
                return Ok(0);
            }
            let mut candidates = self.derived_mask & !root_bit;
            let mut marked = 0u64;
            let mut frontier = root_bit;
            while frontier != 0 && candidates != 0 {
                let mut next_frontier = 0u64;
                let mut active = frontier;
                let mut scan = candidates;
                while scan != 0 {
                    let idx = scan.trailing_zeros() as usize;
                    let bit = 1u64 << idx;
                    scan &= !bit;
                    if let Some(p) = self.slots[idx].parent_slot()
                        && (active & (1u64 << p)) != 0
                    {
                        marked |= bit;
                        next_frontier |= bit;
                        active |= bit;
                        candidates &= !bit;
                    }
                }
                frontier = next_frontier & self.has_children_mask;
            }

            self.has_children_mask &= !(marked | root_bit);
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
                self.slots[idx].parent = 0;
                self.slots[idx].ext_cnode = 0;
                self.slots[idx].ext_slot = 0;
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
                if let Some(p) = self.slots[idx].parent_slot()
                    && (p == root_idx || marked[p])
                {
                    marked[idx] = true;
                    changed = true;
                }
            }
        }

        if root_idx < 64 {
            self.has_children_mask &= !(1u64 << root_idx);
        }
        let mut revoked_count = 0usize;
        for (idx, should_revoke) in marked.iter().enumerate().skip(1) {
            if *should_revoke {
                self.slots[idx].cap = None;
                self.slots[idx].parent = 0;
                self.slots[idx].ext_cnode = 0;
                self.slots[idx].ext_slot = 0;
                self.slots[idx].bump_generation();
                if idx < 64 {
                    let bit = 1u64 << idx;
                    self.occupied_mask &= !bit;
                    self.derived_mask &= !bit;
                    self.has_children_mask &= !bit;
                }
                revoked_count += 1;
            }
        }
        Ok(revoked_count)
    }

    /// Transitively revoke all intra-`CNode` descendants of `id`, invoking `on_revoked` for each
    /// revoked `Capability`, and return `(revoked_count, root_idx, revoked_slot_mask)` (`SLOTS <= 64`).
    pub fn revoke_with_mask_cb(
        &mut self,
        id: CapId,
        mut on_revoked: impl FnMut(Capability),
    ) -> Result<(usize, usize, u64), SysError> {
        if SLOTS > 64 {
            return Err(SysError::Unsupported);
        }
        let (root_idx, root_rights) = {
            let (idx, cap) = self.validate_cap(id)?;
            (idx, cap.rights)
        };
        if !root_rights.contains(Rights::REVOKE) {
            return Err(SysError::InsufficientRights);
        }

        let root_bit = 1u64 << root_idx;
        if (self.has_children_mask & root_bit) == 0 {
            return Ok((0, root_idx, 0));
        }

        let mut candidates = self.derived_mask & !root_bit;
        let mut marked = 0u64;
        let mut frontier = root_bit;
        while frontier != 0 && candidates != 0 {
            let mut next_frontier = 0u64;
            let mut active = frontier;
            let mut scan = candidates;
            while scan != 0 {
                let idx = scan.trailing_zeros() as usize;
                let bit = 1u64 << idx;
                scan &= !bit;
                if let Some(p) = self.slots[idx].parent_slot()
                    && (active & (1u64 << p)) != 0
                {
                    marked |= bit;
                    next_frontier |= bit;
                    active |= bit;
                    candidates &= !bit;
                }
            }
            frontier = next_frontier & self.has_children_mask;
        }

        self.has_children_mask &= !(marked | root_bit);
        if marked == 0 {
            return Ok((0, root_idx, 0));
        }
        self.occupied_mask &= !marked;
        self.derived_mask &= !marked;
        let revoked_count = marked.count_ones() as usize;
        let mut clear = marked;
        while clear != 0 {
            let idx = clear.trailing_zeros() as usize;
            clear &= clear - 1;
            if let Some(cap) = self.slots[idx].cap.take() {
                on_revoked(cap);
            }
            self.slots[idx].parent = 0;
            self.slots[idx].ext_cnode = 0;
            self.slots[idx].ext_slot = 0;
            self.slots[idx].bump_generation();
        }
        Ok((revoked_count, root_idx, marked))
    }

    /// Transitively revoke all intra-`CNode` descendants of `id` and return
    /// `(revoked_count, root_idx, revoked_slot_mask)` for cross-`CNode` CDT propagation (`SLOTS <= 64`).
    pub fn revoke_with_mask(&mut self, id: CapId) -> Result<(usize, usize, u64), SysError> {
        self.revoke_with_mask_cb(id, |_| {})
    }

    /// Revoke all occupied slots in this `CNode` whose `external_parent` appears in `parent_masks`,
    /// invoking `on_revoked` for each revoked `Capability`.
    pub fn revoke_matching_external_parents_cb(
        &mut self,
        parent_masks: &[u64],
        mut on_revoked: impl FnMut(Capability),
    ) -> (usize, u64) {
        if SLOTS > 64 {
            let mut marked = [false; SLOTS];
            let mut any_root = false;
            for idx in 1..SLOTS {
                if self.slots[idx].cap.is_none() {
                    continue;
                }
                if let Some(ext) = self.slots[idx].external_parent()
                    && let Some(&mask) = parent_masks.get(ext.cnode_id as usize)
                    && ext.slot < 64
                    && (mask & (1u64 << ext.slot)) != 0
                {
                    marked[idx] = true;
                    any_root = true;
                }
            }
            if !any_root {
                return (0, 0);
            }
            let mut changed = true;
            while changed {
                changed = false;
                for idx in 1..SLOTS {
                    if marked[idx] || self.slots[idx].cap.is_none() {
                        continue;
                    }
                    if let Some(p) = self.slots[idx].parent_slot()
                        && p < SLOTS
                        && marked[p]
                    {
                        marked[idx] = true;
                        changed = true;
                    }
                }
            }
            let mut count = 0usize;
            let mut low_mask = 0u64;
            for (idx, should_revoke) in marked.iter().enumerate().skip(1) {
                if *should_revoke {
                    if let Some(cap) = self.slots[idx].cap.take() {
                        on_revoked(cap);
                    }
                    self.slots[idx].parent = 0;
                    self.slots[idx].ext_cnode = 0;
                    self.slots[idx].ext_slot = 0;
                    self.slots[idx].bump_generation();
                    if idx < 64 {
                        let bit = 1u64 << idx;
                        self.occupied_mask &= !bit;
                        self.derived_mask &= !bit;
                        self.has_children_mask &= !bit;
                        low_mask |= bit;
                    }
                    count += 1;
                }
            }
            return (count, low_mask);
        }

        let mut roots = 0u64;
        let mut scan = self.occupied_mask;
        while scan != 0 {
            let idx = scan.trailing_zeros() as usize;
            let bit = 1u64 << idx;
            scan &= !bit;
            if let Some(ext) = self.slots[idx].external_parent()
                && let Some(&mask) = parent_masks.get(ext.cnode_id as usize)
                && ext.slot < 64
                && (mask & (1u64 << ext.slot)) != 0
            {
                roots |= bit;
            }
        }
        if roots == 0 {
            return (0, 0);
        }

        let mut candidates = self.derived_mask & !roots;
        let mut marked = roots;
        let mut frontier = roots & self.has_children_mask;
        while frontier != 0 && candidates != 0 {
            let mut next_frontier = 0u64;
            let mut active = frontier;
            let mut cscan = candidates;
            while cscan != 0 {
                let idx = cscan.trailing_zeros() as usize;
                let bit = 1u64 << idx;
                cscan &= !bit;
                if let Some(p) = self.slots[idx].parent_slot()
                    && (active & (1u64 << p)) != 0
                {
                    marked |= bit;
                    next_frontier |= bit;
                    active |= bit;
                    candidates &= !bit;
                }
            }
            frontier = next_frontier & self.has_children_mask;
        }

        self.occupied_mask &= !marked;
        self.derived_mask &= !marked;
        self.has_children_mask &= !marked;
        let count = marked.count_ones() as usize;
        let mut clear = marked;
        while clear != 0 {
            let idx = clear.trailing_zeros() as usize;
            clear &= clear - 1;
            if let Some(cap) = self.slots[idx].cap.take() {
                on_revoked(cap);
            }
            self.slots[idx].parent = 0;
            self.slots[idx].ext_cnode = 0;
            self.slots[idx].ext_slot = 0;
            self.slots[idx].bump_generation();
        }
        (count, marked)
    }

    /// Revoke all occupied slots in this `CNode` whose `external_parent` appears in `parent_masks`
    /// (`parent_masks[cnode_id]` has bit `slot` set), plus all of their intra-`CNode` descendants.
    ///
    /// Returns `(revoked_count, revoked_slot_mask)` for `SLOTS <= 64`.
    pub fn revoke_matching_external_parents(&mut self, parent_masks: &[u64]) -> (usize, u64) {
        self.revoke_matching_external_parents_cb(parent_masks, |_| {})
    }

    /// Pure seL4 `Untyped` -> `Frame` retype into `dst_slot`: verifies `untyped_cap` carries
    /// `Rights::WRITE`, carves a 4 KiB physical frame strictly from its designated `region_index`,
    /// and installs a derived `Frame` capability as a CDT child of `untyped_cap`.
    pub fn retype_frame_from_into(
        &mut self,
        untyped_cap: CapId,
        dst_slot: usize,
        inv: &mut UntypedInventory,
    ) -> Result<CapId, SysError> {
        let (parent_idx, cap) = {
            let (idx, cap) = self.validate_cap(untyped_cap)?;
            (idx, *cap)
        };

        let CapObject::Untyped { region_index } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        if !cap.rights.contains(Rights::WRITE) {
            return Err(SysError::InsufficientRights);
        }
        if dst_slot == 0 || dst_slot >= SLOTS || dst_slot > u16::MAX as usize {
            return Err(SysError::InvalidArgument);
        }
        if self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }

        let frame = inv.retype_frame_in(region_index as usize)?;
        let frame_cap = Capability::new(
            CapObject::Frame {
                phys: frame.start_addr(),
            },
            Rights::ALL,
        );
        self.insert_at(dst_slot, frame_cap, Some(parent_idx))
    }

    /// Pure seL4 `Untyped` -> `Frame` retype into the first free slot.
    pub fn retype_frame_from(
        &mut self,
        untyped_cap: CapId,
        inv: &mut UntypedInventory,
    ) -> Result<CapId, SysError> {
        let dst_slot = self.find_free_slot()?;
        self.retype_frame_from_into(untyped_cap, dst_slot, inv)
    }

    /// Install a kernel object capability retyped from `untyped_cap` into `dst_slot` as a CDT child.
    pub fn insert_retyped_child(
        &mut self,
        untyped_cap: CapId,
        dst_slot: usize,
        object: CapObject,
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
        self.insert_at(
            dst_slot,
            Capability::new(object, Rights::ALL),
            Some(parent_idx),
        )
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
            .insert_root(Capability::new(
                CapObject::Notification { id: 3 },
                Rights::ALL,
            ))
            .expect("root");
        let badged = cnode
            .mint(root, 2, Rights::ALL, Some(0xAA))
            .expect("first badge");

        // Attempting to re-badge an already badged capability must fail
        assert_eq!(
            cnode.mint(badged, 3, Rights::READ, Some(0xBB)),
            Err(SysError::InsufficientRights)
        );

        // Explicit Some(0) badge is rejected to prevent confusion with the unbadged sentinel.
        assert_eq!(
            cnode.mint(root, 4, Rights::READ, Some(0)),
            Err(SysError::InvalidArgument)
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
        let grandchild = cnode
            .mint(child, 4, Rights::READ, Some(1))
            .expect("grandchild");

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
    fn retype_frame_from_respects_designated_region_index() {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x10_0000, PAGE_SIZE * 4)); // region 0
        assert!(inv.push_raw_region(0x50_0000, PAGE_SIZE)); // region 1 (1 frame only)

        let mut cnode = CNode::<16>::new();
        let region1_cap = cnode
            .insert_root(Capability::new(
                CapObject::Untyped { region_index: 1 },
                Rights::ALL,
            ))
            .unwrap();

        let f1 = cnode.retype_frame_from(region1_cap, &mut inv).unwrap();
        let CapObject::Frame { phys } = cnode.lookup(f1, Rights::READ).unwrap().object else {
            panic!("expected Frame");
        };
        assert_eq!(phys, PhysAddr::new(0x50_0000));
        // Region 0 must be completely untouched, and region 1 must now be exhausted!
        assert_eq!(inv.region_remaining(0), Some(PAGE_SIZE * 4));
        assert_eq!(inv.region_remaining(1), Some(0));
        assert_eq!(
            cnode.retype_frame_from(region1_cap, &mut inv),
            Err(SysError::OutOfMemory)
        );
    }

    #[test]
    fn cnode_edge_sizes_zero_one_sixty_four_and_over_sixty_four() {
        let c0 = CNode::<0>::new();
        assert_eq!(c0.find_free_slot(), Err(SysError::OutOfMemory));
        assert_eq!(c0.occupied_count(), 0);
        assert_eq!(
            c0.lookup(CapId::new(1), Rights::NONE),
            Err(SysError::InvalidCapability)
        );

        let c1 = CNode::<1>::new();
        assert_eq!(c1.find_free_slot(), Err(SysError::OutOfMemory));
        assert_eq!(c1.occupied_count(), 0);

        // CNode::<64> has 63 usable slots (1..=63).
        let mut c64 = CNode::<64>::new();
        let mut caps64 = [CapId::NULL; 63];
        for (i, slot_cap) in caps64.iter_mut().enumerate() {
            *slot_cap = c64
                .insert_root(Capability::new(
                    CapObject::Endpoint { id: i as u32 },
                    Rights::ALL,
                ))
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
            .insert_root(Capability::new(
                CapObject::Endpoint { id: 100 },
                Rights::ALL,
            ))
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
        assert_eq!(
            c80.lookup(child64, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            c80.lookup(grandchild70, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
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
        assert_eq!(
            cnode.lookup(child, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            cnode.lookup(grandchild, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            cnode.lookup(great_grandchild, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(cnode.occupied_count(), 1);

        // Test delete(child) reparents grandchild to root so revoke(root) still revokes grandchild.
        let child2 = cnode.copy(root, 8).unwrap();
        let grandchild2 = cnode.copy(child2, 4).unwrap();
        cnode.delete(child2).unwrap();
        assert_eq!(cnode.revoke(root), Ok(1));
        assert_eq!(
            cnode.lookup(grandchild2, Rights::NONE),
            Err(SysError::InvalidCapability)
        );

        // Test delete(root) promotes child to root so revoking unrelated caps never touches it.
        let other = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
            .unwrap();
        let promoted = cnode.copy(root, 9).unwrap();
        cnode.delete(root).unwrap();
        assert_eq!(cnode.revoke(other), Ok(0));
        assert!(cnode.lookup(promoted, Rights::ALL).is_ok());
    }

    #[test]
    fn cap_slot_footprint_and_cnode80_mask_guards() {
        assert_eq!(core::mem::size_of::<CapSlot>(), 48);
        assert_eq!(core::mem::size_of::<CNode<64>>(), 3096);
        let diff = core::mem::size_of::<CNode<64>>() - core::mem::size_of::<CNode<32>>();
        assert_eq!(diff % 32, 0);
        assert_eq!(diff / 32, 48);

        // CNode<80> must return Unsupported on revoke_with_mask_cb instead of shift overflow,
        // and revoke_matching_external_parents_cb must safely handle slots >= 64.
        let mut c80 = CNode::<80>::new();
        let r = c80
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
            .unwrap();
        assert_eq!(
            c80.revoke_with_mask_cb(r, |_| {}),
            Err(SysError::Unsupported)
        );

        // Reject out-of-range ExternalParent fields cleanly.
        assert_eq!(
            c80.insert_external_derived(
                Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL),
                ExternalParent {
                    cnode_id: 256,
                    slot: 1
                },
            ),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            c80.insert_external_derived(
                Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL),
                ExternalParent {
                    cnode_id: 0,
                    slot: 0
                },
            ),
            Err(SysError::InvalidArgument)
        );

        // Fill slots 2..=63 so next external derived lands in slot 64 (>= 64).
        for i in 2..=63u32 {
            let _ = c80
                .insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))
                .unwrap();
        }
        let ext64 = c80
            .insert_external_derived(
                Capability::new(CapObject::Endpoint { id: 99 }, Rights::ALL),
                ExternalParent {
                    cnode_id: 1,
                    slot: 5,
                },
            )
            .unwrap();
        let child70 = c80.copy(ext64, 70).unwrap();
        let mut masks = [0u64; 2];
        masks[1] = 1u64 << 5;
        let (revoked, _low_mask) = c80.revoke_matching_external_parents_cb(&masks, |_| {});
        assert_eq!(revoked, 2);
        assert_eq!(
            c80.lookup(ext64, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            c80.lookup(child70, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }
}
