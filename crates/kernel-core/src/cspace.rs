//! Capability Space (`CSpace`) and inline Capability Derivation Tree (CDT).
//!
//! Zero kernel heap, generational `CapId` handles,
//! non-escalating rights attenuation, immutable badging, and transitive `revoke`.

use crate::memory::{PhysAddr, UntypedInventory};
use core::fmt;
use core::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use newos_abi::{CapId, ObjectType, Rights, SysError};

/// Interrupt controller domain backing an [`CapObject::IrqHandler`] capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrqController {
    /// Standard ARM GIC Shared Peripheral Interrupt (SPI).
    GicSpi,
    /// `BCM2712` / `RP1` MSI-X Interrupt Peripheral (MIP).
    Mip,
}

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
    IrqHandler { irq: u16, controller: IrqController },
    MmioRegion { phys: PhysAddr, len: u64 },
    Console,
    PowerControl,
    IoSpace { domain_id: u16 },
}

impl CapObject {
    #[inline]
    #[must_use]
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
    #[must_use]
    pub const fn new(object: CapObject, rights: Rights) -> Self {
        Self {
            object,
            rights,
            badge: 0,
        }
    }

    /// Return the immutable non-zero badge attached to this capability, or `None` if unbadged.
    #[inline]
    #[must_use]
    pub const fn badge_non_zero(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.badge)
    }
}

/// Cross-`CNode` CDT parent link identifying the `(cnode_id, slot)` that granted a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalParent {
    pub cnode_id: u16,
    pub slot: u16,
}

/// Niche-optimized 2-byte internal representation of an [`ExternalParent`] link.
///
/// Because `slot` is [`NonZeroU8`], `Option<CompactExternalParent>` occupies exactly 2 bytes
/// and makes `(cnode_id != 0, slot == 0)` unrepresentable at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompactExternalParent {
    cnode_id: u8,
    slot: NonZeroU8,
}

impl CompactExternalParent {
    #[inline]
    fn try_from_external(ep: ExternalParent) -> Result<Self, SysError> {
        let cnode_id = u8::try_from(ep.cnode_id).map_err(|_| SysError::InvalidArgument)?;
        let slot_u8 = u8::try_from(ep.slot).map_err(|_| SysError::InvalidArgument)?;
        let slot = NonZeroU8::new(slot_u8).ok_or(SysError::InvalidArgument)?;
        Ok(Self { cnode_id, slot })
    }

    #[inline]
    const fn to_external(self) -> ExternalParent {
        ExternalParent {
            cnode_id: self.cnode_id as u16,
            slot: self.slot.get() as u16,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CapSlot {
    cap: Option<Capability>,
    generation: NonZeroU32,
    parent: Option<NonZeroU16>,
    ext_parent: Option<CompactExternalParent>,
}

const _: () = assert!(core::mem::size_of::<CapSlot>() <= 48);

impl CapSlot {
    const EMPTY: Self = Self {
        cap: None,
        generation: NonZeroU32::MIN,
        parent: None,
        ext_parent: None,
    };

    #[inline]
    const fn parent_slot(&self) -> Option<usize> {
        match self.parent {
            Some(p) => Some(p.get() as usize),
            None => None,
        }
    }

    #[inline]
    const fn take_parent_nz(&mut self) -> Option<NonZeroU16> {
        self.parent.take()
    }

    #[inline]
    const fn external_parent(&self) -> Option<ExternalParent> {
        match self.ext_parent {
            Some(ep) => Some(ep.to_external()),
            None => None,
        }
    }

    #[inline]
    fn set_external_parent(&mut self, ext: Option<ExternalParent>) -> Result<(), SysError> {
        self.ext_parent = match ext {
            None => None,
            Some(ep) => Some(CompactExternalParent::try_from_external(ep)?),
        };
        Ok(())
    }

    #[inline]
    const fn take_compact_external_parent(&mut self) -> Option<CompactExternalParent> {
        self.ext_parent.take()
    }

    #[inline]
    const fn bump_generation(&mut self) {
        // Saturate at `NonZeroU32::MAX` (retired slot) so a generation counter can NEVER wrap
        // around and re-validate a stale `CapId` even after 4 billion reuses.
        self.generation = self.generation.saturating_add(1);
    }

    #[inline]
    const fn clear_metadata(&mut self) {
        self.parent = None;
        self.ext_parent = None;
    }
}

#[inline]
const fn encode_cap_id(slot: NonZeroU16, generation: NonZeroU32) -> CapId {
    CapId::from_parts(generation.get(), slot.get() as u32)
}

#[inline]
const fn decode_cap_id(id: CapId) -> (usize, u32) {
    (id.slot() as usize, id.generation())
}

/// Fixed-capacity capability table with inline Capability Derivation Tree (CDT).
///
/// Slot `0` is permanently reserved for `CapId::NULL`.
pub struct CNode<const SLOTS: usize> {
    slots: [CapSlot; SLOTS],
    occupied_mask: u64,
    derived_mask: u64,
    has_children_mask: u64,
}

impl<const SLOTS: usize> fmt::Debug for CNode<SLOTS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CNode")
            .field("slots", &SLOTS)
            .field("occupied", &self.occupied_count())
            .finish_non_exhaustive()
    }
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

    #[must_use]
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
    #[must_use]
    pub fn has_live_frame_cap(&self, phys: PhysAddr) -> bool {
        self.has_live_object(CapObject::Frame { phys })
    }

    /// Return `true` if any live slot in this `CNode` holds a capability referencing `object`.
    #[inline]
    #[must_use]
    pub fn has_live_object(&self, object: CapObject) -> bool {
        let mut mask = self.occupied_mask;
        while mask != 0 {
            let idx = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if let Some(cap) = &self.slots[idx].cap
                && cap.object == object
            {
                return true;
            }
        }
        if SLOTS > 64 {
            for slot in self.slots.iter().skip(64) {
                if let Some(cap) = &slot.cap
                    && cap.object == object
                {
                    return true;
                }
            }
        }
        false
    }

    /// Clear every occupied capability slot in this `CNode` (bumping generations so old handles stay invalid),
    /// invoking `on_removed(cap)` for each cleared capability (`M4`).
    pub fn clear_all(&mut self, mut on_removed: impl FnMut(Capability)) {
        for slot in &mut self.slots {
            if let Some(cap) = slot.cap.take() {
                slot.clear_metadata();
                // Reset generation to 1 because the entire owning protection domain and VSpace are torn down;
                // a freshly respawned protection domain expects its `CapId::BOOTSTRAP_*` handles at gen 1.
                slot.generation = NonZeroU32::MIN;
                on_removed(cap);
            }
        }
        self.occupied_mask = 0;
        self.derived_mask = 0;
        self.has_children_mask = 0;
    }

    /// Find the first free slot index (`1..SLOTS`).
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if all capability slots in this `CNode` are occupied.
    #[inline]
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

    #[inline]
    fn validate_cap(&self, id: CapId) -> Result<(usize, &Capability), SysError> {
        let (idx, generation) = decode_cap_id(id);
        if idx == 0 || idx >= SLOTS {
            return Err(SysError::InvalidCapability);
        }
        let slot = &self.slots[idx];
        if slot.generation.get() != generation {
            return Err(SysError::InvalidCapability);
        }
        let cap = slot.cap.as_ref().ok_or(SysError::InvalidCapability)?;
        Ok((idx, cap))
    }

    #[inline]
    fn validate_slot_nz(slot: usize) -> Result<NonZeroU16, SysError> {
        if slot >= SLOTS {
            return Err(SysError::InvalidArgument);
        }
        let slot_u16 = u16::try_from(slot).map_err(|_| SysError::InvalidArgument)?;
        NonZeroU16::new(slot_u16).ok_or(SysError::InvalidArgument)
    }

    #[inline]
    fn insert_at(
        &mut self,
        dst_slot: usize,
        cap: Capability,
        parent: Option<usize>,
    ) -> Result<CapId, SysError> {
        let dst_nz = Self::validate_slot_nz(dst_slot)?;
        let parent_nz = match parent {
            None => None,
            Some(p) => {
                let p_u16 = u16::try_from(p).map_err(|_| SysError::InvalidArgument)?;
                Some(NonZeroU16::new(p_u16).ok_or(SysError::InvalidArgument)?)
            }
        };
        if self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }
        if self.slots[dst_slot].generation == NonZeroU32::MAX {
            return Err(SysError::OutOfMemory);
        }
        self.slots[dst_slot].cap = Some(cap);
        self.slots[dst_slot].parent = parent_nz;
        self.slots[dst_slot].ext_parent = None;
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
        Ok(encode_cap_id(dst_nz, self.slots[dst_slot].generation))
    }

    /// Insert a cross-domain granted capability with an explicit `ExternalParent` CDT link.
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `ext_parent` has `slot == 0` or fields exceeding `u8::MAX`.
    /// - [`SysError::OutOfMemory`] if this `CNode` has no free slots.
    pub fn insert_external_derived(
        &mut self,
        cap: Capability,
        ext_parent: ExternalParent,
    ) -> Result<CapId, SysError> {
        let compact = CompactExternalParent::try_from_external(ext_parent)?;
        let dst = self.find_free_slot()?;
        let id = self.insert_at(dst, cap, None)?;
        self.slots[dst].ext_parent = Some(compact);
        Ok(id)
    }

    /// Return the slot index of a valid `CapId` (for CDT parent tracking).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidCapability`] if `id` is null, out of range, empty, or stale.
    #[inline]
    pub fn slot_index(&self, id: CapId) -> Result<usize, SysError> {
        let (idx, _) = self.validate_cap(id)?;
        Ok(idx)
    }

    /// Inspect `(intra_parent_slot, external_parent)` of a valid `CapId`.
    ///
    /// # Errors
    /// Returns [`SysError::InvalidCapability`] if `id` is null, out of range, empty, or stale.
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
                slot.ext_parent = None;
            }
        }
    }

    /// Walk intra-`CNode` parent links starting at `slot` to find the nearest `ExternalParent`
    /// ancestor outside this `CNode` (used to reparent external CDT children when a domain exits).
    #[must_use]
    pub fn root_external_parent_of_slot(&self, mut slot: usize) -> Option<ExternalParent> {
        for _ in 0..SLOTS {
            if slot == 0 || slot >= SLOTS || self.slots[slot].cap.is_none() {
                return None;
            }
            if let Some(ext) = self.slots[slot].external_parent() {
                return Some(ext);
            }
            slot = self.slots[slot].parent_slot()?;
        }
        None
    }

    /// Return `true` if `slot` is currently occupied in this `CNode`.
    #[inline]
    #[must_use]
    pub const fn is_slot_occupied(&self, slot: usize) -> bool {
        slot > 0 && slot < SLOTS && self.slots[slot].cap.is_some()
    }

    /// Insert a root capability (e.g. during bootstrap) into the first free slot.
    ///
    /// # Errors
    /// Returns [`SysError::OutOfMemory`] if no free slot is available.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, SysError> {
        let dst = self.find_free_slot()?;
        self.insert_at(dst, cap, None)
    }

    /// Insert a root capability into an explicit slot index (`1..SLOTS`), ensuring deterministic
    /// bootstrap `CapId`s even when optional hardware capabilities (e.g. `BOOTSTRAP_NET_MMIO`) are absent.
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `dst_slot` is `0` or out of bounds.
    /// - [`SysError::SlotOccupied`] if `dst_slot` already holds a capability.
    /// - [`SysError::OutOfMemory`] if `dst_slot` has exhausted its generation counter.
    pub fn insert_root_at(&mut self, dst_slot: usize, cap: Capability) -> Result<CapId, SysError> {
        self.insert_at(dst_slot, cap, None)
    }

    /// Bind the hardware root physical address on an existing `CapObject::VSpace` capability during boot.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `id` is invalid or stale.
    /// - [`SysError::InvalidArgument`] if `id` does not reference a [`CapObject::VSpace`].
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

    /// Install or rebind a root `CapObject::Thread { id }` capability at fixed `slot`
    /// while preserving generation 1 across `DomainRespawn` cycles.
    ///
    /// # Errors
    /// - [`SysError::InvalidArgument`] if `slot` is `0` or out of bounds.
    /// - [`SysError::SlotOccupied`] if `slot` is occupied by a non-`Thread` capability.
    /// - [`SysError::OutOfMemory`] if `slot` has exhausted its generation counter.
    pub fn bind_thread_at(&mut self, slot: usize, thread_id: u32) -> Result<CapId, SysError> {
        let slot_nz = Self::validate_slot_nz(slot)?;
        if let Some(cap) = self.slots[slot].cap.as_mut() {
            match &mut cap.object {
                CapObject::Thread { id } => {
                    *id = thread_id;
                    Ok(encode_cap_id(slot_nz, self.slots[slot].generation))
                }
                _ => Err(SysError::SlotOccupied),
            }
        } else {
            self.insert_root_at(
                slot,
                Capability::new(CapObject::Thread { id: thread_id }, Rights::ALL),
            )
        }
    }

    /// Bind the target `UntypedInventory` region index on an existing `CapObject::Untyped` cap during boot.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `id` is invalid or stale.
    /// - [`SysError::InvalidArgument`] if `id` does not reference a [`CapObject::Untyped`].
    pub fn bind_untyped_region(&mut self, id: CapId, region_index: u16) -> Result<(), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        let Some(cap) = self.slots[idx].cap.as_mut() else {
            return Err(SysError::InvalidCapability);
        };
        match &mut cap.object {
            CapObject::Untyped {
                region_index: slot_region,
            } => {
                *slot_region = region_index;
                Ok(())
            }
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Resolve a `CapId` and verify it carries at least `required` rights.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `id` is null, out of range, empty, or stale.
    /// - [`SysError::InsufficientRights`] if the capability lacks any bit in `required`.
    #[inline]
    pub fn lookup(&self, id: CapId, required: Rights) -> Result<&Capability, SysError> {
        let (_, cap) = self.validate_cap(id)?;
        if !cap.rights.contains(required) {
            return Err(SysError::InsufficientRights);
        }
        Ok(cap)
    }

    /// Derive a new capability with strictly attenuated rights and an optional immutable badge.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `src` is invalid or stale.
    /// - [`SysError::InsufficientRights`] if `src` lacks [`Rights::GRANT`] or is already badged when `new_badge` is `Some`.
    /// - [`SysError::InvalidArgument`] if `new_badge` is `Some(0)` or `dst_slot` is invalid.
    /// - [`SysError::SlotOccupied`] if `dst_slot` is already occupied.
    /// - [`SysError::OutOfMemory`] if `dst_slot` has exhausted its generation counter.
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
                // Invariant: once a capability is badged, its badge cannot be altered.
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
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::mint`].
    #[inline]
    pub fn copy(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        self.mint(src, dst_slot, Rights::ALL, None)
    }

    /// Move a capability to `dst_slot`, invalidating the old `CapId` and preserving CDT links.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `src` is invalid or stale.
    /// - [`SysError::InvalidArgument`] if `dst_slot` is `0` or out of bounds.
    /// - [`SysError::SlotOccupied`] if `dst_slot == src` or `dst_slot` is already occupied.
    /// - [`SysError::OutOfMemory`] if `dst_slot` has exhausted its generation counter.
    pub fn move_cap(&mut self, src: CapId, dst_slot: usize) -> Result<CapId, SysError> {
        let (src_idx, _) = self.validate_cap(src)?;
        let dst_nz = Self::validate_slot_nz(dst_slot)?;
        if dst_slot == src_idx || self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }
        if self.slots[dst_slot].generation == NonZeroU32::MAX {
            return Err(SysError::OutOfMemory);
        }

        let cap = self.slots[src_idx]
            .cap
            .take()
            .ok_or(SysError::InvalidCapability)?;
        let parent = self.slots[src_idx]
            .take_parent_nz()
            .map(|p| usize::from(p.get()));
        let ext_parent = self.slots[src_idx].take_compact_external_parent();
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
                        self.slots[idx].parent = Some(dst_nz);
                    }
                }
                self.has_children_mask &= !src_bit;
                self.has_children_mask |= 1u64 << dst_slot;
            }
        } else {
            let mut moved_any = false;
            for slot in &mut self.slots[1..SLOTS] {
                if slot.cap.is_some() && slot.parent_slot() == Some(src_idx) {
                    slot.parent = Some(dst_nz);
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
        self.slots[dst_slot].ext_parent = ext_parent;
        Ok(new_id)
    }

    /// Delete a single capability slot (without revoking its descendants).
    ///
    /// # Errors
    /// Returns [`SysError::InvalidCapability`] if `id` is null, out of range, empty, or stale.
    pub fn delete(&mut self, id: CapId) -> Result<(), SysError> {
        let (idx, _) = self.validate_cap(id)?;
        let parent_nz = self.slots[idx].take_parent_nz();
        let parent = parent_nz.map(|p| usize::from(p.get()));
        let ext_parent = self.slots[idx].take_compact_external_parent();
        self.slots[idx].cap = None;
        self.slots[idx].bump_generation();
        if idx < 64 {
            let bit = 1u64 << idx;
            self.occupied_mask &= !bit;
            self.derived_mask &= !bit;
        }

        // Preserve CDT ancestry by reparenting direct children to the deleted slot's parent.
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
                        self.slots[child_idx].parent = parent_nz;
                        if parent_nz.is_none() {
                            self.slots[child_idx].ext_parent = ext_parent;
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
                    self.slots[child_idx].parent = parent_nz;
                    if parent_nz.is_none() {
                        self.slots[child_idx].ext_parent = ext_parent;
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

    /// Collect all intra-`CNode` descendants reachable from `initial_frontier` for `SLOTS <= 64`.
    #[inline]
    const fn collect_descendants_mask(&self, initial_frontier: u64, excluded_mask: u64) -> u64 {
        let mut candidates = self.derived_mask & !excluded_mask;
        let mut marked = 0u64;
        let mut frontier = initial_frontier;
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
        marked
    }

    /// Clear every slot in `marked` (`SLOTS <= 64`), invoking `on_revoked` for each removed cap.
    #[inline]
    fn clear_marked_mask(&mut self, marked: u64, mut on_revoked: impl FnMut(Capability)) -> usize {
        self.occupied_mask &= !marked;
        self.derived_mask &= !marked;
        let count = marked.count_ones() as usize;
        let mut clear = marked;
        while clear != 0 {
            let idx = clear.trailing_zeros() as usize;
            clear &= clear - 1;
            if let Some(cap) = self.slots[idx].cap.take() {
                on_revoked(cap);
            }
            self.slots[idx].clear_metadata();
            self.slots[idx].bump_generation();
        }
        count
    }

    /// Transitively revoke all descendants derived from `id` (leaving `id` itself intact).
    ///
    /// Requires `Rights::REVOKE`. Uses an iterative fixed-point scan over `SLOTS`.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `id` is invalid or stale.
    /// - [`SysError::InsufficientRights`] if `id` lacks [`Rights::REVOKE`].
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
            let marked = self.collect_descendants_mask(root_bit, root_bit);
            self.has_children_mask &= !(marked | root_bit);
            if marked == 0 {
                return Ok(0);
            }
            return Ok(self.clear_marked_mask(marked, |_| {}));
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
                self.slots[idx].clear_metadata();
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
    ///
    /// # Errors
    /// - [`SysError::Unsupported`] if `SLOTS > 64`.
    /// - [`SysError::InvalidCapability`] if `id` is invalid or stale.
    /// - [`SysError::InsufficientRights`] if `id` lacks [`Rights::REVOKE`].
    pub fn revoke_with_mask_cb(
        &mut self,
        id: CapId,
        on_revoked: impl FnMut(Capability),
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

        let marked = self.collect_descendants_mask(root_bit, root_bit);
        self.has_children_mask &= !(marked | root_bit);
        if marked == 0 {
            return Ok((0, root_idx, 0));
        }
        let revoked_count = self.clear_marked_mask(marked, on_revoked);
        Ok((revoked_count, root_idx, marked))
    }

    /// Transitively revoke all intra-`CNode` descendants of `id` and return
    /// `(revoked_count, root_idx, revoked_slot_mask)` for cross-`CNode` CDT propagation (`SLOTS <= 64`).
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::revoke_with_mask_cb`].
    pub fn revoke_with_mask(&mut self, id: CapId) -> Result<(usize, usize, u64), SysError> {
        self.revoke_with_mask_cb(id, |_| {})
    }

    fn revoke_external_large(
        &mut self,
        parent_masks: &[u64],
        mut on_revoked: impl FnMut(Capability),
    ) -> (usize, u64) {
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
                self.slots[idx].clear_metadata();
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
        (count, low_mask)
    }

    fn revoke_external_mask(
        &mut self,
        parent_masks: &[u64],
        on_revoked: impl FnMut(Capability),
    ) -> (usize, u64) {
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

        let descendants = self.collect_descendants_mask(roots & self.has_children_mask, roots);
        let marked = roots | descendants;
        self.has_children_mask &= !marked;
        let count = self.clear_marked_mask(marked, on_revoked);
        (count, marked)
    }

    /// Revoke all occupied slots in this `CNode` whose `external_parent` appears in `parent_masks`,
    /// invoking `on_revoked` for each revoked `Capability`.
    pub fn revoke_matching_external_parents_cb(
        &mut self,
        parent_masks: &[u64],
        on_revoked: impl FnMut(Capability),
    ) -> (usize, u64) {
        if SLOTS > 64 {
            self.revoke_external_large(parent_masks, on_revoked)
        } else {
            self.revoke_external_mask(parent_masks, on_revoked)
        }
    }

    /// Revoke all occupied slots in this `CNode` whose `external_parent` appears in `parent_masks`
    /// (`parent_masks[cnode_id]` has bit `slot` set), plus all of their intra-`CNode` descendants.
    ///
    /// Returns `(revoked_count, revoked_slot_mask)` for `SLOTS <= 64`.
    pub fn revoke_matching_external_parents(&mut self, parent_masks: &[u64]) -> (usize, u64) {
        self.revoke_matching_external_parents_cb(parent_masks, |_| {})
    }

    /// `Untyped` -> `Frame` retype into `dst_slot`: verifies `untyped_cap` carries
    /// `Rights::WRITE`, carves a 4 KiB physical frame strictly from its designated `region_index`,
    /// and installs a derived `Frame` capability as a CDT child of `untyped_cap`.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `untyped_cap` is invalid or stale.
    /// - [`SysError::InvalidArgument`] if `untyped_cap` is not `Untyped` or `dst_slot` is invalid.
    /// - [`SysError::InsufficientRights`] if `untyped_cap` lacks [`Rights::WRITE`].
    /// - [`SysError::SlotOccupied`] if `dst_slot` is already occupied.
    /// - [`SysError::OutOfMemory`] if the slot is retired or the designated untyped region is exhausted.
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
        let _ = Self::validate_slot_nz(dst_slot)?;
        if self.slots[dst_slot].cap.is_some() {
            return Err(SysError::SlotOccupied);
        }
        if self.slots[dst_slot].generation == NonZeroU32::MAX {
            return Err(SysError::OutOfMemory);
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

    /// `Untyped` -> `Frame` retype into the first free slot.
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::find_free_slot`] or [`Self::retype_frame_from_into`].
    pub fn retype_frame_from(
        &mut self,
        untyped_cap: CapId,
        inv: &mut UntypedInventory,
    ) -> Result<CapId, SysError> {
        let dst_slot = self.find_free_slot()?;
        self.retype_frame_from_into(untyped_cap, dst_slot, inv)
    }

    /// Install a kernel object capability retyped from `untyped_cap` into `dst_slot` as a CDT child.
    ///
    /// # Errors
    /// - [`SysError::InvalidCapability`] if `untyped_cap` is invalid or stale.
    /// - [`SysError::InvalidArgument`] if `untyped_cap` is not `Untyped` or `dst_slot` is invalid.
    /// - [`SysError::InsufficientRights`] if `untyped_cap` lacks [`Rights::WRITE`].
    /// - [`SysError::SlotOccupied`] or [`SysError::OutOfMemory`] if insertion fails.
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
        // Retyped child inherits at most the parent Untyped capability's rights (no amplification).
        self.insert_at(
            dst_slot,
            Capability::new(object, cap.rights),
            Some(parent_idx),
        )
    }

    /// Return `true` if any occupied slot in this `CNode` holds `object` with at least `required` rights.
    #[inline]
    #[must_use]
    pub fn has_live_object_with_rights(&self, object: CapObject, required: Rights) -> bool {
        self.slots.iter().skip(1).any(|s| {
            s.cap
                .is_some_and(|c| c.object == object && c.rights.contains(required))
        })
    }

    /// Count currently occupied capability slots.
    #[inline]
    #[must_use]
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
    fn move_cap_to_retired_slot_fails_atomically_preserving_source_and_children() {
        let mut cnode = CNode::<16>::new();
        let root = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 9 }, Rights::ALL))
            .expect("root");
        let child = cnode.copy(root, 2).expect("child");

        // Retire destination slot 5 by exhausting its generation counter.
        cnode.slots[5].generation = NonZeroU32::MAX;

        assert_eq!(cnode.move_cap(root, 5), Err(SysError::OutOfMemory));
        // Source capability, occupied count, and CDT parent-child linkage must remain intact.
        assert!(cnode.lookup(root, Rights::ALL).is_ok());
        assert_eq!(cnode.occupied_count(), 2);
        assert_eq!(cnode.parent_info(child), Ok((2, Some(1), None)));
        assert_eq!(cnode.revoke(root), Ok(1));
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
        for (i, slot_cap) in (0u32..).zip(caps64.iter_mut()) {
            *slot_cap = c64
                .insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))
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

    #[test]
    fn cnode_debug_badge_non_zero_irq_controller_and_external_delete_reparent() {
        use core::fmt::Write as _;

        struct Buf([u8; 128], usize);
        impl core::fmt::Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let n = bytes.len().min(self.0.len() - self.1);
                self.0[self.1..self.1 + n].copy_from_slice(&bytes[..n]);
                self.1 += n;
                Ok(())
            }
        }

        let mut cnode = CNode::<16>::new();
        let ext = ExternalParent {
            cnode_id: 2,
            slot: 7,
        };
        let irq_cap = Capability::new(
            CapObject::IrqHandler {
                irq: 33,
                controller: IrqController::GicSpi,
            },
            Rights::ALL,
        );
        assert_eq!(irq_cap.badge_non_zero(), None);
        assert_ne!(IrqController::GicSpi, IrqController::Mip);

        let root_ext = cnode.insert_external_derived(irq_cap, ext).expect("insert");
        assert_eq!(root_ext, CapId::from_parts(1, 1));
        assert_eq!(decode_cap_id(root_ext), (1, 1));

        let child = cnode
            .mint(root_ext, 3, Rights::READ, Some(0x55))
            .expect("mint");
        assert_eq!(
            cnode
                .lookup(child, Rights::READ)
                .expect("lookup")
                .badge_non_zero(),
            NonZeroU64::new(0x55)
        );

        // Deleting root_ext must transfer its CompactExternalParent directly to `child`.
        cnode.delete(root_ext).expect("delete");
        assert_eq!(cnode.parent_info(child), Ok((3, None, Some(ext))));

        let mut buf = Buf([0; 128], 0);
        write!(&mut buf, "{cnode:?}").expect("format debug");
        let rendered = core::str::from_utf8(&buf.0[..buf.1]).expect("utf8");
        assert!(rendered.contains("CNode"));
        assert!(rendered.contains("slots: 16"));
        assert!(rendered.contains("occupied: 1"));
        assert!(rendered.contains(".."));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove monotonic rights attenuation: `CNode::mint` NEVER grants any bit not in parent rights,
    /// and a non-zero badge can NEVER be overwritten.
    #[kani::proof]
    fn cnode_mint_monotonic_attenuation_and_badge_immutability() {
        let mut cnode: CNode<8> = CNode::new();
        let orig_bits: u8 = kani::any();
        let mask_bits: u8 = kani::any();
        let badge1: u64 = kani::any();
        let badge2: u64 = kani::any();
        kani::assume(badge1 != 0);

        let orig = Rights::from_bits_truncate(orig_bits).union(Rights::GRANT);
        let mask = Rights::from_bits_truncate(mask_bits);

        let root = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, orig))
            .unwrap();
        let minted = cnode.mint(root, 2, mask, Some(badge1)).unwrap();
        let cap = cnode.lookup(minted, Rights::NONE).unwrap();

        // Monotonicity: minted rights are strictly a subset of parent rights
        assert_eq!(cap.rights.bits() & !orig.bits(), 0);
        assert_eq!(cap.rights.bits(), orig.bits() & mask.bits());
        assert_eq!(cap.badge, badge1);

        // Badge immutability: attempting to re-badge an already badged cap must fail
        // (`Some(0)` is rejected as `InvalidArgument`; any non-zero badge as `InsufficientRights`).
        if cap.rights.contains(Rights::GRANT) {
            let expected = if badge2 == 0 {
                Err(SysError::InvalidArgument)
            } else {
                Err(SysError::InsufficientRights)
            };
            assert_eq!(cnode.mint(minted, 3, mask, Some(badge2)), expected);
        }
    }

    /// Prove generational `CapId` safety: deleting a slot permanently invalidates the old handle
    /// even after the exact same slot is reused.
    #[kani::proof]
    fn cnode_stale_generation_rejected_after_reuse() {
        let mut cnode: CNode<4> = CNode::new();
        let id1 = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
            .unwrap();
        cnode.delete(id1).unwrap();
        let id2 = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(
            cnode.lookup(id1, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
        assert!(cnode.lookup(id2, Rights::NONE).is_ok());
    }
}
