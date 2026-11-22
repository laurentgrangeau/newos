//! Pure seL4-style kernel IPC primitives: `Endpoint` (fastpath), 64-bit `Notification`,
//! and capability-scoped MMIO validation for Ring-3 drivers.
//!
//! 100% `#![forbid(unsafe_code)]`, zero kernel heap (`no_alloc`). All operations are
//! capability-checked through the caller's `CNode`.

use crate::cspace::{CNode, CapObject, Capability};
use crate::memory::PhysAddr;
use newos_abi::{CapId, Rights, SysError};

const MAX_NOTIFICATIONS: usize = 16;
const MAX_ENDPOINTS: usize = 16;
const ROOT_CSPACE_SLOTS: usize = 64;

/// Register-only fastpath IPC message delivered through an `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcMessage {
    pub badge: u64,
    pub payload: u64,
}

/// Fixed-capacity, `no_alloc` kernel IPC + root `CSpace` state.
pub struct KernelIpcState {
    pub root_cspace: CNode<ROOT_CSPACE_SLOTS>,
    notifications: [u64; MAX_NOTIFICATIONS],
    endpoints: [Option<IpcMessage>; MAX_ENDPOINTS],
}

impl Default for KernelIpcState {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelIpcState {
    pub const fn new() -> Self {
        Self {
            root_cspace: CNode::new(),
            notifications: [0; MAX_NOTIFICATIONS],
            endpoints: [None; MAX_ENDPOINTS],
        }
    }

    /// Install the well-known bootstrap capabilities:
    /// - Slot 1 (`BOOTSTRAP_NOTIF`): general `Notification`
    /// - Slot 2 (`BOOTSTRAP_EP`): badged (`0x5E14`) `Endpoint`
    /// - Slot 3 (`BOOTSTRAP_FAULT_NOTIF`): Ring-3 supervisor fault `Notification`
    pub fn init_bootstrap_caps(&mut self) -> Result<(CapId, CapId, CapId), SysError> {
        let notif = self.root_cspace.insert_root(Capability::new(
            CapObject::Notification { id: 0 },
            Rights::ALL,
        ))?;
        let ep = self.root_cspace.insert_root(Capability {
            object: CapObject::Endpoint { id: 0 },
            rights: Rights::ALL,
            badge: 0x5E14,
        })?;
        let fault_notif = self.root_cspace.insert_root(Capability::new(
            CapObject::Notification { id: 1 },
            Rights::ALL,
        ))?;
        Ok((notif, ep, fault_notif))
    }

    /// Bitwise-OR `badge` (or the capability's immutable badge if non-zero) into a `Notification`.
    pub fn notify_signal(&mut self, cap_id: CapId, badge: u64) -> Result<(), SysError> {
        let cap = *self.root_cspace.lookup(cap_id, Rights::WRITE)?;
        let CapObject::Notification { id } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        let slot = self
            .notifications
            .get_mut(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        let effective_badge = if cap.badge != 0 { cap.badge } else { badge };
        *slot |= effective_badge;
        Ok(())
    }

    /// Atomically read and clear the 64-bit signal word of a `Notification`.
    pub fn notify_poll(&mut self, cap_id: CapId) -> Result<u64, SysError> {
        let cap = *self.root_cspace.lookup(cap_id, Rights::READ)?;
        let CapObject::Notification { id } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        let slot = self
            .notifications
            .get_mut(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        let bits = *slot;
        *slot = 0;
        Ok(bits)
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` (stamping `cap.badge`).
    pub fn ipc_send(&mut self, cap_id: CapId, payload: u64) -> Result<(), SysError> {
        let cap = *self.root_cspace.lookup(cap_id, Rights::WRITE)?;
        let CapObject::Endpoint { id } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        let slot = self
            .endpoints
            .get_mut(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        if slot.is_some() {
            return Err(SysError::WouldBlock);
        }
        *slot = Some(IpcMessage {
            badge: cap.badge,
            payload,
        });
        Ok(())
    }

    /// Receive a pending register-only fastpath IPC message from an `Endpoint`.
    pub fn ipc_recv(&mut self, cap_id: CapId) -> Result<IpcMessage, SysError> {
        let cap = *self.root_cspace.lookup(cap_id, Rights::READ)?;
        let CapObject::Endpoint { id } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        let slot = self
            .endpoints
            .get_mut(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        slot.take().ok_or(SysError::WouldBlock)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO read against its scoped `MmioRegion` capability.
    pub fn validate_mmio_read32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        let cap = self.root_cspace.lookup(cap_id, Rights::READ)?;
        let CapObject::MmioRegion { phys, len } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        if (offset & 0x3) != 0 {
            return Err(SysError::InvalidArgument);
        }
        let end = offset.checked_add(4).ok_or(SysError::InvalidArgument)?;
        if end > len {
            return Err(SysError::InvalidArgument);
        }
        Ok(PhysAddr::new(
            phys.raw().checked_add(offset).ok_or(SysError::InvalidArgument)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_coalesces_bits_and_clears_on_poll() {
        let mut ipc = KernelIpcState::new();
        let (notif, _ep, fault_notif) = ipc.init_bootstrap_caps().unwrap();
        assert_eq!(notif, CapId::BOOTSTRAP_NOTIF);
        assert_eq!(fault_notif, CapId::BOOTSTRAP_FAULT_NOTIF);

        ipc.notify_signal(notif, 1 << 0).unwrap();
        ipc.notify_signal(notif, 1 << 3).unwrap();
        assert_eq!(ipc.notify_poll(notif), Ok((1 << 0) | (1 << 3)));
        assert_eq!(ipc.notify_poll(notif), Ok(0));
    }

    #[test]
    fn endpoint_stamps_badge_and_enforces_rights() {
        let mut ipc = KernelIpcState::new();
        let (_notif, ep, _fault) = ipc.init_bootstrap_caps().unwrap();
        assert_eq!(ep, CapId::BOOTSTRAP_EP);

        assert_eq!(ipc.ipc_recv(ep), Err(SysError::WouldBlock));
        ipc.ipc_send(ep, 0xCAFE).unwrap();
        assert_eq!(ipc.ipc_send(ep, 0xBEEF), Err(SysError::WouldBlock));
        assert_eq!(
            ipc.ipc_recv(ep),
            Ok(IpcMessage {
                badge: 0x5E14,
                payload: 0xCAFE,
            })
        );

        let ro_slot = ipc.root_cspace.find_free_slot().unwrap();
        let ro_ep = ipc
            .root_cspace
            .mint(ep, ro_slot, Rights::READ, None)
            .unwrap();
        assert_eq!(ipc.ipc_send(ro_ep, 1), Err(SysError::InsufficientRights));
    }

    #[test]
    fn mmio_capability_enforces_bounds_alignment_and_rights() {
        let mut ipc = KernelIpcState::new();
        let mmio_cap = ipc
            .root_cspace
            .insert_root(Capability::new(
                CapObject::MmioRegion {
                    phys: PhysAddr::new(0xFE00_0000),
                    len: 0x100,
                },
                Rights::READ,
            ))
            .unwrap();

        assert_eq!(
            ipc.validate_mmio_read32(mmio_cap, 0x10),
            Ok(PhysAddr::new(0xFE00_0010))
        );
        // Unaligned offset rejected
        assert_eq!(
            ipc.validate_mmio_read32(mmio_cap, 0x02),
            Err(SysError::InvalidArgument)
        );
        // Out-of-bounds offset rejected
        assert_eq!(
            ipc.validate_mmio_read32(mmio_cap, 0x100),
            Err(SysError::InvalidArgument)
        );
        // Invalid capability rejected
        assert_eq!(
            ipc.validate_mmio_read32(CapId::NULL, 0),
            Err(SysError::InvalidCapability)
        );
    }
}
