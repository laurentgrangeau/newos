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

/// Live kernel-core IPC and notification operation counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IpcStats {
    pub ipc_sends: u64,
    pub ipc_recvs: u64,
    pub ipc_calls: u64,
    pub notify_signals: u64,
    pub notify_polls: u64,
    pub would_blocks: u64,
}

impl IpcStats {
    pub const fn new() -> Self {
        Self {
            ipc_sends: 0,
            ipc_recvs: 0,
            ipc_calls: 0,
            notify_signals: 0,
            notify_polls: 0,
            would_blocks: 0,
        }
    }
}

/// Fixed-capacity, `no_alloc` kernel IPC + root `CSpace` state.
pub struct KernelIpcState {
    pub root_cspace: CNode<ROOT_CSPACE_SLOTS>,
    notifications: [u64; MAX_NOTIFICATIONS],
    endpoints: [Option<IpcMessage>; MAX_ENDPOINTS],
    stats: IpcStats,
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
            stats: IpcStats::new(),
        }
    }

    #[inline]
    pub const fn stats(&self) -> IpcStats {
        self.stats
    }

    #[inline]
    pub fn reset_stats(&mut self) {
        self.stats = IpcStats::new();
    }

    #[inline]
    pub const fn root_cspace(&self) -> &CNode<ROOT_CSPACE_SLOTS> {
        &self.root_cspace
    }

    #[inline]
    pub fn root_cspace_mut(&mut self) -> &mut CNode<ROOT_CSPACE_SLOTS> {
        &mut self.root_cspace
    }

    /// Install the well-known bootstrap capabilities:
    /// - Slot 1 (`BOOTSTRAP_NOTIF`): general `Notification`
    /// - Slot 2 (`BOOTSTRAP_EP`): badged (`0x5E14`) `Endpoint`
    /// - Slot 3 (`BOOTSTRAP_FAULT_NOTIF`): Ring-3 supervisor fault `Notification`
    /// - Slot 4 (`BOOTSTRAP_NET_MMIO`): scoped VirtIO-MMIO window (if `net_mmio` is provided)
    pub fn init_bootstrap_caps(
        &mut self,
        net_mmio: Option<(PhysAddr, u64)>,
    ) -> Result<(CapId, CapId, CapId), SysError> {
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
        if let Some((phys, len)) = net_mmio {
            let _ = self.root_cspace.insert_root(Capability::new(
                CapObject::MmioRegion { phys, len },
                Rights::READ.union(Rights::WRITE),
            ))?;
        }
        Ok((notif, ep, fault_notif))
    }

    /// Bitwise-OR `badge` (or the capability's immutable badge if non-zero) into a `Notification`.
    #[inline]
    pub fn notify_signal(&mut self, cap_id: CapId, badge: u64) -> Result<(), SysError> {
        let (id, cap_badge) = {
            let cap = self.root_cspace.lookup(cap_id, Rights::WRITE)?;
            let CapObject::Notification { id } = cap.object else {
                return Err(SysError::InvalidArgument);
            };
            (id as usize, cap.badge)
        };
        let slot = self
            .notifications
            .get_mut(id)
            .ok_or(SysError::InvalidArgument)?;
        let effective_badge = if cap_badge != 0 { cap_badge } else { badge };
        *slot |= effective_badge;
        self.stats.notify_signals = self.stats.notify_signals.wrapping_add(1);
        Ok(())
    }

    /// Atomically read and clear the 64-bit signal word of a `Notification`.
    #[inline]
    pub fn notify_poll(&mut self, cap_id: CapId) -> Result<u64, SysError> {
        let id = {
            let cap = self.root_cspace.lookup(cap_id, Rights::READ)?;
            let CapObject::Notification { id } = cap.object else {
                return Err(SysError::InvalidArgument);
            };
            id as usize
        };
        let slot = self
            .notifications
            .get_mut(id)
            .ok_or(SysError::InvalidArgument)?;
        let bits = *slot;
        *slot = 0;
        self.stats.notify_polls = self.stats.notify_polls.wrapping_add(1);
        Ok(bits)
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` (stamping `cap.badge`).
    #[inline]
    pub fn ipc_send(&mut self, cap_id: CapId, payload: u64) -> Result<(), SysError> {
        let (id, badge) = {
            let cap = self.root_cspace.lookup(cap_id, Rights::WRITE)?;
            let CapObject::Endpoint { id } = cap.object else {
                return Err(SysError::InvalidArgument);
            };
            (id as usize, cap.badge)
        };
        let slot = self
            .endpoints
            .get_mut(id)
            .ok_or(SysError::InvalidArgument)?;
        if slot.is_some() {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        *slot = Some(IpcMessage { badge, payload });
        self.stats.ipc_sends = self.stats.ipc_sends.wrapping_add(1);
        Ok(())
    }

    /// Receive a pending register-only fastpath IPC message from an `Endpoint`.
    #[inline]
    pub fn ipc_recv(&mut self, cap_id: CapId) -> Result<IpcMessage, SysError> {
        let id = {
            let cap = self.root_cspace.lookup(cap_id, Rights::READ)?;
            let CapObject::Endpoint { id } = cap.object else {
                return Err(SysError::InvalidArgument);
            };
            id as usize
        };
        let slot = self
            .endpoints
            .get_mut(id)
            .ok_or(SysError::InvalidArgument)?;
        match slot.take() {
            Some(msg) => {
                self.stats.ipc_recvs = self.stats.ipc_recvs.wrapping_add(1);
                Ok(msg)
            }
            None => {
                self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
                Err(SysError::WouldBlock)
            }
        }
    }

    /// Synchronous direct call/reply fastpath on an `Endpoint` without intermediate buffering.
    ///
    /// Requires both `Rights::READ` and `Rights::WRITE` on `cap_id` and fails with
    /// `SysError::WouldBlock` if the endpoint already holds an unread buffered message.
    #[inline]
    pub fn ipc_call(
        &mut self,
        cap_id: CapId,
        payload: u64,
        handler: impl FnOnce(IpcMessage) -> IpcMessage,
    ) -> Result<IpcMessage, SysError> {
        let (id, badge) = {
            let cap = self
                .root_cspace
                .lookup(cap_id, Rights::READ.union(Rights::WRITE))?;
            let CapObject::Endpoint { id } = cap.object else {
                return Err(SysError::InvalidArgument);
            };
            (id as usize, cap.badge)
        };
        let slot = self
            .endpoints
            .get(id)
            .ok_or(SysError::InvalidArgument)?;
        if slot.is_some() {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        let reply = handler(IpcMessage { badge, payload });
        self.stats.ipc_calls = self.stats.ipc_calls.wrapping_add(1);
        Ok(reply)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO read against its scoped `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_read32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(cap_id, offset, Rights::READ)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO write against its scoped `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_write32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(cap_id, offset, Rights::WRITE)
    }

    #[inline]
    fn validate_mmio_access32(
        &self,
        cap_id: CapId,
        offset: u64,
        required: Rights,
    ) -> Result<PhysAddr, SysError> {
        let cap = self.root_cspace.lookup(cap_id, required)?;
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
        let (notif, _ep, fault_notif) = ipc.init_bootstrap_caps(None).unwrap();
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
        let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
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

    #[test]
    fn ipc_stats_counts_and_reset() {
        let mut ipc = KernelIpcState::new();
        let (notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
        assert_eq!(ipc.stats(), IpcStats::new());

        assert_eq!(ipc.ipc_recv(ep), Err(SysError::WouldBlock));
        ipc.ipc_send(ep, 0x1111).unwrap();
        assert_eq!(ipc.ipc_send(ep, 0x2222), Err(SysError::WouldBlock));
        let _ = ipc.ipc_recv(ep).unwrap();
        ipc.notify_signal(notif, 0x1).unwrap();
        let _ = ipc.notify_poll(notif).unwrap();
        let _ = ipc
            .ipc_call(ep, 0x42, |req| IpcMessage {
                badge: req.badge,
                payload: req.payload + 1,
            })
            .unwrap();

        assert_eq!(
            ipc.stats(),
            IpcStats {
                ipc_sends: 1,
                ipc_recvs: 1,
                ipc_calls: 1,
                notify_signals: 1,
                notify_polls: 1,
                would_blocks: 2,
            }
        );

        ipc.reset_stats();
        assert_eq!(ipc.stats(), IpcStats::new());
    }

    #[test]
    fn ipc_call_fastpath_rights_badge_and_busy_endpoint() {
        let mut ipc = KernelIpcState::new();
        let (notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();

        // Happy path: stamps badge and returns handler reply without buffering.
        let reply = ipc
            .ipc_call(ep, 0xCAFE, |req| {
                assert_eq!(req.badge, 0x5E14);
                assert_eq!(req.payload, 0xCAFE);
                IpcMessage {
                    badge: req.badge,
                    payload: req.payload ^ 0xFFFF,
                }
            })
            .unwrap();
        assert_eq!(
            reply,
            IpcMessage {
                badge: 0x5E14,
                payload: 0xCAFE ^ 0xFFFF,
            }
        );
        assert_eq!(ipc.ipc_recv(ep), Err(SysError::WouldBlock));

        // Non-endpoint capability rejected.
        assert_eq!(
            ipc.ipc_call(notif, 1, |m| m),
            Err(SysError::InvalidArgument)
        );

        // Read-only and write-only capabilities rejected with InsufficientRights.
        let ro_slot = ipc.root_cspace_mut().find_free_slot().unwrap();
        let ro_ep = ipc
            .root_cspace_mut()
            .mint(ep, ro_slot, Rights::READ, None)
            .unwrap();
        assert_eq!(
            ipc.ipc_call(ro_ep, 1, |m| m),
            Err(SysError::InsufficientRights)
        );

        let wo_slot = ipc.root_cspace_mut().find_free_slot().unwrap();
        let wo_ep = ipc
            .root_cspace_mut()
            .mint(ep, wo_slot, Rights::WRITE, None)
            .unwrap();
        assert_eq!(
            ipc.ipc_call(wo_ep, 1, |m| m),
            Err(SysError::InsufficientRights)
        );

        // Busy endpoint returns WouldBlock and increments would_blocks.
        ipc.reset_stats();
        ipc.ipc_send(ep, 0x99).unwrap();
        assert_eq!(ipc.ipc_call(ep, 0xAA, |m| m), Err(SysError::WouldBlock));
        assert_eq!(ipc.stats().would_blocks, 1);
        assert_eq!(ipc.stats().ipc_calls, 0);
    }
}
