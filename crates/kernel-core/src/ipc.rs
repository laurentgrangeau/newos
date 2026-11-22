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
/// Maximum number of isolated process capability spaces (`PID 0..MAX_IPC_PROCS`).
pub const MAX_IPC_PROCS: usize = 8;

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

/// Fixed-capacity, `no_alloc` kernel IPC + per-process isolated `CSpace` state.
///
/// PID 0 (`init`) owns `root_cspace`; PIDs `1..MAX_IPC_PROCS` each own an independent
/// `CNode<64>` so unprivileged processes cannot access capabilities belonging to `init`
/// (such as `BOOTSTRAP_NET_MMIO` or `BOOTSTRAP_FAULT_NOTIF`).
pub struct KernelIpcState {
    pub root_cspace: CNode<ROOT_CSPACE_SLOTS>,
    proc_cspaces: [CNode<ROOT_CSPACE_SLOTS>; MAX_IPC_PROCS - 1],
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
            proc_cspaces: [const { CNode::new() }; MAX_IPC_PROCS - 1],
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

    /// Borrow the isolated `CNode` for process `pid` (`0..MAX_IPC_PROCS`).
    #[inline]
    pub fn cspace(&self, pid: usize) -> Result<&CNode<ROOT_CSPACE_SLOTS>, SysError> {
        if pid == 0 {
            Ok(&self.root_cspace)
        } else if pid < MAX_IPC_PROCS {
            Ok(&self.proc_cspaces[pid - 1])
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Mutably borrow the isolated `CNode` for process `pid` (`0..MAX_IPC_PROCS`).
    #[inline]
    pub fn cspace_mut(&mut self, pid: usize) -> Result<&mut CNode<ROOT_CSPACE_SLOTS>, SysError> {
        if pid == 0 {
            Ok(&mut self.root_cspace)
        } else if pid < MAX_IPC_PROCS {
            Ok(&mut self.proc_cspaces[pid - 1])
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Install the well-known bootstrap capabilities into PID 0 (`init`):
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

    /// Install least-privilege bootstrap capabilities for a non-root process (`pid >= 1`).
    ///
    /// Grants only `BOOTSTRAP_NOTIF` (`READ | WRITE`) and `BOOTSTRAP_EP` (`READ | WRITE`,
    /// badge `0x5E14`). Hardware MMIO and supervisor fault notifications are intentionally withheld.
    pub fn init_worker_bootstrap_caps(&mut self, pid: usize) -> Result<(CapId, CapId), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let cnode = &mut self.proc_cspaces[pid - 1];
        let rw = Rights::READ.union(Rights::WRITE);
        let notif = cnode.insert_root(Capability::new(CapObject::Notification { id: 0 }, rw))?;
        let ep = cnode.insert_root(Capability {
            object: CapObject::Endpoint { id: 0 },
            rights: rw,
            badge: 0x5E14,
        })?;
        Ok((notif, ep))
    }

    /// Resolve an `Endpoint` capability in `pid`'s `CSpace`, returning `(endpoint_id, badge)`.
    #[inline]
    pub fn lookup_endpoint_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<(u32, u64), SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::Endpoint { id } => Ok((id, cap.badge)),
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Bitwise-OR `badge` (or the capability's immutable badge if non-zero) into a `Notification`
    /// resolved in `pid`'s `CSpace`.
    #[inline]
    pub fn notify_signal_for(
        &mut self,
        pid: usize,
        cap_id: CapId,
        badge: u64,
    ) -> Result<(), SysError> {
        let (id, cap_badge) = {
            let cap = self.cspace(pid)?.lookup(cap_id, Rights::WRITE)?;
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

    /// Bitwise-OR `badge` into a `Notification` in PID 0's root `CSpace`.
    #[inline]
    pub fn notify_signal(&mut self, cap_id: CapId, badge: u64) -> Result<(), SysError> {
        self.notify_signal_for(0, cap_id, badge)
    }

    /// Atomically read and clear the 64-bit signal word of a `Notification` in `pid`'s `CSpace`.
    #[inline]
    pub fn notify_poll_for(&mut self, pid: usize, cap_id: CapId) -> Result<u64, SysError> {
        let id = {
            let cap = self.cspace(pid)?.lookup(cap_id, Rights::READ)?;
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

    /// Atomically read and clear the 64-bit signal word of a `Notification` in PID 0's `CSpace`.
    #[inline]
    pub fn notify_poll(&mut self, cap_id: CapId) -> Result<u64, SysError> {
        self.notify_poll_for(0, cap_id)
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` in `pid`'s `CSpace`.
    #[inline]
    pub fn ipc_send_for(
        &mut self,
        pid: usize,
        cap_id: CapId,
        payload: u64,
    ) -> Result<(), SysError> {
        let (id, badge) = self.lookup_endpoint_for(pid, cap_id, Rights::WRITE)?;
        let slot = self
            .endpoints
            .get_mut(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        if slot.is_some() {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        *slot = Some(IpcMessage { badge, payload });
        self.stats.ipc_sends = self.stats.ipc_sends.wrapping_add(1);
        Ok(())
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` in PID 0's `CSpace`.
    #[inline]
    pub fn ipc_send(&mut self, cap_id: CapId, payload: u64) -> Result<(), SysError> {
        self.ipc_send_for(0, cap_id, payload)
    }

    /// Receive a pending register-only fastpath IPC message from an `Endpoint` in `pid`'s `CSpace`.
    #[inline]
    pub fn ipc_recv_for(&mut self, pid: usize, cap_id: CapId) -> Result<IpcMessage, SysError> {
        let (id, _) = self.lookup_endpoint_for(pid, cap_id, Rights::READ)?;
        let slot = self
            .endpoints
            .get_mut(id as usize)
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

    /// Receive a pending register-only fastpath IPC message from an `Endpoint` in PID 0's `CSpace`.
    #[inline]
    pub fn ipc_recv(&mut self, cap_id: CapId) -> Result<IpcMessage, SysError> {
        self.ipc_recv_for(0, cap_id)
    }

    /// Synchronous direct call/reply fastpath on an `Endpoint` in `pid`'s `CSpace`.
    #[inline]
    pub fn ipc_call_for(
        &mut self,
        pid: usize,
        cap_id: CapId,
        payload: u64,
        handler: impl FnOnce(IpcMessage) -> IpcMessage,
    ) -> Result<IpcMessage, SysError> {
        let (id, badge) =
            self.lookup_endpoint_for(pid, cap_id, Rights::READ.union(Rights::WRITE))?;
        let slot = self
            .endpoints
            .get(id as usize)
            .ok_or(SysError::InvalidArgument)?;
        if slot.is_some() {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        let reply = handler(IpcMessage { badge, payload });
        self.stats.ipc_calls = self.stats.ipc_calls.wrapping_add(1);
        Ok(reply)
    }

    /// Synchronous direct call/reply fastpath on an `Endpoint` in PID 0's `CSpace`.
    #[inline]
    pub fn ipc_call(
        &mut self,
        cap_id: CapId,
        payload: u64,
        handler: impl FnOnce(IpcMessage) -> IpcMessage,
    ) -> Result<IpcMessage, SysError> {
        self.ipc_call_for(0, cap_id, payload, handler)
    }

    /// Derive a new capability in `pid`'s `CSpace` (`dst_slot == 0` auto-selects a free slot).
    pub fn cap_mint_for(
        &mut self,
        pid: usize,
        src: CapId,
        dst_slot: usize,
        rights_mask: Rights,
        new_badge: Option<u64>,
    ) -> Result<CapId, SysError> {
        let cnode = self.cspace_mut(pid)?;
        let slot = if dst_slot == 0 {
            cnode.find_free_slot()?
        } else {
            dst_slot
        };
        cnode.mint(src, slot, rights_mask, new_badge)
    }

    /// Copy a capability verbatim in `pid`'s `CSpace` (`dst_slot == 0` auto-selects a free slot).
    pub fn cap_copy_for(
        &mut self,
        pid: usize,
        src: CapId,
        dst_slot: usize,
    ) -> Result<CapId, SysError> {
        self.cap_mint_for(pid, src, dst_slot, Rights::ALL, None)
    }

    /// Move a capability to another slot in `pid`'s `CSpace` (`dst_slot == 0` auto-selects).
    pub fn cap_move_for(
        &mut self,
        pid: usize,
        src: CapId,
        dst_slot: usize,
    ) -> Result<CapId, SysError> {
        let cnode = self.cspace_mut(pid)?;
        let slot = if dst_slot == 0 {
            cnode.find_free_slot()?
        } else {
            dst_slot
        };
        cnode.move_cap(src, slot)
    }

    /// Delete a single capability slot from `pid`'s `CSpace`.
    pub fn cap_delete_for(&mut self, pid: usize, cap_id: CapId) -> Result<(), SysError> {
        self.cspace_mut(pid)?.delete(cap_id)
    }

    /// Transitively revoke all CDT descendants of `cap_id` in `pid`'s `CSpace`.
    pub fn cap_revoke_for(&mut self, pid: usize, cap_id: CapId) -> Result<usize, SysError> {
        self.cspace_mut(pid)?.revoke(cap_id)
    }

    /// Grant an attenuated capability from `src_pid`'s `CSpace` into `dst_pid`'s `CSpace`.
    ///
    /// Enforces `Rights::GRANT` on `src_cap`, non-escalating rights attenuation, and immutable
    /// badging. Only PID 0 (`init`) may grant into another process's `CSpace` (preventing
    /// unprivileged processes from injecting capabilities into peers).
    pub fn cap_grant_between(
        &mut self,
        src_pid: usize,
        dst_pid: usize,
        src_cap: CapId,
        rights_mask: Rights,
        new_badge: Option<u64>,
    ) -> Result<CapId, SysError> {
        if src_pid == dst_pid {
            return self.cap_mint_for(src_pid, src_cap, 0, rights_mask, new_badge);
        }
        if src_pid != 0 {
            return Err(SysError::InsufficientRights);
        }
        if dst_pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }

        let cap = *self.cspace(src_pid)?.lookup(src_cap, Rights::GRANT)?;
        let badge = match new_badge {
            None => cap.badge,
            Some(b) => {
                if cap.badge != 0 {
                    return Err(SysError::InsufficientRights);
                }
                b
            }
        };
        let derived = Capability {
            object: cap.object,
            rights: cap.rights.attenuate(rights_mask),
            badge,
        };
        self.cspace_mut(dst_pid)?.insert_root(derived)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO read against `pid`'s `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_read32_for(
        &self,
        pid: usize,
        cap_id: CapId,
        offset: u64,
    ) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(pid, cap_id, offset, Rights::READ)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO write against `pid`'s `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_write32_for(
        &self,
        pid: usize,
        cap_id: CapId,
        offset: u64,
    ) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(pid, cap_id, offset, Rights::WRITE)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO read in PID 0's `CSpace`.
    #[inline]
    pub fn validate_mmio_read32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        self.validate_mmio_read32_for(0, cap_id, offset)
    }

    /// Validate a Ring-3 driver's 32-bit MMIO write in PID 0's `CSpace`.
    #[inline]
    pub fn validate_mmio_write32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        self.validate_mmio_write32_for(0, cap_id, offset)
    }

    #[inline]
    fn validate_mmio_access32(
        &self,
        pid: usize,
        cap_id: CapId,
        offset: u64,
        required: Rights,
    ) -> Result<PhysAddr, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
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

    #[test]
    fn per_process_cspace_isolates_worker_from_init_mmio_and_fault_caps() {
        let mut ipc = KernelIpcState::new();
        let _ = ipc
            .init_bootstrap_caps(Some((PhysAddr::new(0x0A00_0000), 0x4000)))
            .unwrap();
        let (w_notif, w_ep) = ipc.init_worker_bootstrap_caps(1).unwrap();
        assert_eq!(w_notif, CapId::BOOTSTRAP_NOTIF);
        assert_eq!(w_ep, CapId::BOOTSTRAP_EP);

        // PID 0 (`init`) can access BOOTSTRAP_NET_MMIO and BOOTSTRAP_FAULT_NOTIF.
        assert_eq!(
            ipc.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, 0),
            Ok(PhysAddr::new(0x0A00_0000))
        );
        assert!(ipc.notify_signal_for(0, CapId::BOOTSTRAP_FAULT_NOTIF, 1).is_ok());

        // PID 1 (`worker`) is completely isolated from init's MMIO and fault caps!
        assert_eq!(
            ipc.validate_mmio_read32_for(1, CapId::BOOTSTRAP_NET_MMIO, 0),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.notify_signal_for(1, CapId::BOOTSTRAP_FAULT_NOTIF, 1),
            Err(SysError::InvalidCapability)
        );

        // PID 1 cannot mint/escalate its least-privilege BOOTSTRAP_EP (lacks Rights::GRANT).
        assert_eq!(
            ipc.cap_mint_for(1, w_ep, 0, Rights::READ, None),
            Err(SysError::InsufficientRights)
        );

        // PID 0 and PID 1 can still communicate over shared Endpoint { id: 0 }.
        ipc.ipc_send_for(0, CapId::BOOTSTRAP_EP, 0x4242).unwrap();
        assert_eq!(
            ipc.ipc_recv_for(1, w_ep),
            Ok(IpcMessage {
                badge: 0x5E14,
                payload: 0x4242,
            })
        );
    }

    #[test]
    fn dynamic_cap_syscalls_and_cross_process_grant() {
        let mut ipc = KernelIpcState::new();
        let (notif, ep, _) = ipc.init_bootstrap_caps(None).unwrap();
        let _ = ipc.init_worker_bootstrap_caps(1).unwrap();

        // Mint badged read-only notification in PID 0 (auto slot).
        let minted = ipc
            .cap_mint_for(0, notif, 0, Rights::READ.union(Rights::GRANT), Some(0xAA))
            .unwrap();
        // Copy and move within PID 0.
        let copied = ipc.cap_copy_for(0, minted, 0).unwrap();
        let moved = ipc.cap_move_for(0, copied, 0).unwrap();
        assert_eq!(ipc.notify_poll_for(0, copied), Err(SysError::InvalidCapability));
        assert_eq!(ipc.notify_poll_for(0, moved), Ok(0));

        // Revoke from `notif` transitively destroys both `minted` and `moved`.
        assert_eq!(ipc.cap_revoke_for(0, notif), Ok(2));
        assert_eq!(ipc.notify_poll_for(0, moved), Err(SysError::InvalidCapability));

        // Cross-process CapGrant: PID 0 grants a read-only notification cap to PID 1.
        let granted = ipc
            .cap_grant_between(0, 1, notif, Rights::READ, Some(0xBEEF))
            .unwrap();
        assert_eq!(ipc.notify_poll_for(1, granted), Ok(0));
        // Attenuated right enforced in PID 1 (cannot signal a READ-only cap).
        assert_eq!(
            ipc.notify_signal_for(1, granted, 1),
            Err(SysError::InsufficientRights)
        );
        // Unprivileged PID 1 cannot grant capabilities into PID 0.
        assert_eq!(
            ipc.cap_grant_between(1, 0, CapId::BOOTSTRAP_EP, Rights::READ, None),
            Err(SysError::InsufficientRights)
        );
        // Deleting in PID 1 does not affect PID 0's `notif` or `ep`.
        ipc.cap_delete_for(1, granted).unwrap();
        assert_eq!(ipc.notify_poll_for(1, granted), Err(SysError::InvalidCapability));
        assert_eq!(ipc.notify_poll_for(0, notif), Ok(0));
        assert!(ipc.ipc_send_for(0, ep, 7).is_ok());
    }
}
