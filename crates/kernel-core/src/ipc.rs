//! Pure seL4-style kernel IPC primitives: `Endpoint` (fastpath), 64-bit `Notification`,
//! and capability-scoped MMIO validation for EL0 drivers.
//!
//! 100% `#![forbid(unsafe_code)]`, zero kernel heap (`no_alloc`). All operations are
//! capability-checked through the caller's `CNode`.

use crate::cspace::{CNode, CapObject, Capability, ExternalParent};
use crate::memory::{PhysAddr, UntypedInventory};
use newos_abi::{CapId, ObjectType, Rights, SysError};

const MAX_NOTIFICATIONS: usize = 16;
/// Maximum number of kernel IPC `Endpoint` objects (`0..MAX_ENDPOINTS`).
pub const MAX_ENDPOINTS: usize = 16;
const ROOT_CSPACE_SLOTS: usize = 64;
/// Maximum number of isolated process capability spaces (`PID 0..MAX_IPC_PROCS`).
pub const MAX_IPC_PROCS: usize = 8;

const _: () = assert!(MAX_ENDPOINTS <= 16);
const _: () = assert!(MAX_IPC_PROCS + 2 <= u8::MAX as usize);

/// Register-only fastpath IPC message delivered through an `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcMessage {
    pub badge: u64,
    pub payload: u64,
}

impl IpcMessage {
    const EMPTY: Self = Self {
        badge: 0,
        payload: 0,
    };
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
    /// Per-endpoint occupancy + buffered `IpcCall` sender PID:
    /// `0` = empty, `1` = occupied (`sender_pid == None`), `2 + pid` = occupied (`Some(pid)`).
    endpoint_state: [u8; MAX_ENDPOINTS],
    endpoints: [IpcMessage; MAX_ENDPOINTS],
    stats: IpcStats,
    notifications: [u64; MAX_NOTIFICATIONS],
    next_endpoint_id: u16,
    next_notif_id: u16,
}

const _: () = assert!(core::mem::size_of::<KernelIpcState>() <= 25_224);

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
            endpoint_state: [0; MAX_ENDPOINTS],
            endpoints: [IpcMessage::EMPTY; MAX_ENDPOINTS],
            stats: IpcStats::new(),
            notifications: [0; MAX_NOTIFICATIONS],
            next_endpoint_id: 7,
            next_notif_id: 2,
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
    #[inline(always)]
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
    #[inline(always)]
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
    /// - Slot 3 (`BOOTSTRAP_FAULT_NOTIF`): EL0 supervisor fault `Notification`
    /// - Slot 4 (`BOOTSTRAP_NET_MMIO`): scoped NIC MMIO window (if `net_mmio` is provided)
    /// - Slot 5 (`BOOTSTRAP_CONSOLE`): `Console` capability (`READ | WRITE`)
    /// - Slot 6 (`BOOTSTRAP_POWER`): `PowerControl` capability (`Exit` / `SysInfo`)
    /// - Slot 7 (`BOOTSTRAP_VSPACE`): `VSpace` capability (`MapPage` / `UnmapPage` / `VirtToPhys`)
    pub fn init_bootstrap_caps(
        &mut self,
        net_mmio: Option<(PhysAddr, u64)>,
    ) -> Result<(CapId, CapId, CapId), SysError> {
        let notif = self.root_cspace.insert_root_at(
            1,
            Capability::new(CapObject::Notification { id: 0 }, Rights::ALL),
        )?;
        let ep = self.root_cspace.insert_root_at(
            2,
            Capability {
                object: CapObject::Endpoint { id: 0 },
                rights: Rights::ALL,
                badge: 0x5E14,
            },
        )?;
        let fault_notif = self.root_cspace.insert_root_at(
            3,
            Capability::new(CapObject::Notification { id: 1 }, Rights::ALL),
        )?;
        if let Some((phys, len)) = net_mmio {
            let _ = self.root_cspace.insert_root_at(
                4,
                Capability::new(
                    CapObject::MmioRegion { phys, len },
                    Rights::READ.union(Rights::WRITE),
                ),
            )?;
        }
        let _ = self
            .root_cspace
            .insert_root_at(5, Capability::new(CapObject::Console, Rights::ALL))?;
        let _ = self
            .root_cspace
            .insert_root_at(6, Capability::new(CapObject::PowerControl, Rights::ALL))?;
        let _ = self.root_cspace.insert_root_at(
            7,
            Capability::new(
                CapObject::VSpace {
                    root_phys: PhysAddr::new(0),
                },
                Rights::ALL,
            ),
        )?;
        let _ = self
            .root_cspace
            .insert_root_at(8, Capability::new(CapObject::Thread { id: 0 }, Rights::ALL))?;
        let _ = self
            .root_cspace
            .insert_root_at(9, Capability::new(CapObject::CNode { id: 0 }, Rights::ALL))?;
        let _ = self.root_cspace.insert_root_at(
            10,
            Capability::new(CapObject::Untyped { region_index: 0 }, Rights::ALL),
        )?;
        let _ = self.root_cspace.insert_root_at(
            11,
            Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL),
        )?;
        let rw = Rights::READ.union(Rights::WRITE);
        let _ = self.root_cspace.insert_root_at(
            13,
            Capability {
                object: CapObject::Endpoint { id: 2 },
                rights: rw,
                badge: 0x1000,
            },
        )?;
        let _ = self.root_cspace.insert_root_at(
            15,
            Capability::new(CapObject::Endpoint { id: 4 }, Rights::READ),
        )?;
        let _ = self.root_cspace.insert_root_at(
            16,
            Capability::new(CapObject::Endpoint { id: 5 }, Rights::READ),
        )?;
        let _ = self.root_cspace.insert_root_at(
            17,
            Capability::new(CapObject::Endpoint { id: 6 }, Rights::WRITE),
        )?;
        Ok((notif, ep, fault_notif))
    }

    /// Install a capability-scoped `MmioRegion` (`R|W`) at `slot` in `init` (PID 0)'s `CSpace`.
    pub fn register_bootstrap_mmio_cap(
        &mut self,
        slot: usize,
        phys: PhysAddr,
        len: u64,
    ) -> Result<CapId, SysError> {
        let rw = Rights::READ.union(Rights::WRITE);
        self.root_cspace.insert_root_at(
            slot,
            Capability::new(CapObject::MmioRegion { phys, len }, rw),
        )
    }

    /// Install `CapId::BOOTSTRAP_WDT_MMIO` (slot 18, gen 1, `R|W`) in `init` (PID 0)'s `CSpace`
    /// for the Raspberry Pi 5 BCM2712 hardware watchdog (`0x10_7D20_0000`, `0x100` bytes).
    pub fn register_wdt_mmio_cap(&mut self, phys: PhysAddr, len: u64) -> Result<CapId, SysError> {
        self.register_bootstrap_mmio_cap(18, phys, len)
    }

    /// Install strict least-privilege capabilities for `newos-netd` (Network & DMA plane).
    ///
    /// Holds ONLY `BOOTSTRAP_NET_MMIO` (`R|W`), `BOOTSTRAP_VSPACE` (`R` only for `VirtToPhys`),
    /// `BOOTSTRAP_NET_EP` (`R|W`, server), and write-only `BOOTSTRAP_LOG_EP` (`W`, badged `pid`).
    /// Explicitly omits `RNG_MMIO`, `KEY_EP`, `AUTH_GATE_EP`, `SSH_SHELL_EP`, `THREAD`, `CNODE`,
    /// `CONSOLE`, `POWER`, `UNTYPED`, and `GRANT`/`REVOKE`.
    pub fn init_netd_bootstrap_caps(
        &mut self,
        pid: usize,
        net_mmio: Option<(PhysAddr, u64)>,
    ) -> Result<(), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let cnode = &mut self.proc_cspaces[pid - 1];
        let rw = Rights::READ.union(Rights::WRITE);
        if let Some((phys, len)) = net_mmio {
            let _ = cnode
                .insert_root_at(4, Capability::new(CapObject::MmioRegion { phys, len }, rw))?;
        }
        let _ = cnode.insert_root_at(
            7,
            Capability::new(
                CapObject::VSpace {
                    root_phys: PhysAddr::new(0),
                },
                Rights::READ,
            ),
        )?;
        let _ = cnode.insert_root_at(
            11,
            Capability {
                object: CapObject::Endpoint { id: 1 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        let _ = cnode.insert_root_at(13, Capability::new(CapObject::Endpoint { id: 2 }, rw))?;
        Ok(())
    }

    /// Install strict least-privilege capabilities for `newos-keyd` (Entropy & PQ Signing Vault).
    ///
    /// Holds ONLY `BOOTSTRAP_RNG_MMIO` (`R|W`), `BOOTSTRAP_VSPACE` (`R` only, QEMU VirtIO-RNG DMA
    /// only — omitted on Raspberry Pi 5), `BOOTSTRAP_KEY_EP` (`R|W`, server), write-only
    /// `BOOTSTRAP_AUTH_GATE_EP` (`W`, badged `pid`), and write-only `BOOTSTRAP_LOG_EP` (`W`, badged `pid`).
    pub fn init_keyd_bootstrap_caps(
        &mut self,
        pid: usize,
        rng_mmio: Option<(PhysAddr, u64)>,
        allow_vspace_read: bool,
    ) -> Result<(), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let cnode = &mut self.proc_cspaces[pid - 1];
        let rw = Rights::READ.union(Rights::WRITE);
        if allow_vspace_read {
            let _ = cnode.insert_root_at(
                7,
                Capability::new(
                    CapObject::VSpace {
                        root_phys: PhysAddr::new(0),
                    },
                    Rights::READ,
                ),
            )?;
        }
        let _ = cnode.insert_root_at(
            11,
            Capability {
                object: CapObject::Endpoint { id: 1 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        if let Some((phys, len)) = rng_mmio {
            let _ = cnode
                .insert_root_at(12, Capability::new(CapObject::MmioRegion { phys, len }, rw))?;
        }
        let _ = cnode.insert_root_at(14, Capability::new(CapObject::Endpoint { id: 3 }, rw))?;
        let _ = cnode.insert_root_at(
            16,
            Capability {
                object: CapObject::Endpoint { id: 5 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        Ok(())
    }

    /// Install strict least-privilege capabilities for `newos-sshd` (Untrusted SSH Parser).
    ///
    /// Holds **ZERO** MMIO capabilities, **ZERO** `VSpace` capability, **ZERO** `AUTH_GATE_EP`,
    /// **ZERO** `THREAD`/`CNODE`/`GRANT`/`REVOKE`. Holds ONLY badged `BOOTSTRAP_NET_EP`,
    /// `BOOTSTRAP_KEY_EP`, `BOOTSTRAP_SSH_SHELL_EP`, and write-only `BOOTSTRAP_LOG_EP`.
    pub fn init_sshd_bootstrap_caps(&mut self, pid: usize) -> Result<(), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let cnode = &mut self.proc_cspaces[pid - 1];
        let rw = Rights::READ.union(Rights::WRITE);
        let _ = cnode.insert_root_at(
            11,
            Capability {
                object: CapObject::Endpoint { id: 1 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        let _ = cnode.insert_root_at(
            13,
            Capability {
                object: CapObject::Endpoint { id: 2 },
                rights: rw,
                badge: pid as u64,
            },
        )?;
        let _ = cnode.insert_root_at(
            14,
            Capability {
                object: CapObject::Endpoint { id: 3 },
                rights: rw,
                badge: pid as u64,
            },
        )?;
        let _ = cnode.insert_root_at(
            15,
            Capability {
                object: CapObject::Endpoint { id: 4 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        let _ = cnode.insert_root_at(
            17,
            Capability {
                object: CapObject::Endpoint { id: 6 },
                rights: Rights::READ,
                badge: pid as u64,
            },
        )?;
        Ok(())
    }

    /// Install least-privilege bootstrap capabilities for a non-root process (`pid >= 1`).
    ///
    /// Grants `BOOTSTRAP_NOTIF` (`READ | WRITE`), `BOOTSTRAP_EP` (`READ | WRITE`, badge `0x5E14`),
    /// `BOOTSTRAP_SELF_THREAD` (`READ | WRITE`), and write-only `BOOTSTRAP_LOG_EP` (`WRITE`,
    /// immutable kernel-stamped `badge = pid as u64`) for routing console output through `init`.
    /// Direct `Console` UART access, hardware MMIO, supervisor fault notifications, `PowerControl`,
    /// `VSpace`, and peer `CNode` capabilities are intentionally withheld.
    pub fn init_worker_bootstrap_caps(&mut self, pid: usize) -> Result<(CapId, CapId), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let cnode = &mut self.proc_cspaces[pid - 1];
        let rw = Rights::READ.union(Rights::WRITE);
        let notif =
            cnode.insert_root_at(1, Capability::new(CapObject::Notification { id: 0 }, rw))?;
        let ep = cnode.insert_root_at(
            2,
            Capability {
                object: CapObject::Endpoint { id: 0 },
                rights: rw,
                badge: 0x5E14,
            },
        )?;
        let _ =
            cnode.insert_root_at(8, Capability::new(CapObject::Thread { id: pid as u32 }, rw))?;
        let _ = cnode.insert_root_at(
            11,
            Capability {
                object: CapObject::Endpoint { id: 1 },
                rights: Rights::WRITE,
                badge: pid as u64,
            },
        )?;
        Ok((notif, ep))
    }

    /// Install designated `Thread` and `CNode` capabilities for `child_pid` into PID 0 (`init`).
    pub fn register_child_caps_in_root(
        &mut self,
        child_pid: usize,
    ) -> Result<(CapId, CapId), SysError> {
        if child_pid == 0 || child_pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let thread_cap = self.root_cspace.insert_root(Capability::new(
            CapObject::Thread {
                id: child_pid as u32,
            },
            Rights::ALL,
        ))?;
        let cnode_cap = self.root_cspace.insert_root(Capability::new(
            CapObject::CNode {
                id: child_pid as u32,
            },
            Rights::ALL,
        ))?;
        Ok((thread_cap, cnode_cap))
    }

    /// Validate a `Thread` capability in `pid`'s `CSpace`, returning the designated target `pid`.
    #[inline]
    pub fn validate_thread_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<usize, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::Thread { id } => {
                let target = id as usize;
                if target < MAX_IPC_PROCS {
                    Ok(target)
                } else {
                    Err(SysError::InvalidArgument)
                }
            }
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Validate a `CNode` capability in `pid`'s `CSpace`, returning the designated target `pid`.
    #[inline]
    pub fn validate_cnode_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<usize, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::CNode { id } => {
                let target = id as usize;
                if target < MAX_IPC_PROCS {
                    Ok(target)
                } else {
                    Err(SysError::InvalidArgument)
                }
            }
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Bind the hardware page-table root physical address onto `pid`'s `BOOTSTRAP_VSPACE` cap.
    pub fn bind_bootstrap_vspace(
        &mut self,
        pid: usize,
        root_phys: PhysAddr,
    ) -> Result<(), SysError> {
        self.cspace_mut(pid)?
            .bind_vspace_root(CapId::BOOTSTRAP_VSPACE, root_phys)
    }

    /// Bind the largest usable `UntypedInventory` region index onto PID 0's `BOOTSTRAP_UNTYPED` cap.
    pub fn bind_bootstrap_untyped_region(&mut self, region_index: u16) -> Result<(), SysError> {
        self.root_cspace
            .bind_untyped_region(CapId::BOOTSTRAP_UNTYPED, region_index)
    }

    /// Validate an `IrqHandler` capability in `pid`'s `CSpace`, returning its hardware IRQ number.
    #[inline]
    pub fn validate_irq_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<u16, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::IrqHandler { irq } => Ok(irq),
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Validate a `Console` capability in `pid`'s `CSpace` (`WRITE` for `DebugWrite`, `READ` for `DebugRead`).
    #[inline]
    pub fn validate_console_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<(), SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::Console => Ok(()),
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Validate a `PowerControl` capability in `pid`'s `CSpace` (`WRITE` for `Exit`, `READ` for `SysInfo`).
    #[inline]
    pub fn validate_power_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<(), SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::PowerControl => Ok(()),
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Validate a `VSpace` capability in `pid`'s `CSpace` (`WRITE` for `MapPage`/`UnmapPage`,
    /// `READ` for `VirtToPhys`), returning its bound hardware root physical address.
    #[inline]
    pub fn validate_vspace_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<PhysAddr, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::VSpace { root_phys } => Ok(root_phys),
            _ => Err(SysError::InvalidArgument),
        }
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
        let CapObject::Endpoint { id } = cap.object else {
            return Err(SysError::InvalidArgument);
        };
        Ok((id, cap.badge))
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

    /// Buffer a fastpath IPC message into an already-validated `Endpoint` (`ep_id`),
    /// optionally recording `sender_pid` for buffered `IpcCall` reply tracking.
    #[inline(always)]
    pub fn ipc_send_resolved(
        &mut self,
        ep_id: u32,
        badge: u64,
        payload: u64,
        sender_pid: Option<usize>,
    ) -> Result<(), SysError> {
        let idx = ep_id as usize;
        if idx >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        if self.endpoint_state[idx] != 0 {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        self.endpoints[idx] = IpcMessage { badge, payload };
        self.endpoint_state[idx] = match sender_pid {
            None => 1,
            Some(p) if p < MAX_IPC_PROCS => 2 + p as u8,
            Some(_) => 1,
        };
        self.stats.ipc_sends = self.stats.ipc_sends.wrapping_add(1);
        Ok(())
    }

    /// Receive a buffered fastpath IPC message from an already-validated `Endpoint` (`ep_id`),
    /// returning `(message, optional_sender_pid)`.
    #[inline(always)]
    pub fn ipc_recv_resolved(
        &mut self,
        ep_id: u32,
    ) -> Result<(IpcMessage, Option<usize>), SysError> {
        let idx = ep_id as usize;
        if idx >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let state = self.endpoint_state[idx];
        if state == 0 {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        self.endpoint_state[idx] = 0;
        let msg = self.endpoints[idx];
        let sender = if state >= 2 {
            Some((state - 2) as usize)
        } else {
            None
        };
        self.stats.ipc_recvs = self.stats.ipc_recvs.wrapping_add(1);
        Ok((msg, sender))
    }

    /// Drain all occupied endpoints holding a buffered `IpcCall` (`sender_pid.is_some()`),
    /// clearing each endpoint's occupancy and invoking `on_sender(pid)` for every caller.
    pub fn drain_buffered_call_senders(&mut self, mut on_sender: impl FnMut(usize)) {
        for slot in &mut self.endpoint_state {
            let state = *slot;
            if state >= 2 {
                *slot = 0;
                on_sender((state - 2) as usize);
            }
        }
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` in `pid`'s `CSpace`.
    #[inline(always)]
    pub fn ipc_send_for(
        &mut self,
        pid: usize,
        cap_id: CapId,
        payload: u64,
    ) -> Result<(), SysError> {
        let (id, badge) = self.lookup_endpoint_for(pid, cap_id, Rights::WRITE)?;
        self.ipc_send_resolved(id, badge, payload, None)
    }

    /// Send a register-only fastpath IPC payload to an `Endpoint` in PID 0's `CSpace`.
    #[inline(always)]
    pub fn ipc_send(&mut self, cap_id: CapId, payload: u64) -> Result<(), SysError> {
        self.ipc_send_for(0, cap_id, payload)
    }

    /// Receive a pending register-only fastpath IPC message from an `Endpoint` in `pid`'s `CSpace`.
    ///
    /// Refuses to consume a buffered `IpcCall` (`endpoint_state >= 2`) so a plain `IpcRecv` can
    /// never swallow another task's synchronous call and hang the caller forever (`H3`).
    #[inline(always)]
    pub fn ipc_recv_for(&mut self, pid: usize, cap_id: CapId) -> Result<IpcMessage, SysError> {
        let (id, _) = self.lookup_endpoint_for(pid, cap_id, Rights::READ)?;
        let idx = id as usize;
        if idx >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        if self.endpoint_state[idx] >= 2 {
            self.stats.would_blocks = self.stats.would_blocks.wrapping_add(1);
            return Err(SysError::WouldBlock);
        }
        self.ipc_recv_resolved(id).map(|(msg, _)| msg)
    }

    /// Receive a pending register-only fastpath IPC message from an `Endpoint` in PID 0's `CSpace`.
    #[inline(always)]
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
        let idx = id as usize;
        if idx >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        if self.endpoint_state[idx] != 0 {
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

    /// Move a capability to another slot in `pid`'s `CSpace` (`dst_slot == 0` auto-selects),
    /// updating any cross-process `ExternalParent` CDT links referencing the moved slot.
    pub fn cap_move_for(
        &mut self,
        pid: usize,
        src: CapId,
        dst_slot: usize,
    ) -> Result<CapId, SysError> {
        let old_slot = self.cspace(pid)?.slot_index(src)?;
        let cnode = self.cspace_mut(pid)?;
        let slot = if dst_slot == 0 {
            cnode.find_free_slot()?
        } else {
            dst_slot
        };
        let new_id = cnode.move_cap(src, slot)?;
        let old_ext = ExternalParent {
            cnode_id: pid as u16,
            slot: old_slot as u16,
        };
        let new_ext = ExternalParent {
            cnode_id: pid as u16,
            slot: slot as u16,
        };
        for other in 0..MAX_IPC_PROCS {
            if let Ok(other_cn) = self.cspace_mut(other) {
                other_cn.reparent_external_children(old_ext, Some(new_ext));
            }
        }
        Ok(new_id)
    }

    /// Delete a single capability slot from `pid`'s `CSpace`, preserving cross-process CDT ancestry.
    pub fn cap_delete_for(&mut self, pid: usize, cap_id: CapId) -> Result<(), SysError> {
        self.cap_delete_for_with_frame_reclaim_cb(pid, cap_id, |_, _| {})
    }

    /// Delete a single capability slot from `pid`'s `CSpace`, preserving cross-process CDT ancestry,
    /// and invoking `on_deleted_frame(phys, can_reclaim)` if the deleted capability was a `Frame` (`M3`).
    pub fn cap_delete_for_with_frame_reclaim_cb(
        &mut self,
        pid: usize,
        cap_id: CapId,
        mut on_deleted_frame: impl FnMut(PhysAddr, bool),
    ) -> Result<(), SysError> {
        let deleted_obj = self.cspace(pid)?.lookup(cap_id, Rights::NONE)?.object;
        let (slot, intra_parent, ext_parent) = self.cspace(pid)?.parent_info(cap_id)?;
        self.cspace_mut(pid)?.delete(cap_id)?;

        let old_ext = ExternalParent {
            cnode_id: pid as u16,
            slot: slot as u16,
        };
        let replacement = intra_parent
            .map(|p| ExternalParent {
                cnode_id: pid as u16,
                slot: p as u16,
            })
            .or(ext_parent);
        for other in 0..MAX_IPC_PROCS {
            if let Ok(other_cn) = self.cspace_mut(other) {
                other_cn.reparent_external_children(old_ext, replacement);
            }
        }
        if let CapObject::Frame { phys } = deleted_obj {
            let can_reclaim = !self.has_live_frame_cap(phys);
            on_deleted_frame(phys, can_reclaim);
        }
        Ok(())
    }

    /// Clear all capabilities held by an exited non-root process `pid` (`M4`), invoking
    /// `on_frame(phys, can_reclaim)` for any `Frame` capabilities it held.
    pub fn clear_process_cspace(
        &mut self,
        pid: usize,
        mut on_frame: impl FnMut(PhysAddr, bool),
    ) -> Result<(), SysError> {
        if pid == 0 || pid >= MAX_IPC_PROCS {
            return Err(SysError::InvalidArgument);
        }
        let mut frames = [PhysAddr::new(0); ROOT_CSPACE_SLOTS];
        let mut frame_len = 0usize;
        self.proc_cspaces[pid - 1].clear_all(|cap| {
            if let CapObject::Frame { phys } = cap.object
                && !frames[..frame_len].contains(&phys)
                && frame_len < frames.len()
            {
                frames[frame_len] = phys;
                frame_len += 1;
            }
        });
        for &phys in &frames[..frame_len] {
            let can_reclaim = !self.has_live_frame_cap(phys);
            on_frame(phys, can_reclaim);
        }
        Ok(())
    }

    /// Return `true` if any active `CSpace` holds a live `CapObject::Endpoint { id }` capability.
    #[inline]
    pub fn has_live_endpoint_cap(&self, id: u32) -> bool {
        let obj = CapObject::Endpoint { id };
        self.root_cspace.has_live_object(obj)
            || self.proc_cspaces.iter().any(|cn| cn.has_live_object(obj))
    }

    /// Return `true` if any active `CSpace` holds a live `CapObject::Notification { id }` capability.
    #[inline]
    pub fn has_live_notif_cap(&self, id: u32) -> bool {
        let obj = CapObject::Notification { id };
        self.root_cspace.has_live_object(obj)
            || self.proc_cspaces.iter().any(|cn| cn.has_live_object(obj))
    }

    /// Allocate a free endpoint ID (`0..MAX_ENDPOINTS`), recycling IDs whose capabilities have
    /// all been deleted or revoked (`M5`).
    fn alloc_endpoint_id(&mut self) -> Option<u32> {
        if (self.next_endpoint_id as usize) < MAX_ENDPOINTS {
            let id = u32::from(self.next_endpoint_id);
            self.next_endpoint_id += 1;
            return Some(id);
        }
        // Scan dynamic endpoint IDs (skipping reserved bootstrap IDs 0..=6) for any unused slot.
        (7..(MAX_ENDPOINTS as u32)).find(|&id| !self.has_live_endpoint_cap(id))
    }

    /// Allocate a free notification ID (`0..MAX_NOTIFICATIONS`), recycling IDs whose capabilities
    /// have all been deleted or revoked (`M5`).
    fn alloc_notif_id(&mut self) -> Option<u32> {
        if (self.next_notif_id as usize) < MAX_NOTIFICATIONS {
            let id = u32::from(self.next_notif_id);
            self.next_notif_id += 1;
            return Some(id);
        }
        // Scan dynamic notification IDs (skipping reserved bootstrap IDs 0..=1) for any unused slot.
        (2..(MAX_NOTIFICATIONS as u32)).find(|&id| !self.has_live_notif_cap(id))
    }

    /// Return `true` if any active `CSpace` holds a live `CapObject::Frame { phys }` capability.
    #[inline]
    pub fn has_live_frame_cap(&self, phys: PhysAddr) -> bool {
        self.root_cspace.has_live_frame_cap(phys)
            || self
                .proc_cspaces
                .iter()
                .any(|cn| cn.has_live_frame_cap(phys))
    }

    /// Validate a `Frame` capability in `pid`'s `CSpace`, returning its physical base address.
    #[inline]
    pub fn validate_frame_for(
        &self,
        pid: usize,
        cap_id: CapId,
        required: Rights,
    ) -> Result<PhysAddr, SysError> {
        let cap = self.cspace(pid)?.lookup(cap_id, required)?;
        match cap.object {
            CapObject::Frame { phys } => Ok(phys),
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Retype a kernel object (`Frame`, `Endpoint`, `Notification`) from a designated `Untyped`
    /// capability in `pid`'s `CSpace` (`dst_slot == 0` auto-selects a free slot).
    pub fn untyped_retype_for(
        &mut self,
        pid: usize,
        untyped_cap: CapId,
        obj_type: ObjectType,
        dst_slot: usize,
        inv: &mut UntypedInventory,
    ) -> Result<CapId, SysError> {
        let slot = if dst_slot == 0 {
            self.cspace(pid)?.find_free_slot()?
        } else {
            dst_slot
        };
        match obj_type {
            ObjectType::Frame => {
                self.cspace_mut(pid)?
                    .retype_frame_from_into(untyped_cap, slot, inv)
            }
            ObjectType::Endpoint => {
                let ep_id = self.alloc_endpoint_id().ok_or(SysError::OutOfMemory)?;
                let cap_id = self.cspace_mut(pid)?.insert_retyped_child(
                    untyped_cap,
                    slot,
                    CapObject::Endpoint { id: ep_id },
                )?;
                self.endpoint_state[ep_id as usize] = 0;
                Ok(cap_id)
            }
            ObjectType::Notification => {
                let notif_id = self.alloc_notif_id().ok_or(SysError::OutOfMemory)?;
                let cap_id = self.cspace_mut(pid)?.insert_retyped_child(
                    untyped_cap,
                    slot,
                    CapObject::Notification { id: notif_id },
                )?;
                self.notifications[notif_id as usize] = 0;
                Ok(cap_id)
            }
            _ => Err(SysError::Unsupported),
        }
    }

    /// Transitively revoke all CDT descendants of `cap_id` across all `CSpace`s, invoking
    /// `on_revoked_frame(phys, can_reclaim)` for each unique revoked `CapObject::Frame { phys }`
    /// per revoked `CSpace`, where `can_reclaim` is `true` ONLY when NO live `CapObject::Frame`
    /// capability for `phys` remains in any `CSpace` (preventing physical-frame aliasing / UAF).
    pub fn cap_revoke_for_with_frame_reclaim_cb(
        &mut self,
        pid: usize,
        cap_id: CapId,
        mut on_revoked_frame: impl FnMut(PhysAddr, bool),
    ) -> Result<usize, SysError> {
        let mut batch = [PhysAddr::new(0); ROOT_CSPACE_SLOTS];
        let mut batch_len = 0usize;
        let (mut total, root_slot, local_mask) = {
            let mut collect = |cap: Capability| {
                if let CapObject::Frame { phys } = cap.object
                    && !batch[..batch_len].contains(&phys)
                    && batch_len < batch.len()
                {
                    batch[batch_len] = phys;
                    batch_len += 1;
                }
            };
            self.cspace_mut(pid)?
                .revoke_with_mask_cb(cap_id, &mut collect)?
        };
        for &phys in &batch[..batch_len] {
            let can_reclaim = !self.has_live_frame_cap(phys);
            on_revoked_frame(phys, can_reclaim);
        }

        let mut parent_masks = [0u64; MAX_IPC_PROCS];
        parent_masks[pid] = local_mask | (1u64 << root_slot);

        let mut changed = true;
        while changed {
            changed = false;
            for target_pid in 0..MAX_IPC_PROCS {
                batch_len = 0;
                let (cnt, new_mask) = {
                    let mut collect = |cap: Capability| {
                        if let CapObject::Frame { phys } = cap.object
                            && !batch[..batch_len].contains(&phys)
                            && batch_len < batch.len()
                        {
                            batch[batch_len] = phys;
                            batch_len += 1;
                        }
                    };
                    self.cspace_mut(target_pid)?
                        .revoke_matching_external_parents_cb(&parent_masks, &mut collect)
                };
                for &phys in &batch[..batch_len] {
                    let can_reclaim = !self.has_live_frame_cap(phys);
                    on_revoked_frame(phys, can_reclaim);
                }
                if new_mask != 0 {
                    parent_masks[target_pid] |= new_mask;
                    total += cnt;
                    changed = true;
                }
            }
        }
        Ok(total)
    }

    /// Transitively revoke all CDT descendants of `cap_id` across all `CSpace`s, invoking
    /// `on_revoked_frame` for EVERY revoked `CapObject::Frame { phys }` (no fixed buffer cap).
    pub fn cap_revoke_for_with_frame_cb(
        &mut self,
        pid: usize,
        cap_id: CapId,
        mut on_revoked_frame: impl FnMut(PhysAddr),
    ) -> Result<usize, SysError> {
        let mut handle_cap = |cap: Capability| {
            if let CapObject::Frame { phys } = cap.object {
                on_revoked_frame(phys);
            }
        };

        let (mut total, root_slot, local_mask) = self
            .cspace_mut(pid)?
            .revoke_with_mask_cb(cap_id, &mut handle_cap)?;
        let mut parent_masks = [0u64; MAX_IPC_PROCS];
        parent_masks[pid] = local_mask | (1u64 << root_slot);

        let mut changed = true;
        while changed {
            changed = false;
            for target_pid in 0..MAX_IPC_PROCS {
                let (cnt, new_mask) = self
                    .cspace_mut(target_pid)?
                    .revoke_matching_external_parents_cb(&parent_masks, &mut handle_cap);
                if new_mask != 0 {
                    parent_masks[target_pid] |= new_mask;
                    total += cnt;
                    changed = true;
                }
            }
        }
        Ok(total)
    }

    /// Transitively revoke all CDT descendants of `cap_id` across all `CSpace`s, collecting any
    /// revoked `CapObject::Frame { phys }` addresses into `revoked_frames` so hardware PTEs can
    /// be unmapped and flushed (`H-3`). Returns `(revoked_cap_count, collected_frame_count)`.
    pub fn cap_revoke_for_collecting_frames(
        &mut self,
        pid: usize,
        cap_id: CapId,
        revoked_frames: &mut [Option<PhysAddr>],
    ) -> Result<(usize, usize), SysError> {
        let mut frame_count = 0usize;
        let total = self.cap_revoke_for_with_frame_cb(pid, cap_id, |phys| {
            if frame_count < revoked_frames.len() {
                revoked_frames[frame_count] = Some(phys);
                frame_count += 1;
            }
        })?;
        Ok((total, frame_count))
    }

    /// Transitively revoke all CDT descendants of `cap_id` across `pid`'s `CSpace` AND any
    /// capabilities granted into other processes' `CSpace`s (multi-hop cross-process CDT).
    pub fn cap_revoke_for(&mut self, pid: usize, cap_id: CapId) -> Result<usize, SysError> {
        self.cap_revoke_for_with_frame_cb(pid, cap_id, |_| {})
    }

    /// Grant an attenuated capability from `src_pid`'s `CSpace` into the `CNode` designated by
    /// `dst_cnode_cap` (`CapObject::CNode`, requiring `Rights::WRITE`), validating that the
    /// target PID is `< active_procs`.
    pub fn cap_grant_between_checked(
        &mut self,
        src_pid: usize,
        dst_cnode_cap: CapId,
        src_cap: CapId,
        rights_mask: Rights,
        new_badge: Option<u64>,
        active_procs: usize,
    ) -> Result<CapId, SysError> {
        let dst_pid = self.validate_cnode_for(src_pid, dst_cnode_cap, Rights::WRITE)?;
        if dst_pid >= active_procs {
            return Err(SysError::InvalidArgument);
        }
        if src_pid == dst_pid {
            return self.cap_mint_for(src_pid, src_cap, 0, rights_mask, new_badge);
        }

        let src_slot = self.cspace(src_pid)?.slot_index(src_cap)?;
        let cap = *self.cspace(src_pid)?.lookup(src_cap, Rights::GRANT)?;
        let badge = match new_badge {
            None => cap.badge,
            Some(0) => return Err(SysError::InvalidArgument),
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
        let ext_parent = ExternalParent {
            cnode_id: src_pid as u16,
            slot: src_slot as u16,
        };
        self.cspace_mut(dst_pid)?
            .insert_external_derived(derived, ext_parent)
    }

    /// Grant an attenuated capability from `src_pid`'s `CSpace` into the `CNode` designated by
    /// `dst_cnode_cap` (`CapObject::CNode`, requiring `Rights::WRITE`).
    ///
    /// Enforces `Rights::GRANT` on `src_cap`, non-escalating rights attenuation, immutable non-zero
    /// badging, and preserves cross-process CDT ancestry for transitive `CapRevoke`.
    pub fn cap_grant_between(
        &mut self,
        src_pid: usize,
        dst_cnode_cap: CapId,
        src_cap: CapId,
        rights_mask: Rights,
        new_badge: Option<u64>,
    ) -> Result<CapId, SysError> {
        self.cap_grant_between_checked(
            src_pid,
            dst_cnode_cap,
            src_cap,
            rights_mask,
            new_badge,
            MAX_IPC_PROCS,
        )
    }

    /// Validate an EL0 driver's 32-bit MMIO read against `pid`'s `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_read32_for(
        &self,
        pid: usize,
        cap_id: CapId,
        offset: u64,
    ) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(pid, cap_id, offset, Rights::READ)
    }

    /// Validate an EL0 driver's 32-bit MMIO write against `pid`'s `MmioRegion` capability.
    #[inline]
    pub fn validate_mmio_write32_for(
        &self,
        pid: usize,
        cap_id: CapId,
        offset: u64,
    ) -> Result<PhysAddr, SysError> {
        self.validate_mmio_access32(pid, cap_id, offset, Rights::WRITE)
    }

    /// Validate an EL0 driver's 32-bit MMIO read in PID 0's `CSpace`.
    #[inline]
    pub fn validate_mmio_read32(&self, cap_id: CapId, offset: u64) -> Result<PhysAddr, SysError> {
        self.validate_mmio_read32_for(0, cap_id, offset)
    }

    /// Validate an EL0 driver's 32-bit MMIO write in PID 0's `CSpace`.
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
            phys.raw()
                .checked_add(offset)
                .ok_or(SysError::InvalidArgument)?,
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
        assert!(
            ipc.notify_signal_for(0, CapId::BOOTSTRAP_FAULT_NOTIF, 1)
                .is_ok()
        );

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
        let (worker1_thread, worker1_cnode) = ipc.register_child_caps_in_root(1).unwrap();
        assert_eq!(
            ipc.validate_thread_for(0, worker1_thread, Rights::WRITE),
            Ok(1)
        );

        // Mint badged read-only notification in PID 0 (auto slot).
        let minted = ipc
            .cap_mint_for(0, notif, 0, Rights::READ.union(Rights::GRANT), Some(0xAA))
            .unwrap();
        // Copy and move within PID 0.
        let copied = ipc.cap_copy_for(0, minted, 0).unwrap();
        let moved = ipc.cap_move_for(0, copied, 0).unwrap();
        assert_eq!(
            ipc.notify_poll_for(0, copied),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(ipc.notify_poll_for(0, moved), Ok(0));

        // Revoke from `notif` transitively destroys both `minted` and `moved`.
        assert_eq!(ipc.cap_revoke_for(0, notif), Ok(2));
        assert_eq!(
            ipc.notify_poll_for(0, moved),
            Err(SysError::InvalidCapability)
        );

        // Cross-process CapGrant via designated CNode capability: PID 0 -> PID 1.
        let granted = ipc
            .cap_grant_between(0, worker1_cnode, notif, Rights::READ, Some(0xBEEF))
            .unwrap();
        assert_eq!(ipc.notify_poll_for(1, granted), Ok(0));
        // Attenuated right enforced in PID 1 (cannot signal a READ-only cap).
        assert_eq!(
            ipc.notify_signal_for(1, granted, 1),
            Err(SysError::InsufficientRights)
        );
        // Unprivileged PID 1 holds no CNode cap for PID 0, so granting into PID 0 fails.
        assert_eq!(
            ipc.cap_grant_between(
                1,
                CapId::BOOTSTRAP_SELF_CNODE,
                CapId::BOOTSTRAP_EP,
                Rights::READ,
                None
            ),
            Err(SysError::InvalidCapability)
        );
        // Deleting in PID 1 does not affect PID 0's `notif` or `ep`.
        ipc.cap_delete_for(1, granted).unwrap();
        assert_eq!(
            ipc.notify_poll_for(1, granted),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(ipc.notify_poll_for(0, notif), Ok(0));
        assert!(ipc.ipc_send_for(0, ep, 7).is_ok());
    }

    #[test]
    fn cross_process_cdt_revocation_cascades_across_hops_and_move_delete() {
        let mut ipc = KernelIpcState::new();
        let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();
        let _ = ipc.init_worker_bootstrap_caps(1).unwrap();
        let _ = ipc.init_worker_bootstrap_caps(2).unwrap();
        let (_, w1_cnode) = ipc.register_child_caps_in_root(1).unwrap();
        let (_, w2_cnode) = ipc.register_child_caps_in_root(2).unwrap();

        // Delegate PID 2's CNode cap to PID 1 so PID 1 can grant to PID 2 (no PID-0 ambient check!).
        let w2_cnode_in_1 = ipc
            .cap_grant_between(0, w1_cnode, w2_cnode, Rights::WRITE, None)
            .unwrap();

        // Multi-hop grant chain: PID 0 (`notif`) -> PID 1 (`g1`) -> local mint (`g1_child`) -> PID 2 (`g2`) -> local mint (`g2_child`).
        let g1 = ipc
            .cap_grant_between(
                0,
                w1_cnode,
                notif,
                Rights::READ.union(Rights::GRANT),
                Some(0x1111_2222_3333_4444),
            )
            .unwrap();
        let g1_child = ipc
            .cap_mint_for(1, g1, 0, Rights::READ.union(Rights::GRANT), None)
            .unwrap();
        let g2 = ipc
            .cap_grant_between(
                1,
                w2_cnode_in_1,
                g1_child,
                Rights::READ.union(Rights::GRANT),
                None,
            )
            .unwrap();
        let g2_child = ipc.cap_mint_for(2, g2, 0, Rights::READ, None).unwrap();

        // Move `g1_child` in PID 1 and verify cross-process parent link to `g2` stays intact.
        let g1_moved = ipc.cap_move_for(1, g1_child, 0).unwrap();
        assert_eq!(ipc.notify_poll_for(2, g2_child), Ok(0));

        // Revoking `notif` in PID 0 transitively destroys all 4 descendants across PID 1 & PID 2!
        assert_eq!(ipc.cap_revoke_for(0, notif), Ok(4));
        assert_eq!(ipc.notify_poll_for(1, g1), Err(SysError::InvalidCapability));
        assert_eq!(
            ipc.notify_poll_for(1, g1_moved),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(ipc.notify_poll_for(2, g2), Err(SysError::InvalidCapability));
        assert_eq!(
            ipc.notify_poll_for(2, g2_child),
            Err(SysError::InvalidCapability)
        );

        // Deleting intermediate cap `g1_b` in PID 1 reparents `g2_b` in PID 2 back to PID 0's `notif`.
        let g1_b = ipc
            .cap_grant_between(0, w1_cnode, notif, Rights::READ.union(Rights::GRANT), None)
            .unwrap();
        let g2_b = ipc
            .cap_grant_between(1, w2_cnode_in_1, g1_b, Rights::READ, None)
            .unwrap();
        ipc.cap_delete_for(1, g1_b).unwrap();
        assert_eq!(ipc.cap_revoke_for(0, notif), Ok(1));
        assert_eq!(
            ipc.notify_poll_for(2, g2_b),
            Err(SysError::InvalidCapability)
        );

        // Explicit Some(0) badge is rejected in CapGrant.
        assert_eq!(
            ipc.cap_grant_between(0, w1_cnode, notif, Rights::READ, Some(0)),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn untyped_retype_and_revoke_collects_revoked_frames() {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x8000_0000, crate::memory::PAGE_SIZE * 2));

        let f_cap = ipc
            .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
            .unwrap();
        let ep_cap = ipc
            .untyped_retype_for(
                0,
                CapId::BOOTSTRAP_UNTYPED,
                ObjectType::Endpoint,
                0,
                &mut inv,
            )
            .unwrap();
        let n_cap = ipc
            .untyped_retype_for(
                0,
                CapId::BOOTSTRAP_UNTYPED,
                ObjectType::Notification,
                0,
                &mut inv,
            )
            .unwrap();

        assert_eq!(
            ipc.validate_frame_for(0, f_cap, Rights::READ.union(Rights::WRITE)),
            Ok(PhysAddr::new(0x8000_0000))
        );
        assert!(ipc.ipc_send_for(0, ep_cap, 0x1234).is_ok());
        assert!(ipc.notify_signal_for(0, n_cap, 0x1).is_ok());

        // Revoking BOOTSTRAP_UNTYPED revokes all 3 retyped caps and reports the Frame phys addr.
        let mut revoked_frames = [None; 8];
        let (revoked_caps, frame_cnt) = ipc
            .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut revoked_frames)
            .unwrap();
        assert_eq!(revoked_caps, 3);
        assert_eq!(frame_cnt, 1);
        assert_eq!(revoked_frames[0], Some(PhysAddr::new(0x8000_0000)));
        assert_eq!(
            ipc.validate_frame_for(0, f_cap, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn designated_platform_console_power_and_vspace_caps_isolate_worker() {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();
        ipc.bind_bootstrap_vspace(0, PhysAddr::new(0x4000_0000))
            .unwrap();
        let _ = ipc.init_worker_bootstrap_caps(1).unwrap();

        // PID 0 (`init`) holds full Console, PowerControl, and bound VSpace capabilities.
        assert_eq!(
            ipc.validate_console_for(
                0,
                CapId::BOOTSTRAP_CONSOLE,
                Rights::READ.union(Rights::WRITE)
            ),
            Ok(())
        );
        assert_eq!(
            ipc.validate_power_for(0, CapId::BOOTSTRAP_POWER, Rights::READ.union(Rights::WRITE)),
            Ok(())
        );
        assert_eq!(
            ipc.validate_vspace_for(
                0,
                CapId::BOOTSTRAP_VSPACE,
                Rights::READ.union(Rights::WRITE)
            ),
            Ok(PhysAddr::new(0x4000_0000))
        );

        // PID 1 (`worker`) has NO direct Console capability (single-owner console in `init`),
        // and instead logs through write-only, PID-badged `BOOTSTRAP_LOG_EP`.
        assert_eq!(
            ipc.validate_console_for(1, CapId::BOOTSTRAP_CONSOLE, Rights::WRITE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_console_for(1, CapId::BOOTSTRAP_CONSOLE, Rights::READ),
            Err(SysError::InvalidCapability)
        );
        let log_chunk = newos_abi::log_ipc::encode_chunk(b"hello\n");
        assert_eq!(
            ipc.ipc_send_for(1, CapId::BOOTSTRAP_LOG_EP, log_chunk),
            Ok(())
        );
        assert_eq!(
            ipc.ipc_recv_for(1, CapId::BOOTSTRAP_LOG_EP),
            Err(SysError::InsufficientRights)
        );
        assert_eq!(
            ipc.ipc_recv_for(0, CapId::BOOTSTRAP_LOG_EP),
            Ok(IpcMessage {
                badge: 1,
                payload: log_chunk,
            })
        );

        // PID 1 has NO PowerControl (Exit/SysInfo) and NO VSpace (MapPage/UnmapPage/VirtToPhys).
        assert_eq!(
            ipc.validate_power_for(1, CapId::BOOTSTRAP_POWER, Rights::WRITE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_power_for(1, CapId::BOOTSTRAP_POWER, Rights::READ),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_vspace_for(1, CapId::BOOTSTRAP_VSPACE, Rights::WRITE),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_vspace_for(1, CapId::BOOTSTRAP_VSPACE, Rights::READ),
            Err(SysError::InvalidCapability)
        );

        // Wrong object type and CapId::NULL are rejected cleanly.
        assert_eq!(
            ipc.validate_power_for(0, CapId::BOOTSTRAP_EP, Rights::WRITE),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ipc.validate_vspace_for(0, CapId::NULL, Rights::READ),
            Err(SysError::InvalidCapability)
        );
    }

    #[test]
    fn kernel_ipc_state_footprint_resolved_sender_and_over_64_frame_revoke() {
        assert!(core::mem::size_of::<KernelIpcState>() <= 25_224);

        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();

        // Resolved send/recv tracks sender_pid and rejects out-of-range endpoint IDs.
        assert_eq!(
            ipc.ipc_send_resolved(MAX_ENDPOINTS as u32, 0, 1, None),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ipc.ipc_recv_resolved(MAX_ENDPOINTS as u32),
            Err(SysError::InvalidArgument)
        );
        ipc.ipc_send_resolved(0, 0x5E14, 0xDEAD, Some(3)).unwrap();
        assert_eq!(
            ipc.ipc_send_resolved(0, 0x5E14, 0xBEEF, Some(4)),
            Err(SysError::WouldBlock)
        );
        assert_eq!(
            ipc.ipc_recv_resolved(0),
            Ok((
                IpcMessage {
                    badge: 0x5E14,
                    payload: 0xDEAD
                },
                Some(3)
            ))
        );
        assert_eq!(ipc.ipc_recv_resolved(0), Err(SysError::WouldBlock));

        // Out-of-range PIDs rejected cleanly.
        assert_eq!(
            ipc.cspace(MAX_IPC_PROCS).err(),
            Some(SysError::InvalidArgument)
        );
        assert_eq!(
            ipc.ipc_send_for(MAX_IPC_PROCS, CapId::BOOTSTRAP_EP, 1),
            Err(SysError::InvalidArgument)
        );

        // Revoking >64 Frame capabilities across multiple processes invokes callback for EVERY frame.
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x8000_0000, crate::memory::PAGE_SIZE * 80));
        let (_, c1) = ipc.register_child_caps_in_root(1).unwrap();
        let (_, c2) = ipc.register_child_caps_in_root(2).unwrap();

        // Retype 40 frames in PID 0, grant each into PID 1 and PID 2 (40 + 40 + 40 = 120 Frame caps > 64!).
        let mut expected_frames = 0usize;
        for _ in 0..40 {
            let f0 = ipc
                .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
                .unwrap();
            let _ = ipc
                .cap_grant_between(0, c1, f0, Rights::READ.union(Rights::WRITE), None)
                .unwrap();
            let _ = ipc
                .cap_grant_between(0, c2, f0, Rights::READ.union(Rights::WRITE), None)
                .unwrap();
            expected_frames += 3;
        }
        assert!(expected_frames > 64);

        let mut seen_frames = 0usize;
        let revoked = ipc
            .cap_revoke_for_with_frame_cb(0, CapId::BOOTSTRAP_UNTYPED, |_phys| {
                seen_frames += 1;
            })
            .unwrap();
        assert_eq!(revoked, expected_frames);
        assert_eq!(seen_frames, expected_frames);
    }

    #[test]
    fn drain_buffered_call_senders_wakes_only_callers_and_preserves_plain_sends() {
        let mut ipc = KernelIpcState::new();

        // Buffer two IpcCall senders (PID 0 on ep 0, PID 5 on ep 4), one plain IpcSend
        // (sender=None on ep 2), and one out-of-range sender PID (treated as plain send on ep 6).
        ipc.ipc_send_resolved(0, 0x10, 0xAAAA, Some(0)).unwrap();
        ipc.ipc_send_resolved(2, 0x20, 0xBBBB, None).unwrap();
        ipc.ipc_send_resolved(4, 0x30, 0xCCCC, Some(5)).unwrap();
        ipc.ipc_send_resolved(6, 0x40, 0xDDDD, Some(MAX_IPC_PROCS))
            .unwrap();

        let mut drained = [usize::MAX; 4];
        let mut drained_len = 0usize;
        ipc.drain_buffered_call_senders(|pid| {
            drained[drained_len] = pid;
            drained_len += 1;
        });

        assert_eq!(drained_len, 2);
        assert_eq!(&drained[..drained_len], &[0, 5]);

        // Drained IpcCall endpoints are now empty.
        assert_eq!(ipc.ipc_recv_resolved(0), Err(SysError::WouldBlock));
        assert_eq!(ipc.ipc_recv_resolved(4), Err(SysError::WouldBlock));

        // Plain sends (sender_pid == None or out-of-range) remain intact.
        assert_eq!(
            ipc.ipc_recv_resolved(2),
            Ok((
                IpcMessage {
                    badge: 0x20,
                    payload: 0xBBBB
                },
                None
            ))
        );
        assert_eq!(
            ipc.ipc_recv_resolved(6),
            Ok((
                IpcMessage {
                    badge: 0x40,
                    payload: 0xDDDD
                },
                None
            ))
        );
    }

    #[test]
    fn frame_reclaim_cb_guards_live_frame_caps_across_processes() {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();
        let _ = ipc.init_worker_bootstrap_caps(1).unwrap();
        let (_, w1_cnode) = ipc.register_child_caps_in_root(1).unwrap();
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x4000_0000, crate::memory::PAGE_SIZE * 4));

        // Retype a frame from BOOTSTRAP_UNTYPED, copy locally, and grant a child to PID 1.
        let frame_root = ipc
            .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
            .unwrap();
        let phys = ipc.validate_frame_for(0, frame_root, Rights::READ).unwrap();
        assert!(ipc.has_live_frame_cap(phys));

        let frame_child_0 = ipc.cap_copy_for(0, frame_root, 0).unwrap();
        let _frame_child_1 = ipc
            .cap_grant_between_checked(
                0,
                w1_cnode,
                frame_child_0,
                Rights::READ.union(Rights::WRITE),
                None,
                2,
            )
            .unwrap();

        // CapRevoke(frame_root) revokes descendants while frame_root survives -> can_reclaim MUST be false.
        let mut events = [(PhysAddr::new(0), false); 8];
        let mut n_events = 0usize;
        let revoked = ipc
            .cap_revoke_for_with_frame_reclaim_cb(0, frame_root, |p, can_reclaim| {
                events[n_events] = (p, can_reclaim);
                n_events += 1;
            })
            .unwrap();
        assert_eq!(revoked, 2);
        assert_eq!(n_events, 2);
        assert!(events[..n_events].iter().all(|&(p, can)| p == phys && !can));
        assert!(ipc.has_live_frame_cap(phys));

        // Re-grant to PID 1, then CapRevoke(BOOTSTRAP_UNTYPED) -> can_reclaim is true ONLY once last cap is gone.
        let _frame_child_1b = ipc
            .cap_grant_between_checked(
                0,
                w1_cnode,
                frame_root,
                Rights::READ.union(Rights::WRITE),
                None,
                2,
            )
            .unwrap();
        n_events = 0;
        let revoked_all = ipc
            .cap_revoke_for_with_frame_reclaim_cb(0, CapId::BOOTSTRAP_UNTYPED, |p, can_reclaim| {
                events[n_events] = (p, can_reclaim);
                n_events += 1;
            })
            .unwrap();
        assert_eq!(revoked_all, 2);
        assert_eq!(n_events, 2);
        assert_eq!(events[0], (phys, false));
        assert_eq!(events[1], (phys, true));
        assert!(!ipc.has_live_frame_cap(phys));

        // Direct CapDelete on sole Frame cap also drops has_live_frame_cap to false.
        let frame2 = ipc
            .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
            .unwrap();
        let phys2 = ipc.validate_frame_for(0, frame2, Rights::READ).unwrap();
        assert!(ipc.has_live_frame_cap(phys2));
        ipc.cap_delete_for(0, frame2).unwrap();
        assert!(!ipc.has_live_frame_cap(phys2));
    }

    #[test]
    fn cross_process_cdt_return_to_origin_move_delete_and_revoke() {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();
        let _ = ipc.init_worker_bootstrap_caps(1).unwrap();
        let (_, w1_cnode) = ipc.register_child_caps_in_root(1).unwrap();

        // Give PID 1 a CNode cap to PID 0 so PID 1 can grant back to PID 0.
        let cnode0_in_pid1 = ipc
            .cspace_mut(1)
            .unwrap()
            .insert_root_at(20, Capability::new(CapObject::CNode { id: 0 }, Rights::ALL))
            .unwrap();

        // Part A: PID 0 -> PID 1 -> PID 0, delete intermediate g1, move root in PID 0, revoke moved root.
        let root_a = ipc
            .cspace_mut(0)
            .unwrap()
            .insert_root_at(
                30,
                Capability::new(CapObject::Notification { id: 7 }, Rights::ALL),
            )
            .unwrap();
        let g1 = ipc
            .cap_grant_between_checked(0, w1_cnode, root_a, Rights::ALL, None, 2)
            .unwrap();
        let g2 = ipc
            .cap_grant_between_checked(1, cnode0_in_pid1, g1, Rights::READ, None, 2)
            .unwrap();
        ipc.cap_delete_for(1, g1).unwrap();
        let moved_a = ipc.cap_move_for(0, root_a, 40).unwrap();
        assert_eq!(ipc.cap_revoke_for(0, moved_a), Ok(1));
        assert_eq!(
            ipc.cspace(0).unwrap().lookup(g2, Rights::READ),
            Err(SysError::InvalidCapability)
        );

        // Part B: Return-to-origin + delete root + reuse original slot 30 for unrelated cap + revoke.
        let root_b = ipc
            .cspace_mut(0)
            .unwrap()
            .insert_root_at(
                30,
                Capability::new(CapObject::Notification { id: 8 }, Rights::ALL),
            )
            .unwrap();
        let g1_b = ipc
            .cap_grant_between_checked(0, w1_cnode, root_b, Rights::ALL, None, 2)
            .unwrap();
        let g2_b = ipc
            .cap_grant_between_checked(1, cnode0_in_pid1, g1_b, Rights::READ, None, 2)
            .unwrap();
        ipc.cap_delete_for(1, g1_b).unwrap();
        ipc.cap_delete_for(0, root_b).unwrap();

        let unrelated = ipc
            .cspace_mut(0)
            .unwrap()
            .insert_root_at(
                30,
                Capability::new(CapObject::Endpoint { id: 9 }, Rights::ALL),
            )
            .unwrap();
        assert_eq!(ipc.cap_revoke_for(0, unrelated), Ok(0));
        assert!(ipc.cspace(0).unwrap().lookup(g2_b, Rights::READ).is_ok());
    }

    #[test]
    fn three_process_ssh_capability_isolation_enforces_least_privilege() {
        let mut ipc = KernelIpcState::new();
        let net_mmio = Some((PhysAddr::new(0x1F_0010_0000), 0x4000));
        let rng_mmio = Some((PhysAddr::new(0x10_7D20_8000), 0x28));

        // PID 0 (`init`): holds no NET_MMIO when netd owns it, no RNG_MMIO, no KEY_EP,
        // read-only AUTH_GATE_EP, and SSH_SHELL_EP.
        ipc.init_bootstrap_caps(None).unwrap();
        // PID 2 (`netd`): NIC MMIO + read-only VSpace + NET_EP + badged LOG_EP only.
        ipc.init_netd_bootstrap_caps(2, net_mmio).unwrap();
        // PID 3 (`keyd`, Raspberry Pi 5 mode): RNG MMIO + KEY_EP + write-only AUTH_GATE_EP, NO VSpace.
        ipc.init_keyd_bootstrap_caps(3, rng_mmio, false).unwrap();
        // PID 4 (`sshd`): ZERO MMIO, ZERO VSpace, ZERO AUTH_GATE_EP, ZERO THREAD/CNODE.
        ipc.init_sshd_bootstrap_caps(4).unwrap();

        // 1. MMIO isolation
        assert_eq!(
            ipc.validate_mmio_read32_for(2, CapId::BOOTSTRAP_NET_MMIO, 0),
            Ok(PhysAddr::new(0x1F_0010_0000))
        );
        assert_eq!(
            ipc.validate_mmio_read32_for(2, CapId::BOOTSTRAP_RNG_MMIO, 0),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_mmio_read32_for(3, CapId::BOOTSTRAP_RNG_MMIO, 0),
            Ok(PhysAddr::new(0x10_7D20_8000))
        );
        assert_eq!(
            ipc.validate_mmio_read32_for(3, CapId::BOOTSTRAP_RNG_MMIO, 0x28),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ipc.validate_mmio_read32_for(3, CapId::BOOTSTRAP_NET_MMIO, 0),
            Err(SysError::InvalidCapability)
        );
        // `sshd` (PID 4) has ZERO MMIO capabilities
        assert_eq!(
            ipc.validate_mmio_read32_for(4, CapId::BOOTSTRAP_NET_MMIO, 0),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_mmio_read32_for(4, CapId::BOOTSTRAP_RNG_MMIO, 0),
            Err(SysError::InvalidCapability)
        );

        // 2. VSpace isolation (`netd` has READ-only; Pi 5 `keyd` and `sshd` have NONE)
        assert_eq!(
            ipc.validate_vspace_for(2, CapId::BOOTSTRAP_VSPACE, Rights::READ),
            Ok(PhysAddr::new(0))
        );
        assert_eq!(
            ipc.validate_vspace_for(2, CapId::BOOTSTRAP_VSPACE, Rights::WRITE),
            Err(SysError::InsufficientRights)
        );
        assert_eq!(
            ipc.validate_vspace_for(3, CapId::BOOTSTRAP_VSPACE, Rights::READ),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_vspace_for(4, CapId::BOOTSTRAP_VSPACE, Rights::READ),
            Err(SysError::InvalidCapability)
        );

        // 3. Auth-gate isolation: ONLY `keyd` (PID 3) can write, ONLY `init` (PID 0) can read.
        // `sshd` (PID 4) and `netd` (PID 2) cannot forge SessionOpen!
        assert_eq!(
            ipc.ipc_send_for(4, CapId::BOOTSTRAP_AUTH_GATE_EP, 1),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.ipc_send_for(2, CapId::BOOTSTRAP_AUTH_GATE_EP, 1),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.ipc_send_for(0, CapId::BOOTSTRAP_AUTH_GATE_EP, 1),
            Err(SysError::InsufficientRights)
        );
        assert_eq!(
            ipc.ipc_recv_for(3, CapId::BOOTSTRAP_AUTH_GATE_EP),
            Err(SysError::InsufficientRights)
        );
        assert_eq!(
            ipc.ipc_send_for(3, CapId::BOOTSTRAP_AUTH_GATE_EP, 0xA07B),
            Ok(())
        );
        assert_eq!(
            ipc.ipc_recv_for(0, CapId::BOOTSTRAP_AUTH_GATE_EP),
            Ok(IpcMessage {
                badge: 3,
                payload: 0xA07B,
            })
        );

        // 4. Key-vault endpoint isolation: ONLY `sshd` (PID 4) and `keyd` (PID 3) hold KEY_EP
        assert_eq!(
            ipc.ipc_send_for(2, CapId::BOOTSTRAP_KEY_EP, 1),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.ipc_send_for(0, CapId::BOOTSTRAP_KEY_EP, 1),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(ipc.ipc_send_for(4, CapId::BOOTSTRAP_KEY_EP, 0xCAFE), Ok(()));
        assert_eq!(
            ipc.ipc_recv_for(3, CapId::BOOTSTRAP_KEY_EP),
            Ok(IpcMessage {
                badge: 4,
                payload: 0xCAFE,
            })
        );

        // 5. Zero Thread / CNode / Console / Power / Untyped / GRANT on all 3 daemons
        for pid in [2usize, 3, 4] {
            assert_eq!(
                ipc.validate_thread_for(pid, CapId::BOOTSTRAP_SELF_THREAD, Rights::READ),
                Err(SysError::InvalidCapability)
            );
            assert_eq!(
                ipc.validate_console_for(pid, CapId::BOOTSTRAP_CONSOLE, Rights::WRITE),
                Err(SysError::InvalidCapability)
            );
            assert_eq!(
                ipc.validate_power_for(pid, CapId::BOOTSTRAP_POWER, Rights::READ),
                Err(SysError::InvalidCapability)
            );
            assert_eq!(
                ipc.cap_mint_for(pid, CapId::BOOTSTRAP_LOG_EP, 0, Rights::WRITE, None),
                Err(SysError::InsufficientRights)
            );
        }
    }
}
