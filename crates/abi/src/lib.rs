#![no_std]
#![forbid(unsafe_code)]

//! Shared, 100% memory-safe ABI contract between the NewOS microkernel and Ring-3 userspace.

pub mod ring;

/// Unforgeable handle indexing a slot inside a process's capability space (`CSpace`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CapId(pub u64);

impl CapId {
    /// Sentinel representing an empty / null capability slot.
    pub const NULL: Self = Self(0);

    /// Well-known bootstrap `Notification` capability installed in `init`'s CSpace (slot 1, gen 1).
    pub const BOOTSTRAP_NOTIF: Self = Self((1u64 << 32) | 1);

    /// Well-known bootstrap `Endpoint` capability installed in `init`'s CSpace (slot 2, gen 1).
    pub const BOOTSTRAP_EP: Self = Self((1u64 << 32) | 2);

    /// Well-known bootstrap Fault `Notification` capability (slot 3, gen 1) signaled on Ring-3 faults.
    pub const BOOTSTRAP_FAULT_NOTIF: Self = Self((1u64 << 32) | 3);

    /// Well-known bootstrap VirtIO-MMIO capability (slot 4, gen 1) for Ring-3 NIC drivers.
    pub const BOOTSTRAP_NET_MMIO: Self = Self((1u64 << 32) | 4);

    /// Well-known bootstrap Console capability (slot 5, gen 1) gating `DebugRead`/`DebugWrite`.
    pub const BOOTSTRAP_CONSOLE: Self = Self((1u64 << 32) | 5);

    /// Well-known bootstrap Power/Platform capability (slot 6, gen 1) gating `Exit`/`SysInfo`.
    pub const BOOTSTRAP_POWER: Self = Self((1u64 << 32) | 6);

    /// Well-known bootstrap `VSpace` capability (slot 7, gen 1) gating `MapPage`/`UnmapPage`/`VirtToPhys`.
    pub const BOOTSTRAP_VSPACE: Self = Self((1u64 << 32) | 7);

    /// Well-known bootstrap `Thread` capability (slot 8, gen 1) for the caller's own thread.
    pub const BOOTSTRAP_SELF_THREAD: Self = Self((1u64 << 32) | 8);

    /// Well-known bootstrap `CNode` capability (slot 9, gen 1) for the caller's own `CSpace`.
    pub const BOOTSTRAP_SELF_CNODE: Self = Self((1u64 << 32) | 9);

    /// Well-known bootstrap `Untyped` physical memory capability (slot 10, gen 1) for `UntypedRetype`.
    pub const BOOTSTRAP_UNTYPED: Self = Self((1u64 << 32) | 10);

    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Bitmask of permissions attached to a capability.
///
/// Rights may only ever be attenuated (narrowed via intersection), never escalated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0b0001_1111);

    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Construct a `Rights` bitmask from raw bits, truncating any unknown bits.
    #[inline]
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::ALL.0)
    }

    /// Strictly attenuate rights: the resulting set is always a subset of `self`.
    #[inline]
    pub const fn attenuate(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }

    #[inline]
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Irreducible seL4-style kernel object types created by retyping `Untyped` memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectType {
    Untyped = 0,
    Frame = 1,
    PageTable = 2,
    VSpace = 3,
    CNode = 4,
    Thread = 5,
    Endpoint = 6,
    Notification = 7,
    IrqHandler = 8,
    MmioRegion = 9,
    Console = 10,
    PowerControl = 11,
    IoSpace = 12,
}

impl ObjectType {
    #[inline]
    pub const fn from_u64(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Untyped),
            1 => Some(Self::Frame),
            2 => Some(Self::PageTable),
            3 => Some(Self::VSpace),
            4 => Some(Self::CNode),
            5 => Some(Self::Thread),
            6 => Some(Self::Endpoint),
            7 => Some(Self::Notification),
            8 => Some(Self::IrqHandler),
            9 => Some(Self::MmioRegion),
            10 => Some(Self::Console),
            11 => Some(Self::PowerControl),
            12 => Some(Self::IoSpace),
            _ => None,
        }
    }
}

/// Flag bit in `a2` of `SyscallNumber::CapMint` / `CapGrant` indicating `a3` carries a new badge.
pub const CAP_MINT_SET_BADGE: u64 = 1 << 8;

/// Pure 64-bit syscall numbers (`x8` on `aarch64` `svc #0` instruction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum SyscallNumber {
    /// Write diagnostic UTF-8 slice `(console_cap, ptr, len)` to the early debug console (`Rights::WRITE`).
    DebugWrite = 1,
    /// Yield the current thread's remaining time slice to the scheduler.
    Yield = 2,
    /// Terminate the system via PSCI `SYSTEM_OFF`: `(power_cap, exit_code)` (`Rights::WRITE`).
    Exit = 3,
    /// Bitwise-OR a 64-bit badge word into a `Notification` capability (`cap_id, badge`).
    NotifySignal = 4,
    /// Atomically read and clear the 64-bit badge word of a `Notification` capability (`cap_id`).
    NotifyPoll = 5,
    /// Send a register-only fastpath IPC word to an `Endpoint` capability (`cap_id, payload`).
    IpcSend = 6,
    /// Receive a pending register-only fastpath IPC word from an `Endpoint` capability (`cap_id`).
    IpcRecv = 7,
    /// Read the CPU monotonic timestamp counter (cycles) for IPC/syscall benchmarking.
    ReadCycles = 8,
    /// Register Ring-3 supervisor fault-recovery entry `(rip, rsp)` for crash isolation.
    SetFaultHandler = 9,
    /// Capability-scoped 32-bit MMIO read `(mmio_cap_id, byte_offset)` for Ring-3 drivers.
    MmioRead32 = 10,
    /// Non-blocking 1-byte read from the early debug serial console: `(console_cap)` (`Rights::READ`).
    DebugRead = 11,
    /// Read packed system info `(power_cap)` (`Rights::READ`) -> `(interactive << 32) | (proc_count << 16) | online_cpus`.
    SysInfo = 12,
    /// Capability-scoped 32-bit MMIO write `(mmio_cap_id, byte_offset, value)` for Ring-3 drivers.
    MmioWrite32 = 13,
    /// Translate a canonical EL0 virtual address in the designated `VSpace` to its physical address: `(vspace_cap, vaddr)` (`Rights::READ`).
    VirtToPhys = 14,
    /// Synchronous fastpath IPC call: send `(cap_id, payload)` and receive the server's reply in 1 syscall.
    IpcCall = 15,
    /// Synchronous fastpath IPC server loop: optionally reply `(cap_id, reply_payload, has_reply)` and wait for next request.
    IpcReplyRecv = 16,
    /// Derive a capability in the caller's `CSpace`: `(src_cap, dst_slot_or_0, rights | flags, badge)` -> `new_cap_id`.
    CapMint = 17,
    /// Copy a capability verbatim in the caller's `CSpace`: `(src_cap, dst_slot_or_0)` -> `new_cap_id`.
    CapCopy = 18,
    /// Move a capability to another slot in the caller's `CSpace`: `(src_cap, dst_slot_or_0)` -> `new_cap_id`.
    CapMove = 19,
    /// Delete a single capability from the caller's `CSpace`: `(cap_id)`.
    CapDelete = 20,
    /// Transitively revoke all CDT descendants of `cap_id` in the caller's `CSpace` -> `revoked_count`.
    CapRevoke = 21,
    /// Grant an attenuated capability into the `CNode` designated by `dst_cnode_cap` (`Rights::WRITE`):
    /// `(dst_cnode_cap, src_cap, rights | flags, badge)` -> `dst_cap_id` (preserves cross-process CDT).
    CapGrant = 22,
    /// Set scheduling priority (`0..=255`, higher = higher priority) on `thread_cap` (`Rights::WRITE`):
    /// `(thread_cap, priority)`.
    SetPriority = 23,
    /// Map a fresh zeroed 4 KiB page into the designated `VSpace` with W^X `Rights`: `(vspace_cap, vaddr, rights)` (`Rights::WRITE`).
    MapPage = 24,
    /// Unmap a 4 KiB page from the designated `VSpace` and reclaim its physical frame: `(vspace_cap, vaddr)` (`Rights::WRITE`).
    UnmapPage = 25,
    /// Retype a kernel object (`Frame`, `Endpoint`, `Notification`) from a designated `Untyped` capability:
    /// `(untyped_cap, object_type, dst_slot_or_0)` -> `new_cap_id` (`Rights::WRITE`).
    UntypedRetype = 26,
    /// Map a designated `Frame` capability into a designated `VSpace` capability with W^X `Rights`:
    /// `(vspace_cap, frame_cap, vaddr, rights)`.
    FrameMap = 27,
}

impl SyscallNumber {
    #[inline]
    pub const fn from_u64(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::DebugWrite),
            2 => Some(Self::Yield),
            3 => Some(Self::Exit),
            4 => Some(Self::NotifySignal),
            5 => Some(Self::NotifyPoll),
            6 => Some(Self::IpcSend),
            7 => Some(Self::IpcRecv),
            8 => Some(Self::ReadCycles),
            9 => Some(Self::SetFaultHandler),
            10 => Some(Self::MmioRead32),
            11 => Some(Self::DebugRead),
            12 => Some(Self::SysInfo),
            13 => Some(Self::MmioWrite32),
            14 => Some(Self::VirtToPhys),
            15 => Some(Self::IpcCall),
            16 => Some(Self::IpcReplyRecv),
            17 => Some(Self::CapMint),
            18 => Some(Self::CapCopy),
            19 => Some(Self::CapMove),
            20 => Some(Self::CapDelete),
            21 => Some(Self::CapRevoke),
            22 => Some(Self::CapGrant),
            23 => Some(Self::SetPriority),
            24 => Some(Self::MapPage),
            25 => Some(Self::UnmapPage),
            26 => Some(Self::UntypedRetype),
            27 => Some(Self::FrameMap),
            _ => None,
        }
    }
}

/// Typed syscall error codes — invalid userspace inputs always return an error, never a kernel panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum SysError {
    InvalidCapability = 1,
    InsufficientRights = 2,
    OutOfMemory = 3,
    InvalidArgument = 4,
    SlotOccupied = 5,
    WouldBlock = 6,
    Unsupported = 7,
}

impl SysError {
    #[inline]
    pub const fn from_u64(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::InvalidCapability),
            2 => Some(Self::InsufficientRights),
            3 => Some(Self::OutOfMemory),
            4 => Some(Self::InvalidArgument),
            5 => Some(Self::SlotOccupied),
            6 => Some(Self::WouldBlock),
            7 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Exit codes reported on PSCI `SYSTEM_OFF` shutdown (Raspberry Pi 5 & QEMU `aarch64` `virt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_attenuation_never_escalates() {
        let base = Rights::READ.union(Rights::WRITE);
        let derived = base.attenuate(Rights::READ.union(Rights::GRANT));

        assert!(derived.contains(Rights::READ));
        assert!(!derived.contains(Rights::WRITE));
        assert!(!derived.contains(Rights::GRANT));
    }

    #[test]
    fn null_cap_is_recognized() {
        assert!(CapId::NULL.is_null());
        assert!(!CapId::new(1).is_null());
    }

    #[test]
    fn syscall_and_error_roundtrip() {
        let expected_syscalls = [
            (1, SyscallNumber::DebugWrite),
            (2, SyscallNumber::Yield),
            (3, SyscallNumber::Exit),
            (4, SyscallNumber::NotifySignal),
            (5, SyscallNumber::NotifyPoll),
            (6, SyscallNumber::IpcSend),
            (7, SyscallNumber::IpcRecv),
            (8, SyscallNumber::ReadCycles),
            (9, SyscallNumber::SetFaultHandler),
            (10, SyscallNumber::MmioRead32),
            (11, SyscallNumber::DebugRead),
            (12, SyscallNumber::SysInfo),
            (13, SyscallNumber::MmioWrite32),
            (14, SyscallNumber::VirtToPhys),
            (15, SyscallNumber::IpcCall),
            (16, SyscallNumber::IpcReplyRecv),
            (17, SyscallNumber::CapMint),
            (18, SyscallNumber::CapCopy),
            (19, SyscallNumber::CapMove),
            (20, SyscallNumber::CapDelete),
            (21, SyscallNumber::CapRevoke),
            (22, SyscallNumber::CapGrant),
            (23, SyscallNumber::SetPriority),
            (24, SyscallNumber::MapPage),
            (25, SyscallNumber::UnmapPage),
            (26, SyscallNumber::UntypedRetype),
            (27, SyscallNumber::FrameMap),
        ];
        assert_eq!(SyscallNumber::from_u64(0), None);
        for (raw, variant) in expected_syscalls {
            assert_eq!(variant as u64, raw);
            assert_eq!(SyscallNumber::from_u64(raw), Some(variant));
        }
        assert_eq!(SyscallNumber::from_u64(28), None);
        assert_eq!(SyscallNumber::from_u64(99), None);

        let expected_errors = [
            (1, SysError::InvalidCapability),
            (2, SysError::InsufficientRights),
            (3, SysError::OutOfMemory),
            (4, SysError::InvalidArgument),
            (5, SysError::SlotOccupied),
            (6, SysError::WouldBlock),
            (7, SysError::Unsupported),
        ];
        assert_eq!(SysError::from_u64(0), None);
        for (raw, err) in expected_errors {
            assert_eq!(err as u64, raw);
            assert_eq!(SysError::from_u64(raw), Some(err));
        }
        assert_eq!(SysError::from_u64(8), None);
    }
}
