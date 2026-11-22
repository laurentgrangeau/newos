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
}

/// Pure 64-bit syscall numbers (`rax` on `x86_64` `syscall` instruction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum SyscallNumber {
    /// Write diagnostic UTF-8 slice `(ptr, len)` to the early debug console.
    DebugWrite = 1,
    /// Yield the current thread's remaining time slice to the scheduler.
    Yield = 2,
    /// Terminate the root task with a `QemuExitCode` status.
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
    /// Non-blocking 1-byte read from the early debug serial console (returns `WouldBlock` if empty).
    DebugRead = 11,
    /// Read packed system info `(interactive << 32) | (proc_count << 16) | online_cpus`.
    SysInfo = 12,
    /// Capability-scoped 32-bit MMIO write `(mmio_cap_id, byte_offset, value)` for Ring-3 drivers.
    MmioWrite32 = 13,
    /// Translate a canonical Ring-3 virtual address in the caller's `VSpace` to its physical address for DMA.
    VirtToPhys = 14,
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

/// Exit codes written to QEMU's `isa-debug-exit` port (`0xF4`).
///
/// QEMU exits with `(code << 1) | 1`, so `Success` produces process exit status `33`.
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
        assert_eq!(SyscallNumber::from_u64(1), Some(SyscallNumber::DebugWrite));
        assert_eq!(SyscallNumber::from_u64(4), Some(SyscallNumber::NotifySignal));
        assert_eq!(SyscallNumber::from_u64(8), Some(SyscallNumber::ReadCycles));
        assert_eq!(SyscallNumber::from_u64(99), None);
        assert_eq!(
            SysError::from_u64(SysError::WouldBlock as u64),
            Some(SysError::WouldBlock)
        );
    }
}
