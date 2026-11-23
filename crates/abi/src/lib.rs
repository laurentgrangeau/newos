#![no_std]

//! Shared ABI contract between the microkernel (EL1) and EL0 userspace.

pub mod ring;
#[cfg(feature = "sha3")]
pub use newos_crypto::sha3;

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

    /// Well-known bootstrap Fault `Notification` capability (slot 3, gen 1) signaled on EL0 faults.
    pub const BOOTSTRAP_FAULT_NOTIF: Self = Self((1u64 << 32) | 3);

    /// Well-known bootstrap NIC MMIO capability (slot 4, gen 1) for EL0 NIC drivers.
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

    /// Well-known bootstrap Console Log `Endpoint` capability (slot 11, gen 1).
    ///
    /// PID 0 (`init`, console owner) holds `Rights::ALL`; non-root processes (`pid >= 1`)
    /// hold write-only (`Rights::WRITE`) with an immutable kernel-stamped `badge = pid as u64`.
    pub const BOOTSTRAP_LOG_EP: Self = Self((1u64 << 32) | 11);

    /// Well-known bootstrap Hardware RNG MMIO capability (slot 12, gen 1), exclusively owned
    /// by `newos-keyd` (BCM2712 RNG200 on Raspberry Pi 5 or VirtIO-RNG slot on QEMU).
    pub const BOOTSTRAP_RNG_MMIO: Self = Self((1u64 << 32) | 12);

    /// Well-known bootstrap Network Data-Plane `Endpoint` capability (slot 13, gen 1)
    /// connecting `newos-netd` (server) to `newos-sshd` (badge 4) and `newos-init` (badge 0x1000).
    pub const BOOTSTRAP_NET_EP: Self = Self((1u64 << 32) | 13);

    /// Well-known bootstrap Cryptographic Vault `Endpoint` capability (slot 14, gen 1)
    /// connecting `newos-keyd` (server) exclusively to `newos-sshd` (badge 4).
    pub const BOOTSTRAP_KEY_EP: Self = Self((1u64 << 32) | 14);

    /// Well-known bootstrap SSH Shell input `Endpoint` capability (slot 15, gen 1):
    /// unidirectional `newos-sshd` (`Rights::WRITE`, badge 4) -> `newos-init` (`Rights::READ`),
    /// gated by `BOOTSTRAP_AUTH_GATE_EP`.
    pub const BOOTSTRAP_SSH_SHELL_EP: Self = Self((1u64 << 32) | 15);

    /// Well-known bootstrap Cryptographic Auth-Gate `Endpoint` capability (slot 16, gen 1).
    /// `newos-keyd` holds write-only (`Rights::WRITE`, badge 3); `newos-init` holds read-only
    /// (`Rights::READ`). `newos-sshd` explicitly does NOT hold this capability.
    pub const BOOTSTRAP_AUTH_GATE_EP: Self = Self((1u64 << 32) | 16);

    /// Well-known bootstrap SSH Shell output `Endpoint` capability (slot 17, gen 1):
    /// unidirectional `newos-init` (`Rights::WRITE`) -> `newos-sshd` (`Rights::READ`, badge 4).
    pub const BOOTSTRAP_SSH_OUT_EP: Self = Self((1u64 << 32) | 17);

    /// Well-known bootstrap Hardware Watchdog MMIO capability (slot 18, gen 1),
    /// exposing the Raspberry Pi 5 BCM2712 PM/Watchdog block (`0x10_7D20_0000`, `0x100` bytes).
    pub const BOOTSTRAP_WDT_MMIO: Self = Self((1u64 << 32) | 18);

    /// Well-known bootstrap RP1 40-pin GPIO MMIO capability (slot 19, gen 1),
    /// covering `IO_BANK0` (`0x1F_000D_0000`), `RIO0` (`0x1F_000E_0000`), and `PADS_BANK0` (`0x1F_000F_0000`).
    pub const BOOTSTRAP_GPIO_MMIO: Self = Self((1u64 << 32) | 19);

    /// Well-known bootstrap BCM2712 VideoCore Property Mailbox MMIO capability (slot 20, gen 1),
    /// covering `0x10_7C01_3000` (Mailbox at offset `0x880`).
    pub const BOOTSTRAP_MBOX_MMIO: Self = Self((1u64 << 32) | 20);

    /// Well-known bootstrap BCM2712 AVS TMON Thermal Sensor MMIO capability (slot 21, gen 1),
    /// covering `0x10_7D5D_2000` (TMON registers at offset `0x200`).
    pub const BOOTSTRAP_THERMAL_MMIO: Self = Self((1u64 << 32) | 21);

    /// Well-known bootstrap RP1 40-pin Bus Peripherals MMIO capability (slot 22, gen 1),
    /// covering RP1 `UART0` (`0x1F_0003_0000`), `SPI0` (`0x1F_0005_0000`), `I2C0`/`I2C1` (`0x1F_0007_0000`),
    /// and `PWM0` (`0x1F_0009_8000`).
    pub const BOOTSTRAP_RP1_PERIPH_MMIO: Self = Self((1u64 << 32) | 22);

    /// Well-known bootstrap BCM2712 microSD SDHCI MMIO capability (slot 23, gen 1, `0x10_00FF_F000`).
    pub const BOOTSTRAP_SDHCI_MMIO: Self = Self((1u64 << 32) | 23);

    /// Well-known bootstrap RP1 USB 3.0/2.0 xHCI0 MMIO capability (slot 24, gen 1, `0x1F_0020_0000`).
    pub const BOOTSTRAP_XHCI0_MMIO: Self = Self((1u64 << 32) | 24);

    /// Well-known bootstrap RP1 USB 3.0/2.0 xHCI1 MMIO capability (slot 25, gen 1, `0x1F_0030_0000`).
    pub const BOOTSTRAP_XHCI1_MMIO: Self = Self((1u64 << 32) | 25);

    /// Well-known bootstrap PCIe ECAM configuration space MMIO capability (slot 26, gen 1).
    pub const BOOTSTRAP_PCIE_ECAM_MMIO: Self = Self((1u64 << 32) | 26);

    /// Well-known bootstrap UEFI GOP / Limine Framebuffer MMIO capability (slot 27, gen 1).
    pub const BOOTSTRAP_FB_MMIO: Self = Self((1u64 << 32) | 27);

    /// Well-known bootstrap VideoCore VII V3D 7.1 GPU MMIO capability (slot 28, gen 1, `0x10_0200_0000`).
    pub const BOOTSTRAP_V3D_MMIO: Self = Self((1u64 << 32) | 28);

    /// Well-known bootstrap BCM2712 IOMMU (`brcm,bcm2712-iommu`) MMIO capability (slot 29, gen 1, `0x10_0000_5000`).
    pub const BOOTSTRAP_IOMMU_MMIO: Self = Self((1u64 << 32) | 29);

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

    /// Construct a `Rights` bitmask from raw bits, returning `None` if any unknown bit is set.
    #[inline]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if (bits & !Self::ALL.0) == 0 {
            Some(Self(bits))
        } else {
            None
        }
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

/// Kernel object types created by retyping `Untyped` memory.
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
    /// Register EL0 supervisor fault-recovery entry `(pc, sp)` for crash isolation.
    SetFaultHandler = 9,
    /// Capability-scoped 32-bit MMIO read `(mmio_cap_id, byte_offset)` for EL0 drivers.
    MmioRead32 = 10,
    /// Non-blocking 1-byte read from the early debug serial console: `(console_cap)` (`Rights::READ`).
    DebugRead = 11,
    /// Read packed system info `(power_cap)` (`Rights::READ`) -> `(interactive << 32) | (proc_count << 16) | online_cpus`.
    SysInfo = 12,
    /// Capability-scoped 32-bit MMIO write `(mmio_cap_id, byte_offset, value)` for EL0 drivers.
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
    /// Read the architectural Generic Timer frequency (`CNTFRQ_EL0`) in Hz.
    TimerFreq = 28,
    /// Terminate the calling EL0 thread cleanly without requiring a `PowerControl` capability.
    ThreadExit = 29,
    /// Acknowledge and unmask a hardware IRQ via a designated `IrqHandler` capability (`irq_cap`).
    IrqAck = 30,
    /// Perform PAN-safe DMA cache maintenance on a caller-mapped EL0 range:
    /// `(vspace_cap, vaddr, len, op)` where `op` is a [`DmaCacheOp`] discriminant.
    DmaCacheOp = 31,
    /// Read probed ARMv8.2-A Cortex-A76 ISA feature bitmask & cache/PA geometry: `(power_cap)` (`Rights::READ`).
    CpuFeatures = 32,
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
            28 => Some(Self::TimerFreq),
            29 => Some(Self::ThreadExit),
            30 => Some(Self::IrqAck),
            31 => Some(Self::DmaCacheOp),
            32 => Some(Self::CpuFeatures),
            _ => None,
        }
    }
}

/// Cache maintenance operation for [`SyscallNumber::DmaCacheOp`] (non-coherent DMA on Pi 5 RP1/PCIe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum DmaCacheOp {
    /// Clean data cache lines to Point of Coherency (`dc cvac`) before outbound DMA.
    Clean = 0,
    /// Clean & invalidate data cache lines to Point of Coherency (`dc civac`) before/after inbound DMA.
    Invalidate = 1,
    /// Clean & invalidate data cache lines (`dc civac`) for bidirectional DMA buffers.
    CleanInvalidate = 2,
}

impl DmaCacheOp {
    #[inline]
    pub const fn from_u64(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Clean),
            1 => Some(Self::Invalidate),
            2 => Some(Self::CleanInvalidate),
            _ => None,
        }
    }
}

/// Bitfield layout returned by [`SyscallNumber::CpuFeatures`] (ARMv8.2-A Cortex-A76 / BCM2712).
pub mod cpu_isa {
    /// ARMv8.1-A Large System Extensions (atomic CAS/LDADD/SWP).
    pub const LSE: u64 = 1 << 0;
    /// ARMv8.0-A CRC32 instructions.
    pub const CRC32: u64 = 1 << 1;
    /// ARMv8.0-A AES cryptographic instructions (`FEAT_AES`).
    pub const AES: u64 = 1 << 2;
    /// ARMv8.0-A Polynomial Multiply Long (`FEAT_PMULL`).
    pub const PMULL: u64 = 1 << 3;
    /// ARMv8.0-A SHA-1 cryptographic instructions (`FEAT_SHA1`).
    pub const SHA1: u64 = 1 << 4;
    /// ARMv8.0-A SHA-256 cryptographic instructions (`FEAT_SHA256`).
    pub const SHA256: u64 = 1 << 5;
    /// ARMv8.2-A Dot Product SIMD instructions (`FEAT_DotProd`).
    pub const DOTPROD: u64 = 1 << 6;
    /// ARMv8.2-A Half-Precision Floating Point (`FEAT_FP16`).
    pub const FP16: u64 = 1 << 7;
    /// ARMv8.0-A Advanced SIMD / NEON (`AdvSIMD`).
    pub const ASIMD: u64 = 1 << 8;
    /// ARMv8.2-A Performance Monitors Extension (`PMUv3` / `PMCCNTR_EL0`).
    pub const PMUV3: u64 = 1 << 9;

    /// Pack ISA feature flags together with probed physical address width (`pa_bits`)
    /// and D-cache minimum line size (`dcache_line_bytes`) into one 64-bit syscall return word.
    #[inline]
    pub const fn pack(flags: u64, pa_bits: u8, dcache_line_bytes: u16) -> u64 {
        (flags & 0xFFFF_FFFF)
            | ((pa_bits as u64) << 32)
            | (((dcache_line_bytes as u64) & 0xFFFF) << 40)
    }

    #[inline]
    pub const fn pa_bits(packed: u64) -> u8 {
        ((packed >> 32) & 0xFF) as u8
    }

    #[inline]
    pub const fn dcache_line_bytes(packed: u64) -> u16 {
        ((packed >> 40) & 0xFFFF) as u16
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

/// Shutdown/reset status reported on PSCI `SYSTEM_OFF` / `SYSTEM_RESET` (Raspberry Pi 5 & QEMU `aarch64` `virt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShutdownStatus {
    Success = 0,
    Failed = 1,
    Reboot = 2,
}

/// Register-only IPC log chunk framing for `CapId::BOOTSTRAP_LOG_EP`.
///
/// Packs up to 7 UTF-8 bytes into a single 64-bit `Endpoint` payload register:
/// - bits `56..64`: chunk byte length (`0..=7`)
/// - bits `0..56`: little-endian payload bytes `0..len`
pub mod log_ipc {
    /// Maximum UTF-8 bytes carried in a single 64-bit fastpath IPC log message.
    pub const MAX_CHUNK_BYTES: usize = 7;

    /// Pack up to [`MAX_CHUNK_BYTES`] bytes into a single 64-bit IPC register payload.
    #[inline]
    pub const fn encode_chunk(bytes: &[u8]) -> u64 {
        let len = if bytes.len() > MAX_CHUNK_BYTES {
            MAX_CHUNK_BYTES
        } else {
            bytes.len()
        };
        let mut word = (len as u64) << 56;
        let mut i = 0;
        while i < len {
            word |= (bytes[i] as u64) << (i * 8);
            i += 1;
        }
        word
    }

    /// Unpack a 64-bit IPC log payload into `([u8; 7], len)`.
    #[inline]
    pub const fn decode_chunk(word: u64) -> ([u8; MAX_CHUNK_BYTES], usize) {
        let raw_len = (word >> 56) as usize;
        let len = if raw_len > MAX_CHUNK_BYTES {
            MAX_CHUNK_BYTES
        } else {
            raw_len
        };
        let mut buf = [0u8; MAX_CHUNK_BYTES];
        let mut i = 0;
        while i < len {
            buf[i] = ((word >> (i * 8)) & 0xFF) as u8;
            i += 1;
        }
        (buf, len)
    }
}

/// Register-only IPC wire protocol for `CapId::BOOTSTRAP_NET_EP` (`newos-netd` <-> `newos-sshd`/`init`).
///
/// Each 64-bit request word carries an opcode in bits `56..64` and up to 7 payload bytes in bits `0..56`:
/// - `OP_POLL_STATUS (0x01)`: query connection/readiness bits + active IPv4 address
/// - `OP_RECV_CHUNK  (0x02)`: pull up to 7 TCP RX bytes (reply: `0..=7` len in bits `56..64`, or `REPLY_EOF`)
/// - `OP_SEND_BASE..=OP_SEND_BASE+7 (0x10..=0x17)`: push `len` (`0..=7`) TCP TX bytes; reply = bytes accepted
/// - `OP_CLOSE       (0x0E)`: graceful TCP FIN close
/// - `OP_ABORT       (0x0F)`: immediate TCP RST abort (e.g., strict-KEX violation)
pub mod net_ipc {
    pub const MAX_CHUNK_BYTES: usize = 7;

    pub const OP_POLL_STATUS: u8 = 0x01;
    pub const OP_RECV_CHUNK: u8 = 0x02;
    pub const OP_CLOSE: u8 = 0x0E;
    pub const OP_ABORT: u8 = 0x0F;
    pub const OP_SEND_BASE: u8 = 0x10;

    /// Reply sentinel in bits `56..64` for `OP_RECV_CHUNK` when no active TCP connection exists.
    pub const REPLY_EOF: u8 = 0xFF;

    /// Status bitmask flags returned in the low 32 bits of `OP_POLL_STATUS`.
    pub const STATUS_CONNECTED: u64 = 1 << 0;
    pub const STATUS_RX_AVAIL: u64 = 1 << 1;
    pub const STATUS_TX_READY: u64 = 1 << 2;

    /// Kernel-stamped IPC badge for `newos-init` querying `newos-netd` status.
    pub const BADGE_INIT: u64 = 0x1000;
    /// Kernel-stamped IPC badge for `newos-sshd` (PID 4) owning the TCP :22 stream.
    pub const BADGE_SSHD: u64 = 4;

    #[inline]
    pub const fn encode_poll_status() -> u64 {
        (OP_POLL_STATUS as u64) << 56
    }

    #[inline]
    pub const fn encode_recv_chunk() -> u64 {
        (OP_RECV_CHUNK as u64) << 56
    }

    #[inline]
    pub const fn encode_close() -> u64 {
        (OP_CLOSE as u64) << 56
    }

    #[inline]
    pub const fn encode_abort() -> u64 {
        (OP_ABORT as u64) << 56
    }

    #[inline]
    pub const fn encode_send_chunk(bytes: &[u8]) -> u64 {
        let len = if bytes.len() > MAX_CHUNK_BYTES {
            MAX_CHUNK_BYTES
        } else {
            bytes.len()
        };
        let mut word = ((OP_SEND_BASE + len as u8) as u64) << 56;
        let mut i = 0;
        while i < len {
            word |= (bytes[i] as u64) << (i * 8);
            i += 1;
        }
        word
    }

    #[inline]
    pub const fn encode_status_reply(flags: u64, ipv4: [u8; 4]) -> u64 {
        let ip_u32 = u32::from_be_bytes(ipv4) as u64;
        (ip_u32 << 32) | (flags & 0xFFFF_FFFF)
    }

    #[inline]
    pub const fn decode_status_reply(word: u64) -> (u64, [u8; 4]) {
        let flags = word & 0xFFFF_FFFF;
        let ip = ((word >> 32) as u32).to_be_bytes();
        (flags, ip)
    }

    #[inline]
    pub const fn encode_recv_reply(bytes: &[u8]) -> u64 {
        crate::log_ipc::encode_chunk(bytes)
    }

    #[inline]
    pub const fn encode_recv_eof() -> u64 {
        (REPLY_EOF as u64) << 56
    }

    /// Decode a `net_ipc` request word into `(opcode, [u8; 7], payload_len)`.
    #[inline]
    pub const fn decode_request(word: u64) -> (u8, [u8; MAX_CHUNK_BYTES], usize) {
        let op = (word >> 56) as u8;
        if op >= OP_SEND_BASE && op <= OP_SEND_BASE + (MAX_CHUNK_BYTES as u8) {
            let len = (op - OP_SEND_BASE) as usize;
            let mut buf = [0u8; MAX_CHUNK_BYTES];
            let mut i = 0;
            while i < len {
                buf[i] = ((word >> (i * 8)) & 0xFF) as u8;
                i += 1;
            }
            (OP_SEND_BASE, buf, len)
        } else {
            (op, [0u8; MAX_CHUNK_BYTES], 0)
        }
    }
}

/// Cryptographic shell auth-gate signals sent over `CapId::BOOTSTRAP_AUTH_GATE_EP`
/// (`newos-keyd` PID 3 write-only -> `newos-init` PID 0 read-only).
pub mod auth_gate_ipc {
    /// Kernel-stamped IPC badge of `newos-keyd` (PID 3).
    pub const BADGE_KEYD: u64 = 3;
    /// Signal `newos-init` to open `BOOTSTRAP_SSH_SHELL_EP` after valid ML-DSA-87 userauth.
    pub const SESSION_OPEN: u64 = 0x5345_5353_4F50_454E;
    /// Signal `newos-init` to close `BOOTSTRAP_SSH_SHELL_EP` on disconnect.
    pub const SESSION_CLOSE: u64 = 0x5345_5353_434C_4F53;
}

/// Narrow, register-only IPC RPC protocol for `CapId::BOOTSTRAP_KEY_EP`
/// (`newos-sshd` PID 4 -> `newos-keyd` PID 3).
///
/// The ML-DSA-87 host private key never leaves `newos-keyd`.
pub mod key_ipc {
    /// ML-DSA-87 (NIST FIPS 204) public key size in bytes.
    pub const MLDSA87_PK_BYTES: usize = 2592;
    /// ML-DSA-87 (NIST FIPS 204) signature size in bytes.
    pub const MLDSA87_SIG_BYTES: usize = 4627;
    /// Maximum random bytes `newos-sshd` may request per KEX window (`<= 256 B` cap with margin).
    pub const MAX_RANDOM_BYTES_PER_WINDOW: usize = 256;
    /// Maximum chunk payload bytes carried in a single 64-bit IPC register word.
    pub const MAX_CHUNK_BYTES: usize = 7;

    /// Kernel-stamped IPC badge of `newos-sshd` (PID 4).
    pub const BADGE_SSHD: u64 = 4;

    /// Opcode tags in bits `56..64` of the 64-bit IPC request word.
    pub const OP_GET_HOST_PK_WORD: u8 = 0x01;
    pub const OP_GET_RANDOM_U64: u8 = 0x02;
    pub const OP_SIGN_KEX_RESET: u8 = 0x03;
    pub const OP_SIGN_KEX_PUSH_BASE: u8 = 0x10; // 0x10..=0x17 carries 0..=7 bytes
    pub const OP_SIGN_KEX_COMMIT: u8 = 0x04;
    pub const OP_SIGN_KEX_READ_WORD: u8 = 0x05;
    pub const OP_VERIFY_RESET: u8 = 0x06;
    pub const OP_VERIFY_PUSH_PK_BASE: u8 = 0x20; // 0x20..=0x27 carries 0..=7 bytes
    pub const OP_VERIFY_PUSH_MSG_BASE: u8 = 0x30; // 0x30..=0x37 carries 0..=7 bytes
    pub const OP_VERIFY_PUSH_SIG_BASE: u8 = 0x40; // 0x40..=0x47 carries 0..=7 bytes
    pub const OP_VERIFY_COMMIT: u8 = 0x07;
    pub const OP_CLOSE_SESSION: u8 = 0x08;

    /// Reply status codes.
    pub const REPLY_DENIED: u64 = 0;
    pub const REPLY_OK: u64 = 1;
    pub const REPLY_RATE_LIMITED: u64 = 2;

    /// Encode 4 bytes of CSPRNG output with a non-zero `REPLY_OK` tag in bits `32..64` so a
    /// `REPLY_DENIED` (0) or `REPLY_RATE_LIMITED` (2) error can NEVER be mistaken for random bytes (`N1`).
    #[inline]
    pub const fn encode_random_u32_reply(val: u32) -> u64 {
        (REPLY_OK << 32) | (val as u64)
    }

    /// Decode a tagged 4-byte CSPRNG reply, returning `None` on any error status (`N1`).
    #[inline]
    pub const fn decode_random_u32_reply(word: u64) -> Option<u32> {
        if (word >> 32) == REPLY_OK {
            Some(word as u32)
        } else {
            None
        }
    }

    #[inline]
    pub const fn encode_word_req(op: u8, word_index: u32) -> u64 {
        ((op as u64) << 56) | (word_index as u64)
    }

    #[inline]
    pub const fn encode_chunk_req(base_op: u8, bytes: &[u8]) -> u64 {
        let len = if bytes.len() > MAX_CHUNK_BYTES {
            MAX_CHUNK_BYTES
        } else {
            bytes.len()
        };
        let mut word = ((base_op + len as u8) as u64) << 56;
        let mut i = 0;
        while i < len {
            word |= (bytes[i] as u64) << (i * 8);
            i += 1;
        }
        word
    }

    #[inline]
    pub const fn decode_chunk_req(
        word: u64,
        base_op: u8,
    ) -> Option<([u8; MAX_CHUNK_BYTES], usize)> {
        let op = (word >> 56) as u8;
        if op < base_op || op > base_op + (MAX_CHUNK_BYTES as u8) {
            return None;
        }
        let len = (op - base_op) as usize;
        let mut buf = [0u8; MAX_CHUNK_BYTES];
        let mut i = 0;
        while i < len {
            buf[i] = ((word >> (i * 8)) & 0xFF) as u8;
            i += 1;
        }
        Some((buf, len))
    }
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
            (28, SyscallNumber::TimerFreq),
            (29, SyscallNumber::ThreadExit),
            (30, SyscallNumber::IrqAck),
            (31, SyscallNumber::DmaCacheOp),
            (32, SyscallNumber::CpuFeatures),
        ];
        assert_eq!(SyscallNumber::from_u64(0), None);
        for (raw, variant) in expected_syscalls {
            assert_eq!(variant as u64, raw);
            assert_eq!(SyscallNumber::from_u64(raw), Some(variant));
        }
        assert_eq!(SyscallNumber::from_u64(33), None);
        assert_eq!(SyscallNumber::from_u64(99), None);

        assert_eq!(DmaCacheOp::from_u64(0), Some(DmaCacheOp::Clean));
        assert_eq!(DmaCacheOp::from_u64(1), Some(DmaCacheOp::Invalidate));
        assert_eq!(DmaCacheOp::from_u64(2), Some(DmaCacheOp::CleanInvalidate));
        assert_eq!(DmaCacheOp::from_u64(3), None);

        let packed = cpu_isa::pack(cpu_isa::LSE | cpu_isa::AES | cpu_isa::PMUV3, 40, 64);
        assert_eq!(cpu_isa::pa_bits(packed), 40);
        assert_eq!(cpu_isa::dcache_line_bytes(packed), 64);
        assert_ne!(packed & cpu_isa::LSE, 0);
        assert_ne!(packed & cpu_isa::PMUV3, 0);

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

    #[test]
    fn log_ipc_chunk_roundtrip_and_bounds() {
        let (buf, len) = log_ipc::decode_chunk(log_ipc::encode_chunk(b""));
        assert_eq!(len, 0);
        assert_eq!(&buf[..len], b"");

        let (buf, len) = log_ipc::decode_chunk(log_ipc::encode_chunk(b"hi\n"));
        assert_eq!(len, 3);
        assert_eq!(&buf[..len], b"hi\n");

        let (buf, len) = log_ipc::decode_chunk(log_ipc::encode_chunk(b"1234567"));
        assert_eq!(len, 7);
        assert_eq!(&buf[..len], b"1234567");

        // Oversized slices clamp cleanly to 7 bytes; corrupted lengths clamp to 7.
        let (buf, len) = log_ipc::decode_chunk(log_ipc::encode_chunk(b"123456789"));
        assert_eq!(len, 7);
        assert_eq!(&buf[..len], b"1234567");

        let (_, clamped) = log_ipc::decode_chunk(0xFFu64 << 56);
        assert_eq!(clamped, 7);
    }

    #[test]
    fn rights_from_bits_rejects_unknown_bits_and_accepts_valid_mask() {
        for raw in 0..=Rights::ALL.bits() {
            assert_eq!(
                Rights::from_bits(raw),
                Some(Rights::from_bits_truncate(raw))
            );
        }
        for raw in (Rights::ALL.bits() + 1)..=u8::MAX {
            assert_eq!(Rights::from_bits(raw), None);
        }
        assert_eq!(Rights::from_bits(0), Some(Rights::NONE));
        assert_eq!(Rights::from_bits(0xFF), None);
        assert_eq!(Rights::from_bits(1 << 5), None);
        assert_eq!(Rights::from_bits_truncate(0xFF), Rights::ALL);
    }

    #[test]
    fn object_type_cap_id_and_extreme_boundary_values() {
        for raw in 0..=12u64 {
            let obj = ObjectType::from_u64(raw);
            assert!(obj.is_some());
            assert_eq!(obj.unwrap() as u64, raw);
        }
        assert_eq!(ObjectType::from_u64(13), None);
        assert_eq!(ObjectType::from_u64(u64::MAX), None);

        assert_eq!(SyscallNumber::from_u64(u64::MAX), None);
        assert_eq!(SysError::from_u64(u64::MAX), None);

        assert!(CapId::new(0).is_null());
        assert_eq!(CapId::new(u64::MAX).raw(), u64::MAX);
        assert!(!CapId::new(u64::MAX).is_null());
    }
}
