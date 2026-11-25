---
trigger: always_on
description: Enforce seL4-inspired microkernel architecture, research-backed design, and continuous verification of memory safety, security, modernity, and speed.
---

# seL4-Inspired Microkernel Architecture & Engineering Bar

NewOS is a **modern, capability-based microkernel OS inspired by seL4 and microkernel research — NOT Linux or monolithic POSIX kernels**.

Every architectural decision, API, and line of code MUST be evaluated against these principles:

## 1. seL4 & Research-Grounded Microkernel Design (Not Linux)
- **Minimal EL1 TCB**: Never pull drivers, filesystems, networking, crypto, or policy into EL1. Keep them in least-privilege, isolated EL0 protection domains (`TTBR0_EL1` + capability-scoped MMIO/IPC).
- **Capability-based authority**: Enforce explicit, unforgeable capabilities (`CSpace` + Capability Derivation Tree), strict rights attenuation, and zero ambient authority. Prefer `Untyped` memory delegation over in-kernel dynamic heap allocation.
- **Draw from microkernel research**: Take inspiration from peer-reviewed systems and microkernel literature — including **seL4** (capability/untyped memory model, MCS scheduling, formal-verification-friendly simplicity), **L4** (register-only fastpath IPC, minimal syscalls), **RedLeaf / Theseus / Hubris** (Rust language-level isolation and zero-allocation resilience), and modern capability/object-store designs — rather than legacy monolithic Linux/POSIX patterns.

## 2. Continuous Verification: Safest, Fastest, Most Modern, Memory-Safe
At every design and implementation step, explicitly verify:
- **Safest & Memory-Safe**:
  - Preserve `#![forbid(unsafe_code)]` across all safe crates (`kernel-core`, `abi`, `shell-core`, `net`, `ssh`, `crypto`, drivers, PDs).
  - Confine `unsafe` strictly to audited hardware/ABI boundaries (`hal`, `user-rt`) with minimal scope and rigorous `// SAFETY:` invariants.
  - Zero production `.unwrap()`, `.expect()`, or unchecked panics in OS crates; zero EL1 heap allocation; uphold hardware mitigations (W^X, PXN, UXN, PAN, SSBS, CSV2/CSV3, Shadow Call Stack, ASLR, IOMMU/DMA pinning).
- **Fastest**:
  - Keep kernel hot paths O(1), bounded-WCET, and allocation-free.
  - Prefer register-only IPC fastpaths (`IpcCall`/`IpcReplyRecv`), lock-free shared-memory `SpscRing` data planes, batched I/O, and zero-copy transfers.
  - Avoid unnecessary syscalls, locks, or formatting overhead on hot paths.
- **Most Modern**:
  - Use idiomatic modern Rust (`#![no_std]`, const assertions, typestate/strong types, zero-cost abstractions) and modern AArch64 hardware features rather than legacy workarounds.
  - Before finishing any change, ask: *"Is this the safest, fastest, cleanest, most modern seL4-style microkernel implementation possible?"* — and refine if not.

## 3. Modern Microkernel Naming Conventions (No Unix/POSIX/Daemon Legacy)
NewOS aims to be **modern, expressive, and innovative** — do NOT default to 1970s Unix/POSIX/Linux terminology when naming crates, types, syscalls, CLI commands, log tags, or concepts:
- **Avoid legacy Unix/POSIX names**: `daemon` or `*d` suffixes (`sshd`, `netd`, `initd`), `pid`, `proc`, `fork`/`exec`, `fd`, `ioctl`, `errno`, `printk`/`dmesg`, `root`/`sudo`, `chroot`, `/dev`, `/proc`, `/etc`.
- **Use capability-microkernel names**:
  - **Isolation units**: Protection Domains (`*-pd`, e.g. `supervisor-pd`, `net-pd`, `key-pd`, `ssh-pd`, `shell-pd`), `DomainId` / `pd_id`, `DomainRole`, `Thread` (not `daemon`, `process`, `pid`).
  - **Authority & Memory**: `CapId`, `CNode`, `CSpace`, `CDT`, `Rights`, `Untyped`, `VSpace`, `Frame`, `IoSpace`, `MmioRegion` (not `fd`, `uid`/`gid`, `root`).
  - **Communication**: `Endpoint`, `Notification`, `SpscRing`, `IpcCall`/`IpcReplyRecv`, `IrqHandler` (not `pipe`, `signal`, `ioctl`).
  - **Storage & Shell**: Content-Addressed Object Store (`CAOS`), `Object`, `Ref`, typed `Record` pipelines, clear modern names (not cryptic POSIX abbreviations).
- **Prefer clarity & innovation**: Choose self-documenting, domain-accurate Rust names that make the capability and isolation model obvious at a glance.
