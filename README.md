# NewOS

A pure **seL4-style 64-bit capability microkernel** and **post-UNIX Ring-3 environment** written in modern Rust — built with **zero kernel heap (`no_alloc` in Ring 0)**, **100% memory-safe Rust APIs (`#![forbid(unsafe_code)]` across core & userspace)**, **pure 64-bit UEFI + Limine + x2APIC** (zero 32-bit or legacy BIOS/xAPIC support), **SMP multi-core bring-up**, **isolated Ring-3 `CR3` address spaces**, **Ring-3 crash isolation**, a **Content-Addressed Object Store (CAOS)**, and a **Typed Pipeline Shell (`newos-sh`)**.

## Architecture Principles

- **Strict Liedtke Minimality (Ultra-Minimal Ring 0):**
  - Only CPU/interrupt dispatch, 4-level `VSpace` page tables, `CSpace` capability & `Untyped` memory enforcement, thread scheduling, and minimal IPC (`Endpoint`, 64-bit `Notification`) live in Ring 0.
  - Zero kernel heap (`no_alloc`): all physical memory is tracked in `UntypedInventory` and explicitly retyped into frames/page tables.
  - Storage, shell, shared-memory ring buffers, and crash supervision live in isolated Ring-3 processes.
- **100% Memory-Safe Rust Interfaces:**
  - `#![forbid(unsafe_code)]` is compiler-enforced on `newos-abi`, `newos-kernel-core`, `newos-kernel`, `newos-init`, and `newos-worker`.
  - Audited `unsafe` is strictly confined to hardware/MSR/paging/context-switch instructions in `crates/hal` and the minimal `syscall` trampoline in `crates/user-rt`.
- **Post-UNIX Userspace (Zero POSIX Paths / Zero Untyped Text Pipes):**
  - **Content-Addressed Object Store (CAOS):** Immutable blobs addressed by 64-bit `ObjHash` with automatic deduplication, lock-free reads, capability-gated named Refs (`@name`), instant atomic `rollback`, and irreversible `seal` (read-only attenuation).
  - **Typed Pipeline Shell (`newos-sh`):** Stages pass typed `Record` values (`Proc`, `Object`, `Ref`, `Metric`, `Count`) directly through `|` (`put "hello" | save @note`, `objects | where size > 20`, `procs | where pid == 1 | count`).
- **Modern 64-bit Hardware Only:**
  - Pure 64-bit UEFI ISO (OVMF + Limine protocol), x2APIC MSRs, 64-bit `syscall`/`sysretq`, and hardware security hardening (`WP`, `NXE`, `SMEP`, `SMAP`, `UMIP`, W^X page tables).

## Workspace Layout

```text
newos/
├── rust-toolchain.toml          # Nightly toolchain + rust-src, llvm-tools-preview, x86_64-unknown-none
├── Cargo.toml                   # Workspace manifest
├── xtask/                       # Build automation: pure UEFI Limine ISO builder & QEMU/KVM runner/tests
├── crates/
│   ├── abi/                     # #![no_std], #![forbid(unsafe_code)] — Syscalls, CapId, Rights, SpscRing
│   ├── hal/                     # #![no_std], no_alloc — Minimal audited unsafe TCB (x86_64, SMP, paging, syscall)
│   ├── kernel-core/             # #![no_std], no_alloc, #![forbid(unsafe_code)] — Untyped, CSpace/CDT, ELF64, IPC, Sched
│   ├── kernel/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Thin Ring-0 kernel binary
│   ├── user-rt/                 # #![no_std] — Safe Ring-3 Rust SDK (syscall wrappers & fault handler registration)
│   ├── init/                    # #![no_std], #![no_main], #![forbid(unsafe_code)] — Ring-3 root task, CAOS & `newos-sh`
│   └── worker/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Isolated Ring-3 worker process
└── infra/
    └── startup.sh               # GCP Debian 13 + QEMU/KVM + Rust nightly dev VM provisioning script
```

## Build, Test & Run

### Host Unit Tests (`newos-abi` & `newos-kernel-core`)
```bash
cargo xtask host-test
cargo clippy --package newos-abi --package newos-kernel-core --package xtask -- -D warnings
```

### Automated UEFI + Limine + QEMU/KVM Test Suite
Requires `qemu-system-x86_64`, `ovmf`, `xorriso`, `git`, and Rust nightly (`x86_64-unknown-none` + `rust-src` — pre-installed on `newos-dev`):

```bash
cargo xtask test
```

### Interactive Ring-3 Shell (`newos-sh`)
```bash
cargo xtask run
```

Example interactive commands at the `newos λ ` prompt:
```text
get @guide
put "hello newos" | save @note
get @note
objects | where size > 20
refs | where writable == false
procs | where pid == 1 | count
ref rollback @note
ref seal @note
ping 0x1234
bench
crash
exit
```

## GCP Dev VM (`newos-dev`)

The private Debian 13 + QEMU/KVM dev VM in `lgu-demos` has no public IP and is accessed exclusively via IAP (with outbound HTTPS via Cloud NAT):

```bash
gcloud compute ssh newos-dev \
  --project=lgu-demos \
  --zone=europe-west1-b \
  --tunnel-through-iap
```
