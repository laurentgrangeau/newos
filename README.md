# NewOS

A pure **seL4-style 64-bit capability microkernel** written in modern Rust — built with **zero kernel heap (`no_alloc` in Ring 0)**, **100% memory-safe Rust APIs (`#![forbid(unsafe_code)]` across core & userspace)**, **pure 64-bit UEFI + Limine + x2APIC** (zero 32-bit or legacy BIOS/xAPIC support), **SMP multi-core bring-up**, **isolated Ring-3 `CR3` address spaces**, and **Ring-3 crash isolation**.

## Architecture Principles

- **Strict Liedtke Minimality (Ultra-Minimal Ring 0):**
  - Only CPU/interrupt dispatch, 4-level `VSpace` page tables, `CSpace` capability & `Untyped` memory enforcement, thread scheduling, and minimal IPC (`Endpoint`, 64-bit `Notification`) live in Ring 0.
  - Zero kernel heap (`no_alloc`): all physical memory is tracked in `UntypedInventory` and explicitly retyped into frames/page tables.
  - Drivers, shared-memory ring buffers, and crash supervision live in isolated Ring-3 processes.
- **100% Memory-Safe Rust Interfaces:**
  - `#![forbid(unsafe_code)]` is compiler-enforced on `newos-abi`, `newos-kernel-core`, `newos-kernel`, `newos-init`, and `newos-worker`.
  - Audited `unsafe` is strictly confined to hardware/MSR/paging/context-switch instructions in `crates/hal` and the minimal `syscall` trampoline in `crates/user-rt`.
- **Modern 64-bit Hardware Only:**
  - Pure 64-bit UEFI ISO (OVMF + Limine protocol), x2APIC MSRs, 64-bit `syscall`/`sysretq`, and hardware security hardening (`WP`, `NXE`, `SMEP`, `SMAP`, `UMIP`, W^X page tables).

## Workspace Layout

```text
newos/
├── rust-toolchain.toml          # Nightly toolchain + rust-src, llvm-tools-preview, x86_64-unknown-none
├── Cargo.toml                   # Workspace manifest
├── xtask/                       # Build automation: pure UEFI Limine ISO builder & QEMU/KVM test runner
├── crates/
│   ├── abi/                     # #![no_std], #![forbid(unsafe_code)] — Syscalls, CapId, Rights, SpscRing
│   ├── hal/                     # #![no_std], no_alloc — Minimal audited unsafe TCB (x86_64, SMP, paging, syscall)
│   ├── kernel-core/             # #![no_std], no_alloc, #![forbid(unsafe_code)] — Untyped, CSpace/CDT, ELF64, IPC, Sched
│   ├── kernel/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Thin Ring-0 kernel binary
│   ├── user-rt/                 # #![no_std] — Safe Ring-3 Rust SDK (syscall wrappers & fault handler registration)
│   ├── init/                    # #![no_std], #![no_main], #![forbid(unsafe_code)] — Ring-3 root task & crash supervisor
│   └── worker/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Isolated Ring-3 worker process
└── infra/
    └── startup.sh               # GCP Debian 13 + QEMU/KVM + Rust nightly dev VM provisioning script
```

## Build & Test

### Host Unit Tests (`newos-abi` & `newos-kernel-core`)
```bash
cargo xtask host-test
cargo clippy --package newos-abi --package newos-kernel-core --package xtask -- -D warnings
```

### Full UEFI + Limine + QEMU/KVM Boot & Integration Tests
Requires `qemu-system-x86_64`, `ovmf`, `xorriso`, `git`, and Rust nightly (`x86_64-unknown-none` + `rust-src` — pre-installed on `newos-dev`):

```bash
cargo xtask test
```

Example verified output on `newos-dev` (`n2-standard-4`, nested KVM, `-smp 2`):
```text
[newos] booting pure seL4-style 64-bit Rust microkernel (arch=x86_64, no_alloc, forbid_unsafe_core)
[newos] HHDM=0xffff800000000000, RAM=208 MiB (10 untyped regions), SMP=2/2 CPUs online, x2APIC=true, RSDP=0xfb7e014
[newos] CPU hardening: WP=true, NXE=true, SMEP=true, SMAP=true, UMIP=true (bsp_cpu_id=0)
[newos] phase-1 HAL, SMP & x2APIC self-check: OK (cpus=2, bp=1, timer=1)
[newos] phase-2 Untyped & 4-level VSpace self-check: OK (retyped_frames=4, remaining=208 MiB)
[newos] phase-3 CSpace & CDT self-check: OK (active_caps=3, revoked=2)
[newos] spawned Ring-3 `init` (pid=0, cr3=0x0000000000006000, entry=0x00000000004011d8, segs=3)
[newos] spawned Ring-3 `worker` (pid=1, cr3=0x0000000000026000, entry=0x00000000004008a0, segs=2)
[init] hello from Ring 3 (100% safe Rust, forbid_unsafe, isolated CR3 VSpace)!
[worker] alive in isolated Ring-3 VSpace (vaddr=0x400000, separate CR3)!
[worker] received IPC (badge=0x5e14, payload=0xa110c0de) -> replying 0xa110c0df
[init] multi-process isolated CR3 IPC ping-pong with `worker`: OK
[init] phase-5 IPC, Notification & CR3 switch self-check: OK (~1243 cycles/CR3-switch)
[init] triggering deliberate Ring-3 hardware fault (#UD) to verify crash isolation...
[newos-hal] caught Ring-3 #UD (vec=6, RIP=0x0000000000401c89) -> kernel healthy, redirecting to Ring-3 supervisor
[init] phase-6 Ring-3 crash isolation & supervisor recovery: OK (fault_bits=0x40)
[xtask] QEMU exited cleanly (isa-debug-exit success)
```

## GCP Dev VM (`newos-dev`)

The private Debian 13 + QEMU/KVM dev VM in `lgu-demos` has no public IP and is accessed exclusively via IAP (with outbound HTTPS via Cloud NAT):

```bash
gcloud compute ssh newos-dev \
  --project=lgu-demos \
  --zone=europe-west1-b \
  --tunnel-through-iap
```
