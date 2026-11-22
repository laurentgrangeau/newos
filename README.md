# NewOS

A pure **seL4-style 64-bit capability microkernel** and **post-UNIX EL0 environment** written in modern Rust — built solely for the **Raspberry Pi 5 16 GB** (`aarch64` / ARMv8.2-A quad-core BCM2712 Cortex-A76, with QEMU `aarch64` `virt` retained as a local test harness). Built with **zero kernel heap (`no_alloc` in EL1)**, **100% memory-safe Rust APIs (`#![forbid(unsafe_code)]` across core, networking & userspace)**, **SMP multi-core bring-up**, **isolated `TTBR0_EL1` address spaces**, **EL0 crash isolation**, an **EL0 `smoltcp` TCP/IP stack + RP1 Cadence GEM Gigabit Ethernet driver** (plus VirtIO 1.0+ for QEMU testing), a **Content-Addressed Object Store (CAOS)**, and a **Typed Pipeline Shell (`newos-sh`)**.

## Architecture Principles

- **Strict Liedtke Minimality (Ultra-Minimal EL1):**
  - Only CPU/exception dispatch, 4-level `VSpace` page tables, `CSpace` capability & `Untyped` memory enforcement, thread scheduling, and minimal IPC (`Endpoint`, 64-bit `Notification`, capability-scoped `MmioRegion`) live in the kernel.
  - Zero kernel heap (`no_alloc`): all 16 GB of physical memory is tracked in `UntypedInventory` (64 regions) and explicitly retyped into frames/page tables.
  - Networking (`smoltcp` IPv4/DHCPv4/DNS/ICMP/TCP + Raspberry Pi 5 RP1 Cadence GEM Gigabit Ethernet & QEMU VirtIO 1.0+), storage (CAOS), shell (`newos-sh`), shared-memory ring buffers, and crash supervision live in isolated EL0 processes.
- **100% Memory-Safe Rust Interfaces:**
  - `#![forbid(unsafe_code)]` is compiler-enforced on `newos-abi`, `newos-kernel-core`, `newos-kernel`, `newos-net`, `newos-init`, and `newos-worker`.
  - Audited `unsafe` is strictly confined to hardware/paging/context-switch instructions in `crates/hal` and the minimal `svc #0` trampoline in `crates/user-rt`.
- **Post-UNIX Userspace (Zero POSIX Paths / Zero Untyped Text Pipes):**
  - **Content-Addressed Object Store (CAOS):** Immutable blobs addressed by 64-bit `ObjHash` with automatic deduplication, lock-free reads, capability-gated named Refs (`@name`), instant atomic `rollback`, and irreversible `seal` (read-only attenuation).
  - **Typed Pipeline Shell (`newos-sh`):** Stages pass typed `Record` values (`Proc`, `Object`, `Ref`, `Metric`, `Count`) directly through `|` (`put "hello" | save @note`, `objects | where size > 20`, `procs | where pid == 1 | count`, `net dhcp`, `net ping`, `net resolve`).
- **Raspberry Pi 5 (16 GB) Hardware Target:**
  - Pure 64-bit `aarch64` compiled for `-C target-cpu=cortex-a76` (ARMv8.2-A, zero 32-bit, zero x86_64).
  - UEFI + Limine, 4-level `TTBR0_EL1`/`TTBR1_EL1` with ASID tagging, 4 KiB & 2 MiB block pages, `PXN`/`UXN` W^X + `MAIR_EL1` Device-nGnRnE, `svc #0`/`eret`, PSCI, BCM2712 3-pin JST Debug PL011 UART (`0x10_7D00_1000`), and RP1 Cadence GEM Gigabit Ethernet (`0x1F_0010_0000`) with 64-bit DMA.

## System Architecture

```mermaid
flowchart TB
    subgraph Userspace["Userspace — EL0 (aarch64)"]
        direction LR

        subgraph InitProc["newos-init (PID 0 — Isolated TTBR0_EL1 VSpace, forbid unsafe)"]
            Shell["newos-sh (Typed Pipeline Shell)"]
            CAOS["CAOS (Content-Addressed Object Store)"]
            Sup["Crash Supervisor (supervisor_recover)"]
            Net["newos-net (smoltcp TCP/IP + RPi5 RP1 GEM / QEMU VirtIO 1.0+)"]
            InitRT["newos-user-rt (Safe SDK + svc #0 trampoline)"]
            Shell --> CAOS
            Shell --> Net
            Sup --> Shell
            Shell --> InitRT
            Net --> InitRT
            Sup --> InitRT
        end

        subgraph WorkerProc["newos-worker (PID 1 — Isolated TTBR0_EL1 VSpace @ 0x400000, forbid unsafe)"]
            WorkerMain["Worker Loop (IPC Echo)"]
            WorkerRT["newos-user-rt (Safe SDK + svc #0 trampoline)"]
            WorkerMain --> WorkerRT
        end

        ABI["newos-abi (forbid unsafe): SyscallNumber, CapId, Rights, SpscRing"]
        InitRT -.-> ABI
        WorkerRT -.-> ABI
    end

    subgraph Kernel["Microkernel — EL1 (Zero Heap / no_alloc)"]
        direction TB
        KernelBin["newos-kernel (forbid unsafe): Thin entry wiring HAL -> Core"]

        subgraph Core["newos-kernel-core (forbid unsafe, no_alloc)"]
            direction LR
            Mem["UntypedInventory & VSpaceMapper"]
            CSpace["CSpace / CNode & CDT Revocation"]
            IPC["Endpoint & 64-bit Notification IPC"]
            ELF["ELF64 Loader & Scheduler"]
        end

        subgraph HAL["newos-hal (Minimal Audited unsafe TCB — aarch64)"]
            direction LR
            Boot["Limine Boot Protocol (HHDM, Memmap, MP, RSDP, Modules)"]
            ARM["aarch64 HAL: VBAR_EL1, TPIDR_EL1, SMP, TTBR0/TTBR1, svc #0/eret, PL011, PSCI"]
        end

        KernelBin --> Core
        KernelBin --> HAL
        Core -- "HalPlatform & VSpaceMapper traits" --> HAL
    end

    subgraph HW["64-bit ARMv8.2-A Hardware"]
        direction LR
        HW_RPI5["Raspberry Pi 5 16 GB — BCM2712 Cortex-A76 (PL011, RP1 GEM)"]
        HW_QEMU["Local Test Harness — QEMU aarch64 virt -cpu cortex-a76 (PL011, VirtIO-Net)"]
    end

    InitRT -- "svc #0 (IPC, Notify, MmioRegion, VirtToPhys)" --> HAL
    WorkerRT -- "svc #0 (Endpoint IPC, Yield)" --> HAL
    ARM --> HW_RPI5
    ARM -. "cmdline: qemu" .-> HW_QEMU
```

## Boot Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Boot as UEFI + Limine
    participant HAL as newos-hal (_start)
    participant Core as newos-kernel-core
    participant Init as newos-init (PID 0)
    participant Worker as newos-worker (PID 1)

    Boot->>HAL: Load kernel + modules (newos-init, newos-worker), fulfill Limine requests, jump to _start()
    HAL->>HAL: Check Limine BaseRevision(3) & parse boot::boot_info() (16 GB UntypedInventory, HHDM, MP, RSDP, modules)
    HAL->>HAL: Wrap TTBR1_EL1, map PL011 UART & RP1 GEM MMIO (Device-nGnRnE), TPIDR_EL1, SP_EL1 + VBAR_EL1, svc #0, SMP APs
    HAL->>Core: kmain(platform, info) -> boot_early()
    Core->>Core: Verify all SMP secondary Cortex-A76 cores online
    Core->>Core: Phase 1 — Trigger brk #0 & verify ARM Generic Timer (CNTVCT_EL0)
    Core->>Core: Phase 2 — Untyped retype -> 4-level VSpace map, translate, probe, unmap
    Core->>Core: Phase 3 — CSpace root caps -> retype -> badged mint -> copy -> transitive CDT revoke

    Core->>Core: Phase 4 — Create isolated TTBR0_EL1 VSpace, load newos-init ELF64 + 64 KiB stack -> register PID 0
    Core->>Core: Phase 4 — Create isolated TTBR0_EL1 VSpace, load newos-worker ELF64 + 64 KiB stack -> register PID 1
    Core->>HAL: start_userspace() — drop to EL0 (eret)

    HAL->>Init: Enter newos-init::main()
    Init->>HAL: set_fault_handler(supervisor_recover)

    alt Interactive Mode (default on Raspberry Pi 5 / cargo xtask run)
        Init->>Init: Launch newos-sh ("newos λ " prompt)
    else Automated Self-Test Mode (cargo xtask test)
        Init->>HAL: ipc_send(BOOTSTRAP_EP, 0xA110_C0DE) + yield_now()
        HAL->>Worker: Switch TTBR0_EL1 -> enter newos-worker::main()
        Worker->>HAL: ipc_recv(BOOTSTRAP_EP) -> ipc_send(BOOTSTRAP_EP, payload + 1) + yield_now()
        HAL->>Init: Switch TTBR0_EL1 back to init
        Init->>Init: Verify IPC reply, 64-bit Notification + SpscRing, TTBR0 switch cycle benchmark
        Init->>Init: Run CAOS (dedup/rollback/seal) & typed pipeline self-test
        Init->>HAL: Probe NIC via BOOTSTRAP_NET_MMIO -> EL0 live DHCPv4 & ICMP ping (or smoltcp check)
        Init->>HAL: Verify unauthorized CapId::NULL MMIO read is rejected
        Init->>HAL: trigger_user_fault() (deliberate EL0 udf #0)
        HAL->>Init: Signal BOOTSTRAP_FAULT_NOTIF & redirect to supervisor_recover()
        Init->>HAL: exit(QemuExitCode::Success) -> PSCI SYSTEM_OFF
    end
```

## Workspace Layout

```text
newos/
├── rust-toolchain.toml          # Nightly toolchain + rust-src, llvm-tools-preview, aarch64-unknown-none
├── Cargo.toml                   # Workspace manifest
├── xtask/                       # Build automation: RPi5 FAT32 image & QEMU aarch64 virt test harness
├── crates/
│   ├── abi/                     # #![no_std], #![forbid(unsafe_code)] — Syscalls, CapId, Rights, SpscRing
│   ├── hal/                     # #![no_std], no_alloc — Minimal audited unsafe TCB (aarch64 / BCM2712)
│   ├── kernel-core/             # #![no_std], no_alloc, #![forbid(unsafe_code)] — Untyped, CSpace/CDT, ELF64, IPC, Sched
│   ├── kernel/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Thin EL1 kernel binary
│   ├── user-rt/                 # #![no_std] — Safe EL0 Rust SDK (aarch64 svc #0)
│   ├── net/                     # #![no_std], no_alloc, #![forbid(unsafe_code)] — EL0 smoltcp + RP1 GEM & VirtIO 1.0+
│   ├── init/                    # #![no_std], #![no_main], #![forbid(unsafe_code)] — Root task, CAOS & `newos-sh`
│   └── worker/                  # #![no_std], #![no_main], #![forbid(unsafe_code)] — Isolated EL0 worker process
└── infra/
    └── startup.sh               # GCP Debian 13 + QEMU aarch64 + Rust nightly dev VM provisioning script
```

## Raspberry Pi 5 (16 GB) Deployment

Build the 64 MiB FAT32 UEFI boot image (`target/newos-rpi5.img`, configured for the BCM2712 Cortex-A76, 3-pin JST Debug PL011 UART at `0x10_7D00_1000`, and RP1 Cadence GEM Gigabit Ethernet at `0x1F_0010_0000`):

```bash
cargo xtask rpi5-image --release
```

To boot on a Raspberry Pi 5 (16 GB):
1. Flash `target/newos-rpi5.img` to a microSD card (or copy the contents of `target/rpi5_boot/` onto a FAT32-formatted microSD card).
2. Download `RPI_EFI.fd` from [worproject/rpi5-uefi](https://github.com/worproject/rpi5-uefi/releases) and place it on the FAT32 root alongside `config.txt`.
3. Connect a 3.3V UART adapter (e.g., Raspberry Pi Debug Probe) to the Pi 5 **3-pin JST Debug UART** at **115200 8N1** and power on to reach the interactive `newos λ ` shell.

## Build, Test & Local QEMU Harness

### Host Unit Tests & Clippy
```bash
cargo xtask host-test
cargo clippy --package newos-abi --package newos-kernel-core --package newos-shell-core --package newos-net --package xtask -- -D warnings
```

### Automated AArch64 UEFI + Limine + QEMU `virt` Test Suite
Requires `qemu-system-aarch64`, `qemu-efi-aarch64` (or `AAVMF` / Homebrew QEMU EDK2), `xorriso`, `dosfstools`, `mtools`, and Rust nightly:

```bash
cargo xtask test
```

### Interactive EL0 Shell (`newos-sh`) in QEMU `virt`
```bash
cargo xtask run
```

Example interactive commands at the `newos λ ` prompt:
```text
sys
get @guide
put "hello newos" | save @note
get @note
objects | where size > 20
refs | where writable == false
procs | where pid == 1 | count
ref rollback @note
ref seal @note
net
net dhcp
net ping 10.0.2.2
net resolve example.com
ping 0x1234
bench
crash
exit
```
