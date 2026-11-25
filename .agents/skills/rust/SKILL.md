---
name: rust
description: >-
  Use this skill when writing, building, debugging, or testing Rust code in this
  repository—especially bare-metal `#![no_std]` kernel, bootloader, and OS
  components targeting QEMU/KVM.
---

# Rust OS & Kernel Development Skill

Follow these procedures and conventions when working on Rust kernel and OS code
in this repository.

> **Architectural North Star**: NewOS is a **seL4-inspired capability microkernel** (NOT a Linux/monolithic kernel). Draw from seL4, L4, and modern Rust OS research (e.g., RedLeaf, Theseus, Hubris), keep the EL1 TCB strictly minimal, use modern capability-microkernel naming (no Unix/POSIX/`daemon` legacy), and continuously verify that every change is the **safest, fastest, most modern, memory-safe** implementation possible (see `.agents/rules/sel4-microkernel-principles.md`).

## 1. Toolchain & Cargo Configuration

- Use the Rust **nightly** toolchain with `rust-src`, `llvm-tools-preview`,
  `clippy`, and `rustfmt` installed (keep a `rust-toolchain.toml` at the repo
  root once Cargo crates are initialized).
- Target bare-metal `aarch64-unknown-none` (`-C target-cpu=cortex-a76` for Raspberry Pi 5 16 GB BCM2712) and configure builds with:
  - `[unstable]` `build-std = ["core", "compiler_builtins", "alloc"]`
  - `build-std-features = ["compiler-builtins-mem"]`
  - Target-specific linker arguments or custom linker scripts (`-C link-arg=-T...`).
- Use `cargo-binutils` (`cargo objdump`, `cargo nm`, `cargo size`,
  `cargo readobj`) to inspect ELF sections, symbol addresses, and alignment.

## 2. Bare-Metal `#![no_std]` Conventions

- Kernel crates must declare `#![no_std]` and `#![no_main]` and provide a
  `#[panic_handler]` (plus `#[alloc_error_handler]` or default OOM hook when
  using `alloc`).
- **ABI & hardware layouts:** Always annotate structs crossing hardware,
  assembly, or firmware boundaries (GDT, IDT, TSS, page tables, multiboot/UEFI
  headers, MMIO registers) with `#[repr(C)]`, `#[repr(C, packed)]`, or
  `#[repr(transparent)]` and verify sizes with `const _: () = assert!(...)`.
- **MMIO & volatile access:** Never access memory-mapped hardware registers via
  plain references; use `core::ptr::{read_volatile, write_volatile}` or a
  volatile wrapper type.
- **`unsafe` discipline:**
  - Keep `unsafe` blocks as small as possible and encapsulate invariants behind
    safe module APIs.
  - Every `unsafe` block and `unsafe fn` must include a `// SAFETY:` comment
    justifying the upheld invariants (alignment, aliasing, lifetime, CPU state).
- **Concurrency & interrupts:** Disable interrupts while holding spinlocks
  accessed from both normal execution and interrupt handlers to prevent
  same-CPU deadlocks.

## 3. Running & Debugging with QEMU/KVM

- Prefer headless serial output on QEMU `aarch64` `virt` (`-cpu cortex-a76`) for fast iteration and agent-readable logs:
  ```bash
  cargo xtask test
  ```
- **Raspberry Pi 5 (16 GB) boot image:** Build `target/newos-rpi5.img` via `cargo xtask rpi5-image`.
- **GDB debugging:** Start QEMU with `-s -S` (GDB server on `:1234`, paused at
  reset) and attach with `gdb <kernel-elf> -ex "target remote :1234"`.
- **Remote GCP dev VM (`newos-dev`):** This repo's Debian 13 + QEMU/KVM + Rust
  nightly VM is provisioned by [startup.sh](../../../infra/startup.sh) and
  accessed via IAP only:
  ```bash
  gcloud compute ssh newos-dev \
    --project=lgu-demos \
    --zone=europe-west1-b \
    --tunnel-through-iap
  ```

## 4. Verification Checklist

Every time you add, modify, or delete any line of code, you MUST:
1. Create or update tests covering the change (unit tests and/or E2E tests).
2. Run local checks:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings` (or target-specific `--target ...`)
   - `cargo test` (host unit and E2E tests)
3. Sync all modified/added/deleted files to `newos-dev` (`/home/laurentgrangeau/newos`) via IAP.
4. Run `source /etc/profile.d/rust.sh && cd ~/newos && cargo xtask test` on `newos-dev` and confirm the AArch64 kernel + EL0 protection domains build cleanly and boot in QEMU with `PSCI SYSTEM_OFF (status=OK)` and no panics or failures.
