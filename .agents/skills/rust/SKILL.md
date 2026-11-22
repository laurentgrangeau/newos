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

## 1. Toolchain & Cargo Configuration

- Use the Rust **nightly** toolchain with `rust-src`, `llvm-tools-preview`,
  `clippy`, and `rustfmt` installed (keep a `rust-toolchain.toml` at the repo
  root once Cargo crates are initialized).
- Target bare-metal triples such as `x86_64-unknown-none` (or
  `aarch64-unknown-none`) and configure `.cargo/config.toml` with:
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

- Prefer headless serial output for fast iteration and agent-readable logs:
  ```bash
  qemu-system-x86_64 \
    -enable-kvm \
    -serial stdio \
    -display none \
    -no-reboot \
    -no-shutdown \
    -drive format=raw,file=<image>
  ```
  (Omit `-enable-kvm` if running on a host without KVM, such as macOS.)
- **Automated kernel tests:** Use `#![feature(custom_test_frameworks)]` with
  QEMU's `isa-debug-exit` device (`-device isa-debug-exit,iobase=0xf4,iosize=0x04`)
  and map the exit code in `.cargo/config.toml` (`test-success-exit-code`).
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

Before concluding a change, run the applicable checks:
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings` (or target-specific `--target ...`)
3. `cargo build` / boot image build succeeds cleanly
4. `cargo test` passes (both host unit tests and QEMU integration tests)
5. Boot the image in QEMU with `-serial stdio -display none` and confirm
   expected boot/serial output with no triple-faults or panics.
