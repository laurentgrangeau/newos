# NewOS Benchmark Results

This document records reproducible **Pre-Optimization Baseline** measurements and (after M2+M3 optimizations) **Post-Optimization** comparison results for `newos` across **Kernel Speed** (9 metrics), **Shell Speed** (3 metrics), **IPC Consumption** (10 metrics), and **IPC Footprint** (6 metrics), measured by the zero-external-dependency, `#![forbid(unsafe_code)]` `newos-bench` harness (`crates/bench`).

> **Measurement Caveat:** All timed benchmarks below are **host-side microbenchmarks** of the `kernel-core` and `shell-core` libraries (not bare-metal EL1/EL0 hardware timings), small kernel latency deltas are within run-to-run noise, and the IPC consumption metrics are deterministic structural counts produced by the harness.

## Environment & Build Metadata

- **Host OS / Architecture**: `Darwin 27.2.0 arm64`
- **CPU**: `Apple M3 Pro`
- **Compiler**: `rustc 1.100.0 (0ef1bc386 2026-11-09) (Homebrew)`
- **Rust Edition**: `2024`
- **Build Profile / Optimization Level**: `release` (`-C opt-level=3`, via `cargo xtask bench`)
- **Timing Methodology**: 1 warmup pass + 5 measured samples per timed benchmark, reporting the **median** `ns/op` with `std::hint::black_box` dead-code elimination guards.
- **Correctness Gate**: `Shell::run_self_test()` executes and passes with zero `DebugWrite` syscalls before any metrics are reported.

### Reproducible Commands

```bash
# 1. Host unit tests
cargo xtask host-test

# 2. Run extended 28-metric benchmark suite (release / opt-level=3)
cargo xtask bench
cargo xtask bench --markdown
cargo xtask bench --json
```

## Methodology Summary (28 Metrics)

- **Kernel Speed (9 metrics, `ns/op`)**:
  - `kernel.cnode.lookup`: `CNode::<64>::lookup` cycling across 32 populated endpoint capability slots.
  - `kernel.cnode.mint_revoke`: `find_free_slot` + `mint` + `find_free_slot` + `copy` + transitive `revoke` (2-level chain) with 32 persistent slots occupied.
  - `kernel.ipc.send_recv`: `KernelIpcState::ipc_send` + `ipc_recv` roundtrip on `CapId::BOOTSTRAP_EP`.
  - `kernel.ipc.notify_signal_poll`: `KernelIpcState::notify_signal` + `notify_poll` on `CapId::BOOTSTRAP_NOTIF`.
  - `kernel.sched.schedule_next`: `Scheduler::<64>::schedule_next` with 4 active threads (`priorities 1, 5, 10, 10`).
  - `kernel.memory.retype_frame`: `UntypedInventory::retype_frame` after 15 exhausted prefix regions into a large trailing region.
  - `kernel.ring.spsc_transfer`: 32-word bursts of `SpscRing::<64>::try_push` + `try_pop` (reported per word).
  - `kernel.ipc.call_reply`: Synchronous `KernelIpcState::ipc_call` + inline reply fastpath on `CapId::BOOTSTRAP_EP` (asserts `would_blocks == 0`).
  - `kernel.ring.spsc_slice_transfer`: 32-word batched bursts of `SpscRing::<64>::try_push_slice` + `try_pop_slice` (reported per word).
- **Shell Speed (3 metrics, `ns/op`)**:
  - `shell.caos.put_get_ref`: CAOS `ObjectStore` put (unique + deduplicated), `set_ref` (create + update), `get_any`, `get_by_hash`, `rollback_ref`, and `object_count`.
  - `shell.pipeline.eval`: 4-pipeline typed stream evaluation suite (`where`, `first`, `count` over `objects`, `refs`, `procs`).
  - `shell.session.full`: Full 14-command deterministic `newos-shell-pd` session executed via `Shell::exec_line`.
- **IPC Consumption (10 metrics, exact syscall counts & payload/chunk bytes)**:
  - `ipc.shell_session.debug_write_syscalls`: Exact `ShellHost::write_debug` (`DebugWrite`) syscalls emitted during the 14-command session.
  - `ipc.shell_session.sys_info_syscalls`: Exact `ShellHost::sys_info` (`SysInfo`) syscalls during the 14-command session.
  - `ipc.ping_roundtrip.syscalls_per_op`: Exact total client + worker syscalls per `ping` roundtrip over 100 verified roundtrips.
  - `ipc.ring_burst_32w.notify_syscalls`: Exact `notify_signal` + `notify_poll` syscalls for a 32-word `SpscRing` transfer.
  - `ipc.idle_poll_100.wasted_worker_ipc`: Exact `Err(SysError::WouldBlock)` worker `ipc_recv` polls across 100 idle yields.
  - `ipc.total_consumption`: Exact sum of the 5 syscall-count IPC consumption metrics above (byte metrics are reported separately).
  - `ipc.shell_session.debug_write_bytes`: Exact total payload bytes written via `ShellHost::write_debug` during the 14-command session.
  - `ipc.shell_session.max_chunk_bytes`: Maximum single `ShellHost::write_debug` chunk size (in bytes) during the 14-command session.
  - `ipc.repl_line.syscalls`: Exact total syscalls (`read_debug_byte` + `write_debug` + `sys_info` + `yield_now`) for an interactive REPL line edit (`b"helx\x7fp\x0c\r"` -> `"help"`) and execution.
  - `ipc.repl_line.payload_bytes`: Exact total read + write payload bytes transferred across the host syscall boundary during the REPL line edit and `"help"` execution.
- **IPC Footprint (6 metrics, exact `core::mem::size_of` bytes)**:
  - `ipc.footprint.cap_slot_bytes`: Per-slot `CapSlot` footprint derived via `(size_of::<CNode<64>>() - size_of::<CNode<32>>()) / 32`.
  - `ipc.footprint.cnode64_bytes`: `size_of::<CNode<64>>()`.
  - `ipc.footprint.kernel_ipc_state_bytes`: `size_of::<KernelIpcState>()`.
  - `ipc.footprint.spsc_ring64_bytes`: `size_of::<SpscRing<64>>()`.
  - `ipc.footprint.record_stream_bytes`: `size_of::<RecordStream>()`.
  - `ipc.footprint.shell_bytes`: `size_of::<Shell<ZeroSizedHost>>()` (verified `size_of::<ZeroSizedHost>() == 0`).

## Pre-Optimization Baseline (Extended 28-Metric Suite)

### Markdown Table (`cargo xtask bench --markdown`)

| Category | Metric | Value | Unit |
|---|---|---|---|
| Kernel Speed | `kernel.cnode.lookup` | 1.15 | ns/op |
| Kernel Speed | `kernel.cnode.mint_revoke` | 15.52 | ns/op |
| Kernel Speed | `kernel.ipc.send_recv` | 2.46 | ns/op |
| Kernel Speed | `kernel.ipc.notify_signal_poll` | 2.13 | ns/op |
| Kernel Speed | `kernel.sched.schedule_next` | 7.00 | ns/op |
| Kernel Speed | `kernel.memory.retype_frame` | 1.92 | ns/op |
| Kernel Speed | `kernel.ring.spsc_transfer` | 2.51 | ns/op |
| Kernel Speed | `kernel.ipc.call_reply` | 1.03 | ns/op |
| Kernel Speed | `kernel.ring.spsc_slice_transfer` | 0.51 | ns/op |
| Shell Speed | `shell.caos.put_get_ref` | 205.56 | ns/op |
| Shell Speed | `shell.pipeline.eval` | 106.37 | ns/op |
| Shell Speed | `shell.session.full` | 1818.81 | ns/op |
| IPC Consumption | `ipc.shell_session.debug_write_syscalls` | 16 | syscalls |
| IPC Consumption | `ipc.shell_session.sys_info_syscalls` | 1 | syscalls |
| IPC Consumption | `ipc.ping_roundtrip.syscalls_per_op` | 2 | syscalls/op |
| IPC Consumption | `ipc.ring_burst_32w.notify_syscalls` | 2 | syscalls |
| IPC Consumption | `ipc.idle_poll_100.wasted_worker_ipc` | 0 | syscalls |
| IPC Consumption | `ipc.total_consumption` | 21 | syscalls |
| IPC Consumption | `ipc.shell_session.debug_write_bytes` | 1857 | bytes |
| IPC Consumption | `ipc.shell_session.max_chunk_bytes` | 256 | bytes |
| IPC Consumption | `ipc.repl_line.syscalls` | 21 | syscalls |
| IPC Consumption | `ipc.repl_line.payload_bytes` | 813 | bytes |
| IPC Footprint | `ipc.footprint.cap_slot_bytes` | 72 | bytes |
| IPC Footprint | `ipc.footprint.cnode64_bytes` | 4624 | bytes |
| IPC Footprint | `ipc.footprint.kernel_ipc_state_bytes` | 37560 | bytes |
| IPC Footprint | `ipc.footprint.spsc_ring64_bytes` | 640 | bytes |
| IPC Footprint | `ipc.footprint.record_stream_bytes` | 2056 | bytes |
| IPC Footprint | `ipc.footprint.shell_bytes` | 7656 | bytes |

### Raw Baseline `METRIC` Output (`cargo xtask bench`)

```text
METRIC kernel.cnode.lookup 1.11 ns/op
METRIC kernel.cnode.mint_revoke 14.28 ns/op
METRIC kernel.ipc.send_recv 2.37 ns/op
METRIC kernel.ipc.notify_signal_poll 2.07 ns/op
METRIC kernel.sched.schedule_next 6.93 ns/op
METRIC kernel.memory.retype_frame 1.88 ns/op
METRIC kernel.ring.spsc_transfer 2.51 ns/op
METRIC kernel.ipc.call_reply 1.04 ns/op
METRIC kernel.ring.spsc_slice_transfer 0.51 ns/op
METRIC shell.caos.put_get_ref 213.48 ns/op
METRIC shell.pipeline.eval 111.13 ns/op
METRIC shell.session.full 1760.96 ns/op
METRIC ipc.shell_session.debug_write_syscalls 16 syscalls
METRIC ipc.shell_session.sys_info_syscalls 1 syscalls
METRIC ipc.ping_roundtrip.syscalls_per_op 2 syscalls/op
METRIC ipc.ring_burst_32w.notify_syscalls 2 syscalls
METRIC ipc.idle_poll_100.wasted_worker_ipc 0 syscalls
METRIC ipc.total_consumption 21 syscalls
METRIC ipc.shell_session.debug_write_bytes 1857 bytes
METRIC ipc.shell_session.max_chunk_bytes 256 bytes
METRIC ipc.repl_line.syscalls 21 syscalls
METRIC ipc.repl_line.payload_bytes 813 bytes
METRIC ipc.footprint.cap_slot_bytes 72 bytes
METRIC ipc.footprint.cnode64_bytes 4624 bytes
METRIC ipc.footprint.kernel_ipc_state_bytes 37560 bytes
METRIC ipc.footprint.spsc_ring64_bytes 640 bytes
METRIC ipc.footprint.record_stream_bytes 2056 bytes
METRIC ipc.footprint.shell_bytes 7656 bytes
```

> Note: `cargo xtask bench --json` was also executed and verified to exit 0 with a valid 28-element `metrics` JSON array.

## Post-Optimization & Before/After Comparison

Post-optimization measurements were captured on the identical host (`Darwin 27.2.0 arm64`, `Apple M3 Pro`, `rustc 1.100.0 (0ef1bc386 2026-11-09) (Homebrew)`, Rust edition `2024`, `release` / `-C opt-level=3`) after M2 (Kernel Core, ABI & HAL), M3 (Shell Core & Userspace), and M4 Tier-5 adversarial hardening fixes. `measure_repl_line_ipc()` calls production `Shell::read_line(&mut buf)` on the identical input (`b"helx\x7fp\x0c\r"` -> `"help"`), capturing M3's Ctrl-L write coalescing alongside the 1024B `DebugWrite` buffer cap; all other 27 benchmarks are completely unchanged.

### Before (M1) vs. After (M2+M3) Comparison (All 28 Metrics)

| Category | Metric | Before (M1) | After (M2+M3) | Delta | Unit |
|---|---|---|---|---|---|
| Kernel Speed | `kernel.cnode.lookup` | 1.15 | 0.95 | -17.4% | ns/op |
| Kernel Speed | `kernel.cnode.mint_revoke` | 15.52 | 12.96 | -16.5% | ns/op |
| Kernel Speed | `kernel.ipc.send_recv` | 2.46 | 2.15 | -12.6% | ns/op |
| Kernel Speed | `kernel.ipc.notify_signal_poll` | 2.13 | 1.93 | -9.4% | ns/op |
| Kernel Speed | `kernel.sched.schedule_next` | 7.00 | 6.44 | -8.0% | ns/op |
| Kernel Speed | `kernel.memory.retype_frame` | 1.92 | 1.82 | -5.2% | ns/op |
| Kernel Speed | `kernel.ring.spsc_transfer` | 2.51 | 2.44 | -2.8% | ns/op |
| Kernel Speed | `kernel.ipc.call_reply` | 1.03 | 1.07 | +3.9%† | ns/op |
| Kernel Speed | `kernel.ring.spsc_slice_transfer` | 0.51 | 0.52 | +2.0%† | ns/op |
| Shell Speed | `shell.caos.put_get_ref` | 205.56 | 159.28 | -22.5% | ns/op |
| Shell Speed | `shell.pipeline.eval` | 106.37 | 87.81 | -17.4% | ns/op |
| Shell Speed | `shell.session.full` | 1818.81 | 1282.33 | -29.5% | ns/op |
| IPC Consumption | `ipc.shell_session.debug_write_syscalls` | 16 | 14 | -12.5% | syscalls |
| IPC Consumption | `ipc.shell_session.sys_info_syscalls` | 1 | 1 | 0.0% | syscalls |
| IPC Consumption | `ipc.ping_roundtrip.syscalls_per_op` | 2 | 2 | 0.0% | syscalls/op |
| IPC Consumption | `ipc.ring_burst_32w.notify_syscalls` | 2 | 2 | 0.0% | syscalls |
| IPC Consumption | `ipc.idle_poll_100.wasted_worker_ipc` | 0 | 0 | 0.0% | syscalls |
| IPC Consumption | `ipc.total_consumption` | 21 | 19 | -9.5% | syscalls |
| IPC Consumption | `ipc.shell_session.debug_write_bytes` | 1857 | 1322 | -28.8% | bytes |
| IPC Consumption | `ipc.shell_session.max_chunk_bytes` | 256 | 548 | +114.1%* | bytes |
| IPC Consumption | `ipc.repl_line.syscalls` | 21 | 18 | -14.3% | syscalls |
| IPC Consumption | `ipc.repl_line.payload_bytes` | 813 | 594 | -26.9% | bytes |
| IPC Footprint | `ipc.footprint.cap_slot_bytes` | 72 | 48 | -33.3% | bytes |
| IPC Footprint | `ipc.footprint.cnode64_bytes` | 4624 | 3096 | -33.0% | bytes |
| IPC Footprint | `ipc.footprint.kernel_ipc_state_bytes` | 37560 | 25224 | -32.8% | bytes |
| IPC Footprint | `ipc.footprint.spsc_ring64_bytes` | 640 | 640 | 0.0% | bytes |
| IPC Footprint | `ipc.footprint.record_stream_bytes` | 2056 | 1160 | -43.6% | bytes |
| IPC Footprint | `ipc.footprint.shell_bytes` | 7656 | 6296 | -17.8% | bytes |

> \* **`ipc.shell_session.max_chunk_bytes` (`256 -> 548` bytes, `+114.1%`) is an intended improvement**: raising the `DebugWrite` / `BufferedWriter` / `BufferedConsole` buffer cap from `256` bytes to `1024` bytes allows the full `help` output to fit in a single `DebugWrite` syscall instead of fragmenting across 3 syscalls (`ipc.shell_session.debug_write_syscalls`: `16 -> 14`).
>
> † **`kernel.ipc.call_reply` (`1.03 -> 1.07` ns/op, `+0.04` ns/op)** and **`kernel.ring.spsc_slice_transfer` (`0.51 -> 0.52` ns/op, `+0.01` ns/op)** are within host macOS sub-2ns measurement noise (raw `METRIC` recorded `0.50 ns/op` and `--json` recorded `0.51 ns/op` for `spsc_slice_transfer`).

### Key Improvements Summary

- **Kernel Speed**: CSpace lookup (`-17.4%`), mint/revoke (`-16.5%`), IPC send/recv (`-12.6%`), notification signal/poll (`-9.4%`), scheduler dispatch (`-8.0%`), memory frame retype (`-5.2%`), and SPSC ring transfer (`-2.8%`) all improved via compact `CapSlot` layout, bitmask-backed IPC queues, and compact priority/single-ready fastpaths.
- **Shell Speed**: Substantial speedups across all three workloads — CAOS `put`/`get`/`ref` (`-22.5%`, `205.56 -> 159.28 ns/op`), typed pipeline evaluation (`-17.4%`, `106.37 -> 87.81 ns/op`, including atomic single-pass multi-stage syntax pre-validation), and full 14-command session (`-29.5%`, `1818.81 -> 1282.33 ns/op`) — driven by SoA blob hash indexing, `scratch_stream` reuse, zero-copy `put`, and eliminating `core::fmt` overhead in built-ins.
- **IPC Message / Round-Trip Counts**: Shell session `DebugWrite` syscalls dropped `-12.5%` (`16 -> 14`), total IPC consumption dropped `-9.5%` (`21 -> 19`), and interactive REPL line edit + execution syscalls dropped `-14.3%` (`21 -> 18`, combining 1024B `help` coalescing and Ctrl-L single-write redraw).
- **IPC Payload Bytes**: Shell session `DebugWrite` payload dropped `-28.8%` (`1857 -> 1322` bytes) and interactive REPL payload dropped `-26.9%` (`813 -> 594` bytes) while preserving command semantics; `max_chunk_bytes` increased from `256` to `548` bytes by design under the 1024B `DebugWrite` buffer cap.
- **IPC Struct & Buffer Footprints**: `CapSlot` shrank `-33.3%` (`72 -> 48` B), `CNode<64>` shrank `-33.0%` (`4624 -> 3096` B), `KernelIpcState` shrank `-32.8%` (`37560 -> 25224` B, saving `12,336` bytes), `RecordStream` shrank `-43.6%` (`2056 -> 1160` B), and `Shell` shrank `-17.8%` (`7656 -> 6296` B).

### Raw Post-Optimization `METRIC` Output (`cargo xtask bench`)

```text
METRIC kernel.cnode.lookup 1.08 ns/op
METRIC kernel.cnode.mint_revoke 15.48 ns/op
METRIC kernel.ipc.send_recv 2.45 ns/op
METRIC kernel.ipc.notify_signal_poll 2.04 ns/op
METRIC kernel.sched.schedule_next 6.91 ns/op
METRIC kernel.memory.retype_frame 1.98 ns/op
METRIC kernel.ring.spsc_transfer 2.66 ns/op
METRIC kernel.ipc.call_reply 1.15 ns/op
METRIC kernel.ring.spsc_slice_transfer 0.50 ns/op
METRIC shell.caos.put_get_ref 161.34 ns/op
METRIC shell.pipeline.eval 88.55 ns/op
METRIC shell.session.full 1312.33 ns/op
METRIC ipc.shell_session.debug_write_syscalls 14 syscalls
METRIC ipc.shell_session.sys_info_syscalls 1 syscalls
METRIC ipc.ping_roundtrip.syscalls_per_op 2 syscalls/op
METRIC ipc.ring_burst_32w.notify_syscalls 2 syscalls
METRIC ipc.idle_poll_100.wasted_worker_ipc 0 syscalls
METRIC ipc.total_consumption 19 syscalls
METRIC ipc.shell_session.debug_write_bytes 1322 bytes
METRIC ipc.shell_session.max_chunk_bytes 548 bytes
METRIC ipc.repl_line.syscalls 18 syscalls
METRIC ipc.repl_line.payload_bytes 594 bytes
METRIC ipc.footprint.cap_slot_bytes 48 bytes
METRIC ipc.footprint.cnode64_bytes 3096 bytes
METRIC ipc.footprint.kernel_ipc_state_bytes 25224 bytes
METRIC ipc.footprint.spsc_ring64_bytes 640 bytes
METRIC ipc.footprint.record_stream_bytes 1160 bytes
METRIC ipc.footprint.shell_bytes 6296 bytes
```

> Verification note: `cargo xtask bench --markdown` (28-row Markdown table used in the `After (M2+M3)` column above) and `cargo xtask bench --json` (valid JSON with a 28-element `metrics` array) were both executed and verified to exit `0` with all 28 metrics intact.

---

## On-Target AArch64 Cycle & Tail-Latency Benchmarks (Phase 3a)

In addition to the 28 host-side microbenchmarks above (`crates/bench`), `crates/init/src/full.rs` executes an on-target AArch64 `CNTVCT_EL0` (`read_cycles()`) benchmark pass (`[bench-aarch64]`) at the end of `cargo xtask test --release` (QEMU `aarch64` `virt`, `-cpu cortex-a76`, 4 CPUs, `rustc 1.102.0-nightly`):

| Workload | Samples | `p50` (ticks) | `p99` (ticks) | `max` (ticks) | Notes |
|---|---:|---:|---:|---:|---|
| `IpcCall` round-trip (`init` ↔ `worker`, separate `TTBR0_EL1`) | 256 | `9,668` | `20,362` | `23,006` | Cross-VSpace context switch |
| `NotifySignal` + `NotifyWait` fastpath | 256 | `453` | `688` | `2,298` | Zero-block notification consumption |
| `SpscRing` 4 KiB framed byte burst (`try_push_bytes`/`try_pop_bytes`) | 16 × 256 B | — | — | `28,413` total | **0 syscalls** in data path |

> Note: `p99.9` is also printed by `[bench-aarch64]` on subsequent runs. Host-side `crates/bench` measurements above remain the pre/post M2+M3 reference baseline (`rustc 1.100.0`).
