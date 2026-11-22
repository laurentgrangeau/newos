# NewOS Benchmark Results

This document records reproducible pre-optimization (M1) baseline measurements and post-optimization (M4) comparison results for `newos` across **Kernel Speed**, **Shell Speed**, and **IPC Consumption**, measured by the zero-external-dependency `newos-bench` harness (`crates/bench`).

## Environment & Build Metadata

- **Host OS / Architecture**: `Darwin 27.2.0 arm64`
- **Compiler**: `rustc 1.100.0 (0ef1bc386 2026-11-09) (Homebrew)`
- **Rust Edition**: `2024`
- **Optimization Level**: `-C opt-level=3`
- **Timing Methodology**: 1 warmup pass + 5 measured samples per benchmark, reporting the **median** `ns/op` with `std::hint::black_box` dead-code elimination guards.
- **Correctness Gate**: `Shell::run_self_test()` executes and passes before metrics are reported.

### Reproducible Build & Run Commands (Offline-Safe)

```bash
# 1. Host unit tests (all zero-dep crates)
mkdir -p target/local-test
rustc --edition 2024 --crate-name newos_abi --crate-type lib crates/abi/src/lib.rs -o target/local-test/libnewos_abi.rlib
rustc --edition 2024 --test --crate-name newos_abi crates/abi/src/lib.rs -o target/local-test/test_abi && ./target/local-test/test_abi
rustc --edition 2024 --test --crate-name newos_kernel_core crates/kernel-core/src/lib.rs --extern newos_abi=target/local-test/libnewos_abi.rlib -o target/local-test/test_kernel_core && ./target/local-test/test_kernel_core
rustc --edition 2024 --test --crate-name newos_shell_core crates/shell-core/src/lib.rs --extern newos_abi=target/local-test/libnewos_abi.rlib -o target/local-test/test_shell_core && ./target/local-test/test_shell_core
CARGO_MANIFEST_DIR="$PWD/xtask" rustc --edition 2024 --crate-name xtask xtask/src/main.rs -o target/local-test/xtask_check

# 2. Build & run benchmark (-C opt-level=3)
mkdir -p target/bench
rustc --edition 2024 -C opt-level=3 --crate-name newos_abi --crate-type lib crates/abi/src/lib.rs -o target/bench/libnewos_abi.rlib
rustc --edition 2024 -C opt-level=3 --crate-name newos_kernel_core --crate-type lib crates/kernel-core/src/lib.rs --extern newos_abi=target/bench/libnewos_abi.rlib -o target/bench/libnewos_kernel_core.rlib
rustc --edition 2024 -C opt-level=3 --crate-name newos_shell_core --crate-type lib crates/shell-core/src/lib.rs --extern newos_abi=target/bench/libnewos_abi.rlib -o target/bench/libnewos_shell_core.rlib
rustc --edition 2024 -C opt-level=3 --crate-name newos_bench crates/bench/src/main.rs --extern newos_abi=target/bench/libnewos_abi.rlib --extern newos_kernel_core=target/bench/libnewos_kernel_core.rlib --extern newos_shell_core=target/bench/libnewos_shell_core.rlib -o target/bench/newos_bench

./target/bench/newos_bench
./target/bench/newos_bench --markdown
./target/bench/newos_bench --json
```

## Methodology Summary

- **Kernel Speed (7 metrics, `ns/op`)**:
  - `kernel.cnode.lookup`: `CNode::<64>::lookup` cycling across 32 populated endpoint capability slots.
  - `kernel.cnode.mint_revoke`: `find_free_slot` + `mint` + `find_free_slot` + `copy` + transitive `revoke` (2-level chain) with 32 persistent slots occupied.
  - `kernel.ipc.send_recv`: `KernelIpcState::ipc_send` + `ipc_recv` roundtrip on `CapId::BOOTSTRAP_EP`.
  - `kernel.ipc.notify_signal_poll`: `KernelIpcState::notify_signal` + `notify_poll` on `CapId::BOOTSTRAP_NOTIF`.
  - `kernel.sched.schedule_next`: `Scheduler::<64>::schedule_next` with 4 active threads (`priorities 1, 5, 10, 10`).
  - `kernel.memory.retype_frame`: `UntypedInventory::retype_frame` after 15 exhausted prefix regions into a large trailing region.
  - `kernel.ring.spsc_transfer`: 32-word bursts of `SpscRing::<64>::try_push` + `try_pop` (reported per word).
- **Shell Speed (3 metrics, `ns/op`)**:
  - `shell.caos.put_get_ref`: CAOS `ObjectStore` put (unique + deduplicated), `set_ref` (create + update), `get_any`, `get_by_hash`, `rollback_ref`, and `object_count`.
  - `shell.pipeline.eval`: 4-pipeline typed stream evaluation suite (`where`, `first`, `count` over `objects`, `refs`, `procs`).
  - `shell.session.full`: Full 14-command deterministic `newos-sh` session executed via `Shell::exec_line`.
- **IPC Consumption (6 metrics, exact syscall counts)**:
  - `ipc.shell_session.debug_write_syscalls`: Exact `ShellHost::write_debug` (`DebugWrite`) syscalls emitted during the 14-command session.
  - `ipc.shell_session.sys_info_syscalls`: Exact `ShellHost::sys_info` (`SysInfo`) syscalls during the 14-command session.
  - `ipc.ping_roundtrip.syscalls_per_op`: Exact total client + worker syscalls per `ping` roundtrip over 100 verified roundtrips.
  - `ipc.ring_burst_32w.notify_syscalls`: Exact `notify_signal` + `notify_poll` syscalls for a 32-word `SpscRing` transfer.
  - `ipc.idle_poll_100.wasted_worker_ipc`: Exact `Err(SysError::WouldBlock)` worker `ipc_recv` polls across 100 idle yields.
  - `ipc.total_consumption`: Exact sum of the 5 IPC consumption metrics above.

## Baseline (Pre-Optimization)

| Category | Metric | Value | Unit |
|---|---|---|---|
| Kernel Speed | `kernel.cnode.lookup` | 1.79 | ns/op |
| Kernel Speed | `kernel.cnode.mint_revoke` | 132.31 | ns/op |
| Kernel Speed | `kernel.ipc.send_recv` | 2.71 | ns/op |
| Kernel Speed | `kernel.ipc.notify_signal_poll` | 2.50 | ns/op |
| Kernel Speed | `kernel.sched.schedule_next` | 26.31 | ns/op |
| Kernel Speed | `kernel.memory.retype_frame` | 5.96 | ns/op |
| Kernel Speed | `kernel.ring.spsc_transfer` | 2.44 | ns/op |
| Shell Speed | `shell.caos.put_get_ref` | 508.85 | ns/op |
| Shell Speed | `shell.pipeline.eval` | 196.77 | ns/op |
| Shell Speed | `shell.session.full` | 2012.52 | ns/op |
| IPC Consumption | `ipc.shell_session.debug_write_syscalls` | 199 | syscalls |
| IPC Consumption | `ipc.shell_session.sys_info_syscalls` | 4 | syscalls |
| IPC Consumption | `ipc.ping_roundtrip.syscalls_per_op` | 16 | syscalls/op |
| IPC Consumption | `ipc.ring_burst_32w.notify_syscalls` | 64 | syscalls |
| IPC Consumption | `ipc.idle_poll_100.wasted_worker_ipc` | 100 | syscalls |
| IPC Consumption | `ipc.total_consumption` | 383 | syscalls |

### Raw Baseline `METRIC` Output

```text
METRIC kernel.cnode.lookup 1.79 ns/op
METRIC kernel.cnode.mint_revoke 132.31 ns/op
METRIC kernel.ipc.send_recv 2.71 ns/op
METRIC kernel.ipc.notify_signal_poll 2.50 ns/op
METRIC kernel.sched.schedule_next 26.31 ns/op
METRIC kernel.memory.retype_frame 5.96 ns/op
METRIC kernel.ring.spsc_transfer 2.44 ns/op
METRIC shell.caos.put_get_ref 508.85 ns/op
METRIC shell.pipeline.eval 196.77 ns/op
METRIC shell.session.full 2012.52 ns/op
METRIC ipc.shell_session.debug_write_syscalls 199 syscalls
METRIC ipc.shell_session.sys_info_syscalls 4 syscalls
METRIC ipc.ping_roundtrip.syscalls_per_op 16 syscalls/op
METRIC ipc.ring_burst_32w.notify_syscalls 64 syscalls
METRIC ipc.idle_poll_100.wasted_worker_ipc 100 syscalls
METRIC ipc.total_consumption 383 syscalls
```

## Post-Optimization

| Category | Metric | Value | Unit |
|---|---|---|---|
| Kernel Speed | `kernel.cnode.lookup` | 0.81 | ns/op |
| Kernel Speed | `kernel.cnode.mint_revoke` | 12.66 | ns/op |
| Kernel Speed | `kernel.ipc.send_recv` | 2.02 | ns/op |
| Kernel Speed | `kernel.ipc.notify_signal_poll` | 1.84 | ns/op |
| Kernel Speed | `kernel.sched.schedule_next` | 6.45 | ns/op |
| Kernel Speed | `kernel.memory.retype_frame` | 1.95 | ns/op |
| Kernel Speed | `kernel.ring.spsc_transfer` | 2.35 | ns/op |
| Shell Speed | `shell.caos.put_get_ref` | 214.58 | ns/op |
| Shell Speed | `shell.pipeline.eval` | 104.74 | ns/op |
| Shell Speed | `shell.session.full` | 1677.83 | ns/op |
| IPC Consumption | `ipc.shell_session.debug_write_syscalls` | 16 | syscalls |
| IPC Consumption | `ipc.shell_session.sys_info_syscalls` | 1 | syscalls |
| IPC Consumption | `ipc.ping_roundtrip.syscalls_per_op` | 2 | syscalls/op |
| IPC Consumption | `ipc.ring_burst_32w.notify_syscalls` | 2 | syscalls |
| IPC Consumption | `ipc.idle_poll_100.wasted_worker_ipc` | 0 | syscalls |
| IPC Consumption | `ipc.total_consumption` | 21 | syscalls |

### Raw Post-Optimization `METRIC` Output

```text
METRIC kernel.cnode.lookup 0.81 ns/op
METRIC kernel.cnode.mint_revoke 12.66 ns/op
METRIC kernel.ipc.send_recv 2.02 ns/op
METRIC kernel.ipc.notify_signal_poll 1.84 ns/op
METRIC kernel.sched.schedule_next 6.45 ns/op
METRIC kernel.memory.retype_frame 1.95 ns/op
METRIC kernel.ring.spsc_transfer 2.35 ns/op
METRIC shell.caos.put_get_ref 214.58 ns/op
METRIC shell.pipeline.eval 104.74 ns/op
METRIC shell.session.full 1677.83 ns/op
METRIC ipc.shell_session.debug_write_syscalls 16 syscalls
METRIC ipc.shell_session.sys_info_syscalls 1 syscalls
METRIC ipc.ping_roundtrip.syscalls_per_op 2 syscalls/op
METRIC ipc.ring_burst_32w.notify_syscalls 2 syscalls
METRIC ipc.idle_poll_100.wasted_worker_ipc 0 syscalls
METRIC ipc.total_consumption 21 syscalls
```

## Comparison (Baseline vs Post-Optimization)

| Category | Metric | M1 Baseline | M4 Post-Opt | Delta / Speedup | Unit |
|---|---|---|---|---|---|
| Kernel Speed | `kernel.cnode.lookup` | 1.79 | 0.81 | 2.21x (-54.7%) | ns/op |
| Kernel Speed | `kernel.cnode.mint_revoke` | 132.31 | 12.66 | 10.45x (-90.4%) | ns/op |
| Kernel Speed | `kernel.ipc.send_recv` | 2.71 | 2.02 | 1.34x (-25.5%) | ns/op |
| Kernel Speed | `kernel.ipc.notify_signal_poll` | 2.50 | 1.84 | 1.36x (-26.4%) | ns/op |
| Kernel Speed | `kernel.sched.schedule_next` | 26.31 | 6.45 | 4.08x (-75.5%) | ns/op |
| Kernel Speed | `kernel.memory.retype_frame` | 5.96 | 1.95 | 3.06x (-67.3%) | ns/op |
| Kernel Speed | `kernel.ring.spsc_transfer` | 2.44 | 2.35 | 1.04x (-3.7%) | ns/op |
| Shell Speed | `shell.caos.put_get_ref` | 508.85 | 214.58 | 2.37x (-57.8%) | ns/op |
| Shell Speed | `shell.pipeline.eval` | 196.77 | 104.74 | 1.88x (-46.8%) | ns/op |
| Shell Speed | `shell.session.full` | 2012.52 | 1677.83 | 1.20x (-16.6%) | ns/op |
| IPC Consumption | `ipc.shell_session.debug_write_syscalls` | 199 | 16 | -92.0% (12.44x) | syscalls |
| IPC Consumption | `ipc.shell_session.sys_info_syscalls` | 4 | 1 | -75.0% (4.00x) | syscalls |
| IPC Consumption | `ipc.ping_roundtrip.syscalls_per_op` | 16 | 2 | -87.5% (8.00x) | syscalls/op |
| IPC Consumption | `ipc.ring_burst_32w.notify_syscalls` | 64 | 2 | -96.9% (32.00x) | syscalls |
| IPC Consumption | `ipc.idle_poll_100.wasted_worker_ipc` | 100 | 0 | -100.0% | syscalls |
| IPC Consumption | `ipc.total_consumption` | 383 | 21 | -94.5% (18.24x) | syscalls |
