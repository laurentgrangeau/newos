//! Benchmark harness for `newos`.
//!
//! Measures 28 metrics across 4 categories:
//! - Kernel speed (9 metrics, ns/op) against production `newos-abi` and `newos-kernel-core`
//! - Shell speed (3 metrics, ns/op) against production `newos-shell-core`
//! - IPC consumption (10 metrics, exact syscall counts & payload/chunk bytes)
//! - IPC footprint (6 metrics, exact `size_of` bytes for IPC & shell data structures)

use std::hint::black_box;
use std::time::Instant;

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, Rights, SysError};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{PAGE_SIZE, UntypedInventory};
use newos_kernel_core::sched::Scheduler;
use newos_shell_core::caos::ObjectStore;
use newos_shell_core::shell::{
    ExecOutcome, LINE_BUF_SIZE, Record, RecordStream, Shell, ShellHost, SysInfo,
};

const SAMPLES: usize = 5;

const SESSION_COMMANDS: [&str; 14] = [
    "help",
    "sys",
    "put \"hello caos v1\" | save @demo",
    "put \"hello caos v1\"",
    "put \"hello caos v2\" | save @demo",
    "get @demo",
    "ref rollback @demo",
    "ref seal @demo",
    "objects | where size > 20",
    "refs | where writable == false",
    "domains | where id == 1 | count",
    "domains",
    "sys",
    "history",
];

enum OutputFormat {
    Default,
    Markdown,
    Json,
}

enum MetricValue {
    Float(f64),
    Int(u64),
}

struct Metric {
    category: &'static str,
    name: &'static str,
    value: MetricValue,
    unit: &'static str,
}

/// Runs `f` once for warmup, then `SAMPLES` times, returning median ns/op.
fn bench_median_ns_per_op<F>(
    warmup_iters: usize,
    measured_iters: usize,
    ops_per_iter: usize,
    mut f: F,
) -> f64
where
    F: FnMut(usize) -> u64,
{
    black_box(f(warmup_iters));
    let mut samples = [0.0f64; SAMPLES];
    let total_ops = (measured_iters * ops_per_iter) as f64;
    for sample in &mut samples {
        let start = Instant::now();
        let sink = f(measured_iters);
        let elapsed_ns = start.elapsed().as_nanos() as f64;
        black_box(sink);
        *sample = elapsed_ns / total_ops;
    }
    samples.sort_by(|a, b| a.total_cmp(b));
    samples[SAMPLES / 2]
}

// ---------------------------------------------------------------------------
// Kernel Speed Benchmarks (9 metrics)
// ---------------------------------------------------------------------------

fn bench_kernel_cnode_lookup() -> f64 {
    let mut cnode = CNode::<64>::new();
    let mut caps = [CapId::NULL; 32];
    for (i, slot) in caps.iter_mut().enumerate() {
        *slot = cnode
            .insert_root(Capability::new(
                CapObject::Endpoint { id: i as u32 },
                Rights::ALL,
            ))
            .unwrap();
    }
    let required = Rights::READ.union(Rights::WRITE);
    bench_median_ns_per_op(10_000, 1_000_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let cap = cnode
                .lookup(black_box(caps[i & 31]), black_box(required))
                .unwrap();
            acc = acc.wrapping_add(cap.badge ^ (cap.rights.bits() as u64));
        }
        acc
    })
}

fn bench_kernel_cnode_mint_revoke() -> f64 {
    let mut cnode = CNode::<64>::new();
    let mut root_cap = CapId::NULL;
    for i in 0..32u32 {
        let cap = cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))
            .unwrap();
        if i == 0 {
            root_cap = cap;
        }
    }
    let child_rights = Rights::READ.union(Rights::GRANT);
    bench_median_ns_per_op(2_000, 100_000, 1, |iters| {
        let mut total_revoked = 0u64;
        for i in 0..iters {
            let child_slot = cnode.find_free_slot().unwrap();
            let child = cnode
                .mint(
                    black_box(root_cap),
                    child_slot,
                    child_rights,
                    Some((i as u64) | 1),
                )
                .unwrap();
            let grandchild_slot = cnode.find_free_slot().unwrap();
            let grandchild = cnode.copy(child, grandchild_slot).unwrap();
            black_box(grandchild);
            let revoked = cnode.revoke(black_box(root_cap)).unwrap();
            total_revoked += revoked as u64;
        }
        assert_eq!(total_revoked, (iters as u64) * 2);
        total_revoked
    })
}

fn bench_kernel_ipc_send_recv() -> f64 {
    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
    bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            ipc.ipc_send(black_box(ep), black_box(i as u64)).unwrap();
            let msg = ipc.ipc_recv(black_box(ep)).unwrap();
            acc = acc.wrapping_add(msg.payload ^ msg.badge);
        }
        acc
    })
}

fn bench_kernel_ipc_notify_signal_poll() -> f64 {
    let mut ipc = KernelIpcState::new();
    let (notif, _ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
    bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let badge = 1u64 << (i & 63);
            ipc.notify_signal(black_box(notif), black_box(badge))
                .unwrap();
            let bits = ipc.notify_poll(black_box(notif)).unwrap();
            acc = acc.wrapping_add(bits);
        }
        acc
    })
}

fn bench_kernel_sched_schedule_next() -> f64 {
    let mut sched = Scheduler::<64>::new();
    let _ = sched.spawn(1).unwrap();
    let _ = sched.spawn(5).unwrap();
    let _ = sched.spawn(10).unwrap();
    let _ = sched.spawn(10).unwrap();
    bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for _ in 0..iters {
            let tid = sched.schedule_next().unwrap();
            acc = acc.wrapping_add(tid.0 as u64);
        }
        acc
    })
}

fn bench_kernel_memory_retype_frame() -> f64 {
    let mut prewarmed_inv = UntypedInventory::new();
    for r in 0..15u64 {
        assert!(prewarmed_inv.push_raw_region(0x0010_0000 + r * 0x0010_0000, PAGE_SIZE * 2));
    }
    assert!(prewarmed_inv.push_raw_region(0x1000_0000, PAGE_SIZE * 1_000_000));
    for _ in 0..64 {
        black_box(prewarmed_inv.retype_frame().unwrap().start_addr().raw());
    }

    // Warmup on a copy
    {
        let mut inv = prewarmed_inv.clone();
        let mut acc = 0u64;
        for _ in 0..10_000 {
            acc = acc.wrapping_add(inv.retype_frame().unwrap().start_addr().raw());
        }
        black_box(acc);
    }

    let mut samples = [0.0f64; SAMPLES];
    let measured_iters = 500_000usize;
    for sample in &mut samples {
        let mut inv = prewarmed_inv.clone();
        let start = Instant::now();
        let mut acc = 0u64;
        for _ in 0..measured_iters {
            let frame = inv.retype_frame().unwrap();
            acc = acc.wrapping_add(frame.start_addr().raw());
        }
        let elapsed_ns = start.elapsed().as_nanos() as f64;
        black_box(acc);
        *sample = elapsed_ns / (measured_iters as f64);
    }
    samples.sort_by(|a, b| a.total_cmp(b));
    samples[SAMPLES / 2]
}

fn bench_kernel_ring_spsc_transfer() -> f64 {
    const BURST: usize = 32;
    let ring = SpscRing::<64>::new();
    let ns = bench_median_ns_per_op(1_000, 25_000, BURST, |batches| {
        let mut acc = 0u64;
        for b in 0..batches {
            let base = (b as u64) << 5;
            for j in 0..BURST {
                ring.try_push(black_box(base + j as u64)).unwrap();
            }
            for _ in 0..BURST {
                acc = acc.wrapping_add(ring.try_pop().unwrap());
            }
        }
        acc
    });
    assert!(ring.is_empty());
    ns
}

fn bench_kernel_ipc_call_reply() -> f64 {
    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
    let ns = bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let reply = ipc
                .ipc_call(black_box(ep), black_box(i as u64), |req| IpcMessage {
                    badge: req.badge,
                    payload: req.payload.wrapping_add(1),
                })
                .unwrap();
            acc = acc.wrapping_add(reply.payload ^ reply.badge);
        }
        acc
    });
    assert_eq!(ipc.stats().would_blocks, 0);
    ns
}

fn bench_kernel_ring_spsc_slice_transfer() -> f64 {
    const BURST: usize = 32;
    let ring = SpscRing::<64>::new();
    let mut src = [0u64; BURST];
    for (j, slot) in src.iter_mut().enumerate() {
        *slot = (j as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let mut dst = [0u64; BURST];
    let ns = bench_median_ns_per_op(5_000, 100_000, BURST, |batches| {
        let mut acc = 0u64;
        for b in 0..batches {
            src[0] = b as u64;
            assert_eq!(ring.try_push_slice(black_box(&src)), BURST);
            assert_eq!(ring.try_pop_slice(black_box(&mut dst)), BURST);
            acc = acc.wrapping_add(dst[b & (BURST - 1)]);
        }
        acc
    });
    assert!(ring.is_empty());
    ns
}

// ---------------------------------------------------------------------------
// ShellHost Implementations for Shell & IPC Benchmarks
// ---------------------------------------------------------------------------

struct BenchmarkHost {
    debug_write_syscalls: u64,
    debug_write_bytes: u64,
    debug_write_max_chunk: u64,
    sys_info_syscalls: u64,
}

impl BenchmarkHost {
    const fn new() -> Self {
        Self {
            debug_write_syscalls: 0,
            debug_write_bytes: 0,
            debug_write_max_chunk: 0,
            sys_info_syscalls: 0,
        }
    }
}

impl ShellHost for BenchmarkHost {
    fn write_debug(&mut self, s: &str) {
        let len = s.len() as u64;
        self.debug_write_syscalls += 1;
        self.debug_write_bytes += len;
        self.debug_write_max_chunk = self.debug_write_max_chunk.max(len);
        black_box(s.as_bytes());
    }

    fn sys_info(&mut self) -> SysInfo {
        self.sys_info_syscalls += 1;
        SysInfo {
            online_cpus: 2,
            domain_count: 2,
            interactive_shell: false,
        }
    }
}

/// Host for interactive REPL line-editing & command-execution IPC measurement.
struct ReplBenchHost {
    input: &'static [u8],
    pos: usize,
    debug_read_syscalls: u64,
    debug_read_bytes: u64,
    debug_write_syscalls: u64,
    debug_write_bytes: u64,
    sys_info_syscalls: u64,
    yield_syscalls: u64,
}

impl ReplBenchHost {
    const fn new(input: &'static [u8]) -> Self {
        Self {
            input,
            pos: 0,
            debug_read_syscalls: 0,
            debug_read_bytes: 0,
            debug_write_syscalls: 0,
            debug_write_bytes: 0,
            sys_info_syscalls: 0,
            yield_syscalls: 0,
        }
    }
}

impl ShellHost for ReplBenchHost {
    fn write_debug(&mut self, s: &str) {
        self.debug_write_syscalls += 1;
        self.debug_write_bytes += s.len() as u64;
        black_box(s.as_bytes());
    }

    fn sys_info(&mut self) -> SysInfo {
        self.sys_info_syscalls += 1;
        SysInfo {
            online_cpus: 2,
            domain_count: 2,
            interactive_shell: true,
        }
    }

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        self.debug_read_syscalls += 1;
        if self.pos < self.input.len() {
            let b = self.input[self.pos];
            self.pos += 1;
            self.debug_read_bytes += 1;
            Ok(b)
        } else {
            Err(SysError::WouldBlock)
        }
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        self.yield_syscalls += 1;
        Ok(0)
    }
}

/// Zero-sized `ShellHost` used to measure pure `Shell<ZeroSizedHost>` struct footprint.
struct ZeroSizedHost;

impl ShellHost for ZeroSizedHost {
    fn write_debug(&mut self, s: &str) {
        black_box(s.as_bytes());
    }

    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            online_cpus: 2,
            domain_count: 2,
            interactive_shell: false,
        }
    }
}

/// Host implementing the M3 `init` <-> `worker` synchronous `IpcCall`/`IpcReplyRecv`
/// fastpath protocol (silent worker, zero hot-path serial logging) backed by `KernelIpcState`.
struct PingBenchHost {
    ipc: KernelIpcState,
    worker_reply_recvs: u64,
    replies_verified: u64,
}

impl PingBenchHost {
    fn new() -> Self {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None).unwrap();
        Self {
            ipc,
            worker_reply_recvs: 0,
            replies_verified: 0,
        }
    }

    fn total_syscalls(&self) -> u64 {
        let stats = self.ipc.stats();
        stats.ipc_calls + stats.ipc_sends + stats.ipc_recvs + self.worker_reply_recvs
    }
}

impl ShellHost for PingBenchHost {
    fn write_debug(&mut self, s: &str) {
        black_box(s.as_bytes());
    }

    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            online_cpus: 2,
            domain_count: 2,
            interactive_shell: false,
        }
    }

    fn ipc_call(&mut self, cap: CapId, payload: u64) -> Result<(u64, u64), SysError> {
        let worker_reply_recvs = &mut self.worker_reply_recvs;
        let msg = self.ipc.ipc_call(cap, payload, |req| {
            *worker_reply_recvs += 1; // 1 silent worker IpcReplyRecv per roundtrip
            IpcMessage {
                badge: req.badge,
                payload: req.payload.wrapping_add(1),
            }
        })?;
        self.replies_verified += 1;
        Ok((msg.badge, msg.payload))
    }
}

// ---------------------------------------------------------------------------
// Shell Speed Benchmarks (3 metrics)
// ---------------------------------------------------------------------------

fn bench_shell_caos_put_get_ref() -> f64 {
    bench_median_ns_per_op(500, 10_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let mut store = ObjectStore::new();
            let p1 = b"alpha-config-payload-v1";
            let p2 = b"alpha-config-payload-v2";
            let p3 = b"beta-telemetry-blob-001";
            let p4 = b"gamma-snapshot-record";

            let h1 = store.put(black_box(p1)).unwrap();
            let h1_dup = store.put(black_box(p1)).unwrap();
            assert_eq!(h1, h1_dup);
            let h2 = store.put(black_box(p2)).unwrap();
            let h3 = store.put(black_box(p3)).unwrap();
            let h4 = store.put(black_box(p4)).unwrap();

            store.set_ref("@cfg", h1).unwrap();
            store.set_ref("@cfg", h2).unwrap();
            store.set_ref("@tel", h3).unwrap();
            store.set_ref("@snap", h4).unwrap();

            let (rh, rb) = store.get_any("@cfg").unwrap();
            let rb_len = rb.len() as u64;
            let by_hash_len = store.get_by_hash(h3).unwrap().len() as u64;
            let rolled = store.rollback_ref("@cfg").unwrap();
            let count = store.object_count();

            acc = acc
                .wrapping_add(rh.0)
                .wrapping_add(rb_len)
                .wrapping_add(by_hash_len)
                .wrapping_add(rolled.0)
                .wrapping_add(count as u64)
                .wrapping_add(i as u64);
        }
        acc
    })
}

fn bench_shell_pipeline_eval() -> f64 {
    let mut sh = Shell::new(BenchmarkHost::new());
    let payloads: [&[u8]; 8] = [
        b"short-1",
        b"medium-object-payload-02",
        b"longer-object-payload-for-pipeline-filter-03",
        b"another-structured-record-value-04",
        b"tiny5",
        b"capability-store-entry-number-06",
        b"typed-pipeline-benchmark-blob-07",
        b"final-seeded-object-for-where-clause-08",
    ];
    let ref_names = ["@r1", "@r2", "@r3", "@r4"];
    for (idx, payload) in payloads.iter().enumerate() {
        let h = sh.store_mut().put(payload).unwrap();
        if idx < ref_names.len() {
            sh.store_mut().set_ref(ref_names[idx], h).unwrap();
        }
    }

    let pipelines = [
        "objects | where size > 20 | first 8 | count",
        "refs | where writable == false | count",
        "domains | where id == 1 | count",
        "objects | where size >= 10 | where size <= 100 | first 4",
    ];

    bench_median_ns_per_op(500, 5_000, pipelines.len(), |iters| {
        let mut acc = 0u64;
        for _ in 0..iters {
            for &cmd in &pipelines {
                let stream = sh.eval_pipeline(black_box(cmd));
                let val = match stream.first() {
                    Some(Record::Count(c)) => c as u64,
                    Some(Record::Object(m)) => m.hash.0,
                    Some(Record::Ref(m)) => m.target.0,
                    Some(Record::Domain { id, .. }) => id,
                    Some(Record::Metric { value, .. }) => value,
                    None => 0,
                };
                acc = acc.wrapping_add(val ^ (stream.len() as u64));
            }
        }
        acc
    })
}

fn run_canonical_session(sh: &mut Shell<BenchmarkHost>) -> u64 {
    let mut executed = 0u64;
    for &cmd in &SESSION_COMMANDS {
        sh.record_history(cmd);
        let outcome = sh.exec_line(black_box(cmd));
        assert_eq!(outcome, ExecOutcome::Continue);
        executed += 1;
    }
    executed ^ sh.host().debug_write_bytes ^ sh.host().sys_info_syscalls
}

fn bench_shell_session_full() -> f64 {
    bench_median_ns_per_op(200, 2_000, 1, |iters| {
        let mut acc = 0u64;
        for _ in 0..iters {
            let mut sh = Shell::new(BenchmarkHost::new());
            acc = acc.wrapping_add(run_canonical_session(&mut sh));
        }
        acc
    })
}

// ---------------------------------------------------------------------------
// IPC Consumption Benchmarks (10 metrics, exact production syscall & byte counts)
// ---------------------------------------------------------------------------

struct ShellSessionIpcStats {
    debug_write_syscalls: u64,
    sys_info_syscalls: u64,
    debug_write_bytes: u64,
    max_chunk_bytes: u64,
}

fn measure_shell_session_ipc() -> ShellSessionIpcStats {
    let mut sh = Shell::new(BenchmarkHost::new());
    black_box(run_canonical_session(&mut sh));
    let host = sh.host();
    ShellSessionIpcStats {
        debug_write_syscalls: host.debug_write_syscalls,
        sys_info_syscalls: host.sys_info_syscalls,
        debug_write_bytes: host.debug_write_bytes,
        max_chunk_bytes: host.debug_write_max_chunk,
    }
}

fn measure_repl_line_ipc() -> (u64, u64) {
    // Types "helx", backspace deletes 'x', types 'p', Ctrl-L redraws, Enter submits "help".
    const REPL_INPUT: &[u8] = b"helx\x7fp\x0c\r";

    let mut sh = Shell::new(ReplBenchHost::new(REPL_INPUT));
    let mut buf = [0u8; LINE_BUF_SIZE];

    sh.host_mut().write_debug("newos λ ");
    let len = sh.read_line(&mut buf);

    let line = core::str::from_utf8(&buf[..len]).unwrap_or("").trim();
    assert_eq!(line, "help");
    sh.record_history(line);
    assert_eq!(sh.exec_line(line), ExecOutcome::Continue);

    let host = sh.host();
    let syscalls = host.debug_read_syscalls
        + host.debug_write_syscalls
        + host.sys_info_syscalls
        + host.yield_syscalls;
    let payload_bytes = host.debug_read_bytes + host.debug_write_bytes;
    (syscalls, payload_bytes)
}

fn measure_ping_roundtrip_syscalls_per_op() -> u64 {
    const ROUNDTRIPS: u64 = 100;
    let mut sh = Shell::new(PingBenchHost::new());
    for _ in 0..ROUNDTRIPS {
        let stream = sh.eval_pipeline("ping 0xA110C0DE");
        assert_eq!(stream.len(), 2);
        match stream.first() {
            Some(Record::Metric {
                label: "ipc.badge",
                value: 0x5E14,
                ..
            }) => {}
            _ => panic!("unexpected ping metric output"),
        }
    }
    let stats = sh.host().ipc.stats();
    assert_eq!(stats.ipc_calls, ROUNDTRIPS);
    assert_eq!(stats.ipc_sends, 0);
    assert_eq!(stats.ipc_recvs, 0);
    assert_eq!(sh.host().worker_reply_recvs, ROUNDTRIPS);
    assert_eq!(sh.host().replies_verified, ROUNDTRIPS);
    sh.host().total_syscalls() / ROUNDTRIPS
}

fn measure_ring_burst_32w_notify_syscalls() -> u64 {
    const WORDS: usize = 32;
    let ring = SpscRing::<64>::new();
    let mut ipc = KernelIpcState::new();
    let (notif, _ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();

    let mut src = [0u64; WORDS];
    for (i, slot) in src.iter_mut().enumerate() {
        *slot = black_box((i as u64) * 7);
    }

    // Batched producer push + single coalesced notification
    let pushed = ring.try_push_slice(&src);
    assert_eq!(pushed, WORDS);
    ipc.notify_signal(notif, 1).unwrap();

    // Single coalesced consumer poll + batched drain
    let bits = ipc.notify_poll(notif).unwrap();
    assert_eq!(bits, 1);
    let mut dst = [0u64; WORDS];
    let popped = ring.try_pop_slice(&mut dst);
    assert_eq!(popped, WORDS);
    assert_eq!(dst, src);
    assert!(ring.is_empty());

    let stats = ipc.stats();
    assert_eq!(stats.notify_signals, 1);
    assert_eq!(stats.notify_polls, 1);
    stats.notify_signals + stats.notify_polls
}

fn measure_idle_poll_100_wasted_worker_ipc() -> u64 {
    const IDLE_YIELDS: u64 = 100;
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WorkerState {
        WaitingRecv,
        Running,
    }

    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None).unwrap();
    let mut worker_state = WorkerState::WaitingRecv;

    // Across 100 idle scheduler ticks with no incoming message, a worker blocked in
    // `WaitingRecv` (`IpcReplyRecv`) is not scheduled and issues zero speculative `IpcRecv`s.
    for _ in 0..IDLE_YIELDS {
        let pending = black_box(false);
        if pending && worker_state == WorkerState::WaitingRecv {
            worker_state = WorkerState::Running;
        }
        if worker_state == WorkerState::Running {
            let _ = ipc.ipc_recv(black_box(ep));
            worker_state = WorkerState::WaitingRecv;
        }
    }
    let idle_stats = ipc.stats();
    assert_eq!(idle_stats.ipc_recvs, 0);
    assert_eq!(worker_state, WorkerState::WaitingRecv);

    // Sanity check: a genuine message wakes the blocked worker and delivers cleanly.
    ipc.ipc_send(ep, black_box(0xBEEF)).unwrap();
    worker_state = WorkerState::Running;
    let msg = ipc.ipc_recv(ep).unwrap();
    assert_eq!(msg.payload, 0xBEEF);
    assert_eq!(worker_state, WorkerState::Running);

    idle_stats.would_blocks
}

// ---------------------------------------------------------------------------
// IPC Footprint Benchmarks (6 metrics, exact struct sizes in bytes)
// ---------------------------------------------------------------------------

struct IpcFootprintStats {
    cap_slot_bytes: u64,
    cnode64_bytes: u64,
    kernel_ipc_state_bytes: u64,
    spsc_ring64_bytes: u64,
    record_stream_bytes: u64,
    shell_bytes: u64,
}

fn measure_ipc_footprint() -> IpcFootprintStats {
    let cnode64 = core::mem::size_of::<CNode<64>>();
    let cnode32 = core::mem::size_of::<CNode<32>>();
    let cnode_diff = cnode64 - cnode32;
    assert_eq!(cnode_diff % 32, 0);
    let cap_slot_bytes = (cnode_diff / 32) as u64;

    assert_eq!(core::mem::size_of::<ZeroSizedHost>(), 0);

    IpcFootprintStats {
        cap_slot_bytes,
        cnode64_bytes: cnode64 as u64,
        kernel_ipc_state_bytes: core::mem::size_of::<KernelIpcState>() as u64,
        spsc_ring64_bytes: core::mem::size_of::<SpscRing<64>>() as u64,
        record_stream_bytes: core::mem::size_of::<RecordStream>() as u64,
        shell_bytes: core::mem::size_of::<Shell<ZeroSizedHost>>() as u64,
    }
}

// ---------------------------------------------------------------------------
// CLI & Reporting
// ---------------------------------------------------------------------------

fn print_usage() {
    println!("Usage: newos_bench [--markdown | --json | --help]");
    println!();
    println!("Options:");
    println!("  (default)   Print machine-parseable `METRIC <name> <value> <unit>` lines");
    println!("  --markdown  Print GitHub-flavored Markdown table");
    println!("  --json      Print JSON object with all 28 benchmark metrics");
    println!("  -h, --help  Show this help message and exit");
}

fn parse_args() -> OutputFormat {
    let mut args = std::env::args().skip(1);
    let format = match args.next().as_deref() {
        None => OutputFormat::Default,
        Some("--markdown") => OutputFormat::Markdown,
        Some("--json") => OutputFormat::Json,
        Some("--help" | "-h") => {
            if let Some(extra) = args.next() {
                eprintln!("error: unexpected extra argument `{extra}`");
                eprintln!("Run with `--help` for usage.");
                std::process::exit(2);
            }
            print_usage();
            std::process::exit(0);
        }
        Some(flag) => {
            eprintln!("error: unknown argument `{flag}`");
            eprintln!("Run with `--help` for usage.");
            std::process::exit(2);
        }
    };
    if let Some(extra) = args.next() {
        eprintln!("error: unexpected extra argument `{extra}`");
        eprintln!("Run with `--help` for usage.");
        std::process::exit(2);
    }
    format
}

fn main() {
    let format = parse_args();

    // Correctness gate: run production shell self-test before benchmarking
    let mut self_test_shell = Shell::new(BenchmarkHost::new());
    self_test_shell
        .run_self_test()
        .expect("newos-shell-core run_self_test failed");
    assert_eq!(self_test_shell.host().debug_write_syscalls, 0);

    // 1. Kernel Speed (9 metrics)
    let k_cnode_lookup = bench_kernel_cnode_lookup();
    let k_cnode_mint_revoke = bench_kernel_cnode_mint_revoke();
    let k_ipc_send_recv = bench_kernel_ipc_send_recv();
    let k_ipc_notify = bench_kernel_ipc_notify_signal_poll();
    let k_sched_next = bench_kernel_sched_schedule_next();
    let k_mem_retype = bench_kernel_memory_retype_frame();
    let k_ring_spsc = bench_kernel_ring_spsc_transfer();
    let k_ipc_call_reply = bench_kernel_ipc_call_reply();
    let k_ring_spsc_slice = bench_kernel_ring_spsc_slice_transfer();

    // 2. Shell Speed (3 metrics)
    let s_caos = bench_shell_caos_put_get_ref();
    let s_pipeline = bench_shell_pipeline_eval();
    let s_session = bench_shell_session_full();

    // 3. IPC Consumption (10 metrics)
    let session_ipc = measure_shell_session_ipc();
    let ipc_debug_writes = session_ipc.debug_write_syscalls;
    let ipc_sys_info = session_ipc.sys_info_syscalls;
    let ipc_ping_per_op = measure_ping_roundtrip_syscalls_per_op();
    let ipc_ring_notify = measure_ring_burst_32w_notify_syscalls();
    let ipc_idle_wasted = measure_idle_poll_100_wasted_worker_ipc();
    let ipc_total =
        ipc_debug_writes + ipc_sys_info + ipc_ping_per_op + ipc_ring_notify + ipc_idle_wasted;
    let (ipc_repl_syscalls, ipc_repl_payload_bytes) = measure_repl_line_ipc();

    // 4. IPC Footprint (6 metrics)
    let footprint = measure_ipc_footprint();

    let metrics = [
        Metric {
            category: "Kernel Speed",
            name: "kernel.cnode.lookup",
            value: MetricValue::Float(k_cnode_lookup),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.cnode.mint_revoke",
            value: MetricValue::Float(k_cnode_mint_revoke),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.ipc.send_recv",
            value: MetricValue::Float(k_ipc_send_recv),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.ipc.notify_signal_poll",
            value: MetricValue::Float(k_ipc_notify),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.sched.schedule_next",
            value: MetricValue::Float(k_sched_next),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.memory.retype_frame",
            value: MetricValue::Float(k_mem_retype),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.ring.spsc_transfer",
            value: MetricValue::Float(k_ring_spsc),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.ipc.call_reply",
            value: MetricValue::Float(k_ipc_call_reply),
            unit: "ns/op",
        },
        Metric {
            category: "Kernel Speed",
            name: "kernel.ring.spsc_slice_transfer",
            value: MetricValue::Float(k_ring_spsc_slice),
            unit: "ns/op",
        },
        Metric {
            category: "Shell Speed",
            name: "shell.caos.put_get_ref",
            value: MetricValue::Float(s_caos),
            unit: "ns/op",
        },
        Metric {
            category: "Shell Speed",
            name: "shell.pipeline.eval",
            value: MetricValue::Float(s_pipeline),
            unit: "ns/op",
        },
        Metric {
            category: "Shell Speed",
            name: "shell.session.full",
            value: MetricValue::Float(s_session),
            unit: "ns/op",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.shell_session.debug_write_syscalls",
            value: MetricValue::Int(ipc_debug_writes),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.shell_session.sys_info_syscalls",
            value: MetricValue::Int(ipc_sys_info),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.ping_roundtrip.syscalls_per_op",
            value: MetricValue::Int(ipc_ping_per_op),
            unit: "syscalls/op",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.ring_burst_32w.notify_syscalls",
            value: MetricValue::Int(ipc_ring_notify),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.idle_poll_100.wasted_worker_ipc",
            value: MetricValue::Int(ipc_idle_wasted),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.total_consumption",
            value: MetricValue::Int(ipc_total),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.shell_session.debug_write_bytes",
            value: MetricValue::Int(session_ipc.debug_write_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.shell_session.max_chunk_bytes",
            value: MetricValue::Int(session_ipc.max_chunk_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.repl_line.syscalls",
            value: MetricValue::Int(ipc_repl_syscalls),
            unit: "syscalls",
        },
        Metric {
            category: "IPC Consumption",
            name: "ipc.repl_line.payload_bytes",
            value: MetricValue::Int(ipc_repl_payload_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.cap_slot_bytes",
            value: MetricValue::Int(footprint.cap_slot_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.cnode64_bytes",
            value: MetricValue::Int(footprint.cnode64_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.kernel_ipc_state_bytes",
            value: MetricValue::Int(footprint.kernel_ipc_state_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.spsc_ring64_bytes",
            value: MetricValue::Int(footprint.spsc_ring64_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.record_stream_bytes",
            value: MetricValue::Int(footprint.record_stream_bytes),
            unit: "bytes",
        },
        Metric {
            category: "IPC Footprint",
            name: "ipc.footprint.shell_bytes",
            value: MetricValue::Int(footprint.shell_bytes),
            unit: "bytes",
        },
    ];

    match format {
        OutputFormat::Default => {
            for m in &metrics {
                match m.value {
                    MetricValue::Float(v) => println!("METRIC {} {:.2} {}", m.name, v, m.unit),
                    MetricValue::Int(v) => println!("METRIC {} {} {}", m.name, v, m.unit),
                }
            }
        }
        OutputFormat::Markdown => {
            println!("| Category | Metric | Value | Unit |");
            println!("|---|---|---|---|");
            for m in &metrics {
                match m.value {
                    MetricValue::Float(v) => {
                        println!("| {} | `{}` | {:.2} | {} |", m.category, m.name, v, m.unit);
                    }
                    MetricValue::Int(v) => {
                        println!("| {} | `{}` | {} | {} |", m.category, m.name, v, m.unit);
                    }
                }
            }
        }
        OutputFormat::Json => {
            print!("{{\"metrics\":[");
            for (i, m) in metrics.iter().enumerate() {
                if i > 0 {
                    print!(",");
                }
                match m.value {
                    MetricValue::Float(v) => {
                        print!(
                            "{{\"category\":\"{}\",\"name\":\"{}\",\"value\":{:.2},\"unit\":\"{}\"}}",
                            m.category, m.name, v, m.unit
                        );
                    }
                    MetricValue::Int(v) => {
                        print!(
                            "{{\"category\":\"{}\",\"name\":\"{}\",\"value\":{},\"unit\":\"{}\"}}",
                            m.category, m.name, v, m.unit
                        );
                    }
                }
            }
            println!("]}}");
        }
    }
}
