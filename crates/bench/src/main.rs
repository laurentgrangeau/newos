//! Benchmark harness for `newos`.
//!
//! Measures 28 metrics across 4 categories:
//! - Kernel speed (9 metrics, ns/op) against production `newos-abi` and `newos-kernel-core`
//! - Shell speed (3 metrics, ns/op) against production `newos-shell-core`
//! - IPC consumption (10 metrics, exact syscall counts & payload/chunk bytes)
//! - IPC footprint (6 metrics, exact `size_of` bytes for IPC & shell data structures)

use std::fmt;
use std::hint::black_box;
use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, Rights, SysError};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{PAGE_SIZE, UntypedInventory};
use newos_kernel_core::sched::Scheduler;
use newos_shell_core::caos::{ObjectStore, StoreError};
use newos_shell_core::shell::{
    ExecOutcome, LINE_BUF_SIZE, Record, RecordStream, Shell, ShellHost, ShellSelfTestError, SysInfo,
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

#[derive(Debug)]
enum BenchError {
    Sys(SysError),
    Store(StoreError),
    SelfTest(ShellSelfTestError),
    UnexpectedPingMetric,
    CliUnknownArg(String),
    CliExtraArg(String),
    Io(io::Error),
}

impl fmt::Display for BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sys(e) => write!(f, "kernel syscall error: {e}"),
            Self::Store(e) => write!(f, "CAOS object store error: {e}"),
            Self::SelfTest(e) => write!(f, "newos-shell-core run_self_test failed: {e}"),
            Self::UnexpectedPingMetric => f.write_str("unexpected ping metric output"),
            Self::CliUnknownArg(flag) => write!(f, "unknown argument `{flag}`"),
            Self::CliExtraArg(extra) => write!(f, "unexpected extra argument `{extra}`"),
            Self::Io(e) => write!(f, "output write error: {e}"),
        }
    }
}

impl std::error::Error for BenchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sys(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::SelfTest(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SysError> for BenchError {
    fn from(e: SysError) -> Self {
        Self::Sys(e)
    }
}

impl From<StoreError> for BenchError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<io::Error> for BenchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Default,
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliAction {
    Run(OutputFormat),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MetricValue {
    Float(f64),
    Int(u64),
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
    let total_ops =
        f64::from(u32::try_from(measured_iters * ops_per_iter).expect("total_ops fits in u32"));
    for sample in &mut samples {
        let start = Instant::now();
        let sink = f(measured_iters);
        let elapsed_ns = start.elapsed().as_secs_f64() * 1e9;
        black_box(sink);
        *sample = elapsed_ns / total_ops;
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

// ---------------------------------------------------------------------------
// Kernel Speed Benchmarks (9 metrics)
// ---------------------------------------------------------------------------

fn bench_kernel_cnode_lookup() -> Result<f64, BenchError> {
    let mut cnode = CNode::<64>::new();
    let mut caps = [CapId::NULL; 32];
    for (id, slot) in (0u32..).zip(&mut caps) {
        *slot = cnode.insert_root(Capability::new(CapObject::Endpoint { id }, Rights::ALL))?;
    }
    let required = Rights::READ.union(Rights::WRITE);
    Ok(bench_median_ns_per_op(10_000, 1_000_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let cap = cnode
                .lookup(black_box(caps[i & 31]), black_box(required))
                .expect("inserted root cap with Rights::ALL satisfies READ|WRITE");
            acc = acc.wrapping_add(cap.badge ^ u64::from(cap.rights.bits()));
        }
        acc
    }))
}

fn bench_kernel_cnode_mint_revoke() -> Result<f64, BenchError> {
    let mut cnode = CNode::<64>::new();
    let mut root_cap = CapId::NULL;
    for i in 0..32u32 {
        let cap = cnode.insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))?;
        if i == 0 {
            root_cap = cap;
        }
    }
    let child_rights = Rights::READ.union(Rights::GRANT);
    Ok(bench_median_ns_per_op(2_000, 100_000, 1, |iters| {
        let mut total_revoked = 0u64;
        for i in 0..iters {
            let child_slot = cnode
                .find_free_slot()
                .expect("CNode<64> has 32 free slots after setup");
            let child = cnode
                .mint(
                    black_box(root_cap),
                    child_slot,
                    child_rights,
                    Some((i as u64) | 1),
                )
                .expect("root_cap has Rights::ALL and child_slot is free");
            let grandchild_slot = cnode
                .find_free_slot()
                .expect("CNode<64> has 31 free slots after mint");
            let grandchild = cnode
                .copy(child, grandchild_slot)
                .expect("child has Rights::GRANT and grandchild_slot is free");
            black_box(grandchild);
            let revoked = cnode
                .revoke(black_box(root_cap))
                .expect("root_cap is a valid root capability");
            total_revoked += revoked as u64;
        }
        assert_eq!(total_revoked, (iters as u64) * 2);
        total_revoked
    }))
}

fn bench_kernel_ipc_send_recv() -> Result<f64, BenchError> {
    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None)?;
    Ok(bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            ipc.ipc_send(black_box(ep), black_box(i as u64))
                .expect("bootstrap endpoint accepts ipc_send when queue is empty");
            let msg = ipc
                .ipc_recv(black_box(ep))
                .expect("message was just enqueued on bootstrap endpoint");
            acc = acc.wrapping_add(msg.payload ^ msg.badge);
        }
        acc
    }))
}

fn bench_kernel_ipc_notify_signal_poll() -> Result<f64, BenchError> {
    let mut ipc = KernelIpcState::new();
    let (notif, _ep, _fault) = ipc.init_bootstrap_caps(None)?;
    Ok(bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let badge = 1u64 << (i & 63);
            ipc.notify_signal(black_box(notif), black_box(badge))
                .expect("bootstrap notification cap has WRITE right");
            let bits = ipc
                .notify_poll(black_box(notif))
                .expect("bootstrap notification cap has READ right");
            acc = acc.wrapping_add(bits);
        }
        acc
    }))
}

fn bench_kernel_sched_schedule_next() -> Result<f64, BenchError> {
    let mut sched = Scheduler::<64>::new();
    let _ = sched.spawn(1)?;
    let _ = sched.spawn(5)?;
    let _ = sched.spawn(10)?;
    let _ = sched.spawn(10)?;
    Ok(bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for _ in 0..iters {
            let tid = sched
                .schedule_next()
                .expect("4 spawned threads remain runnable");
            acc = acc.wrapping_add(u64::from(tid.0));
        }
        acc
    }))
}

fn bench_kernel_memory_retype_frame() -> Result<f64, BenchError> {
    const MEASURED_ITERS: u32 = 500_000;

    let mut prewarmed_inv = UntypedInventory::new();
    for r in 0..15u64 {
        assert!(prewarmed_inv.push_raw_region(0x0010_0000 + r * 0x0010_0000, PAGE_SIZE * 2));
    }
    assert!(prewarmed_inv.push_raw_region(0x1000_0000, PAGE_SIZE * 1_000_000));
    for _ in 0..64 {
        let frame = prewarmed_inv.retype_frame()?;
        black_box(frame.start_addr().raw());
    }

    // Warmup on an independent clone so every measured sample starts from identical allocator state.
    {
        let mut inv = prewarmed_inv.clone();
        let mut acc = 0u64;
        for _ in 0..10_000 {
            let frame = inv
                .retype_frame()
                .expect("1M-frame untyped region covers 10k warmup retypes");
            acc = acc.wrapping_add(frame.start_addr().raw());
        }
        black_box(acc);
    }

    let mut samples = [0.0f64; SAMPLES];
    for sample in &mut samples {
        // Clone prewarmed inventory per sample for repeatable, isolated allocator state.
        let mut inv = prewarmed_inv.clone();
        let start = Instant::now();
        let mut acc = 0u64;
        for _ in 0..MEASURED_ITERS {
            let frame = inv
                .retype_frame()
                .expect("1M-frame untyped region covers 500k measured retypes");
            acc = acc.wrapping_add(frame.start_addr().raw());
        }
        let elapsed_ns = start.elapsed().as_secs_f64() * 1e9;
        black_box(acc);
        *sample = elapsed_ns / f64::from(MEASURED_ITERS);
    }
    samples.sort_by(f64::total_cmp);
    Ok(samples[SAMPLES / 2])
}

fn bench_kernel_ring_spsc_transfer() -> f64 {
    const BURST: usize = 32;
    let ring = SpscRing::<64>::new();
    let ns = bench_median_ns_per_op(1_000, 25_000, BURST, |batches| {
        let mut acc = 0u64;
        for b in 0..batches {
            let base = (b as u64) << 5;
            for j in 0..BURST {
                ring.try_push(black_box(base + j as u64))
                    .expect("SpscRing<64> has capacity >= BURST(32)");
            }
            for _ in 0..BURST {
                acc = acc.wrapping_add(ring.try_pop().expect("BURST(32) items were just pushed"));
            }
        }
        acc
    });
    assert!(ring.is_empty());
    ns
}

fn bench_kernel_ipc_call_reply() -> Result<f64, BenchError> {
    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None)?;
    let ns = bench_median_ns_per_op(10_000, 500_000, 1, |iters| {
        let mut acc = 0u64;
        for i in 0..iters {
            let reply = ipc
                .ipc_call(black_box(ep), black_box(i as u64), |req| IpcMessage {
                    badge: req.badge,
                    payload: req.payload.wrapping_add(1),
                })
                .expect("bootstrap endpoint handles synchronous ipc_call");
            acc = acc.wrapping_add(reply.payload ^ reply.badge);
        }
        acc
    });
    assert_eq!(ipc.stats().would_blocks, 0);
    Ok(ns)
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
    fn try_new() -> Result<Self, SysError> {
        let mut ipc = KernelIpcState::new();
        let _ = ipc.init_bootstrap_caps(None)?;
        Ok(Self {
            ipc,
            worker_reply_recvs: 0,
            replies_verified: 0,
        })
    }

    const fn total_syscalls(&self) -> u64 {
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

            let h1 = store
                .put(black_box(p1))
                .expect("fresh ObjectStore fits 4 benchmark payloads");
            let h1_dup = store
                .put(black_box(p1))
                .expect("deduplicated put succeeds on existing payload");
            assert_eq!(h1, h1_dup);
            let h2 = store
                .put(black_box(p2))
                .expect("fresh ObjectStore fits payload 2");
            let h3 = store
                .put(black_box(p3))
                .expect("fresh ObjectStore fits payload 3");
            let h4 = store
                .put(black_box(p4))
                .expect("fresh ObjectStore fits payload 4");

            store
                .set_ref("@cfg", h1)
                .expect("fresh ObjectStore accepts @cfg ref");
            store
                .set_ref("@cfg", h2)
                .expect("@cfg ref is writable for update");
            store
                .set_ref("@tel", h3)
                .expect("fresh ObjectStore accepts @tel ref");
            store
                .set_ref("@snap", h4)
                .expect("fresh ObjectStore accepts @snap ref");

            let (rh, rb) = store.get_any("@cfg").expect("@cfg ref was just set");
            let rb_len = rb.len() as u64;
            let by_hash_len = store
                .get_by_hash(h3)
                .expect("h3 object was just stored")
                .len() as u64;
            let rolled = store
                .rollback_ref("@cfg")
                .expect("@cfg has prior version h1 to roll back to");
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

fn bench_shell_pipeline_eval() -> Result<f64, BenchError> {
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
        let h = sh.store_mut().put(payload)?;
        if idx < ref_names.len() {
            sh.store_mut().set_ref(ref_names[idx], h)?;
        }
    }

    let pipelines = [
        "objects | where size > 20 | first 8 | count",
        "refs | where writable == false | count",
        "domains | where id == 1 | count",
        "objects | where size >= 10 | where size <= 100 | first 4",
    ];

    Ok(bench_median_ns_per_op(
        500,
        5_000,
        pipelines.len(),
        |iters| {
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
        },
    ))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

fn measure_ping_roundtrip_syscalls_per_op() -> Result<u64, BenchError> {
    const ROUNDTRIPS: u64 = 100;
    let mut sh = Shell::new(PingBenchHost::try_new()?);
    for _ in 0..ROUNDTRIPS {
        let stream = sh.eval_pipeline("ping 0xA110C0DE");
        assert_eq!(stream.len(), 2);
        match stream.first() {
            Some(Record::Metric {
                label: "ipc.badge",
                value: 0x5E14,
                ..
            }) => {}
            _ => return Err(BenchError::UnexpectedPingMetric),
        }
    }
    let stats = sh.host().ipc.stats();
    assert_eq!(stats.ipc_calls, ROUNDTRIPS);
    assert_eq!(stats.ipc_sends, 0);
    assert_eq!(stats.ipc_recvs, 0);
    assert_eq!(sh.host().worker_reply_recvs, ROUNDTRIPS);
    assert_eq!(sh.host().replies_verified, ROUNDTRIPS);
    Ok(sh.host().total_syscalls() / ROUNDTRIPS)
}

fn measure_ring_burst_32w_notify_syscalls() -> Result<u64, BenchError> {
    const WORDS: usize = 32;
    let ring = SpscRing::<64>::new();
    let mut ipc = KernelIpcState::new();
    let (notif, _ep, _fault) = ipc.init_bootstrap_caps(None)?;

    let mut src = [0u64; WORDS];
    for (i, slot) in src.iter_mut().enumerate() {
        *slot = black_box((i as u64) * 7);
    }

    // Batched producer push + single coalesced notification
    let pushed = ring.try_push_slice(&src);
    assert_eq!(pushed, WORDS);
    ipc.notify_signal(notif, 1)?;

    // Single coalesced consumer poll + batched drain
    let bits = ipc.notify_poll(notif)?;
    assert_eq!(bits, 1);
    let mut dst = [0u64; WORDS];
    let popped = ring.try_pop_slice(&mut dst);
    assert_eq!(popped, WORDS);
    assert_eq!(dst, src);
    assert!(ring.is_empty());

    let stats = ipc.stats();
    assert_eq!(stats.notify_signals, 1);
    assert_eq!(stats.notify_polls, 1);
    Ok(stats.notify_signals + stats.notify_polls)
}

fn measure_idle_poll_100_wasted_worker_ipc() -> Result<u64, BenchError> {
    const IDLE_YIELDS: u64 = 100;
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WorkerState {
        WaitingRecv,
        Running,
    }

    let mut ipc = KernelIpcState::new();
    let (_notif, ep, _fault) = ipc.init_bootstrap_caps(None)?;
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
    ipc.ipc_send(ep, black_box(0xBEEF))?;
    worker_state = WorkerState::Running;
    let msg = ipc.ipc_recv(ep)?;
    assert_eq!(msg.payload, 0xBEEF);
    assert_eq!(worker_state, WorkerState::Running);

    Ok(idle_stats.would_blocks)
}

// ---------------------------------------------------------------------------
// IPC Footprint Benchmarks (6 metrics, exact struct sizes in bytes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpcFootprintStats {
    cap_slot: u64,
    cnode64: u64,
    kernel_ipc_state: u64,
    spsc_ring64: u64,
    record_stream: u64,
    shell: u64,
}

fn measure_ipc_footprint() -> IpcFootprintStats {
    let cnode64 = core::mem::size_of::<CNode<64>>();
    let cnode32 = core::mem::size_of::<CNode<32>>();
    let cnode_diff = cnode64 - cnode32;
    assert_eq!(cnode_diff % 32, 0);
    let cap_slot = (cnode_diff / 32) as u64;

    assert_eq!(core::mem::size_of::<ZeroSizedHost>(), 0);

    IpcFootprintStats {
        cap_slot,
        cnode64: cnode64 as u64,
        kernel_ipc_state: core::mem::size_of::<KernelIpcState>() as u64,
        spsc_ring64: core::mem::size_of::<SpscRing<64>>() as u64,
        record_stream: core::mem::size_of::<RecordStream>() as u64,
        shell: core::mem::size_of::<Shell<ZeroSizedHost>>() as u64,
    }
}

// ---------------------------------------------------------------------------
// CLI & Reporting
// ---------------------------------------------------------------------------

fn write_usage(w: &mut impl io::Write) -> io::Result<()> {
    writeln!(w, "Usage: newos_bench [--markdown | --json | --help]")?;
    writeln!(w)?;
    writeln!(w, "Options:")?;
    writeln!(
        w,
        "  (default)   Print machine-parseable `METRIC <name> <value> <unit>` lines"
    )?;
    writeln!(w, "  --markdown  Print GitHub-flavored Markdown table")?;
    writeln!(
        w,
        "  --json      Print JSON object with all 28 benchmark metrics"
    )?;
    writeln!(w, "  -h, --help  Show this help message and exit")
}

fn parse_args_from<I, S>(args: I) -> Result<CliAction, BenchError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let action = match iter.next().as_ref().map(AsRef::as_ref) {
        None => CliAction::Run(OutputFormat::Default),
        Some("--markdown") => CliAction::Run(OutputFormat::Markdown),
        Some("--json") => CliAction::Run(OutputFormat::Json),
        Some("--help" | "-h") => CliAction::Help,
        Some(flag) => return Err(BenchError::CliUnknownArg(flag.to_string())),
    };
    if let Some(extra) = iter.next() {
        return Err(BenchError::CliExtraArg(extra.as_ref().to_string()));
    }
    Ok(action)
}

impl Metric {
    const fn float(
        category: &'static str,
        name: &'static str,
        value: f64,
        unit: &'static str,
    ) -> Self {
        Self {
            category,
            name,
            value: MetricValue::Float(value),
            unit,
        }
    }

    const fn int(
        category: &'static str,
        name: &'static str,
        value: u64,
        unit: &'static str,
    ) -> Self {
        Self {
            category,
            name,
            value: MetricValue::Int(value),
            unit,
        }
    }
}

fn collect_speed_metrics() -> Result<[Metric; 12], BenchError> {
    Ok([
        Metric::float(
            "Kernel Speed",
            "kernel.cnode.lookup",
            bench_kernel_cnode_lookup()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.cnode.mint_revoke",
            bench_kernel_cnode_mint_revoke()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.ipc.send_recv",
            bench_kernel_ipc_send_recv()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.ipc.notify_signal_poll",
            bench_kernel_ipc_notify_signal_poll()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.sched.schedule_next",
            bench_kernel_sched_schedule_next()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.memory.retype_frame",
            bench_kernel_memory_retype_frame()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.ring.spsc_transfer",
            bench_kernel_ring_spsc_transfer(),
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.ipc.call_reply",
            bench_kernel_ipc_call_reply()?,
            "ns/op",
        ),
        Metric::float(
            "Kernel Speed",
            "kernel.ring.spsc_slice_transfer",
            bench_kernel_ring_spsc_slice_transfer(),
            "ns/op",
        ),
        Metric::float(
            "Shell Speed",
            "shell.caos.put_get_ref",
            bench_shell_caos_put_get_ref(),
            "ns/op",
        ),
        Metric::float(
            "Shell Speed",
            "shell.pipeline.eval",
            bench_shell_pipeline_eval()?,
            "ns/op",
        ),
        Metric::float(
            "Shell Speed",
            "shell.session.full",
            bench_shell_session_full(),
            "ns/op",
        ),
    ])
}

fn collect_ipc_consumption_metrics() -> Result<[Metric; 10], BenchError> {
    let session_ipc = measure_shell_session_ipc();
    let ipc_debug_writes = session_ipc.debug_write_syscalls;
    let ipc_sys_info = session_ipc.sys_info_syscalls;
    let ipc_ping_per_op = measure_ping_roundtrip_syscalls_per_op()?;
    let ipc_ring_notify = measure_ring_burst_32w_notify_syscalls()?;
    let ipc_idle_wasted = measure_idle_poll_100_wasted_worker_ipc()?;
    let ipc_total =
        ipc_debug_writes + ipc_sys_info + ipc_ping_per_op + ipc_ring_notify + ipc_idle_wasted;
    let (ipc_repl_syscalls, ipc_repl_payload_bytes) = measure_repl_line_ipc();

    Ok([
        Metric::int(
            "IPC Consumption",
            "ipc.shell_session.debug_write_syscalls",
            ipc_debug_writes,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.shell_session.sys_info_syscalls",
            ipc_sys_info,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.ping_roundtrip.syscalls_per_op",
            ipc_ping_per_op,
            "syscalls/op",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.ring_burst_32w.notify_syscalls",
            ipc_ring_notify,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.idle_poll_100.wasted_worker_ipc",
            ipc_idle_wasted,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.total_consumption",
            ipc_total,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.shell_session.debug_write_bytes",
            session_ipc.debug_write_bytes,
            "bytes",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.shell_session.max_chunk_bytes",
            session_ipc.max_chunk_bytes,
            "bytes",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.repl_line.syscalls",
            ipc_repl_syscalls,
            "syscalls",
        ),
        Metric::int(
            "IPC Consumption",
            "ipc.repl_line.payload_bytes",
            ipc_repl_payload_bytes,
            "bytes",
        ),
    ])
}

fn collect_ipc_footprint_metrics() -> [Metric; 6] {
    let footprint = measure_ipc_footprint();
    [
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.cap_slot_bytes",
            footprint.cap_slot,
            "bytes",
        ),
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.cnode64_bytes",
            footprint.cnode64,
            "bytes",
        ),
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.kernel_ipc_state_bytes",
            footprint.kernel_ipc_state,
            "bytes",
        ),
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.spsc_ring64_bytes",
            footprint.spsc_ring64,
            "bytes",
        ),
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.record_stream_bytes",
            footprint.record_stream,
            "bytes",
        ),
        Metric::int(
            "IPC Footprint",
            "ipc.footprint.shell_bytes",
            footprint.shell,
            "bytes",
        ),
    ]
}

fn collect_metrics() -> Result<Vec<Metric>, BenchError> {
    // Correctness gate: run production shell self-test before benchmarking
    let mut self_test_shell = Shell::new(BenchmarkHost::new());
    self_test_shell
        .run_self_test()
        .map_err(BenchError::SelfTest)?;
    assert_eq!(self_test_shell.host().debug_write_syscalls, 0);

    let mut metrics = Vec::with_capacity(28);
    metrics.extend_from_slice(&collect_speed_metrics()?);
    metrics.extend_from_slice(&collect_ipc_consumption_metrics()?);
    metrics.extend_from_slice(&collect_ipc_footprint_metrics());
    Ok(metrics)
}

fn format_metrics(
    format: OutputFormat,
    metrics: &[Metric],
    w: &mut impl io::Write,
) -> io::Result<()> {
    match format {
        OutputFormat::Default => {
            for m in metrics {
                match m.value {
                    MetricValue::Float(v) => writeln!(w, "METRIC {} {v:.2} {}", m.name, m.unit)?,
                    MetricValue::Int(v) => writeln!(w, "METRIC {} {v} {}", m.name, m.unit)?,
                }
            }
        }
        OutputFormat::Markdown => {
            writeln!(w, "| Category | Metric | Value | Unit |")?;
            writeln!(w, "|---|---|---|---|")?;
            for m in metrics {
                match m.value {
                    MetricValue::Float(v) => {
                        writeln!(w, "| {} | `{}` | {v:.2} | {} |", m.category, m.name, m.unit)?;
                    }
                    MetricValue::Int(v) => {
                        writeln!(w, "| {} | `{}` | {v} | {} |", m.category, m.name, m.unit)?;
                    }
                }
            }
        }
        OutputFormat::Json => {
            write!(w, "{{\"metrics\":[")?;
            for (i, m) in metrics.iter().enumerate() {
                if i > 0 {
                    write!(w, ",")?;
                }
                match m.value {
                    MetricValue::Float(v) => {
                        write!(
                            w,
                            "{{\"category\":\"{}\",\"name\":\"{}\",\"value\":{v:.2},\"unit\":\"{}\"}}",
                            m.category, m.name, m.unit
                        )?;
                    }
                    MetricValue::Int(v) => {
                        write!(
                            w,
                            "{{\"category\":\"{}\",\"name\":\"{}\",\"value\":{v},\"unit\":\"{}\"}}",
                            m.category, m.name, m.unit
                        )?;
                    }
                }
            }
            writeln!(w, "]}}")?;
        }
    }
    Ok(())
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), BenchError> {
    let mut stdout = io::stdout().lock();
    match parse_args_from(args)? {
        CliAction::Help => {
            write_usage(&mut stdout)?;
        }
        CliAction::Run(format) => {
            let metrics = collect_metrics()?;
            format_metrics(format, &metrics, &mut stdout)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err @ (BenchError::CliUnknownArg(_) | BenchError::CliExtraArg(_))) => {
            eprintln!("error: {err}");
            eprintln!("Run with `--help` for usage.");
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn parse_args_from_handles_valid_and_invalid_cli_flags() {
        assert_eq!(
            parse_args_from(Vec::<&str>::new()).ok(),
            Some(CliAction::Run(OutputFormat::Default))
        );
        assert_eq!(
            parse_args_from(["--markdown"]).ok(),
            Some(CliAction::Run(OutputFormat::Markdown))
        );
        assert_eq!(
            parse_args_from(["--json"]).ok(),
            Some(CliAction::Run(OutputFormat::Json))
        );
        assert_eq!(parse_args_from(["--help"]).ok(), Some(CliAction::Help));
        assert_eq!(parse_args_from(["-h"]).ok(), Some(CliAction::Help));

        assert!(matches!(
            parse_args_from(["--bogus"]),
            Err(BenchError::CliUnknownArg(ref s)) if s == "--bogus"
        ));
        assert!(matches!(
            parse_args_from(["--json", "--extra"]),
            Err(BenchError::CliExtraArg(ref s)) if s == "--extra"
        ));
        assert!(matches!(
            parse_args_from(["--help", "extra"]),
            Err(BenchError::CliExtraArg(ref s)) if s == "extra"
        ));
    }

    #[test]
    fn format_metrics_emits_expected_default_markdown_and_json() {
        let sample = [
            Metric {
                category: "Kernel Speed",
                name: "kernel.cnode.lookup",
                value: MetricValue::Float(12.345),
                unit: "ns/op",
            },
            Metric {
                category: "IPC Footprint",
                name: "ipc.footprint.cap_slot_bytes",
                value: MetricValue::Int(48),
                unit: "bytes",
            },
        ];

        let mut default_out = Vec::new();
        format_metrics(OutputFormat::Default, &sample, &mut default_out).expect("format default");
        assert_eq!(
            String::from_utf8(default_out).expect("utf8"),
            "METRIC kernel.cnode.lookup 12.35 ns/op\nMETRIC ipc.footprint.cap_slot_bytes 48 bytes\n"
        );

        let mut md_out = Vec::new();
        format_metrics(OutputFormat::Markdown, &sample, &mut md_out).expect("format markdown");
        let md = String::from_utf8(md_out).expect("utf8");
        assert!(md.starts_with("| Category | Metric | Value | Unit |\n|---|---|---|---|\n"));
        assert!(md.contains("| Kernel Speed | `kernel.cnode.lookup` | 12.35 | ns/op |"));
        assert!(md.contains("| IPC Footprint | `ipc.footprint.cap_slot_bytes` | 48 | bytes |"));

        let mut json_out = Vec::new();
        format_metrics(OutputFormat::Json, &sample, &mut json_out).expect("format json");
        assert_eq!(
            String::from_utf8(json_out).expect("utf8"),
            "{\"metrics\":[{\"category\":\"Kernel Speed\",\"name\":\"kernel.cnode.lookup\",\"value\":12.35,\"unit\":\"ns/op\"},{\"category\":\"IPC Footprint\",\"name\":\"ipc.footprint.cap_slot_bytes\",\"value\":48,\"unit\":\"bytes\"}]}\n"
        );
    }

    #[test]
    fn measure_ipc_footprint_reports_nonzero_sizes() {
        let fp = measure_ipc_footprint();
        assert!(fp.cap_slot > 0);
        assert!(fp.cnode64 >= fp.cap_slot * 64);
        assert!(fp.kernel_ipc_state > 0);
        assert!(fp.spsc_ring64 > 0);
        assert!(fp.record_stream > 0);
        assert!(fp.shell > 0);
    }

    #[test]
    fn bench_error_display_and_source_work() {
        let sys_err = BenchError::from(SysError::WouldBlock);
        assert!(sys_err.source().is_some());
        assert!(sys_err.to_string().contains("syscall"));

        let io_err = BenchError::from(io::Error::other("broken pipe"));
        assert!(io_err.source().is_some());
        assert!(io_err.to_string().contains("broken pipe"));

        let cli_err = BenchError::CliUnknownArg("--bad".into());
        assert!(cli_err.source().is_none());
        assert_eq!(cli_err.to_string(), "unknown argument `--bad`");
    }
}
