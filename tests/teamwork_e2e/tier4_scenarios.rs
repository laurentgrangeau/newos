use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, Rights, SysError};
use newos_kernel_core::elf::parse_elf64;
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_SIZE, PhysAddr, PhysFrame, UntypedInventory, VirtAddr,
};
use newos_kernel_core::sched::{SmpScheduler, ThreadState};
use newos_shell_core::caos::{ObjHash, ObjectStore};
use newos_shell_core::shell::{ExecOutcome, Record, Shell};

use crate::helpers::{
    ElfSegSpec, MockShellHost, PF_R, PF_X, PT_LOAD, TokKind, Xorshift64, build_elf64,
    collect_rs_files, find_repo_root, find_unsafe_sites, has_forbid_unsafe_code,
    has_safety_comment, parse_metric_lines, run_newos_bench, scan_rust_source, strip_cfg_test,
};

#[test]
fn t4_scenario1_full_multicommand_shell_session() {
    let mut sh = Shell::new(MockShellHost::new());
    assert_eq!(sh.run_self_test(), Ok(()));
    assert_eq!(sh.host().write_debug_calls, 0);

    let session = [
        "help",
        "sys",
        "procs | where pid == 1 | count",
        "put \"config v1\" | save @cfg",
        "put \"config v2\" | save @cfg",
        "put \"temp orphan\"",
        "objects | where size > 5 | count",
        "get @cfg",
        "gc",
        "ref rollback @cfg",
        "get @cfg",
        "ref seal @cfg",
        "ping 0x100",
        "ping 0x200",
        "bench",
        // Interleaved malformed commands must not corrupt shell state
        "objects | where invalid == 1",
        "put \"unterminated",
        "get obj:NOTHEX",
        "history",
    ];

    for cmd in session {
        sh.record_history(cmd);
        assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
    }

    assert_eq!(sh.host().sys_info_calls, 1);
    assert_eq!(sh.host().ipc_call_calls, 2);
    assert_eq!(sh.store().get_any("@cfg").unwrap().1, b"config v1");

    // Snapshot round-trip preserves full session store state
    let mut snap = [0u8; 4096];
    let n = sh.store().encode_snapshot(&mut snap).unwrap();
    let restored = ObjectStore::decode_snapshot(&snap[..n]).unwrap();
    assert_eq!(restored.get_any("@cfg").unwrap().1, b"config v1");
    assert_eq!(
        restored.get_any("@motd").unwrap().0,
        sh.store().get_any("@motd").unwrap().0
    );

    // Pipelines still operate cleanly after full session
    sh.host_mut().clear_output();
    let count_stream = sh.eval_pipeline("objects | count");
    assert!(matches!(count_stream.first(), Some(Record::Count(n)) if n >= 3));
}

#[test]
fn t4_scenario2_multiprocess_microkernel_simulation() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x4000_0000, PAGE_SIZE * 32));
    let mut tracker = FrameMappingTracker::<32>::new();

    let mut ipc = KernelIpcState::new();
    let (_, _, fault_notif) = ipc.init_bootstrap_caps(None).unwrap();

    // Bootstrap 3 isolated workers (PIDs 1, 2, 3)
    let mut worker_cnodes = [CapId::NULL; 3];
    let mut worker_eps = [CapId::NULL; 3];
    let mut root_frames = [CapId::NULL; 3];
    let mut worker_frames = [CapId::NULL; 3];
    let mut worker_phys = [PhysAddr::new(0); 3];

    for idx in 0..3usize {
        let pid = idx + 1;
        ipc.init_worker_bootstrap_caps(pid).unwrap();
        let (_, cnode_cap) = ipc.register_child_caps_in_root(pid).unwrap();
        worker_cnodes[idx] = cnode_cap;

        // Mint a unique badged endpoint and a dedicated frame for each worker
        let ep_root = ipc
            .untyped_retype_for(
                0,
                CapId::BOOTSTRAP_UNTYPED,
                ObjectType::Endpoint,
                20 + idx,
                &mut inv,
            )
            .unwrap();
        worker_eps[idx] = ipc
            .cap_grant_between(
                0,
                cnode_cap,
                ep_root,
                Rights::READ.union(Rights::WRITE),
                Some((pid as u64) << 8),
            )
            .unwrap();

        let frame_root = ipc
            .untyped_retype_for(
                0,
                CapId::BOOTSTRAP_UNTYPED,
                ObjectType::Frame,
                30 + idx,
                &mut inv,
            )
            .unwrap();
        root_frames[idx] = frame_root;
        let phys = ipc.validate_frame_for(0, frame_root, Rights::READ).unwrap();
        worker_phys[idx] = phys;
        worker_frames[idx] = ipc
            .cap_grant_between(
                0,
                cnode_cap,
                frame_root,
                Rights::READ.union(Rights::WRITE),
                None,
            )
            .unwrap();

        let vs = PhysAddr::new_aligned(0x1000_0000 + (pid as u64) * PAGE_SIZE).unwrap();
        tracker
            .record(vs, VirtAddr::new_page_aligned(0x4000_0000).unwrap(), phys)
            .unwrap();
    }

    // Schedule across 4-CPU SMP scheduler with load balancing & work stealing
    let mut smp = SmpScheduler::<4, 8>::new(4);
    let mut worker_cpus = [0usize; 3];
    for idx in 0..3usize {
        let (cpu, _tid) = smp.spawn_balanced(16 + idx as u8).unwrap();
        worker_cpus[idx] = cpu;
    }

    // Healthy IPC call from each worker
    for idx in 0..3usize {
        let pid = idx + 1;
        let reply = ipc
            .ipc_call_for(pid, worker_eps[idx], 0x1000 + pid as u64, |m| IpcMessage {
                badge: m.badge,
                payload: m.payload ^ 0xFF,
            })
            .unwrap();
        assert_eq!(reply.badge, (pid as u64) << 8);
        assert_eq!(reply.payload, (0x1000 + pid as u64) ^ 0xFF);
    }

    // Worker 2 (PID 2, idx 1) faults: supervisor receives fault notification,
    // exits its thread, revokes its frame cap, drains mappings, and reclaims frame.
    ipc.notify_signal_for(0, fault_notif, 1u64 << 2).unwrap();
    assert_eq!(ipc.notify_poll_for(0, fault_notif), Ok(1u64 << 2));

    let bad_cpu = smp.cpu_mut(worker_cpus[1]).unwrap();
    bad_cpu.exit_slot(0).unwrap();
    assert_eq!(bad_cpu.tcb(0).unwrap().state, ThreadState::Exited);

    // Revoke worker 2's delegated frame cap across processes via `cap_revoke_for`
    assert_eq!(ipc.cap_revoke_for(0, root_frames[1]).unwrap(), 1);
    assert_eq!(
        ipc.validate_frame_for(2, worker_frames[1], Rights::READ),
        Err(SysError::InvalidCapability)
    );
    let mut drained = [None; 4];
    assert_eq!(tracker.drain_for_phys(worker_phys[1], &mut drained), 1);
    assert!(inv.reclaim_frame(PhysFrame::from_aligned(worker_phys[1]).unwrap()));

    // Workers 1 and 3 continue uninterrupted
    for idx in [0usize, 2usize] {
        let pid = idx + 1;
        assert_eq!(
            ipc.validate_frame_for(pid, worker_frames[idx], Rights::READ),
            Ok(worker_phys[idx])
        );
        let reply = ipc
            .ipc_call_for(pid, worker_eps[idx], 0x777, |m| IpcMessage {
                badge: m.badge,
                payload: m.payload + 1,
            })
            .unwrap();
        assert_eq!(reply.payload, 0x778);
    }
}

#[test]
fn t4_scenario3_reproducible_benchmark_and_regression_validation() {
    // Gate 1: Shell self-test passes with 0 debug_write syscalls
    let mut sh = Shell::new(MockShellHost::new());
    assert_eq!(sh.run_self_test(), Ok(()));
    assert_eq!(sh.host().write_debug_calls, 0);

    // Gate 2: Two consecutive default benchmark runs
    let run1 = run_newos_bench(&[]);
    let run2 = run_newos_bench(&[]);
    assert!(run1.status.success(), "run1 stderr={}", run1.stderr);
    assert!(run2.status.success(), "run2 stderr={}", run2.stderr);

    let m1 = parse_metric_lines(&run1.stdout);
    let m2 = parse_metric_lines(&run2.stdout);
    assert!(m1.len() >= 16);
    assert_eq!(m1.len(), m2.len());

    for ((n1, v1, u1), (n2, v2, u2)) in m1.iter().zip(m2.iter()) {
        assert_eq!(n1, n2);
        assert_eq!(u1, u2);
        let f1: f64 = v1.parse().expect("numeric value run1");
        let f2: f64 = v2.parse().expect("numeric value run2");
        assert!(f1.is_finite() && f1 >= 0.0);
        assert!(f2.is_finite() && f2 >= 0.0);
        if u1 == "ns/op" {
            assert!(f1 > 0.0 && f2 > 0.0, "expected positive ns/op for {n1}");
        } else {
            assert_eq!(v1, v2, "deterministic metric {n1} changed between runs");
        }
    }

    // Gate 3: --markdown and --json formats succeed and contain core metrics
    let md = run_newos_bench(&["--markdown"]);
    assert!(md.status.success());
    assert!(md.stdout.contains("kernel.ipc.send_recv"));

    let js = run_newos_bench(&["--json"]);
    assert!(js.status.success());
    assert!(js.stdout.contains("\"metrics\""));
}

#[test]
fn t4_scenario4_multithreaded_spsc_ring_100k_streaming() {
    const TOTAL_WORDS: u64 = 100_000;
    let ring = SpscRing::<64>::new();
    let producer_done = AtomicBool::new(false);

    thread::scope(|s| {
        let prod = s.spawn(|| {
            let mut next = 0u64;
            let mut batch = [0u64; 17]; // odd prime size to exercise wraparound boundaries
            while next < TOTAL_WORDS {
                if next % 19 == 0 {
                    // Mix single-item push
                    while ring.try_push(next).is_err() {
                        thread::yield_now();
                    }
                    next += 1;
                } else {
                    let count = ((TOTAL_WORDS - next) as usize).min(batch.len());
                    for (i, slot) in batch[..count].iter_mut().enumerate() {
                        *slot = next + i as u64;
                    }
                    let mut pushed = 0usize;
                    while pushed < count {
                        let n = ring.try_push_slice(&batch[pushed..count]);
                        if n == 0 {
                            thread::yield_now();
                        } else {
                            pushed += n;
                        }
                    }
                    next += count as u64;
                }
            }
            producer_done.store(true, Ordering::Release);
        });

        let cons = s.spawn(|| {
            let mut expected = 0u64;
            let mut buf = [0u64; 13]; // another prime size
            while expected < TOTAL_WORDS {
                if expected % 23 == 0 {
                    if let Some(v) = ring.try_pop() {
                        assert_eq!(v, expected, "FIFO mismatch on single pop");
                        expected += 1;
                    } else {
                        thread::yield_now();
                    }
                } else {
                    let n = ring.try_pop_slice(&mut buf);
                    if n == 0 {
                        if producer_done.load(Ordering::Acquire) && ring.is_empty() {
                            break;
                        }
                        thread::yield_now();
                    } else {
                        for &v in &buf[..n] {
                            assert_eq!(v, expected, "FIFO mismatch on slice pop");
                            expected += 1;
                        }
                    }
                }
            }
            assert_eq!(expected, TOTAL_WORDS);
        });

        prod.join().expect("producer thread panicked");
        cons.join().expect("consumer thread panicked");
    });

    assert!(ring.is_empty());
}

#[test]
fn t4_scenario5_full_workspace_safety_and_unsafe_budget_audit() {
    let root = find_repo_root();

    // 1. All 8 required crates enforce #![forbid(unsafe_code)]
    for rel in [
        "crates/abi/src/lib.rs",
        "crates/kernel-core/src/lib.rs",
        "crates/kernel/src/main.rs",
        "crates/shell-core/src/lib.rs",
        "crates/init/src/main.rs",
        "crates/worker/src/main.rs",
        "crates/net/src/lib.rs",
        "crates/bench/src/main.rs",
    ] {
        let sf = scan_rust_source(&root.join(rel));
        assert!(
            has_forbid_unsafe_code(&sf.tokens),
            "{rel} missing #![forbid(unsafe_code)]"
        );
    }

    // 2. Zero production .unwrap()/.expect()/panic!() across all 9 OS crates
    let os_crates = [
        "abi",
        "kernel-core",
        "hal",
        "kernel",
        "user-rt",
        "shell-core",
        "init",
        "worker",
        "net",
    ];
    for krate in os_crates {
        for file in collect_rs_files(&root.join("crates").join(krate).join("src")) {
            let sf = scan_rust_source(&file);
            let prod = strip_cfg_test(&sf.tokens);
            for i in 0..prod.len() {
                if prod[i].text == "."
                    && let Some(m) = prod.get(i + 1)
                    && m.kind == TokKind::Ident
                    && matches!(
                        m.text.as_str(),
                        "unwrap" | "unwrap_err" | "unwrap_unchecked" | "expect" | "expect_err"
                    )
                    && prod.get(i + 2).is_some_and(|t| t.text == "(")
                {
                    panic!("production .{}() at {}:{}", m.text, file.display(), m.line);
                }
                if prod[i].kind == TokKind::Ident
                    && matches!(prod[i].text.as_str(), "panic" | "todo" | "unimplemented")
                    && prod.get(i + 1).is_some_and(|t| t.text == "!")
                    && prod
                        .get(i + 2)
                        .is_some_and(|t| matches!(t.text.as_str(), "(" | "[" | "{"))
                {
                    panic!(
                        "production {}! at {}:{}",
                        prod[i].text,
                        file.display(),
                        prod[i].line
                    );
                }
            }
        }
    }

    // 3. Per-item // SAFETY: on every unsafe site in hal & user-rt (Post-M2/M3 hardened)
    let mut missing_safety = Vec::new();
    for dir in [root.join("crates/hal/src"), root.join("crates/user-rt/src")] {
        for file in collect_rs_files(&dir) {
            let sf = scan_rust_source(&file);
            let prod = strip_cfg_test(&sf.tokens);
            for line_num in find_unsafe_sites(&prod) {
                if !has_safety_comment(&sf.lines, line_num) {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    missing_safety.push(format!("{}:{line_num}", rel.display()));
                }
            }
        }
    }
    assert!(
        missing_safety.is_empty(),
        "unsafe sites missing `// SAFETY:` ({}): {:?}",
        missing_safety.len(),
        missing_safety
    );

    // 4. Budget checks: user-rt SyncUnsafeCell removed & paging.rs consolidated <= 15
    let user_rt = scan_rust_source(&root.join("crates/user-rt/src/lib.rs"));
    let user_rt_prod = strip_cfg_test(&user_rt.tokens);
    assert!(
        !user_rt_prod
            .iter()
            .any(|t| t.text == "SyncUnsafeCell" || t.text == "sync_unsafe_cell"),
        "user-rt must not use SyncUnsafeCell"
    );
    let paging = scan_rust_source(&root.join("crates/hal/src/arch/aarch64/paging.rs"));
    let paging_unsafe = find_unsafe_sites(&strip_cfg_test(&paging.tokens));
    assert!(
        paging_unsafe.len() <= 15,
        "paging.rs unsafe budget exceeded: {} > 15",
        paging_unsafe.len()
    );
}

#[test]
fn t4_scenario6_deterministic_adversarial_fuzz_stress_1024() {
    let mut rng = Xorshift64::new(0x5EED_C0DE_2026_0001);

    // 1. 1,024+ adversarial shell command lines (zero panics)
    let mut sh = Shell::new(MockShellHost::new());
    let fragments = [
        "put \"hello | world\"",
        "put \"unterminated quote",
        "put aaaaaaaaaaaaaaaa",
        "save @r1",
        "save @bad/name",
        "save @motd",
        "objects",
        "refs",
        "procs",
        "where size > 10",
        "where pid == 1",
        "where badfield != 0",
        "where size > nope",
        "first 2",
        "first 0",
        "first abc",
        "count",
        "ping 0x10",
        "ping zzz",
        "get @motd",
        "get obj:ZZZZ",
        "gc",
        "sys",
        "history",
        "ref rollback @r1",
        "ref seal @r1",
        "λ🦀€é",
        "",
        "   ",
    ];
    for i in 0..1024usize {
        let mut cmd = String::new();
        let stages = 1 + rng.next_usize(8);
        for s in 0..stages {
            if s > 0 {
                cmd.push_str(" | ");
            }
            let frag = fragments[rng.next_usize(fragments.len())];
            cmd.push_str(frag);
        }
        if i % 17 == 0 {
            // Append multi-byte UTF-8 near 128-byte boundary
            cmd.push_str(&"x".repeat(rng.next_usize(140)));
            cmd.push('🦀');
        }
        sh.record_history(&cmd);
        let outcome = sh.exec_line(&cmd);
        assert_eq!(outcome, ExecOutcome::Continue);
        sh.host_mut().clear_output();
    }
    assert_eq!(sh.run_self_test(), Ok(()));
    let mut snap = [0u8; 4096];
    let n = sh.store().encode_snapshot(&mut snap).unwrap();
    let _ = ObjectStore::decode_snapshot(&snap[..n]).unwrap();

    // 2. 1,024+ adversarial CAOS snapshot mutations (zero panics)
    let mut base_store = ObjectStore::new();
    let h = base_store.put(b"seed-blob").unwrap();
    base_store.set_ref("@seed", h).unwrap();
    let mut valid_snap = [0u8; 2048];
    let valid_len = base_store.encode_snapshot(&mut valid_snap).unwrap();

    for i in 0..1024usize {
        if i % 2 == 0 {
            let mut mutated = valid_snap[..valid_len].to_vec();
            let flips = 1 + rng.next_usize(6);
            for _ in 0..flips {
                let idx = rng.next_usize(mutated.len());
                mutated[idx] ^= (rng.next_u64() as u8) | 1;
            }
            if i % 6 == 0 && mutated.len() > 16 {
                // Recompute CRC so parser reaches deep structural validation
                let body = mutated.len() - 8;
                let crc = ObjHash::hash_bytes(&mutated[..body]).0;
                mutated[body..].copy_from_slice(&crc.to_le_bytes());
            }
            let _ = ObjectStore::decode_snapshot(&mutated);
        } else {
            let len = rng.next_usize(300);
            let mut raw = vec![0u8; len];
            rng.fill_bytes(&mut raw);
            let _ = ObjectStore::decode_snapshot(&raw);
        }
    }

    // 3. 1,024+ adversarial ELF64 mutations (zero panics)
    let valid_elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_vaddr: 0x40_0000,
            p_memsz: 64,
            data: vec![0xD5; 16],
        }],
    );
    for i in 0..1024usize {
        if i % 2 == 0 {
            let mut mutated = valid_elf.clone();
            let flips = 1 + rng.next_usize(8);
            for _ in 0..flips {
                let idx = rng.next_usize(mutated.len());
                mutated[idx] ^= (rng.next_u64() as u8) | 1;
            }
            let _ = parse_elf64(&mutated);
        } else {
            let len = rng.next_usize(256);
            let mut raw = vec![0u8; len];
            rng.fill_bytes(&mut raw);
            let _ = parse_elf64(&raw);
        }
    }

    // 4. 1,024+ randomized KernelIpcState & CSpace ops (zero panics)
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x6000_0000, PAGE_SIZE * 32));
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc
        .init_bootstrap_caps(Some((PhysAddr::new(0x0A00_0000), 0x200)))
        .unwrap();
    ipc.init_worker_bootstrap_caps(1).unwrap();
    let (_, cnode1) = ipc.register_child_caps_in_root(1).unwrap();

    for _ in 0..1024usize {
        let op = rng.next_usize(10);
        let pid = rng.next_usize(10);
        let raw_cap = match rng.next_usize(5) {
            0 => CapId::NULL,
            1 => ep,
            2 => notif,
            3 => CapId::BOOTSTRAP_NET_MMIO,
            _ => CapId::new(rng.next_u64()),
        };
        let rights = Rights::from_bits_truncate(rng.next_u64() as u8);
        match op {
            0 => {
                let _ = ipc.ipc_send_for(pid, raw_cap, rng.next_u64());
            }
            1 => {
                let _ = ipc.ipc_recv_for(pid, raw_cap);
            }
            2 => {
                let _ = ipc.ipc_call_for(pid, raw_cap, rng.next_u64(), |m| m);
            }
            3 => {
                let _ = ipc.notify_signal_for(pid, raw_cap, rng.next_u64());
            }
            4 => {
                let _ = ipc.notify_poll_for(pid, raw_cap);
            }
            5 => {
                let _ = ipc.cap_mint_for(pid, raw_cap, rng.next_usize(70), rights, None);
            }
            6 => {
                let _ = ipc.cap_copy_for(pid, raw_cap, rng.next_usize(70));
            }
            7 => {
                let _ = ipc.cap_delete_for(pid, raw_cap);
            }
            8 => {
                let _ = ipc.cap_grant_between(0, cnode1, raw_cap, rights, None);
            }
            _ => {
                let _ = ipc.validate_mmio_read32_for(pid, raw_cap, rng.next_u64());
            }
        }
    }

    // 5. 1,024+ randomized SpscRing<64> ops with shadow VecDeque verification (zero panics)
    let ring = SpscRing::<64>::new();
    let mut ring_shadow = std::collections::VecDeque::new();
    for _ in 0..1024usize {
        match rng.next_usize(4) {
            0 => {
                let w = rng.next_u64();
                if ring.try_push(w).is_ok() {
                    ring_shadow.push_back(w);
                }
            }
            1 => {
                if let Some(w) = ring.try_pop() {
                    assert_eq!(ring_shadow.pop_front(), Some(w));
                } else {
                    assert!(ring_shadow.is_empty());
                }
            }
            2 => {
                let count = rng.next_usize(20);
                let src: Vec<u64> = (0..count).map(|_| rng.next_u64()).collect();
                let pushed = ring.try_push_slice(&src);
                for &w in &src[..pushed] {
                    ring_shadow.push_back(w);
                }
            }
            _ => {
                let count = rng.next_usize(20);
                let mut dst = vec![0u64; count];
                let popped = ring.try_pop_slice(&mut dst);
                for &w in &dst[..popped] {
                    assert_eq!(ring_shadow.pop_front(), Some(w));
                }
            }
        }
    }

    // Drain remaining ring items and verify exact FIFO match
    while let Some(w) = ring.try_pop() {
        assert_eq!(ring_shadow.pop_front(), Some(w));
    }
    assert!(ring_shadow.is_empty());

    // Final sanity check: `Record` stream still works cleanly
    let s = sh.eval_pipeline("objects | count");
    assert!(matches!(s.first(), Some(Record::Count(_))));
}
