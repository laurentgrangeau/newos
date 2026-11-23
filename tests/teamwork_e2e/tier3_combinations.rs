use std::panic::{AssertUnwindSafe, catch_unwind};

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, ShutdownStatus, Rights, SysError};
use newos_kernel_core::elf::parse_elf64;
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_SIZE, PhysAddr, PhysFrame, UntypedInventory, VirtAddr,
};
use newos_kernel_core::sched::{Scheduler, SmpScheduler, ThreadState};
use newos_shell_core::caos::{MAX_OBJECTS, ObjectStore, StoreError};
use newos_shell_core::shell::{Record, RecordStream, Shell};

use crate::helpers::{
    ElfSegSpec, ExitSentinel, MockShellHost, PF_R, PF_W, PF_X, PT_LOAD, build_elf64,
    parse_metric_lines, run_newos_bench,
};

#[test]
fn t3_cspace_ipc_memory_three_hop_delegation_and_reclaim() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x3000_0000, PAGE_SIZE * 8));
    let mut tracker = FrameMappingTracker::<16>::new();

    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    ipc.init_worker_bootstrap_caps(1).unwrap();
    ipc.init_worker_bootstrap_caps(2).unwrap();
    let (_, cnode1) = ipc.register_child_caps_in_root(1).unwrap();
    let (_, cnode2) = ipc.register_child_caps_in_root(2).unwrap();

    // PID 0 retypes a Frame and an Endpoint from Untyped
    let frame0 = ipc
        .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 30, &mut inv)
        .unwrap();
    let ep0 = ipc
        .untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Endpoint,
            31,
            &mut inv,
        )
        .unwrap();
    let frame_phys = ipc.validate_frame_for(0, frame0, Rights::READ).unwrap();

    // Track mappings in two VSpaces
    let vs1 = PhysAddr::new_aligned(0x1000_0000).unwrap();
    let vs2 = PhysAddr::new_aligned(0x1000_1000).unwrap();
    tracker
        .record(
            vs1,
            VirtAddr::new_page_aligned(0x4000_0000).unwrap(),
            frame_phys,
        )
        .unwrap();
    tracker
        .record(
            vs2,
            VirtAddr::new_page_aligned(0x5000_0000).unwrap(),
            frame_phys,
        )
        .unwrap();

    // 3-hop CDT: PID 0 -> PID 1 -> PID 2 (give PID 1 a CNode cap to PID 2 with WRITE | GRANT)
    let cnode2_for_p1 = ipc
        .cap_grant_between(0, cnode1, cnode2, Rights::WRITE.union(Rights::GRANT), None)
        .unwrap();
    let frame1 = ipc
        .cap_grant_between(0, cnode1, frame0, Rights::READ.union(Rights::GRANT), None)
        .unwrap();
    let ep1 = ipc
        .cap_grant_between(
            0,
            cnode1,
            ep0,
            Rights::WRITE.union(Rights::GRANT),
            Some(0x11),
        )
        .unwrap();

    let frame2 = ipc
        .cap_grant_between(1, cnode2_for_p1, frame1, Rights::READ, None)
        .unwrap();
    let ep2 = ipc
        .cap_grant_between(1, cnode2_for_p1, ep1, Rights::WRITE, None)
        .unwrap();

    // PID 1 moves its cap and deletes it; PID 2 must still remain under PID 0's CDT
    let frame1_moved = ipc.cap_move_for(1, frame1, 40).unwrap();
    ipc.cap_delete_for(1, frame1_moved).unwrap();
    assert_eq!(
        ipc.validate_frame_for(2, frame2, Rights::READ),
        Ok(frame_phys)
    );
    assert!(ipc.ipc_send_for(2, ep2, 0x99).is_ok());
    assert_eq!(
        ipc.ipc_recv_for(0, ep0),
        Ok(IpcMessage {
            badge: 0x11,
            payload: 0x99
        })
    );

    // PID 0 revokes Untyped -> cascades across PID 1 and PID 2, collects frame
    let mut collected = [None; 8];
    let (revoked_caps, frame_count) = ipc
        .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut collected)
        .unwrap();
    assert!(revoked_caps >= 4);
    assert!(frame_count >= 1);
    assert_eq!(collected[0], Some(frame_phys));

    // Drain mappings and reclaim physical frame back into UntypedInventory
    let mut drained = [None; 4];
    assert_eq!(tracker.drain_for_phys(frame_phys, &mut drained), 2);
    assert_eq!(tracker.count(), 0);
    assert!(inv.reclaim_frame(PhysFrame::from_aligned(frame_phys).unwrap()));

    // PID 2's caps are now revoked
    assert_eq!(
        ipc.validate_frame_for(2, frame2, Rights::READ),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        ipc.ipc_send_for(2, ep2, 0xAA),
        Err(SysError::InvalidCapability)
    );
}

#[test]
fn t3_memory_sched_ipc_client_server_frame_pipeline() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x4000_0000, PAGE_SIZE * 4));
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    let mut sched = Scheduler::<8>::new();
    let client = sched.spawn(16).unwrap(); // slot 0
    let server = sched.spawn(20).unwrap(); // slot 1

    // Server runs first, blocks waiting on empty endpoint
    assert_eq!(sched.schedule_next(), Some(server));
    assert_eq!(ipc.ipc_recv_for(0, ep), Err(SysError::WouldBlock));
    sched.block_slot(1).unwrap();

    // Client runs, sends request, blocks waiting for notification
    assert_eq!(sched.schedule_next(), Some(client));
    ipc.ipc_send_for(0, ep, 0xCAFE).unwrap();
    sched.wake_slot(1).unwrap();
    sched.block_slot(0).unwrap();

    // Server wakes, receives request, allocates a frame, signals completion
    assert_eq!(sched.schedule_next(), Some(server));
    let req = ipc.ipc_recv_for(0, ep).unwrap();
    assert_eq!(req.payload, 0xCAFE);
    let resp_frame = inv.retype_frame().unwrap();
    ipc.notify_signal_for(0, notif, resp_frame.start_addr().raw())
        .unwrap();
    sched.wake_slot(0).unwrap();
    sched.block_slot(1).unwrap();

    // Client wakes and polls notification containing the allocated frame address
    assert_eq!(sched.schedule_next(), Some(client));
    assert_eq!(
        ipc.notify_poll_for(0, notif),
        Ok(resp_frame.start_addr().raw())
    );
}

#[test]
fn t3_elf_memory_cspace_load_map_and_revoke_segments() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_X,
                p_vaddr: 0x40_0000,
                p_memsz: PAGE_SIZE,
                data: vec![0xD5; 16],
            },
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_vaddr: 0x41_0000,
                p_memsz: PAGE_SIZE * 2,
                data: vec![0x42; 32],
            },
        ],
    );
    let parsed = parse_elf64(&elf).unwrap();
    assert_eq!(parsed.segment_count(), 2);

    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x5000_0000, PAGE_SIZE * 8));
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    let mut tracker = FrameMappingTracker::<16>::new();
    let vspace_root = PhysAddr::new_aligned(0x1000_0000).unwrap();

    // Retype and map 1 page per 4 KiB of each PT_LOAD segment
    let mut slot = 20usize;
    for seg in parsed.segments() {
        let pages = seg.mem_size.div_ceil(PAGE_SIZE);
        for p in 0..pages {
            let fcap = ipc
                .untyped_retype_for(
                    0,
                    CapId::BOOTSTRAP_UNTYPED,
                    ObjectType::Frame,
                    slot,
                    &mut inv,
                )
                .unwrap();
            let phys = ipc.validate_frame_for(0, fcap, Rights::READ).unwrap();
            let va = VirtAddr::new_page_aligned(seg.vaddr + p * PAGE_SIZE).unwrap();
            tracker.record(vspace_root, va, phys).unwrap();
            slot += 1;
        }
    }
    assert_eq!(tracker.count(), 3);

    // Revoke Untyped and tear down all mapped segment frames
    let mut collected = [None; 8];
    let (revoked, nframes) = ipc
        .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut collected)
        .unwrap();
    assert_eq!(revoked, 3);
    assert_eq!(nframes, 3);
    for phys in collected.iter().take(nframes).flatten() {
        let mut out = [None; 2];
        assert_eq!(tracker.drain_for_phys(*phys, &mut out), 1);
    }
    assert_eq!(tracker.count(), 0);
}

#[test]
fn t3_ring_ipc_notification_batch_producer_consumer() {
    let ring = SpscRing::<32>::new();
    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();

    let mut sent_total = 0u64;
    let mut recv_total = 0u64;
    for batch in 0..10u64 {
        let payload: [u64; 16] = std::array::from_fn(|i| batch * 100 + i as u64);
        let pushed = ring.try_push_slice(&payload);
        assert_eq!(pushed, 16);
        sent_total += pushed as u64;
        // Single coalesced notification per 16-word batch (minimizing IPC syscalls)
        ipc.notify_signal_for(0, notif, 1 << (batch % 8)).unwrap();

        let bits = ipc.notify_poll_for(0, notif).unwrap();
        assert_ne!(bits, 0);
        let mut out = [0u64; 16];
        let popped = ring.try_pop_slice(&mut out);
        assert_eq!(popped, 16);
        assert_eq!(out, payload);
        recv_total += popped as u64;
    }
    assert_eq!(sent_total, 160);
    assert_eq!(recv_total, 160);
    assert_eq!(ipc.stats().notify_signals, 10);
}

#[test]
fn t3_shell_caos_snapshot_gc_recovery_cycle() {
    let mut store = ObjectStore::new();
    // Fill to MAX_OBJECTS with unreferenced blobs, hit NoSpace, recover via GC
    let mut last_hash = None;
    for i in 0..(MAX_OBJECTS - 2) {
        let s = format!("ephemeral-blob-{i}");
        last_hash = Some(store.put(s.as_bytes()).unwrap());
    }
    assert_eq!(store.put(b"one-too-many"), Err(StoreError::NoSpace));

    // Anchor only the last blob, then GC the rest
    let keeper = last_hash.unwrap();
    store.set_ref("@keeper", keeper).unwrap();
    let freed = store.gc();
    assert_eq!(freed, MAX_OBJECTS - 3);

    // Store is usable again and round-trips cleanly through snapshot
    let fresh = store.put(b"post-gc-blob").unwrap();
    store.set_ref("@fresh", fresh).unwrap();
    let mut buf = [0u8; 2048];
    let n = store.encode_snapshot(&mut buf).unwrap();
    let restored = ObjectStore::decode_snapshot(&buf[..n]).unwrap();
    assert_eq!(restored.get_any("@keeper").unwrap().0, keeper);
    assert_eq!(restored.get_any("@fresh").unwrap().1, b"post-gc-blob");
}

#[test]
fn t3_shell_host_ipc_error_propagation_and_fallback() {
    let mut host = MockShellHost::new();
    host.ipc_call_fn = Some(|_, _| Err(SysError::WouldBlock));
    let mut sh = Shell::new(host);
    let s1 = sh.eval_pipeline("ping 0x1234");
    assert!(s1.is_empty());

    sh.host_mut().ipc_call_fn = Some(|_, _| Err(SysError::InvalidCapability));
    let s2 = sh.eval_pipeline("ping 0x5678");
    assert!(s2.is_empty());

    // Recover when host IPC succeeds again
    sh.host_mut().ipc_call_fn = Some(|_, p| Ok((0x7, p + 1)));
    let s3 = sh.eval_pipeline("ping 0x10");
    assert_eq!(s3.len(), 2);
}

#[test]
fn t3_shell_interactive_repl_roundtrip_and_exit() {
    let mut host = MockShellHost::new();
    host.push_input_bytes(b"put \"repl-item\" | save @repl\nget @repl\nexit\n");
    let mut sh = Shell::new(host);

    let res = catch_unwind(AssertUnwindSafe(|| {
        sh.run_interactive();
    }));
    match res {
        Ok(_) => unreachable!("run_interactive returns !"),
        Err(payload) => {
            let sentinel = payload
                .downcast_ref::<ExitSentinel>()
                .expect("run_interactive must call host.exit(Success)");
            assert_eq!(sentinel.0, ShutdownStatus::Success);
        }
    }
    assert_eq!(sh.store().get_any("@repl").unwrap().1, b"repl-item");
    assert!(sh.host().output.contains("repl-item"));
}

#[test]
fn t3_sched_smp_ipc_worker_fault_isolation() {
    let mut ipc = KernelIpcState::new();
    let (_, _, fault_notif) = ipc.init_bootstrap_caps(None).unwrap();
    ipc.init_worker_bootstrap_caps(1).unwrap();
    ipc.init_worker_bootstrap_caps(2).unwrap();

    let mut smp = SmpScheduler::<2, 8>::new(2);
    let (c1, _t1) = smp.spawn_balanced(16).unwrap();
    let (c2, t2) = smp.spawn_balanced(16).unwrap();
    assert_ne!(c1, c2);

    // Worker 1 faults: supervisor receives fault notification and exits worker 1's thread
    ipc.notify_signal_for(0, fault_notif, 1u64 << 1).unwrap();
    assert_eq!(ipc.notify_poll_for(0, fault_notif), Ok(1u64 << 1));
    let cpu1 = smp.cpu_mut(c1).unwrap();
    cpu1.exit_slot(0).unwrap();
    assert_eq!(cpu1.tcb(0).unwrap().state, ThreadState::Exited);

    // Worker 2 remains runnable and unaffected
    let running2 = smp.schedule_or_steal(c2).unwrap();
    assert_eq!(running2, t2);
}

#[test]
fn t3_caos_shell_history_wraparound_and_pipeline_consistency() {
    let mut sh = Shell::new(MockShellHost::new());
    for i in 0..100usize {
        let line = format!("cmd-{i:03}");
        sh.record_history(&line);
    }
    sh.host_mut().clear_output();
    sh.exec_line("history");
    // Only the latest 8 entries (92..=99) are retained in the ring buffer
    assert!(sh.host().output.contains("cmd-099"));
    assert!(sh.host().output.contains("cmd-092"));
    assert!(!sh.host().output.contains("cmd-000"));

    // Pipelines still operate cleanly after history wraparound
    let count_s = sh.eval_pipeline("objects | count");
    assert!(matches!(count_s.first(), Some(Record::Count(2))));
}

#[test]
fn t3_bench_reproducibility_and_footprint_sanity() {
    let r1 = run_newos_bench(&[]);
    let r2 = run_newos_bench(&[]);
    assert!(r1.status.success() && r2.status.success());

    let m1 = parse_metric_lines(&r1.stdout);
    let m2 = parse_metric_lines(&r2.stdout);
    assert_eq!(m1.len(), m2.len());

    // All integer IPC count & footprint metrics must be 100% deterministic across runs
    for ((n1, v1, u1), (n2, v2, u2)) in m1.iter().zip(m2.iter()) {
        assert_eq!(n1, n2);
        assert_eq!(u1, u2);
        if u1 == "syscalls" || u1 == "syscalls/op" || u1 == "bytes" {
            assert_eq!(v1, v2, "deterministic metric {n1} drifted between runs");
        }
    }

    // Sanity check in-process struct sizes
    assert!(std::mem::size_of::<RecordStream>() > 0);
    assert!(std::mem::size_of::<Shell<MockShellHost>>() > 0);
}
