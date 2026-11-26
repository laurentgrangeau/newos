//! Tier 5 — Adversarial Regression & Edge-Path Tests (M4 Stage C).
//!
//! Covers all 5 confirmed Tier-5 adversarial bugs plus the Tier-5 E2E edge-path specs
//! (`BufferedWriter`, `Shell::read_line`, and `ObjectStore` full-dedup / snapshot boundaries).

use core::fmt::{self, Write};
use std::collections::VecDeque;

use newos_abi::{CapId, ObjectType, Rights, SysError};
use newos_kernel_core::cspace::{CapObject, Capability};
use newos_kernel_core::ipc::KernelIpcState;
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_SIZE, PhysAddr, UntypedInventory, VirtAddr,
};
use newos_kernel_core::sched::{Scheduler, ThreadState};
use newos_shell_core::caos::{
    MAX_BLOB_SIZE, MAX_OBJECTS, MAX_REFS, ObjHash, ObjectStore, StoreError,
};
use newos_shell_core::shell::{
    BufferedWriter, ExecOutcome, LINE_BUF_SIZE, Shell, ShellHost, SysInfo,
};

use crate::helpers::MockShellHost;

fn count_refs(store: &ObjectStore) -> usize {
    let mut n = 0usize;
    store.for_each_ref(|_| n += 1);
    n
}

// ============================================================================
// 1. Kernel Frame Reclaim Guards (Live Frame Caps & Shared Mappings)
// ============================================================================

#[test]
fn t5_kernel_frame_reclaim_guards_live_cap_and_shared_mapping() {
    let mut ipc = KernelIpcState::new();
    let _ = ipc.init_bootstrap_caps(None).expect("bootstrap caps");
    let _ = ipc.init_worker_pd_bootstrap_caps(1).expect("worker 1 caps");
    let (_, w1_cnode) = ipc
        .register_child_caps_in_root(1)
        .expect("register worker 1");
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x5000_0000, PAGE_SIZE * 4));

    // Retype a frame from BOOTSTRAP_UNTYPED, copy locally, and grant to PID 1.
    let frame_root = ipc
        .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
        .expect("retype frame");
    let phys = ipc
        .validate_frame_for(0, frame_root, Rights::READ)
        .expect("validate frame");
    assert!(ipc.has_live_frame_cap(phys));

    let frame_copy = ipc.cap_copy_for(0, frame_root, 0).expect("copy frame");
    let _frame_worker = ipc
        .cap_grant_between_checked(
            0,
            w1_cnode,
            frame_copy,
            Rights::READ.union(Rights::WRITE),
            None,
            2,
        )
        .expect("grant frame to PID 1");

    // 1a. CapRevoke(frame_root) revokes descendants while frame_root survives -> can_reclaim MUST be false.
    let mut events = Vec::new();
    let revoked = ipc
        .cap_revoke_for_with_frame_reclaim_cb(0, frame_root, |p, can_reclaim| {
            events.push((p, can_reclaim));
        })
        .expect("revoke frame_root");
    assert_eq!(revoked, 2);
    assert_eq!(events.len(), 2);
    assert!(
        events.iter().all(|&(p, can)| p == phys && !can),
        "frame must never be marked reclaimable while root Frame cap survives: {events:?}"
    );
    assert!(ipc.has_live_frame_cap(phys));

    // 1b. Re-grant to PID 1 and CapRevoke(BOOTSTRAP_UNTYPED) -> can_reclaim is true ONLY once last cap is gone.
    let _frame_worker2 = ipc
        .cap_grant_between_checked(
            0,
            w1_cnode,
            frame_root,
            Rights::READ.union(Rights::WRITE),
            None,
            2,
        )
        .expect("re-grant frame to PID 1");
    events.clear();
    let revoked_all = ipc
        .cap_revoke_for_with_frame_reclaim_cb(0, CapId::BOOTSTRAP_UNTYPED, |p, can_reclaim| {
            events.push((p, can_reclaim));
        })
        .expect("revoke untyped");
    assert_eq!(revoked_all, 2);
    assert_eq!(events, vec![(phys, false), (phys, true)]);
    assert!(!ipc.has_live_frame_cap(phys));

    // 1c. CapDelete(frame_cap) drops has_live_frame_cap to false only when no alias cap remains.
    let frame2 = ipc
        .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
        .expect("retype frame2");
    let phys2 = ipc
        .validate_frame_for(0, frame2, Rights::READ)
        .expect("validate frame2");
    let frame2_alias = ipc.cap_copy_for(0, frame2, 0).expect("copy frame2");
    assert!(ipc.has_live_frame_cap(phys2));
    ipc.cap_delete_for(0, frame2).expect("delete frame2");
    assert!(ipc.has_live_frame_cap(phys2));
    ipc.cap_delete_for(0, frame2_alias)
        .expect("delete frame2_alias");
    assert!(!ipc.has_live_frame_cap(phys2));

    // 1d. FrameMappingTracker::has_mapping_for_phys across shared mappings.
    let mut tracker = FrameMappingTracker::<16>::new();
    let vs0 = PhysAddr::new(0x10_0000);
    let vs1 = PhysAddr::new(0x20_0000);
    let va0 = VirtAddr::new_page_aligned(0x40_0000).expect("va0");
    let va1 = VirtAddr::new_page_aligned(0x40_1000).expect("va1");
    assert!(!tracker.has_mapping_for_phys(phys));

    tracker.record(vs0, va0, phys).expect("record mapping 0");
    tracker.record(vs1, va1, phys).expect("record mapping 1");
    assert!(tracker.has_mapping_for_phys(phys));
    assert!(!tracker.has_mapping_for_phys(phys2));

    // Removing one shared mapping must leave has_mapping_for_phys == true.
    assert_eq!(tracker.remove(vs0, va0), Some(phys));
    assert!(tracker.has_mapping_for_phys(phys));

    // Removing the final mapping drops has_mapping_for_phys to false.
    assert_eq!(tracker.remove(vs1, va1), Some(phys));
    assert!(!tracker.has_mapping_for_phys(phys));
}

// ============================================================================
// 2. Cross-Process CDT Return-to-Origin Move / Delete / Revoke
// ============================================================================

#[test]
fn t5_kernel_cdt_return_to_origin_move_delete_revoke() {
    let mut ipc = KernelIpcState::new();
    let _ = ipc.init_bootstrap_caps(None).expect("bootstrap caps");
    let _ = ipc.init_worker_pd_bootstrap_caps(1).expect("worker 1 caps");
    let (_, w1_cnode) = ipc
        .register_child_caps_in_root(1)
        .expect("register worker 1");

    // Give PID 1 a CNode cap to PID 0 so PID 1 can grant back to PID 0.
    let cnode0_in_pid1 = ipc
        .cspace_mut(1)
        .expect("pid 1 cspace")
        .insert_root_at(20, Capability::new(CapObject::CNode { id: 0 }, Rights::ALL))
        .expect("insert cnode0 cap in pid 1");

    // Scenario A: PID 0 -> PID 1 -> PID 0 return grant, delete intermediate g1,
    // move root in PID 0, and revoke moved root (must revoke g2).
    let notif = ipc
        .cspace_mut(0)
        .expect("pid 0 cspace")
        .insert_root_at(
            30,
            Capability::new(CapObject::Notification { id: 5 }, Rights::ALL),
        )
        .expect("insert notif in pid 0");
    let g1 = ipc
        .cap_grant_between_checked(0, w1_cnode, notif, Rights::ALL, None, 2)
        .expect("grant PID 0 -> PID 1");
    let g2 = ipc
        .cap_grant_between_checked(1, cnode0_in_pid1, g1, Rights::READ, None, 2)
        .expect("return grant PID 1 -> PID 0");

    ipc.cap_delete_for(1, g1).expect("delete intermediate g1");
    let notif_moved = ipc
        .cap_move_for(0, notif, 40)
        .expect("move root notif to slot 40");

    // Reusing old slot 30 for an unrelated cap and revoking it must NOT affect g2.
    let unrelated_a = ipc
        .cspace_mut(0)
        .expect("pid 0 cspace")
        .insert_root_at(
            30,
            Capability::new(CapObject::Endpoint { id: 10 }, Rights::ALL),
        )
        .expect("insert unrelated cap in slot 30");
    assert_eq!(ipc.cap_revoke_for(0, unrelated_a), Ok(0));
    assert!(ipc.cspace(0).unwrap().lookup(g2, Rights::READ).is_ok());

    // Revoking moved root MUST transitively revoke return-to-origin g2.
    assert_eq!(ipc.cap_revoke_for(0, notif_moved), Ok(1));
    assert_eq!(
        ipc.cspace(0).unwrap().lookup(g2, Rights::READ),
        Err(SysError::InvalidCapability)
    );

    // Scenario B: Return-to-origin + delete g1 + delete root + reuse slot for unrelated cap + revoke.
    ipc.cap_delete_for(0, unrelated_a).expect("free slot 30");
    let notif2 = ipc
        .cspace_mut(0)
        .expect("pid 0 cspace")
        .insert_root_at(
            30,
            Capability::new(CapObject::Notification { id: 6 }, Rights::ALL),
        )
        .expect("insert notif2 in slot 30");
    let g1_b = ipc
        .cap_grant_between_checked(0, w1_cnode, notif2, Rights::ALL, None, 2)
        .expect("grant notif2 PID 0 -> PID 1");
    let g2_b = ipc
        .cap_grant_between_checked(1, cnode0_in_pid1, g1_b, Rights::READ, None, 2)
        .expect("return grant notif2 PID 1 -> PID 0");

    ipc.cap_delete_for(1, g1_b).expect("delete g1_b");
    ipc.cap_delete_for(0, notif2).expect("delete root notif2");

    let unrelated_b = ipc
        .cspace_mut(0)
        .expect("pid 0 cspace")
        .insert_root_at(
            30,
            Capability::new(CapObject::Endpoint { id: 11 }, Rights::ALL),
        )
        .expect("reuse slot 30 for unrelated cap");
    assert_eq!(ipc.cap_revoke_for(0, unrelated_b), Ok(0));
    assert!(
        ipc.cspace(0).unwrap().lookup(g2_b, Rights::READ).is_ok(),
        "revoking unrelated cap in reused slot must not destroy orphaned return-to-origin cap"
    );
}

// ============================================================================
// 3. Scheduler::select_slot Rejects Empty & Exited Slots
// ============================================================================

#[test]
fn t5_kernel_sched_select_slot_rejects_empty_and_exited() {
    let mut sched = Scheduler::<8>::new();
    let t0 = sched.spawn(10).expect("spawn t0");
    let t1 = sched.spawn(10).expect("spawn t1");
    assert_eq!(sched.schedule_next(), Some(t0));
    assert_eq!(sched.current_slot(), Some(0));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);
    assert_eq!(sched.ready_count(), 1);

    // Calling select_slot on an empty slot (slot 3) or out-of-bounds slot (slot 99)
    // must be a complete no-op: current remains slot 0 in Running state and on_timer_tick works.
    sched.select_slot(3);
    assert_eq!(sched.current_slot(), Some(0));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);
    assert_eq!(sched.ready_count(), 1);

    sched.select_slot(99);
    assert_eq!(sched.current_slot(), Some(0));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);

    // Timer tick preemption still works cleanly after rejected select_slot.
    let mut preempted = false;
    for _ in 0..16 {
        if sched.on_timer_tick() {
            preempted = true;
            break;
        }
    }
    assert!(preempted, "timer tick should still preempt running thread");

    // Exiting slot 1 and calling select_slot(1) must NOT resurrect the Exited thread.
    sched.exit_slot(1).expect("exit slot 1");
    assert_eq!(sched.tcb(1).unwrap().id, t1);
    assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Exited);

    sched.select_slot(1);
    assert_eq!(sched.current_slot(), Some(0));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);
    assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Exited);
}

// ============================================================================
// 4. Shell Pipeline Syntax Errors in Stage >= 1 Cause Zero Side Effects
// ============================================================================

#[test]
fn t5_shell_syntax_error_in_later_stage_causes_no_side_effects() {
    let mut sh = Shell::new(MockShellHost::new());
    let base_objs = sh.store().object_count();
    let bad_cmds = [
        r#"put "leak1" |"#,
        r#"put "leak2" | | count"#,
        r#"put "leak3" | where "unclosed"#,
        r#"put "leak4" | first 1 | first 1 | first 1 | first 1 | first 1 | count"#,
        r#"put "leak5" | where a b c d e f g h i j k l"#,
        r#"put "leak6" | save @leakref |"#,
        "ping 0x10 |",
    ];

    for cmd in bad_cmds {
        sh.host_mut().clear_output();
        assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
        assert!(
            sh.host().output.contains("newos-shell-pd:"),
            "expected parse diagnostic for `{cmd}`, got {:?}",
            sh.host().output
        );
        assert_eq!(
            sh.store().object_count(),
            base_objs,
            "CAOS object count mutated by invalid pipeline `{cmd}`"
        );
        assert!(
            sh.store().get_any("@leakref").is_err(),
            "@leakref should not be bound by invalid pipeline `{cmd}`"
        );
        assert_eq!(
            sh.host().ipc_call_calls,
            0,
            "ipc_call should not fire for invalid pipeline `{cmd}`"
        );
    }
}

// ============================================================================
// 5. Failed Transform Clears eval_pipeline / eval_pipeline_ref Stream
// ============================================================================

#[test]
fn t5_shell_failed_transform_clears_eval_pipeline_stream() {
    let mut sh = Shell::new(MockShellHost::new());
    for cmd in [
        "objects | bogus_stage",
        "domains | save @x",
        r#"put "abc" | save @motd"#,
    ] {
        let owned = sh.eval_pipeline(cmd);
        assert!(
            owned.is_empty(),
            "eval_pipeline(`{cmd}`) returned {} stale records",
            owned.len()
        );
        let borrowed = sh.eval_pipeline_ref(cmd);
        assert!(
            borrowed.is_empty(),
            "eval_pipeline_ref(`{cmd}`) returned {} stale records",
            borrowed.len()
        );
    }
}

// ============================================================================
// 6. BufferedWriter, read_line, and ObjectStore Full-Dedup / Snapshot Edges
// ============================================================================

#[derive(Debug)]
struct RecordingWriter {
    out: String,
    calls: usize,
    fail_on_call: Option<usize>,
}

impl RecordingWriter {
    const fn new(fail_on_call: Option<usize>) -> Self {
        Self {
            out: String::new(),
            calls: 0,
            fail_on_call,
        }
    }
}

impl Write for RecordingWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.calls += 1;
        if self.fail_on_call == Some(self.calls) {
            return Err(fmt::Error);
        }
        self.out.push_str(s);
        Ok(())
    }
}

#[derive(Debug)]
struct EdgeReadLineHost {
    reads: VecDeque<Result<u8, SysError>>,
    yield_res: Result<u64, SysError>,
    yield_calls: usize,
    writes: Vec<String>,
    bg_log: Option<(u64, Vec<u8>, usize)>,
}

impl EdgeReadLineHost {
    fn new(reads: &[Result<u8, SysError>], yield_res: Result<u64, SysError>) -> Self {
        Self {
            reads: reads.iter().copied().collect(),
            yield_res,
            yield_calls: 0,
            writes: Vec::new(),
            bg_log: None,
        }
    }
}

impl ShellHost for EdgeReadLineHost {
    fn write_debug(&mut self, s: &str) {
        self.writes.push(s.to_owned());
    }

    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            online_cpus: 1,
            domain_count: 1,
            interactive_shell: true,
        }
    }

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        self.reads.pop_front().unwrap_or(Err(SysError::WouldBlock))
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        self.yield_calls += 1;
        self.yield_res
    }

    fn poll_background_log(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        let (badge, payload, reported_len) = self.bg_log.take()?;
        let copy_len = payload.len().min(out.len());
        out[..copy_len].copy_from_slice(&payload[..copy_len]);
        Some((badge, reported_len))
    }
}

fn check_buffered_writer_edges() {
    {
        let mut inner = RecordingWriter::new(None);
        {
            let mut bw = BufferedWriter::<0, _>::new(&mut inner);
            bw.write_str("abc🦀").expect("N=0 write");
        }
        assert_eq!(inner.out, "abc🦀");
        assert!(inner.calls >= 1);
    }
    {
        let mut inner = RecordingWriter::new(None);
        {
            let mut bw = BufferedWriter::<1, _>::new(&mut inner);
            bw.write_str("λ€🦀x").expect("N=1 write");
        }
        assert_eq!(inner.out, "λ€🦀x");
    }
    {
        // >1024B single write with multi-byte UTF-8 straddling byte 1024.
        let mut big = "a".repeat(1022);
        big.push('🦀'); // bytes 1022..1026 straddling 1024
        big.push_str(&"€".repeat(400)); // +1200 bytes (> 2048 total)
        let mut inner = RecordingWriter::new(None);
        {
            let mut bw = BufferedWriter::<1024, _>::new(&mut inner);
            bw.write_str(&big).expect("N=1024 >1024B UTF-8 write");
            bw.flush();
        }
        assert_eq!(inner.out, big);
        assert!(inner.calls >= 2);
    }
    {
        // Inner Write::write_str error propagation for N=0 and chunked N=8 writes.
        let mut inner0 = RecordingWriter::new(Some(1));
        let mut bw0 = BufferedWriter::<0, _>::new(&mut inner0);
        assert!(bw0.write_str("fail").is_err());

        let mut inner8 = RecordingWriter::new(Some(1));
        let mut bw8 = BufferedWriter::<8, _>::new(&mut inner8);
        assert!(bw8.write_str("0123456789").is_err());
    }
}

fn check_readline_edges() {
    // B1: Fatal yield_now() error on WouldBlock breaks cleanly after 1 yield.
    {
        let host = EdgeReadLineHost::new(&[Err(SysError::WouldBlock)], Err(SysError::Unsupported));
        let mut sh = Shell::new(host);
        let mut buf = [0u8; LINE_BUF_SIZE];
        let n = sh.read_line(&mut buf);
        assert_eq!(n, 0);
        assert_eq!(sh.host().yield_calls, 1);
    }
    // B2: Exact LINE_BUF_SIZE (128B) saturation + extra ignored byte + Ctrl-L + backspace + replace.
    {
        let mut inputs = Vec::new();
        for _ in 0..LINE_BUF_SIZE {
            inputs.push(Ok(b'x'));
        }
        inputs.push(Ok(b'Y')); // must be ignored (buffer full)
        inputs.push(Ok(0x0C)); // Ctrl-L redraw
        inputs.push(Ok(0x7F)); // Backspace removes last 'x'
        inputs.push(Ok(b'Z')); // replaces last byte -> 127*'x' + 'Z'
        inputs.push(Ok(b'\r'));
        let host = EdgeReadLineHost::new(&inputs, Ok(0));
        let mut sh = Shell::new(host);
        let mut buf = [0u8; LINE_BUF_SIZE];
        let n = sh.read_line(&mut buf);
        assert_eq!(n, LINE_BUF_SIZE);
        assert!(buf[..LINE_BUF_SIZE - 1].iter().all(|&b| b == b'x'));
        assert_eq!(buf[LINE_BUF_SIZE - 1], b'Z');
    }
    // B3: High bytes 0x80..=0xFF ignored cleanly, plus Ctrl-C mid-line cancels input.
    {
        let mut inputs = vec![Ok(b'a'), Ok(b'b')];
        for b in 0x80u8..=0xFFu8 {
            inputs.push(Ok(b));
        }
        inputs.push(Ok(0x03)); // Ctrl-C cancels line -> returns 0
        let host = EdgeReadLineHost::new(&inputs, Ok(0));
        let mut sh = Shell::new(host);
        let mut buf = [0u8; LINE_BUF_SIZE];
        let n = sh.read_line(&mut buf);
        assert_eq!(n, 0);
    }
    // B4: Invalid UTF-8 & oversized raw_n from poll_background_log handled without panic.
    {
        let mut host = EdgeReadLineHost::new(&[Ok(b'o'), Ok(b'k'), Ok(b'\n')], Ok(0));
        host.bg_log = Some((7, vec![0xFF, 0xFE, b'b', b'a', b'd'], 999));
        let mut sh = Shell::new(host);
        let mut buf = [0u8; LINE_BUF_SIZE];
        let n = sh.read_line(&mut buf);
        assert_eq!(&buf[..n], b"ok");
    }
}

fn check_caos_full_dedup_edges() {
    let mut store = ObjectStore::new();
    let existing_count = store.object_count();
    let mut first_new_hash = None;
    let mut first_new_payload = [0u8; MAX_BLOB_SIZE];
    for i in existing_count..MAX_OBJECTS {
        let tag = u8::try_from(i).expect("MAX_OBJECTS <= 255");
        let mut blob = [tag; MAX_BLOB_SIZE];
        blob[1] = 0xA5;
        let h = store.put(&blob).expect("fill object slot");
        if first_new_hash.is_none() {
            first_new_hash = Some(h);
            first_new_payload = blob;
        }
    }
    assert_eq!(store.object_count(), MAX_OBJECTS);

    // Deduplicating an already-present blob at 24/24 full MUST succeed and return identical hash.
    let dedup_hash = store
        .put(&first_new_payload)
        .expect("dedup at 24/24 full must succeed");
    assert_eq!(dedup_hash, first_new_hash.unwrap());
    assert_eq!(store.object_count(), MAX_OBJECTS);

    // A brand-new blob at 24/24 full MUST fail with NoSpace.
    assert_eq!(
        store.put(b"brand-new-overflow-blob"),
        Err(StoreError::NoSpace)
    );

    // Fill all remaining refs to MAX_REFS and encode max-capacity snapshot.
    let target_hash = first_new_hash.unwrap();
    let start_refs = count_refs(&store);
    for i in start_refs..MAX_REFS {
        let name = format!("r{i}");
        store.set_ref(&name, target_hash).expect("fill ref slot");
    }
    assert_eq!(count_refs(&store), MAX_REFS);

    let mut snap = [0u8; 4096];
    let written = store
        .encode_snapshot(&mut snap)
        .expect("encode max-capacity snapshot");
    assert!(written > 0 && written <= snap.len());
    // Exact boundary: buffer of `written - 1` bytes MUST return NoSpace.
    assert_eq!(
        store.encode_snapshot(&mut snap[..written - 1]),
        Err(StoreError::NoSpace)
    );

    let decoded = ObjectStore::decode_snapshot(&snap[..written]).expect("decode max snapshot");
    assert_eq!(decoded.object_count(), MAX_OBJECTS);
    assert_eq!(count_refs(&decoded), MAX_REFS);

    // Empty 0-object / 0-ref snapshot (16-byte header + checksum) decodes cleanly and gc() returns 0.
    let mut empty_snap = [0u8; 16];
    empty_snap[0..8].copy_from_slice(&[b'C', b'A', b'O', b'S', 1, 0, 0, 0]);
    let csum = ObjHash::hash_bytes(&empty_snap[0..8]).0.to_le_bytes();
    empty_snap[8..16].copy_from_slice(&csum);
    let mut empty_store =
        ObjectStore::decode_snapshot(&empty_snap).expect("decode 0-object/0-ref empty snapshot");
    assert_eq!(empty_store.object_count(), 0);
    assert_eq!(count_refs(&empty_store), 0);
    assert_eq!(empty_store.gc(), 0);
}

#[test]
fn t5_shell_buffered_writer_readline_and_caos_full_dedup_edges() {
    check_buffered_writer_edges();
    check_readline_edges();
    check_caos_full_dedup_edges();
}
