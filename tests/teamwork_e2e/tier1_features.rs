use std::fmt::Write as _;

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, Rights, ShutdownStatus, SysError, SyscallNumber};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::{MAX_LOAD_SEGMENTS, parse_elf64};
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{
    FrameMappingTracker, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory, VirtAddr,
};
use newos_kernel_core::sched::{DEFAULT_TIME_SLICE, Scheduler, SmpScheduler, ThreadState};
use newos_shell_core::caos::{ObjHash, ObjectStore, StoreError};
use newos_shell_core::shell::{BufferedWriter, ExecOutcome, Record, RecordStream, Shell};

use crate::helpers::{
    DefaultIpcFallbackHost, ElfSegSpec, MockShellHost, PF_R, PF_W, PF_X, PT_LOAD, PT_NOTE,
    build_elf64, parse_metric_lines, run_newos_bench,
};

// ============================================================================
// Area 1: ABI & Lock-Free SpscRing (6 tests)
// ============================================================================

#[test]
fn t1_abi_capid_constants_and_roundtrip() {
    assert!(CapId::NULL.is_null());
    assert_eq!(CapId::NULL.raw(), 0);

    let custom = CapId::new(0x0001_0000_0000_002A);
    assert!(!custom.is_null());
    assert_eq!(custom.raw(), 0x0001_0000_0000_002A);

    let bootstraps = [
        CapId::BOOTSTRAP_NOTIF,
        CapId::BOOTSTRAP_EP,
        CapId::BOOTSTRAP_FAULT_NOTIF,
        CapId::BOOTSTRAP_NET_MMIO,
        CapId::BOOTSTRAP_CONSOLE,
        CapId::BOOTSTRAP_POWER,
        CapId::BOOTSTRAP_VSPACE,
        CapId::BOOTSTRAP_SELF_THREAD,
        CapId::BOOTSTRAP_SELF_CNODE,
        CapId::BOOTSTRAP_UNTYPED,
    ];
    for i in 0..bootstraps.len() {
        assert!(!bootstraps[i].is_null());
        for j in (i + 1)..bootstraps.len() {
            assert_ne!(bootstraps[i], bootstraps[j]);
        }
    }
}

#[test]
fn t1_abi_rights_lattice_operations() {
    let rw = Rights::READ.union(Rights::WRITE);
    assert!(rw.contains(Rights::READ));
    assert!(rw.contains(Rights::WRITE));
    assert!(!rw.contains(Rights::EXEC));
    assert!(!rw.contains(Rights::GRANT));
    assert!(!rw.contains(Rights::REVOKE));

    let atten = rw.attenuate(Rights::READ.union(Rights::EXEC));
    assert_eq!(atten, Rights::READ);
    assert!(Rights::ALL.contains(Rights::READ));
    assert!(Rights::ALL.contains(Rights::WRITE));
    assert!(Rights::ALL.contains(Rights::EXEC));
    assert!(Rights::ALL.contains(Rights::GRANT));
    assert!(Rights::ALL.contains(Rights::REVOKE));
    assert_eq!(Rights::NONE.bits(), 0);
}

#[test]
fn t1_abi_enum_from_u64_roundtrips() {
    for raw in 0u64..=12 {
        let obj = ObjectType::from_u64(raw).expect("valid ObjectType");
        assert_eq!(obj as u64, raw);
    }
    for raw in 1u64..=27 {
        let sc = SyscallNumber::from_u64(raw).expect("valid SyscallNumber");
        assert_eq!(sc as u64, raw);
    }
    for raw in 1u64..=7 {
        let err = SysError::from_u64(raw).expect("valid SysError");
        assert_eq!(err as u64, raw);
    }
}

#[test]
fn t1_ring_spsc_single_push_pop_fifo() {
    let ring = SpscRing::<8>::new();
    assert_eq!(ring.capacity(), 7);
    assert!(ring.is_empty());
    assert!(!ring.is_full());
    assert_eq!(ring.len(), 0);

    for i in 0..7u64 {
        assert_eq!(ring.try_push(100 + i), Ok(()));
    }
    assert!(ring.is_full());
    assert_eq!(ring.len(), 7);

    for i in 0..7u64 {
        assert_eq!(ring.try_pop(), Some(100 + i));
    }
    assert!(ring.is_empty());
    assert_eq!(ring.len(), 0);
}

#[test]
fn t1_ring_spsc_slice_transfer_wraparound() {
    let ring = SpscRing::<16>::new();
    // Advance head/tail near the end to force wraparound
    assert_eq!(ring.try_push_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), 10);
    let mut tmp = [0u64; 10];
    assert_eq!(ring.try_pop_slice(&mut tmp), 10);
    assert_eq!(tmp, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    let batch: Vec<u64> = (100..112).collect();
    assert_eq!(ring.try_push_slice(&batch), 12);
    let mut out = [0u64; 12];
    assert_eq!(ring.try_pop_slice(&mut out), 12);
    assert_eq!(&out[..], &batch[..]);
    assert!(ring.is_empty());
}

#[test]
fn t1_ring_spsc_alignment_default_and_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SpscRing<64>>();

    assert_eq!(std::mem::align_of::<SpscRing<64>>(), 64);
    let ring = SpscRing::<64>::default();
    assert_eq!(ring.capacity(), 63);
    assert!(ring.is_empty());
}

// ============================================================================
// Area 2: Kernel CSpace (`CNode` & CDT) (6 tests)
// ============================================================================

#[test]
fn t1_cspace_insert_root_lookup_and_occupied_count() {
    let mut cnode = CNode::<16>::new();
    assert_eq!(cnode.occupied_count(), 0);

    let c1 = cnode
        .insert_root(Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    let c2 = cnode
        .insert_root_at(
            5,
            Capability::new(CapObject::Endpoint { id: 3 }, Rights::READ),
        )
        .unwrap();
    assert_eq!(cnode.occupied_count(), 2);
    assert_eq!(cnode.slot_index(c2), Ok(5));

    let found1 = cnode.lookup(c1, Rights::READ.union(Rights::WRITE)).unwrap();
    assert_eq!(found1.object, CapObject::Console);
    let found2 = cnode.lookup(c2, Rights::READ).unwrap();
    assert_eq!(found2.object, CapObject::Endpoint { id: 3 });
}

#[test]
fn t1_cspace_mint_attenuation_badge_and_copy() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();
    let minted = cnode
        .mint(
            root,
            3,
            Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
            Some(0x77),
        )
        .unwrap();
    let cap = *cnode.lookup(minted, Rights::READ).unwrap();
    assert_eq!(cap.badge, 0x77);
    assert!(!cap.rights.contains(Rights::REVOKE));

    let copied = cnode.copy(minted, 4).unwrap();
    let cap_copy = cnode.lookup(copied, Rights::WRITE).unwrap();
    assert_eq!(cap_copy.badge, 0x77);
    assert_eq!(cap_copy.rights, cap.rights);
}

#[test]
fn t1_cspace_move_preserves_cdt_and_invalidates_old_id() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(
            CapObject::Notification { id: 2 },
            Rights::ALL,
        ))
        .unwrap();
    let child = cnode
        .mint(root, 3, Rights::READ.union(Rights::GRANT), None)
        .unwrap();
    let grand = cnode.mint(child, 4, Rights::READ, None).unwrap();

    let moved = cnode.move_cap(child, 7).unwrap();
    assert_eq!(
        cnode.lookup(child, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(moved, Rights::READ).is_ok());

    let revoked = cnode.revoke(root).unwrap();
    assert_eq!(revoked, 2);
    assert_eq!(
        cnode.lookup(moved, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(grand, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(root, Rights::ALL).is_ok());
}

#[test]
fn t1_cspace_delete_reparents_children_to_grandparent() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 4 }, Rights::ALL))
        .unwrap();
    let mid = cnode.mint(root, 3, Rights::ALL, None).unwrap();
    let leaf = cnode.mint(mid, 4, Rights::READ, None).unwrap();

    cnode.delete(mid).unwrap();
    assert_eq!(
        cnode.lookup(mid, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(leaf, Rights::READ).is_ok());

    let revoked = cnode.revoke(root).unwrap();
    assert_eq!(revoked, 1);
    assert_eq!(
        cnode.lookup(leaf, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
}

#[test]
fn t1_cspace_transitive_revoke_with_mask_callback() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 9 }, Rights::ALL))
        .unwrap();
    let c1 = cnode.mint(root, 2, Rights::ALL, None).unwrap();
    let c2 = cnode.mint(c1, 3, Rights::ALL, None).unwrap();
    let _c3 = cnode.mint(c2, 4, Rights::READ, None).unwrap();

    let mut seen = 0usize;
    let (revoked_count, root_slot, mask) = cnode
        .revoke_with_mask_cb(root, |cap| {
            assert_eq!(cap.object, CapObject::Endpoint { id: 9 });
            seen += 1;
        })
        .unwrap();

    assert_eq!(revoked_count, 3);
    assert_eq!(seen, 3);
    assert_eq!(mask, (1u64 << 2) | (1u64 << 3) | (1u64 << 4));
    assert_eq!(cnode.slot_index(root), Ok(root_slot));
}

#[test]
fn t1_cspace_retype_frame_and_bind_vspace_root() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x2000_0000, PAGE_SIZE * 4));

    let mut cnode = CNode::<16>::new();
    let ut = cnode
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::ALL,
        ))
        .unwrap();
    let f1 = cnode.retype_frame_from(ut, &mut inv).unwrap();
    let f2 = cnode.retype_frame_from_into(ut, 6, &mut inv).unwrap();
    assert_eq!(cnode.slot_index(f2), Ok(6));
    assert_ne!(
        cnode.lookup(f1, Rights::READ).unwrap().object,
        cnode.lookup(f2, Rights::READ).unwrap().object
    );

    let vs = cnode
        .insert_retyped_child(
            ut,
            7,
            CapObject::VSpace {
                root_phys: PhysAddr::new(0),
            },
        )
        .unwrap();
    let target_phys = PhysAddr::new_aligned(0x3000_0000).unwrap();
    cnode.bind_vspace_root(vs, target_phys).unwrap();
    assert_eq!(
        cnode.lookup(vs, Rights::READ).unwrap().object,
        CapObject::VSpace {
            root_phys: target_phys
        }
    );
}

// ============================================================================
// Area 3: Kernel IPC (`KernelIpcState` & Notifications) (6 tests)
// ============================================================================

#[test]
fn t1_ipc_init_bootstrap_caps_with_and_without_mmio() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, fault) = ipc
        .init_bootstrap_caps(Some((PhysAddr::new(0x0A00_0000), 0x1000)))
        .unwrap();
    assert_eq!(notif, CapId::BOOTSTRAP_NOTIF);
    assert_eq!(ep, CapId::BOOTSTRAP_EP);
    assert_eq!(fault, CapId::BOOTSTRAP_FAULT_NOTIF);
    assert!(
        ipc.validate_console_for(0, CapId::BOOTSTRAP_CONSOLE, Rights::WRITE)
            .is_ok()
    );
    assert!(
        ipc.validate_power_for(0, CapId::BOOTSTRAP_POWER, Rights::WRITE)
            .is_ok()
    );
    assert!(
        ipc.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, 0)
            .is_ok()
    );

    let mut ipc_no_mmio = KernelIpcState::new();
    ipc_no_mmio.init_bootstrap_caps(None).unwrap();
    assert_eq!(
        ipc_no_mmio.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, 0),
        Err(SysError::InvalidCapability)
    );
}

#[test]
fn t1_ipc_worker_bootstrap_isolation_and_child_caps() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    let (w_notif, w_ep) = ipc.init_worker_bootstrap_caps(1).unwrap();
    let (child_thread, child_cnode) = ipc.register_child_caps_in_root(1).unwrap();

    assert!(ipc.notify_poll_for(1, w_notif).is_ok());
    assert!(ipc.lookup_endpoint_for(1, w_ep, Rights::READ).is_ok());
    // Worker must NOT possess root-only privileges (no Console, PowerControl, VSpace)
    assert_eq!(
        ipc.validate_console_for(1, CapId::BOOTSTRAP_CONSOLE, Rights::WRITE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        ipc.validate_power_for(1, CapId::BOOTSTRAP_POWER, Rights::WRITE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        ipc.validate_vspace_for(1, CapId::BOOTSTRAP_VSPACE, Rights::WRITE),
        Err(SysError::InvalidCapability)
    );
    // Root holds handles to child's thread & cnode
    assert_eq!(
        ipc.validate_thread_for(0, child_thread, Rights::WRITE),
        Ok(1)
    );
    assert_eq!(ipc.validate_cnode_for(0, child_cnode, Rights::GRANT), Ok(1));
}

#[test]
fn t1_ipc_notification_coalescing_and_atomic_poll() {
    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();

    ipc.notify_signal_for(0, notif, 0b0001).unwrap();
    ipc.notify_signal_for(0, notif, 0b0100).unwrap();
    assert_eq!(ipc.notify_poll_for(0, notif), Ok(0b0101));
    // Polling clears the word
    assert_eq!(ipc.notify_poll_for(0, notif), Ok(0));

    // Badged notification cap stamps its badge bit automatically
    let badged = ipc
        .cap_mint_for(0, notif, 20, Rights::WRITE, Some(0b1000))
        .unwrap();
    ipc.notify_signal_for(0, badged, 0b0010).unwrap();
    assert_eq!(ipc.notify_poll_for(0, notif), Ok(0b1000));
}

#[test]
fn t1_ipc_send_recv_badge_and_stats_reset() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x3000_0000, PAGE_SIZE * 4));
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    let ep = ipc
        .untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Endpoint,
            20,
            &mut inv,
        )
        .unwrap();
    let badged = ipc
        .cap_mint_for(0, ep, 22, Rights::WRITE, Some(0xABCD))
        .unwrap();

    ipc.ipc_send_for(0, badged, 0x1122_3344).unwrap();
    let msg = ipc.ipc_recv_for(0, ep).unwrap();
    assert_eq!(
        msg,
        IpcMessage {
            badge: 0xABCD,
            payload: 0x1122_3344
        }
    );

    let stats = ipc.stats();
    assert_eq!(stats.ipc_sends, 1);
    assert_eq!(stats.ipc_recvs, 1);
    ipc.reset_stats();
    assert_eq!(ipc.stats().ipc_sends, 0);
    assert_eq!(ipc.stats().ipc_recvs, 0);
}

#[test]
fn t1_ipc_call_fastpath_and_badge_delivery() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x3000_0000, PAGE_SIZE * 4));
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    let ep = ipc
        .untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Endpoint,
            20,
            &mut inv,
        )
        .unwrap();
    let badged = ipc
        .cap_mint_for(0, ep, 23, Rights::READ.union(Rights::WRITE), Some(0x42))
        .unwrap();

    let reply = ipc
        .ipc_call_for(0, badged, 0x100, |req| IpcMessage {
            badge: req.badge,
            payload: req.payload + 1,
        })
        .unwrap();
    assert_eq!(
        reply,
        IpcMessage {
            badge: 0x42,
            payload: 0x101
        }
    );
    assert_eq!(ipc.stats().ipc_calls, 1);
}

#[test]
fn t1_ipc_cross_process_grant_and_frame_collecting_revoke() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x4000_0000, PAGE_SIZE * 4));

    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();
    ipc.init_worker_bootstrap_caps(1).unwrap();
    let (_, child_cnode) = ipc.register_child_caps_in_root(1).unwrap();

    let frame_cap = ipc
        .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 30, &mut inv)
        .unwrap();
    let expected_phys = ipc.validate_frame_for(0, frame_cap, Rights::READ).unwrap();

    let delegated = ipc
        .cap_grant_between(0, child_cnode, frame_cap, Rights::READ, None)
        .unwrap();
    assert_eq!(
        ipc.validate_frame_for(1, delegated, Rights::READ),
        Ok(expected_phys)
    );

    let mut collected = [None; 8];
    let (revoked_caps, collected_frames) = ipc
        .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut collected)
        .unwrap();
    assert!(revoked_caps >= 2);
    assert!(collected_frames >= 1);
    assert_eq!(collected[0], Some(expected_phys));
    assert_eq!(
        ipc.validate_frame_for(1, delegated, Rights::READ),
        Err(SysError::InvalidCapability)
    );
}

// ============================================================================
// Area 4: Kernel Memory (`UntypedInventory` & `FrameMappingTracker`) (6 tests)
// ============================================================================

#[test]
fn t1_memory_phys_addr_alignment_helpers() {
    let aligned = PhysAddr::new_aligned(0x1000_2000).unwrap();
    assert!(aligned.is_page_aligned());
    assert_eq!(aligned.raw(), 0x1000_2000);

    let unaligned = PhysAddr::new(0x1000_2123);
    assert!(!unaligned.is_page_aligned());
    assert_eq!(unaligned.align_down().raw(), 0x1000_2000);
    assert_eq!(unaligned.align_up().raw(), 0x1000_3000);
}

#[test]
fn t1_memory_virt_addr_canonical_halves() {
    let low = VirtAddr::new_page_aligned(0x0000_0000_0040_0000).unwrap();
    assert!(low.is_page_aligned());
    assert_eq!(low.raw(), 0x40_0000);

    let high = VirtAddr::new_canonical(0xFFFF_8000_0000_1234).unwrap();
    assert!(!high.is_page_aligned());
    assert_eq!(high.raw(), 0xFFFF_8000_0000_1234);
}

#[test]
fn t1_memory_untyped_inventory_multi_region_accounting() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x1000_0000, PAGE_SIZE * 2));
    assert!(inv.push_raw_region(0x2000_0000, PAGE_SIZE * 3));
    assert_eq!(inv.region_count(), 2);
    assert_eq!(inv.total_bytes(), PAGE_SIZE * 5);
    assert_eq!(inv.remaining_bytes(), PAGE_SIZE * 5);

    let f1 = inv.retype_frame().unwrap();
    let f2 = inv.retype_frame().unwrap();
    let f3 = inv.retype_frame().unwrap();
    assert_eq!(f1.start_addr().raw(), 0x1000_0000);
    assert_eq!(f2.start_addr().raw(), 0x1000_1000);
    assert_eq!(f3.start_addr().raw(), 0x2000_0000);
    assert_eq!(inv.retyped_frames(), 3);
    assert_eq!(inv.remaining_bytes(), PAGE_SIZE * 2);
}

#[test]
fn t1_memory_reclaim_frame_lifo_reuse() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x5000_0000, PAGE_SIZE * 2));

    let f1 = inv.retype_frame().unwrap();
    let f2 = inv.retype_frame().unwrap();
    let addr1 = f1.start_addr();
    let addr2 = f2.start_addr();

    assert!(inv.reclaim_frame(f1));
    assert!(inv.reclaim_frame(f2));
    assert_eq!(inv.reclaimed_count(), 2);

    // LIFO reuse: f2 comes back first, then f1
    let r1 = inv.retype_frame().unwrap();
    let r2 = inv.retype_frame().unwrap();
    assert_eq!(r1.start_addr(), addr2);
    assert_eq!(r2.start_addr(), addr1);
    assert_eq!(inv.reclaimed_count(), 0);
}

#[test]
fn t1_memory_retype_2m_superpage_and_designated_region() {
    let mut inv = UntypedInventory::new();
    // Start 4 KiB before a 2 MiB boundary so padding frames get recycled
    let base = 0x2000_0000 - PAGE_SIZE;
    assert!(inv.push_raw_region(base, 4 * 1024 * 1024));
    assert!(inv.push_raw_region(0x6000_0000, PAGE_SIZE * 2));

    let huge = inv.retype_frame_2m().unwrap();
    assert_eq!(huge.start_addr().raw() % (2 * 1024 * 1024), 0);
    assert!(inv.reclaimed_count() >= 1);

    let f_reg1 = inv.retype_frame_in(1).unwrap();
    assert_eq!(f_reg1.start_addr().raw(), 0x6000_0000);
    assert_eq!(inv.region_remaining(1), Some(PAGE_SIZE));
}

#[test]
fn t1_memory_frame_mapping_tracker_shared_frame() {
    let mut tracker = FrameMappingTracker::<16>::new();
    let vs1 = PhysAddr::new_aligned(0x1000_0000).unwrap();
    let vs2 = PhysAddr::new_aligned(0x1000_1000).unwrap();
    let phys = PhysFrame::from_aligned(PhysAddr::new_aligned(0x8000_0000).unwrap())
        .unwrap()
        .start_addr();
    let va1 = VirtAddr::new_page_aligned(0x4000_0000).unwrap();
    let va2 = VirtAddr::new_page_aligned(0x5000_0000).unwrap();

    tracker.record(vs1, va1, phys).unwrap();
    tracker.record(vs2, va2, phys).unwrap();
    assert_eq!(tracker.count(), 2);

    let mut drained = [None; 4];
    let n = tracker.drain_for_phys(phys, &mut drained);
    assert_eq!(n, 2);
    assert_eq!(tracker.count(), 0);

    // Record and remove single mapping
    tracker.record(vs1, va1, phys).unwrap();
    assert_eq!(tracker.remove(vs1, va1), Some(phys));
    assert_eq!(tracker.count(), 0);
}

// ============================================================================
// Area 5: Kernel Scheduler (`Scheduler` & `SmpScheduler`) (6 tests)
// ============================================================================

#[test]
fn t1_sched_priority_ordering_and_round_robin() {
    let mut sched = Scheduler::<8>::new();
    let low = sched.spawn(5).unwrap();
    let high1 = sched.spawn(20).unwrap();
    let high2 = sched.spawn(20).unwrap();

    assert_eq!(sched.active_count(), 3);
    assert_eq!(sched.ready_count(), 3);

    let first = sched.schedule_next().unwrap();
    assert_eq!(first, high1);
    let second = sched.schedule_next().unwrap();
    assert_eq!(second, high2);
    let third = sched.schedule_next().unwrap();
    assert_eq!(third, high1);
    assert_ne!(third, low);
}

#[test]
fn t1_sched_yield_current_increments_and_reschedules() {
    let mut sched = Scheduler::<8>::new();
    let t1 = sched.spawn(16).unwrap();
    let t2 = sched.spawn(16).unwrap();

    assert_eq!(sched.schedule_next(), Some(t1));
    assert_eq!(sched.yield_current(), Some(1));
    assert_eq!(sched.current_slot(), Some(1));
    assert_eq!(sched.tcb(1).unwrap().id, t2);
    assert_eq!(sched.tcb(0).unwrap().yields, 1);
}

#[test]
fn t1_sched_timer_tick_quantum_and_preemption() {
    let mut sched = Scheduler::<8>::new();
    let t1 = sched.spawn(16).unwrap();
    let _t2 = sched.spawn(16).unwrap();
    assert_eq!(sched.schedule_next(), Some(t1));

    for _ in 0..(DEFAULT_TIME_SLICE - 1) {
        assert!(!sched.on_timer_tick());
    }
    // Final tick expires quantum and preempts to equal-priority ready thread
    assert!(sched.on_timer_tick());
    assert_eq!(sched.tcb(0).unwrap().preemptions, 1);
}

#[test]
fn t1_sched_block_wake_set_priority_and_exit() {
    let mut sched = Scheduler::<8>::new();
    let t1 = sched.spawn(10).unwrap();
    let t2 = sched.spawn(20).unwrap();

    assert_eq!(sched.schedule_next(), Some(t2));
    sched.block_slot(1).unwrap();
    assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Blocked);

    // Only t1 is runnable now
    assert_eq!(sched.schedule_next(), Some(t1));
    sched.set_priority(0, 30).unwrap();
    sched.wake_slot(1).unwrap();
    assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Ready);

    // t1 has higher priority (30 > 20)
    assert_eq!(sched.schedule_next(), Some(t1));
    sched.exit_slot(0).unwrap();
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Exited);
    assert_eq!(sched.schedule_next(), Some(t2));
}

#[test]
fn t1_sched_select_slot_direct_switch() {
    let mut sched = Scheduler::<8>::new();
    let _t0 = sched.spawn(10).unwrap();
    let _t1 = sched.spawn(10).unwrap();

    sched.select_slot(0);
    assert_eq!(sched.current_slot(), Some(0));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Running);

    sched.select_slot(1);
    assert_eq!(sched.current_slot(), Some(1));
    assert_eq!(sched.tcb(0).unwrap().state, ThreadState::Ready);
    assert_eq!(sched.tcb(1).unwrap().state, ThreadState::Running);
}

#[test]
fn t1_sched_smp_balanced_spawn_and_work_stealing() {
    let mut smp = SmpScheduler::<4, 8>::new(2);
    assert_eq!(smp.online_cpus(), 2);

    // Put 2 threads on CPU 0 directly so CPU 1 is idle
    let cpu0 = smp.cpu_mut(0).unwrap();
    let t0 = cpu0.spawn_on_cpu(16, 0).unwrap();
    let t1 = cpu0.spawn_on_cpu(16, 0).unwrap();
    assert_eq!(cpu0.schedule_next(), Some(t0));

    // CPU 1 steals the Ready thread t1 from CPU 0
    let stolen = smp.schedule_or_steal(1).unwrap();
    assert_eq!(stolen, t1);
    let cpu1 = smp.cpu_mut(1).unwrap();
    let cur = cpu1.current_slot().unwrap();
    assert_eq!(cpu1.tcb(cur).unwrap().cpu_affinity, 1);

    // spawn_balanced picks least-loaded CPU
    let (chosen_cpu, _tid) = smp.spawn_balanced(12).unwrap();
    assert!(chosen_cpu < 2);
}

// ============================================================================
// Area 6: Kernel ELF64 Loader (`elf::parse_elf64`) (5 tests)
// ============================================================================

#[test]
fn t1_elf_minimal_rx_segment() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_vaddr: 0x40_0000,
            p_memsz: 64,
            data: vec![0xD5, 0x03, 0x20, 0x1F], // AArch64 NOP
        }],
    );
    let parsed = parse_elf64(&elf).unwrap();
    assert_eq!(parsed.entry.raw(), 0x40_0000);
    assert_eq!(parsed.segment_count(), 1);
    let seg = parsed.segments().next().unwrap();
    assert_eq!(seg.vaddr, 0x40_0000);
    assert_eq!(seg.mem_size, 64);
    assert_eq!(seg.file_size, 4);
    assert_eq!(
        seg.flags,
        PageFlags::new_wx(false, true, true, false).unwrap()
    );
}

#[test]
fn t1_elf_multi_segment_with_bss_and_non_load_skipped() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[
            ElfSegSpec {
                p_type: PT_NOTE,
                p_flags: PF_R,
                p_vaddr: 0x30_0000,
                p_memsz: 16,
                data: vec![1; 16],
            },
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_X,
                p_vaddr: 0x40_0000,
                p_memsz: 32,
                data: vec![0xAA; 32],
            },
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_vaddr: 0x41_0000,
                p_memsz: 256,
                data: vec![0xBB; 16],
            },
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R,
                p_vaddr: 0x42_0000,
                p_memsz: 64,
                data: vec![0xCC; 64],
            },
        ],
    );
    let parsed = parse_elf64(&elf).unwrap();
    assert_eq!(parsed.segment_count(), 3);
    let segs: Vec<_> = parsed.segments().collect();
    assert!(segs[0].flags.executable && !segs[0].flags.writable);
    assert!(segs[1].flags.writable && !segs[1].flags.executable);
    assert_eq!(segs[1].mem_size, 256);
    assert_eq!(segs[1].file_size, 16);
    assert!(!segs[2].flags.writable && !segs[2].flags.executable);
}

#[test]
fn t1_elf_pure_bss_zero_filesz_segment() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_vaddr: 0x40_0000,
            p_memsz: 4096,
            data: Vec::new(),
        }],
    );
    let parsed = parse_elf64(&elf).unwrap();
    let seg = parsed.segments().next().unwrap();
    assert_eq!(seg.file_size, 0);
    assert_eq!(seg.mem_size, 4096);
}

#[test]
fn t1_elf_extended_phentsize_stride() {
    let elf = build_elf64(
        0x40_0000,
        64, // > 56 standard ELF64 phdr size
        &[
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_X,
                p_vaddr: 0x40_0000,
                p_memsz: 16,
                data: vec![0x11; 16],
            },
            ElfSegSpec {
                p_type: PT_LOAD,
                p_flags: PF_R | PF_W,
                p_vaddr: 0x41_0000,
                p_memsz: 16,
                data: vec![0x22; 16],
            },
        ],
    );
    let parsed = parse_elf64(&elf).unwrap();
    assert_eq!(parsed.segment_count(), 2);
}

#[test]
fn t1_elf_max_load_segments_order_preserved() {
    let segs: Vec<ElfSegSpec> = (0..MAX_LOAD_SEGMENTS)
        .map(|i| ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: 0x40_0000 + (i as u64) * 0x1000,
            p_memsz: 64,
            data: vec![i as u8; 8],
        })
        .collect();
    let elf = build_elf64(0x40_0000, 56, &segs);
    let parsed = parse_elf64(&elf).unwrap();
    assert_eq!(parsed.segment_count(), MAX_LOAD_SEGMENTS);
    for (idx, seg) in parsed.segments().enumerate() {
        assert_eq!(seg.vaddr, 0x40_0000 + (idx as u64) * 0x1000);
    }
}

// ============================================================================
// Area 7: Shell Core & CAOS (6 tests)
// ============================================================================

#[test]
fn t1_shell_self_test_zero_debug_noise() {
    let mut sh = Shell::new(MockShellHost::new());
    assert_eq!(sh.run_self_test(), Ok(()));
    assert_eq!(sh.host().write_debug_calls, 0);
    assert_eq!(sh.host().sys_info_calls, 1);
}

#[test]
fn t1_caos_crud_dedup_rollback_seal_gc_snapshot() {
    let mut store = ObjectStore::new();
    assert_eq!(store.object_count(), 2); // @motd + @guide

    let h1 = store.put(b"version-one").unwrap();
    let h1_dup = store.put(b"version-one").unwrap();
    assert_eq!(h1, h1_dup);
    assert_eq!(store.get_by_hash(h1), Ok(&b"version-one"[..]));

    let h2 = store.put(b"version-two").unwrap();
    let orphan = store.put(b"orphan-blob").unwrap();
    assert_ne!(h1, orphan);

    store.set_ref("@cfg", h1).unwrap();
    store.set_ref("@cfg", h2).unwrap();
    let (got_h, got_b) = store.get_any("@cfg").unwrap();
    assert_eq!(got_h, h2);
    assert_eq!(got_b, b"version-two");

    // GC preserves both target (h2) and prev (h1), reclaims orphan
    let reclaimed = store.gc();
    assert_eq!(reclaimed, 1);
    assert_eq!(store.get_by_hash(orphan), Err(StoreError::NotFound));
    assert!(store.get_by_hash(h1).is_ok());

    let prev = store.rollback_ref("@cfg").unwrap();
    assert_eq!(prev, h1);
    store.seal_ref("@cfg").unwrap();
    assert_eq!(store.set_ref("@cfg", h2), Err(StoreError::ReadOnly));

    let mut snap = [0u8; 2048];
    let n = store.encode_snapshot(&mut snap).unwrap();
    let restored = ObjectStore::decode_snapshot(&snap[..n]).unwrap();
    assert_eq!(restored.get_any("@cfg").unwrap().1, b"version-one");
    assert_eq!(
        restored.get_any("@motd").unwrap().0,
        store.get_any("@motd").unwrap().0
    );
    let _ = ObjHash::parse_hex("0x1").unwrap();
}

#[test]
fn t1_shell_builtins_and_exit_outcomes() {
    let mut sh = Shell::new(MockShellHost::new());

    assert_eq!(sh.exec_line("help"), ExecOutcome::Continue);
    assert!(!sh.host().output.is_empty());

    sh.host_mut().clear_output();
    assert_eq!(sh.exec_line("sys"), ExecOutcome::Continue);
    assert!(!sh.host().output.is_empty());

    assert_eq!(sh.exec_line("crash"), ExecOutcome::Continue);
    assert_eq!(sh.host().fault_triggers, 1);

    assert_eq!(sh.exec_line("clear"), ExecOutcome::Continue);
    assert_eq!(
        sh.exec_line("exit"),
        ExecOutcome::Exit(ShutdownStatus::Success)
    );
    assert_eq!(
        sh.exec_line("shutdown"),
        ExecOutcome::Exit(ShutdownStatus::Success)
    );
}

#[test]
fn t1_shell_typed_pipelines_where_first_count_save() {
    let mut sh = Shell::new(MockShellHost::new());

    let stream = sh.eval_pipeline("put \"hello caos\" | save @greeting");
    assert_eq!(stream.len(), 1);
    assert!(matches!(stream.first(), Some(Record::Object(_))));
    assert_eq!(sh.store().get_any("@greeting").unwrap().1, b"hello caos");

    let count_stream = sh.eval_pipeline("objects | where size > 5 | count");
    assert!(matches!(count_stream.first(), Some(Record::Count(n)) if n >= 3));

    let first_stream = sh.eval_pipeline("procs | where pid == 1 | first 1");
    assert_eq!(first_stream.len(), 1);
    assert!(matches!(
        first_stream.first(),
        Some(Record::Proc { pid: 1, .. })
    ));

    let writable_refs = sh.eval_pipeline("refs | where writable == true | count");
    assert!(matches!(writable_refs.first(), Some(Record::Count(1))));
}

#[test]
fn t1_shell_sys_info_caching_and_ping_ipc_fastpath() {
    let mut sh = Shell::new(MockShellHost::new());
    sh.exec_line("sys");
    sh.exec_line("procs");
    sh.exec_line("sys");
    sh.eval_pipeline("procs | where pid == 1 | count");
    assert_eq!(sh.host().sys_info_calls, 1);

    sh.exec_line("ping 0x2A");
    assert_eq!(sh.host().ipc_call_calls, 1);
    assert_eq!(sh.host().ipc_send_calls, 0);
    assert_eq!(sh.host().ipc_recv_calls, 0);
    assert_eq!(sh.host().yield_calls, 0);

    // Verify default ShellHost::ipc_call fallback delegates to send -> yield -> recv
    let mut fallback = Shell::new(DefaultIpcFallbackHost::new());
    let stream = fallback.eval_pipeline("ping 0x10");
    assert_eq!(stream.len(), 2);
    assert_eq!(fallback.host().ipc_send_calls, 1);
    assert_eq!(fallback.host().yield_calls, 1);
    assert_eq!(fallback.host().ipc_recv_calls, 1);
}

#[test]
fn t1_shell_buffered_writer_utf8_and_record_stream_render() {
    let mut sink = String::new();
    {
        let mut bw = BufferedWriter::<8, _>::new(&mut sink);
        bw.write_str("abλ🦀cd").unwrap();
        bw.flush();
    }
    assert_eq!(sink, "abλ🦀cd");

    let mut rs = RecordStream::new();
    rs.push(Record::Metric {
        label: "latency",
        value: 42,
        unit: "ns",
    });
    let mut rendered = String::new();
    rs.render(&mut rendered);
    assert!(rendered.contains("42"));

    let mut rs_count = RecordStream::new();
    rs_count.push(Record::Count(3));
    let mut rendered_count = String::new();
    rs_count.render(&mut rendered_count);
    assert!(rendered_count.contains("3"));
}

// ============================================================================
// Area 8: Benchmark Harness (5 tests)
// ============================================================================

#[test]
fn t1_bench_default_emits_all_16_baseline_metrics() {
    let run = run_newos_bench(&[]);
    assert!(
        run.status.success(),
        "newos_bench failed: stderr={}",
        run.stderr
    );
    let metrics = parse_metric_lines(&run.stdout);
    let expected = [
        ("kernel.cnode.lookup", "ns/op"),
        ("kernel.cnode.mint_revoke", "ns/op"),
        ("kernel.ipc.send_recv", "ns/op"),
        ("kernel.ipc.notify_signal_poll", "ns/op"),
        ("kernel.sched.schedule_next", "ns/op"),
        ("kernel.memory.retype_frame", "ns/op"),
        ("kernel.ring.spsc_transfer", "ns/op"),
        ("shell.caos.put_get_ref", "ns/op"),
        ("shell.pipeline.eval", "ns/op"),
        ("shell.session.full", "ns/op"),
        ("ipc.shell_session.debug_write_syscalls", "syscalls"),
        ("ipc.shell_session.sys_info_syscalls", "syscalls"),
        ("ipc.ping_roundtrip.syscalls_per_op", "syscalls/op"),
        ("ipc.ring_burst_32w.notify_syscalls", "syscalls"),
        ("ipc.idle_poll_100.wasted_worker_ipc", "syscalls"),
        ("ipc.total_consumption", "syscalls"),
    ];
    for (name, unit) in expected {
        let found = metrics.iter().find(|(n, _, _)| n == name);
        let (_, val_str, got_unit) =
            found.unwrap_or_else(|| panic!("missing baseline METRIC {name}"));
        assert_eq!(got_unit, unit, "unit mismatch for {name}");
        let parsed: f64 = val_str
            .parse()
            .unwrap_or_else(|e| panic!("invalid numeric value for {name}: {val_str} ({e})"));
        assert!(parsed.is_finite() && parsed >= 0.0);
    }
}

#[test]
fn t1_bench_markdown_output_contract() {
    let run = run_newos_bench(&["--markdown"]);
    assert!(run.status.success(), "stderr={}", run.stderr);
    assert!(run.stdout.contains('|'));
    assert!(run.stdout.contains("kernel.cnode.lookup"));
    assert!(run.stdout.contains("ipc.total_consumption"));
}

#[test]
fn t1_bench_json_output_contract() {
    let run = run_newos_bench(&["--json"]);
    assert!(run.status.success(), "stderr={}", run.stderr);
    let trimmed = run.stdout.trim();
    assert!(trimmed.starts_with('{') && trimmed.ends_with('}'));
    assert!(trimmed.contains("\"metrics\""));
    assert!(trimmed.contains("\"kernel.ipc.send_recv\""));
    assert!(trimmed.contains("\"shell.session.full\""));
}

#[test]
fn t1_bench_help_flag_exits_zero() {
    let run = run_newos_bench(&["--help"]);
    assert!(run.status.success());
    assert!(run.stdout.contains("--markdown"));
    assert!(run.stdout.contains("--json"));
}

#[test]
fn t1_bench_unknown_flag_exits_code_2() {
    let run = run_newos_bench(&["--definitely-unknown-flag"]);
    assert_eq!(run.status.code(), Some(2));
    assert!(!run.stderr.is_empty());
}
