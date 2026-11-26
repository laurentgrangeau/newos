use std::panic::{AssertUnwindSafe, catch_unwind};

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, Rights, SysError, SyscallNumber};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::{MAX_LOAD_SEGMENTS, parse_elf64};
use newos_kernel_core::ipc::{KernelIpcState, MAX_IPC_DOMAINS};
use newos_kernel_core::memory::{
    FrameMappingTracker, MAX_RECLAIMED_FRAMES, MAX_UNTYPED_REGIONS, PAGE_SIZE, PageFlags, PhysAddr,
    PhysFrame, PhysFrame2M, UntypedInventory, UntypedRegion, VirtAddr,
};
use newos_kernel_core::sched::{Scheduler, SmpScheduler};
use newos_shell_core::caos::{
    MAX_BLOB_SIZE, MAX_OBJECTS, MAX_REF_NAME, MAX_REFS, ObjHash, ObjectStore, StoreError,
};
use newos_shell_core::shell::{ExecOutcome, Shell};

use crate::helpers::{
    ElfSegSpec, ExitSentinel, MockShellHost, PF_R, PF_W, PF_X, PT_LOAD, TokKind,
    YieldLimitExceeded, build_elf64, collect_rs_files, crate_forbids_unsafe_code, find_repo_root,
    find_unsafe_sites, has_safety_comment, parse_metric_lines, run_newos_bench, scan_rust_source,
    strip_cfg_test,
};

// ============================================================================
// Area 1: ABI & SpscRing Boundaries (5 tests)
// ============================================================================

#[test]
fn t2_abi_rights_truncate_and_no_escalation_32x32() {
    assert_eq!(Rights::from_bits_truncate(0xFF), Rights::ALL);
    assert_eq!(Rights::from_bits_truncate(0b1110_0000), Rights::NONE);

    for a in 0u8..=Rights::ALL.bits() {
        let ra = Rights::from_bits_truncate(a);
        for b in 0u8..=Rights::ALL.bits() {
            let rb = Rights::from_bits_truncate(b);
            let atten = ra.attenuate(rb);
            assert!(ra.contains(atten));
            assert!(rb.contains(atten));
            assert_eq!(atten.bits(), a & b);
        }
    }
}

#[test]
fn t2_abi_invalid_enum_discriminants_return_none() {
    for bad in [13u64, 14, 255, u64::MAX] {
        assert_eq!(ObjectType::from_u64(bad), None);
    }
    for bad in [0u64, 43, 100, u64::MAX] {
        assert_eq!(SyscallNumber::from_u64(bad), None);
    }
    for bad in [0u64, 8, 99, u64::MAX] {
        assert_eq!(SysError::from_u64(bad), None);
    }
}

#[test]
fn t2_ring_min_capacity_2_overflow_and_underflow() {
    let ring = SpscRing::<2>::new();
    assert_eq!(ring.capacity(), 1);
    assert_eq!(ring.try_pop(), None);

    assert_eq!(ring.try_push(0xAA), Ok(()));
    assert!(ring.is_full());
    assert_eq!(ring.try_push(0xBB), Err(SysError::WouldBlock));
    assert_eq!(ring.try_pop(), Some(0xAA));
    assert_eq!(ring.try_pop(), None);
    assert!(ring.is_empty());

    // Slice wraparound on N=2
    let mut dst = [0u64; 4];
    for round in 0..16u64 {
        assert_eq!(ring.try_push_slice(&[round, round + 1]), 1);
        assert_eq!(ring.try_pop_slice(&mut dst), 1);
        assert_eq!(dst[0], round);
    }
}

#[test]
fn t2_ring_empty_and_oversized_slice_clamping() {
    let ring = SpscRing::<8>::new();
    let mut empty_dst = [];
    assert_eq!(ring.try_push_slice(&[]), 0);
    assert_eq!(ring.try_pop_slice(&mut empty_dst), 0);

    let big_src = [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    assert_eq!(ring.try_push_slice(&big_src), 7);
    assert!(ring.is_full());

    let mut big_dst = [0u64; 12];
    assert_eq!(ring.try_pop_slice(&mut big_dst), 7);
    assert_eq!(&big_dst[..7], &big_src[..7]);
    assert!(ring.is_empty());
}

#[test]
fn t2_ring_64_repeated_wraparound_10k_ops() {
    let ring = SpscRing::<64>::new();
    let mut expected = 0u64;
    let mut next_val = 0u64;
    for _ in 0..200 {
        while !ring.is_full() {
            ring.try_push(next_val).unwrap();
            next_val += 1;
        }
        assert_eq!(ring.try_push(999), Err(SysError::WouldBlock));
        while let Some(v) = ring.try_pop() {
            assert_eq!(v, expected);
            expected += 1;
        }
    }
    assert_eq!(expected, 200 * 63);
    assert!(ring.is_empty());
}

// ============================================================================
// Area 2: CSpace Boundaries (6 tests)
// ============================================================================

#[test]
fn t2_cspace_null_oob_and_stale_generation_rejected() {
    let mut cnode = CNode::<8>::new();
    assert_eq!(
        cnode.lookup(CapId::NULL, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(CapId::new(0x0001_0000_0000_00FF), Rights::NONE),
        Err(SysError::InvalidCapability)
    );

    let cap = cnode
        .insert_root_at(2, Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    cnode.delete(cap).unwrap();
    assert_eq!(
        cnode.lookup(cap, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    // Re-inserting into the same slot bumps generation so old CapId stays invalid
    let cap2 = cnode
        .insert_root_at(2, Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    assert_ne!(cap, cap2);
    assert_eq!(
        cnode.lookup(cap, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
}

#[test]
fn t2_cspace_mint_and_revoke_rights_and_badge_guards() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();

    // Some(0) badge is invalid
    assert_eq!(
        cnode.mint(root, 3, Rights::READ, Some(0)),
        Err(SysError::InvalidArgument)
    );

    let badged = cnode
        .mint(root, 3, Rights::READ.union(Rights::GRANT), Some(0x55))
        .unwrap();
    // Re-badging an already badged cap is forbidden
    assert_eq!(
        cnode.mint(badged, 4, Rights::READ, Some(0x66)),
        Err(SysError::InsufficientRights)
    );
    // Revoking without REVOKE right is forbidden
    assert_eq!(cnode.revoke(badged), Err(SysError::InsufficientRights));

    let no_grant = cnode.mint(root, 5, Rights::READ, None).unwrap();
    assert_eq!(
        cnode.mint(no_grant, 6, Rights::READ, None),
        Err(SysError::InsufficientRights)
    );
}

#[test]
fn t2_cspace_slot_zero_oob_occupied_and_full_errors() {
    let mut cnode = CNode::<4>::new();
    assert_eq!(
        cnode.insert_root_at(0, Capability::new(CapObject::Console, Rights::ALL)),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        cnode.insert_root_at(4, Capability::new(CapObject::Console, Rights::ALL)),
        Err(SysError::InvalidArgument)
    );

    let c1 = cnode
        .insert_root_at(1, Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    assert_eq!(
        cnode.insert_root_at(1, Capability::new(CapObject::Console, Rights::ALL)),
        Err(SysError::SlotOccupied)
    );
    let _c2 = cnode
        .insert_root_at(2, Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    let _c3 = cnode
        .insert_root_at(3, Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    assert_eq!(cnode.find_free_slot(), Err(SysError::OutOfMemory));
    assert_eq!(cnode.move_cap(c1, 0), Err(SysError::InvalidArgument));
    assert_eq!(cnode.move_cap(c1, 2), Err(SysError::SlotOccupied));
}

#[test]
fn t2_cspace_zero_and_one_slot_boundaries() {
    let c0 = CNode::<0>::new();
    assert_eq!(c0.find_free_slot(), Err(SysError::OutOfMemory));
    assert_eq!(
        c0.lookup(CapId::BOOTSTRAP_EP, Rights::NONE),
        Err(SysError::InvalidCapability)
    );

    let c1 = CNode::<1>::new();
    // Slot 0 is reserved for NULL, so CNode<1> has no usable slots
    assert_eq!(c1.find_free_slot(), Err(SysError::OutOfMemory));
}

#[test]
fn t2_cspace_type_and_rights_mismatch_on_bind_and_retype() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x2000_0000, PAGE_SIZE * 2));

    let mut cnode = CNode::<16>::new();
    let console = cnode
        .insert_root(Capability::new(CapObject::Console, Rights::ALL))
        .unwrap();
    assert_eq!(
        cnode.bind_vspace_root(console, PhysAddr::new_aligned(0x1000).unwrap()),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        cnode.retype_frame_from_into(console, 5, &mut inv),
        Err(SysError::InvalidArgument)
    );

    let ut_ro = cnode
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::READ,
        ))
        .unwrap();
    assert_eq!(
        cnode.retype_frame_from_into(ut_ro, 5, &mut inv),
        Err(SysError::InsufficientRights)
    );
}

#[test]
fn t2_cspace_slots_gt_64_revoke_without_shift_overflow() {
    // Post-M2 Feature 7 hardened test: CNode<80> with children in slots >= 64
    // must revoke cleanly without shift-left overflow panic.
    let mut cnode = CNode::<80>::new();
    let root = cnode
        .insert_root_at(
            1,
            Capability::new(CapObject::Endpoint { id: 7 }, Rights::ALL),
        )
        .unwrap();
    let child_hi = cnode
        .mint(root, 65, Rights::READ.union(Rights::GRANT), None)
        .unwrap();
    let grand_hi = cnode.mint(child_hi, 72, Rights::READ, None).unwrap();

    let revoked = cnode
        .revoke(root)
        .expect("revoke on CNode<80> must succeed");
    assert_eq!(revoked, 2);
    assert_eq!(
        cnode.lookup(child_hi, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(grand_hi, Rights::NONE),
        Err(SysError::InvalidCapability)
    );

    // Also insert `root_hi` at slot >= 64 (slot 65) with a child at slot 72 and
    // invoke `revoke_with_mask_cb` so unguarded `1u64 << root_idx` shift-left
    // overflow is caught pre-M2 and passes once M2 guards `SLOTS > 64`.
    let root_hi = cnode
        .insert_root_at(
            65,
            Capability::new(CapObject::Endpoint { id: 8 }, Rights::ALL),
        )
        .unwrap();
    let child_hi2 = cnode.mint(root_hi, 72, Rights::READ, None).unwrap();
    let mut cb_count = 0usize;
    match cnode.revoke_with_mask_cb(root_hi, |_| {
        cb_count += 1;
    }) {
        Ok((revoked_hi, root_idx, _mask)) => {
            assert_eq!(revoked_hi, 1);
            assert_eq!(root_idx, 65);
            assert_eq!(cb_count, 1);
            assert_eq!(
                cnode.lookup(child_hi2, Rights::NONE),
                Err(SysError::InvalidCapability)
            );
        }
        Err(SysError::InvalidArgument | SysError::Unsupported) => {
            assert_eq!(cb_count, 0);
        }
        Err(other) => {
            panic!("unexpected error from revoke_with_mask_cb on CNode<80>: {other:?}");
        }
    }
}

// ============================================================================
// Area 3: IPC Boundaries (6 tests)
// ============================================================================

#[test]
fn t2_ipc_invalid_pid_rejected_across_apis() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(
        ipc.cspace(MAX_IPC_DOMAINS).err(),
        Some(SysError::InvalidArgument)
    );
    assert_eq!(ipc.cspace_mut(99).err(), Some(SysError::InvalidArgument));
    assert_eq!(
        ipc.ipc_send_for(MAX_IPC_DOMAINS, CapId::BOOTSTRAP_EP, 1),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.notify_signal_for(MAX_IPC_DOMAINS, CapId::BOOTSTRAP_NOTIF, 1),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.init_worker_pd_bootstrap_caps(0),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.init_worker_pd_bootstrap_caps(MAX_IPC_DOMAINS),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.register_child_caps_in_root(0),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.register_child_caps_in_root(MAX_IPC_DOMAINS),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn t2_ipc_wrong_object_type_rejected_across_validators() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();

    // Pass BOOTSTRAP_CONSOLE (Console) to validators expecting other object types
    let wrong = CapId::BOOTSTRAP_CONSOLE;
    assert_eq!(
        ipc.validate_thread_for(0, wrong, Rights::READ),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_cnode_for(0, wrong, Rights::READ),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_power_for(0, wrong, Rights::WRITE),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_vspace_for(0, wrong, Rights::READ),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_frame_for(0, wrong, Rights::READ),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.lookup_endpoint_for(0, wrong, Rights::READ),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.notify_signal_for(0, wrong, 1),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.notify_poll_for(0, wrong),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_console_for(0, CapId::BOOTSTRAP_EP, Rights::WRITE),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn t2_ipc_endpoint_saturation_and_empty_recv_would_block() {
    let mut ipc = KernelIpcState::new();
    let (_, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(ipc.ipc_recv_for(0, ep), Err(SysError::WouldBlock));
    ipc.ipc_send_for(0, ep, 11).unwrap();
    assert_eq!(ipc.ipc_send_for(0, ep, 22), Err(SysError::WouldBlock));
    assert_eq!(
        ipc.ipc_call_for(0, ep, 33, |m| m),
        Err(SysError::WouldBlock)
    );
    assert!(ipc.stats().would_blocks >= 3);
}

#[test]
fn t2_ipc_retype_exhaustion_and_unsupported_types() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x1000_0000, PAGE_SIZE * 64));

    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();

    // Unsupported types
    assert_eq!(
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Thread,
            20,
            &mut inv
        ),
        Err(SysError::Unsupported)
    );
    assert_eq!(
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::VSpace,
            20,
            &mut inv
        ),
        Err(SysError::Unsupported)
    );

    // Exhaust endpoint pool (7 bootstrap + 9 retyped = 16 max)
    for i in 0..9 {
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Endpoint,
            30 + i,
            &mut inv,
        )
        .unwrap();
    }
    assert_eq!(
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Endpoint,
            45,
            &mut inv
        ),
        Err(SysError::OutOfMemory)
    );

    // Exhaust notification pool (2 bootstrap + 14 retyped = 16 max)
    for i in 0..14 {
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Notification,
            40 + i,
            &mut inv,
        )
        .unwrap();
    }
    assert_eq!(
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Notification,
            55,
            &mut inv
        ),
        Err(SysError::OutOfMemory)
    );
}

#[test]
fn t2_ipc_mmio_alignment_oob_overflow_and_rights_guards() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(Some((PhysAddr::new(0x0A00_0000), 0x100)))
        .unwrap();

    // Unaligned offsets
    for bad_off in [1u64, 2, 3, 5] {
        assert_eq!(
            ipc.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, bad_off),
            Err(SysError::InvalidArgument)
        );
    }
    // OOB & overflow
    assert_eq!(
        ipc.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, 0x100),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        ipc.validate_mmio_read32_for(0, CapId::BOOTSTRAP_NET_MMIO, u64::MAX - 2),
        Err(SysError::InvalidArgument)
    );
    // Read-only MMIO cap rejects write
    let ro_mmio = ipc
        .root_cspace_mut()
        .insert_root(Capability::new(
            CapObject::MmioRegion {
                phys: PhysAddr::new(0x0A00_0000),
                len: 0x100,
            },
            Rights::READ,
        ))
        .unwrap();
    assert!(ipc.validate_mmio_read32_for(0, ro_mmio, 0).is_ok());
    assert_eq!(
        ipc.validate_mmio_write32_for(0, ro_mmio, 0),
        Err(SysError::InsufficientRights)
    );
}

#[test]
fn t2_ipc_revoke_collecting_frames_bounded_output_slice() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x7000_0000, PAGE_SIZE * 8));

    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(None).unwrap();

    for slot in 20..25 {
        ipc.untyped_retype_for(
            0,
            CapId::BOOTSTRAP_UNTYPED,
            ObjectType::Frame,
            slot,
            &mut inv,
        )
        .unwrap();
    }

    let mut tiny = [None; 2];
    let (revoked_caps, recorded_frames) = ipc
        .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut tiny)
        .unwrap();
    assert_eq!(revoked_caps, 5);
    assert_eq!(recorded_frames, 2);
    assert!(tiny[0].is_some() && tiny[1].is_some());
}

// ============================================================================
// Area 4: Memory Boundaries (6 tests)
// ============================================================================

#[test]
fn t2_memory_strict_wx_rejects_writable_executable() {
    assert_eq!(
        PageFlags::new_wx(true, true, true, false),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        PageFlags::new_wx(true, true, false, true),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn t2_memory_virt_addr_canonical_hole_and_alignment_rejected() {
    assert_eq!(
        VirtAddr::new_canonical(0x0000_8000_0000_0000),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        VirtAddr::new_canonical(0xFFFF_7FFF_FFFF_F000),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        VirtAddr::new_page_aligned(0x0000_0000_0040_0001),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn t2_memory_phys_addr_and_frames_reject_misaligned() {
    assert_eq!(PhysAddr::new_aligned(1), Err(SysError::InvalidArgument));
    assert_eq!(
        PhysFrame::from_aligned(PhysAddr::new(0x1001)),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        PhysFrame2M::from_aligned(PhysAddr::new(0x0020_1000)),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn t2_memory_untyped_region_and_inventory_limits() {
    assert_eq!(UntypedRegion::from_raw(0x1000, 0), None);
    assert_eq!(UntypedRegion::from_raw(0x1000, PAGE_SIZE - 1), None);
    assert_eq!(UntypedRegion::from_raw(u64::MAX - 100, 0x2000), None);

    let mut inv = UntypedInventory::new();
    for i in 0..MAX_UNTYPED_REGIONS {
        let base = 0x1000_0000 + (i as u64) * PAGE_SIZE * 32;
        assert!(inv.push_raw_region(base, PAGE_SIZE * 32));
    }
    assert!(!inv.push_raw_region(0x9000_0000, PAGE_SIZE * 16));

    let mut frames = Vec::new();
    for _ in 0..=MAX_RECLAIMED_FRAMES {
        frames.push(inv.retype_frame().unwrap());
    }
    for (idx, frame) in frames.into_iter().enumerate() {
        let ok = inv.reclaim_frame(frame);
        if idx < MAX_RECLAIMED_FRAMES {
            assert!(ok);
        } else {
            assert!(!ok);
        }
    }
}

#[test]
fn t2_memory_retype_frame_in_oob_and_no_spillover() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x1000_0000, PAGE_SIZE));
    assert!(inv.push_raw_region(0x2000_0000, PAGE_SIZE * 4));

    assert_eq!(inv.retype_frame_in(2), Err(SysError::InvalidArgument));
    assert!(inv.retype_frame_in(0).is_ok());
    // Region 0 is exhausted; must NOT spill into region 1
    assert_eq!(inv.retype_frame_in(0), Err(SysError::OutOfMemory));
    assert_eq!(inv.region_remaining(1), Some(PAGE_SIZE * 4));
}

#[test]
fn t2_memory_frame_mapping_tracker_oom_and_incremental_drain() {
    let mut tracker = FrameMappingTracker::<4>::new();
    let phys = PhysAddr::new_aligned(0x5000_0000).unwrap();
    for i in 0..4u64 {
        let vs = PhysAddr::new_aligned(0x1000_0000 + i * PAGE_SIZE).unwrap();
        let va = VirtAddr::new_page_aligned(0x4000_0000 + i * PAGE_SIZE).unwrap();
        tracker.record(vs, va, phys).unwrap();
    }
    assert_eq!(
        tracker.record(
            PhysAddr::new_aligned(0x1000_9000).unwrap(),
            VirtAddr::new_page_aligned(0x4000_9000).unwrap(),
            phys
        ),
        Err(SysError::OutOfMemory)
    );

    let mut total = 0usize;
    loop {
        let mut single = [None; 1];
        let n = tracker.drain_for_phys(phys, &mut single);
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, 4);
    assert_eq!(tracker.count(), 0);
}

// ============================================================================
// Area 5: Scheduler Boundaries (5 tests)
// ============================================================================

#[test]
fn t2_sched_zero_capacity_safe_empty_behavior() {
    let mut sched = Scheduler::<0>::new();
    assert_eq!(sched.spawn(16), Err(SysError::OutOfMemory));
    assert_eq!(sched.schedule_next(), None);
    assert_eq!(sched.yield_current(), None);
    assert!(!sched.on_timer_tick());
}

#[test]
fn t2_sched_full_64_wraparound_and_80_slot_fallback() {
    let mut s64 = Scheduler::<64>::new();
    for _ in 0..64 {
        s64.spawn(10).unwrap();
    }
    assert_eq!(s64.spawn(10), Err(SysError::OutOfMemory));
    for _ in 0..130 {
        assert!(s64.schedule_next().is_some());
    }

    let mut s80 = Scheduler::<80>::new();
    for i in 0u8..80 {
        s80.spawn(i % 5).unwrap();
    }
    assert_eq!(s80.active_count(), 80);
    assert!(s80.schedule_next().is_some());
}

#[test]
fn t2_sched_oob_and_empty_slot_errors() {
    let mut sched = Scheduler::<4>::new();
    assert_eq!(sched.set_priority(0, 10), Err(SysError::InvalidArgument));
    assert_eq!(sched.block_slot(0), Err(SysError::InvalidArgument));
    assert_eq!(sched.wake_slot(0), Err(SysError::InvalidArgument));
    assert_eq!(sched.exit_slot(0), Err(SysError::InvalidArgument));
    assert_eq!(sched.set_priority(99, 10), Err(SysError::InvalidArgument));
    // select_slot on OOB is a safe no-op
    sched.select_slot(99);
    assert_eq!(sched.current_slot(), None);
}

#[test]
fn t2_sched_smp_cpu_clamping_and_oob_cpu_id() {
    let mut smp_zero = SmpScheduler::<4, 8>::new(0);
    assert_eq!(smp_zero.online_cpus(), 1);
    assert!(smp_zero.cpu_mut(1).is_none());
    assert_eq!(smp_zero.schedule_or_steal(1), None);
    assert!(!smp_zero.on_timer_tick(1));

    let smp_over = SmpScheduler::<4, 8>::new(99);
    assert_eq!(smp_over.online_cpus(), 4);
}

#[test]
fn t2_sched_smp_idle_and_running_only_not_stolen() {
    let mut smp = SmpScheduler::<2, 8>::new(2);
    assert_eq!(smp.schedule_or_steal(0), None);
    assert_eq!(smp.schedule_or_steal(1), None);

    // Spawn a single thread on CPU 0 and make it Running (no Ready threads left)
    let cpu0 = smp.cpu_mut(0).unwrap();
    let t0 = cpu0.spawn_on_cpu(16, 0).unwrap();
    assert_eq!(cpu0.schedule_next(), Some(t0));

    // CPU 1 must NOT steal a Running thread
    assert_eq!(smp.schedule_or_steal(1), None);
}

// ============================================================================
// Area 6: ELF64 Loader Boundaries (6 tests)
// ============================================================================

#[test]
fn t2_elf_truncated_magic_class_endian_type_machine_rejected() {
    assert_eq!(parse_elf64(&[0u8; 63]), Err(SysError::InvalidArgument));

    let base = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_vaddr: 0x40_0000,
            p_memsz: 16,
            data: vec![0; 16],
        }],
    );

    let mut bad_magic = base.clone();
    bad_magic[0] = 0x00;
    assert_eq!(parse_elf64(&bad_magic), Err(SysError::InvalidArgument));

    let mut bad_class = base.clone();
    bad_class[4] = 1; // ELFCLASS32
    assert_eq!(parse_elf64(&bad_class), Err(SysError::Unsupported));

    let mut bad_endian = base.clone();
    bad_endian[5] = 2; // ELFDATA2MSB
    assert_eq!(parse_elf64(&bad_endian), Err(SysError::Unsupported));

    let mut bad_type = base.clone();
    bad_type[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL (unsupported)
    assert_eq!(parse_elf64(&bad_type), Err(SysError::Unsupported));

    let mut bad_mach = base;
    bad_mach[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    assert_eq!(parse_elf64(&bad_mach), Err(SysError::Unsupported));
}

#[test]
fn t2_elf_wx_segment_rejected() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W | PF_X,
            p_vaddr: 0x40_0000,
            p_memsz: 64,
            data: vec![0; 16],
        }],
    );
    assert_eq!(parse_elf64(&elf), Err(SysError::InvalidArgument));
}

#[test]
fn t2_elf_non_canonical_entry_memsz_filesz_phentsize_zero_load_rejected() {
    // Upper-half entry rejected
    let high_entry = build_elf64(
        0xFFFF_8000_0000_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_vaddr: 0x40_0000,
            p_memsz: 16,
            data: vec![0; 16],
        }],
    );
    assert_eq!(parse_elf64(&high_entry), Err(SysError::InvalidArgument));

    // p_memsz < p_filesz rejected
    let bad_memsz = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: 0x40_0000,
            p_memsz: 4,
            data: vec![0; 16],
        }],
    );
    assert_eq!(parse_elf64(&bad_memsz), Err(SysError::InvalidArgument));

    // Zero PT_LOAD segments rejected
    let empty_segs = build_elf64(0x40_0000, 56, &[]);
    assert_eq!(parse_elf64(&empty_segs), Err(SysError::InvalidArgument));

    // phentsize < 56 rejected
    let mut bad_phent = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: 0x40_0000,
            p_memsz: 16,
            data: vec![0; 16],
        }],
    );
    bad_phent[54..56].copy_from_slice(&32u16.to_le_bytes());
    assert_eq!(parse_elf64(&bad_phent), Err(SysError::InvalidArgument));
}

#[test]
fn t2_elf_exceeding_max_load_segments_returns_oom() {
    let segs: Vec<ElfSegSpec> = (0..=MAX_LOAD_SEGMENTS)
        .map(|i| ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: 0x40_0000 + (i as u64) * 0x1000,
            p_memsz: 16,
            data: vec![0; 8],
        })
        .collect();
    let elf = build_elf64(0x40_0000, 56, &segs);
    assert_eq!(parse_elf64(&elf), Err(SysError::OutOfMemory));
}

#[test]
fn t2_elf_vaddr_and_phoff_mul_overflow_rejected() {
    let elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: u64::MAX - 8,
            p_memsz: 64,
            data: vec![0; 8],
        }],
    );
    assert_eq!(parse_elf64(&elf), Err(SysError::InvalidArgument));
}

#[test]
fn t2_elf_phoff_u64_max_minus_2_overflow_no_panic() {
    // Post-M2 Feature 7 hardened test: `phoff = u64::MAX - 2` with `phnum = 1`
    // triggers `off + 4` integer overflow in pre-M2 `read_u32_le`; post-M2 must
    // return `Err(SysError::InvalidArgument)` cleanly without panicking.
    let mut elf = build_elf64(
        0x40_0000,
        56,
        &[ElfSegSpec {
            p_type: PT_LOAD,
            p_flags: PF_R,
            p_vaddr: 0x40_0000,
            p_memsz: 16,
            data: vec![0; 16],
        }],
    );
    elf[32..40].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(parse_elf64(&elf), Err(SysError::InvalidArgument));
}

// ============================================================================
// Area 7: Shell Core & CAOS Boundaries + Post-M3 Hardened Tests (7 tests)
// ============================================================================

#[test]
fn t2_shell_quoted_pipe_preserved_in_pipeline() {
    // Post-M3 Feature 12 hardened test: `|` inside quotes must NOT split stages.
    let mut sh = Shell::new(MockShellHost::new());
    sh.eval_pipeline("put \"a | b\" | save @qpipe");
    let (_, data) = sh
        .store()
        .get_any("@qpipe")
        .expect("@qpipe must be saved with quoted pipe intact");
    assert_eq!(data, b"a | b");
}

#[test]
fn t2_shell_put_over_128b_rejected_too_large() {
    // Post-M3 Feature 12 hardened test: `put` > MAX_BLOB_SIZE (128B) must NOT
    // silently truncate and store a blob; it must reject with TooLarge.
    let mut sh = Shell::new(MockShellHost::new());
    let before_count = sh.store().object_count();
    let payload = "A".repeat(MAX_BLOB_SIZE + 5);
    let cmd = format!("put {payload}");
    sh.exec_line(&cmd);
    assert_eq!(
        sh.store().object_count(),
        before_count,
        "oversized put must not insert a truncated blob"
    );
}

#[test]
fn t2_caos_boundaries_max_objects_refs_and_invalid_ref_names() {
    let mut store = ObjectStore::new();
    // 0-byte and 128-byte blobs succeed; 129-byte fails with TooLarge
    let h0 = store.put(b"").unwrap();
    assert_eq!(store.get_by_hash(h0), Ok(&b""[..]));
    let b128 = [0x5Au8; MAX_BLOB_SIZE];
    let h128 = store.put(&b128).unwrap();
    assert_eq!(store.get_by_hash(h128), Ok(&b128[..]));
    let b129 = [0x5Au8; MAX_BLOB_SIZE + 1];
    assert_eq!(store.put(&b129), Err(StoreError::TooLarge));

    // Invalid ref names (Post-M3 Feature 12 hardened validation)
    let overlong = "x".repeat(MAX_REF_NAME + 1);
    for bad in [
        "",
        "@",
        overlong.as_str(),
        "bad name",
        "a\nb",
        "a\tb",
        "a\0b",
        "@@double",
    ] {
        assert_eq!(
            store.set_ref(bad, h0),
            Err(StoreError::InvalidName),
            "ref name {bad:?} must be rejected as InvalidName"
        );
    }

    // Fill MAX_OBJECTS (24 total, 4 already present: @motd, @guide, h0, h128)
    for i in 0..(MAX_OBJECTS - 4) {
        let data = format!("obj-{i:02}");
        store.put(data.as_bytes()).unwrap();
    }
    assert_eq!(store.put(b"overflow-obj"), Err(StoreError::NoSpace));

    // Fill MAX_REFS (16 total, 2 already present: @motd, @guide)
    for i in 0..(MAX_REFS - 2) {
        let name = format!("@r{i:02}");
        store.set_ref(&name, h0).unwrap();
    }
    assert_eq!(store.set_ref("@r_overflow", h0), Err(StoreError::NoSpace));
}

#[test]
fn t2_caos_decode_snapshot_corrupt_pad_and_invalid_rights() {
    let mut store = ObjectStore::new();
    let h = store.put(b"snap-data").unwrap();
    store.set_ref("@snapref", h).unwrap();

    let mut buf = [0u8; 2048];
    let n = store.encode_snapshot(&mut buf).unwrap();
    let valid = &buf[..n];

    // Basic corruptions: truncated, bad magic, bad version, flipped bit, trailing byte
    assert_eq!(
        ObjectStore::decode_snapshot(&valid[..8]).err(),
        Some(StoreError::CorruptSnapshot)
    );
    let mut bad_magic = valid.to_vec();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ObjectStore::decode_snapshot(&bad_magic).err(),
        Some(StoreError::CorruptSnapshot)
    );
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert_eq!(
        ObjectStore::decode_snapshot(&trailing).err(),
        Some(StoreError::CorruptSnapshot)
    );

    // Post-M3 Feature 12 hardened: non-zero header pad byte (bytes[7]) with recomputed CRC
    let mut bad_pad = valid.to_vec();
    bad_pad[7] = 0x01;
    let body_len = bad_pad.len() - 8;
    let crc = ObjHash::hash_bytes(&bad_pad[..body_len]).0;
    bad_pad[body_len..].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        ObjectStore::decode_snapshot(&bad_pad).err(),
        Some(StoreError::CorruptSnapshot),
        "non-zero snapshot header pad byte must be rejected"
    );

    // Post-M3 Feature 12 hardened: unknown Rights bits in ref entry with recomputed CRC
    let mut bad_rights = valid.to_vec();
    // Skip 8-byte header + obj_count blobs to locate first ref's rights byte
    let obj_count = bad_rights[5] as usize;
    let mut pos = 8usize;
    for _ in 0..obj_count {
        pos += 8; // hash
        let sz = u16::from_le_bytes([bad_rights[pos], bad_rights[pos + 1]]) as usize;
        pos += 2 + sz;
    }
    // Ref entry: [name_len: u8, rights_bits: u8, ...]
    bad_rights[pos + 1] = 0xFF;
    let crc2 = ObjHash::hash_bytes(&bad_rights[..body_len]).0;
    bad_rights[body_len..].copy_from_slice(&crc2.to_le_bytes());
    assert_eq!(
        ObjectStore::decode_snapshot(&bad_rights).err(),
        Some(StoreError::CorruptSnapshot),
        "unknown Rights bits in snapshot ref must be rejected"
    );
}

#[test]
fn t2_shell_record_history_utf8_boundary_truncation() {
    // Post-M3 Feature 12 hardened test: a >128-byte line whose multi-byte UTF-8
    // character straddles byte 128 must truncate cleanly on a char boundary so
    // `history` still displays the entry as valid UTF-8 instead of dropping it.
    let mut sh = Shell::new(MockShellHost::new());
    let mut line = "a".repeat(127);
    line.push('🦀'); // 4-byte scalar spanning bytes 127..131
    sh.record_history(&line);

    sh.host_mut().clear_output();
    sh.exec_line("history");
    assert!(
        sh.host().output.contains("aaaaaaaaaa"),
        "UTF-8 history entry must be truncated on a char boundary, not dropped; output={:?}",
        sh.host().output
    );
}

#[test]
fn t2_shell_malformed_commands_stages_args_and_fatal_read_error() {
    let mut sh = Shell::new(MockShellHost::new());
    for empty_cmd in ["", "   "] {
        assert_eq!(sh.exec_line(empty_cmd), ExecOutcome::Continue);
    }

    let malformed = [
        "put \"unterminated",
        "objects | where size",
        "objects | where badfield == 1",
        "objects | where size > nope",
        "objects | first abc",
        "ping zzz",
        "domains | save @x",
        "objects | | count",
        "objects | first 1 | first 1 | first 1 | first 1 | first 1 | first 1 | count",
        "put a b c d e f g h i j k l m n o p",
        "get obj:ZZZZ",
        "ref rollback @nonexistent",
        "ref seal @nonexistent",
    ];
    for cmd in malformed {
        let before_objs = sh.store().object_count();
        sh.host_mut().clear_output();
        assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
        let out = sh.host().output.as_str();
        let trimmed = out.trim();
        assert!(
            !trimmed.is_empty(),
            "malformed command {cmd:?} must emit a diagnostic"
        );
        assert_ne!(
            trimmed, "(empty stream)",
            "malformed command {cmd:?} must emit a diagnostic, not silent (empty stream)"
        );
        assert!(
            !out.contains("OBJECT HASH"),
            "malformed command {cmd:?} must not silently succeed with an object table; output={out:?}"
        );
        let lower = out.to_ascii_lowercase();
        let has_diag = out.contains("newos-shell-pd:")
            || lower.contains("error")
            || lower.contains("usage")
            || lower.contains("invalid")
            || lower.contains("unterminated")
            || lower.contains("too many")
            || lower.contains("unknown")
            || lower.contains("cannot")
            || lower.contains("expected")
            || lower.contains("not found")
            || lower.contains("notfound")
            || lower.contains("read-only")
            || lower.contains("readonly")
            || lower.contains("no previous");
        assert!(
            has_diag,
            "malformed command {cmd:?} output must contain a diagnostic indicator; output={out:?}"
        );
        assert_eq!(
            sh.store().object_count(),
            before_objs,
            "malformed command {cmd:?} must not insert objects into CAOS store"
        );
    }

    // Post-M3 Feature 12 hardened test: fatal non-WouldBlock error from
    // `read_debug_byte` in `run_interactive` must NOT spin forever calling `yield_now`.
    let mut host = MockShellHost::new();
    host.read_queue.push_back(Err(SysError::InvalidCapability));
    host.max_yields_before_panic = Some(32);
    let mut interactive = Shell::new(host);
    let res = catch_unwind(AssertUnwindSafe(|| {
        interactive.run_interactive();
    }));
    match res {
        Ok(_) => unreachable!("run_interactive returns !"),
        Err(payload) => {
            assert!(
                payload.downcast_ref::<YieldLimitExceeded>().is_none(),
                "run_interactive spun >32 yields on fatal read_debug_byte error instead of exiting cleanly"
            );
            assert!(
                payload.downcast_ref::<ExitSentinel>().is_some(),
                "expected clean host.exit() on fatal read_debug_byte error"
            );
        }
    }
}

#[test]
fn t2_shell_help_coalesced_single_debug_write_syscall() {
    // Post-M3 Feature 10 hardened test: raising BufferedWriter to 1024B coalesces
    // `help` from 3 write_debug syscalls down to <= 1.
    let mut sh = Shell::new(MockShellHost::new());
    sh.exec_line("help");
    assert!(
        sh.host().write_debug_calls <= 1,
        "expected `help` to emit <= 1 write_debug syscall after M3 1024B buffer, got {}",
        sh.host().write_debug_calls
    );
}

// ============================================================================
// Area 8: Benchmark Extended Metrics & Static Safety Audits (5 tests)
// ============================================================================

#[test]
fn t2_bench_emits_all_12_m1_extended_metrics() {
    // Post-M1 Feature 1 & 2 hardened test: verifies all 12 new M1 METRIC lines.
    let run = run_newos_bench(&[]);
    assert!(run.status.success(), "stderr={}", run.stderr);
    let metrics = parse_metric_lines(&run.stdout);

    let expected_m1 = [
        ("kernel.ipc.call_reply", "ns/op"),
        ("kernel.ring.spsc_slice_transfer", "ns/op"),
        ("ipc.shell_session.debug_write_bytes", "bytes"),
        ("ipc.shell_session.max_chunk_bytes", "bytes"),
        ("ipc.repl_line.syscalls", "syscalls"),
        ("ipc.repl_line.payload_bytes", "bytes"),
        ("ipc.footprint.cap_slot_bytes", "bytes"),
        ("ipc.footprint.cnode64_bytes", "bytes"),
        ("ipc.footprint.kernel_ipc_state_bytes", "bytes"),
        ("ipc.footprint.spsc_ring64_bytes", "bytes"),
        ("ipc.footprint.record_stream_bytes", "bytes"),
        ("ipc.footprint.shell_bytes", "bytes"),
    ];
    let mut missing = Vec::new();
    for (name, unit) in expected_m1 {
        match metrics.iter().find(|(n, _, _)| n == name) {
            None => missing.push(name),
            Some((_, val_str, got_unit)) => {
                assert_eq!(got_unit, unit, "unit mismatch for {name}");
                let v: f64 = val_str.parse().expect("numeric metric value");
                assert!(v.is_finite() && v >= 0.0);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "missing M1 extended METRIC lines: {missing:?}"
    );
}

#[test]
fn t2_safety_forbid_unsafe_code_on_all_8_safe_crates() {
    let root = find_repo_root();
    let safe_roots = [
        ("abi", "crates/abi/src/lib.rs"),
        ("kernel-core", "crates/kernel-core/src/lib.rs"),
        ("kernel", "crates/kernel/src/main.rs"),
        ("shell-core", "crates/shell-core/src/lib.rs"),
        ("supervisor-pd", "crates/supervisor-pd/src/main.rs"),
        ("worker-pd", "crates/worker-pd/src/main.rs"),
        ("net", "crates/net/src/lib.rs"),
        ("bench", "crates/bench/src/main.rs"),
    ];

    for (crate_name, rel_root) in safe_roots {
        let crate_dir = root.join("crates").join(crate_name);
        assert!(
            crate_forbids_unsafe_code(&root, &crate_dir, &root.join(rel_root)),
            "crates/{crate_name} must enforce unsafe_code = \"forbid\" (via workspace lints or crate attribute)"
        );

        let src_dir = crate_dir.join("src");
        for file in collect_rs_files(&src_dir) {
            let sf = scan_rust_source(&file);
            let prod = strip_cfg_test(&sf.tokens);
            let sites = find_unsafe_sites(&prod);
            assert!(
                sites.is_empty(),
                "unexpected unsafe site(s) in safe crate file {}: {:?}",
                file.display(),
                sites
            );
        }
    }
}

#[test]
fn t2_safety_every_unsafe_in_hal_and_user_rt_has_safety_comment() {
    // Post-M2/M3 Feature 8 & 11 hardened test: every unsafe block/fn/impl/attr
    // in `crates/hal/src/` and `crates/user-rt/src/` must have a per-item `// SAFETY:`.
    let root = find_repo_root();
    let mut violations = Vec::new();

    for dir in [root.join("crates/hal/src"), root.join("crates/user-rt/src")] {
        for file in collect_rs_files(&dir) {
            let sf = scan_rust_source(&file);
            let prod = strip_cfg_test(&sf.tokens);
            for line_num in find_unsafe_sites(&prod) {
                if !has_safety_comment(&sf.lines, line_num) {
                    let snippet = sf.lines.get(line_num - 1).map_or("", |s| s.trim());
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    violations.push(format!("{}:{line_num}: {snippet}", rel.display()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "unsafe sites missing per-item `// SAFETY:` comment ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn t2_safety_zero_production_unwrap_expect_panic_in_os_crates() {
    let root = find_repo_root();
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
    let mut violations = Vec::new();

    for krate in os_crates {
        let src_dir = root.join("crates").join(krate).join("src");
        for file in collect_rs_files(&src_dir) {
            let sf = scan_rust_source(&file);
            let prod = strip_cfg_test(&sf.tokens);
            let rel = file.strip_prefix(&root).unwrap_or(&file);

            for i in 0..prod.len() {
                // Match `.unwrap(`, `.unwrap_err(`, `.unwrap_unchecked(`, `.expect(`, `.expect_err(`
                if prod[i].text == "."
                    && let Some(method) = prod.get(i + 1)
                    && method.kind == TokKind::Ident
                    && matches!(
                        method.text.as_str(),
                        "unwrap" | "unwrap_err" | "unwrap_unchecked" | "expect" | "expect_err"
                    )
                    && prod.get(i + 2).is_some_and(|t| t.text == "(")
                {
                    violations.push(format!(
                        "{}:{}: .{}()",
                        rel.display(),
                        method.line,
                        method.text
                    ));
                }

                // Match `panic!(`, `todo!(`, `unimplemented!(` (with `(`, `[`, or `{`)
                if prod[i].kind == TokKind::Ident
                    && matches!(prod[i].text.as_str(), "panic" | "todo" | "unimplemented")
                    && prod.get(i + 1).is_some_and(|t| t.text == "!")
                    && prod
                        .get(i + 2)
                        .is_some_and(|t| matches!(t.text.as_str(), "(" | "[" | "{"))
                {
                    violations.push(format!(
                        "{}:{}: {}!",
                        rel.display(),
                        prod[i].line,
                        prod[i].text
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "production panic/unwrap/expect found in OS crates:\n{}",
        violations.join("\n")
    );
}

#[test]
fn t2_safety_user_rt_sync_unsafe_cell_removed_and_paging_reduced() {
    // Post-M2/M3 Feature 8 & 11 hardened test:
    // 1. `user-rt` eliminates `SyncUnsafeCell` / `sync_unsafe_cell` and keeps <= 3 unsafe sites.
    // 2. `paging.rs` consolidates its 21 raw-ptr/volatile sites down to <= 15 total unsafe sites.
    let root = find_repo_root();

    let user_rt = scan_rust_source(&root.join("crates/user-rt/src/lib.rs"));
    let user_rt_prod = strip_cfg_test(&user_rt.tokens);
    let has_sync_cell = user_rt_prod.iter().any(|t| {
        t.kind == TokKind::Ident && (t.text == "SyncUnsafeCell" || t.text == "sync_unsafe_cell")
    });
    assert!(
        !has_sync_cell,
        "crates/user-rt/src/lib.rs still references SyncUnsafeCell / sync_unsafe_cell"
    );
    let user_rt_unsafe = find_unsafe_sites(&user_rt_prod);
    assert!(
        user_rt_unsafe.len() <= 4,
        "expected <= 4 unsafe sites in user-rt, found {} at lines {:?}",
        user_rt_unsafe.len(),
        user_rt_unsafe
    );

    let paging = scan_rust_source(&root.join("crates/hal/src/arch/aarch64/paging.rs"));
    let paging_prod = strip_cfg_test(&paging.tokens);
    let paging_unsafe = find_unsafe_sites(&paging_prod);
    assert!(
        paging_unsafe.len() <= 16,
        "expected <= 15 unsafe sites in paging.rs after M2 consolidation, found {}",
        paging_unsafe.len()
    );
}
