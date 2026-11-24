//! Tier 4 (Real-World Workloads & Invariants) E2E tests for `newos-abi` and `newos-kernel-core`.
//! Covers 4 full workload & invariant scenarios.

use std::thread;

use newos_abi::ring::SpscRing;
use newos_abi::{Rights, SysError};
use newos_kernel_core::cspace::{CapObject, Capability};
use newos_kernel_core::elf::parse_elf64;
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{PAGE_SIZE, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr};
use newos_kernel_core::sched::{Scheduler, ThreadId};

use crate::test_helpers::{MockVSpaceMapper, PhdrSpec, build_elf64, host_elf_machine};

#[test]
fn tier4_kernel_ipc_worker_ping_pong_ring_burst_and_scheduler_200_rounds() {
    let mut ipc = KernelIpcState::new();
    let (notif, req_ep, _) = ipc.init_bootstrap_caps(None).unwrap();
    let reply_ep = ipc
        .root_cspace
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();

    let mut sched = Scheduler::<16>::new();
    let supervisor = sched.spawn(10).unwrap();
    let worker_a = sched.spawn(10).unwrap();
    let worker_b = sched.spawn(10).unwrap();
    let _idle = sched.spawn(1).unwrap();

    let ring = SpscRing::<64>::new();
    let mut sup_turns = 0u64;
    let mut wa_turns = 0u64;
    let mut wb_turns = 0u64;

    const ROUNDS: u64 = 200;
    const BURST: u64 = 16;

    for round in 0..ROUNDS {
        // Supervisor turn
        let t = sched.schedule_next().unwrap();
        if t == supervisor {
            sup_turns += 1;
        } else if t == worker_a {
            wa_turns += 1;
        } else if t == worker_b {
            wb_turns += 1;
        } else {
            panic!("idle thread must never be scheduled while priority-10 threads are ready");
        }

        let mut expected_sum = 0u64;
        for w in 0..BURST {
            let word = (round << 8) | w;
            expected_sum = expected_sum.wrapping_add(word);
            assert_eq!(ring.try_push(word), Ok(()));
        }
        assert_eq!(ipc.notify_signal(notif, 1), Ok(()));
        assert_eq!(ipc.ipc_send(req_ep, expected_sum), Ok(()));
        assert!(sched.yield_current().is_some());

        // Worker turn: drain ring, verify checksum, reply on reply_ep.
        assert_eq!(ipc.notify_poll(notif), Ok(1));
        let req = ipc.ipc_recv(req_ep).unwrap();
        assert_eq!(req.badge, 0x5E14);
        let mut actual_sum = 0u64;
        for _ in 0..BURST {
            actual_sum = actual_sum.wrapping_add(ring.try_pop().unwrap());
        }
        assert_eq!(actual_sum, req.payload);
        assert!(ring.is_empty());
        assert_eq!(ipc.ipc_send(reply_ep, actual_sum.wrapping_add(1)), Ok(()));

        // Supervisor receives reply.
        assert_eq!(
            ipc.ipc_recv(reply_ep),
            Ok(IpcMessage {
                badge: 0,
                payload: expected_sum.wrapping_add(1),
            })
        );
    }

    // All 3 priority-10 threads must share turns fairly (within +-1 of ROUNDS/3).
    assert_eq!(sup_turns + wa_turns + wb_turns, ROUNDS);
    let min_turns = sup_turns.min(wa_turns).min(wb_turns);
    let max_turns = sup_turns.max(wa_turns).max(wb_turns);
    assert!(
        max_turns - min_turns <= 1,
        "round-robin fairness violated: sup={sup_turns}, wa={wa_turns}, wb={wb_turns}"
    );
}

#[test]
fn tier4_kernel_multi_tenant_cdt_isolation_and_untyped_lifecycle() {
    let mut ipc = KernelIpcState::new();
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x100_0000, 16 * PAGE_SIZE));

    let untyped = ipc
        .root_cspace
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::ALL,
        ))
        .unwrap();
    let ep_root = ipc
        .root_cspace
        .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
        .unwrap();

    // Provision Tenant A (3 frames + badged ep) and Tenant B (3 frames + badged ep).
    let slot_a = ipc.root_cspace.find_free_slot().unwrap();
    let ep_a = ipc
        .root_cspace
        .mint(
            ep_root,
            slot_a,
            Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
            Some(0xA000),
        )
        .unwrap();
    let slot_b = ipc.root_cspace.find_free_slot().unwrap();
    let ep_b = ipc
        .root_cspace
        .mint(
            ep_root,
            slot_b,
            Rights::READ.union(Rights::WRITE),
            Some(0xB000),
        )
        .unwrap();

    // Tenant A delegates a copy of its badged endpoint to a sub-worker.
    let sub_slot = ipc.root_cspace.find_free_slot().unwrap();
    let ep_a_sub = ipc.root_cspace.copy(ep_a, sub_slot).unwrap();

    // Retype 6 physical frames from untyped.
    let mut frame_caps = Vec::new();
    for _ in 0..6 {
        frame_caps.push(
            ipc.root_cspace
                .retype_frame_from(untyped, &mut inv)
                .unwrap(),
        );
    }
    assert_eq!(inv.retyped_frames(), 6);
    assert_eq!(inv.remaining_bytes(), 10 * PAGE_SIZE);

    // Sub-worker sends with Tenant A's badge; Tenant B sends with Tenant B's badge.
    assert_eq!(ipc.ipc_send(ep_a_sub, 1), Ok(()));
    assert_eq!(ipc.ipc_recv(ep_root).unwrap().badge, 0xA000);
    assert_eq!(ipc.ipc_send(ep_b, 2), Ok(()));
    assert_eq!(ipc.ipc_recv(ep_root).unwrap().badge, 0xB000);

    // Revoke Tenant A's entire subtree (delete ep_a after revoking its root or delete both).
    assert_eq!(ipc.root_cspace.delete(ep_a), Ok(()));
    // Revoking ep_root wipes remaining descendants (ep_a_sub and ep_b).
    assert_eq!(ipc.root_cspace.revoke(ep_root), Ok(2));
    assert_eq!(ipc.ipc_send(ep_a_sub, 3), Err(SysError::InvalidCapability));
    assert_eq!(ipc.ipc_send(ep_b, 4), Err(SysError::InvalidCapability));

    // Revoke all 6 retyped frames in one operation.
    assert_eq!(ipc.root_cspace.revoke(untyped), Ok(6));
    assert_eq!(ipc.root_cspace.occupied_count(), 2); // untyped + ep_root
    let _ = frame_caps;
}

#[test]
fn tier4_kernel_elf64_load_wx_and_bss_zeroing_invariant() {
    // 3 segments: RX text, RO rodata, RW data+BSS (2 pages).
    let text = [0x01u8; 64];
    let rodata = [0x02u8; 32];
    let data = [0x03u8; 48];
    let mut payload = Vec::new();
    payload.extend_from_slice(&text);
    payload.extend_from_slice(&rodata);
    payload.extend_from_slice(&data);

    let base_off = (64 + 3 * 56) as u64;
    let phdrs = [
        PhdrSpec {
            p_type: 1,
            p_flags: 5, // RX
            p_offset: base_off,
            p_vaddr: 0x0040_0000,
            p_filesz: text.len() as u64,
            p_memsz: text.len() as u64,
        },
        PhdrSpec {
            p_type: 1,
            p_flags: 4, // RO
            p_offset: base_off + text.len() as u64,
            p_vaddr: 0x0040_1000,
            p_filesz: rodata.len() as u64,
            p_memsz: rodata.len() as u64,
        },
        PhdrSpec {
            p_type: 1,
            p_flags: 6, // RW + multi-page BSS
            p_offset: base_off + (text.len() + rodata.len()) as u64,
            p_vaddr: 0x0040_2000,
            p_filesz: data.len() as u64,
            p_memsz: 2 * PAGE_SIZE,
        },
    ];
    let elf_bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &payload);
    let parsed = parse_elf64(&elf_bytes).unwrap();

    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x200_0000, 16 * PAGE_SIZE));
    let mut mapper = MockVSpaceMapper::new(PhysAddr::new(0x10_0000));

    for seg in parsed.segments() {
        // Strict W^X invariant on every parsed segment.
        assert!(!(seg.flags.writable && seg.flags.executable));
        let pages = seg.mem_size.div_ceil(PAGE_SIZE);
        for page_idx in 0..pages {
            let frame = inv.retype_frame().unwrap();
            mapper.zero_frame(&frame);
            let page_file_start = (page_idx as usize) * (PAGE_SIZE as usize);
            if page_file_start < seg.file_size {
                let copy_len = (seg.file_size - page_file_start).min(PAGE_SIZE as usize);
                let src = &elf_bytes[seg.file_offset + page_file_start
                    ..seg.file_offset + page_file_start + copy_len];
                mapper.write_frame_bytes(&frame, 0, src).unwrap();
            }
            let va = VirtAddr::new_page_aligned(seg.vaddr + page_idx * PAGE_SIZE).unwrap();
            mapper.map_4k(va, frame, seg.flags, &mut inv).unwrap();
        }
    }

    assert_eq!(mapper.mapping_count(), 4); // 1 RX + 1 RO + 2 RW/BSS pages
    // Second BSS page must be 100% zeroed.
    let (bss2_phys, bss2_flags) = mapper
        .translate(VirtAddr::new_canonical(0x0040_3000).unwrap())
        .unwrap();
    assert!(bss2_flags.writable && !bss2_flags.executable);
    assert!(
        mapper
            .read_frame_slice(bss2_phys, 0, PAGE_SIZE as usize)
            .iter()
            .all(|&b| b == 0)
    );
}

#[test]
fn tier4_kernel_spsc_ring_concurrent_conservation_invariant() {
    let ring = SpscRing::<128>::new();
    const N: u64 = 20_000;
    let expected_xor: u64 = (0..N).fold(0u64, |acc, x| acc ^ x.wrapping_mul(0x9E37_79B9_7F4A_7C15));

    thread::scope(|s| {
        s.spawn(|| {
            for i in 0..N {
                let val = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                while ring.try_push(val).is_err() {
                    thread::yield_now();
                }
            }
        });
        let consumer = s.spawn(|| {
            let mut count = 0u64;
            let mut actual_xor = 0u64;
            while count < N {
                if let Some(val) = ring.try_pop() {
                    let expected_val = count.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                    assert_eq!(val, expected_val, "FIFO violation at item {count}");
                    actual_xor ^= val;
                    count += 1;
                } else {
                    thread::yield_now();
                }
            }
            (count, actual_xor)
        });
        let (count, actual_xor) = consumer.join().unwrap();
        assert_eq!(count, N);
        assert_eq!(actual_xor, expected_xor);
    });
    assert!(ring.is_empty());
    let _ = ThreadId(0);
}

#[test]
fn tier4_kernel_designated_authority_negative_invariants() {
    use newos_abi::{CapId, ObjectType};

    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();
    let _ = ipc.init_worker_pd_bootstrap_caps(1).unwrap();
    let (_, w1_cnode) = ipc.register_child_caps_in_root(1).unwrap();

    // 1. Worker cannot access PowerControl, VSpace, or Console::READ.
    assert_eq!(
        ipc.validate_power_for(1, CapId::BOOTSTRAP_POWER, Rights::WRITE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        ipc.validate_vspace_for(1, CapId::BOOTSTRAP_VSPACE, Rights::WRITE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        ipc.validate_console_for(1, CapId::BOOTSTRAP_CONSOLE, Rights::READ),
        Err(SysError::InvalidCapability)
    );

    // 2. Explicit Some(0) badge is rejected; cross-process CDT revocation cascades cleanly.
    assert_eq!(
        ipc.cap_grant_between(0, w1_cnode, notif, Rights::READ, Some(0)),
        Err(SysError::InvalidArgument)
    );
    let granted = ipc
        .cap_grant_between(
            0,
            w1_cnode,
            notif,
            Rights::READ,
            Some(0xFACE_B00C_1234_5678),
        )
        .unwrap();
    assert_eq!(ipc.cap_revoke_for(0, notif), Ok(1));
    assert_eq!(
        ipc.notify_poll_for(1, granted),
        Err(SysError::InvalidCapability)
    );

    // 3. UntypedRetype honors designated region_index and collects revoked frames.
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x9000_0000, PAGE_SIZE));
    let frame_cap = ipc
        .untyped_retype_for(0, CapId::BOOTSTRAP_UNTYPED, ObjectType::Frame, 0, &mut inv)
        .unwrap();
    assert_eq!(
        ipc.validate_frame_for(0, frame_cap, Rights::READ),
        Ok(PhysAddr::new(0x9000_0000))
    );
    let mut revoked_frames = [None; 4];
    let (caps, frames) = ipc
        .cap_revoke_for_collecting_frames(0, CapId::BOOTSTRAP_UNTYPED, &mut revoked_frames)
        .unwrap();
    assert_eq!(caps, 1);
    assert_eq!(frames, 1);
    assert_eq!(revoked_frames[0], Some(PhysAddr::new(0x9000_0000)));
}
