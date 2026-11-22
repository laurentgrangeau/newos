//! Tier 3 (Cross-Feature Combinations) E2E tests for `newos-abi` and `newos-kernel-core`.
//! Covers 6 cross-subsystem integration tests.

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, Rights, SysError};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::parse_elf64;
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{PAGE_SIZE, PhysAddr, UntypedInventory, VSpaceMapper, VirtAddr};
use newos_kernel_core::sched::Scheduler;

use crate::test_helpers::{MockVSpaceMapper, PhdrSpec, build_elf64, host_elf_machine};

#[test]
fn tier3_cspace_ipc_revoke_isolates_revoked_worker_only() {
    let mut ipc = KernelIpcState::new();
    let root_ep = ipc
        .root_cspace
        .insert_root(Capability::new(CapObject::Endpoint { id: 3 }, Rights::ALL))
        .unwrap();

    let s1 = ipc.root_cspace.find_free_slot().unwrap();
    let worker1_ep = ipc
        .root_cspace
        .mint(root_ep, s1, Rights::READ.union(Rights::WRITE), Some(0x1001))
        .unwrap();
    let s2 = ipc.root_cspace.find_free_slot().unwrap();
    let worker2_ep = ipc
        .root_cspace
        .mint(root_ep, s2, Rights::READ.union(Rights::WRITE), Some(0x2002))
        .unwrap();

    assert_eq!(ipc.ipc_send(worker1_ep, 100), Ok(()));
    assert_eq!(
        ipc.ipc_recv(root_ep),
        Ok(IpcMessage {
            badge: 0x1001,
            payload: 100,
        })
    );

    // Delete worker1_ep; worker2_ep must keep operating uninterrupted.
    assert_eq!(ipc.root_cspace.delete(worker1_ep), Ok(()));
    assert_eq!(
        ipc.ipc_send(worker1_ep, 200),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(ipc.ipc_recv(worker1_ep), Err(SysError::InvalidCapability));

    assert_eq!(ipc.ipc_send(worker2_ep, 300), Ok(()));
    assert_eq!(
        ipc.ipc_recv(root_ep),
        Ok(IpcMessage {
            badge: 0x2002,
            payload: 300,
        })
    );
}

#[test]
fn tier3_spsc_ring_burst_with_coalesced_notification() {
    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();
    let ring = SpscRing::<64>::new();

    // Producer enqueues a 32-word burst and fires a single coalesced notification.
    for i in 0..32u64 {
        assert_eq!(ring.try_push(0xA000 + i), Ok(()));
    }
    assert_eq!(ipc.notify_signal(notif, 1 << 0), Ok(()));

    // Consumer polls notification once, then drains all 32 words in exact FIFO order.
    assert_eq!(ipc.notify_poll(notif), Ok(1));
    for i in 0..32u64 {
        assert_eq!(ring.try_pop(), Some(0xA000 + i));
    }
    assert!(ring.is_empty());
    assert_eq!(ipc.notify_poll(notif), Ok(0));
}

#[test]
fn tier3_untyped_cnode_retype_and_transitive_cdt_revoke() {
    let mut cnode = CNode::<64>::new();
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x40_0000, 8 * PAGE_SIZE));

    let untyped_cap = cnode
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::ALL,
        ))
        .unwrap();

    let mut frames = Vec::new();
    for _ in 0..4 {
        frames.push(cnode.retype_frame_from(untyped_cap, &mut inv).unwrap());
    }
    let s1 = cnode.find_free_slot().unwrap();
    let ro0 = cnode.mint(frames[0], s1, Rights::READ, None).unwrap();
    let s2 = cnode.find_free_slot().unwrap();
    let ro1 = cnode.mint(frames[1], s2, Rights::READ, None).unwrap();

    assert_eq!(cnode.occupied_count(), 7); // 1 untyped + 4 frames + 2 RO copies
    assert_eq!(inv.retyped_frames(), 4);

    // Revoking untyped_cap must transitively revoke all 6 derived caps.
    assert_eq!(cnode.revoke(untyped_cap), Ok(6));
    assert_eq!(cnode.occupied_count(), 1);
    for cap in frames.into_iter().chain([ro0, ro1]) {
        assert_eq!(
            cnode.lookup(cap, Rights::NONE),
            Err(SysError::InvalidCapability)
        );
    }
}

#[test]
fn tier3_cnode_move_cap_preserves_ipc_badge_and_invalidates_old_id() {
    let mut ipc = KernelIpcState::new();
    let root_ep = ipc
        .root_cspace
        .insert_root(Capability::new(CapObject::Endpoint { id: 5 }, Rights::ALL))
        .unwrap();
    let s1 = ipc.root_cspace.find_free_slot().unwrap();
    let badged = ipc
        .root_cspace
        .mint(root_ep, s1, Rights::READ.union(Rights::WRITE), Some(0xBEEF))
        .unwrap();

    let s2 = ipc.root_cspace.find_free_slot().unwrap();
    let moved = ipc.root_cspace.move_cap(badged, s2).unwrap();

    assert_eq!(ipc.ipc_send(badged, 1), Err(SysError::InvalidCapability));
    assert_eq!(ipc.ipc_send(moved, 0x9999), Ok(()));
    assert_eq!(
        ipc.ipc_recv(root_ep),
        Ok(IpcMessage {
            badge: 0xBEEF,
            payload: 0x9999,
        })
    );
}

#[test]
fn tier3_elf64_untyped_and_mock_vspace_mapper_wx_and_bss() {
    let code_bytes = [0x90u8, 0x90, 0xC3, 0x90];
    let data_bytes = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let mut payload = Vec::new();
    payload.extend_from_slice(&code_bytes);
    payload.extend_from_slice(&data_bytes);

    let base_off = (64 + 2 * 56) as u64;
    let phdrs = [
        PhdrSpec {
            p_type: 1,
            p_flags: 5, // RX
            p_offset: base_off,
            p_vaddr: 0x0040_0000,
            p_filesz: 4,
            p_memsz: 4,
        },
        PhdrSpec {
            p_type: 1,
            p_flags: 6, // RW + BSS
            p_offset: base_off + 4,
            p_vaddr: 0x0040_1000,
            p_filesz: 4,
            p_memsz: PAGE_SIZE,
        },
    ];
    let elf_bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &payload);
    let parsed = parse_elf64(&elf_bytes).unwrap();

    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x80_0000, 8 * PAGE_SIZE));
    let mut mapper = MockVSpaceMapper::new(PhysAddr::new(0x1_0000));

    for seg in parsed.segments() {
        let frame = inv.retype_frame().unwrap();
        mapper.zero_frame(&frame);
        let src = &elf_bytes[seg.file_offset..seg.file_offset + seg.file_size];
        mapper.write_frame_bytes(&frame, 0, src).unwrap();
        let va = VirtAddr::new_page_aligned(seg.vaddr).unwrap();
        mapper.map_4k(va, frame, seg.flags, &mut inv).unwrap();
    }

    assert_eq!(mapper.mapping_count(), 2);
    let (code_phys, code_flags) = mapper
        .translate(VirtAddr::new_canonical(0x0040_0000).unwrap())
        .unwrap();
    assert!(code_flags.executable && !code_flags.writable);
    assert_eq!(mapper.read_frame_slice(code_phys, 0, 4), code_bytes);

    let (data_phys, data_flags) = mapper
        .translate(VirtAddr::new_canonical(0x0040_1000).unwrap())
        .unwrap();
    assert!(data_flags.writable && !data_flags.executable);
    assert_eq!(mapper.read_frame_slice(data_phys, 0, 4), data_bytes);
    // BSS tail must be zeroed.
    assert!(
        mapper
            .read_frame_slice(data_phys, 4, (PAGE_SIZE as usize) - 4)
            .iter()
            .all(|&b| b == 0)
    );
}

#[test]
fn tier3_scheduler_ipc_and_mmio_driver_loop() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc
        .init_bootstrap_caps(Some((PhysAddr::new(0xFE00_0000), 0x1000)))
        .unwrap();

    let mut sched = Scheduler::<8>::new();
    let driver = sched.spawn(20).unwrap();
    let client = sched.spawn(20).unwrap();
    let _idle = sched.spawn(1).unwrap();

    // Round 1: driver runs, validates MMIO register access, signals readiness.
    assert_eq!(sched.schedule_next(), Some(driver));
    let reg_phys = ipc
        .validate_mmio_write32(CapId::BOOTSTRAP_NET_MMIO, 0x10)
        .unwrap();
    assert_eq!(reg_phys, PhysAddr::new(0xFE00_0010));
    assert_eq!(ipc.notify_signal(notif, 0x1), Ok(()));
    assert_eq!(sched.yield_current(), Some(1));

    // Round 2: client runs, polls driver ready bit, sends IPC request.
    assert_eq!(ipc.notify_poll(notif), Ok(0x1));
    assert_eq!(ipc.ipc_send(ep, 0x7777), Ok(()));
    assert_eq!(sched.yield_current(), Some(1));

    // Round 3: driver receives IPC request with bootstrap badge.
    assert_eq!(
        ipc.ipc_recv(ep),
        Ok(IpcMessage {
            badge: 0x5E14,
            payload: 0x7777,
        })
    );
    let _ = client;
}
