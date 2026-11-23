//! Tier 1 (Feature Coverage) E2E tests for `newos-abi` and `newos-kernel-core`.
//! Covers 7 feature areas x 5 isolated happy-path tests = 35 tests.

use std::thread;

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, Rights, ShutdownStatus, SysError, SyscallNumber};
use newos_kernel_core::BootInfo;
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::{MAX_LOAD_SEGMENTS, parse_elf64};
use newos_kernel_core::ipc::{IpcMessage, KernelIpcState};
use newos_kernel_core::memory::{
    PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory, UntypedRegion, VirtAddr,
};
use newos_kernel_core::sched::{Scheduler, ThreadId};

use crate::test_helpers::{PhdrSpec, build_elf64, host_elf_machine};

// ============================================================================
// 1. ABI Primitives (5 tests)
// ============================================================================

#[test]
fn tier1_abi_cap_id_bootstrap_constants_and_raw_roundtrip() {
    assert!(CapId::NULL.is_null());
    assert_eq!(CapId::NULL.raw(), 0);

    let caps = [
        CapId::BOOTSTRAP_NOTIF,
        CapId::BOOTSTRAP_EP,
        CapId::BOOTSTRAP_FAULT_NOTIF,
        CapId::BOOTSTRAP_NET_MMIO,
    ];
    for (i, cap) in caps.iter().enumerate() {
        assert!(!cap.is_null(), "bootstrap cap {i} must not be null");
        assert_eq!(CapId::new(cap.raw()), *cap);
        for (j, other) in caps.iter().enumerate() {
            if i != j {
                assert_ne!(cap, other, "bootstrap caps {i} and {j} must be distinct");
            }
        }
    }
    let custom = CapId::new(0x0002_0000_0000_0015);
    assert_eq!(custom.raw(), 0x0002_0000_0000_0015);
    assert!(!custom.is_null());
}

#[test]
fn tier1_abi_rights_union_attenuate_contains() {
    assert_eq!(Rights::NONE.bits(), 0);
    let rw = Rights::READ.union(Rights::WRITE);
    assert!(rw.contains(Rights::READ));
    assert!(rw.contains(Rights::WRITE));
    assert!(!rw.contains(Rights::EXEC));
    assert!(!rw.contains(Rights::GRANT));
    assert!(!rw.contains(Rights::REVOKE));

    let ro = rw.attenuate(Rights::READ);
    assert_eq!(ro, Rights::READ);
    assert!(Rights::ALL.contains(Rights::READ));
    assert!(Rights::ALL.contains(Rights::WRITE));
    assert!(Rights::ALL.contains(Rights::EXEC));
    assert!(Rights::ALL.contains(Rights::GRANT));
    assert!(Rights::ALL.contains(Rights::REVOKE));
}

#[test]
fn tier1_abi_syscall_number_roundtrip_all_14() {
    let expected = [
        (1, SyscallNumber::DebugWrite),
        (2, SyscallNumber::Yield),
        (3, SyscallNumber::Exit),
        (4, SyscallNumber::NotifySignal),
        (5, SyscallNumber::NotifyPoll),
        (6, SyscallNumber::IpcSend),
        (7, SyscallNumber::IpcRecv),
        (8, SyscallNumber::ReadCycles),
        (9, SyscallNumber::SetFaultHandler),
        (10, SyscallNumber::MmioRead32),
        (11, SyscallNumber::DebugRead),
        (12, SyscallNumber::SysInfo),
        (13, SyscallNumber::MmioWrite32),
        (14, SyscallNumber::VirtToPhys),
    ];
    for (raw, variant) in expected {
        assert_eq!(variant as u64, raw);
        assert_eq!(SyscallNumber::from_u64(raw), Some(variant));
    }
}

#[test]
fn tier1_abi_sys_error_roundtrip_all_7() {
    let expected = [
        (1, SysError::InvalidCapability),
        (2, SysError::InsufficientRights),
        (3, SysError::OutOfMemory),
        (4, SysError::InvalidArgument),
        (5, SysError::SlotOccupied),
        (6, SysError::WouldBlock),
        (7, SysError::Unsupported),
    ];
    for (raw, variant) in expected {
        assert_eq!(variant as u64, raw);
        assert_eq!(SysError::from_u64(raw), Some(variant));
    }
}

#[test]
fn tier1_abi_object_type_and_qemu_exit_discriminants() {
    assert_eq!(ObjectType::Untyped as u8, 0);
    assert_eq!(ObjectType::Frame as u8, 1);
    assert_eq!(ObjectType::PageTable as u8, 2);
    assert_eq!(ObjectType::VSpace as u8, 3);
    assert_eq!(ObjectType::CNode as u8, 4);
    assert_eq!(ObjectType::Thread as u8, 5);
    assert_eq!(ObjectType::Endpoint as u8, 6);
    assert_eq!(ObjectType::Notification as u8, 7);
    assert_eq!(ObjectType::IrqHandler as u8, 8);
    assert_eq!(ObjectType::MmioRegion as u8, 9);

    assert_eq!(ShutdownStatus::Success as u32, 0);
    assert_eq!(ShutdownStatus::Failed as u32, 1);
}

// ============================================================================
// 2. SpscRing (5 tests)
// ============================================================================

#[test]
fn tier1_ring_new_and_default_empty_capacity() {
    let r1 = SpscRing::<8>::new();
    let r2 = SpscRing::<8>::default();
    assert_eq!(r1.capacity(), 7);
    assert_eq!(r2.capacity(), 7);
    assert!(r1.is_empty());
    assert!(r2.is_empty());
}

#[test]
fn tier1_ring_fifo_ordering_single_and_multi_word() {
    let ring = SpscRing::<16>::new();
    for i in 1..=10u64 {
        assert_eq!(ring.try_push(i * 100), Ok(()));
    }
    assert!(!ring.is_empty());
    for i in 1..=10u64 {
        assert_eq!(ring.try_pop(), Some(i * 100));
    }
    assert!(ring.is_empty());
}

#[test]
fn tier1_ring_wraparound_multiple_epochs() {
    let ring = SpscRing::<8>::new();
    let mut next_push = 0u64;
    let mut next_pop = 0u64;
    for _epoch in 0..20 {
        for _ in 0..5 {
            assert_eq!(ring.try_push(next_push), Ok(()));
            next_push += 1;
        }
        for _ in 0..5 {
            assert_eq!(ring.try_pop(), Some(next_pop));
            next_pop += 1;
        }
    }
    assert_eq!(next_push, 100);
    assert_eq!(next_pop, 100);
    assert!(ring.is_empty());
}

#[test]
fn tier1_ring_power_of_two_sizes() {
    assert_eq!(SpscRing::<2>::new().capacity(), 1);
    assert_eq!(SpscRing::<4>::new().capacity(), 3);
    assert_eq!(SpscRing::<16>::new().capacity(), 15);
    assert_eq!(SpscRing::<64>::new().capacity(), 63);
    assert_eq!(SpscRing::<256>::new().capacity(), 255);
}

#[test]
fn tier1_ring_concurrent_spsc_two_threads() {
    let ring = SpscRing::<64>::new();
    const COUNT: u64 = 5_000;

    thread::scope(|s| {
        s.spawn(|| {
            for i in 0..COUNT {
                while ring.try_push(i).is_err() {
                    thread::yield_now();
                }
            }
        });
        let consumer = s.spawn(|| {
            let mut expected = 0u64;
            while expected < COUNT {
                if let Some(val) = ring.try_pop() {
                    assert_eq!(val, expected);
                    expected += 1;
                } else {
                    thread::yield_now();
                }
            }
            expected
        });
        assert_eq!(consumer.join().unwrap(), COUNT);
    });
    assert!(ring.is_empty());
}

// ============================================================================
// 3. CSpace & CDT (5 tests)
// ============================================================================

#[test]
fn tier1_cspace_insert_root_lookup_occupied_count() {
    let mut cnode = CNode::<16>::new();
    assert_eq!(cnode.occupied_count(), 0);

    let ep = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let nt = cnode
        .insert_root(Capability::new(
            CapObject::Notification { id: 1 },
            Rights::READ.union(Rights::WRITE),
        ))
        .unwrap();
    let fr = cnode
        .insert_root(Capability::new(
            CapObject::Frame {
                phys: PhysAddr::new(0x2000),
            },
            Rights::READ,
        ))
        .unwrap();

    assert_eq!(cnode.occupied_count(), 3);
    assert_eq!(
        cnode.lookup(ep, Rights::READ).unwrap().object.object_type(),
        ObjectType::Endpoint
    );
    assert_eq!(
        cnode
            .lookup(nt, Rights::WRITE)
            .unwrap()
            .object
            .object_type(),
        ObjectType::Notification
    );
    assert_eq!(
        cnode.lookup(fr, Rights::READ).unwrap().object.object_type(),
        ObjectType::Frame
    );
}

#[test]
fn tier1_cspace_mint_attenuates_rights_and_applies_badge() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
        .unwrap();
    let child_slot = cnode.find_free_slot().unwrap();
    let child = cnode
        .mint(root, child_slot, Rights::WRITE, Some(0xCAFE))
        .unwrap();

    let child_cap = cnode.lookup(child, Rights::WRITE).unwrap();
    assert_eq!(child_cap.rights, Rights::WRITE);
    assert_eq!(child_cap.badge, 0xCAFE);

    // Parent remains completely intact.
    let parent_cap = cnode.lookup(root, Rights::ALL).unwrap();
    assert_eq!(parent_cap.rights, Rights::ALL);
    assert_eq!(parent_cap.badge, 0);
}

#[test]
fn tier1_cspace_copy_preserves_rights_and_badge() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let s1 = cnode.find_free_slot().unwrap();
    let badged = cnode
        .mint(
            root,
            s1,
            Rights::READ.union(Rights::GRANT),
            Some(0x1234_5678),
        )
        .unwrap();
    let s2 = cnode.find_free_slot().unwrap();
    let copied = cnode.copy(badged, s2).unwrap();

    let copied_cap = cnode.lookup(copied, Rights::READ).unwrap();
    assert_eq!(copied_cap.rights, Rights::READ.union(Rights::GRANT));
    assert_eq!(copied_cap.badge, 0x1234_5678);
    assert_eq!(cnode.occupied_count(), 3);
}

#[test]
fn tier1_cspace_move_cap_transfers_slot_and_reparents_children() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let child_slot = cnode.find_free_slot().unwrap();
    let child = cnode.copy(root, child_slot).unwrap();

    let new_root_slot = cnode.find_free_slot().unwrap();
    let moved_root = cnode.move_cap(root, new_root_slot).unwrap();

    assert_eq!(
        cnode.lookup(root, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(moved_root, Rights::ALL).is_ok());

    // Revoking via moved_root must still transitively revoke child.
    assert_eq!(cnode.revoke(moved_root), Ok(1));
    assert_eq!(
        cnode.lookup(child, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
}

#[test]
fn tier1_cspace_delete_and_transitive_revoke() {
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let unrelated = cnode
        .insert_root(Capability::new(
            CapObject::Notification { id: 0 },
            Rights::ALL,
        ))
        .unwrap();

    let s1 = cnode.find_free_slot().unwrap();
    let child = cnode.copy(root, s1).unwrap();
    let s2 = cnode.find_free_slot().unwrap();
    let grandchild = cnode.copy(child, s2).unwrap();
    let s3 = cnode.find_free_slot().unwrap();
    let great_grandchild = cnode.copy(grandchild, s3).unwrap();

    // Deleting middle node reparents grandchild to root.
    assert_eq!(cnode.delete(child), Ok(()));
    assert!(cnode.lookup(grandchild, Rights::READ).is_ok());

    // Revoking root removes both remaining descendants while leaving root and unrelated intact.
    assert_eq!(cnode.revoke(root), Ok(2));
    assert_eq!(
        cnode.lookup(grandchild, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(great_grandchild, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(root, Rights::ALL).is_ok());
    assert!(cnode.lookup(unrelated, Rights::ALL).is_ok());
    assert_eq!(cnode.occupied_count(), 2);
}

// ============================================================================
// 4. Kernel IPC & MMIO (5 tests)
// ============================================================================

#[test]
fn tier1_ipc_bootstrap_caps_layout() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, fault) = ipc
        .init_bootstrap_caps(Some((PhysAddr::new(0x1000_0000), 0x1000)))
        .unwrap();
    assert_eq!(notif, CapId::BOOTSTRAP_NOTIF);
    assert_eq!(ep, CapId::BOOTSTRAP_EP);
    assert_eq!(fault, CapId::BOOTSTRAP_FAULT_NOTIF);

    let ep_cap = ipc.root_cspace.lookup(ep, Rights::ALL).unwrap();
    assert_eq!(ep_cap.badge, 0x5E14);
    assert_eq!(ipc.root_cspace.occupied_count(), 15);
    assert_eq!(
        ipc.validate_mmio_read32(CapId::BOOTSTRAP_NET_MMIO, 0),
        Ok(PhysAddr::new(0x1000_0000))
    );
    assert_eq!(
        ipc.validate_console_for(
            0,
            CapId::BOOTSTRAP_CONSOLE,
            Rights::READ.union(Rights::WRITE)
        ),
        Ok(())
    );
    assert_eq!(
        ipc.validate_power_for(0, CapId::BOOTSTRAP_POWER, Rights::READ.union(Rights::WRITE)),
        Ok(())
    );
    assert_eq!(
        ipc.validate_vspace_for(
            0,
            CapId::BOOTSTRAP_VSPACE,
            Rights::READ.union(Rights::WRITE)
        ),
        Ok(PhysAddr::new(0))
    );
}

#[test]
fn tier1_ipc_notify_signal_coalesce_and_poll_clear() {
    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(ipc.notify_signal(notif, 1 << 0), Ok(()));
    assert_eq!(ipc.notify_signal(notif, 1 << 4), Ok(()));
    assert_eq!(ipc.notify_signal(notif, 0xF000), Ok(()));
    assert_eq!(ipc.notify_poll(notif), Ok(0xF011));
    assert_eq!(ipc.notify_poll(notif), Ok(0));
}

#[test]
fn tier1_ipc_notify_badged_cap_overrides_caller_badge() {
    let mut ipc = KernelIpcState::new();
    let (notif, _, _) = ipc.init_bootstrap_caps(None).unwrap();
    let slot = ipc.root_cspace.find_free_slot().unwrap();
    let badged = ipc
        .root_cspace
        .mint(notif, slot, Rights::WRITE, Some(0x0080))
        .unwrap();

    // Caller supplies 0xFFFF, but cap's fixed badge 0x0080 must be OR'd instead.
    assert_eq!(ipc.notify_signal(badged, 0xFFFF), Ok(()));
    assert_eq!(ipc.notify_poll(notif), Ok(0x0080));
}

#[test]
fn tier1_ipc_endpoint_send_recv_stamps_badge() {
    let mut ipc = KernelIpcState::new();
    let (_, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(ipc.ipc_send(ep, 0xA110_C0DE), Ok(()));
    assert_eq!(
        ipc.ipc_recv(ep),
        Ok(IpcMessage {
            badge: 0x5E14,
            payload: 0xA110_C0DE,
        })
    );
    // Slot is now free for another message.
    assert_eq!(ipc.ipc_send(ep, 0x42), Ok(()));
    assert_eq!(
        ipc.ipc_recv(ep),
        Ok(IpcMessage {
            badge: 0x5E14,
            payload: 0x42,
        })
    );
}

#[test]
fn tier1_ipc_mmio_validate_read32_and_write32() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(Some((PhysAddr::new(0xFE00_0000), 0x100)))
        .unwrap();

    assert_eq!(
        ipc.validate_mmio_read32(CapId::BOOTSTRAP_NET_MMIO, 0),
        Ok(PhysAddr::new(0xFE00_0000))
    );
    assert_eq!(
        ipc.validate_mmio_write32(CapId::BOOTSTRAP_NET_MMIO, 0x40),
        Ok(PhysAddr::new(0xFE00_0040))
    );
    assert_eq!(
        ipc.validate_mmio_read32(CapId::BOOTSTRAP_NET_MMIO, 0xFC),
        Ok(PhysAddr::new(0xFE00_00FC))
    );
}

// ============================================================================
// 5. Scheduler (5 tests)
// ============================================================================

#[test]
fn tier1_sched_spawn_and_single_thread_schedule() {
    let mut sched = Scheduler::<8>::new();
    let tid = sched.spawn(5).unwrap();
    assert_eq!(tid, ThreadId(1));
    assert_eq!(sched.schedule_next(), Some(tid));
    assert_eq!(sched.schedule_next(), Some(tid));
}

#[test]
fn tier1_sched_strict_priority_selection() {
    let mut sched = Scheduler::<8>::new();
    let _low = sched.spawn(1).unwrap();
    let high = sched.spawn(20).unwrap();
    let _mid = sched.spawn(10).unwrap();

    for _ in 0..5 {
        assert_eq!(sched.schedule_next(), Some(high));
    }
}

#[test]
fn tier1_sched_round_robin_equal_priority() {
    let mut sched = Scheduler::<8>::new();
    let a = sched.spawn(10).unwrap();
    let b = sched.spawn(10).unwrap();
    let c = sched.spawn(10).unwrap();

    let order: Vec<ThreadId> = (0..6).map(|_| sched.schedule_next().unwrap()).collect();
    assert_eq!(order, vec![a, b, c, a, b, c]);
}

#[test]
fn tier1_sched_yield_current_increments_and_rotates() {
    let mut sched = Scheduler::<8>::new();
    let a = sched.spawn(10).unwrap();
    let b = sched.spawn(10).unwrap();

    assert_eq!(sched.schedule_next(), Some(a));
    // Yielding a increments a's yields to 1 and schedules b.
    assert_eq!(sched.yield_current(), Some(1));
    // Yielding b increments b's yields to 1 and schedules a.
    assert_eq!(sched.yield_current(), Some(1));
    // Yielding a again increments a's yields to 2.
    assert_eq!(sched.yield_current(), Some(2));
    let _ = b;
}

#[test]
fn tier1_sched_mixed_priority_tiers() {
    let mut sched = Scheduler::<8>::new();
    let _low = sched.spawn(1).unwrap();
    let h1 = sched.spawn(50).unwrap();
    let _mid = sched.spawn(25).unwrap();
    let h2 = sched.spawn(50).unwrap();

    let seq: Vec<ThreadId> = (0..4).map(|_| sched.schedule_next().unwrap()).collect();
    assert_eq!(seq, vec![h1, h2, h1, h2]);
}

// ============================================================================
// 6. Untyped Memory & Paging Types (5 tests)
// ============================================================================

#[test]
fn tier1_mem_phys_virt_addr_alignment_and_canonical() {
    let pa = PhysAddr::new_aligned(0x4000).unwrap();
    assert!(pa.is_page_aligned());
    assert_eq!(PhysAddr::new(0x4001).align_up().raw(), 0x5000);
    assert_eq!(PhysAddr::new(0x4FFF).align_down().raw(), 0x4000);

    let va_low = VirtAddr::new_canonical(0x0000_0000_0040_0000).unwrap();
    assert!(va_low.is_page_aligned());
    let va_high = VirtAddr::new_page_aligned(0xFFFF_8000_0000_0000).unwrap();
    assert_eq!(va_high.raw(), 0xFFFF_8000_0000_0000);
}

#[test]
fn tier1_mem_untyped_region_alignment_and_monotonic_retype() {
    // Base 0x1001 aligns up to 0x2000; end 0x5001 aligns down to 0x5000 -> 3 pages (0x3000 bytes).
    let mut region = UntypedRegion::from_raw(0x1001, 0x4000).unwrap();
    assert_eq!(region.base, 0x2000);
    assert_eq!(region.len, 3 * PAGE_SIZE);
    assert_eq!(region.remaining(), 3 * PAGE_SIZE);

    let f0 = region.retype_frame().unwrap();
    let f1 = region.retype_frame().unwrap();
    assert_eq!(f0.start_addr(), PhysAddr::new(0x2000));
    assert_eq!(f1.start_addr(), PhysAddr::new(0x3000));
    assert_eq!(region.watermark, 2 * PAGE_SIZE);
    assert_eq!(region.remaining(), PAGE_SIZE);
}

#[test]
fn tier1_mem_untyped_inventory_multi_region_spills_seamlessly() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x10_0000, 2 * PAGE_SIZE));
    assert!(inv.push_raw_region(0x20_0000, 2 * PAGE_SIZE));
    assert_eq!(inv.region_count(), 2);
    assert_eq!(inv.total_bytes(), 4 * PAGE_SIZE);

    let addrs: Vec<u64> = (0..4)
        .map(|_| inv.retype_frame().unwrap().start_addr().raw())
        .collect();
    assert_eq!(addrs, vec![0x10_0000, 0x10_1000, 0x20_0000, 0x20_1000]);
    assert_eq!(inv.retyped_frames(), 4);
    assert_eq!(inv.remaining_bytes(), 0);
}

#[test]
fn tier1_mem_page_flags_wx_valid_combinations() {
    let ro = PageFlags::new_wx(false, false, true, false).unwrap();
    let rw = PageFlags::new_wx(true, false, true, false).unwrap();
    let rx = PageFlags::new_wx(false, true, true, false).unwrap();
    let mmio = PageFlags::new_wx(true, false, false, true).unwrap();

    assert!(!ro.writable && !ro.executable && ro.user);
    assert!(rw.writable && !rw.executable && rw.user);
    assert!(!rx.writable && rx.executable && rx.user);
    assert!(mmio.writable && mmio.no_cache && !mmio.user);

    assert!(PageFlags::KERNEL_RW.writable && !PageFlags::KERNEL_RW.executable);
    assert!(!PageFlags::KERNEL_RO.writable && !PageFlags::KERNEL_RO.executable);
    assert!(!PageFlags::KERNEL_RX.writable && PageFlags::KERNEL_RX.executable);
}

#[test]
fn tier1_mem_phys_frame_from_aligned_and_boot_info_usable_mib() {
    let frame = PhysFrame::from_aligned(PhysAddr::new(0x8000)).unwrap();
    assert_eq!(frame.start_addr(), PhysAddr::new(0x8000));

    let mut untyped = UntypedInventory::new();
    assert!(untyped.push_raw_region(0x100_0000, 3 * 1024 * 1024 + PAGE_SIZE));
    let info = BootInfo {
        hhdm_offset: 0xFFFF_8000_0000_0000,
        kernel_virt_base: 0,
        untyped,
        cpu_count: 4,
        rsdp_addr: 0,
        framebuffer: None,
        init_module: None,
        worker_module: None,
        netd_module: None,
        keyd_module: None,
        sshd_module: None,
        interactive_shell: false,
        qemu_virt: false,
    };
    assert_eq!(info.usable_mib(), 3);
}

// ============================================================================
// 7. ELF64 Parser (5 tests)
// ============================================================================

#[test]
fn tier1_elf_parse_minimal_rx_executable() {
    let payload = [0x90u8; 32];
    let phdr = PhdrSpec {
        p_type: 1,  // PT_LOAD
        p_flags: 5, // PF_R | PF_X
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 32,
        p_memsz: 32,
    };
    let bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[phdr], &payload);
    let parsed = parse_elf64(&bytes).unwrap();
    assert_eq!(parsed.entry.raw(), 0x0040_0000);
    assert_eq!(parsed.segment_count(), 1);
    let seg = parsed.segments().next().unwrap();
    assert_eq!(seg.vaddr, 0x0040_0000);
    assert_eq!(seg.file_size, 32);
    assert_eq!(seg.mem_size, 32);
    assert!(seg.flags.user && seg.flags.executable && !seg.flags.writable);
}

#[test]
fn tier1_elf_parse_multi_segment_rx_and_rw_bss() {
    let payload = [0xCCu8; 64];
    let base_off = (64 + 2 * 56) as u64;
    let phdrs = [
        PhdrSpec {
            p_type: 1,
            p_flags: 5, // RX
            p_offset: base_off,
            p_vaddr: 0x0040_0000,
            p_filesz: 32,
            p_memsz: 32,
        },
        PhdrSpec {
            p_type: 1,
            p_flags: 6, // RW with BSS
            p_offset: base_off + 32,
            p_vaddr: 0x0040_1000,
            p_filesz: 32,
            p_memsz: 4096,
        },
    ];
    let bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &payload);
    let parsed = parse_elf64(&bytes).unwrap();
    assert_eq!(parsed.segment_count(), 2);
    let segs: Vec<_> = parsed.segments().collect();
    assert!(segs[0].flags.executable && !segs[0].flags.writable);
    assert!(segs[1].flags.writable && !segs[1].flags.executable);
    assert_eq!(segs[1].mem_size, 4096);
    assert_eq!(segs[1].file_size, 32);
}

#[test]
fn tier1_elf_ignores_non_load_program_headers() {
    let payload = [0xAAu8; 16];
    let base_off = (64 + 3 * 56) as u64;
    let phdrs = [
        PhdrSpec {
            p_type: 4, // PT_NOTE
            p_flags: 4,
            p_offset: 0,
            p_vaddr: 0,
            p_filesz: 0,
            p_memsz: 0,
        },
        PhdrSpec {
            p_type: 1, // PT_LOAD
            p_flags: 5,
            p_offset: base_off,
            p_vaddr: 0x0040_0000,
            p_filesz: 16,
            p_memsz: 16,
        },
        PhdrSpec {
            p_type: 0x6474_E551, // PT_GNU_STACK
            p_flags: 6,
            p_offset: 0,
            p_vaddr: 0,
            p_filesz: 0,
            p_memsz: 0,
        },
    ];
    let bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &payload);
    let parsed = parse_elf64(&bytes).unwrap();
    assert_eq!(parsed.segment_count(), 1);
}

#[test]
fn tier1_elf_max_8_load_segments() {
    let payload = [0x11u8; 64];
    let base_off = (64 + MAX_LOAD_SEGMENTS * 56) as u64;
    let mut phdrs = Vec::new();
    for i in 0..MAX_LOAD_SEGMENTS {
        phdrs.push(PhdrSpec {
            p_type: 1,
            p_flags: 4, // RO
            p_offset: base_off + (i as u64) * 8,
            p_vaddr: 0x0040_0000 + (i as u64) * PAGE_SIZE,
            p_filesz: 8,
            p_memsz: 8,
        });
    }
    let bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &payload);
    let parsed = parse_elf64(&bytes).unwrap();
    assert_eq!(parsed.segment_count(), MAX_LOAD_SEGMENTS);
}

#[test]
fn tier1_elf_ro_data_segment_and_custom_phentsize() {
    let payload = [0x55u8; 16];
    let phentsize = 64u16; // > 56
    let phdr = PhdrSpec {
        p_type: 1,
        p_flags: 4, // PF_R only
        p_offset: 64 + 64,
        p_vaddr: 0x0050_0000,
        p_filesz: 16,
        p_memsz: 16,
    };
    let bytes = build_elf64(
        0x0050_0000,
        2,
        host_elf_machine(),
        phentsize,
        &[phdr],
        &payload,
    );
    let parsed = parse_elf64(&bytes).unwrap();
    assert_eq!(parsed.segment_count(), 1);
    let seg = parsed.segments().next().unwrap();
    assert!(!seg.flags.writable && !seg.flags.executable && seg.flags.user);
}
