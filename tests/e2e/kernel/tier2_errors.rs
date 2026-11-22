//! Tier 2 (Boundary & Error Paths) E2E tests for `newos-abi` and `newos-kernel-core`.
//! Covers 39 boundary, negative, and corner-case tests across all 7 kernel feature areas.

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, Rights, SysError, SyscallNumber};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::{MAX_LOAD_SEGMENTS, parse_elf64};
use newos_kernel_core::ipc::KernelIpcState;
use newos_kernel_core::memory::{
    MAX_UNTYPED_REGIONS, PAGE_SIZE, PageFlags, PhysAddr, PhysFrame, UntypedInventory,
    UntypedRegion, VirtAddr,
};
use newos_kernel_core::sched::Scheduler;

use crate::test_helpers::{PhdrSpec, build_elf64, host_elf_machine, wrong_elf_machine};

// ============================================================================
// 1. ABI Primitives Boundaries (5 tests)
// ============================================================================

#[test]
fn tier2_abi_syscall_from_u64_out_of_range() {
    assert_eq!(SyscallNumber::from_u64(0), None);
    assert_eq!(SyscallNumber::from_u64(100), None);
    assert_eq!(SyscallNumber::from_u64(u64::MAX), None);
}

#[test]
fn tier2_abi_sys_error_from_u64_out_of_range() {
    assert_eq!(SysError::from_u64(0), None);
    assert_eq!(SysError::from_u64(8), None);
    assert_eq!(SysError::from_u64(u64::MAX), None);
}

#[test]
fn tier2_abi_rights_attenuate_never_escalates() {
    let att = Rights::READ.attenuate(Rights::ALL);
    assert_eq!(att, Rights::READ);
    assert!(!att.contains(Rights::WRITE));
    assert!(!att.contains(Rights::EXEC));
    assert!(!att.contains(Rights::GRANT));
    assert!(!att.contains(Rights::REVOKE));
    assert!(Rights::NONE.contains(Rights::NONE));
    assert!(!Rights::NONE.contains(Rights::READ));
}

#[test]
fn tier2_abi_cap_id_zero_vs_max() {
    assert!(CapId::new(0).is_null());
    assert_eq!(CapId::new(0), CapId::NULL);
    let max_cap = CapId::new(u64::MAX);
    assert!(!max_cap.is_null());
    assert_eq!(max_cap.raw(), u64::MAX);
}

#[test]
fn tier2_abi_rights_union_idempotent_and_bounded() {
    let u = Rights::ALL.union(Rights::ALL);
    assert_eq!(u.bits(), 0b0001_1111);
    assert_eq!(Rights::NONE.union(Rights::NONE), Rights::NONE);
    assert_eq!(Rights::READ.union(Rights::READ), Rights::READ);
}

// ============================================================================
// 2. SpscRing Boundaries (5 tests)
// ============================================================================

#[test]
fn tier2_ring_pop_empty_returns_none() {
    let ring = SpscRing::<4>::new();
    for _ in 0..8 {
        assert_eq!(ring.try_pop(), None);
    }
    assert!(ring.is_empty());
}

#[test]
fn tier2_ring_push_full_returns_would_block_without_corrupting() {
    let ring = SpscRing::<4>::new();
    assert_eq!(ring.try_push(10), Ok(()));
    assert_eq!(ring.try_push(20), Ok(()));
    assert_eq!(ring.try_push(30), Ok(()));
    assert_eq!(ring.try_push(40), Err(SysError::WouldBlock));
    assert_eq!(ring.try_push(50), Err(SysError::WouldBlock));

    assert_eq!(ring.try_pop(), Some(10));
    assert_eq!(ring.try_pop(), Some(20));
    assert_eq!(ring.try_pop(), Some(30));
    assert_eq!(ring.try_pop(), None);
}

#[test]
fn tier2_ring_min_size_2_single_element_capacity() {
    let ring = SpscRing::<2>::new();
    assert_eq!(ring.capacity(), 1);
    assert_eq!(ring.try_push(0x99), Ok(()));
    assert_eq!(ring.try_push(0xAA), Err(SysError::WouldBlock));
    assert_eq!(ring.try_pop(), Some(0x99));
    assert_eq!(ring.try_pop(), None);
}

#[test]
fn tier2_ring_extreme_word_values() {
    let ring = SpscRing::<8>::new();
    let values = [0u64, 1, u64::MAX, u64::MAX - 1, 0xDEAD_BEEF_CAFE_BABE];
    for &v in &values {
        assert_eq!(ring.try_push(v), Ok(()));
    }
    for &v in &values {
        assert_eq!(ring.try_pop(), Some(v));
    }
}

#[test]
fn tier2_ring_alternating_full_empty_boundary() {
    let ring = SpscRing::<4>::new();
    assert_eq!(ring.try_push(0), Ok(()));
    assert_eq!(ring.try_push(1), Ok(()));
    assert_eq!(ring.try_push(2), Ok(()));
    for i in 3..50u64 {
        assert_eq!(ring.try_push(i), Err(SysError::WouldBlock));
        assert_eq!(ring.try_pop(), Some(i - 3));
        assert_eq!(ring.try_push(i), Ok(()));
    }
    assert_eq!(ring.try_pop(), Some(47));
    assert_eq!(ring.try_pop(), Some(48));
    assert_eq!(ring.try_pop(), Some(49));
    assert_eq!(ring.try_pop(), None);
}

// ============================================================================
// 3. CSpace & CDT Boundaries (6 tests)
// ============================================================================

#[test]
fn tier2_cspace_rejects_null_oob_and_stale_generation() {
    let mut cnode = CNode::<8>::new();
    assert_eq!(
        cnode.lookup(CapId::NULL, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    // Out-of-bounds slot index (99 >= 8) with generation 1.
    let oob = CapId::new((1u64 << 32) | 99);
    assert_eq!(
        cnode.lookup(oob, Rights::NONE),
        Err(SysError::InvalidCapability)
    );

    let cap = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    // Wrong generation on valid slot.
    let bad_gen = CapId::new((99u64 << 32) | (cap.raw() & 0xFFFF_FFFF));
    assert_eq!(
        cnode.lookup(bad_gen, Rights::NONE),
        Err(SysError::InvalidCapability)
    );

    // Delete & reuse same slot -> old CapId must stay invalid.
    assert_eq!(cnode.delete(cap), Ok(()));
    let reused = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();
    assert_ne!(cap, reused);
    assert_eq!(
        cnode.lookup(cap, Rights::NONE),
        Err(SysError::InvalidCapability)
    );
    assert!(cnode.lookup(reused, Rights::READ).is_ok());
}

#[test]
fn tier2_cspace_full_capacity_and_slot_zero_forbidden() {
    let mut cnode = CNode::<4>::new(); // usable slots: 1, 2, 3
    let c1 = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let _c2 = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();
    let _c3 = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 2 }, Rights::ALL))
        .unwrap();

    assert_eq!(cnode.occupied_count(), 3);
    assert_eq!(cnode.find_free_slot(), Err(SysError::OutOfMemory));
    assert_eq!(
        cnode.insert_root(Capability::new(CapObject::Endpoint { id: 3 }, Rights::ALL)),
        Err(SysError::OutOfMemory)
    );
    // Slot 0 and slot >= SLOTS forbidden; occupied slot returns SlotOccupied.
    assert_eq!(cnode.copy(c1, 0), Err(SysError::InvalidArgument));
    assert_eq!(cnode.copy(c1, 4), Err(SysError::InvalidArgument));
    assert_eq!(cnode.copy(c1, 2), Err(SysError::SlotOccupied));
    assert_eq!(cnode.move_cap(c1, 0), Err(SysError::InvalidArgument));
    assert_eq!(cnode.move_cap(c1, 4), Err(SysError::InvalidArgument));
}

#[test]
fn tier2_cspace_mint_forbids_without_grant_and_forbids_rebadge() {
    let mut cnode = CNode::<8>::new();
    let no_grant = cnode
        .insert_root(Capability::new(
            CapObject::Endpoint { id: 0 },
            Rights::READ.union(Rights::WRITE),
        ))
        .unwrap();
    let s1 = cnode.find_free_slot().unwrap();
    assert_eq!(
        cnode.mint(no_grant, s1, Rights::READ, None),
        Err(SysError::InsufficientRights)
    );

    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();
    let s2 = cnode.find_free_slot().unwrap();
    let badged = cnode.mint(root, s2, Rights::ALL, Some(0x1111)).unwrap();
    let s3 = cnode.find_free_slot().unwrap();
    assert_eq!(
        cnode.mint(badged, s3, Rights::READ, Some(0x2222)),
        Err(SysError::InsufficientRights)
    );
}

#[test]
fn tier2_cspace_move_to_self_rejected() {
    let mut cnode = CNode::<8>::new();
    let cap = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    let same_slot = (cap.raw() & 0xFFFF_FFFF) as usize;
    assert_eq!(cnode.move_cap(cap, same_slot), Err(SysError::SlotOccupied));
    assert!(cnode.lookup(cap, Rights::ALL).is_ok());
}

#[test]
fn tier2_cspace_revoke_requires_revoke_right_and_zero_children() {
    let mut cnode = CNode::<8>::new();
    let no_revoke = cnode
        .insert_root(Capability::new(
            CapObject::Endpoint { id: 0 },
            Rights::READ.union(Rights::WRITE),
        ))
        .unwrap();
    assert_eq!(cnode.revoke(no_revoke), Err(SysError::InsufficientRights));

    let leaf = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 1 }, Rights::ALL))
        .unwrap();
    assert_eq!(cnode.revoke(leaf), Ok(0));
    assert!(cnode.lookup(leaf, Rights::ALL).is_ok());
}

#[test]
fn tier2_cspace_retype_frame_wrong_type_no_write_or_oom() {
    let mut cnode = CNode::<8>::new();
    let mut inv = UntypedInventory::new();

    let ep = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 0 }, Rights::ALL))
        .unwrap();
    assert_eq!(
        cnode.retype_frame_from(ep, &mut inv),
        Err(SysError::InvalidArgument)
    );

    let ro_untyped = cnode
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::READ,
        ))
        .unwrap();
    assert_eq!(
        cnode.retype_frame_from(ro_untyped, &mut inv),
        Err(SysError::InsufficientRights)
    );

    let rw_untyped = cnode
        .insert_root(Capability::new(
            CapObject::Untyped { region_index: 0 },
            Rights::ALL,
        ))
        .unwrap();
    assert_eq!(
        cnode.retype_frame_from(rw_untyped, &mut inv),
        Err(SysError::OutOfMemory)
    );
}

// ============================================================================
// 4. Kernel IPC & MMIO Boundaries (6 tests)
// ============================================================================

#[test]
fn tier2_ipc_endpoint_empty_recv_and_full_send_would_block() {
    let mut ipc = KernelIpcState::new();
    let (_, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(ipc.ipc_recv(ep), Err(SysError::WouldBlock));
    assert_eq!(ipc.ipc_send(ep, 0x1111), Ok(()));
    assert_eq!(ipc.ipc_send(ep, 0x2222), Err(SysError::WouldBlock));
}

#[test]
fn tier2_ipc_wrong_object_type_and_out_of_range_id() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    assert_eq!(ipc.ipc_send(notif, 1), Err(SysError::InvalidArgument));
    assert_eq!(ipc.ipc_recv(notif), Err(SysError::InvalidArgument));
    assert_eq!(ipc.notify_signal(ep, 1), Err(SysError::InvalidArgument));
    assert_eq!(ipc.notify_poll(ep), Err(SysError::InvalidArgument));

    let bad_ep = ipc
        .root_cspace
        .insert_root(Capability::new(CapObject::Endpoint { id: 16 }, Rights::ALL))
        .unwrap();
    let bad_notif = ipc
        .root_cspace
        .insert_root(Capability::new(
            CapObject::Notification { id: 16 },
            Rights::ALL,
        ))
        .unwrap();
    assert_eq!(ipc.ipc_send(bad_ep, 1), Err(SysError::InvalidArgument));
    assert_eq!(ipc.ipc_recv(bad_ep), Err(SysError::InvalidArgument));
    assert_eq!(
        ipc.notify_signal(bad_notif, 1),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(ipc.notify_poll(bad_notif), Err(SysError::InvalidArgument));
}

#[test]
fn tier2_ipc_insufficient_rights_read_only_and_write_only() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc.init_bootstrap_caps(None).unwrap();

    let s1 = ipc.root_cspace.find_free_slot().unwrap();
    let ro_ep = ipc.root_cspace.mint(ep, s1, Rights::READ, None).unwrap();
    let s2 = ipc.root_cspace.find_free_slot().unwrap();
    let wo_ep = ipc.root_cspace.mint(ep, s2, Rights::WRITE, None).unwrap();
    let s3 = ipc.root_cspace.find_free_slot().unwrap();
    let ro_nt = ipc.root_cspace.mint(notif, s3, Rights::READ, None).unwrap();
    let s4 = ipc.root_cspace.find_free_slot().unwrap();
    let wo_nt = ipc
        .root_cspace
        .mint(notif, s4, Rights::WRITE, None)
        .unwrap();

    assert_eq!(ipc.ipc_send(ro_ep, 1), Err(SysError::InsufficientRights));
    assert_eq!(ipc.ipc_recv(wo_ep), Err(SysError::InsufficientRights));
    assert_eq!(
        ipc.notify_signal(ro_nt, 1),
        Err(SysError::InsufficientRights)
    );
    assert_eq!(ipc.notify_poll(wo_nt), Err(SysError::InsufficientRights));
}

#[test]
fn tier2_ipc_mmio_unaligned_oob_and_u64_overflow() {
    let mut ipc = KernelIpcState::new();
    ipc.init_bootstrap_caps(Some((PhysAddr::new(0x1000_0000), 0x10)))
        .unwrap();

    for bad_off in [1u64, 2, 3, 0x0E, 0x10, u64::MAX - 3, u64::MAX] {
        assert_eq!(
            ipc.validate_mmio_read32(CapId::BOOTSTRAP_NET_MMIO, bad_off),
            Err(SysError::InvalidArgument),
            "offset {bad_off:#x} must be rejected"
        );
        assert_eq!(
            ipc.validate_mmio_write32(CapId::BOOTSTRAP_NET_MMIO, bad_off),
            Err(SysError::InvalidArgument),
            "offset {bad_off:#x} must be rejected"
        );
    }

    // Overflowing phys + offset.
    let overflow_mmio = ipc
        .root_cspace
        .insert_root(Capability::new(
            CapObject::MmioRegion {
                phys: PhysAddr::new(u64::MAX - 2),
                len: 0x100,
            },
            Rights::READ.union(Rights::WRITE),
        ))
        .unwrap();
    assert_eq!(
        ipc.validate_mmio_read32(overflow_mmio, 4),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn tier2_ipc_mmio_rights_separation() {
    let mut ipc = KernelIpcState::new();
    let ro_mmio = ipc
        .root_cspace
        .insert_root(Capability::new(
            CapObject::MmioRegion {
                phys: PhysAddr::new(0x2000_0000),
                len: 0x100,
            },
            Rights::READ,
        ))
        .unwrap();
    let wo_mmio = ipc
        .root_cspace
        .insert_root(Capability::new(
            CapObject::MmioRegion {
                phys: PhysAddr::new(0x2000_0000),
                len: 0x100,
            },
            Rights::WRITE,
        ))
        .unwrap();

    assert!(ipc.validate_mmio_read32(ro_mmio, 0).is_ok());
    assert_eq!(
        ipc.validate_mmio_write32(ro_mmio, 0),
        Err(SysError::InsufficientRights)
    );
    assert!(ipc.validate_mmio_write32(wo_mmio, 0).is_ok());
    assert_eq!(
        ipc.validate_mmio_read32(wo_mmio, 0),
        Err(SysError::InsufficientRights)
    );
}

#[test]
fn tier2_ipc_stale_or_null_cap_rejected() {
    let mut ipc = KernelIpcState::new();
    let (notif, ep, _) = ipc
        .init_bootstrap_caps(Some((PhysAddr::new(0x3000_0000), 0x100)))
        .unwrap();

    for cap in [CapId::NULL, notif, ep, CapId::BOOTSTRAP_NET_MMIO] {
        if cap != CapId::NULL {
            assert_eq!(ipc.root_cspace.delete(cap), Ok(()));
        }
        assert_eq!(ipc.notify_signal(cap, 1), Err(SysError::InvalidCapability));
        assert_eq!(ipc.notify_poll(cap), Err(SysError::InvalidCapability));
        assert_eq!(ipc.ipc_send(cap, 1), Err(SysError::InvalidCapability));
        assert_eq!(ipc.ipc_recv(cap), Err(SysError::InvalidCapability));
        assert_eq!(
            ipc.validate_mmio_read32(cap, 0),
            Err(SysError::InvalidCapability)
        );
        assert_eq!(
            ipc.validate_mmio_write32(cap, 0),
            Err(SysError::InvalidCapability)
        );
    }
}

// ============================================================================
// 5. Scheduler Boundaries (5 tests)
// ============================================================================

#[test]
fn tier2_sched_empty_schedule_and_yield_return_none() {
    let mut sched = Scheduler::<4>::new();
    assert_eq!(sched.schedule_next(), None);
    assert_eq!(sched.yield_current(), None);
}

#[test]
fn tier2_sched_capacity_exhaustion_returns_oom() {
    let mut sched = Scheduler::<3>::new();
    assert!(sched.spawn(1).is_ok());
    assert!(sched.spawn(2).is_ok());
    assert!(sched.spawn(3).is_ok());
    assert_eq!(sched.spawn(4), Err(SysError::OutOfMemory));
}

#[test]
fn tier2_sched_zero_capacity_scheduler() {
    let mut sched = Scheduler::<0>::new();
    assert_eq!(sched.spawn(10), Err(SysError::OutOfMemory));
    assert_eq!(sched.schedule_next(), None);
    assert_eq!(sched.yield_current(), None);
}

#[test]
fn tier2_sched_priority_extremes_0_and_255() {
    let mut sched = Scheduler::<4>::new();
    let _min_p = sched.spawn(0).unwrap();
    let max_p = sched.spawn(255).unwrap();
    assert_eq!(sched.schedule_next(), Some(max_p));
    assert_eq!(sched.schedule_next(), Some(max_p));
}

#[test]
fn tier2_sched_yield_before_first_schedule_returns_none() {
    let mut sched = Scheduler::<4>::new();
    let _tid = sched.spawn(5).unwrap();
    assert_eq!(sched.yield_current(), None);
}

// ============================================================================
// 6. Untyped Memory & Paging Boundaries (6 tests)
// ============================================================================

#[test]
fn tier2_mem_unaligned_phys_virt_and_frame_rejected() {
    assert_eq!(PhysAddr::new_aligned(0x1001), Err(SysError::InvalidArgument));
    assert_eq!(
        VirtAddr::new_page_aligned(0x0040_0001),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        PhysFrame::from_aligned(PhysAddr::new(0x1FFF)),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn tier2_mem_non_canonical_virt_addr_hole_boundaries() {
    assert!(VirtAddr::new_canonical(0x0000_7FFF_FFFF_FFFF).is_ok());
    assert_eq!(
        VirtAddr::new_canonical(0x0000_8000_0000_0000),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        VirtAddr::new_canonical(0xFFFF_7FFF_FFFF_FFFF),
        Err(SysError::InvalidArgument)
    );
    assert!(VirtAddr::new_canonical(0xFFFF_8000_0000_0000).is_ok());
}

#[test]
fn tier2_mem_page_flags_wx_rejects_writable_and_executable() {
    assert_eq!(
        PageFlags::new_wx(true, true, false, false),
        Err(SysError::InvalidArgument)
    );
    assert_eq!(
        PageFlags::new_wx(true, true, true, true),
        Err(SysError::InvalidArgument)
    );
}

#[test]
fn tier2_mem_untyped_region_too_small_or_unaligned_empty() {
    assert_eq!(UntypedRegion::from_raw(0, 0), None);
    assert_eq!(UntypedRegion::from_raw(0, PAGE_SIZE - 1), None);
    // 0x1001..0x2001 aligns up to 0x2000 and down to 0x2000 -> 0 usable bytes.
    assert_eq!(UntypedRegion::from_raw(0x1001, PAGE_SIZE), None);
}

#[test]
fn tier2_mem_untyped_inventory_max_32_regions_cap() {
    let mut inv = UntypedInventory::new();
    for i in 0..MAX_UNTYPED_REGIONS {
        let base = 0x100_0000 + (i as u64) * 0x1_0000;
        assert!(inv.push_raw_region(base, PAGE_SIZE));
    }
    assert_eq!(inv.region_count(), MAX_UNTYPED_REGIONS);
    assert!(!inv.push_raw_region(0x900_0000, PAGE_SIZE));
}

#[test]
fn tier2_mem_untyped_inventory_exhaustion_oom() {
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x10_0000, 2 * PAGE_SIZE));
    assert!(inv.retype_frame().is_ok());
    assert!(inv.retype_frame().is_ok());
    assert_eq!(inv.retype_frame(), Err(SysError::OutOfMemory));
    assert_eq!(inv.remaining_bytes(), 0);
}

// ============================================================================
// 7. ELF64 Parser Boundaries (6 tests)
// ============================================================================

#[test]
fn tier2_elf_rejects_short_bad_magic_32bit_bigendian() {
    assert_eq!(parse_elf64(&[0u8; 63]), Err(SysError::InvalidArgument));

    let phdr = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let mut bad_magic = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[phdr], &[0; 8]);
    bad_magic[0] = b'X';
    assert_eq!(parse_elf64(&bad_magic), Err(SysError::InvalidArgument));

    let mut elf32 = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[phdr], &[0; 8]);
    elf32[4] = 1; // ELFCLASS32
    assert_eq!(parse_elf64(&elf32), Err(SysError::Unsupported));

    let mut big_endian = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[phdr], &[0; 8]);
    big_endian[5] = 2; // ELFDATA2MSB
    assert_eq!(parse_elf64(&big_endian), Err(SysError::Unsupported));
}

#[test]
fn tier2_elf_rejects_wrong_type_and_wrong_machine() {
    let phdr = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let dyn_elf = build_elf64(0x0040_0000, 3, host_elf_machine(), 56, &[phdr], &[0; 8]);
    assert_eq!(parse_elf64(&dyn_elf), Err(SysError::Unsupported));

    let wrong_arch = build_elf64(0x0040_0000, 2, wrong_elf_machine(), 56, &[phdr], &[0; 8]);
    assert_eq!(parse_elf64(&wrong_arch), Err(SysError::Unsupported));
}

#[test]
fn tier2_elf_rejects_kernel_space_entry_or_segment() {
    let phdr = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let kern_entry = build_elf64(
        0xFFFF_8000_0000_0000,
        2,
        host_elf_machine(),
        56,
        &[phdr],
        &[0; 8],
    );
    assert_eq!(parse_elf64(&kern_entry), Err(SysError::InvalidArgument));

    let kern_seg = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0xFFFF_8000_0000_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let bad_seg_elf = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[kern_seg], &[0; 8]);
    assert_eq!(parse_elf64(&bad_seg_elf), Err(SysError::InvalidArgument));
}

#[test]
fn tier2_elf_rejects_wx_segment() {
    let wx_phdr = PhdrSpec {
        p_type: 1,
        p_flags: 7, // PF_R | PF_W | PF_X -> W^X violation
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let bytes = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[wx_phdr], &[0; 8]);
    assert_eq!(parse_elf64(&bytes), Err(SysError::InvalidArgument));
}

#[test]
fn tier2_elf_rejects_zero_load_segments_and_gt_8_segments() {
    let zero_elf = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[], &[]);
    assert_eq!(parse_elf64(&zero_elf), Err(SysError::InvalidArgument));

    let too_many_count = MAX_LOAD_SEGMENTS + 1;
    let base_off = (64 + too_many_count * 56) as u64;
    let mut phdrs = Vec::new();
    for i in 0..too_many_count {
        phdrs.push(PhdrSpec {
            p_type: 1,
            p_flags: 4,
            p_offset: base_off,
            p_vaddr: 0x0040_0000 + (i as u64) * PAGE_SIZE,
            p_filesz: 4,
            p_memsz: 4,
        });
    }
    let too_many_elf = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &phdrs, &[0; 8]);
    assert_eq!(parse_elf64(&too_many_elf), Err(SysError::OutOfMemory));
}

#[test]
fn tier2_elf_rejects_truncated_file_memsz_lt_filesz_and_small_phentsize() {
    let truncated_phdr = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 100, // exceeds payload length 8
        p_memsz: 100,
    };
    let truncated = build_elf64(
        0x0040_0000,
        2,
        host_elf_machine(),
        56,
        &[truncated_phdr],
        &[0; 8],
    );
    assert_eq!(parse_elf64(&truncated), Err(SysError::InvalidArgument));

    let bad_sizes = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 4, // memsz < filesz
    };
    let bad_sizes_elf = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[bad_sizes], &[0; 8]);
    assert_eq!(parse_elf64(&bad_sizes_elf), Err(SysError::InvalidArgument));

    let ok_phdr = PhdrSpec {
        p_type: 1,
        p_flags: 5,
        p_offset: 64 + 56,
        p_vaddr: 0x0040_0000,
        p_filesz: 8,
        p_memsz: 8,
    };
    let mut small_phent = build_elf64(0x0040_0000, 2, host_elf_machine(), 56, &[ok_phdr], &[0; 8]);
    small_phent[54..56].copy_from_slice(&40u16.to_le_bytes());
    assert_eq!(parse_elf64(&small_phent), Err(SysError::InvalidArgument));
}
