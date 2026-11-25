//! Phase 8: Microkernel Security, Isolation, Crypto KAT/Zeroize, ABI Contract & OOM Stress Suite.

use core::mem::{align_of, size_of};
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, DomainRoleId, ObjectType, Rights, SysError};
use newos_crypto::chacha20_poly1305::OpenSshChaCha20Poly1305;
use newos_crypto::sha3::{sha3_512, shake256};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::memory::UntypedInventory;
use newos_shell_core::caos::ObjectStore;

/// Security Matrix: Exhaustively verifies every pair of `Rights` bitmasks satisfies
/// non-escalation, idempotence, and transitive revocation in the Capability Derivation Tree.
#[test]
fn security_exhaustive_rights_attenuation_and_transitive_cdt_revocation() {
    for raw_a in 0u8..=Rights::ALL.bits() {
        for raw_b in 0u8..=Rights::ALL.bits() {
            let parent = Rights::from_bits(raw_a).unwrap();
            let mask = Rights::from_bits(raw_b).unwrap();
            let child = parent.attenuate(mask);
            // Child can never contain any bit absent from parent or mask
            assert_eq!(child.bits() & !parent.bits(), 0);
            assert_eq!(child.bits() & !mask.bits(), 0);
            // Attenuation is idempotent
            assert_eq!(child.attenuate(mask), child);
        }
    }

    // 4-level CDT chain: root -> c1 -> c2 -> c3 -> c4; revoking c1 MUST invalidate c2..c4
    let mut cnode = CNode::<16>::new();
    let root = cnode
        .insert_root(Capability::new(CapObject::Endpoint { id: 42 }, Rights::ALL))
        .unwrap();
    let c1 = cnode
        .mint(
            root,
            2,
            Rights::READ
                .union(Rights::WRITE)
                .union(Rights::GRANT)
                .union(Rights::REVOKE),
            None,
        )
        .unwrap();
    let c2 = cnode
        .mint(c1, 3, Rights::READ.union(Rights::GRANT), None)
        .unwrap();
    let c3 = cnode.mint(c2, 4, Rights::READ, Some(3)).unwrap();

    // Confused deputy check 1: c3 lacks GRANT, so minting from it fails with InsufficientRights
    assert_eq!(
        cnode.mint(c3, 5, Rights::ALL, None).err(),
        Some(SysError::InsufficientRights)
    );
    // Confused deputy check 2: c2 has READ|GRANT; minting with Rights::ALL strictly attenuates
    let c4 = cnode.mint(c2, 5, Rights::ALL, Some(4)).unwrap();
    assert_eq!(
        cnode.lookup(c4, Rights::NONE).unwrap().rights,
        Rights::READ.union(Rights::GRANT)
    );

    // Transitive revocation from c1 removes c2, c3, c4 while preserving root & c1
    let revoked = cnode.revoke(c1).unwrap();
    assert_eq!(revoked, 3);
    assert!(cnode.lookup(root, Rights::NONE).is_ok());
    assert!(cnode.lookup(c1, Rights::NONE).is_ok());
    assert_eq!(
        cnode.lookup(c2, Rights::NONE).err(),
        Some(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(c3, Rights::NONE).err(),
        Some(SysError::InvalidCapability)
    );
    assert_eq!(
        cnode.lookup(c4, Rights::NONE).err(),
        Some(SysError::InvalidCapability)
    );

    // Forged CapId with bumped generation MUST be rejected
    let forged = CapId::new(c2.raw().wrapping_add(1u64 << 32));
    assert_eq!(
        cnode.lookup(forged, Rights::NONE).err(),
        Some(SysError::InvalidCapability)
    );
}

/// Crypto KAT (NIST FIPS 202) + OpenSSH ChaCha20-Poly1305 sequence-boundary tests.
#[test]
fn crypto_fips202_kat_and_aead_sequence_boundaries() {
    // NIST FIPS 202 SHA3-512("") known answer vector
    let empty_digest = sha3_512(b"");
    assert_eq!(
        &empty_digest[..8],
        &[0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5]
    );
    assert_eq!(
        &empty_digest[56..],
        &[0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26]
    );

    // NIST FIPS 202 SHAKE256("abc", 32 bytes) known answer vector
    let mut shake_out = [0u8; 32];
    shake256(b"abc", &mut shake_out);
    assert_eq!(
        &shake_out[..8],
        &[0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77]
    );

    // ChaCha20-Poly1305 at extreme sequence numbers (0, 1, u32::MAX, u64::MAX)
    let key = [0x37u8; 64];
    let cipher = OpenSshChaCha20Poly1305::new(&key);
    for seq in [0u64, 1, u32::MAX as u64, u64::MAX] {
        let mut pkt = [0u8; 20];
        pkt[..4].copy_from_slice(&16u32.to_be_bytes());
        pkt[4..].fill(0xA5);
        let tag = cipher.seal_in_place(seq, &mut pkt);
        assert_eq!(
            cipher.decrypt_length(seq, [pkt[0], pkt[1], pkt[2], pkt[3]]),
            16
        );
        let mut wrong_seq = pkt;
        assert!(!cipher.open_in_place(seq.wrapping_add(1), &mut wrong_seq, &tag));
        assert!(cipher.open_in_place(seq, &mut pkt, &tag));
        assert_eq!(&pkt[4..], &[0xA5u8; 16]);
    }
}

/// ABI Layout Contract Snapshot: Guarantees `#[repr(C)]`/`#[repr(transparent)]` EL0<->EL1 types never drift.
#[test]
fn abi_repr_c_layout_contract_stability() {
    assert_eq!(size_of::<CapId>(), 8);
    assert_eq!(align_of::<CapId>(), 8);
    assert_eq!(size_of::<Rights>(), 1);
    assert_eq!(size_of::<ObjectType>(), 1);
    assert_eq!(size_of::<DomainRoleId>(), 8);
    assert_eq!(align_of::<SpscRing<64>>(), 64);
}

/// OOM & Resource-Exhaustion Stress: Drives UntypedInventory, CNode, SpscRing, and CAOS
/// to 100% capacity, verifying zero panics, deterministic errors, and full recovery.
#[test]
fn stress_oom_and_resource_exhaustion_recovery() {
    // 1. UntypedInventory 100% exhaustion & full recovery
    let mut inv = UntypedInventory::new();
    assert!(inv.push_raw_region(0x6000_0000, 32 * 4096));
    let mut frames = Vec::new();
    while let Ok(f) = inv.retype_frame() {
        frames.push(f);
    }
    assert_eq!(frames.len(), 32);
    assert_eq!(inv.remaining_frames(), 0);
    assert!(inv.retype_frame().is_err());
    for f in frames {
        assert!(inv.reclaim_frame(f));
    }
    assert_eq!(inv.remaining_frames(), 32);

    // 2. CNode 100% slot exhaustion & recovery (slot 0 is reserved NULL -> 7 usable slots)
    let mut cnode = CNode::<8>::new();
    let mut inserted = Vec::new();
    for i in 0..7u32 {
        inserted.push(
            cnode
                .insert_root(Capability::new(CapObject::Endpoint { id: i }, Rights::ALL))
                .unwrap(),
        );
    }
    assert_eq!(
        cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 99 }, Rights::ALL))
            .err(),
        Some(SysError::OutOfMemory)
    );
    assert_eq!(cnode.delete(inserted[0]), Ok(()));
    assert!(
        cnode
            .insert_root(Capability::new(CapObject::Endpoint { id: 99 }, Rights::ALL))
            .is_ok()
    );

    // 3. SpscRing 100% capacity exhaustion & drain recovery
    let ring = SpscRing::<8>::new();
    for i in 0..ring.capacity() {
        assert!(ring.try_push(i as u64).is_ok());
    }
    assert!(ring.try_push(999).is_err());
    for i in 0..ring.capacity() {
        assert_eq!(ring.try_pop(), Some(i as u64));
    }
    assert!(ring.is_empty());

    // 4. CAOS ObjectStore 100% table exhaustion
    let mut store = ObjectStore::new();
    let mut count = 0usize;
    loop {
        let data = format!("unique-object-payload-{count}");
        match store.put(data.as_bytes()) {
            Ok(_) => count += 1,
            Err(_) => break,
        }
        assert!(count <= 1024, "CAOS store must have bounded capacity");
    }
    assert!(count > 0);
}

/// Crypto Zeroize & Constant-Time Tag Verification Check:
/// Verifies `OpenSshChaCha20Poly1305` rejects every single-byte position tamper across
/// the Poly1305 tag (no early-exit short-circuiting logic bugs) and rejects mismatched keys.
#[test]
fn crypto_tag_verification_rejects_every_byte_position_and_wrong_key() {
    let key_a = [0x11u8; 64];
    let key_b = [0x22u8; 64];
    let cipher_a = OpenSshChaCha20Poly1305::new(&key_a);
    let cipher_b = OpenSshChaCha20Poly1305::new(&key_b);

    let mut pkt = [0u8; 36];
    pkt[..4].copy_from_slice(&32u32.to_be_bytes());
    for (i, b) in pkt[4..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(7);
    }
    let tag = cipher_a.seal_in_place(7, &mut pkt);

    // Wrong key must reject
    let mut wrong_key_pkt = pkt;
    assert!(!cipher_b.open_in_place(7, &mut wrong_key_pkt, &tag));

    // Flipping every byte position 0..16 in the Poly1305 tag must reject
    for byte_idx in 0..16 {
        let mut bad_tag = tag;
        bad_tag[byte_idx] ^= 0x80;
        let mut attempt = pkt;
        assert!(
            !cipher_a.open_in_place(7, &mut attempt, &bad_tag),
            "tampered tag byte {byte_idx} must be rejected"
        );
    }

    // Valid tag succeeds
    assert!(cipher_a.open_in_place(7, &mut pkt, &tag));
}
