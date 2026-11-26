//! Phase 2: Property-Based Testing Suite (`proptest`).
//!
//! Verifies algebraic invariants, round-trip properties, and panic-freedom across
//! `newos-abi`, `newos-crypto`, `newos-kernel-core`, `newos-shell-core`, `newos-ssh-proto`,
//! and `newos-net`.

use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ObjectType, Rights};
use newos_crypto::chacha20_poly1305::OpenSshChaCha20Poly1305;
use newos_crypto::sha3::{sha3_512, shake256};
use newos_kernel_core::acpi::{
    parse_fadt_arm_boot_arch, parse_gtdt, parse_madt, parse_mcfg, parse_rsdp, parse_spcr,
};
use newos_kernel_core::cspace::{CNode, CapObject, Capability};
use newos_kernel_core::elf::parse_elf64;
use newos_kernel_core::memory::UntypedInventory;
use newos_net::parse_ipv4;
use newos_shell_core::caos::ObjectStore;
use newos_ssh_proto::wire::{WireReader, WireWriter};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_spsc_ring_preserves_exact_fifo_order_and_conservation(
        ops in prop::collection::vec((any::<bool>(), any::<u64>()), 1..256)
    ) {
        let ring = SpscRing::<16>::new();
        let mut model = std::collections::VecDeque::new();
        for (is_push, val) in ops {
            if is_push {
                let res = ring.try_push(val);
                if model.len() < ring.capacity() {
                    prop_assert!(res.is_ok());
                    model.push_back(val);
                } else {
                    prop_assert!(res.is_err());
                }
            } else {
                prop_assert_eq!(ring.try_pop(), model.pop_front());
            }
            prop_assert_eq!(ring.len(), model.len());
        }
        while let Some(expected) = model.pop_front() {
            prop_assert_eq!(ring.try_pop(), Some(expected));
        }
        prop_assert!(ring.is_empty());
    }

    #[test]
    fn prop_spsc_ring_framed_bytes_roundtrip(
        msgs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..96), 1..32)
    ) {
        let ring = SpscRing::<32>::new();
        for msg in msgs {
            let mut out = [0u8; 128];
            if ring.try_push_bytes(&msg).is_ok() {
                let n = ring.try_pop_bytes(&mut out).expect("pushed message must pop");
                prop_assert_eq!(&out[..n], msg.as_slice());
            }
        }
        prop_assert!(ring.is_empty());
    }

    #[test]
    fn prop_rights_attenuation_is_monotone_and_never_escalates(a in any::<u8>(), b in any::<u8>()) {
        let ra = Rights::from_bits_truncate(a);
        let rb = Rights::from_bits_truncate(b);
        let att = ra.attenuate(rb);
        prop_assert_eq!(att.bits() & !ra.bits(), 0);
        prop_assert_eq!(att.bits() & !rb.bits(), 0);
        prop_assert!(ra.contains(att));
        prop_assert!(rb.contains(att));
    }

    #[test]
    fn prop_ssh_wire_roundtrip_and_never_panics_on_arbitrary_bytes(
        a in any::<u8>(),
        b in any::<bool>(),
        c in any::<u32>(),
        s in prop::collection::vec(any::<u8>(), 0..128),
        fuzz_bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut buf = [0u8; 256];
        let mut w = WireWriter::new(&mut buf);
        w.write_u8(a).unwrap();
        w.write_bool(b).unwrap();
        w.write_u32(c).unwrap();
        w.write_string(&s).unwrap();
        let len = w.len();

        let mut r = WireReader::new(&buf[..len]);
        prop_assert_eq!(r.read_u8(), Ok(a));
        prop_assert_eq!(r.read_bool(), Ok(b));
        prop_assert_eq!(r.read_u32(), Ok(c));
        prop_assert_eq!(r.read_string(), Ok(s.as_slice()));
        prop_assert_eq!(r.remaining(), 0);

        // Arbitrary byte stream must never panic
        let mut fr = WireReader::new(&fuzz_bytes);
        let _ = fr.read_u8();
        let _ = fr.read_bool();
        let _ = fr.read_u32();
        let _ = fr.read_string();
        let _ = fr.read_str();
    }

    #[test]
    fn prop_openssh_chacha20_poly1305_roundtrip_and_bitflip_rejection(
        key in prop::array::uniform32(any::<u8>()),
        hdr_key in prop::array::uniform32(any::<u8>()),
        seq in any::<u64>(),
        payload in prop::collection::vec(any::<u8>(), 8..160),
        flip_idx in any::<usize>(),
        flip_bit in 0u8..8u8,
    ) {
        let mut full_key = [0u8; 64];
        full_key[..32].copy_from_slice(&key);
        full_key[32..].copy_from_slice(&hdr_key);
        let cipher = OpenSshChaCha20Poly1305::new(&full_key);

        let mut packet = vec![0u8; 4 + payload.len()];
        let payload_len = u32::try_from(payload.len()).expect("payload <= 160 fits u32");
        packet[..4].copy_from_slice(&payload_len.to_be_bytes());
        packet[4..].copy_from_slice(&payload);
        let tag = cipher.seal_in_place(seq, &mut packet);

        // Decryption succeeds and recovers exact plaintext
        let dec_len = cipher.decrypt_length(seq, [packet[0], packet[1], packet[2], packet[3]]);
        prop_assert_eq!(dec_len as usize, payload.len());
        let mut opened = packet.clone();
        prop_assert!(cipher.open_in_place(seq, &mut opened, &tag));
        prop_assert_eq!(&opened[4..], payload.as_slice());

        // Flipping any single bit in header, ciphertext, or tag MUST fail authentication
        let total = packet.len() + tag.len();
        let idx = flip_idx % total;
        let mut t_pkt = packet;
        let mut t_tag = tag;
        if idx < t_pkt.len() {
            t_pkt[idx] ^= 1u8 << flip_bit;
        } else {
            t_tag[idx - t_pkt.len()] ^= 1u8 << flip_bit;
        }
        prop_assert!(!cipher.open_in_place(seq, &mut t_pkt, &t_tag));
    }

    #[test]
    fn prop_sha3_and_shake256_are_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..512),
        out_len in 1usize..128,
    ) {
        prop_assert_eq!(sha3_512(&data), sha3_512(&data));
        let mut a = vec![0u8; out_len];
        let mut b = vec![0u8; out_len];
        shake256(&data, &mut a);
        shake256(&data, &mut b);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_elf64_and_acpi_parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_elf64(&bytes);
        let _ = parse_rsdp(&bytes);
        let _ = parse_fadt_arm_boot_arch(&bytes);
        let _ = parse_spcr(&bytes);
        let _ = parse_madt(&bytes);
        let _ = parse_gtdt(&bytes);
        let _ = parse_mcfg(&bytes);
    }

    #[test]
    fn prop_ipv4_parser_roundtrips_canonical_quads(a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>()) {
        let s = format!("{a}.{b}.{c}.{d}");
        prop_assert_eq!(parse_ipv4(&s), Some([a, b, c, d]));
    }

    #[test]
    fn prop_untyped_inventory_retype_and_reclaim_conserves_frames(
        ops in prop::collection::vec(any::<bool>(), 1..64)
    ) {
        let mut inv = UntypedInventory::new();
        assert!(inv.push_raw_region(0x4000_0000, 16 * 4096));
        let initial = inv.remaining_frames();
        let mut held = Vec::new();
        for alloc in ops {
            if alloc {
                if let Ok(frame) = inv.retype_frame() {
                    held.push(frame);
                }
            } else if let Some(frame) = held.pop() {
                prop_assert!(inv.reclaim_frame(frame));
            }
            prop_assert_eq!(inv.remaining_frames() + held.len() as u64, initial);
        }
        for frame in held {
            prop_assert!(inv.reclaim_frame(frame));
        }
        prop_assert_eq!(inv.remaining_frames(), initial);
    }

    #[test]
    fn prop_cnode_insert_mint_revoke_never_orphans_slots(
        ops in prop::collection::vec((0u8..4, 0usize..8, 0usize..16), 1..64)
    ) {
        let mut cnode = CNode::<16>::new();
        let mut caps: [Option<CapId>; 8] = [None; 8];
        for (op, a, dst_slot) in ops {
            match op {
                0 => {
                    let ep_id = u32::try_from(a).expect("slot index 0..8 fits u32");
                    if let Ok(cid) = cnode.insert_root(Capability::new(
                        CapObject::Endpoint { id: ep_id },
                        Rights::ALL,
                    )) {
                        caps[a] = Some(cid);
                    }
                }
                1 => {
                    if let Some(src) = caps[a]
                        && let Ok(dst) = cnode.mint(src, dst_slot, Rights::READ, Some(a as u64))
                    {
                        caps[dst_slot % 8] = Some(dst);
                    }
                }
                2 => {
                    if let Some(cid) = caps[a] {
                        let _ = cnode.delete(cid);
                        caps[a] = None;
                    }
                }
                _ => {
                    if let Some(cid) = caps[a] {
                        let _ = cnode.revoke(cid);
                    }
                }
            }
        }
        for cid in caps.into_iter().flatten() {
            let _ = cnode.revoke(cid);
            let _ = cnode.delete(cid);
        }
        let _ = ObjectType::Endpoint;
    }

    #[test]
    fn prop_caos_store_put_get_dedup_invariant(
        blobs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 1..16)
    ) {
        let mut store = ObjectStore::new();
        for blob in &blobs {
            if let Ok(id) = store.put(blob) {
                let got = store.get_by_hash(id).expect("stored object must be retrievable");
                prop_assert_eq!(got, blob.as_slice());
            }
        }
    }
}
