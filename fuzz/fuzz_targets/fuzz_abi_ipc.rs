#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_abi::ring::SpscRing;
use newos_abi::{DomainRoleId, ObjectType, Rights, SyscallNumber};

fuzz_target!(|data: &[u8]| {
    if let Some((head, _)) = data.split_first_chunk::<8>() {
        let word = u64::from_le_bytes(*head);
        let _ = SyscallNumber::from_u64(word);
        let _ = ObjectType::from_u64(word);
        let _ = DomainRoleId::from_u64(word);
        let _ = Rights::from_bits(head[0]);
    }
    let ring = SpscRing::<16>::new();
    let _ = ring.try_push_bytes(data);
    let mut out = [0u8; 256];
    let _ = ring.try_pop_bytes(&mut out);
});
