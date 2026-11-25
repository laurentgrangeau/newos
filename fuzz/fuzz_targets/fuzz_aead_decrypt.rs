#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_crypto::chacha20_poly1305::OpenSshChaCha20Poly1305;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 + 8 + 16 + 4 {
        return;
    }
    let key: [u8; 64] = data[..64].try_into().unwrap();
    let seq = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let tag: [u8; 16] = data[72..88].try_into().unwrap();
    let mut packet = data[88..].to_vec();
    let cipher = OpenSshChaCha20Poly1305::new(&key);
    let _ = cipher.decrypt_length(seq, [packet[0], packet[1], packet[2], packet[3]]);
    let _ = cipher.open_in_place(seq, &mut packet, &tag);
});
