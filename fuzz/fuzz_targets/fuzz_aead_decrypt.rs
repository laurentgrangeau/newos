#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_crypto::chacha20_poly1305::OpenSshChaCha20Poly1305;

fuzz_target!(|data: &[u8]| {
    let Some((key, rest)) = data.split_first_chunk::<64>() else {
        return;
    };
    let Some((seq_bytes, rest)) = rest.split_first_chunk::<8>() else {
        return;
    };
    let Some((tag, rest)) = rest.split_first_chunk::<16>() else {
        return;
    };
    let Some((len_prefix, _)) = rest.split_first_chunk::<4>() else {
        return;
    };
    let seq = u64::from_le_bytes(*seq_bytes);
    let mut packet = rest.to_vec();
    let cipher = OpenSshChaCha20Poly1305::new(key);
    let _ = cipher.decrypt_length(seq, *len_prefix);
    let _ = cipher.open_in_place(seq, &mut packet, tag);
});
