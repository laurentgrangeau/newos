//! Pure-Rust `#![forbid(unsafe_code)]`, `no_alloc`, constant-time
//! **`chacha20-poly1305@openssh.com`** AEAD packet cipher (RFC 8439 + OpenSSH spec).
//!
//! - `k_len` (32 B): encrypts/decrypts the 4-byte SSH packet length (`counter = 0`).
//! - `k_main` (32 B): `counter = 0` derives the 32-byte one-time Poly1305 key;
//!   `counter >= 1` encrypts/decrypts the packet payload.
//! - Poly1305 authenticates `encrypted_length (4 B) || encrypted_payload` in constant time
//!   (`subtle::ConstantTimeEq`).
//! - Zero lookup tables (pure ARX + 26-bit limb arithmetic), zero assembly (`x18`/KCFI safe),
//!   and automatic `ZeroizeOnDrop` on all key material.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// RFC 8439 ChaCha20 64-byte block function with 32-bit counter and 96-bit nonce.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter,
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = state[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&w);
    }
    out
}

fn chacha20_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut offset = 0;
    while offset < data.len() {
        let mut ks = chacha20_block(key, counter, nonce);
        let take = (data.len() - offset).min(64);
        for i in 0..take {
            data[offset + i] ^= ks[i];
        }
        ks.zeroize();
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// Constant-time RFC 8439 Poly1305 authenticator using 5 × 26-bit limbs (mod `2^130 - 5`).
pub(crate) fn poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; TAG_LEN] {
    // Clamp r per RFC 8439 Section 2.5
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&otk[..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let t0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]);
    let t1 = u32::from_le_bytes([r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]]);
    let t2 = u32::from_le_bytes([r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11]]);
    let t3 = u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]);
    r_bytes.zeroize();

    let r0 = u64::from(t0 & 0x03ff_ffff);
    let r1 = u64::from(((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff);
    let r2 = u64::from(((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff);
    let r3 = u64::from(((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff);
    let r4 = u64::from(t3 >> 8);

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    let mut offset = 0;
    while offset < msg.len() {
        let mut block = [0u8; 17];
        let take = (msg.len() - offset).min(16);
        block[..take].copy_from_slice(&msg[offset..offset + take]);
        block[take] = 1; // RFC 8439 hibit
        offset += take;

        let b0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let b1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let b2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let b3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        h0 += u64::from(b0 & 0x03ff_ffff);
        h1 += u64::from(((b0 >> 26) | (b1 << 6)) & 0x03ff_ffff);
        h2 += u64::from(((b1 >> 20) | (b2 << 12)) & 0x03ff_ffff);
        h3 += u64::from(((b2 >> 14) | (b3 << 18)) & 0x03ff_ffff);
        h4 += u64::from((b3 >> 8) | (u32::from(block[16]) << 24));

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        h1 = d1 & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        h2 = d2 & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        h3 = d3 & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        h4 = d4 & 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;
    }

    // Final carry propagation
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 += c;

    // Constant-time conditional subtraction of p = 2^130 - 5
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    let nmask = !mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);
    h4 = (h4 & nmask) | (g4 & mask);

    // Reassemble 128-bit integer and add pad `s` (otk[16..32])
    let f0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let f1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let f2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let f3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    let s0 = u64::from(u32::from_le_bytes([otk[16], otk[17], otk[18], otk[19]]));
    let s1 = u64::from(u32::from_le_bytes([otk[20], otk[21], otk[22], otk[23]]));
    let s2 = u64::from(u32::from_le_bytes([otk[24], otk[25], otk[26], otk[27]]));
    let s3 = u64::from(u32::from_le_bytes([otk[28], otk[29], otk[30], otk[31]]));

    let mut acc = f0 + s0;
    let out0 = (acc as u32).to_le_bytes();
    acc = (acc >> 32) + f1 + s1;
    let out1 = (acc as u32).to_le_bytes();
    acc = (acc >> 32) + f2 + s2;
    let out2 = (acc as u32).to_le_bytes();
    acc = (acc >> 32) + f3 + s3;
    let out3 = (acc as u32).to_le_bytes();

    let mut tag = [0u8; TAG_LEN];
    tag[0..4].copy_from_slice(&out0);
    tag[4..8].copy_from_slice(&out1);
    tag[8..12].copy_from_slice(&out2);
    tag[12..16].copy_from_slice(&out3);
    tag
}

#[inline]
fn seq_nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Directional `chacha20-poly1305@openssh.com` cipher state (automatically zeroized on drop).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpenSshChaCha20Poly1305 {
    k_main: [u8; 32],
    k_len: [u8; 32],
}

impl OpenSshChaCha20Poly1305 {
    /// Construct from 64 bytes of `SHAKE256`-derived key material (`k_main[0..32] || k_len[32..64]`).
    pub fn new(key_64: &[u8; 64]) -> Self {
        let mut k_main = [0u8; 32];
        let mut k_len = [0u8; 32];
        k_main.copy_from_slice(&key_64[0..32]);
        k_len.copy_from_slice(&key_64[32..64]);
        Self { k_main, k_len }
    }

    /// Encrypt a 4-byte length prefix + payload in-place (`buf[0..4]` = len, `buf[4..4+plen]` = body)
    /// and return the 16-byte Poly1305 tag covering `buf[0..4+plen]`.
    pub fn seal_in_place(&self, seq: u64, packet_with_len: &mut [u8]) -> [u8; TAG_LEN] {
        let nonce = seq_nonce(seq);
        let mut poly_blk = chacha20_block(&self.k_main, 0, &nonce);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&poly_blk[..32]);
        poly_blk.zeroize();

        chacha20_xor(&self.k_len, 0, &nonce, &mut packet_with_len[..4]);
        chacha20_xor(&self.k_main, 1, &nonce, &mut packet_with_len[4..]);

        let tag = poly1305_mac(&otk, packet_with_len);
        otk.zeroize();
        tag
    }

    /// Decrypt the 4-byte SSH packet length header without modifying the ciphertext buffer.
    pub fn decrypt_length(&self, seq: u64, enc_len: [u8; 4]) -> u32 {
        let nonce = seq_nonce(seq);
        let mut dec = enc_len;
        chacha20_xor(&self.k_len, 0, &nonce, &mut dec);
        u32::from_be_bytes(dec)
    }

    /// Verify the 16-byte Poly1305 tag in constant time, then decrypt `packet_with_len[4..]` in place.
    pub fn open_in_place(&self, seq: u64, packet_with_len: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        let nonce = seq_nonce(seq);
        let mut poly_blk = chacha20_block(&self.k_main, 0, &nonce);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&poly_blk[..32]);
        poly_blk.zeroize();

        let expected = poly1305_mac(&otk, packet_with_len);
        otk.zeroize();

        if !bool::from(expected.ct_eq(tag)) {
            return false;
        }
        chacha20_xor(&self.k_main, 1, &nonce, &mut packet_with_len[4..]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_poly1305_known_answer_vector() {
        // RFC 8439 Section 2.5.2 test vector
        let otk: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(poly1305_mac(&otk, msg), expected);
    }

    #[test]
    fn openssh_chacha20_poly1305_seal_open_and_tamper_rejection() {
        let key = [0x42u8; 64];
        let cipher = OpenSshChaCha20Poly1305::new(&key);

        let mut pkt = [0u8; 4 + 16];
        pkt[0..4].copy_from_slice(&16u32.to_be_bytes());
        pkt[4..20].copy_from_slice(b"hello-pq-ssh-v1!");
        let orig_body = *b"hello-pq-ssh-v1!";

        let tag = cipher.seal_in_place(7, &mut pkt);
        assert_ne!(&pkt[4..20], &orig_body);
        assert_eq!(
            cipher.decrypt_length(7, [pkt[0], pkt[1], pkt[2], pkt[3]]),
            16
        );

        // Tampered ciphertext MUST fail constant-time tag verification
        let mut tampered = pkt;
        tampered[10] ^= 0x01;
        assert!(!cipher.open_in_place(7, &mut tampered, &tag));

        // Wrong sequence number MUST fail
        let mut wrong_seq = pkt;
        assert!(!cipher.open_in_place(8, &mut wrong_seq, &tag));

        // Valid open restores plaintext
        assert!(cipher.open_in_place(7, &mut pkt, &tag));
        assert_eq!(&pkt[4..20], &orig_body);
    }
}
