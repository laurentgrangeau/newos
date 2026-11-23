//! Pure `#![forbid(unsafe_code)]`, `no_alloc`, `const fn` FIPS 202 **SHA3-512** (Keccak-f[1600]).
//!
//! Shared across NewOS EL1 Verified Boot ELF attestation (`newos-kernel-core`) and
//! EL0 Content-Addressed Object Store (`newos-shell-core`), eliminating all SHA-2 from the OS.

/// SHA3-512 sponge rate in bytes (`(1600 - 2 * 512) / 8 = 72` bytes = 9 lanes).
pub const RATE_BYTES: usize = 72;

/// SHAKE256 sponge rate in bytes (`(1600 - 2 * 256) / 8 = 136` bytes = 17 lanes).
pub const SHAKE256_RATE_BYTES: usize = 136;

/// SHA3-512 digest length in bytes (512 bits).
pub const DIGEST_BYTES: usize = 64;

/// Keccak-f[1600] round constants (`RC[0..24]`).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Keccak-f[1600] rotation offsets for lanes `(x, y)` indexed as `x + 5 * y`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak-f[1600] pi permutation destination index for lane `x + 5 * y -> y + 5 * ((2x + 3y) % 5)`.
const PI: [usize; 25] = [
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
];

/// Perform the 24-round Keccak-f[1600] permutation in `const fn` safe Rust.
#[inline]
const fn keccak_f1600(mut a: [u64; 25]) -> [u64; 25] {
    let mut round = 0;
    while round < 24 {
        // Theta
        let mut c = [0u64; 5];
        let mut x = 0;
        while x < 5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            x += 1;
        }
        let mut d = [0u64; 5];
        x = 0;
        while x < 5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            x += 1;
        }
        let mut i = 0;
        while i < 25 {
            a[i] ^= d[i % 5];
            i += 1;
        }

        // Rho + Pi
        let mut b = [0u64; 25];
        i = 0;
        while i < 25 {
            b[PI[i]] = a[i].rotate_left(RHO[i]);
            i += 1;
        }

        // Chi
        let mut y = 0;
        while y < 5 {
            let row = y * 5;
            x = 0;
            while x < 5 {
                a[row + x] = b[row + x] ^ ((!b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)]);
                x += 1;
            }
            y += 1;
        }

        // Iota
        a[0] ^= RC[round];

        round += 1;
    }
    a
}

#[inline]
const fn absorb_block(mut state: [u64; 25], block: &[u8; RATE_BYTES]) -> [u64; 25] {
    let mut lane = 0;
    while lane < RATE_BYTES / 8 {
        let base = lane * 8;
        let word = u64::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        ]);
        state[lane] ^= word;
        lane += 1;
    }
    keccak_f1600(state)
}

/// Compute the 64-byte FIPS 202 **SHA3-512** digest of `data` without heap allocation (`const fn`).
pub const fn sha3_512(data: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut state = [0u64; 25];
    let mut pos = 0;

    while pos + RATE_BYTES <= data.len() {
        let mut block = [0u8; RATE_BYTES];
        let mut i = 0;
        while i < RATE_BYTES {
            block[i] = data[pos + i];
            i += 1;
        }
        state = absorb_block(state, &block);
        pos += RATE_BYTES;
    }

    let rem = data.len() - pos;
    let mut tail = [0u8; RATE_BYTES];
    let mut i = 0;
    while i < rem {
        tail[i] = data[pos + i];
        i += 1;
    }
    // FIPS 202 SHA-3 domain separation suffix `01` + pad10*1
    tail[rem] ^= 0x06;
    tail[RATE_BYTES - 1] ^= 0x80;
    state = absorb_block(state, &tail);

    // Squeeze 64 bytes (8 lanes, fits inside single 72-byte rate block)
    let mut out = [0u8; DIGEST_BYTES];
    let mut lane = 0;
    while lane < DIGEST_BYTES / 8 {
        let bytes = state[lane].to_le_bytes();
        let base = lane * 8;
        let mut b = 0;
        while b < 8 {
            out[base + b] = bytes[b];
            b += 1;
        }
        lane += 1;
    }
    out
}

/// Return the first 64 bits (big-endian) of the FIPS 202 **SHA3-512** digest for compact
/// boot attestation logs and CAOS content addressing.
pub const fn digest_prefix_u64(data: &[u8]) -> u64 {
    let d = sha3_512(data);
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

#[inline]
fn absorb_shake256_block(state: &mut [u64; 25], block: &[u8; SHAKE256_RATE_BYTES]) {
    for (lane, st) in state.iter_mut().enumerate().take(SHAKE256_RATE_BYTES / 8) {
        let base = lane * 8;
        let word = u64::from_le_bytes([
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        ]);
        *st ^= word;
    }
    *state = keccak_f1600(*state);
}

/// Compute FIPS 202 **SHAKE256** XOF over `input`, writing arbitrary-length output into `out`
/// without heap allocation (`#![forbid(unsafe_code)]`).
pub fn shake256(input: &[u8], out: &mut [u8]) {
    let mut state = [0u64; 25];
    let mut pos = 0;

    while pos + SHAKE256_RATE_BYTES <= input.len() {
        let mut block = [0u8; SHAKE256_RATE_BYTES];
        block.copy_from_slice(&input[pos..pos + SHAKE256_RATE_BYTES]);
        absorb_shake256_block(&mut state, &block);
        pos += SHAKE256_RATE_BYTES;
    }

    let rem = input.len() - pos;
    let mut tail = [0u8; SHAKE256_RATE_BYTES];
    tail[..rem].copy_from_slice(&input[pos..]);
    // FIPS 202 SHAKE domain separation suffix `1111` + pad10*1
    tail[rem] ^= 0x1F;
    tail[SHAKE256_RATE_BYTES - 1] ^= 0x80;
    absorb_shake256_block(&mut state, &tail);

    let mut written = 0;
    while written < out.len() {
        for &lane_word in state.iter().take(SHAKE256_RATE_BYTES / 8) {
            if written >= out.len() {
                break;
            }
            let bytes = lane_word.to_le_bytes();
            let take = (out.len() - written).min(8);
            out[written..written + take].copy_from_slice(&bytes[..take]);
            written += take;
        }
        if written < out.len() {
            state = keccak_f1600(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips202_sha3_512_empty_vector() {
        const EMPTY: [u8; 64] = sha3_512(b"");
        let expected: [u8; 64] = [
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a,
            0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1,
            0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3,
            0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
            0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
        ];
        assert_eq!(EMPTY, expected);
        assert_eq!(digest_prefix_u64(b""), 0xa69f_73cc_a23a_9ac5);
    }

    #[test]
    fn fips202_sha3_512_abc_vector() {
        const ABC: [u8; 64] = sha3_512(b"abc");
        let expected: [u8; 64] = [
            0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b,
            0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02,
            0x40, 0xd2, 0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e,
            0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
            0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
        ];
        assert_eq!(ABC, expected);
        assert_eq!(digest_prefix_u64(b"abc"), 0xb751_850b_1a57_168a);
    }

    #[test]
    fn fips202_sha3_512_multiblock_vector() {
        // 112-byte NIST CAVP / FIPS 202 vector (crosses the 72-byte rate boundary):
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let digest = sha3_512(msg);
        let expected: [u8; 64] = [
            0xaf, 0xeb, 0xb2, 0xef, 0x54, 0x2e, 0x65, 0x79, 0xc5, 0x0c, 0xad, 0x06, 0xd2, 0xe5,
            0x78, 0xf9, 0xf8, 0xdd, 0x68, 0x81, 0xd7, 0xdc, 0x82, 0x4d, 0x26, 0x36, 0x0f, 0xee,
            0xbf, 0x18, 0xa4, 0xfa, 0x73, 0xe3, 0x26, 0x11, 0x22, 0x94, 0x8e, 0xfc, 0xfd, 0x49,
            0x2e, 0x74, 0xe8, 0x2e, 0x21, 0x89, 0xed, 0x0f, 0xb4, 0x40, 0xd1, 0x87, 0xf3, 0x82,
            0x27, 0x0c, 0xb4, 0x55, 0xf2, 0x1d, 0xd1, 0x85,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn fips202_sha3_512_exact_rate_boundary() {
        // 72-byte message exercises padding when `rem == 0` (entire padding block).
        let msg = [0x42u8; RATE_BYTES];
        let d1 = sha3_512(&msg);
        let d2 = sha3_512(&msg);
        assert_eq!(d1, d2);
        assert_ne!(d1, sha3_512(&[0x42u8; RATE_BYTES - 1]));
    }

    #[test]
    fn fips202_shake256_abc_and_empty_vectors() {
        // FIPS 202 SHAKE256("", 32)
        let mut empty_out = [0u8; 32];
        shake256(b"", &mut empty_out);
        assert_eq!(
            empty_out,
            [
                0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
                0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
                0x6e, 0xd5, 0x76, 0x2f,
            ]
        );

        // FIPS 202 SHAKE256("abc", 32)
        let mut abc_out = [0u8; 32];
        shake256(b"abc", &mut abc_out);
        assert_eq!(
            abc_out,
            [
                0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4,
                0x11, 0x4d, 0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37,
                0xe7, 0x8b, 0x57, 0x39,
            ]
        );

        // Multi-squeeze (>136 bytes) prefix consistency
        let mut wide = [0u8; 200];
        shake256(b"abc", &mut wide);
        assert_eq!(&wide[..32], &abc_out);
    }
}
