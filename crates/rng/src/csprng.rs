//! NIST SP 800-90B Startup Health Tests + `SHAKE256` Conditioning + Fast-Key-Erasure
//! **ChaCha20** CSPRNG.
//!
//! - **Fail-closed health checks:** Repetition Count Test (RCT) and Adaptive Proportion Test (APT)
//!   over every 64-byte hardware TRNG seed block reject stuck, constant, or all-zero sources.
//! - **Fast-key-erasure (backtracking resistance):** Every `fill_bytes` call derives
//!   `next_key (32 B) || output` from the current ChaCha20 key and immediately overwrites and
//!   scrubs the prior key so a future memory compromise cannot recover past outputs.
//! - **Periodic hardware reseeding:** Automatically mixes 64 fresh health-checked hardware TRNG
//!   bytes via `SHAKE256(key || hw_entropy)` every 64 KiB of generated output.

use crate::{EntropySource, RngError};
use newos_crypto::sha3::shake256;

/// Hardware TRNG seed block size in bytes (512 bits).
pub const SEED_BLOCK_BYTES: usize = 64;

/// Automatic hardware reseed interval in generated output bytes (64 KiB).
pub const RESEED_INTERVAL_BYTES: usize = 65_536;

/// NIST SP 800-90B startup health checks on a 64-byte raw hardware entropy sample.
///
/// - **Repetition Count Test (RCT):** rejects if `>= 6` identical consecutive bytes appear.
/// - **Adaptive Proportion Test (APT):** rejects if any byte value appears `> 16` times in 64 bytes.
pub fn verify_entropy_health(sample: &[u8; SEED_BLOCK_BYTES]) -> Result<(), RngError> {
    // 1. Repetition Count Test (catches all-zero, all-0xFF, and stuck shift-register runs)
    let mut prev = sample[0];
    let mut run = 1usize;
    for &b in &sample[1..] {
        if b == prev {
            run += 1;
            if run >= 6 {
                return Err(RngError::HealthCheckFailed);
            }
        } else {
            prev = b;
            run = 1;
        }
    }

    // 2. Adaptive Proportion Test (64-byte window, max 16 occurrences of any single byte value)
    let mut counts = [0u8; 256];
    let mut unique = 0usize;
    for &b in sample {
        if counts[b as usize] == 0 {
            unique += 1;
        }
        let c = counts[b as usize].saturating_add(1);
        counts[b as usize] = c;
        if c > 16 {
            return Err(RngError::HealthCheckFailed);
        }
    }
    // Reject low-diversity repeating patterns (e.g. 2- or 4-byte cycles).
    if unique < 16 {
        return Err(RngError::HealthCheckFailed);
    }

    // 3. Constant-delta / linear counter check (rejects monotonic counters like 0,1,2,... `N12`).
    let first_delta = sample[1].wrapping_sub(sample[0]);
    let mut same_delta_run = 1usize;
    for i in 2..sample.len() {
        let d = sample[i].wrapping_sub(sample[i - 1]);
        if d == first_delta {
            same_delta_run += 1;
            if same_delta_run >= 12 {
                return Err(RngError::HealthCheckFailed);
            }
        } else {
            same_delta_run = 0;
        }
    }

    Ok(())
}

#[inline(always)]
fn scrub(buf: &mut [u8]) {
    buf.fill(0);
    core::hint::black_box(buf);
}

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

/// Constant-time RFC 8439 ChaCha20 block function (ARX only, zero lookup tables).
pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
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
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&word);
    }
    out
}

/// Health-checked, `SHAKE256`-conditioned, fast-key-erasure **ChaCha20** CSPRNG.
pub struct ConditionedCsprng<E: EntropySource> {
    source: E,
    key: [u8; 32],
    bytes_since_reseed: usize,
}

impl<E: EntropySource> Drop for ConditionedCsprng<E> {
    fn drop(&mut self) {
        scrub(&mut self.key);
    }
}

impl<E: EntropySource> ConditionedCsprng<E> {
    /// Seed a new CSPRNG from 512 bits of health-checked hardware TRNG entropy + optional
    /// domain-separated personalization (e.g., `CNTVCT_EL0` timestamp bytes).
    ///
    /// Fails closed if the hardware source fails NIST SP 800-90B startup health checks.
    pub fn new(mut source: E, personalization: &[u8]) -> Result<Self, RngError> {
        let mut raw = [0u8; SEED_BLOCK_BYTES];
        source.fill_entropy(&mut raw)?;
        let health = verify_entropy_health(&raw);
        if let Err(e) = health {
            scrub(&mut raw);
            return Err(e);
        }

        let mut seed_input = [0u8; SEED_BLOCK_BYTES + 32];
        seed_input[..SEED_BLOCK_BYTES].copy_from_slice(&raw);
        let p_len = personalization.len().min(32);
        seed_input[SEED_BLOCK_BYTES..SEED_BLOCK_BYTES + p_len]
            .copy_from_slice(&personalization[..p_len]);
        scrub(&mut raw);

        let mut key = [0u8; 32];
        shake256(&seed_input[..SEED_BLOCK_BYTES + p_len], &mut key);
        scrub(&mut seed_input);

        Ok(Self {
            source,
            key,
            bytes_since_reseed: 0,
        })
    }

    /// Mix 512 fresh health-checked hardware TRNG bits into the CSPRNG state via `SHAKE256`.
    pub fn reseed(&mut self) -> Result<(), RngError> {
        let mut raw = [0u8; SEED_BLOCK_BYTES];
        self.source.fill_entropy(&mut raw)?;
        if let Err(e) = verify_entropy_health(&raw) {
            scrub(&mut raw);
            return Err(e);
        }

        let mut material = [0u8; 32 + SEED_BLOCK_BYTES];
        material[..32].copy_from_slice(&self.key);
        material[32..].copy_from_slice(&raw);
        scrub(&mut raw);

        let mut new_key = [0u8; 32];
        shake256(&material, &mut new_key);
        scrub(&mut material);

        scrub(&mut self.key);
        self.key = new_key;
        scrub(&mut new_key);
        self.bytes_since_reseed = 0;
        Ok(())
    }

    /// Fill `dst` with cryptographically strong random bytes using **fast-key-erasure**:
    /// block 0 produces `next_key (32 B) || first_32_out`, subsequent blocks produce remaining
    /// output, and `self.key` is immediately overwritten with `next_key` before returning.
    pub fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        if dst.is_empty() {
            return Ok(());
        }
        if self.bytes_since_reseed.saturating_add(dst.len()) >= RESEED_INTERVAL_BYTES {
            self.reseed()?;
        }

        const ZERO_NONCE: [u8; 12] = [0u8; 12];
        let mut block0 = chacha20_block(&self.key, 0, &ZERO_NONCE);
        let mut next_key = [0u8; 32];
        next_key.copy_from_slice(&block0[..32]);

        let first_take = dst.len().min(32);
        dst[..first_take].copy_from_slice(&block0[32..32 + first_take]);
        scrub(&mut block0);

        let mut offset = first_take;
        let mut counter = 1u32;
        while offset < dst.len() {
            let mut blk = chacha20_block(&self.key, counter, &ZERO_NONCE);
            let take = (dst.len() - offset).min(64);
            dst[offset..offset + take].copy_from_slice(&blk[..take]);
            scrub(&mut blk);
            offset += take;
            counter = counter.checked_add(1).ok_or(RngError::HardwareFault)?;
        }

        // Fast-key-erasure: immediately replace and scrub the previous key.
        scrub(&mut self.key);
        self.key = next_key;
        scrub(&mut next_key);

        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(dst.len());
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn debug_key_snapshot(&self) -> [u8; 32] {
        self.key
    }
}
