#![no_std]

//! ML-DSA-87 Entropy & Signing Vault (`newos-key-vault`).
//!
//! Designed for `newos-key-pd` (PD 3):
//! - Ephemeral **ML-DSA-87** host keypair generated at boot from health-checked HW TRNG +
//!   fast-key-erasure `ChaCha20` CSPRNG (`newos-rng`). The private key never leaves this vault.
//! - **Hedged** FIPS 204 signing with 32 bytes of fresh CSPRNG randomness per signature
//!   (fault-injection resistant on Raspberry Pi 5).
//! - Strict FIPS 204 context domain separation:
//!   - `CTX_KEX = b"newos-ssh-kex-v1"` for host KEX signing
//!   - `CTX_USERAUTH = b"newos-ssh-userauth-v1"` for client `authorized_keys` verification
//! - Single-use `pending_session_id` binding & consumption to prevent userauth replay.
//! - Rate-limited `sign_kex_hash` and `<= 64 B` capped `get_random_u64` per KEX window.

use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey,
    VerifyingKey,
};
use newos_abi::sha3::sha3_512;
use newos_abi::{auth_gate_ipc, key_ipc};
use newos_rng::{ConditionedCsprng, EntropySource, RngError};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// FIPS 204 context string for host KEX exchange-hash signatures.
pub const CTX_KEX: &[u8] = b"newos-ssh-kex-v1";
/// FIPS 204 context string for client public-key userauth signatures.
pub const CTX_USERAUTH: &[u8] = b"newos-ssh-userauth-v1";

const CTX_KEX_LEN: u8 = 16;
const _: () = assert!(CTX_KEX.len() == CTX_KEX_LEN as usize);
#[cfg(test)]
const CTX_USERAUTH_LEN: u8 = 21;
#[cfg(test)]
const _: () = assert!(CTX_USERAUTH.len() == CTX_USERAUTH_LEN as usize);

/// Minimum milliseconds between host KEX signing operations (anti-oracle / anti-DoS).
pub const SIGN_RATE_LIMIT_MS: i64 = 1_000;

/// Maximum SSH `signed_data` buffer length accepted for ML-DSA-87 userauth verification.
pub const MAX_USERAUTH_MSG_BYTES: usize = 512;

/// Vault error codes (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    Rng(RngError),
    RateLimited,
    RandomBudgetExceeded,
    NoPendingSession,
    SessionIdMismatch,
    UnauthorizedKey,
    InvalidSignature,
}

impl From<RngError> for VaultError {
    fn from(err: RngError) -> Self {
        Self::Rng(err)
    }
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rng(err) => write!(f, "vault RNG error: {err}"),
            Self::RateLimited => f.write_str("vault KEX signing rate limited"),
            Self::RandomBudgetExceeded => f.write_str("vault per-window random budget exceeded"),
            Self::NoPendingSession => f.write_str("vault has no pending session"),
            Self::SessionIdMismatch => f.write_str("vault session ID mismatch or replay"),
            Self::UnauthorizedKey => f.write_str("vault client public key not authorized"),
            Self::InvalidSignature => f.write_str("vault invalid ML-DSA-87 signature"),
        }
    }
}

impl core::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rng(err) => Some(err),
            Self::RateLimited
            | Self::RandomBudgetExceeded
            | Self::NoPendingSession
            | Self::SessionIdMismatch
            | Self::UnauthorizedKey
            | Self::InvalidSignature => None,
        }
    }
}

/// Active single-use pending KEX session awaiting user authentication.
struct PendingSession {
    session_id: [u8; 64],
    auth_attempts: u8,
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        self.session_id.zeroize();
    }
}

/// Cryptographic vault owning the ML-DSA-87 host key and CSPRNG.
pub struct KeyVault<E: EntropySource> {
    csprng: ConditionedCsprng<E>,
    host_sk: SigningKey<MlDsa87>,
    host_pk: [u8; key_ipc::MLDSA87_PK_BYTES],
    authorized_keys: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]],
    pending_session: Option<PendingSession>,
    seen_session_hashes: [[u8; 64]; 64],
    seen_session_count: usize,
    seen_session_cursor: usize,
    /// Unflushable 2048-bit (4-probe) Bloom filter over all signed exchange hashes since boot (`M12`).
    /// Prevents a compromised `ssh-pd` from evicting a captured session hash by issuing >= 64 KEX calls.
    seen_bloom: [u64; 32],
    last_sign_ms: Option<i64>,
    sign_tokens: u32,
    random_bytes_in_window: usize,
}

impl<E: EntropySource> core::fmt::Debug for KeyVault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVault")
            .field("csprng", &"<redacted>")
            .field("host_sk", &"<redacted>")
            .field("host_pk_len", &self.host_pk.len())
            .field("authorized_keys_count", &self.authorized_keys.len())
            .field("has_pending_session", &self.pending_session.is_some())
            .field("seen_session_count", &self.seen_session_count)
            .field("sign_tokens", &self.sign_tokens)
            .field("random_bytes_in_window", &self.random_bytes_in_window)
            .finish_non_exhaustive()
    }
}

#[inline]
fn bloom_indices(hash64: &[u8; 64]) -> [(usize, u64); 4] {
    let mut out = [(0usize, 0u64); 4];
    for (i, slot) in out.iter_mut().enumerate() {
        let off = i * 4;
        let idx = (u16::from_le_bytes([hash64[off], hash64[off + 1]]) as usize) & 2047;
        *slot = (idx / 64, 1u64 << (idx % 64));
    }
    out
}

/// Token-bucket burst capacity and refill interval for KEX host signing (`H3`),
/// preventing a 1-handshake/sec attacker from globally locking out legitimate clients.
const SIGN_BUCKET_CAPACITY: u32 = 4;
const SIGN_TOKEN_REFILL_MS: i64 = 250;
/// Maximum failed userauth attempts permitted per KEX handshake (matches `SshServer`).
const MAX_AUTH_ATTEMPTS_PER_SESSION: u8 = 3;

impl<E: EntropySource> Drop for KeyVault<E> {
    fn drop(&mut self) {
        self.pending_session = None;
        for h in &mut self.seen_session_hashes {
            h.zeroize();
        }
        self.seen_bloom.zeroize();
    }
}

impl<E: EntropySource> KeyVault<E> {
    /// Initialize the vault from a hardware [`EntropySource`], fail-closed if NIST SP 800-90B
    /// health checks fail, and generate an ephemeral ML-DSA-87 host keypair.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Rng`] if the entropy source fails health checks or seeding.
    pub fn new(
        source: E,
        personalization: &[u8],
        authorized_keys: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]],
    ) -> Result<Self, VaultError> {
        Self::new_with_optional_host_seed(source, personalization, authorized_keys, None)
    }

    /// Initialize the vault with an optional provisioned 32-byte host-key seed (persistent host key
    /// across reboots) or ephemeral TRNG generation when `host_seed` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Rng`] if the entropy source fails health checks or seed generation.
    pub fn new_with_optional_host_seed(
        source: E,
        personalization: &[u8],
        authorized_keys: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]],
        host_seed: Option<[u8; 32]>,
    ) -> Result<Self, VaultError> {
        let mut csprng = ConditionedCsprng::new(source, personalization)?;
        let mut seed_bytes = if let Some(s) = host_seed {
            s
        } else {
            let mut s = [0u8; 32];
            csprng.fill_bytes(&mut s)?;
            s
        };
        let mut seed = B32::default();
        seed.copy_from_slice(&seed_bytes);
        seed_bytes.zeroize();

        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
        seed.zeroize();

        let encoded_pk = signing_key.verifying_key().encode();
        let mut host_pk = [0u8; key_ipc::MLDSA87_PK_BYTES];
        host_pk.copy_from_slice(encoded_pk.as_slice());

        Ok(Self {
            csprng,
            host_sk: signing_key,
            host_pk,
            authorized_keys,
            pending_session: None,
            seen_session_hashes: [[0u8; 64]; 64],
            seen_session_count: 0,
            seen_session_cursor: 0,
            seen_bloom: [0u64; 32],
            last_sign_ms: None,
            sign_tokens: SIGN_BUCKET_CAPACITY,
            random_bytes_in_window: 0,
        })
    }

    /// Return the 2592-byte ML-DSA-87 host public key.
    #[must_use]
    #[inline]
    pub const fn host_public_key(&self) -> &[u8; key_ipc::MLDSA87_PK_BYTES] {
        &self.host_pk
    }

    /// Compute the 64-byte FIPS 202 `SHA3-512` fingerprint of the ephemeral host public key.
    #[must_use]
    pub const fn host_fingerprint_sha3_512(&self) -> [u8; 64] {
        sha3_512(&self.host_pk)
    }

    /// Issue 4 fresh bytes of fast-key-erasure CSPRNG randomness for tagged IPC transport (`N1`).
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::RandomBudgetExceeded`] if the per-window budget is exhausted, or
    /// [`VaultError::Rng`] if the underlying CSPRNG fails.
    pub fn get_random_u32(&mut self) -> Result<u32, VaultError> {
        if self.random_bytes_in_window.saturating_add(4) > key_ipc::MAX_RANDOM_BYTES_PER_WINDOW {
            return Err(VaultError::RandomBudgetExceeded);
        }
        let mut buf = [0u8; 4];
        self.csprng.fill_bytes(&mut buf)?;
        self.random_bytes_in_window += 4;
        let out = u32::from_le_bytes(buf);
        buf.zeroize();
        Ok(out)
    }

    /// Issue 8 fresh bytes of fast-key-erasure CSPRNG randomness.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::RandomBudgetExceeded`] if the per-window budget is exhausted, or
    /// [`VaultError::Rng`] if the underlying CSPRNG fails.
    pub fn get_random_u64(&mut self) -> Result<u64, VaultError> {
        if self.random_bytes_in_window.saturating_add(8) > key_ipc::MAX_RANDOM_BYTES_PER_WINDOW {
            return Err(VaultError::RandomBudgetExceeded);
        }
        let mut buf = [0u8; 8];
        self.csprng.fill_bytes(&mut buf)?;
        self.random_bytes_in_window += 8;
        let out = u64::from_le_bytes(buf);
        buf.zeroize();
        Ok(out)
    }

    /// Produce a **hedged** FIPS 204 ML-DSA-87 signature over the 64-byte `SHA3-512` exchange hash
    /// `hash64` using domain context [`CTX_KEX`], rate-limited via `now_ms`.
    ///
    /// Rejects previously seen exchange hashes (`N6`) and records a single-use pending session
    /// bound to `*hash64` for userauth replay protection.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::RateLimited`] if the token bucket is empty,
    /// [`VaultError::SessionIdMismatch`] if `hash64` was already signed, or
    /// [`VaultError::Rng`] if hedged signing randomness generation fails.
    pub fn sign_kex_hash(
        &mut self,
        hash64: &[u8; 64],
        now_ms: i64,
    ) -> Result<[u8; key_ipc::MLDSA87_SIG_BYTES], VaultError> {
        if let Some(prev_ms) = self.last_sign_ms {
            let elapsed = now_ms.saturating_sub(prev_ms);
            if elapsed >= SIGN_TOKEN_REFILL_MS {
                let refilled = u32::try_from(elapsed / SIGN_TOKEN_REFILL_MS).unwrap_or(u32::MAX);
                self.sign_tokens = self
                    .sign_tokens
                    .saturating_add(refilled)
                    .min(SIGN_BUCKET_CAPACITY);
                self.last_sign_ms = Some(now_ms);
            }
        } else {
            self.last_sign_ms = Some(now_ms);
        }
        if self.sign_tokens == 0 {
            return Err(VaultError::RateLimited);
        }
        self.sign_tokens -= 1;

        // Reject replayed exchange hashes via both exact recent history AND the unflushable
        // per-boot 2048-bit Bloom filter (`M12`).
        let mut seen = subtle::Choice::from(0u8);
        for prev in &self.seen_session_hashes[..self.seen_session_count] {
            seen |= prev.ct_eq(hash64);
        }
        let probes = bloom_indices(hash64);
        let in_bloom = probes
            .iter()
            .all(|&(word, bit)| (self.seen_bloom[word] & bit) != 0);
        if bool::from(seen) || in_bloom {
            return Err(VaultError::SessionIdMismatch);
        }

        let mut rnd_bytes = [0u8; 32];
        self.csprng.fill_bytes(&mut rnd_bytes)?;
        let mut rnd = B32::default();
        rnd.copy_from_slice(&rnd_bytes);
        rnd_bytes.zeroize();

        // FIPS 204 Algorithm 2 M' domain prefix: [0x00, ctx.len()] || ctx || message
        let prefix = [0u8, CTX_KEX_LEN];
        let sig = self
            .host_sk
            .expanded_key()
            .sign_internal(&[&prefix, CTX_KEX, hash64], &rnd);
        rnd.zeroize();

        let encoded = sig.encode();
        let mut out = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        out.copy_from_slice(encoded.as_slice());

        self.pending_session = Some(PendingSession {
            session_id: *hash64,
            auth_attempts: 0,
        });
        self.seen_session_hashes[self.seen_session_cursor] = *hash64;
        self.seen_session_cursor = (self.seen_session_cursor + 1) % self.seen_session_hashes.len();
        if self.seen_session_count < self.seen_session_hashes.len() {
            self.seen_session_count += 1;
        }
        for (word, bit) in probes {
            self.seen_bloom[word] |= bit;
        }
        self.random_bytes_in_window = 0;
        Ok(out)
    }

    fn verify_user_auth_inner(
        &self,
        expected_sid: &[u8; 64],
        client_pk: &[u8; key_ipc::MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig_bytes: &[u8; key_ipc::MLDSA87_SIG_BYTES],
    ) -> Result<(), VaultError> {
        if signed_data.len() < 68 || signed_data[0..4] != [0, 0, 0, 64] {
            return Err(VaultError::SessionIdMismatch);
        }
        if !bool::from(signed_data[4..68].ct_eq(expected_sid)) {
            return Err(VaultError::SessionIdMismatch);
        }

        // 2. Fail-closed constant-time authorized_keys lookup.
        if self.authorized_keys.is_empty() {
            return Err(VaultError::UnauthorizedKey);
        }
        let mut authorized = subtle::Choice::from(0u8);
        for allowed in self.authorized_keys {
            authorized |= client_pk.ct_eq(allowed);
        }
        if !bool::from(authorized) {
            return Err(VaultError::UnauthorizedKey);
        }

        // 3. ML-DSA-87 FIPS 204 verification under CTX_USERAUTH.
        let mut pk_arr = EncodedVerifyingKey::<MlDsa87>::default();
        pk_arr.copy_from_slice(client_pk);
        let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);

        let mut sig_arr = EncodedSignature::<MlDsa87>::default();
        sig_arr.copy_from_slice(sig_bytes);
        let sig = Signature::<MlDsa87>::decode(&sig_arr).ok_or(VaultError::InvalidSignature)?;

        if !vk.verify_with_context(signed_data, CTX_USERAUTH, &sig) {
            return Err(VaultError::InvalidSignature);
        }
        Ok(())
    }

    /// Verify a client ML-DSA-87 userauth signature against `authorized_keys` under [`CTX_USERAUTH`].
    ///
    /// Permits up to `MAX_AUTH_ATTEMPTS_PER_SESSION` (3) attempts per handshake; immediately consumes
    /// the pending session on success or upon reaching the attempt limit.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NoPendingSession`] if no KEX session is pending,
    /// [`VaultError::SessionIdMismatch`] if `signed_data` does not bind the pending session ID,
    /// [`VaultError::UnauthorizedKey`] if `client_pk` is not in `authorized_keys`, or
    /// [`VaultError::InvalidSignature`] if ML-DSA-87 verification fails.
    pub fn verify_user_auth(
        &mut self,
        client_pk: &[u8; key_ipc::MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig_bytes: &[u8; key_ipc::MLDSA87_SIG_BYTES],
    ) -> Result<(), VaultError> {
        let (expected_sid, consume_now) = {
            let Some(session) = self.pending_session.as_mut() else {
                return Err(VaultError::NoPendingSession);
            };
            session.auth_attempts = session.auth_attempts.saturating_add(1);
            (
                session.session_id,
                session.auth_attempts >= MAX_AUTH_ATTEMPTS_PER_SESSION,
            )
        };

        let result = self.verify_user_auth_inner(&expected_sid, client_pk, signed_data, sig_bytes);
        if result.is_ok() || consume_now {
            self.close_session();
        }
        result
    }

    /// Clear pending session state and reset per-KEX random budget on disconnect.
    pub fn close_session(&mut self) {
        self.pending_session = None;
        self.random_bytes_in_window = 0;
    }
}

/// Register-only `BOOTSTRAP_KEY_EP` IPC state machine wrapping [`KeyVault`].
pub struct KeyVaultServer<E: EntropySource> {
    vault: KeyVault<E>,
    kex_hash_buf: [u8; 64],
    kex_hash_len: usize,
    sig_cache: Option<[u8; key_ipc::MLDSA87_SIG_BYTES]>,
    auth_pk_buf: [u8; key_ipc::MLDSA87_PK_BYTES],
    auth_pk_len: usize,
    auth_msg_buf: [u8; MAX_USERAUTH_MSG_BYTES],
    auth_msg_len: usize,
    auth_sig_buf: [u8; key_ipc::MLDSA87_SIG_BYTES],
    auth_sig_len: usize,
}

impl<E: EntropySource> core::fmt::Debug for KeyVaultServer<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyVaultServer")
            .field("vault", &self.vault)
            .field("kex_hash_len", &self.kex_hash_len)
            .field("sig_ready", &self.sig_cache.is_some())
            .field("auth_pk_len", &self.auth_pk_len)
            .field("auth_msg_len", &self.auth_msg_len)
            .field("auth_sig_len", &self.auth_sig_len)
            .finish_non_exhaustive()
    }
}

impl<E: EntropySource> Drop for KeyVaultServer<E> {
    fn drop(&mut self) {
        self.kex_hash_buf.zeroize();
        self.clear_sig_cache();
        self.reset_auth_buffers();
    }
}

impl<E: EntropySource> KeyVaultServer<E> {
    #[must_use]
    pub const fn new(vault: KeyVault<E>) -> Self {
        Self {
            vault,
            kex_hash_buf: [0u8; 64],
            kex_hash_len: 0,
            sig_cache: None,
            auth_pk_buf: [0u8; key_ipc::MLDSA87_PK_BYTES],
            auth_pk_len: 0,
            auth_msg_buf: [0u8; MAX_USERAUTH_MSG_BYTES],
            auth_msg_len: 0,
            auth_sig_buf: [0u8; key_ipc::MLDSA87_SIG_BYTES],
            auth_sig_len: 0,
        }
    }

    #[must_use]
    pub const fn vault(&self) -> &KeyVault<E> {
        &self.vault
    }

    fn clear_sig_cache(&mut self) {
        if let Some(ref mut sig) = self.sig_cache {
            sig.zeroize();
        }
        self.sig_cache = None;
    }

    fn reset_auth_buffers(&mut self) {
        self.auth_pk_buf.zeroize();
        self.auth_pk_len = 0;
        self.auth_msg_buf.zeroize();
        self.auth_msg_len = 0;
        self.auth_sig_buf.zeroize();
        self.auth_sig_len = 0;
    }

    fn push_chunk(
        buf: &mut [u8],
        cur_len: &mut usize,
        chunk: &[u8],
        len: usize,
    ) -> (u64, Option<u64>) {
        if cur_len.saturating_add(len) <= buf.len() {
            buf[*cur_len..*cur_len + len].copy_from_slice(&chunk[..len]);
            *cur_len += len;
            (key_ipc::REPLY_OK, None)
        } else {
            (key_ipc::REPLY_DENIED, None)
        }
    }

    /// Process a single 64-bit IPC request from `BOOTSTRAP_KEY_EP`.
    ///
    /// Returns `(reply_word, optional_auth_gate_signal)` where `optional_auth_gate_signal`
    /// is sent to `newos-supervisor-pd` over `CapId::BOOTSTRAP_AUTH_GATE_EP`.
    pub fn handle_ipc_word(&mut self, badge: u64, req: u64, now_ms: i64) -> (u64, Option<u64>) {
        // Strictly reject any caller other than `newos-ssh-pd` (PD 4).
        if badge != key_ipc::BADGE_SSH {
            return (key_ipc::REPLY_DENIED, None);
        }

        // Chunked push opcodes first
        if let Some((chunk, len)) = key_ipc::decode_chunk_req(req, key_ipc::OP_SIGN_KEX_PUSH_BASE) {
            return Self::push_chunk(&mut self.kex_hash_buf, &mut self.kex_hash_len, &chunk, len);
        }
        if let Some((chunk, len)) = key_ipc::decode_chunk_req(req, key_ipc::OP_VERIFY_PUSH_PK_BASE)
        {
            return Self::push_chunk(&mut self.auth_pk_buf, &mut self.auth_pk_len, &chunk, len);
        }
        if let Some((chunk, len)) = key_ipc::decode_chunk_req(req, key_ipc::OP_VERIFY_PUSH_MSG_BASE)
        {
            return Self::push_chunk(&mut self.auth_msg_buf, &mut self.auth_msg_len, &chunk, len);
        }
        if let Some((chunk, len)) = key_ipc::decode_chunk_req(req, key_ipc::OP_VERIFY_PUSH_SIG_BASE)
        {
            return Self::push_chunk(&mut self.auth_sig_buf, &mut self.auth_sig_len, &chunk, len);
        }

        let op = (req >> 56) as u8;
        let idx = (req & 0xFFFF_FFFF) as usize;

        match op {
            key_ipc::OP_GET_HOST_PK_WORD => {
                let byte_off = idx.saturating_mul(8);
                let pk = self.vault.host_public_key();
                if byte_off >= pk.len() {
                    return (0, None);
                }
                let mut word = [0u8; 8];
                let take = (pk.len() - byte_off).min(8);
                word[..take].copy_from_slice(&pk[byte_off..byte_off + take]);
                (u64::from_le_bytes(word), None)
            }
            key_ipc::OP_GET_RANDOM_U64 => self
                .vault
                .get_random_u32()
                .map_or((key_ipc::REPLY_DENIED, None), |val| {
                    (key_ipc::encode_random_u32_reply(val), None)
                }),
            key_ipc::OP_SIGN_KEX_RESET => {
                self.kex_hash_buf.zeroize();
                self.kex_hash_len = 0;
                self.clear_sig_cache();
                (key_ipc::REPLY_OK, None)
            }
            key_ipc::OP_SIGN_KEX_COMMIT => {
                if self.kex_hash_len != 64 {
                    return (key_ipc::REPLY_DENIED, None);
                }
                match self.vault.sign_kex_hash(&self.kex_hash_buf, now_ms) {
                    Ok(sig) => {
                        self.sig_cache = Some(sig);
                        (key_ipc::REPLY_OK, None)
                    }
                    Err(VaultError::RateLimited) => (key_ipc::REPLY_RATE_LIMITED, None),
                    Err(_) => (key_ipc::REPLY_DENIED, None),
                }
            }
            key_ipc::OP_SIGN_KEX_READ_WORD => {
                let Some(ref sig_cache) = self.sig_cache else {
                    return (0, None);
                };
                let byte_off = idx.saturating_mul(8);
                if byte_off >= sig_cache.len() {
                    return (0, None);
                }
                let mut word = [0u8; 8];
                let take = (sig_cache.len() - byte_off).min(8);
                word[..take].copy_from_slice(&sig_cache[byte_off..byte_off + take]);
                (u64::from_le_bytes(word), None)
            }
            key_ipc::OP_VERIFY_RESET => {
                self.reset_auth_buffers();
                (key_ipc::REPLY_OK, None)
            }
            key_ipc::OP_VERIFY_COMMIT => {
                if self.auth_pk_len != key_ipc::MLDSA87_PK_BYTES
                    || self.auth_sig_len != key_ipc::MLDSA87_SIG_BYTES
                {
                    self.reset_auth_buffers();
                    return (key_ipc::REPLY_DENIED, None);
                }
                let res = self.vault.verify_user_auth(
                    &self.auth_pk_buf,
                    &self.auth_msg_buf[..self.auth_msg_len],
                    &self.auth_sig_buf,
                );
                self.reset_auth_buffers();
                match res {
                    Ok(()) => (key_ipc::REPLY_OK, Some(auth_gate_ipc::SESSION_OPEN)),
                    Err(_) => (key_ipc::REPLY_DENIED, None),
                }
            }
            key_ipc::OP_CLOSE_SESSION => {
                self.vault.close_session();
                self.clear_sig_cache();
                self.reset_auth_buffers();
                (key_ipc::REPLY_OK, Some(auth_gate_ipc::SESSION_CLOSE))
            }
            _ => (key_ipc::REPLY_DENIED, None),
        }
    }
}

/// Encode a 64-byte `SHA3-512` host fingerprint as unpadded standard Base64 (`86` ASCII bytes).
#[must_use]
pub const fn encode_base64_64(digest: &[u8; 64]) -> [u8; 86] {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = [0u8; 86];
    let mut i = 0usize;
    let mut o = 0usize;
    while i + 3 <= 64 {
        let n = u32::from_be_bytes([0, digest[i], digest[i + 1], digest[i + 2]]);
        out[o] = TABLE[((n >> 18) & 63) as usize];
        out[o + 1] = TABLE[((n >> 12) & 63) as usize];
        out[o + 2] = TABLE[((n >> 6) & 63) as usize];
        out[o + 3] = TABLE[(n & 63) as usize];
        i += 3;
        o += 4;
    }
    // 64 % 3 == 1 remaining byte -> 2 base64 chars (21 * 4 + 2 = 86)
    let rem = u32::from_be_bytes([0, digest[63], 0, 0]);
    out[84] = TABLE[((rem >> 18) & 63) as usize];
    out[85] = TABLE[((rem >> 12) & 63) as usize];
    out
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct DeterministicTestEntropy(u64);

    impl EntropySource for DeterministicTestEntropy {
        fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
            for b in dst.iter_mut() {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                *b = (z ^ (z >> 31)).to_le_bytes()[0];
            }
            Ok(())
        }
    }

    fn make_client_keypair(
        seed_byte: u8,
    ) -> (SigningKey<MlDsa87>, [u8; key_ipc::MLDSA87_PK_BYTES]) {
        let mut seed = B32::default();
        seed.as_mut_slice().fill(seed_byte);
        let sk = SigningKey::<MlDsa87>::from_seed(&seed);
        let enc = sk.verifying_key().encode();
        let mut pk = [0u8; key_ipc::MLDSA87_PK_BYTES];
        pk.copy_from_slice(enc.as_slice());
        (sk, pk)
    }

    #[test]
    fn mldsa87_hedged_kex_signing_and_context_separation() {
        let mut vault =
            KeyVault::new(DeterministicTestEntropy(0x1111), b"kex-test", &[]).expect("vault init");
        let hash64 = sha3_512(b"exchange-hash-v1");
        let sig_bytes = vault.sign_kex_hash(&hash64, 1_000).expect("sign kex");

        let mut pk_arr = EncodedVerifyingKey::<MlDsa87>::default();
        pk_arr.copy_from_slice(vault.host_public_key());
        let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);

        let mut sig_arr = EncodedSignature::<MlDsa87>::default();
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::<MlDsa87>::decode(&sig_arr).expect("valid sig encoding");

        // Valid under CTX_KEX
        assert!(vk.verify_with_context(&hash64, CTX_KEX, &sig));
        // FIPS 204 context separation: MUST fail under CTX_USERAUTH
        assert!(!vk.verify_with_context(&hash64, CTX_USERAUTH, &sig));

        // Token bucket permits burst up to SIGN_BUCKET_CAPACITY (4) so a single attacker
        // cannot globally DoS legitimate clients, then rate-limits until 250 ms refill (`H3`).
        for i in 2u8..=4 {
            let h = sha3_512(&[b'e', b'x', i]);
            assert!(vault.sign_kex_hash(&h, 1_100).is_ok());
        }
        let hash64_burst_exceeded = sha3_512(b"exchange-hash-burst-5");
        assert_eq!(
            vault.sign_kex_hash(&hash64_burst_exceeded, 1_100).err(),
            Some(VaultError::RateLimited)
        );
        // Replaying the exact same exchange hash MUST be rejected (`N6`) after refill
        assert_eq!(
            vault.sign_kex_hash(&hash64, 1_500).err(),
            Some(VaultError::SessionIdMismatch)
        );
        // Fresh exchange hash after refill succeeds
        assert!(vault.sign_kex_hash(&hash64_burst_exceeded, 2_000).is_ok());

        // M12: Even after 80 more distinct handshakes (exceeding the 64-entry exact ring buffer),
        // replaying the original `hash64` MUST still be rejected by the unflushable Bloom filter.
        for i in 10i64..90 {
            let h = sha3_512(&i.to_le_bytes());
            assert!(vault.sign_kex_hash(&h, 3_000 + i * 500).is_ok());
        }
        assert_eq!(
            vault.sign_kex_hash(&hash64, 100_000).err(),
            Some(VaultError::SessionIdMismatch)
        );
    }

    #[test]
    fn userauth_verifies_authorized_key_and_rejects_replay() {
        let (client_signing_key, client_pk) = make_client_keypair(0x5A);
        let allowed_static: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]] =
            std::boxed::Box::leak(std::boxed::Box::new([client_pk]));

        let mut vault = KeyVault::new(
            DeterministicTestEntropy(0x2222),
            b"auth-test",
            allowed_static,
        )
        .expect("vault init");

        // 1. Host signs KEX hash -> sets single-use pending_session_id
        let sid = sha3_512(b"session-1");
        let _ = vault.sign_kex_hash(&sid, 1_000).expect("sign kex");

        // 2. Client signs `string(sid) || "userauth-payload"` under CTX_USERAUTH
        let mut signed_data = [0u8; 80];
        signed_data[0..4].copy_from_slice(&64u32.to_be_bytes());
        signed_data[4..68].copy_from_slice(&sid);
        signed_data[68..80].copy_from_slice(b"newos-user!!");

        let prefix = [0u8, CTX_USERAUTH_LEN];
        let mut rnd = B32::default();
        rnd.as_mut_slice().fill(0x77);
        let sig = client_signing_key
            .expanded_key()
            .sign_internal(&[&prefix, CTX_USERAUTH, &signed_data], &rnd);
        let mut sig_bytes = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        sig_bytes.copy_from_slice(sig.encode().as_slice());

        // First verification succeeds
        assert_eq!(
            vault.verify_user_auth(&client_pk, &signed_data, &sig_bytes),
            Ok(())
        );
        // Replay of the exact same valid payload MUST fail (pending_session_id consumed)
        assert_eq!(
            vault.verify_user_auth(&client_pk, &signed_data, &sig_bytes),
            Err(VaultError::NoPendingSession)
        );
    }

    #[test]
    fn random_budget_caps_at_256_bytes_per_kex_window() {
        let mut vault =
            KeyVault::new(DeterministicTestEntropy(0x3333), b"rng-cap", &[]).expect("vault init");
        for _ in 0..(key_ipc::MAX_RANDOM_BYTES_PER_WINDOW / 8) {
            assert!(vault.get_random_u64().is_ok());
        }
        // Exceeding MAX_RANDOM_BYTES_PER_WINDOW MUST fail closed
        assert_eq!(
            vault.get_random_u64(),
            Err(VaultError::RandomBudgetExceeded)
        );
    }

    fn push_ipc_chunks<E: EntropySource>(
        srv: &mut KeyVaultServer<E>,
        op_base: u8,
        data: &[u8],
        now_ms: i64,
    ) {
        for chunk in data.chunks(key_ipc::MAX_CHUNK_BYTES) {
            let req = key_ipc::encode_chunk_req(op_base, chunk);
            assert_eq!(
                srv.handle_ipc_word(key_ipc::BADGE_SSH, req, now_ms),
                (key_ipc::REPLY_OK, None)
            );
        }
    }

    #[test]
    fn key_vault_server_enforces_ssh_pd_badge_and_emits_auth_gate() {
        let (client_signing_key, client_pk) = make_client_keypair(0x99);
        let allowed_static: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]] =
            std::boxed::Box::leak(std::boxed::Box::new([client_pk]));
        let vault = KeyVault::new(DeterministicTestEntropy(0x4444), b"ipc-srv", allowed_static)
            .expect("vault init");
        let mut srv = KeyVaultServer::new(vault);

        // Wrong badge (e.g., `net-pd` role badge or legacy raw PD 4) is rejected
        for wrong_badge in [u64::from(newos_abi::role_badge::ROLE_NET), 4] {
            assert_eq!(
                srv.handle_ipc_word(
                    wrong_badge,
                    key_ipc::encode_word_req(key_ipc::OP_GET_RANDOM_U64, 0),
                    0
                ),
                (key_ipc::REPLY_DENIED, None)
            );
        }

        // Stream KEX hash + commit
        let sid = sha3_512(b"ipc-session");
        assert_eq!(
            srv.handle_ipc_word(
                key_ipc::BADGE_SSH,
                key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_RESET, 0),
                1_000
            ),
            (key_ipc::REPLY_OK, None)
        );
        push_ipc_chunks(&mut srv, key_ipc::OP_SIGN_KEX_PUSH_BASE, &sid, 1_000);
        assert_eq!(
            srv.handle_ipc_word(
                key_ipc::BADGE_SSH,
                key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_COMMIT, 0),
                1_000
            ),
            (key_ipc::REPLY_OK, None)
        );

        // Stream valid userauth + commit -> emits SESSION_OPEN
        let mut signed_data = [0u8; 72];
        signed_data[0..4].copy_from_slice(&64u32.to_be_bytes());
        signed_data[4..68].copy_from_slice(&sid);
        signed_data[68..72].copy_from_slice(b"auth");
        let prefix = [0u8, CTX_USERAUTH_LEN];
        let sig = client_signing_key
            .expanded_key()
            .sign_internal(&[&prefix, CTX_USERAUTH, &signed_data], &B32::default());
        let mut sig_bytes = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        sig_bytes.copy_from_slice(sig.encode().as_slice());

        let _ = srv.handle_ipc_word(
            key_ipc::BADGE_SSH,
            key_ipc::encode_word_req(key_ipc::OP_VERIFY_RESET, 0),
            1_000,
        );
        push_ipc_chunks(&mut srv, key_ipc::OP_VERIFY_PUSH_PK_BASE, &client_pk, 1_000);
        push_ipc_chunks(
            &mut srv,
            key_ipc::OP_VERIFY_PUSH_MSG_BASE,
            &signed_data,
            1_000,
        );
        push_ipc_chunks(
            &mut srv,
            key_ipc::OP_VERIFY_PUSH_SIG_BASE,
            &sig_bytes,
            1_000,
        );
        assert_eq!(
            srv.handle_ipc_word(
                key_ipc::BADGE_SSH,
                key_ipc::encode_word_req(key_ipc::OP_VERIFY_COMMIT, 0),
                1_000
            ),
            (key_ipc::REPLY_OK, Some(auth_gate_ipc::SESSION_OPEN))
        );

        // Close session -> emits SESSION_CLOSE
        assert_eq!(
            srv.handle_ipc_word(
                key_ipc::BADGE_SSH,
                key_ipc::encode_word_req(key_ipc::OP_CLOSE_SESSION, 0),
                2_000
            ),
            (key_ipc::REPLY_OK, Some(auth_gate_ipc::SESSION_CLOSE))
        );
    }

    #[test]
    fn persistent_host_seed_produces_deterministic_host_key_and_fingerprint() {
        let seed = [0x42u8; 32];
        let v1 = KeyVault::new_with_optional_host_seed(
            DeterministicTestEntropy(0x1001),
            b"persist-1",
            &[],
            Some(seed),
        )
        .unwrap();
        let v2 = KeyVault::new_with_optional_host_seed(
            DeterministicTestEntropy(0x9999),
            b"persist-2",
            &[],
            Some(seed),
        )
        .unwrap();
        assert_eq!(v1.host_public_key(), v2.host_public_key());
        assert_eq!(
            v1.host_fingerprint_sha3_512(),
            v2.host_fingerprint_sha3_512()
        );
    }

    #[test]
    fn userauth_rejects_unauthorized_key_short_data_wrong_sid_and_locks_after_3_attempts() {
        let (_allowed_signing_key, allowed_pk) = make_client_keypair(0xA1);
        let (other_signing_key, other_pk) = make_client_keypair(0xB2);
        let allowed_static: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]] =
            std::boxed::Box::leak(std::boxed::Box::new([allowed_pk]));

        let mut vault = KeyVault::new(
            DeterministicTestEntropy(0x5555),
            b"neg-auth",
            allowed_static,
        )
        .expect("vault init");

        // No pending session yet
        let zero_sig = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        assert_eq!(
            vault.verify_user_auth(&allowed_pk, &[0u8; 72], &zero_sig),
            Err(VaultError::NoPendingSession)
        );

        let sid = sha3_512(b"session-neg-1");
        let _ = vault.sign_kex_hash(&sid, 1_000).expect("sign kex");

        // Attempt 1: truncated signed_data
        assert_eq!(
            vault.verify_user_auth(&allowed_pk, &[0u8; 10], &zero_sig),
            Err(VaultError::SessionIdMismatch)
        );

        // Attempt 2: mismatched session ID
        let mut wrong_sid_data = [0u8; 72];
        wrong_sid_data[0..4].copy_from_slice(&64u32.to_be_bytes());
        wrong_sid_data[4..68].copy_from_slice(&sha3_512(b"wrong-sid"));
        assert_eq!(
            vault.verify_user_auth(&allowed_pk, &wrong_sid_data, &zero_sig),
            Err(VaultError::SessionIdMismatch)
        );

        // Attempt 3: valid session ID but unauthorized key -> consumes pending session!
        let mut valid_sid_data = [0u8; 72];
        valid_sid_data[0..4].copy_from_slice(&64u32.to_be_bytes());
        valid_sid_data[4..68].copy_from_slice(&sid);
        let prefix = [0u8, CTX_USERAUTH_LEN];
        let sig = other_signing_key
            .expanded_key()
            .sign_internal(&[&prefix, CTX_USERAUTH, &valid_sid_data], &B32::default());
        let mut other_sig = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        other_sig.copy_from_slice(sig.encode().as_slice());
        assert_eq!(
            vault.verify_user_auth(&other_pk, &valid_sid_data, &other_sig),
            Err(VaultError::UnauthorizedKey)
        );

        // Attempt 4: session must now be closed (NoPendingSession)
        assert_eq!(
            vault.verify_user_auth(&allowed_pk, &valid_sid_data, &zero_sig),
            Err(VaultError::NoPendingSession)
        );
    }

    #[test]
    fn userauth_rejects_empty_authorized_keys_and_corrupted_signature() {
        let (client_signing_key, client_pk) = make_client_keypair(0xC3);
        let mut empty_vault =
            KeyVault::new(DeterministicTestEntropy(0x6666), b"empty-ak", &[]).expect("vault init");
        let sid = sha3_512(b"session-empty-ak");
        let _ = empty_vault.sign_kex_hash(&sid, 1_000).expect("sign kex");
        let mut data = [0u8; 72];
        data[0..4].copy_from_slice(&64u32.to_be_bytes());
        data[4..68].copy_from_slice(&sid);
        assert_eq!(
            empty_vault.verify_user_auth(&client_pk, &data, &[0u8; key_ipc::MLDSA87_SIG_BYTES]),
            Err(VaultError::UnauthorizedKey)
        );

        // Authorized key with 1-bit flipped signature must fail with InvalidSignature
        let allowed_static: &'static [[u8; key_ipc::MLDSA87_PK_BYTES]] =
            std::boxed::Box::leak(std::boxed::Box::new([client_pk]));
        let mut vault = KeyVault::new(
            DeterministicTestEntropy(0x7777),
            b"tamper-sig",
            allowed_static,
        )
        .expect("vault init");
        let _ = vault.sign_kex_hash(&sid, 1_000).expect("sign kex");
        let prefix = [0u8, CTX_USERAUTH_LEN];
        let sig = client_signing_key
            .expanded_key()
            .sign_internal(&[&prefix, CTX_USERAUTH, &data], &B32::default());
        let mut sig_bytes = [0u8; key_ipc::MLDSA87_SIG_BYTES];
        sig_bytes.copy_from_slice(sig.encode().as_slice());
        sig_bytes[17] ^= 0x01;
        assert_eq!(
            vault.verify_user_auth(&client_pk, &data, &sig_bytes),
            Err(VaultError::InvalidSignature)
        );
    }

    #[test]
    fn random_u32_respects_window_budget_and_resets_after_kex_sign() {
        let mut vault =
            KeyVault::new(DeterministicTestEntropy(0x8888), b"u32-cap", &[]).expect("vault init");
        for _ in 0..(key_ipc::MAX_RANDOM_BYTES_PER_WINDOW / 4) {
            assert!(vault.get_random_u32().is_ok());
        }
        assert_eq!(
            vault.get_random_u32(),
            Err(VaultError::RandomBudgetExceeded)
        );

        // Signing a fresh KEX hash resets the per-window random budget
        let sid = sha3_512(b"reset-budget");
        assert!(vault.sign_kex_hash(&sid, 1_000).is_ok());
        assert!(vault.get_random_u32().is_ok());
    }

    #[test]
    fn vault_error_display_error_source_and_from_rng_error() {
        use core::error::Error as _;
        use std::format;

        let rng_err = RngError::HealthCheckFailed;
        let converted: VaultError = rng_err.into();
        assert_eq!(converted, VaultError::Rng(rng_err));
        assert!(converted.source().is_some());
        assert_ne!(format!("{converted}"), "");

        for err in [
            VaultError::RateLimited,
            VaultError::RandomBudgetExceeded,
            VaultError::NoPendingSession,
            VaultError::SessionIdMismatch,
            VaultError::UnauthorizedKey,
            VaultError::InvalidSignature,
        ] {
            assert!(err.source().is_none());
            assert_ne!(format!("{err}"), "");
        }
    }

    #[test]
    fn key_vault_and_server_debug_redact_secrets() {
        use std::format;

        let seed = [0xABu8; 32];
        let mut vault = KeyVault::new_with_optional_host_seed(
            DeterministicTestEntropy(0x9001),
            b"debug-redact",
            &[],
            Some(seed),
        )
        .expect("vault init");
        let sid = [0xCDu8; 64];
        let _ = vault.sign_kex_hash(&sid, 1_000).expect("sign kex");

        let vault_dbg = format!("{vault:?}");
        assert!(vault_dbg.contains("<redacted>"));
        assert!(!vault_dbg.contains("171, 171, 171"));
        assert!(!vault_dbg.contains("205, 205, 205"));

        let srv = KeyVaultServer::new(vault);
        let srv_dbg = format!("{srv:?}");
        assert!(srv_dbg.contains("<redacted>"));
        assert!(srv_dbg.contains("KeyVaultServer"));
    }

    #[test]
    fn sign_kex_hash_rejects_backwards_clock_rate_limit_bypass() {
        let mut vault = KeyVault::new(DeterministicTestEntropy(0x9002), b"backwards-clk", &[])
            .expect("vault init");

        // Exhaust the entire SIGN_BUCKET_CAPACITY (4) burst at t = 10_000 ms
        for i in 0u8..4 {
            let h = sha3_512(&[b'b', b'c', i]);
            assert!(vault.sign_kex_hash(&h, 10_000).is_ok());
        }

        // Backwards clock timestamps MUST NOT refill tokens (previously wrapped negative i64 to u32::MAX)
        let h_back1 = sha3_512(b"backwards-1");
        assert_eq!(
            vault.sign_kex_hash(&h_back1, 1_000).err(),
            Some(VaultError::RateLimited)
        );
        let h_back2 = sha3_512(b"backwards-2");
        assert_eq!(
            vault.sign_kex_hash(&h_back2, -500).err(),
            Some(VaultError::RateLimited)
        );
    }
}
