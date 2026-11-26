#![no_std]

//! `SSHv2` protocol engine (`newos-ssh-proto`).
//!
//! Enforces a single NIST Level 5 post-quantum cryptographic suite:
//! - **KEX:** `mlkem1024-sha3-512` (NIST FIPS 203 **ML-KEM-1024** + `SHA3-512`)
//! - **Host & User Auth:** `ssh-mldsa87` (NIST FIPS 204 **ML-DSA-87**, hedged, domain-separated)
//! - **AEAD:** `chacha20-poly1305@openssh.com` (256-bit `ChaCha20` + Poly1305, encrypted length)
//! - **KDF:** FIPS 202 `SHAKE256`
//! - **Transport Hardening:** `kex-strict` (Terrapin CVE-2023-48795 mitigation)
//! - **Zero legacy crypto:** no RSA, DH, ECDH, X25519, Ed25519, SHA-1, SHA-2, CBC/CTR, or passwords.
//! - **Minimal session surface:** single interactive `newos-shell-pd` shell (`session` + `pty-req`/`shell`).

pub mod aead;
pub mod wire;

use aead::{OpenSshChaCha20Poly1305, TAG_LEN};
use ml_dsa::{
    B32 as DsaB32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey,
    VerifyingKey,
};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{
    B32 as KemB32, Ciphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024, Seed,
};
use newos_abi::key_ipc::{MLDSA87_PK_BYTES, MLDSA87_SIG_BYTES};
use newos_abi::sha3::{sha3_512, shake256};
use wire::{MAX_PACKET_BODY, WireReader, WireWriter};
use zeroize::Zeroize;

/// Server & Client SSH protocol banner (RFC 4253).
pub const SSH_BANNER: &[u8] = b"SSH-2.0-NewOS_PQ_0.1\r\n";
pub const SSH_BANNER_NO_CRLF: &[u8] = b"SSH-2.0-NewOS_PQ_0.1";

/// Algorithm identifiers for the supported suite.
pub const ALG_KEX: &str = "mlkem1024-sha3-512";
pub const ALG_KEX_STRICT_S: &str = "kex-strict-s-v00@openssh.com";
pub const ALG_KEX_STRICT_C: &str = "kex-strict-c-v00@openssh.com";
pub const ALG_HOST_KEY: &str = "ssh-mldsa87";
pub const ALG_CIPHER: &str = "chacha20-poly1305@openssh.com";
pub const ALG_COMP: &str = "none";

/// FIPS 204 ML-DSA-87 domain contexts (must match `newos-key-vault`).
pub const CTX_KEX: &[u8] = b"newos-ssh-kex-v1";
pub const CTX_USERAUTH: &[u8] = b"newos-ssh-userauth-v1";

#[cfg(test)]
const CTX_KEX_LEN: u8 = 16;
#[cfg(test)]
const _: () = assert!(CTX_KEX.len() == CTX_KEX_LEN as usize);
const CTX_USERAUTH_LEN: u8 = 21;
const _: () = assert!(CTX_USERAUTH.len() == CTX_USERAUTH_LEN as usize);

/// ML-KEM-1024 wire sizes (FIPS 203).
pub const MLKEM1024_EK_BYTES: usize = 1568;
pub const MLKEM1024_CT_BYTES: usize = 1568;

/// `SSHv2` message numbers (RFC 4253 / 4252 / 4254).
pub const MSG_DISCONNECT: u8 = 1;
pub const MSG_IGNORE: u8 = 2;
pub const MSG_UNIMPLEMENTED: u8 = 3;
pub const MSG_DEBUG: u8 = 4;
pub const MSG_SERVICE_REQUEST: u8 = 5;
pub const MSG_SERVICE_ACCEPT: u8 = 6;
pub const MSG_KEXINIT: u8 = 20;
pub const MSG_NEWKEYS: u8 = 21;
pub const MSG_KEX_MLKEM_INIT: u8 = 30;
pub const MSG_KEX_MLKEM_REPLY: u8 = 31;
pub const MSG_USERAUTH_REQUEST: u8 = 50;
pub const MSG_USERAUTH_FAILURE: u8 = 51;
pub const MSG_USERAUTH_SUCCESS: u8 = 52;
pub const MSG_CHANNEL_OPEN: u8 = 90;
pub const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const MSG_CHANNEL_DATA: u8 = 94;
pub const MSG_CHANNEL_EOF: u8 = 96;
pub const MSG_CHANNEL_CLOSE: u8 = 97;
pub const MSG_CHANNEL_REQUEST: u8 = 98;
pub const MSG_CHANNEL_SUCCESS: u8 = 99;
pub const MSG_CHANNEL_FAILURE: u8 = 100;

/// Maximum authentication attempts before disconnect.
pub const MAX_AUTH_ATTEMPTS: u8 = 3;

/// SSH protocol errors (fail-closed -> disconnect / TCP RST on strict-KEX violations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshError {
    MalformedPacket,
    PacketTooLarge,
    StrictKexViolation,
    UnsupportedAlgorithm,
    CryptoFailure,
    AuthFailed,
    TooManyAuthAttempts,
    DisallowedRequest,
    VaultError,
    Disconnected,
}

impl core::fmt::Display for SshError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::MalformedPacket => "malformed SSH packet",
            Self::PacketTooLarge => "SSH packet exceeds maximum length",
            Self::StrictKexViolation => "strict-KEX protocol violation",
            Self::UnsupportedAlgorithm => "unsupported SSH algorithm",
            Self::CryptoFailure => "SSH cryptographic verification or AEAD failure",
            Self::AuthFailed => "SSH user authentication failed",
            Self::TooManyAuthAttempts => "too many SSH authentication attempts",
            Self::DisallowedRequest => "disallowed SSH service or channel request",
            Self::VaultError => "key vault operation failed",
            Self::Disconnected => "SSH peer disconnected",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SshError {}

/// Abstract cryptographic vault interface implemented by `newos-ssh-pd` over `BOOTSTRAP_KEY_EP`
/// (and by direct in-process `KeyVault` in host unit/E2E tests).
pub trait KeyVaultClient {
    /// Retrieve the server's 2592-byte ML-DSA-87 host public key.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::VaultError`] if the vault IPC call fails.
    fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError>;

    /// Obtain 32 bytes of fresh CSPRNG randomness from the vault.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::VaultError`] if the vault random budget is exhausted or IPC fails.
    fn random_32(&mut self) -> Result<[u8; 32], SshError>;

    /// Sign the 64-byte KEX exchange hash `hash64` under `CTX_KEX`.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::VaultError`] if signing is rate-limited, replayed, or IPC fails.
    fn sign_kex_hash(&mut self, hash64: &[u8; 64]) -> Result<[u8; MLDSA87_SIG_BYTES], SshError>;

    /// Verify a client's ML-DSA-87 userauth signature against the vault's authorized keys.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::VaultError`] if the vault IPC transport fails.
    fn verify_user_auth(
        &mut self,
        client_pk: &[u8; MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig: &[u8; MLDSA87_SIG_BYTES],
    ) -> Result<bool, SshError>;

    /// Notify the vault that the current SSH session has closed.
    fn close_session(&mut self);
}

fn name_list_contains(list: &str, needle: &str) -> bool {
    list.split(',').any(|item| item == needle)
}

/// Borrowed inputs to the `mlkem1024-sha3-512` exchange hash `H`.
struct ExchangeHashInput<'a> {
    v_c: &'a [u8],
    v_s: &'a [u8],
    i_c: &'a [u8],
    i_s: &'a [u8],
    k_s: &'a [u8],
    q_c: &'a [u8],
    q_s: &'a [u8],
    k_shared_hash: &'a [u8; 64],
}

/// Compute the 64-byte `SHA3-512` exchange hash `H` for `mlkem1024-sha3-512`.
///
/// `H = SHA3-512(string(V_C) || string(V_S) || string(I_C) || string(I_S)
///              || string(K_S) || string(Q_C) || string(Q_S) || string(K))`
fn compute_exchange_hash(input: &ExchangeHashInput<'_>) -> Result<[u8; 64], SshError> {
    // 2592 (K_S) + 1568 (Q_C) + 1568 (Q_S) + 64 (K) + banners + kexinits <= 8192 bytes
    let mut transcript = [0u8; 8192];
    let mut w = WireWriter::new(&mut transcript);
    let res = w
        .write_string(input.v_c)
        .and_then(|()| w.write_string(input.v_s))
        .and_then(|()| w.write_string(input.i_c))
        .and_then(|()| w.write_string(input.i_s))
        .and_then(|()| w.write_string(input.k_s))
        .and_then(|()| w.write_string(input.q_c))
        .and_then(|()| w.write_string(input.q_s))
        .and_then(|()| w.write_string(input.k_shared_hash));
    let len = w.len();
    let out = res.map(|()| sha3_512(&transcript[..len]));
    transcript[..len].zeroize();
    out
}

/// Derive directional 64-byte `chacha20-poly1305@openssh.com` keys via domain-separated `SHAKE256`.
fn derive_session_keys(
    k_hash: &[u8; 64],
    h: &[u8; 64],
    session_id: &[u8; 64],
) -> ([u8; 64], [u8; 64]) {
    let mut material = [0u8; 16 + 64 + 64 + 64];
    material[0..15].copy_from_slice(b"newos-pq-ssh-v1");
    material[15] = b'C';
    material[16..80].copy_from_slice(k_hash);
    material[80..144].copy_from_slice(h);
    material[144..208].copy_from_slice(session_id);

    let mut c2s = [0u8; 64];
    shake256(&material, &mut c2s);

    material[15] = b'S';
    let mut s2c = [0u8; 64];
    shake256(&material, &mut s2c);

    material.zeroize();
    (c2s, s2c)
}

/// Role of a KEX participant for strict-KEX algorithm list construction and validation.
#[derive(Clone, Copy)]
enum KexRole {
    Server,
    Client,
}

/// Outcome of an SSH channel request reply.
#[derive(Clone, Copy)]
enum ChannelReply {
    Success,
    Failure,
}

/// Encode an `SSHv2` packet (plaintext before `NEWKEYS`, or `chacha20-poly1305@openssh.com` after).
fn encode_packet(
    payload: &[u8],
    cipher: Option<&OpenSshChaCha20Poly1305>,
    seq: &mut u64,
    out: &mut [u8],
) -> Result<usize, SshError> {
    let align = 8usize;
    let unpadded = if cipher.is_some() {
        1 + payload.len()
    } else {
        4 + 1 + payload.len()
    };
    let mut pad_len = align - (unpadded % align);
    if pad_len < 4 {
        pad_len += align;
    }
    let packet_len = 1 + payload.len() + pad_len;
    if packet_len > MAX_PACKET_BODY {
        return Err(SshError::PacketTooLarge);
    }
    let total = 4 + packet_len + if cipher.is_some() { TAG_LEN } else { 0 };
    if total > out.len() {
        return Err(SshError::PacketTooLarge);
    }

    let packet_len_u32 = u32::try_from(packet_len).map_err(|_| SshError::PacketTooLarge)?;
    let pad_len_u8 = u8::try_from(pad_len).map_err(|_| SshError::PacketTooLarge)?;
    out[0..4].copy_from_slice(&packet_len_u32.to_be_bytes());
    out[4] = pad_len_u8;
    out[5..5 + payload.len()].copy_from_slice(payload);
    out[5 + payload.len()..4 + packet_len].fill(0);

    if let Some(c) = cipher {
        let tag = c.seal_in_place(*seq, &mut out[..4 + packet_len]);
        out[4 + packet_len..total].copy_from_slice(&tag);
    }
    *seq = seq.wrapping_add(1);
    Ok(total)
}

/// Build a single-suite strict `SSH_MSG_KEXINIT` payload.
fn build_kexinit(role: KexRole, cookie: &[u8; 16], out: &mut [u8]) -> Result<usize, SshError> {
    let mut w = WireWriter::new(out);
    w.write_u8(MSG_KEXINIT)?;
    w.write_raw(cookie)?;
    match role {
        KexRole::Server => w.write_str("mlkem1024-sha3-512,kex-strict-s-v00@openssh.com")?,
        KexRole::Client => w.write_str("mlkem1024-sha3-512,kex-strict-c-v00@openssh.com")?,
    }
    w.write_str(ALG_HOST_KEY)?;
    w.write_str(ALG_CIPHER)?;
    w.write_str(ALG_CIPHER)?;
    w.write_str("none")?; // AEAD cipher includes integrity
    w.write_str("none")?;
    w.write_str(ALG_COMP)?;
    w.write_str(ALG_COMP)?;
    w.write_str("")?;
    w.write_str("")?;
    w.write_bool(false)?; // first_kex_packet_follows
    w.write_u32(0)?; // reserved
    Ok(w.len())
}

/// Validate a peer's `SSH_MSG_KEXINIT` against the supported suite.
fn validate_peer_kexinit(payload: &[u8], peer_role: KexRole) -> Result<(), SshError> {
    let mut r = WireReader::new(payload);
    if r.read_u8()? != MSG_KEXINIT {
        return Err(SshError::StrictKexViolation);
    }
    let _cookie = r.read_exact(16)?;
    let kex_algs = r.read_str()?;
    let host_key_algs = r.read_str()?;
    let enc_c2s = r.read_str()?;
    let enc_s2c = r.read_str()?;
    let _mac_c2s = r.read_str()?;
    let _mac_s2c = r.read_str()?;
    let comp_c2s = r.read_str()?;
    let comp_s2c = r.read_str()?;
    let _lang_c2s = r.read_str()?;
    let _lang_s2c = r.read_str()?;
    let _first_follows = r.read_bool()?;
    let _reserved = r.read_u32()?;

    let strict_ext = match peer_role {
        KexRole::Client => ALG_KEX_STRICT_C,
        KexRole::Server => ALG_KEX_STRICT_S,
    };
    if !name_list_contains(kex_algs, ALG_KEX)
        || !name_list_contains(kex_algs, strict_ext)
        || !name_list_contains(host_key_algs, ALG_HOST_KEY)
        || !name_list_contains(enc_c2s, ALG_CIPHER)
        || !name_list_contains(enc_s2c, ALG_CIPHER)
        || !name_list_contains(comp_c2s, ALG_COMP)
        || !name_list_contains(comp_s2c, ALG_COMP)
    {
        return Err(SshError::UnsupportedAlgorithm);
    }
    Ok(())
}

/// Build the `SSHv2` `signed_data` payload for `SSH_MSG_USERAUTH_REQUEST` publickey signing.
///
/// # Errors
///
/// Returns [`SshError::PacketTooLarge`] if `out` is too small to hold the encoded payload.
pub fn build_userauth_signed_data(
    session_id: &[u8; 64],
    username: &str,
    client_pk: &[u8; MLDSA87_PK_BYTES],
    out: &mut [u8],
) -> Result<usize, SshError> {
    let mut w = WireWriter::new(out);
    w.write_string(session_id)?;
    w.write_u8(MSG_USERAUTH_REQUEST)?;
    w.write_str(username)?;
    w.write_str("ssh-connection")?;
    w.write_str("publickey")?;
    w.write_bool(true)?;
    w.write_str(ALG_HOST_KEY)?;
    // Compact SHA3-512 key-blob commitment inside signed_data (keeps `signed_data <= 512 B` for key-pd)
    let pk_digest = sha3_512(client_pk);
    w.write_string(&pk_digest)?;
    Ok(w.len())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    AwaitBanner,
    AwaitKexInit,
    AwaitMlKemInit,
    AwaitNewKeys,
    AwaitServiceReq,
    AwaitUserAuth,
    Authenticated,
    ShellOpen,
}

/// Server-side `SSHv2` state machine.
pub struct SshServer {
    state: ServerState,
    rx_buf: [u8; MAX_PACKET_BODY + 64],
    rx_len: usize,
    tx_buf: [u8; MAX_PACKET_BODY + 64],
    tx_len: usize,
    tx_off: usize,
    client_banner: [u8; 128],
    client_banner_len: usize,
    client_kexinit: [u8; 512],
    client_kexinit_len: usize,
    server_kexinit: [u8; 512],
    server_kexinit_len: usize,
    rx_seq: u64,
    tx_seq: u64,
    rx_cipher: Option<OpenSshChaCha20Poly1305>,
    tx_cipher: Option<OpenSshChaCha20Poly1305>,
    pending_c2s: Option<[u8; 64]>,
    pending_s2c: Option<[u8; 64]>,
    session_id: Option<[u8; 64]>,
    auth_attempts: u8,
    peer_channel_id: u32,
}

impl core::fmt::Debug for SshServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshServer")
            .field("state", &self.state)
            .field("rx_len", &self.rx_len)
            .field("tx_pending", &(self.tx_len - self.tx_off))
            .field("rx_seq", &self.rx_seq)
            .field("tx_seq", &self.tx_seq)
            .field("rx_cipher_active", &self.rx_cipher.is_some())
            .field("tx_cipher_active", &self.tx_cipher.is_some())
            .field("has_session_id", &self.session_id.is_some())
            .field("auth_attempts", &self.auth_attempts)
            .field("secrets", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        if let Some(ref mut k) = self.pending_c2s {
            k.zeroize();
        }
        if let Some(ref mut k) = self.pending_s2c {
            k.zeroize();
        }
        if let Some(ref mut sid) = self.session_id {
            sid.zeroize();
        }
        self.rx_buf.zeroize();
        self.tx_buf.zeroize();
    }
}

impl Default for SshServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SshServer {
    #[must_use]
    // Intentional: `#![no_std]` zero-heap state machine owns fixed 12 KiB wire buffers inline.
    #[allow(
        unknown_lints,
        renamed_and_removed_lints,
        clippy::large_stack_frames,
        clippy::large_unopt_stack_frames
    )]
    pub fn new() -> Self {
        let mut s = Self {
            state: ServerState::AwaitBanner,
            rx_buf: [0u8; MAX_PACKET_BODY + 64],
            rx_len: 0,
            tx_buf: [0u8; MAX_PACKET_BODY + 64],
            tx_len: 0,
            tx_off: 0,
            client_banner: [0u8; 128],
            client_banner_len: 0,
            client_kexinit: [0u8; 512],
            client_kexinit_len: 0,
            server_kexinit: [0u8; 512],
            server_kexinit_len: 0,
            rx_seq: 0,
            tx_seq: 0,
            rx_cipher: None,
            tx_cipher: None,
            pending_c2s: None,
            pending_s2c: None,
            session_id: None,
            auth_attempts: 0,
            peer_channel_id: 0,
        };
        s.queue_raw_tx(SSH_BANNER);
        s
    }

    pub fn reset(&mut self) {
        if let Some(ref mut k) = self.pending_c2s {
            k.zeroize();
        }
        if let Some(ref mut k) = self.pending_s2c {
            k.zeroize();
        }
        if let Some(ref mut sid) = self.session_id {
            sid.zeroize();
        }
        self.rx_buf.zeroize();
        self.tx_buf.zeroize();
        self.rx_cipher = None;
        self.tx_cipher = None;
        self.pending_c2s = None;
        self.pending_s2c = None;
        self.session_id = None;
        self.state = ServerState::AwaitBanner;
        self.rx_len = 0;
        self.tx_len = 0;
        self.tx_off = 0;
        self.client_banner_len = 0;
        self.client_kexinit_len = 0;
        self.server_kexinit_len = 0;
        self.rx_seq = 0;
        self.tx_seq = 0;
        self.auth_attempts = 0;
        self.peer_channel_id = 0;
        self.queue_raw_tx(SSH_BANNER);
    }

    #[must_use]
    #[inline]
    pub const fn is_shell_open(&self) -> bool {
        matches!(self.state, ServerState::ShellOpen)
    }

    /// Pending encrypted wire bytes ready to transmit to `newos-net-pd`.
    #[must_use]
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx_buf[self.tx_off..self.tx_len]
    }

    /// Mark `n` bytes of `pending_tx()` as sent.
    pub fn consume_tx(&mut self, n: usize) {
        self.tx_off = self.tx_off.saturating_add(n).min(self.tx_len);
        if self.tx_off == self.tx_len {
            self.tx_off = 0;
            self.tx_len = 0;
        }
    }

    fn queue_raw_tx(&mut self, data: &[u8]) {
        if self.tx_off > 0 {
            let rem = self.tx_len - self.tx_off;
            self.tx_buf.copy_within(self.tx_off..self.tx_len, 0);
            self.tx_off = 0;
            self.tx_len = rem;
        }
        let avail = self.tx_buf.len() - self.tx_len;
        let take = data.len().min(avail);
        self.tx_buf[self.tx_len..self.tx_len + take].copy_from_slice(&data[..take]);
        self.tx_len += take;
    }

    fn send_packet(&mut self, payload: &[u8]) -> Result<(), SshError> {
        if self.tx_off > 0 {
            let rem = self.tx_len - self.tx_off;
            self.tx_buf.copy_within(self.tx_off..self.tx_len, 0);
            self.tx_off = 0;
            self.tx_len = rem;
        }
        let n = encode_packet(
            payload,
            self.tx_cipher.as_ref(),
            &mut self.tx_seq,
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += n;
        Ok(())
    }

    /// Queue interactive shell output bytes as one or more `SSH_MSG_CHANNEL_DATA` packets (`N9`).
    ///
    /// # Errors
    ///
    /// Returns [`SshError::PacketTooLarge`] if the internal transmit buffer has insufficient space.
    pub fn send_shell_output(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state != ServerState::ShellOpen || data.is_empty() {
            return Ok(());
        }
        let mut body = [0u8; 1024];
        for chunk in data.chunks(960) {
            let mut w = WireWriter::new(&mut body);
            w.write_u8(MSG_CHANNEL_DATA)?;
            w.write_u32(self.peer_channel_id)?;
            w.write_string(chunk)?;
            let len = w.len();
            self.send_packet(&body[..len])?;
        }
        Ok(())
    }

    /// Feed incoming TCP bytes from `newos-net-pd`. Any decrypted interactive shell input
    /// is written into `shell_in_out` and its byte count is returned.
    ///
    /// # Errors
    ///
    /// Returns an [`SshError`] on framing, AEAD, strict-KEX, authentication, vault, or disconnect
    /// failures.
    pub fn feed_rx<V: KeyVaultClient>(
        &mut self,
        incoming: &[u8],
        vault: &mut V,
        shell_in_out: &mut [u8],
    ) -> Result<usize, SshError> {
        let mut shell_written = 0usize;
        let mut pos = 0;
        while pos < incoming.len() {
            let space = self.rx_buf.len() - self.rx_len;
            if space == 0 {
                return Err(SshError::PacketTooLarge);
            }
            let take = (incoming.len() - pos).min(space);
            self.rx_buf[self.rx_len..self.rx_len + take]
                .copy_from_slice(&incoming[pos..pos + take]);
            self.rx_len += take;
            pos += take;

            loop {
                if self.state == ServerState::AwaitBanner {
                    if !self.try_parse_banner(vault)? {
                        break;
                    }
                    continue;
                }
                let Some(n_shell) =
                    self.try_process_packet(vault, &mut shell_in_out[shell_written..])?
                else {
                    break;
                };
                shell_written += n_shell;
            }
        }
        Ok(shell_written)
    }

    fn try_parse_banner<V: KeyVaultClient>(&mut self, vault: &mut V) -> Result<bool, SshError> {
        let Some(lf) = self.rx_buf[..self.rx_len].iter().position(|&b| b == b'\n') else {
            if self.rx_len > 128 {
                return Err(SshError::MalformedPacket);
            }
            return Ok(false);
        };
        let line_len = if lf > 0 && self.rx_buf[lf - 1] == b'\r' {
            lf - 1
        } else {
            lf
        };
        if line_len < 8 || line_len > self.client_banner.len() || &self.rx_buf[..8] != b"SSH-2.0-" {
            return Err(SshError::MalformedPacket);
        }
        self.client_banner[..line_len].copy_from_slice(&self.rx_buf[..line_len]);
        self.client_banner_len = line_len;

        let consumed = lf + 1;
        self.rx_buf.copy_within(consumed..self.rx_len, 0);
        self.rx_len -= consumed;

        // Immediately send `SSH_MSG_KEXINIT`
        let rnd = vault.random_32()?;
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&rnd[..16]);
        let mut kex_payload = [0u8; 512];
        let kex_len = build_kexinit(KexRole::Server, &cookie, &mut kex_payload)?;
        self.server_kexinit[..kex_len].copy_from_slice(&kex_payload[..kex_len]);
        self.server_kexinit_len = kex_len;
        self.send_packet(&kex_payload[..kex_len])?;

        self.state = ServerState::AwaitKexInit;
        Ok(true)
    }

    fn try_process_packet<V: KeyVaultClient>(
        &mut self,
        vault: &mut V,
        shell_out: &mut [u8],
    ) -> Result<Option<usize>, SshError> {
        if self.rx_len < 4 {
            return Ok(None);
        }
        let enc_len = [
            self.rx_buf[0],
            self.rx_buf[1],
            self.rx_buf[2],
            self.rx_buf[3],
        ];
        let packet_len = match &self.rx_cipher {
            Some(c) => c.decrypt_length(self.rx_seq, enc_len) as usize,
            None => u32::from_be_bytes(enc_len) as usize,
        };
        if !(2..=MAX_PACKET_BODY).contains(&packet_len) {
            return Err(SshError::PacketTooLarge);
        }
        let total = 4 + packet_len + if self.rx_cipher.is_some() { TAG_LEN } else { 0 };
        if self.rx_len < total {
            return Ok(None);
        }

        if let Some(ref c) = self.rx_cipher {
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&self.rx_buf[4 + packet_len..total]);
            if !c.open_in_place(self.rx_seq, &mut self.rx_buf[..4 + packet_len], &tag) {
                return Err(SshError::CryptoFailure);
            }
        }
        self.rx_seq = self.rx_seq.wrapping_add(1);

        let pad_len = self.rx_buf[4] as usize;
        if pad_len < 4 || 1 + pad_len >= packet_len {
            return Err(SshError::MalformedPacket);
        }
        let payload_len = packet_len - 1 - pad_len;
        let mut payload = [0u8; MAX_PACKET_BODY];
        payload[..payload_len].copy_from_slice(&self.rx_buf[5..5 + payload_len]);

        self.rx_buf.copy_within(total..self.rx_len, 0);
        self.rx_len -= total;

        let res = self.handle_message(&payload[..payload_len], vault, shell_out);
        payload[..payload_len].zeroize();
        res.map(Some)
    }

    fn handle_message<V: KeyVaultClient>(
        &mut self,
        payload: &[u8],
        vault: &mut V,
        shell_out: &mut [u8],
    ) -> Result<usize, SshError> {
        let msg_type = *payload.first().ok_or(SshError::MalformedPacket)?;

        // Strict KEX (Terrapin CVE-2023-48795): ZERO unexpected packets before NEWKEYS!
        if matches!(
            self.state,
            ServerState::AwaitKexInit | ServerState::AwaitMlKemInit | ServerState::AwaitNewKeys
        ) && matches!(msg_type, MSG_IGNORE | MSG_DEBUG | MSG_UNIMPLEMENTED)
        {
            return Err(SshError::StrictKexViolation);
        }

        match (self.state, msg_type) {
            (ServerState::AwaitKexInit, MSG_KEXINIT) => {
                validate_peer_kexinit(payload, KexRole::Client)?;
                if payload.len() > self.client_kexinit.len() {
                    return Err(SshError::PacketTooLarge);
                }
                self.client_kexinit[..payload.len()].copy_from_slice(payload);
                self.client_kexinit_len = payload.len();
                self.state = ServerState::AwaitMlKemInit;
                Ok(0)
            }
            (ServerState::AwaitMlKemInit, MSG_KEX_MLKEM_INIT) => {
                self.handle_kex_mlkem_init(payload, vault)
            }
            (ServerState::AwaitNewKeys, MSG_NEWKEYS) => {
                if let Some(mut c2s_key) = self.pending_c2s.take() {
                    self.rx_cipher = Some(OpenSshChaCha20Poly1305::new(&c2s_key));
                    c2s_key.zeroize();
                }
                self.rx_seq = 0;
                self.state = ServerState::AwaitServiceReq;
                Ok(0)
            }
            (ServerState::AwaitServiceReq, MSG_SERVICE_REQUEST) => {
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let svc = r.read_str()?;
                if svc != "ssh-userauth" {
                    return Err(SshError::DisallowedRequest);
                }
                let mut resp = [0u8; 64];
                let mut w = WireWriter::new(&mut resp);
                w.write_u8(MSG_SERVICE_ACCEPT)?;
                w.write_str("ssh-userauth")?;
                let len = w.len();
                self.send_packet(&resp[..len])?;
                self.state = ServerState::AwaitUserAuth;
                Ok(0)
            }
            (ServerState::AwaitUserAuth, MSG_USERAUTH_REQUEST) => {
                self.handle_userauth_request(payload, vault)
            }
            (ServerState::Authenticated, MSG_CHANNEL_OPEN) => self.handle_channel_open(payload),
            (ServerState::Authenticated | ServerState::ShellOpen, MSG_CHANNEL_REQUEST) => {
                self.handle_channel_request(payload)
            }
            (ServerState::ShellOpen, MSG_CHANNEL_DATA) => {
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let _recipient = r.read_u32()?;
                let data = r.read_string()?;
                let take = data.len().min(shell_out.len());
                shell_out[..take].copy_from_slice(&data[..take]);
                Ok(take)
            }
            (ServerState::ShellOpen, MSG_CHANNEL_WINDOW_ADJUST) => Ok(0),
            (_, MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE | MSG_DISCONNECT) => {
                vault.close_session();
                Err(SshError::Disconnected)
            }
            _ => Err(SshError::StrictKexViolation),
        }
    }

    fn handle_kex_mlkem_init<V: KeyVaultClient>(
        &mut self,
        payload: &[u8],
        vault: &mut V,
    ) -> Result<usize, SshError> {
        let mut r = WireReader::new(payload);
        let _ = r.read_u8()?;
        let q_c = r.read_string()?;
        if q_c.len() != MLKEM1024_EK_BYTES {
            return Err(SshError::MalformedPacket);
        }
        let mut ek_arr = ml_kem::array::Array::default();
        ek_arr.copy_from_slice(q_c);
        let ek = EncapsulationKey1024::new(&ek_arr).map_err(|_| SshError::CryptoFailure)?;

        // Encapsulate with 32 bytes from `newos-key-pd` fast-key-erasure CSPRNG
        let mut rnd_bytes = vault.random_32()?;
        let mut m = KemB32::default();
        m.copy_from_slice(&rnd_bytes);
        rnd_bytes.zeroize();
        let (ct, mut ss) = ek.encapsulate_deterministic(&m);
        m.zeroize();

        let mut k_hash = sha3_512(ss.as_slice());
        ss.zeroize();

        let kex_res = (|| -> Result<_, SshError> {
            let host_pk = vault.host_public_key()?;
            let h = compute_exchange_hash(&ExchangeHashInput {
                v_c: &self.client_banner[..self.client_banner_len],
                v_s: SSH_BANNER_NO_CRLF,
                i_c: &self.client_kexinit[..self.client_kexinit_len],
                i_s: &self.server_kexinit[..self.server_kexinit_len],
                k_s: &host_pk,
                q_c,
                q_s: ct.as_slice(),
                k_shared_hash: &k_hash,
            })?;
            let sig = vault.sign_kex_hash(&h)?;
            Ok((host_pk, sig, h))
        })();
        let (host_pk, sig, h) = match kex_res {
            Ok(v) => v,
            Err(e) => {
                k_hash.zeroize();
                return Err(e);
            }
        };

        let sid = *self.session_id.get_or_insert(h);
        let (c2s, s2c) = derive_session_keys(&k_hash, &h, &sid);
        k_hash.zeroize();
        self.pending_c2s = Some(c2s);
        self.pending_s2c = Some(s2c);

        // Send SSH_MSG_KEX_MLKEM_REPLY
        let mut reply = [0u8; MAX_PACKET_BODY];
        let mut w = WireWriter::new(&mut reply);
        w.write_u8(MSG_KEX_MLKEM_REPLY)?;
        w.write_string(&host_pk)?;
        w.write_string(ct.as_slice())?;
        w.write_string(&sig)?;
        let rlen = w.len();
        self.send_packet(&reply[..rlen])?;

        // Send SSH_MSG_NEWKEYS and activate TX cipher + strict-KEX seq reset
        self.send_packet(&[MSG_NEWKEYS])?;
        if let Some(mut s2c_key) = self.pending_s2c.take() {
            self.tx_cipher = Some(OpenSshChaCha20Poly1305::new(&s2c_key));
            s2c_key.zeroize();
        }
        self.tx_seq = 0;
        self.state = ServerState::AwaitNewKeys;
        Ok(0)
    }

    fn handle_userauth_request<V: KeyVaultClient>(
        &mut self,
        payload: &[u8],
        vault: &mut V,
    ) -> Result<usize, SshError> {
        self.auth_attempts = self.auth_attempts.saturating_add(1);
        if self.auth_attempts > MAX_AUTH_ATTEMPTS {
            return Err(SshError::TooManyAuthAttempts);
        }
        let mut r = WireReader::new(payload);
        let _ = r.read_u8()?;
        let username = r.read_str()?;
        let service = r.read_str()?;
        let method = r.read_str()?;
        if !matches!(username, "newos" | "root")
            || service != "ssh-connection"
            || method != "publickey"
        {
            self.send_userauth_failure()?;
            return Err(SshError::AuthFailed);
        }
        let has_sig = r.read_bool()?;
        let alg = r.read_str()?;
        let pk_slice = r.read_string()?;
        if !has_sig || alg != ALG_HOST_KEY || pk_slice.len() != MLDSA87_PK_BYTES {
            self.send_userauth_failure()?;
            return Err(SshError::AuthFailed);
        }
        let sig_slice = r.read_string()?;
        if sig_slice.len() != MLDSA87_SIG_BYTES {
            self.send_userauth_failure()?;
            return Err(SshError::AuthFailed);
        }
        let mut client_pk = [0u8; MLDSA87_PK_BYTES];
        client_pk.copy_from_slice(pk_slice);
        let mut client_sig = [0u8; MLDSA87_SIG_BYTES];
        client_sig.copy_from_slice(sig_slice);

        let sid = self.session_id.ok_or(SshError::CryptoFailure)?;
        let mut signed_data = [0u8; 512];
        let sd_len = build_userauth_signed_data(&sid, username, &client_pk, &mut signed_data)?;

        let ok = vault.verify_user_auth(&client_pk, &signed_data[..sd_len], &client_sig)?;
        if !ok {
            self.send_userauth_failure()?;
            if self.auth_attempts >= MAX_AUTH_ATTEMPTS {
                return Err(SshError::TooManyAuthAttempts);
            }
            return Ok(0);
        }
        self.send_packet(&[MSG_USERAUTH_SUCCESS])?;
        self.state = ServerState::Authenticated;
        Ok(0)
    }

    fn handle_channel_open(&mut self, payload: &[u8]) -> Result<usize, SshError> {
        let mut r = WireReader::new(payload);
        let _ = r.read_u8()?;
        let ch_type = r.read_str()?;
        let sender_ch = r.read_u32()?;
        let _init_win = r.read_u32()?;
        let _max_pkt = r.read_u32()?;
        if ch_type != "session" {
            let mut fail = [0u8; 64];
            let mut w = WireWriter::new(&mut fail);
            w.write_u8(MSG_CHANNEL_OPEN_FAILURE)?;
            w.write_u32(sender_ch)?;
            w.write_u32(1)?; // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
            w.write_str("disallowed")?;
            w.write_str("")?;
            let len = w.len();
            self.send_packet(&fail[..len])?;
            return Err(SshError::DisallowedRequest);
        }
        self.peer_channel_id = sender_ch;
        let mut conf = [0u8; 32];
        let mut w = WireWriter::new(&mut conf);
        w.write_u8(MSG_CHANNEL_OPEN_CONFIRMATION)?;
        w.write_u32(sender_ch)?;
        w.write_u32(0)?; // local channel id 0
        w.write_u32(65_536)?; // initial window
        w.write_u32(1_024)?; // max packet
        let len = w.len();
        self.send_packet(&conf[..len])?;
        Ok(0)
    }

    fn handle_channel_request(&mut self, payload: &[u8]) -> Result<usize, SshError> {
        let mut r = WireReader::new(payload);
        let _ = r.read_u8()?;
        let _recipient = r.read_u32()?;
        let req_type = r.read_str()?;
        let want_reply = r.read_bool()?;
        match req_type {
            "pty-req" | "window-change" => {
                if want_reply {
                    self.send_channel_reply(ChannelReply::Success)?;
                }
                Ok(0)
            }
            "shell" => {
                self.state = ServerState::ShellOpen;
                if want_reply {
                    self.send_channel_reply(ChannelReply::Success)?;
                }
                Ok(0)
            }
            // Strictly reject `exec`, `subsystem`, `x11-req`, `auth-agent-req`, etc.
            _ => {
                if want_reply {
                    self.send_channel_reply(ChannelReply::Failure)?;
                }
                Err(SshError::DisallowedRequest)
            }
        }
    }

    fn send_userauth_failure(&mut self) -> Result<(), SshError> {
        let mut resp = [0u8; 64];
        let mut w = WireWriter::new(&mut resp);
        w.write_u8(MSG_USERAUTH_FAILURE)?;
        w.write_str("publickey")?;
        w.write_bool(false)?;
        let len = w.len();
        self.send_packet(&resp[..len])
    }

    fn send_channel_reply(&mut self, reply: ChannelReply) -> Result<(), SshError> {
        let mut resp = [0u8; 8];
        let mut w = WireWriter::new(&mut resp);
        w.write_u8(match reply {
            ChannelReply::Success => MSG_CHANNEL_SUCCESS,
            ChannelReply::Failure => MSG_CHANNEL_FAILURE,
        })?;
        w.write_u32(self.peer_channel_id)?;
        let len = w.len();
        self.send_packet(&resp[..len])
    }
}

/// Client-side `SSHv2` state machine shared by `crates/ssh-client` (`newos-ssh`) and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    AwaitBanner,
    AwaitKexInit,
    AwaitMlKemReply,
    AwaitNewKeys,
    AwaitServiceAccept,
    AwaitUserAuth,
    AwaitChannelOpen,
    AwaitShellReady,
    ShellOpen,
}

pub struct SshClient {
    state: ClientState,
    rx_buf: [u8; MAX_PACKET_BODY + 64],
    rx_len: usize,
    tx_buf: [u8; MAX_PACKET_BODY + 64],
    tx_len: usize,
    tx_off: usize,
    server_banner: [u8; 128],
    server_banner_len: usize,
    client_kexinit: [u8; 512],
    client_kexinit_len: usize,
    server_kexinit: [u8; 512],
    server_kexinit_len: usize,
    rx_seq: u64,
    tx_seq: u64,
    rx_cipher: Option<OpenSshChaCha20Poly1305>,
    tx_cipher: Option<OpenSshChaCha20Poly1305>,
    pending_c2s: Option<[u8; 64]>,
    pending_s2c: Option<[u8; 64]>,
    kem_dk: Option<DecapsulationKey1024>,
    kem_ek_bytes: [u8; MLKEM1024_EK_BYTES],
    session_id: Option<[u8; 64]>,
    host_fingerprint: Option<[u8; 64]>,
    expected_fingerprint: Option<[u8; 64]>,
    username: [u8; 32],
    username_len: usize,
    user_sk: SigningKey<MlDsa87>,
    user_pk: [u8; MLDSA87_PK_BYTES],
}

impl core::fmt::Debug for SshClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshClient")
            .field("state", &self.state)
            .field("rx_len", &self.rx_len)
            .field("tx_pending", &(self.tx_len - self.tx_off))
            .field("rx_seq", &self.rx_seq)
            .field("tx_seq", &self.tx_seq)
            .field("rx_cipher_active", &self.rx_cipher.is_some())
            .field("tx_cipher_active", &self.tx_cipher.is_some())
            .field("has_kem_dk", &self.kem_dk.is_some())
            .field("has_session_id", &self.session_id.is_some())
            .field("has_host_fingerprint", &self.host_fingerprint.is_some())
            .field("secrets", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for SshClient {
    fn drop(&mut self) {
        if let Some(ref mut k) = self.pending_c2s {
            k.zeroize();
        }
        if let Some(ref mut k) = self.pending_s2c {
            k.zeroize();
        }
        if let Some(ref mut sid) = self.session_id {
            sid.zeroize();
        }
        self.rx_buf.zeroize();
        self.tx_buf.zeroize();
    }
}

/// Explicit host-key verification policy required by [`SshClient::new_with_policy`].
///
/// Prevents library callers from accidentally skipping SHA3-512 host-key pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Fail closed unless the server's ML-DSA-87 host key matches this 64-byte `SHA3-512` digest.
    Pinned([u8; 64]),
    /// Explicitly opt out of host-key verification (e.g., ephemeral QEMU/lab testing only).
    InsecureAcceptAny,
}

impl SshClient {
    /// Construct an `SshClient` with an explicit [`HostKeyPolicy`] (preferred safe constructor).
    #[must_use]
    // Intentional: `#![no_std]` zero-heap client owns fixed 12 KiB wire buffers + ML-DSA-87/ML-KEM-1024 keys inline.
    #[allow(
        unknown_lints,
        renamed_and_removed_lints,
        clippy::large_stack_frames,
        clippy::large_unopt_stack_frames
    )]
    pub fn new_with_policy(
        username: &str,
        user_sk: SigningKey<MlDsa87>,
        policy: HostKeyPolicy,
        kem_seed: [u8; 64],
    ) -> Self {
        let expected_fingerprint = match policy {
            HostKeyPolicy::Pinned(fp) => Some(fp),
            HostKeyPolicy::InsecureAcceptAny => None,
        };
        Self::new(username, user_sk, expected_fingerprint, kem_seed)
    }

    #[must_use]
    // Intentional: `#![no_std]` zero-heap client owns fixed 12 KiB wire buffers + ML-DSA-87/ML-KEM-1024 keys inline.
    #[allow(
        unknown_lints,
        renamed_and_removed_lints,
        clippy::large_stack_frames,
        clippy::large_unopt_stack_frames
    )]
    pub fn new(
        username: &str,
        user_sk: SigningKey<MlDsa87>,
        expected_fingerprint: Option<[u8; 64]>,
        mut kem_seed: [u8; 64],
    ) -> Self {
        let mut user_public_key = [0u8; MLDSA87_PK_BYTES];
        {
            let enc_pk = user_sk.verifying_key().encode();
            user_public_key.copy_from_slice(enc_pk.as_slice());
        }

        let kem_dk = {
            let mut seed = Seed::default();
            seed.copy_from_slice(&kem_seed);
            kem_seed.zeroize();
            DecapsulationKey1024::from_seed(seed)
        };
        let mut kem_ek_bytes = [0u8; MLKEM1024_EK_BYTES];
        {
            let ek_enc = kem_dk.encapsulation_key().to_bytes();
            kem_ek_bytes.copy_from_slice(ek_enc.as_slice());
        }

        let mut uname = [0u8; 32];
        let ulen = username.floor_char_boundary(32);
        uname[..ulen].copy_from_slice(&username.as_bytes()[..ulen]);

        let mut c = Self {
            state: ClientState::AwaitBanner,
            rx_buf: [0u8; MAX_PACKET_BODY + 64],
            rx_len: 0,
            tx_buf: [0u8; MAX_PACKET_BODY + 64],
            tx_len: 0,
            tx_off: 0,
            server_banner: [0u8; 128],
            server_banner_len: 0,
            client_kexinit: [0u8; 512],
            client_kexinit_len: 0,
            server_kexinit: [0u8; 512],
            server_kexinit_len: 0,
            rx_seq: 0,
            tx_seq: 0,
            rx_cipher: None,
            tx_cipher: None,
            pending_c2s: None,
            pending_s2c: None,
            kem_dk: Some(kem_dk),
            kem_ek_bytes,
            session_id: None,
            host_fingerprint: None,
            expected_fingerprint,
            username: uname,
            username_len: ulen,
            user_sk,
            user_pk: user_public_key,
        };
        c.queue_raw_tx(SSH_BANNER);
        c
    }

    #[must_use]
    pub const fn state(&self) -> ClientState {
        self.state
    }

    #[must_use]
    pub const fn host_fingerprint(&self) -> Option<[u8; 64]> {
        self.host_fingerprint
    }

    #[must_use]
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx_buf[self.tx_off..self.tx_len]
    }

    pub fn consume_tx(&mut self, n: usize) {
        self.tx_off = self.tx_off.saturating_add(n).min(self.tx_len);
        if self.tx_off == self.tx_len {
            self.tx_off = 0;
            self.tx_len = 0;
        }
    }

    fn queue_raw_tx(&mut self, data: &[u8]) {
        let avail = self.tx_buf.len() - self.tx_len;
        let take = data.len().min(avail);
        self.tx_buf[self.tx_len..self.tx_len + take].copy_from_slice(&data[..take]);
        self.tx_len += take;
    }

    fn send_packet(&mut self, payload: &[u8]) -> Result<(), SshError> {
        if self.tx_off > 0 {
            let rem = self.tx_len - self.tx_off;
            self.tx_buf.copy_within(self.tx_off..self.tx_len, 0);
            self.tx_off = 0;
            self.tx_len = rem;
        }
        let n = encode_packet(
            payload,
            self.tx_cipher.as_ref(),
            &mut self.tx_seq,
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += n;
        Ok(())
    }

    /// Queue interactive shell input bytes as one or more `SSH_MSG_CHANNEL_DATA` packets.
    ///
    /// # Errors
    ///
    /// Returns [`SshError::PacketTooLarge`] if the internal transmit buffer has insufficient space.
    pub fn send_shell_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state != ClientState::ShellOpen || data.is_empty() {
            return Ok(());
        }
        let mut body = [0u8; 1024];
        for chunk in data.chunks(960) {
            let mut w = WireWriter::new(&mut body);
            w.write_u8(MSG_CHANNEL_DATA)?;
            w.write_u32(0)?;
            w.write_string(chunk)?;
            let len = w.len();
            self.send_packet(&body[..len])?;
        }
        Ok(())
    }

    /// Feed incoming TCP bytes from the SSH server. Any decrypted shell output is written into
    /// `shell_out` and its byte count is returned.
    ///
    /// # Errors
    ///
    /// Returns an [`SshError`] on framing, AEAD, host-key pinning, authentication, or disconnect
    /// failures.
    pub fn feed_rx(
        &mut self,
        incoming: &[u8],
        cookie: [u8; 16],
        sign_rnd: [u8; 32],
        shell_out: &mut [u8],
    ) -> Result<usize, SshError> {
        let mut written = 0usize;
        let mut pos = 0;
        while pos < incoming.len() {
            let space = self.rx_buf.len() - self.rx_len;
            if space == 0 {
                return Err(SshError::PacketTooLarge);
            }
            let take = (incoming.len() - pos).min(space);
            self.rx_buf[self.rx_len..self.rx_len + take]
                .copy_from_slice(&incoming[pos..pos + take]);
            self.rx_len += take;
            pos += take;

            loop {
                if self.state == ClientState::AwaitBanner {
                    let Some(lf) = self.rx_buf[..self.rx_len].iter().position(|&b| b == b'\n')
                    else {
                        break;
                    };
                    let line_len = if lf > 0 && self.rx_buf[lf - 1] == b'\r' {
                        lf - 1
                    } else {
                        lf
                    };
                    if line_len < 8 || line_len > self.server_banner.len() {
                        return Err(SshError::MalformedPacket);
                    }
                    self.server_banner[..line_len].copy_from_slice(&self.rx_buf[..line_len]);
                    self.server_banner_len = line_len;
                    self.rx_buf.copy_within(lf + 1..self.rx_len, 0);
                    self.rx_len -= lf + 1;

                    let mut kex = [0u8; 512];
                    let klen = build_kexinit(KexRole::Client, &cookie, &mut kex)?;
                    self.client_kexinit[..klen].copy_from_slice(&kex[..klen]);
                    self.client_kexinit_len = klen;
                    self.send_packet(&kex[..klen])?;
                    self.state = ClientState::AwaitKexInit;
                    continue;
                }

                if self.rx_len < 4 {
                    break;
                }
                let enc_len = [
                    self.rx_buf[0],
                    self.rx_buf[1],
                    self.rx_buf[2],
                    self.rx_buf[3],
                ];
                let packet_len = match &self.rx_cipher {
                    Some(c) => c.decrypt_length(self.rx_seq, enc_len) as usize,
                    None => u32::from_be_bytes(enc_len) as usize,
                };
                if !(2..=MAX_PACKET_BODY).contains(&packet_len) {
                    return Err(SshError::PacketTooLarge);
                }
                let total = 4 + packet_len + if self.rx_cipher.is_some() { TAG_LEN } else { 0 };
                if self.rx_len < total {
                    break;
                }
                if let Some(ref c) = self.rx_cipher {
                    let mut tag = [0u8; TAG_LEN];
                    tag.copy_from_slice(&self.rx_buf[4 + packet_len..total]);
                    if !c.open_in_place(self.rx_seq, &mut self.rx_buf[..4 + packet_len], &tag) {
                        return Err(SshError::CryptoFailure);
                    }
                }
                self.rx_seq = self.rx_seq.wrapping_add(1);
                let pad_len = self.rx_buf[4] as usize;
                // Bounds-check padding length before subtraction so a hostile server cannot crash
                // the client before authentication (`N11`).
                if pad_len < 4 || pad_len + 1 > packet_len {
                    return Err(SshError::MalformedPacket);
                }
                let payload_len = packet_len - 1 - pad_len;
                let mut payload = [0u8; MAX_PACKET_BODY];
                payload[..payload_len].copy_from_slice(&self.rx_buf[5..5 + payload_len]);
                self.rx_buf.copy_within(total..self.rx_len, 0);
                self.rx_len -= total;

                let res = self.handle_server_msg(
                    &payload[..payload_len],
                    sign_rnd,
                    &mut shell_out[written..],
                );
                payload[..payload_len].zeroize();
                written += res?;
            }
        }
        Ok(written)
    }

    fn handle_server_msg(
        &mut self,
        payload: &[u8],
        sign_rnd: [u8; 32],
        shell_out: &mut [u8],
    ) -> Result<usize, SshError> {
        let msg_type = *payload.first().ok_or(SshError::MalformedPacket)?;
        match (self.state, msg_type) {
            (ClientState::AwaitKexInit, MSG_KEXINIT) => {
                validate_peer_kexinit(payload, KexRole::Server)?;
                if payload.len() > self.server_kexinit.len() {
                    return Err(SshError::PacketTooLarge);
                }
                self.server_kexinit[..payload.len()].copy_from_slice(payload);
                self.server_kexinit_len = payload.len();

                let mut init = [0u8; MLKEM1024_EK_BYTES + 16];
                let mut w = WireWriter::new(&mut init);
                w.write_u8(MSG_KEX_MLKEM_INIT)?;
                w.write_string(&self.kem_ek_bytes)?;
                let len = w.len();
                self.send_packet(&init[..len])?;
                self.state = ClientState::AwaitMlKemReply;
                Ok(0)
            }
            (ClientState::AwaitMlKemReply, MSG_KEX_MLKEM_REPLY) => {
                self.handle_kex_mlkem_reply(payload)
            }
            (ClientState::AwaitNewKeys, MSG_NEWKEYS) => {
                if let Some(mut s2c_k) = self.pending_s2c.take() {
                    self.rx_cipher = Some(OpenSshChaCha20Poly1305::new(&s2c_k));
                    s2c_k.zeroize();
                }
                self.rx_seq = 0;

                let mut req = [0u8; 64];
                let mut w = WireWriter::new(&mut req);
                w.write_u8(MSG_SERVICE_REQUEST)?;
                w.write_str("ssh-userauth")?;
                let len = w.len();
                self.send_packet(&req[..len])?;
                self.state = ClientState::AwaitServiceAccept;
                Ok(0)
            }
            (ClientState::AwaitServiceAccept, MSG_SERVICE_ACCEPT) => {
                self.handle_service_accept(sign_rnd)
            }
            (ClientState::AwaitUserAuth, MSG_USERAUTH_SUCCESS) => {
                let mut open = [0u8; 64];
                let mut w = WireWriter::new(&mut open);
                w.write_u8(MSG_CHANNEL_OPEN)?;
                w.write_str("session")?;
                w.write_u32(0)?;
                w.write_u32(65_536)?;
                w.write_u32(1_024)?;
                let len = w.len();
                self.send_packet(&open[..len])?;
                self.state = ClientState::AwaitChannelOpen;
                Ok(0)
            }
            (ClientState::AwaitUserAuth, MSG_USERAUTH_FAILURE) => Err(SshError::AuthFailed),
            (ClientState::AwaitChannelOpen, MSG_CHANNEL_OPEN_CONFIRMATION) => {
                let mut sh = [0u8; 32];
                let mut w = WireWriter::new(&mut sh);
                w.write_u8(MSG_CHANNEL_REQUEST)?;
                w.write_u32(0)?;
                w.write_str("shell")?;
                w.write_bool(true)?;
                let len = w.len();
                self.send_packet(&sh[..len])?;
                self.state = ClientState::AwaitShellReady;
                Ok(0)
            }
            (ClientState::AwaitShellReady, MSG_CHANNEL_SUCCESS) => {
                self.state = ClientState::ShellOpen;
                Ok(0)
            }
            (ClientState::ShellOpen, MSG_CHANNEL_DATA) => {
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let _rec = r.read_u32()?;
                let data = r.read_string()?;
                let take = data.len().min(shell_out.len());
                shell_out[..take].copy_from_slice(&data[..take]);
                Ok(take)
            }
            (_, MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE | MSG_DISCONNECT) => {
                Err(SshError::Disconnected)
            }
            _ => Err(SshError::StrictKexViolation),
        }
    }

    fn handle_kex_mlkem_reply(&mut self, payload: &[u8]) -> Result<usize, SshError> {
        let mut r = WireReader::new(payload);
        let _ = r.read_u8()?;
        let host_pk = r.read_string()?;
        let ct_bytes = r.read_string()?;
        let sig_bytes = r.read_string()?;
        if host_pk.len() != MLDSA87_PK_BYTES
            || ct_bytes.len() != MLKEM1024_CT_BYTES
            || sig_bytes.len() != MLDSA87_SIG_BYTES
        {
            return Err(SshError::MalformedPacket);
        }
        let fp = sha3_512(host_pk);
        if let Some(expected) = self.expected_fingerprint
            && fp != expected
        {
            return Err(SshError::CryptoFailure);
        }
        self.host_fingerprint = Some(fp);

        let dk = self.kem_dk.take().ok_or(SshError::CryptoFailure)?;
        let mut ct = Ciphertext::<MlKem1024>::default();
        ct.copy_from_slice(ct_bytes);
        let mut ss = dk.decapsulate(&ct);
        let mut k_hash = sha3_512(ss.as_slice());
        ss.zeroize();

        let verify_res = (|| {
            let h = compute_exchange_hash(&ExchangeHashInput {
                v_c: SSH_BANNER_NO_CRLF,
                v_s: &self.server_banner[..self.server_banner_len],
                i_c: &self.client_kexinit[..self.client_kexinit_len],
                i_s: &self.server_kexinit[..self.server_kexinit_len],
                k_s: host_pk,
                q_c: &self.kem_ek_bytes,
                q_s: ct_bytes,
                k_shared_hash: &k_hash,
            })?;

            // Verify server's ML-DSA-87 KEX signature under FIPS 204 CTX_KEX
            let mut pk_arr = EncodedVerifyingKey::<MlDsa87>::default();
            pk_arr.copy_from_slice(host_pk);
            let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);
            let mut sig_arr = EncodedSignature::<MlDsa87>::default();
            sig_arr.copy_from_slice(sig_bytes);
            let sig = Signature::<MlDsa87>::decode(&sig_arr).ok_or(SshError::CryptoFailure)?;
            if !vk.verify_with_context(&h, CTX_KEX, &sig) {
                return Err(SshError::CryptoFailure);
            }
            Ok(h)
        })();
        let h = match verify_res {
            Ok(h) => h,
            Err(e) => {
                k_hash.zeroize();
                return Err(e);
            }
        };

        let sid = *self.session_id.get_or_insert(h);
        let (c2s, s2c) = derive_session_keys(&k_hash, &h, &sid);
        k_hash.zeroize();
        self.pending_c2s = Some(c2s);
        self.pending_s2c = Some(s2c);

        self.send_packet(&[MSG_NEWKEYS])?;
        if let Some(mut c2s_k) = self.pending_c2s.take() {
            self.tx_cipher = Some(OpenSshChaCha20Poly1305::new(&c2s_k));
            c2s_k.zeroize();
        }
        self.tx_seq = 0;
        self.state = ClientState::AwaitNewKeys;
        Ok(0)
    }

    fn handle_service_accept(&mut self, sign_rnd: [u8; 32]) -> Result<usize, SshError> {
        let sid = self.session_id.ok_or(SshError::CryptoFailure)?;
        let uname = core::str::from_utf8(&self.username[..self.username_len]).unwrap_or("newos");
        let mut sd = [0u8; 512];
        let sd_len = build_userauth_signed_data(&sid, uname, &self.user_pk, &mut sd)?;

        let prefix = [0u8, CTX_USERAUTH_LEN];
        let mut rnd = DsaB32::default();
        rnd.copy_from_slice(&sign_rnd);
        let sig = self
            .user_sk
            .expanded_key()
            .sign_internal(&[&prefix, CTX_USERAUTH, &sd[..sd_len]], &rnd);
        rnd.zeroize();
        let sig_enc = sig.encode();

        let mut auth_pkt = [0u8; MAX_PACKET_BODY];
        let mut w = WireWriter::new(&mut auth_pkt);
        w.write_u8(MSG_USERAUTH_REQUEST)?;
        w.write_str(uname)?;
        w.write_str("ssh-connection")?;
        w.write_str("publickey")?;
        w.write_bool(true)?;
        w.write_str(ALG_HOST_KEY)?;
        w.write_string(&self.user_pk)?;
        w.write_string(sig_enc.as_slice())?;
        let len = w.len();
        self.send_packet(&auth_pkt[..len])?;
        self.state = ClientState::AwaitUserAuth;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVault {
        host_sk: SigningKey<MlDsa87>,
        host_pk: [u8; MLDSA87_PK_BYTES],
        allowed_pk: [u8; MLDSA87_PK_BYTES],
        pending_sid: Option<[u8; 64]>,
        counter: u8,
    }

    impl MockVault {
        fn new(allowed_pk: &[u8; MLDSA87_PK_BYTES]) -> Self {
            let mut seed = DsaB32::default();
            seed.as_mut_slice().fill(0x33);
            let host_signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
            let mut host_pk = [0u8; MLDSA87_PK_BYTES];
            host_pk.copy_from_slice(host_signing_key.verifying_key().encode().as_slice());
            Self {
                host_sk: host_signing_key,
                host_pk,
                allowed_pk: *allowed_pk,
                pending_sid: None,
                counter: 1,
            }
        }
    }

    impl KeyVaultClient for MockVault {
        fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError> {
            Ok(self.host_pk)
        }

        fn random_32(&mut self) -> Result<[u8; 32], SshError> {
            self.counter = self.counter.wrapping_add(1);
            Ok([self.counter; 32])
        }

        fn sign_kex_hash(
            &mut self,
            hash64: &[u8; 64],
        ) -> Result<[u8; MLDSA87_SIG_BYTES], SshError> {
            let prefix = [0u8, CTX_KEX_LEN];
            let sig = self
                .host_sk
                .expanded_key()
                .sign_internal(&[&prefix, CTX_KEX, hash64], &DsaB32::default());
            let mut out = [0u8; MLDSA87_SIG_BYTES];
            out.copy_from_slice(sig.encode().as_slice());
            self.pending_sid = Some(*hash64);
            Ok(out)
        }

        fn verify_user_auth(
            &mut self,
            client_pk: &[u8; MLDSA87_PK_BYTES],
            signed_data: &[u8],
            sig_bytes: &[u8; MLDSA87_SIG_BYTES],
        ) -> Result<bool, SshError> {
            let Some(sid) = self.pending_sid.take() else {
                return Ok(false);
            };
            if signed_data.len() < 68 || signed_data[4..68] != sid || client_pk != &self.allowed_pk
            {
                return Ok(false);
            }
            let mut pk_arr = EncodedVerifyingKey::<MlDsa87>::default();
            pk_arr.copy_from_slice(client_pk);
            let vk = VerifyingKey::<MlDsa87>::decode(&pk_arr);
            let mut sig_arr = EncodedSignature::<MlDsa87>::default();
            sig_arr.copy_from_slice(sig_bytes);
            let Some(sig) = Signature::<MlDsa87>::decode(&sig_arr) else {
                return Ok(false);
            };
            Ok(vk.verify_with_context(signed_data, CTX_USERAUTH, &sig))
        }

        fn close_session(&mut self) {
            self.pending_sid = None;
        }
    }

    #[test]
    fn full_pure_pq_mlkem1024_mldsa87_handshake_and_shell_exchange() {
        let mut user_seed = DsaB32::default();
        user_seed.as_mut_slice().fill(0x77);
        let user_signing_key = SigningKey::<MlDsa87>::from_seed(&user_seed);
        let mut user_pk = [0u8; MLDSA87_PK_BYTES];
        user_pk.copy_from_slice(user_signing_key.verifying_key().encode().as_slice());

        let mut vault = MockVault::new(&user_pk);
        let expected_fp = sha3_512(&vault.host_pk);

        let mut server = SshServer::new();
        let mut client = SshClient::new("newos", user_signing_key, Some(expected_fp), [0x99u8; 64]);

        let mut s_shell_buf = [0u8; 256];
        let mut c_shell_buf = [0u8; 256];

        // Pump wire bytes until both sides reach ShellOpen
        for _ in 0..12 {
            let s_tx_len = server.pending_tx().len();
            if s_tx_len > 0 {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                tmp[..s_tx_len].copy_from_slice(server.pending_tx());
                server.consume_tx(s_tx_len);
                let _ = client
                    .feed_rx(&tmp[..s_tx_len], [0x11; 16], [0x22; 32], &mut c_shell_buf)
                    .expect("client rx");
            }
            let c_tx_len = client.pending_tx().len();
            if c_tx_len > 0 {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                tmp[..c_tx_len].copy_from_slice(client.pending_tx());
                client.consume_tx(c_tx_len);
                let _ = server
                    .feed_rx(&tmp[..c_tx_len], &mut vault, &mut s_shell_buf)
                    .expect("server rx");
            }
            if server.is_shell_open() && client.state() == ClientState::ShellOpen {
                break;
            }
        }
        assert!(server.is_shell_open());
        assert_eq!(client.state(), ClientState::ShellOpen);
        assert_eq!(client.host_fingerprint(), Some(expected_fp));

        // Bidirectional encrypted shell command & output exchange
        client.send_shell_input(b"domains | count\n").unwrap();
        let c_len = client.pending_tx().len();
        let mut wire = [0u8; 1024];
        wire[..c_len].copy_from_slice(client.pending_tx());
        client.consume_tx(c_len);
        let n_in = server
            .feed_rx(&wire[..c_len], &mut vault, &mut s_shell_buf)
            .unwrap();
        assert_eq!(&s_shell_buf[..n_in], b"domains | count\n");

        server.send_shell_output(b"count: 5\n").unwrap();
        let s_len = server.pending_tx().len();
        wire[..s_len].copy_from_slice(server.pending_tx());
        server.consume_tx(s_len);
        let n_out = client
            .feed_rx(&wire[..s_len], [0; 16], [0; 32], &mut c_shell_buf)
            .unwrap();
        assert_eq!(&c_shell_buf[..n_out], b"count: 5\n");
    }

    #[test]
    fn strict_kex_rejects_pre_newkeys_ignore_and_classical_kexinit() {
        let mut vault = MockVault::new(&[0u8; MLDSA87_PK_BYTES]);
        let mut server = SshServer::new();
        let mut shell = [0u8; 64];

        // 1. Send banner -> server transitions to AwaitKexInit
        assert_eq!(server.feed_rx(SSH_BANNER, &mut vault, &mut shell), Ok(0));

        // 2. Inject SSH_MSG_IGNORE before NEWKEYS -> MUST fail with StrictKexViolation (Terrapin)
        let mut pkt = [0u8; 64];
        let mut seq = 0u64;
        let n = encode_packet(&[MSG_IGNORE, 0, 0, 0, 0], None, &mut seq, &mut pkt).unwrap();
        assert_eq!(
            server.feed_rx(&pkt[..n], &mut vault, &mut shell),
            Err(SshError::StrictKexViolation)
        );

        // 3. Classical-only KEXINIT (`curve25519-sha256` / `ssh-ed25519`) MUST be rejected
        server.reset();
        assert_eq!(server.feed_rx(SSH_BANNER, &mut vault, &mut shell), Ok(0));
        let mut legacy = [0u8; 512];
        let mut w = WireWriter::new(&mut legacy);
        w.write_u8(MSG_KEXINIT).unwrap();
        w.write_raw(&[0u8; 16]).unwrap();
        w.write_str("curve25519-sha256,kex-strict-c-v00@openssh.com")
            .unwrap();
        w.write_str("ssh-ed25519").unwrap();
        w.write_str(ALG_CIPHER).unwrap();
        w.write_str(ALG_CIPHER).unwrap();
        w.write_str("none").unwrap();
        w.write_str("none").unwrap();
        w.write_str("none").unwrap();
        w.write_str("none").unwrap();
        w.write_str("").unwrap();
        w.write_str("").unwrap();
        w.write_bool(false).unwrap();
        w.write_u32(0).unwrap();
        let llen = w.len();
        let mut lseq = 0u64;
        let mut lpkt = [0u8; 600];
        let ln = encode_packet(&legacy[..llen], None, &mut lseq, &mut lpkt).unwrap();
        assert_eq!(
            server.feed_rx(&lpkt[..ln], &mut vault, &mut shell),
            Err(SshError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn banner_validation_rejects_non_ssh2_and_overlong_lines() {
        let mut vault = MockVault::new(&[0u8; MLDSA87_PK_BYTES]);
        let mut server = SshServer::new();
        let mut shell = [0u8; 64];

        // SSH-1.99 / SSH-1.5 rejected
        assert!(
            server
                .feed_rx(b"SSH-1.5-legacy\r\n", &mut vault, &mut shell)
                .is_err()
        );

        // Overlong banner (>255 bytes without CRLF)
        server.reset();
        let overlong = [b'A'; 260];
        assert!(server.feed_rx(&overlong, &mut vault, &mut shell).is_err());
    }

    #[test]
    fn client_rejects_mismatched_host_fingerprint() {
        let mut user_seed = DsaB32::default();
        user_seed.as_mut_slice().fill(0x55);
        let user_signing_key = SigningKey::<MlDsa87>::from_seed(&user_seed);
        let mut user_pk = [0u8; MLDSA87_PK_BYTES];
        user_pk.copy_from_slice(user_signing_key.verifying_key().encode().as_slice());

        let mut vault = MockVault::new(&user_pk);
        let wrong_fp = [0xAAu8; 64];
        let mut server = SshServer::new();
        let mut client = SshClient::new("newos", user_signing_key, Some(wrong_fp), [0x12u8; 64]);
        let mut s_buf = [0u8; 64];
        let mut c_buf = [0u8; 64];

        let mut saw_fp_err = false;
        for _ in 0..8 {
            if !server.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = server.pending_tx().len();
                tmp[..n].copy_from_slice(server.pending_tx());
                server.consume_tx(n);
                match client.feed_rx(&tmp[..n], [0x33; 16], [0x44; 32], &mut c_buf) {
                    Err(SshError::CryptoFailure | SshError::AuthFailed) => {
                        saw_fp_err = true;
                        break;
                    }
                    Err(other) => panic!("expected CryptoFailure/AuthFailed, got {other:?}"),
                    Ok(_) => {}
                }
            }
            if !client.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = client.pending_tx().len();
                tmp[..n].copy_from_slice(client.pending_tx());
                client.consume_tx(n);
                let _ = server.feed_rx(&tmp[..n], &mut vault, &mut s_buf).unwrap();
            }
        }
        assert!(saw_fp_err, "client must reject mismatched host fingerprint");
    }

    #[test]
    fn unauthorized_client_key_cannot_open_shell() {
        let mut user_seed = DsaB32::default();
        user_seed.as_mut_slice().fill(0x21);
        let user_sk = SigningKey::<MlDsa87>::from_seed(&user_seed);

        // Vault allows a DIFFERENT key than `user_sk`
        let mut vault = MockVault::new(&[0xEEu8; MLDSA87_PK_BYTES]);
        let expected_fp = sha3_512(&vault.host_pk);
        let mut server = SshServer::new();
        let mut client = SshClient::new("newos", user_sk, Some(expected_fp), [0x34u8; 64]);
        let mut s_buf = [0u8; 64];
        let mut c_buf = [0u8; 64];

        for _ in 0..12 {
            if !server.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = server.pending_tx().len();
                tmp[..n].copy_from_slice(server.pending_tx());
                server.consume_tx(n);
                let _ = client.feed_rx(&tmp[..n], [0x55; 16], [0x66; 32], &mut c_buf);
            }
            if !client.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = client.pending_tx().len();
                tmp[..n].copy_from_slice(client.pending_tx());
                client.consume_tx(n);
                let _ = server.feed_rx(&tmp[..n], &mut vault, &mut s_buf);
            }
        }
        assert!(!server.is_shell_open());
        assert_ne!(client.state(), ClientState::ShellOpen);

        // Sending shell data before ShellOpen must emit zero wire bytes on both sides
        let s_tx_before = server.pending_tx().len();
        assert_eq!(server.send_shell_output(b"hi"), Ok(()));
        assert_eq!(server.pending_tx().len(), s_tx_before);
        let c_tx_before = client.pending_tx().len();
        assert_eq!(client.send_shell_input(b"hi"), Ok(()));
        assert_eq!(client.pending_tx().len(), c_tx_before);
    }

    #[test]
    fn tampered_encrypted_shell_packet_fails_with_crypto_failure() {
        let mut good_seed = DsaB32::default();
        good_seed.as_mut_slice().fill(0x88);
        let good_signing_key = SigningKey::<MlDsa87>::from_seed(&good_seed);
        let mut good_pk = [0u8; MLDSA87_PK_BYTES];
        good_pk.copy_from_slice(good_signing_key.verifying_key().encode().as_slice());
        let mut good_vault = MockVault::new(&good_pk);
        let good_fp = sha3_512(&good_vault.host_pk);
        let mut srv2 = SshServer::new();
        let mut cli2 = SshClient::new("newos", good_signing_key, Some(good_fp), [0x78u8; 64]);
        let mut s_buf = [0u8; 64];
        let mut c_buf = [0u8; 64];

        for _ in 0..12 {
            if !srv2.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = srv2.pending_tx().len();
                tmp[..n].copy_from_slice(srv2.pending_tx());
                srv2.consume_tx(n);
                let _ = cli2
                    .feed_rx(&tmp[..n], [0x11; 16], [0x22; 32], &mut c_buf)
                    .unwrap();
            }
            if !cli2.pending_tx().is_empty() {
                let mut tmp = [0u8; MAX_PACKET_BODY + 64];
                let n = cli2.pending_tx().len();
                tmp[..n].copy_from_slice(cli2.pending_tx());
                cli2.consume_tx(n);
                let _ = srv2
                    .feed_rx(&tmp[..n], &mut good_vault, &mut s_buf)
                    .unwrap();
            }
            if srv2.is_shell_open() && cli2.state() == ClientState::ShellOpen {
                break;
            }
        }
        assert!(srv2.is_shell_open());

        cli2.send_shell_input(b"status\n").unwrap();
        let n = cli2.pending_tx().len();
        let mut tampered = [0u8; 1024];
        tampered[..n].copy_from_slice(cli2.pending_tx());
        cli2.consume_tx(n);
        tampered[n - 1] ^= 0x01; // Flip 1 bit in Poly1305 tag
        assert_eq!(
            srv2.feed_rx(&tampered[..n], &mut good_vault, &mut s_buf),
            Err(SshError::CryptoFailure)
        );
    }

    #[test]
    fn ssh_error_display_and_core_error() {
        extern crate std;
        use core::error::Error as _;
        use std::format;

        for err in [
            SshError::MalformedPacket,
            SshError::PacketTooLarge,
            SshError::StrictKexViolation,
            SshError::UnsupportedAlgorithm,
            SshError::CryptoFailure,
            SshError::AuthFailed,
            SshError::TooManyAuthAttempts,
            SshError::DisallowedRequest,
            SshError::VaultError,
            SshError::Disconnected,
        ] {
            assert!(err.source().is_none());
            assert_ne!(format!("{err}"), "");
        }
    }

    #[test]
    fn ssh_server_and_client_debug_redact_secrets() {
        extern crate std;
        use std::format;

        let mut seed = DsaB32::default();
        seed.as_mut_slice().fill(0x42);
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
        let server = SshServer::new();
        let client = SshClient::new("newos", signing_key, None, [0x5Au8; 64]);

        let s_dbg = format!("{server:?}");
        assert!(s_dbg.contains("SshServer"));
        assert!(s_dbg.contains("<redacted>"));

        let c_dbg = format!("{client:?}");
        assert!(c_dbg.contains("SshClient"));
        assert!(c_dbg.contains("<redacted>"));
        assert!(!c_dbg.contains("90, 90, 90"));
    }

    #[test]
    fn ssh_client_truncates_multibyte_utf8_username_on_char_boundary() {
        let mut seed = DsaB32::default();
        seed.as_mut_slice().fill(0x19);
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

        // 30 ASCII bytes + a 3-byte UTF-8 char ('€' = 0xE2 0x82 0xAC) crosses byte 32.
        let long_utf8 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa€tail";
        let client = SshClient::new(long_utf8, signing_key, None, [0x11u8; 64]);
        let stored = core::str::from_utf8(&client.username[..client.username_len])
            .expect("truncated username must remain valid UTF-8");
        assert_eq!(stored, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
}
