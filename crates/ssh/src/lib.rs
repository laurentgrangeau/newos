#![no_std]
#![forbid(unsafe_code)]

//! Pure Post-Quantum SSHv2 Engine (`newos-ssh-proto`) — `#![no_std]`, `no_alloc`,
//! `#![forbid(unsafe_code)]`.
//!
//! Enforces a single, maximally hardened NIST Level 5 / CNSA 2.0 pure-PQ cryptographic suite:
//! - **KEX:** `mlkem1024-sha3-512` (NIST FIPS 203 **ML-KEM-1024** + `SHA3-512`)
//! - **Host & User Auth:** `ssh-mldsa87` (NIST FIPS 204 **ML-DSA-87**, hedged, domain-separated)
//! - **AEAD:** `chacha20-poly1305@openssh.com` (256-bit ChaCha20 + Poly1305, encrypted length)
//! - **KDF:** FIPS 202 `SHAKE256`
//! - **Transport Hardening:** `kex-strict` (Terrapin CVE-2023-48795 mitigation)
//! - **Zero legacy crypto:** no RSA, DH, ECDH, X25519, Ed25519, SHA-1, SHA-2, CBC/CTR, or passwords.
//! - **Minimal session surface:** single interactive `newos-sh` shell (`session` + `pty-req`/`shell`).

pub mod aead;
pub mod wire;

use aead::{OpenSshChaCha20Poly1305, TAG_LEN};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_dsa::{
    B32 as DsaB32, EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey,
    VerifyingKey,
};
use ml_kem::{B32 as KemB32, Ciphertext, DecapsulationKey1024, EncapsulationKey1024, MlKem1024, Seed};
use newos_abi::key_ipc::{MLDSA87_PK_BYTES, MLDSA87_SIG_BYTES};
use newos_abi::sha3::{sha3_512, shake256};
use wire::{MAX_PACKET_BODY, WireReader, WireWriter};
use zeroize::Zeroize;

/// Server & Client SSH protocol banner (RFC 4253).
pub const SSH_BANNER: &[u8] = b"SSH-2.0-NewOS_PQ_0.1\r\n";
pub const SSH_BANNER_NO_CRLF: &[u8] = b"SSH-2.0-NewOS_PQ_0.1";

/// Single-suite strict algorithm identifiers (zero legacy / classical algorithms).
pub const ALG_KEX: &str = "mlkem1024-sha3-512";
pub const ALG_KEX_STRICT_S: &str = "kex-strict-s-v00@openssh.com";
pub const ALG_KEX_STRICT_C: &str = "kex-strict-c-v00@openssh.com";
pub const ALG_HOST_KEY: &str = "ssh-mldsa87";
pub const ALG_CIPHER: &str = "chacha20-poly1305@openssh.com";
pub const ALG_COMP: &str = "none";

/// FIPS 204 ML-DSA-87 domain contexts (must match `newos-key-vault`).
pub const CTX_KEX: &[u8] = b"newos-ssh-kex-v1";
pub const CTX_USERAUTH: &[u8] = b"newos-ssh-userauth-v1";

/// ML-KEM-1024 wire sizes (FIPS 203).
pub const MLKEM1024_EK_BYTES: usize = 1568;
pub const MLKEM1024_CT_BYTES: usize = 1568;

/// SSHv2 message numbers (RFC 4253 / 4252 / 4254).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Abstract cryptographic vault interface implemented by `newos-sshd` over `BOOTSTRAP_KEY_EP`
/// (and by direct in-process `KeyVault` in host unit/E2E tests).
pub trait KeyVaultClient {
    fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError>;
    fn random_32(&mut self) -> Result<[u8; 32], SshError>;
    fn sign_kex_hash(&mut self, hash64: &[u8; 64]) -> Result<[u8; MLDSA87_SIG_BYTES], SshError>;
    fn verify_user_auth(
        &mut self,
        client_pk: &[u8; MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig: &[u8; MLDSA87_SIG_BYTES],
    ) -> Result<bool, SshError>;
    fn close_session(&mut self);
}

fn name_list_contains(list: &str, needle: &str) -> bool {
    list.split(',').any(|item| item == needle)
}

/// Compute the 64-byte `SHA3-512` exchange hash `H` for `mlkem1024-sha3-512`.
///
/// `H = SHA3-512(string(V_C) || string(V_S) || string(I_C) || string(I_S)
///              || string(K_S) || string(Q_C) || string(Q_S) || string(K))`
#[allow(clippy::too_many_arguments)]
fn compute_exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    k_shared_hash: &[u8; 64],
) -> Result<[u8; 64], SshError> {
    // 2592 (K_S) + 1568 (Q_C) + 1568 (Q_S) + 64 (K) + banners + kexinits <= 8192 bytes
    let mut transcript = [0u8; 8192];
    let mut w = WireWriter::new(&mut transcript);
    w.write_string(v_c)?;
    w.write_string(v_s)?;
    w.write_string(i_c)?;
    w.write_string(i_s)?;
    w.write_string(k_s)?;
    w.write_string(q_c)?;
    w.write_string(q_s)?;
    w.write_string(k_shared_hash)?;
    let len = w.len();
    let h = sha3_512(&transcript[..len]);
    transcript[..len].zeroize();
    Ok(h)
}

/// Derive directional 64-byte `chacha20-poly1305@openssh.com` keys via domain-separated `SHAKE256`.
fn derive_session_keys(k_hash: &[u8; 64], h: &[u8; 64], session_id: &[u8; 64]) -> ([u8; 64], [u8; 64]) {
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

/// Encode an SSHv2 packet (plaintext before `NEWKEYS`, or `chacha20-poly1305@openssh.com` after).
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

    out[0..4].copy_from_slice(&(packet_len as u32).to_be_bytes());
    out[4] = pad_len as u8;
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
fn build_kexinit(is_server: bool, cookie: &[u8; 16], out: &mut [u8]) -> Result<usize, SshError> {
    let mut w = WireWriter::new(out);
    w.write_u8(MSG_KEXINIT)?;
    w.write_raw(cookie)?;
    if is_server {
        w.write_str("mlkem1024-sha3-512,kex-strict-s-v00@openssh.com")?;
    } else {
        w.write_str("mlkem1024-sha3-512,kex-strict-c-v00@openssh.com")?;
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

/// Validate a peer's `SSH_MSG_KEXINIT` against our strict pure-PQ single-suite policy.
fn validate_peer_kexinit(payload: &[u8], peer_is_client: bool) -> Result<(), SshError> {
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

    let strict_ext = if peer_is_client {
        ALG_KEX_STRICT_C
    } else {
        ALG_KEX_STRICT_S
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

/// Build the SSHv2 `signed_data` payload for `SSH_MSG_USERAUTH_REQUEST` publickey signing.
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
    // Compact SHA3-512 key-blob commitment inside signed_data (keeps `signed_data <= 512 B` for keyd)
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

/// Server-side pure-PQ SSHv2 state machine (`#![no_std]`, `no_alloc`, `#![forbid(unsafe_code)]`).
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

impl Default for SshServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SshServer {
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

    #[inline]
    pub fn is_shell_open(&self) -> bool {
        self.state == ServerState::ShellOpen
    }

    /// Pending encrypted wire bytes ready to transmit to `newos-netd`.
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx_buf[self.tx_off..self.tx_len]
    }

    /// Mark `n` bytes of `pending_tx()` as sent.
    pub fn consume_tx(&mut self, n: usize) {
        self.tx_off = (self.tx_off + n).min(self.tx_len);
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

    /// Queue interactive shell output bytes as `SSH_MSG_CHANNEL_DATA`.
    pub fn send_shell_output(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state != ServerState::ShellOpen || data.is_empty() {
            return Ok(());
        }
        let mut body = [0u8; 1024];
        let mut w = WireWriter::new(&mut body);
        w.write_u8(MSG_CHANNEL_DATA)?;
        w.write_u32(self.peer_channel_id)?;
        let chunk = data.len().min(960);
        w.write_string(&data[..chunk])?;
        let len = w.len();
        self.send_packet(&body[..len])
    }

    /// Feed incoming TCP bytes from `newos-netd`. Any decrypted interactive shell input
    /// is written into `shell_in_out` and its byte count is returned.
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

        // Immediately send strict pure-PQ `SSH_MSG_KEXINIT`
        let rnd = vault.random_32()?;
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&rnd[..16]);
        let mut kex_payload = [0u8; 512];
        let kex_len = build_kexinit(true, &cookie, &mut kex_payload)?;
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
        let enc_len = [self.rx_buf[0], self.rx_buf[1], self.rx_buf[2], self.rx_buf[3]];
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

        let n_shell = self.handle_message(&payload[..payload_len], vault, shell_out)?;
        payload[..payload_len].zeroize();
        Ok(Some(n_shell))
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
                validate_peer_kexinit(payload, true)?;
                if payload.len() > self.client_kexinit.len() {
                    return Err(SshError::PacketTooLarge);
                }
                self.client_kexinit[..payload.len()].copy_from_slice(payload);
                self.client_kexinit_len = payload.len();
                self.state = ServerState::AwaitMlKemInit;
                Ok(0)
            }
            (ServerState::AwaitMlKemInit, MSG_KEX_MLKEM_INIT) => {
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let q_c = r.read_string()?;
                if q_c.len() != MLKEM1024_EK_BYTES {
                    return Err(SshError::MalformedPacket);
                }
                let mut ek_arr = ml_kem::array::Array::default();
                ek_arr.copy_from_slice(q_c);
                let ek = EncapsulationKey1024::new(&ek_arr).map_err(|_| SshError::CryptoFailure)?;

                // Encapsulate with 32 bytes from `newos-keyd` fast-key-erasure CSPRNG
                let mut rnd_bytes = vault.random_32()?;
                let mut m = KemB32::default();
                m.copy_from_slice(&rnd_bytes);
                rnd_bytes.zeroize();
                let (ct, mut ss) = ek.encapsulate_deterministic(&m);
                m.zeroize();

                let mut k_hash = sha3_512(ss.as_slice());
                ss.zeroize();

                let host_pk = vault.host_public_key()?;
                let h = compute_exchange_hash(
                    &self.client_banner[..self.client_banner_len],
                    SSH_BANNER_NO_CRLF,
                    &self.client_kexinit[..self.client_kexinit_len],
                    &self.server_kexinit[..self.server_kexinit_len],
                    &host_pk,
                    q_c,
                    ct.as_slice(),
                    &k_hash,
                )?;
                let sig = vault.sign_kex_hash(&h)?;

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
                self.auth_attempts = self.auth_attempts.saturating_add(1);
                if self.auth_attempts > MAX_AUTH_ATTEMPTS {
                    return Err(SshError::TooManyAuthAttempts);
                }
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let username = r.read_str()?;
                let service = r.read_str()?;
                let method = r.read_str()?;
                if service != "ssh-connection" || method != "publickey" {
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
                let sd_len =
                    build_userauth_signed_data(&sid, username, &client_pk, &mut signed_data)?;

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
            (ServerState::Authenticated, MSG_CHANNEL_OPEN) => {
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
            (ServerState::Authenticated | ServerState::ShellOpen, MSG_CHANNEL_REQUEST) => {
                let mut r = WireReader::new(payload);
                let _ = r.read_u8()?;
                let _recipient = r.read_u32()?;
                let req_type = r.read_str()?;
                let want_reply = r.read_bool()?;
                match req_type {
                    "pty-req" | "window-change" => {
                        if want_reply {
                            self.send_channel_reply(true)?;
                        }
                        Ok(0)
                    }
                    "shell" => {
                        self.state = ServerState::ShellOpen;
                        if want_reply {
                            self.send_channel_reply(true)?;
                        }
                        Ok(0)
                    }
                    // Strictly reject `exec`, `subsystem`, `x11-req`, `auth-agent-req`, etc.
                    _ => {
                        if want_reply {
                            self.send_channel_reply(false)?;
                        }
                        Err(SshError::DisallowedRequest)
                    }
                }
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
            (_, MSG_CHANNEL_WINDOW_ADJUST) => Ok(0),
            (_, MSG_CHANNEL_EOF | MSG_CHANNEL_CLOSE | MSG_DISCONNECT) => {
                vault.close_session();
                Err(SshError::Disconnected)
            }
            _ => Err(SshError::StrictKexViolation),
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

    fn send_channel_reply(&mut self, ok: bool) -> Result<(), SshError> {
        let mut resp = [0u8; 8];
        let mut w = WireWriter::new(&mut resp);
        w.write_u8(if ok {
            MSG_CHANNEL_SUCCESS
        } else {
            MSG_CHANNEL_FAILURE
        })?;
        w.write_u32(self.peer_channel_id)?;
        let len = w.len();
        self.send_packet(&resp[..len])
    }
}

/// Client-side pure-PQ SSHv2 state machine shared by `crates/ssh-client` (`newos-ssh`) and tests.
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

impl SshClient {
    pub fn new(
        username: &str,
        user_sk: SigningKey<MlDsa87>,
        expected_fingerprint: Option<[u8; 64]>,
        kem_seed: [u8; 64],
    ) -> Self {
        let enc_pk = user_sk.verifying_key().encode();
        let mut user_pk = [0u8; MLDSA87_PK_BYTES];
        user_pk.copy_from_slice(enc_pk.as_slice());

        let mut seed = Seed::default();
        seed.copy_from_slice(&kem_seed);
        let kem_dk = DecapsulationKey1024::from_seed(seed);
        let ek_enc = kem_dk.encapsulation_key().to_bytes();
        let mut kem_ek_bytes = [0u8; MLKEM1024_EK_BYTES];
        kem_ek_bytes.copy_from_slice(ek_enc.as_slice());

        let mut uname = [0u8; 32];
        let ulen = username.len().min(32);
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
            user_pk,
        };
        c.queue_raw_tx(SSH_BANNER);
        c
    }

    pub fn state(&self) -> ClientState {
        self.state
    }

    pub fn host_fingerprint(&self) -> Option<[u8; 64]> {
        self.host_fingerprint
    }

    pub fn pending_tx(&self) -> &[u8] {
        &self.tx_buf[self.tx_off..self.tx_len]
    }

    pub fn consume_tx(&mut self, n: usize) {
        self.tx_off = (self.tx_off + n).min(self.tx_len);
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

    pub fn send_shell_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        if self.state != ClientState::ShellOpen || data.is_empty() {
            return Ok(());
        }
        let mut body = [0u8; 1024];
        let mut w = WireWriter::new(&mut body);
        w.write_u8(MSG_CHANNEL_DATA)?;
        w.write_u32(0)?;
        let chunk = data.len().min(960);
        w.write_string(&data[..chunk])?;
        let len = w.len();
        self.send_packet(&body[..len])
    }

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
                    let klen = build_kexinit(false, &cookie, &mut kex)?;
                    self.client_kexinit[..klen].copy_from_slice(&kex[..klen]);
                    self.client_kexinit_len = klen;
                    self.send_packet(&kex[..klen])?;
                    self.state = ClientState::AwaitKexInit;
                    continue;
                }

                if self.rx_len < 4 {
                    break;
                }
                let enc_len = [self.rx_buf[0], self.rx_buf[1], self.rx_buf[2], self.rx_buf[3]];
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
                let payload_len = packet_len - 1 - pad_len;
                let mut payload = [0u8; MAX_PACKET_BODY];
                payload[..payload_len].copy_from_slice(&self.rx_buf[5..5 + payload_len]);
                self.rx_buf.copy_within(total..self.rx_len, 0);
                self.rx_len -= total;

                let n = self.handle_server_msg(
                    &payload[..payload_len],
                    sign_rnd,
                    &mut shell_out[written..],
                )?;
                written += n;
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
                validate_peer_kexinit(payload, false)?;
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

                let h = compute_exchange_hash(
                    SSH_BANNER_NO_CRLF,
                    &self.server_banner[..self.server_banner_len],
                    &self.client_kexinit[..self.client_kexinit_len],
                    &self.server_kexinit[..self.server_kexinit_len],
                    host_pk,
                    &self.kem_ek_bytes,
                    ct_bytes,
                    &k_hash,
                )?;

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
                let sid = self.session_id.ok_or(SshError::CryptoFailure)?;
                let uname = core::str::from_utf8(&self.username[..self.username_len])
                    .unwrap_or("newos");
                let mut sd = [0u8; 512];
                let sd_len = build_userauth_signed_data(&sid, uname, &self.user_pk, &mut sd)?;

                let prefix = [0u8, CTX_USERAUTH.len() as u8];
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
        fn new(allowed_pk: [u8; MLDSA87_PK_BYTES]) -> Self {
            let mut seed = DsaB32::default();
            seed.as_mut_slice().fill(0x33);
            let host_sk = SigningKey::<MlDsa87>::from_seed(&seed);
            let mut host_pk = [0u8; MLDSA87_PK_BYTES];
            host_pk.copy_from_slice(host_sk.verifying_key().encode().as_slice());
            Self {
                host_sk,
                host_pk,
                allowed_pk,
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

        fn sign_kex_hash(&mut self, hash64: &[u8; 64]) -> Result<[u8; MLDSA87_SIG_BYTES], SshError> {
            let prefix = [0u8, CTX_KEX.len() as u8];
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
            if signed_data.len() < 68 || &signed_data[4..68] != &sid || client_pk != &self.allowed_pk
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
        let user_sk = SigningKey::<MlDsa87>::from_seed(&user_seed);
        let mut user_pk = [0u8; MLDSA87_PK_BYTES];
        user_pk.copy_from_slice(user_sk.verifying_key().encode().as_slice());

        let mut vault = MockVault::new(user_pk);
        let expected_fp = sha3_512(&vault.host_pk);

        let mut server = SshServer::new();
        let mut client = SshClient::new("newos", user_sk, Some(expected_fp), [0x99u8; 64]);

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
        client.send_shell_input(b"procs | count\n").unwrap();
        let c_len = client.pending_tx().len();
        let mut wire = [0u8; 1024];
        wire[..c_len].copy_from_slice(client.pending_tx());
        client.consume_tx(c_len);
        let n_in = server
            .feed_rx(&wire[..c_len], &mut vault, &mut s_shell_buf)
            .unwrap();
        assert_eq!(&s_shell_buf[..n_in], b"procs | count\n");

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
        let mut vault = MockVault::new([0u8; MLDSA87_PK_BYTES]);
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
        w.write_str("curve25519-sha256,kex-strict-c-v00@openssh.com").unwrap();
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
}
