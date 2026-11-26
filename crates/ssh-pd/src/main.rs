#![no_std]
#![no_main]

//! Isolated EL0 `SSHv2` protection domain (`newos-ssh-pd`, PD 4).
//!
//! Strict least-privilege capability set:
//! - `CapId::BOOTSTRAP_NET_EP` (`R|W`, badge 4) — opaque TCP byte stream from `newos-net-pd`
//! - `CapId::BOOTSTRAP_KEY_EP` (`R|W`, badge 4) — narrow RPCs to `newos-key-pd`
//! - `CapId::BOOTSTRAP_SSH_SHELL_EP` (`R|W`, badge 4) — auth-gated shell bytes to `newos-supervisor-pd`
//! - `CapId::BOOTSTRAP_LOG_EP` (`W`, badge 4) — write-only audit log
//!
//! Explicitly holds **ZERO** MMIO capabilities, **ZERO** `VSpace`, **ZERO** `AUTH_GATE_EP`,
//! **ZERO** `CONSOLE`/`POWER`/`UNTYPED`/`THREAD`/`CNODE`, and **ZERO** access to the
//! ML-DSA-87 host private key.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::key_ipc::{MLDSA87_PK_BYTES, MLDSA87_SIG_BYTES};
use newos_abi::{CapId, SysError, key_ipc, log_ipc, net_ipc};
use newos_ssh_proto::{KeyVaultClient, SshError, SshServer};
use newos_user_rt::IpcLogConsole;

fn ipc_call_retry(ep: CapId, word: u64) -> Result<u64, SysError> {
    for _ in 0..10_000 {
        match newos_user_rt::ipc_call(ep, word) {
            Ok((_badge, reply)) => return Ok(reply),
            Err(SysError::WouldBlock) => {
                let _ = newos_user_rt::sleep_ms(1);
            }
            Err(e) => return Err(e),
        }
    }
    Err(SysError::WouldBlock)
}

/// RPC client talking exclusively to `newos-key-pd` (PD 3) over `CapId::BOOTSTRAP_KEY_EP`.
struct IpcKeyVault;

impl KeyVaultClient for IpcKeyVault {
    fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError> {
        let mut pk = [0u8; MLDSA87_PK_BYTES];
        let words = MLDSA87_PK_BYTES.div_ceil(8);
        for i in 0..words {
            let idx = u32::try_from(i).map_err(|_| SshError::VaultError)?;
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_GET_HOST_PK_WORD, idx),
            )
            .map_err(|_| SshError::VaultError)?;
            let bytes = w.to_le_bytes();
            let off = i * 8;
            let take = (MLDSA87_PK_BYTES - off).min(8);
            pk[off..off + take].copy_from_slice(&bytes[..take]);
        }
        Ok(pk)
    }

    fn random_32(&mut self) -> Result<[u8; 32], SshError> {
        // Fetch 8 tagged 4-byte CSPRNG chunks (`N1`): fail closed on any non-OK status tag
        // so `REPLY_DENIED` (0) can NEVER become all-zero ML-KEM randomness.
        let mut out = [0u8; 32];
        for i in 0..8 {
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_GET_RANDOM_U64, 0),
            )
            .map_err(|_| SshError::VaultError)?;
            let word32 = key_ipc::decode_random_u32_reply(w).ok_or(SshError::VaultError)?;
            out[i * 4..i * 4 + 4].copy_from_slice(&word32.to_le_bytes());
        }
        Ok(out)
    }

    fn sign_kex_hash(&mut self, hash64: &[u8; 64]) -> Result<[u8; MLDSA87_SIG_BYTES], SshError> {
        if ipc_call_retry(
            CapId::BOOTSTRAP_KEY_EP,
            key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_RESET, 0),
        ) != Ok(key_ipc::REPLY_OK)
        {
            return Err(SshError::VaultError);
        }
        for chunk in hash64.chunks(key_ipc::MAX_CHUNK_BYTES) {
            if ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_chunk_req(key_ipc::OP_SIGN_KEX_PUSH_BASE, chunk),
            ) != Ok(key_ipc::REPLY_OK)
            {
                return Err(SshError::VaultError);
            }
        }
        if ipc_call_retry(
            CapId::BOOTSTRAP_KEY_EP,
            key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_COMMIT, 0),
        ) != Ok(key_ipc::REPLY_OK)
        {
            return Err(SshError::VaultError);
        }
        let mut sig = [0u8; MLDSA87_SIG_BYTES];
        let words = MLDSA87_SIG_BYTES.div_ceil(8);
        for i in 0..words {
            let idx = u32::try_from(i).map_err(|_| SshError::VaultError)?;
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_READ_WORD, idx),
            )
            .map_err(|_| SshError::VaultError)?;
            let bytes = w.to_le_bytes();
            let off = i * 8;
            let take = (MLDSA87_SIG_BYTES - off).min(8);
            sig[off..off + take].copy_from_slice(&bytes[..take]);
        }
        Ok(sig)
    }

    fn verify_user_auth(
        &mut self,
        client_pk: &[u8; MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig: &[u8; MLDSA87_SIG_BYTES],
    ) -> Result<bool, SshError> {
        if ipc_call_retry(
            CapId::BOOTSTRAP_KEY_EP,
            key_ipc::encode_word_req(key_ipc::OP_VERIFY_RESET, 0),
        ) != Ok(key_ipc::REPLY_OK)
        {
            return Err(SshError::VaultError);
        }
        for c in client_pk.chunks(key_ipc::MAX_CHUNK_BYTES) {
            let _ = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_chunk_req(key_ipc::OP_VERIFY_PUSH_PK_BASE, c),
            )
            .map_err(|_| SshError::VaultError)?;
        }
        for c in signed_data.chunks(key_ipc::MAX_CHUNK_BYTES) {
            let _ = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_chunk_req(key_ipc::OP_VERIFY_PUSH_MSG_BASE, c),
            )
            .map_err(|_| SshError::VaultError)?;
        }
        for c in sig.chunks(key_ipc::MAX_CHUNK_BYTES) {
            let _ = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_chunk_req(key_ipc::OP_VERIFY_PUSH_SIG_BASE, c),
            )
            .map_err(|_| SshError::VaultError)?;
        }
        let res = ipc_call_retry(
            CapId::BOOTSTRAP_KEY_EP,
            key_ipc::encode_word_req(key_ipc::OP_VERIFY_COMMIT, 0),
        )
        .map_err(|_| SshError::VaultError)?;
        Ok(res == key_ipc::REPLY_OK)
    }

    fn close_session(&mut self) {
        let _ = ipc_call_retry(
            CapId::BOOTSTRAP_KEY_EP,
            key_ipc::encode_word_req(key_ipc::OP_CLOSE_SESSION, 0),
        );
    }
}

const NET_SSH_RING_VADDR: u64 = 0x0000_6000_0000_0000;
const SSH_KEY_RING_VADDR: u64 = 0x0000_6000_0001_0000;
const NET_TX_DOORBELL_BIT: u64 = 1 << 1;
const LOGIN_GRACE_MS: u64 = 30_000;
const IDLE_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Clone, Copy)]
struct ActiveSession {
    start_ms: u64,
    last_activity_ms: u64,
}

impl ActiveSession {
    const fn is_timed_out(self, shell_open: bool, now_ms: u64) -> bool {
        (!shell_open && now_ms.saturating_sub(self.start_ms) >= LOGIN_GRACE_MS)
            || now_ms.saturating_sub(self.last_activity_ms) >= IDLE_TIMEOUT_MS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxOutcome {
    Empty,
    Data(usize),
    Eof,
}

fn reset_session(
    vault: &mut IpcKeyVault,
    server: &mut SshServer,
    session: &mut Option<ActiveSession>,
) {
    vault.close_session();
    server.reset();
    *session = None;
}

fn flush_ssh_tx(server: &mut SshServer, net_ssh_ring: Option<&newos_user_rt::SharedRingPair>) {
    let mut pushed_ring_tx = false;
    while !server.pending_tx().is_empty() {
        if let Some(ring) = net_ssh_ring {
            let chunk_len = server.pending_tx().len().min(256);
            if let Ok(pushed) = ring
                .b_to_a
                .try_push_bytes(&server.pending_tx()[..chunk_len])
                && pushed > 0
            {
                server.consume_tx(pushed);
                pushed_ring_tx = true;
                continue;
            }
        }
        let chunk_len = server.pending_tx().len().min(net_ipc::MAX_CHUNK_BYTES);
        let req = net_ipc::encode_send_chunk(&server.pending_tx()[..chunk_len]);
        match ipc_call_retry(CapId::BOOTSTRAP_NET_EP, req) {
            Ok(sent) if sent > 0 => {
                let clamped = usize::try_from(sent).unwrap_or(chunk_len).min(chunk_len);
                server.consume_tx(clamped);
            }
            _ => break,
        }
    }
    if pushed_ring_tx {
        let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NET_NOTIF, NET_TX_DOORBELL_BIT);
    }
}

fn poll_ssh_rx(
    net_ssh_ring: Option<&newos_user_rt::SharedRingPair>,
    flags: u64,
    rx_batch: &mut [u8; 256],
) -> RxOutcome {
    let mut rx_len = net_ssh_ring
        .and_then(|ring| ring.a_to_b.try_pop_bytes(rx_batch))
        .unwrap_or(0);
    if rx_len == 0 && (flags & net_ipc::STATUS_RX_AVAIL) != 0 {
        while rx_len + net_ipc::MAX_CHUNK_BYTES <= rx_batch.len() {
            match ipc_call_retry(CapId::BOOTSTRAP_NET_EP, net_ipc::encode_recv_chunk()) {
                Ok(word) => {
                    let tag = (word >> 56) as u8;
                    if tag == net_ipc::REPLY_EOF {
                        return RxOutcome::Eof;
                    }
                    let (bytes, raw_n) = log_ipc::decode_chunk(word);
                    let n = raw_n.min(rx_batch.len().saturating_sub(rx_len));
                    if n == 0 {
                        break;
                    }
                    rx_batch[rx_len..rx_len + n].copy_from_slice(&bytes[..n]);
                    rx_len += n;
                }
                Err(_) => break,
            }
        }
    }
    if rx_len > 0 {
        RxOutcome::Data(rx_len)
    } else {
        RxOutcome::Empty
    }
}

fn forward_shell_input(input: &[u8]) {
    // Forward decrypted shell input chunks to `newos-shell-pd` with bounded retry (`N9`).
    for chunk in input.chunks(log_ipc::MAX_CHUNK_BYTES) {
        let word = log_ipc::encode_chunk(chunk);
        for _ in 0..256 {
            match newos_user_rt::ipc_send(CapId::BOOTSTRAP_SSH_SHELL_EP, word) {
                Err(newos_abi::SysError::WouldBlock) => {
                    let _ = newos_user_rt::sleep_ms(1);
                }
                Ok(()) | Err(_) => break,
            }
        }
    }
}

fn drain_shell_output(server: &mut SshServer) {
    if !server.is_shell_open() {
        return;
    }
    let mut sh_out = [0u8; 256];
    let mut sh_len = 0usize;
    while sh_len + log_ipc::MAX_CHUNK_BYTES <= sh_out.len() {
        match newos_user_rt::ipc_recv(CapId::BOOTSTRAP_SSH_OUT_EP) {
            Ok((_badge, word)) => {
                let (bytes, raw_n) = log_ipc::decode_chunk(word);
                let n = raw_n.min(sh_out.len().saturating_sub(sh_len));
                if n > 0 {
                    sh_out[sh_len..sh_len + n].copy_from_slice(&bytes[..n]);
                    sh_len += n;
                }
            }
            Err(_) => break,
        }
    }
    if sh_len > 0 {
        let _ = server.send_shell_output(&sh_out[..sh_len]);
    }
}

fn wait_for_peer_reset() -> bool {
    matches!(
        newos_user_rt::notify_wait(CapId::BOOTSTRAP_SSH_NOTIF, u64::MAX, 5_000_000),
        Ok((bits, _)) if (bits & newos_abi::RING_PEER_RESET_BIT) != 0
    )
}

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = IpcLogConsole::<256>::new(CapId::BOOTSTRAP_LOG_EP);
    let _ = writeln!(
        out,
        "[ssh-pd] online (mlkem1024-sha3-512 + ssh-mldsa87 + chacha20-poly1305)"
    );
    out.flush();

    let net_ssh_ring = newos_user_rt::map_shared_ring_pair(
        CapId::BOOTSTRAP_VSPACE,
        CapId::BOOTSTRAP_NET_SSH_RING,
        NET_SSH_RING_VADDR,
    )
    .ok();
    let _ssh_key_ring = newos_user_rt::map_shared_ring_pair(
        CapId::BOOTSTRAP_VSPACE,
        CapId::BOOTSTRAP_SSH_KEY_RING,
        SSH_KEY_RING_VADDR,
    )
    .ok();

    let mut vault = IpcKeyVault;
    let mut server = SshServer::new();
    let mut session: Option<ActiveSession> = None;
    let freq_hz = newos_user_rt::timer_freq_hz();
    let cycles_per_ms = (freq_hz / 1_000).max(1);
    let mut shell_in = [0u8; 1024];

    loop {
        let now_ms = newos_user_rt::read_cycles().unwrap_or(0) / cycles_per_ms;
        let Ok(status_word) =
            ipc_call_retry(CapId::BOOTSTRAP_NET_EP, net_ipc::encode_poll_status())
        else {
            if wait_for_peer_reset() {
                reset_session(&mut vault, &mut server, &mut session);
            }
            continue;
        };
        let (flags, _ip) = net_ipc::decode_status_reply(status_word);
        let connected = (flags & net_ipc::STATUS_CONNECTED) != 0;

        if !connected {
            if session.is_some() {
                reset_session(&mut vault, &mut server, &mut session);
            }
            if wait_for_peer_reset() {
                server.reset();
                session = None;
            }
            continue;
        }
        let active = session.get_or_insert(ActiveSession {
            start_ms: now_ms,
            last_activity_ms: now_ms,
        });

        // Enforce unauthenticated login grace timer (30s) and idle session timeout (10m) (`N3`).
        if active.is_timed_out(server.is_shell_open(), now_ms) {
            let _ = writeln!(out, "[ssh-pd] closing session: timeout");
            out.flush();
            let _ = ipc_call_retry(CapId::BOOTSTRAP_NET_EP, net_ipc::encode_abort());
            reset_session(&mut vault, &mut server, &mut session);
            continue;
        }

        // 1. Flush pending SSH wire TX bytes to `newos-net-pd` (prefer shared `SpscRing`, fallback to IPC)
        flush_ssh_tx(&mut server, net_ssh_ring);

        // 2. Pull incoming TCP RX chunks from `newos-net-pd` (shared `SpscRing` first, then IPC fallback)
        let mut rx_batch = [0u8; 256];
        match poll_ssh_rx(net_ssh_ring, flags, &mut rx_batch) {
            RxOutcome::Eof => {
                // On EOF, discard any leftover bytes from the dead connection (`N10`).
                reset_session(&mut vault, &mut server, &mut session);
                continue;
            }
            RxOutcome::Data(rx_len) => {
                active.last_activity_ms = now_ms;
                match server.feed_rx(&rx_batch[..rx_len], &mut vault, &mut shell_in) {
                    Ok(n_shell) if n_shell > 0 && server.is_shell_open() => {
                        forward_shell_input(&shell_in[..n_shell]);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let _ = writeln!(out, "[ssh-pd] closing session: {err:?}");
                        out.flush();
                        let op = match err {
                            SshError::StrictKexViolation
                            | SshError::UnsupportedAlgorithm
                            | SshError::CryptoFailure => net_ipc::encode_abort(),
                            _ => net_ipc::encode_close(),
                        };
                        let _ = ipc_call_retry(CapId::BOOTSTRAP_NET_EP, op);
                        reset_session(&mut vault, &mut server, &mut session);
                        continue;
                    }
                }
            }
            RxOutcome::Empty => {}
        }

        // 3. Drain shell output from `newos-supervisor-pd` when an authenticated shell is open
        drain_shell_output(&mut server);

        if wait_for_peer_reset() {
            reset_session(&mut vault, &mut server, &mut session);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    // Best-effort fail-closed auth-gate close before terminating (`M13`).
    let _ = newos_user_rt::ipc_call(
        CapId::BOOTSTRAP_KEY_EP,
        key_ipc::encode_word_req(key_ipc::OP_CLOSE_SESSION, 0),
    );
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[ssh-pd] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
