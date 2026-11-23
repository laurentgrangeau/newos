#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Isolated EL0 Pure-PQ SSHv2 Protocol Engine (`newos-sshd`, PID 4).
//!
//! Strict least-privilege capability set:
//! - `CapId::BOOTSTRAP_NET_EP` (`R|W`, badge 4) — opaque TCP byte stream from `newos-netd`
//! - `CapId::BOOTSTRAP_KEY_EP` (`R|W`, badge 4) — narrow RPCs to `newos-keyd`
//! - `CapId::BOOTSTRAP_SSH_SHELL_EP` (`R|W`, badge 4) — auth-gated shell bytes to `newos-init`
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
                let _ = newos_user_rt::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Err(SysError::WouldBlock)
}

/// RPC client talking exclusively to `newos-keyd` (PID 3) over `CapId::BOOTSTRAP_KEY_EP`.
struct IpcKeyVault;

impl KeyVaultClient for IpcKeyVault {
    fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError> {
        let mut pk = [0u8; MLDSA87_PK_BYTES];
        let words = MLDSA87_PK_BYTES.div_ceil(8);
        for i in 0..words {
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_GET_HOST_PK_WORD, i as u32),
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
        let mut out = [0u8; 32];
        for i in 0..4 {
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_GET_RANDOM_U64, 0),
            )
            .map_err(|_| SshError::VaultError)?;
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
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
            let w = ipc_call_retry(
                CapId::BOOTSTRAP_KEY_EP,
                key_ipc::encode_word_req(key_ipc::OP_SIGN_KEX_READ_WORD, i as u32),
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

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = IpcLogConsole::<256>::new(CapId::BOOTSTRAP_LOG_EP);
    let _ = writeln!(
        out,
        "[sshd] online (pure-PQ: mlkem1024-sha3-512 + ssh-mldsa87 + chacha20-poly1305, ZERO MMIO)"
    );
    out.flush();

    let mut vault = IpcKeyVault;
    let mut server = SshServer::new();
    let mut active_conn = false;
    let mut shell_in = [0u8; 256];

    loop {
        let Ok(status_word) =
            ipc_call_retry(CapId::BOOTSTRAP_NET_EP, net_ipc::encode_poll_status())
        else {
            let _ = newos_user_rt::yield_now();
            continue;
        };
        let (flags, _ip) = net_ipc::decode_status_reply(status_word);
        let connected = (flags & net_ipc::STATUS_CONNECTED) != 0;

        if !connected {
            if active_conn {
                vault.close_session();
                server.reset();
                active_conn = false;
            }
            let _ = newos_user_rt::yield_now();
            continue;
        }
        active_conn = true;

        // 1. Flush pending SSH wire TX bytes to `newos-netd`
        while !server.pending_tx().is_empty() {
            let chunk_len = server.pending_tx().len().min(net_ipc::MAX_CHUNK_BYTES);
            let req = net_ipc::encode_send_chunk(&server.pending_tx()[..chunk_len]);
            match ipc_call_retry(CapId::BOOTSTRAP_NET_EP, req) {
                Ok(sent) if sent > 0 => server.consume_tx(sent as usize),
                _ => break,
            }
        }

        // 2. Pull incoming TCP RX chunks from `newos-netd` and drive `SshServer`
        if (flags & net_ipc::STATUS_RX_AVAIL) != 0 {
            let mut rx_batch = [0u8; 256];
            let mut rx_len = 0usize;
            while rx_len + net_ipc::MAX_CHUNK_BYTES <= rx_batch.len() {
                match ipc_call_retry(CapId::BOOTSTRAP_NET_EP, net_ipc::encode_recv_chunk()) {
                    Ok(word) => {
                        let tag = (word >> 56) as u8;
                        if tag == net_ipc::REPLY_EOF {
                            vault.close_session();
                            server.reset();
                            active_conn = false;
                            break;
                        }
                        let (bytes, n) = log_ipc::decode_chunk(word);
                        if n == 0 {
                            break;
                        }
                        rx_batch[rx_len..rx_len + n].copy_from_slice(&bytes[..n]);
                        rx_len += n;
                    }
                    Err(_) => break,
                }
            }

            if rx_len > 0 {
                match server.feed_rx(&rx_batch[..rx_len], &mut vault, &mut shell_in) {
                    Ok(n_shell) if n_shell > 0 && server.is_shell_open() => {
                        // Forward decrypted shell input chunks to `newos-init` (gated by `keyd`)
                        for chunk in shell_in[..n_shell].chunks(log_ipc::MAX_CHUNK_BYTES) {
                            let word = log_ipc::encode_chunk(chunk);
                            let _ = newos_user_rt::ipc_send(CapId::BOOTSTRAP_SSH_SHELL_EP, word);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let _ = writeln!(out, "[sshd] closing session: {err:?}");
                        out.flush();
                        vault.close_session();
                        let op = match err {
                            SshError::StrictKexViolation
                            | SshError::UnsupportedAlgorithm
                            | SshError::CryptoFailure => net_ipc::encode_abort(),
                            _ => net_ipc::encode_close(),
                        };
                        let _ = ipc_call_retry(CapId::BOOTSTRAP_NET_EP, op);
                        server.reset();
                        active_conn = false;
                        continue;
                    }
                }
            }
        }

        // 3. Drain shell output from `newos-init` when an authenticated shell is open
        if server.is_shell_open() {
            let mut sh_out = [0u8; 256];
            let mut sh_len = 0usize;
            while sh_len + log_ipc::MAX_CHUNK_BYTES <= sh_out.len() {
                match newos_user_rt::ipc_recv(CapId::BOOTSTRAP_SSH_OUT_EP) {
                    Ok((_badge, word)) => {
                        let (bytes, n) = log_ipc::decode_chunk(word);
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

        let _ = newos_user_rt::yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[sshd] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
