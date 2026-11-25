//! Phase 5: Full-Stack Host E2E Tests for `rng` -> `key-vault` -> `ssh-proto` <-> `shell-core`
//! and `storage` CAOS block snapshots.

use ml_dsa::{B32, Keypair, MlDsa87, SigningKey};
use newos_abi::SysError;
use newos_abi::key_ipc::{MLDSA87_PK_BYTES, MLDSA87_SIG_BYTES};
use newos_abi::sha3::sha3_512;
use newos_key_vault::KeyVault;
use newos_rng::{EntropySource, RngError};
use newos_shell_core::shell::{Shell, ShellHost, SysInfo};
use newos_ssh_proto::wire::MAX_PACKET_BODY;
use newos_ssh_proto::{ClientState, KeyVaultClient, SshClient, SshError, SshServer};
use newos_storage::{BlockDevice, SECTOR_SIZE, read_caos_snapshot, write_caos_snapshot};

struct SplitMixHwTrng(u64);
impl EntropySource for SplitMixHwTrng {
    fn fill_entropy(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        for b in dst.iter_mut() {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)) as u8;
        }
        Ok(())
    }
}

/// Bridges `newos-ssh-proto::KeyVaultClient` directly to the real `newos-key-vault::KeyVault`.
struct RealKeyVaultAdapter<E: EntropySource> {
    vault: KeyVault<E>,
    clock_ms: i64,
}

impl<E: EntropySource> KeyVaultClient for RealKeyVaultAdapter<E> {
    fn host_public_key(&mut self) -> Result<[u8; MLDSA87_PK_BYTES], SshError> {
        Ok(*self.vault.host_public_key())
    }

    fn random_32(&mut self) -> Result<[u8; 32], SshError> {
        let mut out = [0u8; 32];
        for chunk in out.as_chunks_mut::<8>().0 {
            let v = self
                .vault
                .get_random_u64()
                .map_err(|_| SshError::VaultError)?;
            *chunk = v.to_le_bytes();
        }
        Ok(out)
    }

    fn sign_kex_hash(&mut self, hash64: &[u8; 64]) -> Result<[u8; MLDSA87_SIG_BYTES], SshError> {
        self.clock_ms += 1_000;
        self.vault
            .sign_kex_hash(hash64, self.clock_ms)
            .map_err(|_| SshError::VaultError)
    }

    fn verify_user_auth(
        &mut self,
        client_pk: &[u8; MLDSA87_PK_BYTES],
        signed_data: &[u8],
        sig: &[u8; MLDSA87_SIG_BYTES],
    ) -> Result<bool, SshError> {
        match self.vault.verify_user_auth(client_pk, signed_data, sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn close_session(&mut self) {
        self.vault.close_session();
    }
}

struct CaptureShellHost {
    output: String,
}

impl ShellHost for CaptureShellHost {
    fn write_debug(&mut self, s: &str) {
        self.output.push_str(s);
    }

    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            domain_count: 6,
            online_cpus: 4,
            interactive_shell: true,
        }
    }

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        Err(SysError::WouldBlock)
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        Ok(0)
    }
}

struct RamBlockDev {
    sectors: [[u8; SECTOR_SIZE]; 16],
}

impl RamBlockDev {
    fn new() -> Self {
        Self {
            sectors: [[0u8; SECTOR_SIZE]; 16],
        }
    }
}

impl BlockDevice for RamBlockDev {
    fn block_count(&self) -> u64 {
        self.sectors.len() as u64
    }

    fn read_block(&mut self, lba: u64, dst: &mut [u8; SECTOR_SIZE]) -> Result<(), SysError> {
        let idx = usize::try_from(lba).map_err(|_| SysError::InvalidArgument)?;
        if idx >= self.sectors.len() {
            return Err(SysError::InvalidArgument);
        }
        *dst = self.sectors[idx];
        Ok(())
    }

    fn write_block(&mut self, lba: u64, src: &[u8; SECTOR_SIZE]) -> Result<(), SysError> {
        let idx = usize::try_from(lba).map_err(|_| SysError::InvalidArgument)?;
        if idx >= self.sectors.len() {
            return Err(SysError::InvalidArgument);
        }
        self.sectors[idx] = *src;
        Ok(())
    }
}

#[test]
fn e2e_full_pq_ssh_with_real_key_vault_and_shell_execution() {
    std::thread::Builder::new()
        .name("e2e-pq-ssh".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(run_e2e_full_pq_ssh)
        .expect("spawn e2e thread")
        .join()
        .expect("e2e thread panicked");
}

fn run_e2e_full_pq_ssh() {
    // 1. Generate client ML-DSA-87 identity
    let mut user_seed = B32::default();
    user_seed.as_mut_slice().fill(0x5A);
    let user_sk = SigningKey::<MlDsa87>::from_seed(&user_seed);
    let mut user_pk = [0u8; MLDSA87_PK_BYTES];
    user_pk.copy_from_slice(user_sk.verifying_key().encode().as_slice());
    let authorized: &'static [[u8; MLDSA87_PK_BYTES]] = Box::leak(Box::new([user_pk]));

    // 2. Initialize real KeyVault backed by NIST SP 800-90B conditioned CSPRNG
    let vault = KeyVault::new(SplitMixHwTrng(0xDEAD_BEEF_1234), b"e2e-ssh-net", authorized)
        .expect("KeyVault init");
    let expected_fp = sha3_512(vault.host_public_key());
    let mut adapter = RealKeyVaultAdapter { vault, clock_ms: 0 };

    // 3. Complete full ML-KEM-1024 + ML-DSA-87 + ChaCha20-Poly1305 handshake
    let mut server = Box::new(SshServer::new());
    let mut client = Box::new(SshClient::new(
        "newos",
        user_sk,
        Some(expected_fp),
        [0x33u8; 64],
    ));
    let mut s_shell_in = [0u8; 512];
    let mut c_shell_out = [0u8; 512];

    for _ in 0..16 {
        if !server.pending_tx().is_empty() {
            let take = server.pending_tx().len().min(MAX_PACKET_BODY + 64);
            let tmp = server.pending_tx()[..take].to_vec();
            server.consume_tx(take);
            let _ = client
                .feed_rx(&tmp, [0x11; 16], [0x22; 32], &mut c_shell_out)
                .expect("client handshake");
        }
        if !client.pending_tx().is_empty() {
            let take = client.pending_tx().len().min(MAX_PACKET_BODY + 64);
            let tmp = client.pending_tx()[..take].to_vec();
            client.consume_tx(take);
            let _ = server
                .feed_rx(&tmp, &mut adapter, &mut s_shell_in)
                .expect("server handshake");
        }
        if server.is_shell_open() && client.state() == ClientState::ShellOpen {
            break;
        }
    }
    assert!(server.is_shell_open());
    assert_eq!(client.state(), ClientState::ShellOpen);

    // 4. Send a real shell command over encrypted SSH, execute it in `Shell`, return encrypted output
    let mut shell = Box::new(Shell::new(CaptureShellHost {
        output: String::new(),
    }));
    client
        .send_shell_input(b"put config hello-pq-ssh\n")
        .unwrap();
    let c_wire = client.pending_tx().to_vec();
    client.consume_tx(c_wire.len());
    let in_len = server
        .feed_rx(&c_wire, &mut adapter, &mut s_shell_in)
        .expect("decrypt shell cmd");
    let cmd = core::str::from_utf8(&s_shell_in[..in_len]).unwrap().trim();
    shell.exec_line(cmd);

    let reply = shell.host_mut().output.clone();
    assert!(!reply.is_empty());
    server.send_shell_output(reply.as_bytes()).unwrap();
    let s_wire = server.pending_tx().to_vec();
    server.consume_tx(s_wire.len());
    let out_len = client
        .feed_rx(&s_wire, [0; 16], [0; 32], &mut c_shell_out)
        .expect("decrypt shell output");
    assert_eq!(&c_shell_out[..out_len], reply.as_bytes());
}

#[test]
fn e2e_storage_caos_snapshot_roundtrip_and_corruption_detection() {
    let mut dev = RamBlockDev::new();
    let payload = b"newos-caos-snapshot-v1:verified-state";
    write_caos_snapshot(&mut dev, 0, payload).expect("save snapshot");

    let mut restored = [0u8; 128];
    let n = read_caos_snapshot(&mut dev, 0, &mut restored).expect("load snapshot");
    assert_eq!(&restored[..n], payload);

    // Corrupt 1 byte on block device -> SHA3 integrity check MUST fail closed
    let mut sector = [0u8; SECTOR_SIZE];
    dev.read_block(0, &mut sector).unwrap();
    sector[24] ^= 0x80;
    dev.write_block(0, &sector).unwrap();
    assert!(read_caos_snapshot(&mut dev, 0, &mut restored).is_err());
}
