#![no_std]
#![no_main]

//! Isolated EL0 Entropy & ML-DSA-87 Signing Vault (`newos-key-pd`, PD 3).
//!
//! Strict least-privilege capability set:
//! - `CapId::BOOTSTRAP_RNG_MMIO` (`R|W`) — BCM2712 RNG200 (Pi 5) or VirtIO-RNG (QEMU)
//! - `CapId::BOOTSTRAP_VSPACE` (`R` only, QEMU only — omitted on Pi 5)
//! - `CapId::BOOTSTRAP_KEY_EP` (`R|W`, server) — narrow RPCs exclusively from `newos-ssh-pd` (badge 4)
//! - `CapId::BOOTSTRAP_AUTH_GATE_EP` (`W`, badge 3) — signals `SESSION_OPEN`/`SESSION_CLOSE` to `supervisor-pd`
//! - `CapId::BOOTSTRAP_LOG_EP` (`W`, badge 3) — write-only diagnostic log
//!
//! Explicitly holds ZERO access to `NET_MMIO`, `NET_EP`, `SSH_SHELL_EP`, `CONSOLE`, `POWER`,
//! `UNTYPED`, `THREAD`, or `CNODE`. Fails closed via `thread_exit()` if HW TRNG health fails.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, SysError};
use newos_key_vault::{KeyVault, KeyVaultServer, encode_base64_64};
use newos_rng::{
    Bcm2712Rng200, EntropySource, RngKind, RngTransport, VirtioRngDevice, VirtioRngDma,
};
use newos_user_rt::IpcLogConsole;

include!(concat!(env!("OUT_DIR"), "/authorized_keys.rs"));

/// Static EL0 DMA buffer for QEMU `VirtioRngDevice` (`Sync` via atomics, zero `unsafe`).
static VIRTIO_RNG_DMA: VirtioRngDma = VirtioRngDma::new();

struct CapRngTransport;

impl RngTransport for CapRngTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError> {
        newos_user_rt::mmio_read32(CapId::BOOTSTRAP_RNG_MMIO, offset)
    }

    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
        newos_user_rt::mmio_write32(CapId::BOOTSTRAP_RNG_MMIO, offset, val)
    }

    fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
        newos_user_rt::virt_to_phys(r)
    }
}

fn serve_vault<E: EntropySource>(
    source: E,
    driver_name: &str,
    cycles_per_ms: u64,
    start_cycles: u64,
    out: &mut IpcLogConsole<256>,
) -> ! {
    let personalization = start_cycles.to_le_bytes();
    let vault = match KeyVault::new_with_optional_host_seed(
        source,
        &personalization,
        AUTHORIZED_KEYS,
        HOST_KEY_SEED,
    ) {
        Ok(v) => v,
        Err(err) => {
            let _ = writeln!(
                out,
                "[key-pd] FAIL-CLOSED: HW RNG/health check failed ({driver_name}, {err:?}); exiting"
            );
            out.flush();
            newos_user_rt::thread_exit();
        }
    };

    let fp_digest = vault.host_fingerprint_sha3_512();
    let fp_b64 = encode_base64_64(&fp_digest);
    let fp_str = core::str::from_utf8(&fp_b64).unwrap_or("?");
    let _ = writeln!(
        out,
        "[key-pd] online ({driver_name}, hostkey=ssh-mldsa87, authorized_keys={}, SHA3-512:{fp_str})",
        AUTHORIZED_KEYS.len(),
    );
    out.flush();

    const SSH_KEY_RING_VADDR: u64 = 0x0000_6000_0001_0000;
    let _ssh_key_ring = newos_user_rt::map_shared_ring_pair(
        CapId::BOOTSTRAP_VSPACE,
        CapId::BOOTSTRAP_SSH_KEY_RING,
        SSH_KEY_RING_VADDR,
    )
    .ok();

    let mut server = KeyVaultServer::new(vault);
    let mut has_reply = false;
    let mut reply_payload = 0u64;

    loop {
        match newos_user_rt::ipc_reply_recv(CapId::BOOTSTRAP_KEY_EP, reply_payload, has_reply) {
            Ok((badge, req)) => {
                let now_cycles = newos_user_rt::read_cycles().unwrap_or(start_cycles);
                let now_ms = (now_cycles.saturating_sub(start_cycles) / cycles_per_ms) as i64;
                let (mut reply, gate_signal) = server.handle_ipc_word(badge, req, now_ms);
                if let Some(sig) = gate_signal {
                    // Fail-closed auth-gate delivery (`N7`): if `supervisor-pd` cannot be notified,
                    // refuse to report `REPLY_OK` to `ssh-pd` so auth state never diverges.
                    let mut delivered = false;
                    for _ in 0..256 {
                        match newos_user_rt::ipc_send(CapId::BOOTSTRAP_AUTH_GATE_EP, sig) {
                            Ok(()) => {
                                delivered = true;
                                break;
                            }
                            Err(SysError::WouldBlock) => {
                                let _ = newos_user_rt::sleep_ms(1);
                            }
                            Err(_) => break,
                        }
                    }
                    if !delivered && reply == newos_abi::key_ipc::REPLY_OK {
                        reply = newos_abi::key_ipc::REPLY_DENIED;
                    }
                }
                reply_payload = reply;
                has_reply = true;
            }
            Err(SysError::WouldBlock) => {
                has_reply = false;
                if let Ok((bits, _)) =
                    newos_user_rt::notify_wait(CapId::BOOTSTRAP_KEY_NOTIF, u64::MAX, 5_000_000)
                    && (bits & newos_abi::RING_PEER_RESET_BIT) != 0
                {
                    // Fail-closed: `ssh-pd` exited or faulted; immediately close the auth gate (`M13`).
                    let _ = server.handle_ipc_word(
                        newos_abi::key_ipc::BADGE_SSH,
                        newos_abi::key_ipc::encode_word_req(
                            newos_abi::key_ipc::OP_CLOSE_SESSION,
                            0,
                        ),
                        0,
                    );
                    for _ in 0..256 {
                        match newos_user_rt::ipc_send(
                            CapId::BOOTSTRAP_AUTH_GATE_EP,
                            newos_abi::auth_gate_ipc::SESSION_CLOSE,
                        ) {
                            Ok(()) => break,
                            Err(SysError::WouldBlock) => {
                                let _ = newos_user_rt::sleep_ms(1);
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = writeln!(
                        out,
                        "[key-pd] peer reset signal received; closed auth gate & cleared state"
                    );
                    out.flush();
                }
            }
            Err(err) => {
                let _ = writeln!(
                    out,
                    "[key-pd] fatal IPC error (code={}); exiting",
                    err as u64
                );
                out.flush();
                newos_user_rt::thread_exit();
            }
        }
    }
}

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = IpcLogConsole::<256>::new(CapId::BOOTSTRAP_LOG_EP);
    let freq_hz = newos_user_rt::timer_freq_hz();
    let cycles_per_ms = (freq_hz / 1_000).max(1);
    let start_cycles = newos_user_rt::read_cycles().unwrap_or(0);

    let kind = match newos_rng::probe_rng(|off| {
        newos_user_rt::mmio_read32(CapId::BOOTSTRAP_RNG_MMIO, off)
    }) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(
                out,
                "[key-pd] FAIL-CLOSED: no HW RNG via BOOTSTRAP_RNG_MMIO ({e:?}); exiting"
            );
            out.flush();
            newos_user_rt::thread_exit();
        }
    };

    match kind {
        RngKind::VirtioRng { .. } => {
            match VirtioRngDevice::init(CapRngTransport, &VIRTIO_RNG_DMA) {
                Ok(dev) => serve_vault(
                    dev,
                    kind.driver_name(),
                    cycles_per_ms,
                    start_cycles,
                    &mut out,
                ),
                Err(e) => {
                    let _ = writeln!(out, "[key-pd] FAIL-CLOSED: virtio-rng init failed ({e:?})");
                    out.flush();
                    newos_user_rt::thread_exit();
                }
            }
        }
        RngKind::Bcm2712Rng200 => match Bcm2712Rng200::init(CapRngTransport) {
            Ok(dev) => serve_vault(
                dev,
                kind.driver_name(),
                cycles_per_ms,
                start_cycles,
                &mut out,
            ),
            Err(e) => {
                let _ = writeln!(
                    out,
                    "[key-pd] FAIL-CLOSED: bcm2712-rng200 init failed ({e:?})"
                );
                out.flush();
                newos_user_rt::thread_exit();
            }
        },
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[key-pd] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
