#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! EL0 Root Task (`init`), Crash Supervisor, Content-Addressed Object Store (CAOS),
//! and Post-UNIX Typed Pipeline Shell (`newos-sh`).
//!
//! 100% memory-safe Rust (`#![forbid(unsafe_code)]`, `no_alloc`).

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ShutdownStatus, SysError};
use newos_net::{GemDma, MmioDmaTransport, NetConfig, NicKind, VirtioNetDma};
use newos_shell_core::shell::{NullWriter, Record, RecordStream, Shell, ShellHost, SysInfo};
use newos_user_rt::{BufferedConsole, IpcLogAssembler};

/// Static EL0 DMA rings & packet buffers (`Sync` via atomics, 100% `#![forbid(unsafe_code)]`).
pub static VIRTIO_DMA: VirtioNetDma = VirtioNetDma::new();
/// Static EL0 64-bit DMA rings & packet buffers for Raspberry Pi 5 RP1 Cadence GEM.
pub static GEM_DMA: GemDma = GemDma::new();

/// Capability-scoped MMIO + `VirtToPhys` transport for EL0 NIC drivers.
pub struct CapMmioDmaTransport;

impl MmioDmaTransport for CapMmioDmaTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError> {
        newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, offset)
    }

    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
        newos_user_rt::mmio_write32(CapId::BOOTSTRAP_NET_MMIO, offset, val)
    }

    fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
        newos_user_rt::virt_to_phys(r)
    }

    fn dma_clean<T>(&self, r: &T) -> Result<(), SysError> {
        newos_user_rt::dma_clean(r).map(|_| ())
    }

    fn dma_invalidate<T>(&self, r: &T) -> Result<(), SysError> {
        newos_user_rt::dma_invalidate(r).map(|_| ())
    }
}

/// EL0 `ShellHost` adapter connecting `newos-shell-core` to `newos-user-rt`, `newos-net`,
/// and the `newos-keyd`-gated `newos-sshd` interactive shell channel.
struct InitShellHost {
    net_cfg: Option<NetConfig>,
    cached_nic: Option<Option<NicKind>>,
    log_rx: IpcLogAssembler<256>,
    ssh_session_authorized: bool,
    ssh_rx_buf: [u8; 64],
    ssh_rx_pos: usize,
    ssh_rx_len: usize,
}

impl InitShellHost {
    const fn new() -> Self {
        Self::with_log_rx(IpcLogAssembler::new())
    }

    const fn with_log_rx(log_rx: IpcLogAssembler<256>) -> Self {
        Self {
            net_cfg: None,
            cached_nic: None,
            log_rx,
            ssh_session_authorized: false,
            ssh_rx_buf: [0u8; 64],
            ssh_rx_pos: 0,
            ssh_rx_len: 0,
        }
    }

    /// Poll `CapId::BOOTSTRAP_AUTH_GATE_EP` (`newos-keyd` PID 3 write-only -> `init` read-only)
    /// to open/close the SSH shell channel strictly on `keyd`'s ML-DSA-87 verification.
    fn poll_ssh_auth_gate(&mut self) {
        while let Ok((badge, word)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_AUTH_GATE_EP) {
            if badge != newos_abi::auth_gate_ipc::BADGE_KEYD {
                continue;
            }
            match word {
                newos_abi::auth_gate_ipc::SESSION_OPEN => {
                    self.ssh_session_authorized = true;
                }
                newos_abi::auth_gate_ipc::SESSION_CLOSE => {
                    self.ssh_session_authorized = false;
                    self.ssh_rx_pos = 0;
                    self.ssh_rx_len = 0;
                }
                _ => {}
            }
        }
    }

    fn probe_nic_cached(&mut self) -> Option<NicKind> {
        if let Some(cached) = self.cached_nic {
            return cached;
        }
        let nic =
            newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
        self.cached_nic = Some(nic);
        nic
    }

    fn handle_net_with<W: Write>(
        &mut self,
        subcmd: &str,
        arg: Option<&str>,
        stream: &mut RecordStream,
        out: &mut W,
    ) {
        let nic = self.probe_nic_cached();
        let mac = nic
            .map(|n| n.mac())
            .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        if let Some(n) = nic {
            match subcmd {
                "dhcp" => {
                    match newos_net::live_dhcp_v4(CapMmioDmaTransport, n, &VIRTIO_DMA, &GEM_DMA) {
                        Ok(cfg) => {
                            self.net_cfg = Some(cfg);
                            let gw = cfg.gateway.unwrap_or([0; 4]);
                            let dns = cfg.dns.unwrap_or([0; 4]);
                            let _ = writeln!(
                                out,
                                "net dhcp ({}): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
                                n.driver_name(),
                                cfg.ip[0],
                                cfg.ip[1],
                                cfg.ip[2],
                                cfg.ip[3],
                                cfg.prefix_len,
                                gw[0],
                                gw[1],
                                gw[2],
                                gw[3],
                                dns[0],
                                dns[1],
                                dns[2],
                                dns[3],
                            );
                            stream.push(Record::Metric {
                                label: "dhcp.prefix",
                                value: u64::from(cfg.prefix_len),
                                unit: "bits (IPv4 leased)",
                            });
                        }
                        Err(e) => {
                            let _ = writeln!(out, "net dhcp: {e}");
                        }
                    }
                }
                "ping" => {
                    let cfg = self.net_cfg.unwrap_or(NetConfig::QEMU_DEFAULT);
                    let target = match arg {
                        None => cfg.gateway.unwrap_or([10, 0, 2, 2]),
                        Some(raw) => {
                            if let Some(ip) = newos_net::parse_ipv4(raw) {
                                ip
                            } else if raw.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                                let _ = writeln!(out, "net ping: invalid IPv4 address '{raw}'");
                                return;
                            } else {
                                let cycles_per_ms = (newos_user_rt::timer_freq_hz() / 1_000).max(1);
                                let mut clock = newos_net::CycleClock::new(
                                    || newos_user_rt::read_cycles().unwrap_or(0),
                                    cycles_per_ms,
                                );
                                match newos_net::live_dns_resolve_with_clock(
                                    CapMmioDmaTransport,
                                    &mut clock,
                                    n,
                                    &cfg,
                                    raw,
                                    5_000,
                                    &VIRTIO_DMA,
                                    &GEM_DMA,
                                ) {
                                    Ok(ip) => ip,
                                    Err(e) => {
                                        let _ = writeln!(
                                            out,
                                            "net ping: could not resolve '{raw}' ({e})"
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                    };
                    match newos_net::live_icmp_ping(
                        CapMmioDmaTransport,
                        n,
                        &cfg,
                        target,
                        &VIRTIO_DMA,
                        &GEM_DMA,
                    ) {
                        Ok(res) => {
                            let _ = writeln!(
                                out,
                                "ICMP EchoReply from {}.{}.{}.{} (seq={}, driver={})",
                                res.target[0],
                                res.target[1],
                                res.target[2],
                                res.target[3],
                                res.seq,
                                n.driver_name(),
                            );
                            stream.push(Record::Metric {
                                label: "icmp.reply.seq",
                                value: u64::from(res.seq),
                                unit: "(ok)",
                            });
                        }
                        Err(e) => {
                            let _ = writeln!(out, "net ping: {e}");
                        }
                    }
                }
                "resolve" => {
                    let Some(host) = arg else {
                        let _ = writeln!(out, "usage: net resolve <hostname>");
                        return;
                    };
                    let cfg = self.net_cfg.unwrap_or(NetConfig::QEMU_DEFAULT);
                    let cycles_per_ms = (newos_user_rt::timer_freq_hz() / 1_000).max(1);
                    let mut clock = newos_net::CycleClock::new(
                        || newos_user_rt::read_cycles().unwrap_or(0),
                        cycles_per_ms,
                    );
                    match newos_net::live_dns_resolve_with_clock(
                        CapMmioDmaTransport,
                        &mut clock,
                        n,
                        &cfg,
                        host,
                        5_000,
                        &VIRTIO_DMA,
                        &GEM_DMA,
                    ) {
                        Ok(ip) => {
                            let _ =
                                writeln!(out, "{host} -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            stream.push(Record::Metric {
                                label: "dns.resolved",
                                value: u64::from(u32::from_be_bytes(ip)),
                                unit: "(ipv4 u32)",
                            });
                        }
                        Err(e) => {
                            let _ = writeln!(out, "net resolve: {e}");
                        }
                    }
                }
                _ => {
                    let _ = writeln!(
                        out,
                        "nic: driver={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        n.driver_name(),
                        mac[0],
                        mac[1],
                        mac[2],
                        mac[3],
                        mac[4],
                        mac[5],
                    );
                    if let Some(cfg) = self.net_cfg {
                        let gw = cfg.gateway.unwrap_or([0; 4]);
                        let dns = cfg.dns.unwrap_or([0; 4]);
                        let _ = writeln!(
                            out,
                            "ipv4: {}.{}.{}.{}/{} gw={}.{}.{}.{} dns={}.{}.{}.{}",
                            cfg.ip[0],
                            cfg.ip[1],
                            cfg.ip[2],
                            cfg.ip[3],
                            cfg.prefix_len,
                            gw[0],
                            gw[1],
                            gw[2],
                            gw[3],
                            dns[0],
                            dns[1],
                            dns[2],
                            dns[3],
                        );
                    }
                    match n {
                        newos_net::NicKind::Virtio(v) => {
                            stream.push(Record::Metric {
                                label: "virtio.net.slot",
                                value: u64::from(v.slot),
                                unit: "(mmio cap)",
                            });
                            stream.push(Record::Metric {
                                label: "virtio.net.ver",
                                value: u64::from(v.version),
                                unit: "(virtio)",
                            });
                        }
                        newos_net::NicKind::CadenceGem(g) => {
                            stream.push(Record::Metric {
                                label: "rp1.gem.mid",
                                value: u64::from(g.module_id),
                                unit: "(rpi5 cadence gem)",
                            });
                        }
                    }
                }
            }
        } else if let Ok(frame_len) = newos_net::verify_smoltcp_el0_stack(mac) {
            stream.push(Record::Metric {
                label: "smoltcp.tx.frame",
                value: frame_len as u64,
                unit: "bytes (EL0 IPv4)",
            });
        }
    }
}

impl ShellHost for InitShellHost {
    fn write_debug(&mut self, s: &str) {
        let _ = newos_user_rt::debug_write_all(s);
        if self.ssh_session_authorized {
            for chunk in s.as_bytes().chunks(newos_abi::log_ipc::MAX_CHUNK_BYTES) {
                let word = newos_abi::log_ipc::encode_chunk(chunk);
                for _ in 0..128 {
                    match newos_user_rt::ipc_send(CapId::BOOTSTRAP_SSH_OUT_EP, word) {
                        Ok(()) => break,
                        Err(SysError::WouldBlock) => {
                            let _ = newos_user_rt::yield_now();
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    fn sys_info(&mut self) -> SysInfo {
        let info = newos_user_rt::sys_info();
        SysInfo {
            online_cpus: info.online_cpus,
            proc_count: info.proc_count,
            interactive_shell: info.interactive_shell,
        }
    }

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        self.poll_ssh_auth_gate();
        if self.ssh_session_authorized {
            if self.ssh_rx_pos < self.ssh_rx_len {
                let b = self.ssh_rx_buf[self.ssh_rx_pos];
                self.ssh_rx_pos += 1;
                if self.ssh_rx_pos == self.ssh_rx_len {
                    self.ssh_rx_pos = 0;
                    self.ssh_rx_len = 0;
                }
                return Ok(b);
            }
            if let Ok((badge, word)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_SSH_SHELL_EP)
                && badge == newos_abi::key_ipc::BADGE_SSHD
            {
                let (bytes, n) = newos_abi::log_ipc::decode_chunk(word);
                if n > 0 {
                    self.ssh_rx_buf[..n].copy_from_slice(&bytes[..n]);
                    self.ssh_rx_len = n;
                    self.ssh_rx_pos = 1;
                    return Ok(self.ssh_rx_buf[0]);
                }
            }
        } else {
            // Drain and discard any unsolicited SSH shell bytes while auth-gate is closed.
            let _ = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_SSH_SHELL_EP);
        }
        newos_user_rt::debug_read_byte()
    }

    fn ipc_send(&mut self, cap: CapId, payload: u64) -> Result<(), SysError> {
        newos_user_rt::ipc_send(cap, payload)
    }

    fn ipc_recv(&mut self, cap: CapId) -> Result<(u64, u64), SysError> {
        newos_user_rt::ipc_recv(cap)
    }

    fn ipc_call(&mut self, cap: CapId, payload: u64) -> Result<(u64, u64), SysError> {
        newos_user_rt::ipc_call(cap, payload)
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        newos_user_rt::yield_now()
    }

    fn read_cycles(&mut self) -> Result<u64, SysError> {
        newos_user_rt::read_cycles()
    }

    fn trigger_user_fault(&mut self) {
        newos_user_rt::trigger_user_fault()
    }

    fn exit(&mut self, code: ShutdownStatus) -> ! {
        newos_user_rt::exit(code)
    }

    fn handle_net(
        &mut self,
        subcmd: &str,
        arg: Option<&str>,
        stream: &mut RecordStream,
        silent: bool,
    ) {
        if silent {
            let mut sink = NullWriter;
            self.handle_net_with(subcmd, arg, stream, &mut sink);
        } else {
            let mut out = BufferedConsole::<1024>::new();
            self.handle_net_with(subcmd, arg, stream, &mut out);
            out.flush();
        }
    }

    fn poll_background_log(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        self.log_rx.poll_line(CapId::BOOTSTRAP_LOG_EP, out)
    }
}

newos_user_rt::entry!(main);

/// EL0 supervisor fault-recovery entry point.
///
/// Re-entrancy invariant: `init` is single-threaded. On any EL0 hardware fault (including a
/// subsequent fault inside a recovered interactive shell), the kernel discards the faulted
/// context and resets `SP_EL0` to the 16-byte-aligned top of the 64 KiB
/// `SUPERVISOR_RECOVERY_STACK` before entering `supervisor_recover`. No stack growth occurs
/// across repeated faults, and `SUPERVISOR_RECOVERY_STACK` is never aliased by Rust references.
extern "C" fn supervisor_recover() -> ! {
    let mut out = BufferedConsole::<1024>::new();
    let info = newos_user_rt::sys_info();

    match newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF) {
        Ok(bits) if bits != 0 => {
            if info.interactive_shell {
                let _ = writeln!(
                    out,
                    "[init-supervisor] recovered from EL0 fault (bits={:#x}) — restarting `newos-sh`!",
                    bits
                );
                out.flush();
                let _ = newos_user_rt::set_fault_handler(supervisor_recover);
                let mut sh = Shell::new(InitShellHost::new());
                sh.run_interactive()
            } else if bits == (1 << 6) {
                let _ = writeln!(
                    out,
                    "[init] phase-6 EL0 crash isolation & supervisor recovery: OK (fault_bits={:#x})",
                    bits
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Success)
            } else {
                let _ = writeln!(out, "[init] FAIL: unexpected fault bits {bits:#x}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed)
            }
        }
        other => {
            let _ = writeln!(
                out,
                "[init] FAIL: unexpected fault notification bits: {other:?}"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed)
        }
    }
}

/// Drain `worker`'s startup log line over `CapId::BOOTSTRAP_LOG_EP` as the sole console owner.
///
/// Bounded by `MAX_BOOT_LOG_YIELDS` so `init` cannot hang forever if `worker` fails to start
/// or `BOOTSTRAP_LOG_EP` is revoked.
fn drain_worker_boot_log<const N: usize>(
    log_rx: &mut IpcLogAssembler<256>,
    out: &mut BufferedConsole<N>,
) {
    const MAX_BOOT_LOG_YIELDS: usize = 10_000;
    let mut line_buf = [0u8; 256];
    for _ in 0..MAX_BOOT_LOG_YIELDS {
        if let Some((badge, n)) = log_rx.poll_line(CapId::BOOTSTRAP_LOG_EP, &mut line_buf) {
            if let Ok(line) = core::str::from_utf8(&line_buf[..n]) {
                // Stamp with kernel-verified sender badge so no daemon can forge another's prefix (`N17`).
                let _ = writeln!(out, "[pid={badge}] {line}");
                out.flush();
            }
            return;
        }
        if newos_user_rt::yield_now().is_err() {
            return;
        }
    }
}

fn main() -> ! {
    let mut out = BufferedConsole::<1024>::new();
    let mut log_rx = IpcLogAssembler::<256>::new();
    let info = newos_user_rt::sys_info();
    let _ = newos_user_rt::set_fault_handler(supervisor_recover);

    if info.interactive_shell {
        if info.proc_count > 1 {
            drain_worker_boot_log(&mut log_rx, &mut out);
            // Deterministic readiness handshake so `worker` is in its IPC loop before prompt.
            let _ = newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, 0x5245_4144);
        }
        let mut sh = Shell::new(InitShellHost::with_log_rx(log_rx));
        sh.run_interactive()
    }

    // Automated self-test mode (`cargo xtask test`)
    let _ = writeln!(
        out,
        "[init] hello from EL0 (100% safe Rust, forbid_unsafe, isolated TTBR0_EL1 VSpace)!"
    );
    out.flush();

    if info.proc_count > 1 {
        drain_worker_boot_log(&mut log_rx, &mut out);
    }

    // Multi-process TTBR0_EL1 IPC ping-pong with isolated EL0 `worker` process (1-syscall `IpcCall`)
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, PING_PAYLOAD) != Ok((0x5E14, PING_PAYLOAD + 1))
    {
        let _ = writeln!(out, "[init] FAIL: missing IPC reply from worker");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[init] multi-process isolated TTBR0_EL1 IPC ping-pong with `worker`: OK"
    );

    // 64-bit Notification coalescing + userspace SpscRing check
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 0).is_err()
        || newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 2).is_err()
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0b101)
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0)
    {
        let _ = writeln!(out, "[init] FAIL: Notification capability check failed");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }

    const RING_BURST: usize = 32;
    let ring = SpscRing::<64>::new();
    let mut tx_batch = [0u64; RING_BURST];
    for (i, slot) in tx_batch.iter_mut().enumerate() {
        *slot = (i as u64) * 7;
    }
    if ring.try_push_slice(&tx_batch) != RING_BURST {
        let _ = writeln!(out, "[init] FAIL: SpscRing batch push failed");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1);
    let mut rx_batch = [0u64; RING_BURST];
    if newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(1)
        || ring.try_pop_slice(&mut rx_batch) != RING_BURST
        || rx_batch != tx_batch
    {
        let _ = writeln!(out, "[init] FAIL: SpscRing batch pop/notify mismatch");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }

    // Hardware TTBR0_EL1 context-switch latency benchmark
    const ROUNDTRIPS: u64 = 100;
    let t0 = newos_user_rt::read_cycles().unwrap_or(0);
    for _ in 0..ROUNDTRIPS {
        let _ = newos_user_rt::yield_now();
    }
    let t1 = newos_user_rt::read_cycles().unwrap_or(0);
    let avg_cycles = t1.saturating_sub(t0) / (ROUNDTRIPS * 2);
    let _ = writeln!(
        out,
        "[init] phase-5 IPC, Notification & TTBR0 switch self-check: OK (~{avg_cycles} cycles/TTBR0-switch)"
    );

    // EL0 Post-UNIX CAOS + Typed Pipeline Shell (`newos-sh`) self-check
    let mut sh = Shell::new(InitShellHost::new());
    if let Err(msg) = sh.run_self_test() {
        let _ = writeln!(
            out,
            "[init] FAIL: EL0 CAOS & typed pipeline self-check: {msg}"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[init] EL0 CAOS (dedup/rollback/seal) & typed `|` pipeline self-check: OK"
    );

    // EL0 Networking: capability-scoped NIC (Pi 5 RP1 GEM or QEMU VirtIO-net) + live DHCPv4 + ICMP ping
    let detected_nic =
        newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
    let mac = detected_nic
        .map(|n| n.mac())
        .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    if let Some(nic) = detected_nic {
        let cfg = match newos_net::live_dhcp_v4(CapMmioDmaTransport, nic, &VIRTIO_DMA, &GEM_DMA) {
            Ok(leased) => {
                let gw = leased.gateway.unwrap_or([0; 4]);
                let dns = leased.dns.unwrap_or([0; 4]);
                let _ = writeln!(
                    out,
                    "[init] EL0 LIVE DHCPv4 ({}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
                    nic.driver_name(),
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5],
                    leased.ip[0],
                    leased.ip[1],
                    leased.ip[2],
                    leased.ip[3],
                    leased.prefix_len,
                    gw[0],
                    gw[1],
                    gw[2],
                    gw[3],
                    dns[0],
                    dns[1],
                    dns[2],
                    dns[3],
                );
                leased
            }
            Err(msg) => {
                let _ = writeln!(out, "[init] FAIL: live DHCPv4 lease: {msg}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        };

        let target = cfg
            .gateway
            .unwrap_or(NetConfig::QEMU_DEFAULT.gateway.unwrap_or([10, 0, 2, 2]));
        match newos_net::live_icmp_ping(
            CapMmioDmaTransport,
            nic,
            &cfg,
            target,
            &VIRTIO_DMA,
            &GEM_DMA,
        ) {
            Ok(res) => {
                let _ = writeln!(
                    out,
                    "[init] EL0 LIVE ICMP ping {}.{}.{}.{} ({}): OK (seq={})",
                    res.target[0],
                    res.target[1],
                    res.target[2],
                    res.target[3],
                    nic.driver_name(),
                    res.seq,
                );
            }
            Err(msg) => {
                let _ = writeln!(out, "[init] FAIL: live ICMP ping: {msg}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        }
    } else {
        match newos_net::verify_smoltcp_el0_stack(mac) {
            Ok(frame_len) => {
                let _ = writeln!(
                    out,
                    "[init] EL0 smoltcp IPv4/UDP stack ({frame_len}B Ethernet frame, no_alloc, forbid_unsafe): OK"
                );
            }
            Err(msg) => {
                let _ = writeln!(out, "[init] FAIL: EL0 smoltcp stack check: {msg}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        }
    }

    // Unauthorized MMIO capability rejection
    if newos_user_rt::mmio_read32(CapId::NULL, 0) != Err(SysError::InvalidCapability) {
        let _ = writeln!(out, "[init] FAIL: unauthorized MMIO read was not rejected");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }

    // Deliberate EL0 hardware fault (`udf #0`) -> supervisor recovery
    let _ = writeln!(
        out,
        "[init] triggering deliberate EL0 hardware fault (`udf #0`) to verify crash isolation..."
    );
    out.flush();
    newos_user_rt::trigger_user_fault()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[init] PANIC in EL0\n");
    newos_user_rt::exit(ShutdownStatus::Failed)
}
