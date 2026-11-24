//! EL0 Root Task (`supervisor-pd`), Crash Supervisor, Content-Addressed Object Store (CAOS),
//! and Typed Pipeline Shell (`newos-shell-pd`).
//!

use core::fmt::Write;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ShutdownStatus, SysError};
#[cfg(feature = "net")]
use newos_net::{GemDma, MmioDmaTransport, NetConfig, NicKind, VirtioNetDma};
use newos_shell_core::shell::{NullWriter, Record, RecordStream, Shell, ShellHost, SysInfo};
use newos_user_rt::{BufferedConsole, IpcLogAssembler};

/// Static EL0 DMA rings & packet buffers (`Sync` via atomics).
#[cfg(feature = "net")]
pub static VIRTIO_DMA: VirtioNetDma = VirtioNetDma::new();
/// Static EL0 64-bit DMA rings & packet buffers for Raspberry Pi 5 RP1 Cadence GEM.
#[cfg(feature = "net")]
pub static GEM_DMA: GemDma = GemDma::new();

/// Capability-scoped MMIO + `VirtToPhys` transport for EL0 NIC drivers.
#[cfg(feature = "net")]
pub struct CapMmioDmaTransport;

#[cfg(feature = "net")]
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
/// and the `newos-key-pd`-gated `newos-ssh-pd` interactive shell channel.
struct SupervisorShellHost {
    #[cfg(feature = "net")]
    net_cfg: Option<NetConfig>,
    #[cfg(feature = "net")]
    cached_nic: Option<Option<NicKind>>,
    log_rx: IpcLogAssembler<256>,
    ssh_session_authorized: bool,
    ssh_rx_buf: [u8; 64],
    ssh_rx_pos: usize,
    ssh_rx_len: usize,
}

impl SupervisorShellHost {
    const fn new() -> Self {
        Self::with_log_rx(IpcLogAssembler::new())
    }

    const fn with_log_rx(log_rx: IpcLogAssembler<256>) -> Self {
        Self {
            #[cfg(feature = "net")]
            net_cfg: None,
            #[cfg(feature = "net")]
            cached_nic: None,
            log_rx,
            ssh_session_authorized: false,
            ssh_rx_buf: [0u8; 64],
            ssh_rx_pos: 0,
            ssh_rx_len: 0,
        }
    }

    /// Poll `CapId::BOOTSTRAP_AUTH_GATE_EP` (`newos-key-pd` PD 3 write-only -> `supervisor-pd` read-only)
    /// to open/close the SSH shell channel strictly on `key-pd`'s ML-DSA-87 verification.
    fn poll_ssh_auth_gate(&mut self) {
        while let Ok((badge, word)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_AUTH_GATE_EP) {
            if badge != newos_abi::auth_gate_ipc::BADGE_KEY {
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

    #[cfg(feature = "net")]
    fn probe_nic_cached(&mut self) -> Option<NicKind> {
        if let Some(cached) = self.cached_nic {
            return cached;
        }
        let nic =
            newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
        self.cached_nic = Some(nic);
        nic
    }

    #[cfg(not(feature = "net"))]
    fn handle_net_with<W: Write>(
        &mut self,
        _subcmd: &str,
        _arg: Option<&str>,
        _stream: &mut RecordStream,
        out: &mut W,
    ) {
        let _ = writeln!(out, "net: disabled in this build profile");
    }

    #[cfg(feature = "net")]
    fn handle_net_with<W: Write>(
        &mut self,
        subcmd: &str,
        arg: Option<&str>,
        stream: &mut RecordStream,
        out: &mut W,
    ) {
        let _ = arg;
        let nic = self.probe_nic_cached();
        let mac = nic
            .map(|n| n.mac())
            .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        if let Some(n) = nic {
            match subcmd {
                #[cfg(feature = "ipv4")]
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
                #[cfg(all(feature = "ipv4", feature = "icmp"))]
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
                #[cfg(all(feature = "ipv4", feature = "dns"))]
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
        } else {
            #[cfg(all(feature = "ipv4", feature = "udp"))]
            if let Ok(frame_len) = newos_net::verify_smoltcp_el0_stack(mac) {
                stream.push(Record::Metric {
                    label: "smoltcp.tx.frame",
                    value: frame_len as u64,
                    unit: "bytes (EL0 IPv4)",
                });
            }
        }
    }
}

impl ShellHost for SupervisorShellHost {
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
            domain_count: info.domain_count,
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
                && badge == newos_abi::key_ipc::BADGE_SSH
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

/// EL0 supervisor fault-recovery entry point.
///
/// Re-entrancy invariant: `supervisor-pd` is single-threaded. On any EL0 hardware fault (including a
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
                    "[init-supervisor] recovered from EL0 fault (bits={:#x}) — restarting `newos-shell-pd`!",
                    bits
                );
                out.flush();
                let _ = newos_user_rt::set_fault_handler(supervisor_recover);
                let mut sh = Shell::new(SupervisorShellHost::new());
                sh.run_interactive()
            } else if bits == (1 << 6) {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] EL0 fault isolation & supervisor recovery: OK (fault_bits={:#x})",
                    bits
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Success)
            } else {
                let _ = writeln!(out, "[supervisor-pd] FAIL: unexpected fault bits {bits:#x}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed)
            }
        }
        other => {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: unexpected fault notification bits: {other:?}"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed)
        }
    }
}

/// Drain `worker`'s startup log line over `CapId::BOOTSTRAP_LOG_EP` as the sole console owner.
///
/// Prints any complete protection domain lines that arrive concurrently and waits until `worker` (verified
/// via its kernel-stamped `role_badge::ROLE_WORKER` tag, independent of PD) finishes its boot
/// line so `supervisor-pd` does not block on `BOOTSTRAP_EP` while `worker` is still writing to
/// `BOOTSTRAP_LOG_EP`. Bounded by `MAX_BOOT_LOG_YIELDS` so `supervisor-pd` cannot hang forever if
/// `worker` fails to start or `BOOTSTRAP_LOG_EP` is revoked.
fn drain_worker_boot_log<const N: usize>(
    log_rx: &mut IpcLogAssembler<256>,
    out: &mut BufferedConsole<N>,
) {
    const MAX_BOOT_LOG_YIELDS: usize = 10_000;
    let mut line_buf = [0u8; 256];
    for _ in 0..MAX_BOOT_LOG_YIELDS {
        while let Some((badge, n)) = log_rx.poll_line(CapId::BOOTSTRAP_LOG_EP, &mut line_buf) {
            let role = newos_abi::role_badge::decode_log_role(badge);
            let pid = newos_abi::role_badge::decode_log_pd_id(badge);
            let role_name = newos_abi::role_badge::role_name(role);
            if let Ok(line) = core::str::from_utf8(&line_buf[..n]) {
                // Stamp with kernel-verified sender role + diagnostic PD so no protection domain can forge
                // another's prefix (`N17`).
                let _ = writeln!(out, "[{role_name} pid={pid}] {line}");
                out.flush();
            }
            if role == newos_abi::role_badge::ROLE_WORKER {
                return;
            }
        }
        if newos_user_rt::yield_now().is_err() {
            return;
        }
    }
}

#[cfg(feature = "wdt")]
struct CapWdtTransport;

#[cfg(feature = "wdt")]
impl newos_wdt::WdtTransport for CapWdtTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError> {
        newos_user_rt::mmio_read32(CapId::BOOTSTRAP_WDT_MMIO, offset)
    }

    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
        newos_user_rt::mmio_write32(CapId::BOOTSTRAP_WDT_MMIO, offset, val)
    }
}

/// Interactive-mode minimal Root Supervisor loop (PD 0).
///
/// Arms the Raspberry Pi 5 `Bcm2712Watchdog` (8,000 ms timeout) when `BOOTSTRAP_WDT_MMIO` is
/// provisioned and `wdt` feature is enabled, pets it every 2,000 ms, and listens on
/// `BOOTSTRAP_FAULT_NOTIF` via `NotifyWait` to inspect and respawn crashed permanent protection domains
/// (`Shell`, `Net`, `Key`, `Ssh`) with exponential backoff and restart-intensity limits.
fn run_root_supervisor(out: &mut BufferedConsole<1024>) -> ! {
    #[cfg(feature = "wdt")]
    let (wdt, wdt_armed) = {
        let mut wdt = newos_wdt::Bcm2712Watchdog::new(CapWdtTransport);
        let armed = wdt.arm(8_000).is_ok();
        if armed {
            let _ = writeln!(
                out,
                "[supervisor] BCM2712 hardware watchdog armed (8000 ms)"
            );
            out.flush();
        }
        (wdt, armed)
    };

    const MAX_ROLES: usize = 6;
    const MAX_RESTARTS_IN_WINDOW: u32 = 5;
    let mut restart_counts = [0u32; MAX_ROLES];
    let mut backoff_ms = [10u64; MAX_ROLES];
    let mut window_start_cycles = [0u64; MAX_ROLES];
    let freq = newos_user_rt::timer_freq_hz().max(1);
    let window_ticks = freq.saturating_mul(10); // 10 s intensity window

    loop {
        match newos_user_rt::notify_wait(CapId::BOOTSTRAP_FAULT_NOTIF, 0xFF, 2_000_000_000) {
            Ok((bits, _timed_out)) => {
                #[cfg(feature = "wdt")]
                if wdt_armed {
                    let _ = wdt.pet();
                }
                if bits == 0 {
                    continue;
                }
                for pid in 1..8usize {
                    if (bits & (1u64 << pid)) == 0 {
                        continue;
                    }
                    let Ok((role, esr, elr)) = newos_user_rt::domain_get_fault_info(pid) else {
                        continue;
                    };
                    let _ = writeln!(
                        out,
                        "[supervisor] isolated fault pid={pid} role={role:?} ESR={esr:#x} ELR={elr:#018x}"
                    );
                    out.flush();
                    let is_permanent = matches!(
                        role,
                        newos_abi::DomainRoleId::Shell
                            | newos_abi::DomainRoleId::Net
                            | newos_abi::DomainRoleId::Key
                            | newos_abi::DomainRoleId::Ssh
                    );
                    if !is_permanent {
                        continue;
                    }
                    let idx = (role as usize).min(MAX_ROLES - 1);
                    let now = newos_user_rt::read_cycles().unwrap_or(0);
                    if now.saturating_sub(window_start_cycles[idx]) > window_ticks {
                        window_start_cycles[idx] = now;
                        restart_counts[idx] = 0;
                        backoff_ms[idx] = 10;
                    }
                    if restart_counts[idx] >= MAX_RESTARTS_IN_WINDOW {
                        let _ = writeln!(
                            out,
                            "[supervisor] circuit-breaker tripped for {role:?} (>= {MAX_RESTARTS_IN_WINDOW} crashes/10s)"
                        );
                        out.flush();
                        continue;
                    }
                    let delay = backoff_ms[idx];
                    let _ = newos_user_rt::sleep_ms(delay);
                    backoff_ms[idx] = (delay.saturating_mul(2)).min(1_000);
                    restart_counts[idx] += 1;
                    match newos_user_rt::domain_respawn(role) {
                        Ok(new_pid) => {
                            let _ = writeln!(
                                out,
                                "[supervisor] respawned {role:?} as pid={new_pid} (backoff={delay}ms)"
                            );
                            out.flush();
                        }
                        Err(e) => {
                            let _ =
                                writeln!(out, "[supervisor] respawn failed for {role:?}: {e:?}");
                            out.flush();
                        }
                    }
                }
            }
            Err(_) => {
                let _ = newos_user_rt::sleep_ms(50);
            }
        }
    }
}

pub fn main() -> ! {
    let mut out = BufferedConsole::<1024>::new();
    let mut log_rx = IpcLogAssembler::<256>::new();
    let info = newos_user_rt::sys_info();
    let _ = newos_user_rt::set_fault_handler(supervisor_recover);

    if info.interactive_shell {
        // Standalone `newos-shell-pd` runs in its own isolated EL0 process; PD 0 serves as the
        // minimal root supervisor + hardware watchdog loop.
        run_root_supervisor(&mut out)
    }

    // Automated self-test mode (`cargo xtask test`)
    let _ = writeln!(
        out,
        "[supervisor-pd] hello from EL0 (isolated TTBR0_EL1 VSpace)!"
    );
    out.flush();

    if info.domain_count > 1 {
        drain_worker_boot_log(&mut log_rx, &mut out);
    }

    // Multi-process TTBR0_EL1 IPC ping-pong with isolated EL0 `worker` process (1-syscall `IpcCall`)
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, PING_PAYLOAD) != Ok((0x5E14, PING_PAYLOAD + 1))
    {
        let _ = writeln!(out, "[supervisor-pd] FAIL: missing IPC reply from worker");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] multi-process isolated TTBR0_EL1 IPC ping-pong with `worker`: OK"
    );

    // 64-bit Notification coalescing + userspace SpscRing check
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 0).is_err()
        || newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 2).is_err()
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0b101)
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0)
    {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Notification capability check failed"
        );
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
        let _ = writeln!(out, "[supervisor-pd] FAIL: SpscRing batch push failed");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1);
    let mut rx_batch = [0u64; RING_BURST];
    if newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(1)
        || ring.try_pop_slice(&mut rx_batch) != RING_BURST
        || rx_batch != tx_batch
    {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: SpscRing batch pop/notify mismatch"
        );
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
        "[supervisor-pd] IPC, notifications & TTBR0 switch: OK (~{avg_cycles} cycles/TTBR0-switch)"
    );

    // EL0 CAOS + Typed Pipeline Shell (`newos-shell-pd`) self-check
    let mut sh = Shell::new(SupervisorShellHost::new());
    if let Err(msg) = sh.run_self_test() {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: EL0 CAOS & typed pipeline self-check: {msg}"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] EL0 CAOS (dedup/rollback/seal) & typed `|` pipeline self-check: OK"
    );

    // EL0 Networking: capability-scoped NIC (Pi 5 RP1 GEM or QEMU VirtIO-net) + live DHCPv4 / IPv6 check
    #[cfg(feature = "net")]
    {
        let detected_nic =
            newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
        let mac = detected_nic
            .map(|n| n.mac())
            .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        #[cfg(feature = "ipv4")]
        if let Some(nic) = detected_nic {
            let cfg = match newos_net::live_dhcp_v4(CapMmioDmaTransport, nic, &VIRTIO_DMA, &GEM_DMA)
            {
                Ok(leased) => {
                    let gw = leased.gateway.unwrap_or([0; 4]);
                    let dns = leased.dns.unwrap_or([0; 4]);
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] EL0 LIVE DHCPv4 ({}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
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
                    let _ = writeln!(out, "[supervisor-pd] FAIL: live DHCPv4 lease: {msg}");
                    out.flush();
                    newos_user_rt::exit(ShutdownStatus::Failed);
                }
            };

            #[cfg(feature = "icmp")]
            {
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
                            "[supervisor-pd] EL0 LIVE ICMP ping {}.{}.{}.{} ({}): OK (seq={})",
                            res.target[0],
                            res.target[1],
                            res.target[2],
                            res.target[3],
                            nic.driver_name(),
                            res.seq,
                        );
                    }
                    Err(msg) => {
                        let _ = writeln!(out, "[supervisor-pd] FAIL: live ICMP ping: {msg}");
                        out.flush();
                        newos_user_rt::exit(ShutdownStatus::Failed);
                    }
                }
            }
        } else {
            #[cfg(feature = "udp")]
            match newos_net::verify_smoltcp_el0_stack(mac) {
                Ok(frame_len) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] EL0 smoltcp IPv4/UDP stack ({frame_len}B Ethernet frame): OK"
                    );
                }
                Err(msg) => {
                    let _ = writeln!(out, "[supervisor-pd] FAIL: EL0 smoltcp stack check: {msg}");
                    out.flush();
                    newos_user_rt::exit(ShutdownStatus::Failed);
                }
            }
        }
        #[cfg(all(not(feature = "ipv4"), feature = "ipv6", feature = "udp"))]
        {
            let _ = detected_nic;
            match newos_net::verify_smoltcp_ipv6_el0_stack(mac) {
                Ok(frame_len) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] EL0 smoltcp IPv6/UDP stack ({frame_len}B Ethernet frame): OK"
                    );
                }
                Err(msg) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] FAIL: EL0 smoltcp IPv6 stack check: {msg}"
                    );
                    out.flush();
                    newos_user_rt::exit(ShutdownStatus::Failed);
                }
            }
        }
        #[cfg(not(any(feature = "ipv4", all(feature = "ipv6", feature = "udp"))))]
        let _ = (detected_nic, mac);
    }

    // Unauthorized MMIO capability rejection
    if newos_user_rt::mmio_read32(CapId::NULL, 0) != Err(SysError::InvalidCapability) {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: unauthorized MMIO read was not rejected"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }

    // Phase 1 EL1 hardening & blocking event primitives self-test:
    // 1. NotifyWait: zero-mask rejection, partial-mask fastpath, timeout wakeup, preserved bits.
    if newos_user_rt::notify_wait(CapId::BOOTSTRAP_NOTIF, 0, 0) != Err(SysError::InvalidArgument) {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: NotifyWait(mask=0) was not rejected"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF);
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 0b1010_0101).is_err()
        || newos_user_rt::notify_wait(CapId::BOOTSTRAP_NOTIF, 0b0000_1111, 0)
            != Ok((0b0000_0101, false))
        || newos_user_rt::notify_wait(CapId::BOOTSTRAP_NOTIF, 0b0000_1111, 5_000_000)
            != Ok((0, true))
        || newos_user_rt::notify_wait(CapId::BOOTSTRAP_NOTIF, 0b1111_0000, 0)
            != Ok((0b1010_0000, false))
    {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: NotifyWait fastpath/timeout/preserve check"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    // 2. SleepUntil / sleep_ms: immediate past deadline + timed sleep across idle WFI.
    let t0 = newos_user_rt::read_cycles().unwrap_or(0);
    let freq = newos_user_rt::timer_freq_hz().max(1);
    let min_ticks = (freq / 100).max(1); // 10 ms
    if newos_user_rt::sleep_until(0).is_err()
        || newos_user_rt::sleep_ms(10).is_err()
        || newos_user_rt::read_cycles().unwrap_or(0).saturating_sub(t0) < min_ticks
    {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: SleepUntil/sleep_ms deadline check"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    // 3. IrqBind / IrqAck: validation, binding, duplicate rejection, and ack.
    if newos_user_rt::irq_bind(
        CapId::NULL,
        CapId::BOOTSTRAP_NOTIF,
        0,
        newos_abi::IrqTriggerMode::LevelHigh,
    ) != Err(SysError::InvalidCapability)
        || newos_user_rt::irq_bind(
            CapId::BOOTSTRAP_UART_IRQ,
            CapId::BOOTSTRAP_NOTIF,
            64,
            newos_abi::IrqTriggerMode::LevelHigh,
        ) != Err(SysError::InvalidArgument)
        || newos_user_rt::irq_bind(
            CapId::BOOTSTRAP_UART_IRQ,
            CapId::BOOTSTRAP_NOTIF,
            1,
            newos_abi::IrqTriggerMode::LevelHigh,
        )
        .is_err()
        || newos_user_rt::irq_bind(
            CapId::BOOTSTRAP_UART_IRQ,
            CapId::BOOTSTRAP_NOTIF,
            1,
            newos_abi::IrqTriggerMode::LevelHigh,
        ) != Err(SysError::SlotOccupied)
        || newos_user_rt::irq_ack(CapId::BOOTSTRAP_UART_IRQ).is_err()
    {
        let _ = writeln!(out, "[supervisor-pd] FAIL: IrqBind/IrqAck check");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    // 4. MmioMap: unaligned VA, invalid cap, and sub-page shared MMIO rejection.
    if newos_user_rt::mmio_map(CapId::BOOTSTRAP_VSPACE, CapId::BOOTSTRAP_NET_MMIO, 0x1234)
        != Err(SysError::InvalidArgument)
        || newos_user_rt::mmio_map(CapId::BOOTSTRAP_VSPACE, CapId::NULL, 0x2000_0000)
            != Err(SysError::InvalidCapability)
    {
        let _ = writeln!(out, "[supervisor-pd] FAIL: MmioMap validation check");
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] Phase 1 EL1 primitives (NotifyWait, SleepUntil, IrqBind/IrqAck, MmioMap): OK"
    );

    // Phase 2 Chaos Respawn & Zero-Leak Reclamation self-test:
    // Deliberately crash `worker` twice via `udf #0` (`0xDEAD_C0DE`), verify fault notification +
    // `DomainGetFaultInfo`, verify `DomainRespawn` restores IPC service, and prove exact 0-frame leak.
    let _ = newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF);
    let mut rem_after_cycle = [0u64; 2];
    for cycle in 0..2usize {
        if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, 0xDEAD_C0DE)
            != Err(SysError::InvalidCapability)
        {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2 worker crash trigger (cycle={cycle})"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        let (fault_bits, timed_out) =
            match newos_user_rt::notify_wait(CapId::BOOTSTRAP_FAULT_NOTIF, !0u64, 1_000_000_000) {
                Ok(v) => v,
                Err(_) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] FAIL: Phase 2 fault NotifyWait (cycle={cycle})"
                    );
                    out.flush();
                    newos_user_rt::exit(ShutdownStatus::Failed);
                }
            };
        if timed_out || fault_bits == 0 {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2 fault NotifyWait (cycle={cycle})"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        let worker_pd = fault_bits.trailing_zeros() as usize;
        match newos_user_rt::domain_get_fault_info(worker_pd) {
            Ok((newos_abi::DomainRoleId::Worker, esr, _elr)) if (esr >> 26) == 0 => {}
            other => {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] FAIL: Phase 2 DomainGetFaultInfo mismatch (cycle={cycle}): {other:?}"
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        }
        let (rem_frames, reclaimed_len) = match newos_user_rt::mem_stats() {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(out, "[supervisor-pd] FAIL: Phase 2 MemStats error: {e:?}");
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        };
        if reclaimed_len == 0 {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2 expected reclaimed frames > 0"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        rem_after_cycle[cycle] = rem_frames;
        if newos_user_rt::domain_respawn(newos_abi::DomainRoleId::Worker) != Ok(worker_pd) {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2 DomainRespawn(Worker) (cycle={cycle})"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        drain_worker_boot_log(&mut log_rx, &mut out);
        let probe = 0xBEEF_0001u64 + cycle as u64;
        if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, probe) != Ok((0x5E14, probe + 1)) {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2 respawned worker IPC check (cycle={cycle})"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
    }
    if rem_after_cycle[0] != rem_after_cycle[1] {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Phase 2 frame leak across respawn cycles ({} != {})",
            rem_after_cycle[0], rem_after_cycle[1]
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] Phase 2 chaos respawn & zero-leak reclamation (2 cycles, remaining_frames={}): OK",
        rem_after_cycle[1]
    );

    // Phase 3a On-Target AArch64 Cycle & Tail-Latency Benchmark Suite (256 samples each):
    // Measures real EL0<->EL1<->EL0 IpcCall round-trip, NotifySignal+NotifyWait fastpath,
    // and shared-memory SpscRing 4 KiB framed byte burst on AArch64 CNTVCT_EL0.
    {
        const SAMPLES: usize = 256;
        let mut ipc_samples = [0u64; SAMPLES];
        for (i, slot) in ipc_samples.iter_mut().enumerate() {
            let t0 = newos_user_rt::read_cycles().unwrap_or(0);
            let _ = newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, 0x3A00_0000 + i as u64);
            let t1 = newos_user_rt::read_cycles().unwrap_or(0);
            *slot = t1.saturating_sub(t0);
        }
        ipc_samples.sort_unstable();
        let ipc_p50 = ipc_samples[SAMPLES / 2];
        let ipc_p99 = ipc_samples[(SAMPLES * 99) / 100];
        let ipc_p999 = ipc_samples[(SAMPLES * 999) / 1000];
        let ipc_max = ipc_samples[SAMPLES - 1];

        let _ = newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF);
        let mut notif_samples = [0u64; SAMPLES];
        for slot in &mut notif_samples {
            let t0 = newos_user_rt::read_cycles().unwrap_or(0);
            let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1);
            let _ = newos_user_rt::notify_wait(CapId::BOOTSTRAP_NOTIF, 1, 0);
            let t1 = newos_user_rt::read_cycles().unwrap_or(0);
            *slot = t1.saturating_sub(t0);
        }
        notif_samples.sort_unstable();
        let notif_p50 = notif_samples[SAMPLES / 2];
        let notif_p99 = notif_samples[(SAMPLES * 99) / 100];
        let notif_p999 = notif_samples[(SAMPLES * 999) / 1000];
        let notif_max = notif_samples[SAMPLES - 1];

        let ring = newos_abi::ring::SpscRing::<64>::new();
        let src = [0x5Au8; 256];
        let mut dst = [0u8; 256];
        let t0 = newos_user_rt::read_cycles().unwrap_or(0);
        for _ in 0..16usize {
            // 16 x 256 B = 4 KiB framed SpscRing burst (zero syscalls in data path)
            if ring.try_push_bytes(&src) != Ok(256) || ring.try_pop_bytes(&mut dst) != Some(256) {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] FAIL: Phase 3a SpscRing byte burst check"
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        }
        let ring_4k_cycles = newos_user_rt::read_cycles().unwrap_or(0).saturating_sub(t0);
        let _ = writeln!(
            out,
            "[bench-aarch64] IpcCall(ticks): p50={ipc_p50} p99={ipc_p99} p99.9={ipc_p999} max={ipc_max} | NotifyWait(ticks): p50={notif_p50} p99={notif_p99} p99.9={notif_p999} max={notif_max} | SpscRing-4KiB(ticks): {ring_4k_cycles} (0 syscalls)"
        );
    }

    // Deliberate EL0 hardware fault (`udf #0`) -> supervisor recovery
    let _ = writeln!(
        out,
        "[supervisor-pd] triggering deliberate EL0 hardware fault (`udf #0`) to verify crash isolation..."
    );
    out.flush();
    newos_user_rt::trigger_user_fault()
}
