#![no_std]
#![no_main]
#![forbid(unsafe_code)]

//! Ring-3 Root Task (`init`), Crash Supervisor, Content-Addressed Object Store (CAOS),
//! and Post-UNIX Typed Pipeline Shell (`newos-sh`).
//!
//! 100% memory-safe Rust (`#![forbid(unsafe_code)]`, `no_alloc`).

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, QemuExitCode, SysError};
use newos_net::{GemDma, NetConfig, NicKind, VirtioNetDma, VirtioTransport};
use newos_shell_core::shell::{NullWriter, Record, RecordStream, Shell, ShellHost, SysInfo};
use newos_user_rt::BufferedConsole;

/// Static Ring-3 DMA rings & packet buffers (`Sync` via atomics, 100% `#![forbid(unsafe_code)]`).
pub static VIRTIO_DMA: VirtioNetDma = VirtioNetDma::new();
/// Static Ring-3 64-bit DMA rings & packet buffers for Raspberry Pi 5 RP1 Cadence GEM.
pub static GEM_DMA: GemDma = GemDma::new();

/// Capability-scoped MMIO + `VirtToPhys` transport for Ring-3 VirtIO drivers.
pub struct CapVirtioTransport;

impl VirtioTransport for CapVirtioTransport {
    fn read32(&self, offset: u64) -> Result<u32, SysError> {
        newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, offset)
    }

    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
        newos_user_rt::mmio_write32(CapId::BOOTSTRAP_NET_MMIO, offset, val)
    }

    fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
        newos_user_rt::virt_to_phys(r)
    }
}

/// Ring-3 `ShellHost` adapter connecting `newos-shell-core` to `newos-user-rt` and `newos-net`.
struct InitShellHost {
    net_cfg: Option<NetConfig>,
    cached_nic: Option<Option<NicKind>>,
}

impl InitShellHost {
    const fn new() -> Self {
        Self {
            net_cfg: None,
            cached_nic: None,
        }
    }

    fn probe_nic_cached(&mut self) -> Option<NicKind> {
        if let Some(cached) = self.cached_nic {
            return cached;
        }
        let nic = newos_net::probe_nic(|off| {
            newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off)
        });
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
                "dhcp" => match newos_net::live_dhcp_v4(
                    CapVirtioTransport,
                    n,
                    &VIRTIO_DMA,
                    &GEM_DMA,
                ) {
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
                },
                "ping" => {
                    let cfg = self.net_cfg.unwrap_or(NetConfig::QEMU_DEFAULT);
                    let target = arg
                        .and_then(newos_net::parse_ipv4)
                        .or(cfg.gateway)
                        .unwrap_or([10, 0, 2, 2]);
                    match newos_net::live_icmp_ping(
                        CapVirtioTransport,
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
                    match newos_net::live_dns_resolve(
                        CapVirtioTransport,
                        n,
                        &cfg,
                        host,
                        &VIRTIO_DMA,
                        &GEM_DMA,
                    ) {
                        Ok(ip) => {
                            let _ = writeln!(
                                out,
                                "{host} -> {}.{}.{}.{}",
                                ip[0], ip[1], ip[2], ip[3]
                            );
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
        } else if let Ok(frame_len) = newos_net::verify_smoltcp_ring3_stack(mac) {
            stream.push(Record::Metric {
                label: "smoltcp.tx.frame",
                value: frame_len as u64,
                unit: "bytes (Ring-3 IPv4)",
            });
        }
    }
}

impl ShellHost for InitShellHost {
    fn write_debug(&mut self, s: &str) {
        let _ = newos_user_rt::debug_write_all(s);
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

    fn exit(&mut self, code: QemuExitCode) -> ! {
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
            let mut out = BufferedConsole::<256>::new();
            self.handle_net_with(subcmd, arg, stream, &mut out);
            out.flush();
        }
    }
}

newos_user_rt::entry!(main);

extern "C" fn supervisor_recover() -> ! {
    let mut out = BufferedConsole::<256>::new();
    let info = newos_user_rt::sys_info();

    match newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF) {
        Ok(bits) if bits != 0 => {
            if info.interactive_shell {
                let _ = writeln!(
                    out,
                    "[init-supervisor] recovered from Ring-3 fault (bits={:#x}) — restarting `newos-sh`!",
                    bits
                );
                out.flush();
                let _ = newos_user_rt::set_fault_handler(supervisor_recover);
                let mut sh = Shell::new(InitShellHost::new());
                sh.run_interactive()
            } else if bits == (1 << 6) {
                let _ = writeln!(
                    out,
                    "[init] phase-6 Ring-3 crash isolation & supervisor recovery: OK (fault_bits={:#x})",
                    bits
                );
                out.flush();
                newos_user_rt::exit(QemuExitCode::Success)
            } else {
                let _ = writeln!(out, "[init] FAIL: unexpected fault bits {bits:#x}");
                out.flush();
                newos_user_rt::exit(QemuExitCode::Failed)
            }
        }
        other => {
            let _ = writeln!(
                out,
                "[init] FAIL: unexpected fault notification bits: {other:?}"
            );
            out.flush();
            newos_user_rt::exit(QemuExitCode::Failed)
        }
    }
}

fn main() -> ! {
    let mut out = BufferedConsole::<256>::new();
    let info = newos_user_rt::sys_info();
    let _ = newos_user_rt::set_fault_handler(supervisor_recover);

    if info.interactive_shell {
        let mut sh = Shell::new(InitShellHost::new());
        sh.run_interactive()
    }

    // Automated self-test mode (`cargo xtask test`)
    let _ = writeln!(
        out,
        "[init] hello from Ring 3 (100% safe Rust, forbid_unsafe, isolated CR3 VSpace)!"
    );
    out.flush();

    // Multi-process CR3 IPC ping-pong with isolated Ring-3 `worker` process (1-syscall `IpcCall`)
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, PING_PAYLOAD) != Ok((0x5E14, PING_PAYLOAD + 1)) {
        let _ = writeln!(out, "[init] FAIL: missing IPC reply from worker");
        out.flush();
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] multi-process isolated CR3 IPC ping-pong with `worker`: OK"
    );

    // 64-bit Notification coalescing + userspace SpscRing check
    if newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 0).is_err()
        || newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1 << 2).is_err()
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0b101)
        || newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(0)
    {
        let _ = writeln!(out, "[init] FAIL: Notification capability check failed");
        out.flush();
        newos_user_rt::exit(QemuExitCode::Failed);
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
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_NOTIF, 1);
    let mut rx_batch = [0u64; RING_BURST];
    if newos_user_rt::notify_poll(CapId::BOOTSTRAP_NOTIF) != Ok(1)
        || ring.try_pop_slice(&mut rx_batch) != RING_BURST
        || rx_batch != tx_batch
    {
        let _ = writeln!(out, "[init] FAIL: SpscRing batch pop/notify mismatch");
        out.flush();
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Hardware CR3 context-switch latency benchmark
    const ROUNDTRIPS: u64 = 100;
    let t0 = newos_user_rt::read_cycles().unwrap_or(0);
    for _ in 0..ROUNDTRIPS {
        let _ = newos_user_rt::yield_now();
    }
    let t1 = newos_user_rt::read_cycles().unwrap_or(0);
    let avg_cycles = t1.saturating_sub(t0) / (ROUNDTRIPS * 2);
    let _ = writeln!(
        out,
        "[init] phase-5 IPC, Notification & CR3 switch self-check: OK (~{avg_cycles} cycles/CR3-switch)"
    );

    // Ring-3 Post-UNIX CAOS + Typed Pipeline Shell (`newos-sh`) self-check
    let mut sh = Shell::new(InitShellHost::new());
    if let Err(msg) = sh.run_self_test() {
        let _ = writeln!(out, "[init] FAIL: Ring-3 CAOS & typed pipeline self-check: {msg}");
        out.flush();
        newos_user_rt::exit(QemuExitCode::Failed);
    }
    let _ = writeln!(
        out,
        "[init] Ring-3 CAOS (dedup/rollback/seal) & typed `|` pipeline self-check: OK"
    );

    // Ring-3 Networking: capability-scoped NIC (VirtIO-net or Pi 5 RP1 GEM) + live DHCPv4 + ICMP ping
    let detected_nic =
        newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
    let mac = detected_nic
        .map(|n| n.mac())
        .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    if let Some(nic) = detected_nic {
        let cfg = match newos_net::live_dhcp_v4(CapVirtioTransport, nic, &VIRTIO_DMA, &GEM_DMA) {
            Ok(leased) => {
                let gw = leased.gateway.unwrap_or([0; 4]);
                let dns = leased.dns.unwrap_or([0; 4]);
                let _ = writeln!(
                    out,
                    "[init] Ring-3 LIVE DHCPv4 ({}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
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
                newos_user_rt::exit(QemuExitCode::Failed);
            }
        };

        let target = cfg.gateway.unwrap_or(NetConfig::QEMU_DEFAULT.gateway.unwrap_or([10, 0, 2, 2]));
        match newos_net::live_icmp_ping(CapVirtioTransport, nic, &cfg, target, &VIRTIO_DMA, &GEM_DMA) {
            Ok(res) => {
                let _ = writeln!(
                    out,
                    "[init] Ring-3 LIVE ICMP ping {}.{}.{}.{} ({}): OK (seq={})",
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
                newos_user_rt::exit(QemuExitCode::Failed);
            }
        }
    } else {
        match newos_net::verify_smoltcp_ring3_stack(mac) {
            Ok(frame_len) => {
                let _ = writeln!(
                    out,
                    "[init] Ring-3 smoltcp IPv4/UDP stack ({frame_len}B Ethernet frame, no_alloc, forbid_unsafe): OK"
                );
            }
            Err(msg) => {
                let _ = writeln!(out, "[init] FAIL: Ring-3 smoltcp stack check: {msg}");
                out.flush();
                newos_user_rt::exit(QemuExitCode::Failed);
            }
        }
    }

    // Unauthorized MMIO capability rejection
    if newos_user_rt::mmio_read32(CapId::NULL, 0) != Err(SysError::InvalidCapability) {
        let _ = writeln!(out, "[init] FAIL: unauthorized MMIO read was not rejected");
        out.flush();
        newos_user_rt::exit(QemuExitCode::Failed);
    }

    // Deliberate Ring-3 hardware fault (#UD) -> supervisor recovery
    let _ = writeln!(
        out,
        "[init] triggering deliberate Ring-3 hardware fault (#UD) to verify crash isolation..."
    );
    out.flush();
    newos_user_rt::trigger_user_fault()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::debug_log("[init] PANIC in Ring 3\n");
    newos_user_rt::exit(QemuExitCode::Failed)
}
