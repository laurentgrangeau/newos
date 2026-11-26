//! EL0 Root Task (`supervisor-pd`), Crash Supervisor, Content-Addressed Object Store (CAOS),
//! and Typed Pipeline Shell (`newos-shell-pd`).
//!

use core::fmt::Write;
#[cfg(feature = "net")]
use newos_abi::net_ipc;
use newos_abi::ring::SpscRing;
use newos_abi::{CapId, ShutdownStatus, SysError};
#[cfg(all(feature = "net", feature = "ipv4"))]
use newos_net::{GemDma, MmioDmaTransport, VirtioNetDma};
#[cfg(feature = "net")]
use newos_net::{NetConfig, NicKind};
#[cfg(feature = "net")]
use newos_shell_core::shell::{NullWriter, Record};
use newos_shell_core::shell::{OutputMode, RecordStream, Shell, ShellHost, SysInfo};
use newos_user_rt::{BufferedConsole, IpcLogAssembler};

/// Static EL0 DMA rings & packet buffers (`Sync` via atomics).
#[cfg(all(feature = "net", feature = "ipv4"))]
pub static VIRTIO_DMA: VirtioNetDma = VirtioNetDma::new();
/// Static EL0 64-bit DMA rings & packet buffers for Raspberry Pi 5 RP1 Cadence GEM.
#[cfg(all(feature = "net", feature = "ipv4"))]
pub static GEM_DMA: GemDma = GemDma::new();

/// Capability-scoped MMIO + `VirtToPhys` transport for EL0 NIC drivers.
#[cfg(all(feature = "net", feature = "ipv4"))]
pub struct CapMmioDmaTransport;

#[cfg(all(feature = "net", feature = "ipv4"))]
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

/// Fixed-capacity UTF-8 buffer implementing `core::fmt::Write` so shell commands can
/// format text and route it through `ShellHost::write_debug` (serial + SSH).
#[cfg(feature = "net")]
struct StackStrWriter<const N: usize> {
    buf: [u8; N],
    len: usize,
}

#[cfg(feature = "net")]
impl<const N: usize> StackStrWriter<N> {
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

#[cfg(feature = "net")]
impl<const N: usize> Write for StackStrWriter<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let avail = N.saturating_sub(self.len);
        let bytes = s.as_bytes();
        let n = bytes.len().min(avail);
        // Never split a multi-byte UTF-8 sequence.
        let mut safe_n = n;
        while safe_n > 0 && core::str::from_utf8(&bytes[..safe_n]).is_err() {
            safe_n -= 1;
        }
        self.buf[self.len..self.len + safe_n].copy_from_slice(&bytes[..safe_n]);
        self.len += safe_n;
        Ok(())
    }
}

#[cfg(feature = "net")]
fn net_pd_call(req: u64) -> Result<u64, SysError> {
    for _ in 0..500 {
        match newos_user_rt::ipc_call(CapId::BOOTSTRAP_NET_EP, req) {
            Ok((_badge, reply)) => return Ok(reply),
            Err(SysError::WouldBlock) => {
                let _ = newos_user_rt::sleep_ms(1);
            }
            Err(e) => return Err(e),
        }
    }
    Err(SysError::WouldBlock)
}

#[cfg(feature = "net")]
const fn net_pd_driver_name(driver_id: u8) -> &'static str {
    match driver_id {
        net_ipc::DRIVER_VIRTIO => "virtio-net",
        net_ipc::DRIVER_GEM => "rpi5-rp1-gem",
        _ => "net-pd",
    }
}

#[cfg(all(
    feature = "net",
    feature = "ipv4",
    any(feature = "dns", feature = "icmp")
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetPdError {
    Ipc(SysError),
    #[cfg(feature = "dns")]
    HostnameTooLong,
    #[cfg(feature = "dns")]
    DnsStartFailed,
    #[cfg(feature = "dns")]
    DnsTimeout,
    #[cfg(feature = "dns")]
    DnsFailed,
    #[cfg(feature = "icmp")]
    PingUnavailable,
    #[cfg(feature = "icmp")]
    PingTimeout,
    #[cfg(feature = "icmp")]
    PingFailed,
}

#[cfg(all(
    feature = "net",
    feature = "ipv4",
    any(feature = "dns", feature = "icmp")
))]
impl core::fmt::Display for NetPdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Ipc(_) => "net-pd IPC error",
            #[cfg(feature = "dns")]
            Self::HostnameTooLong => "hostname too long",
            #[cfg(feature = "dns")]
            Self::DnsStartFailed => "dns query failed (no IPv4 or invalid hostname)",
            #[cfg(feature = "dns")]
            Self::DnsTimeout => "dns query timed out",
            #[cfg(feature = "dns")]
            Self::DnsFailed => "dns query failed",
            #[cfg(feature = "icmp")]
            Self::PingUnavailable => "no IPv4 address or ICMP unavailable",
            #[cfg(feature = "icmp")]
            Self::PingTimeout => "ICMP EchoReply timed out",
            #[cfg(feature = "icmp")]
            Self::PingFailed => "ping failed",
        };
        f.write_str(msg)
    }
}

#[cfg(all(
    feature = "net",
    feature = "ipv4",
    any(feature = "dns", feature = "icmp")
))]
impl core::error::Error for NetPdError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ipc(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(all(
    feature = "net",
    feature = "ipv4",
    any(feature = "dns", feature = "icmp")
))]
impl From<SysError> for NetPdError {
    fn from(err: SysError) -> Self {
        Self::Ipc(err)
    }
}

#[cfg(all(feature = "net", feature = "ipv4", feature = "dns"))]
fn net_pd_resolve(host: &str) -> Result<[u8; 4], NetPdError> {
    net_pd_call(net_ipc::encode_dns_chunk(b""))?;
    for chunk in host.as_bytes().chunks(net_ipc::MAX_CHUNK_BYTES) {
        let res = net_pd_call(net_ipc::encode_dns_chunk(chunk))?;
        if res == u64::MAX {
            return Err(NetPdError::HostnameTooLong);
        }
    }
    let start_rep = net_pd_call(net_ipc::encode_dns_start())?;
    let (start_status, _) = net_ipc::decode_dns_reply(start_rep);
    if start_status == net_ipc::DNS_ERR {
        return Err(NetPdError::DnsStartFailed);
    }
    for _ in 0..550 {
        let poll_rep = net_pd_call(net_ipc::encode_dns_poll())?;
        let (status, ip) = net_ipc::decode_dns_reply(poll_rep);
        match status {
            net_ipc::DNS_OK => return Ok(ip),
            net_ipc::DNS_TIMEOUT => return Err(NetPdError::DnsTimeout),
            net_ipc::DNS_ERR => return Err(NetPdError::DnsFailed),
            _ => {
                let _ = newos_user_rt::sleep_ms(10);
            }
        }
    }
    Err(NetPdError::DnsTimeout)
}

#[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
fn net_pd_ping(target: [u8; 4]) -> Result<(u16, u32), NetPdError> {
    let start_rep = net_pd_call(net_ipc::encode_ping_start(target))?;
    let (start_status, _, _) = net_ipc::decode_ping_reply(start_rep);
    if start_status == net_ipc::PING_ERR {
        return Err(NetPdError::PingUnavailable);
    }
    for _ in 0..350 {
        let poll_rep = net_pd_call(net_ipc::encode_ping_poll())?;
        let (status, seq, rtt_ms) = net_ipc::decode_ping_reply(poll_rep);
        match status {
            net_ipc::PING_OK => return Ok((seq, rtt_ms)),
            net_ipc::PING_TIMEOUT => return Err(NetPdError::PingTimeout),
            net_ipc::PING_ERR => return Err(NetPdError::PingFailed),
            _ => {
                let _ = newos_user_rt::sleep_ms(10);
            }
        }
    }
    Err(NetPdError::PingTimeout)
}

#[cfg(feature = "net")]
#[derive(Debug, Clone, Copy)]
enum NicProbeCache {
    Unprobed,
    Absent,
    Found(NicKind),
}

/// EL0 `ShellHost` adapter connecting `newos-shell-core` to `newos-user-rt`, `newos-net`,
/// and the `newos-key-pd`-gated `newos-ssh-pd` interactive shell channel.
struct SupervisorShellHost {
    #[cfg(feature = "net")]
    net_cfg: Option<NetConfig>,
    #[cfg(feature = "net")]
    cached_nic: NicProbeCache,
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
            cached_nic: NicProbeCache::Unprobed,
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
        match self.cached_nic {
            NicProbeCache::Found(nic) => Some(nic),
            NicProbeCache::Absent => None,
            NicProbeCache::Unprobed => {
                let nic = newos_net::probe_nic(|off| {
                    newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off)
                });
                self.cached_nic = nic.map_or(NicProbeCache::Absent, NicProbeCache::Found);
                nic
            }
        }
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
            .as_ref()
            .map_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], NicKind::mac);
        if let Some(n) = nic {
            match subcmd {
                #[cfg(feature = "ipv4")]
                "dhcp" => self.handle_net_direct_dhcp(n, stream, out),
                #[cfg(all(feature = "ipv4", feature = "icmp"))]
                "ping" => self.handle_net_direct_ping(n, arg, stream, out),
                #[cfg(all(feature = "ipv4", feature = "dns"))]
                "resolve" => self.handle_net_direct_resolve(n, arg, stream, out),
                _ => self.handle_net_direct_info(n, mac, stream, out),
            }
        } else if let Ok(status_word) = net_pd_call(net_ipc::encode_poll_status()) {
            handle_net_via_net_pd(subcmd, arg, stream, out, status_word);
        } else {
            match subcmd {
                "dhcp" | "ping" | "resolve" => {
                    let _ = writeln!(out, "net {subcmd}: no NIC or net-pd available");
                }
                _ =>
                {
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
    }

    #[cfg(all(feature = "net", feature = "ipv4"))]
    fn handle_net_direct_dhcp<W: Write>(
        &mut self,
        n: NicKind,
        stream: &mut RecordStream,
        out: &mut W,
    ) {
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

    #[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
    fn handle_net_direct_ping<W: Write>(
        &self,
        n: NicKind,
        arg: Option<&str>,
        stream: &mut RecordStream,
        out: &mut W,
    ) {
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
                    #[cfg(feature = "dns")]
                    {
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
                                let _ = writeln!(out, "net ping: could not resolve '{raw}' ({e})");
                                return;
                            }
                        }
                    }
                    #[cfg(not(feature = "dns"))]
                    {
                        let _ = writeln!(
                            out,
                            "net ping: DNS disabled; pass an IPv4 address instead of '{raw}'"
                        );
                        return;
                    }
                }
            }
        };
        match newos_net::live_icmp_ping(CapMmioDmaTransport, n, &cfg, target, &VIRTIO_DMA, &GEM_DMA)
        {
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

    #[cfg(all(feature = "net", feature = "ipv4", feature = "dns"))]
    fn handle_net_direct_resolve<W: Write>(
        &self,
        n: NicKind,
        arg: Option<&str>,
        stream: &mut RecordStream,
        out: &mut W,
    ) {
        let Some(host) = arg else {
            let _ = writeln!(out, "usage: net resolve <hostname>");
            return;
        };
        let cfg = self.net_cfg.unwrap_or(NetConfig::QEMU_DEFAULT);
        let cycles_per_ms = (newos_user_rt::timer_freq_hz() / 1_000).max(1);
        let mut clock =
            newos_net::CycleClock::new(|| newos_user_rt::read_cycles().unwrap_or(0), cycles_per_ms);
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
                let _ = writeln!(out, "{host} -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
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

    #[cfg(feature = "net")]
    fn handle_net_direct_info<W: Write>(
        &self,
        n: NicKind,
        mac: [u8; 6],
        stream: &mut RecordStream,
        out: &mut W,
    ) {
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

#[cfg(feature = "net")]
fn handle_net_via_net_pd<W: Write>(
    subcmd: &str,
    arg: Option<&str>,
    stream: &mut RecordStream,
    out: &mut W,
    initial_status_word: u64,
) {
    let _ = arg;
    match subcmd {
        #[cfg(feature = "ipv4")]
        "dhcp" => handle_net_pd_dhcp(stream, out),
        #[cfg(all(feature = "ipv4", feature = "icmp"))]
        "ping" => handle_net_pd_ping(arg, stream, out),
        #[cfg(all(feature = "ipv4", feature = "dns"))]
        "resolve" => handle_net_pd_resolve(arg, stream, out),
        _ => handle_net_pd_info(stream, out, initial_status_word),
    }
}

#[cfg(all(feature = "net", feature = "ipv4"))]
fn handle_net_pd_dhcp<W: Write>(stream: &mut RecordStream, out: &mut W) {
    if net_pd_call(net_ipc::encode_dhcp_renew()).is_err() {
        let _ = writeln!(out, "net dhcp: net-pd IPC error");
        return;
    }
    let mut ip = [0u8; 4];
    let mut prefix_len = 0u8;
    let mut gw = [0u8; 4];
    let mut dns = [0u8; 4];
    let mut driver_id = net_ipc::DRIVER_UNKNOWN;
    for _ in 0..500 {
        if let Ok(st) = net_pd_call(net_ipc::encode_poll_status()) {
            let (_, cur_ip) = net_ipc::decode_status_reply(st);
            if cur_ip != [0, 0, 0, 0] {
                ip = cur_ip;
                if let Ok(info) =
                    net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX))
                {
                    let (g, p, d) = net_ipc::decode_gateway_prefix_reply(info);
                    gw = g.unwrap_or([0; 4]);
                    prefix_len = p;
                    driver_id = d;
                }
                if let Ok(dinfo) = net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_DNS)) {
                    dns = net_ipc::decode_dns_info_reply(dinfo).unwrap_or([0; 4]);
                }
                break;
            }
        }
        let _ = newos_user_rt::sleep_ms(10);
    }
    if ip == [0, 0, 0, 0] {
        let _ = writeln!(out, "net dhcp: DHCPv4 lease timed out");
        return;
    }
    let _ = writeln!(
        out,
        "net dhcp ({}, via net-pd): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
        net_pd_driver_name(driver_id),
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        prefix_len,
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
        value: u64::from(prefix_len),
        unit: "bits (IPv4 leased)",
    });
}

#[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
fn handle_net_pd_ping<W: Write>(arg: Option<&str>, stream: &mut RecordStream, out: &mut W) {
    let target = match arg {
        None => {
            let gw = net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX))
                .ok()
                .and_then(|w| net_ipc::decode_gateway_prefix_reply(w).0);
            gw.unwrap_or([10, 0, 2, 2])
        }
        Some(raw) => {
            if let Some(ip) = newos_net::parse_ipv4(raw) {
                ip
            } else if raw.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                let _ = writeln!(out, "net ping: invalid IPv4 address '{raw}'");
                return;
            } else {
                #[cfg(feature = "dns")]
                match net_pd_resolve(raw) {
                    Ok(ip) => ip,
                    Err(e) => {
                        let _ = writeln!(out, "net ping: could not resolve '{raw}' ({e})");
                        return;
                    }
                }
                #[cfg(not(feature = "dns"))]
                {
                    let _ = writeln!(
                        out,
                        "net ping: DNS disabled; pass an IPv4 address instead of '{raw}'"
                    );
                    return;
                }
            }
        }
    };
    match net_pd_ping(target) {
        Ok((seq, rtt_ms)) => {
            let _ = writeln!(
                out,
                "ICMP EchoReply from {}.{}.{}.{} (seq={seq}, rtt={rtt_ms}ms, via net-pd)",
                target[0], target[1], target[2], target[3],
            );
            stream.push(Record::Metric {
                label: "icmp.reply.seq",
                value: u64::from(seq),
                unit: "(ok)",
            });
        }
        Err(e) => {
            let _ = writeln!(out, "net ping: {e}");
        }
    }
}

#[cfg(all(feature = "net", feature = "ipv4", feature = "dns"))]
fn handle_net_pd_resolve<W: Write>(arg: Option<&str>, stream: &mut RecordStream, out: &mut W) {
    let Some(host) = arg else {
        let _ = writeln!(out, "usage: net resolve <hostname>");
        return;
    };
    match net_pd_resolve(host) {
        Ok(ip) => {
            let _ = writeln!(out, "{host} -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
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

#[cfg(feature = "net")]
fn handle_net_pd_info<W: Write>(stream: &mut RecordStream, out: &mut W, initial_status_word: u64) {
    let (_flags, ip) = net_ipc::decode_status_reply(initial_status_word);
    let (gw_opt, prefix_len, driver_id) =
        net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX)).map_or(
            (None, 0, net_ipc::DRIVER_UNKNOWN),
            net_ipc::decode_gateway_prefix_reply,
        );
    let dns_opt = net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_DNS))
        .ok()
        .and_then(net_ipc::decode_dns_info_reply);
    let mac = net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_MAC))
        .map_or([0; 6], net_ipc::decode_mac_reply);
    let gw = gw_opt.unwrap_or([0; 4]);
    let dns = dns_opt.unwrap_or([0; 4]);
    let _ = writeln!(
        out,
        "nic: driver={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (via net-pd)",
        net_pd_driver_name(driver_id),
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
    );
    let _ = writeln!(
        out,
        "ipv4: {}.{}.{}.{}/{} gw={}.{}.{}.{} dns={}.{}.{}.{}",
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        prefix_len,
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
        label: "net.ipv4.prefix",
        value: u64::from(prefix_len),
        unit: "(via net-pd)",
    });
}

impl ShellHost for SupervisorShellHost {
    fn write_debug(&mut self, s: &str) {
        let _ = newos_user_rt::debug_write_all(s);
        if self.ssh_session_authorized {
            for chunk in s.as_bytes().chunks(newos_abi::log_ipc::MAX_CHUNK_BYTES) {
                let word = newos_abi::log_ipc::encode_chunk(chunk);
                for _ in 0..128 {
                    match newos_user_rt::ipc_send(CapId::BOOTSTRAP_SSH_OUT_EP, word) {
                        Err(SysError::WouldBlock) => {
                            let _ = newos_user_rt::yield_now();
                        }
                        Ok(()) | Err(_) => break,
                    }
                }
            }
        }
    }

    newos_user_rt::forward_shell_host_syscalls!();

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
        mode: OutputMode,
    ) {
        #[cfg(not(feature = "net"))]
        {
            let _ = (subcmd, arg, stream);
            if !mode.is_silent() {
                self.write_debug("net: disabled in this build profile\n");
            }
        }
        #[cfg(feature = "net")]
        if mode.is_silent() {
            let mut sink = NullWriter;
            self.handle_net_with(subcmd, arg, stream, &mut sink);
        } else {
            let mut out = StackStrWriter::<1024>::new();
            self.handle_net_with(subcmd, arg, stream, &mut out);
            let s = out.as_str();
            if !s.is_empty() {
                self.write_debug(s);
            }
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
                    "[supervisor-pd] recovered from EL0 fault (bits={bits:#x}) — resuming root supervisor!"
                );
                out.flush();
                let _ = newos_user_rt::set_fault_handler(supervisor_recover);
                run_root_supervisor(&mut out)
            } else if bits == (1 << 6) {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] EL0 fault isolation & supervisor recovery: OK (fault_bits={bits:#x})"
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Success)
            }
            let _ = writeln!(out, "[supervisor-pd] FAIL: unexpected fault bits {bits:#x}");
        }
        other => {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: unexpected fault notification bits: {other:?}"
            );
        }
    }
    out.flush();
    newos_user_rt::exit(ShutdownStatus::Failed)
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
            let pd_id = newos_abi::role_badge::decode_log_pd_id(badge);
            let role_name = newos_abi::role_badge::role_name(role);
            if let Ok(line) = core::str::from_utf8(&line_buf[..n]) {
                // Stamp with kernel-verified sender role + diagnostic PD so no protection domain can forge
                // another's prefix (`N17`).
                let _ = writeln!(out, "[{role_name} pd={pd_id}] {line}");
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

const MAX_ROLES: usize = 6;
const MAX_RESTARTS_IN_WINDOW: u32 = 5;

struct RestartTracker {
    restart_counts: [u32; MAX_ROLES],
    backoff_ms: [u64; MAX_ROLES],
    window_start_cycles: [u64; MAX_ROLES],
    window_ticks: u64,
}

impl RestartTracker {
    const fn new(window_ticks: u64) -> Self {
        Self {
            restart_counts: [0u32; MAX_ROLES],
            backoff_ms: [10u64; MAX_ROLES],
            window_start_cycles: [0u64; MAX_ROLES],
            window_ticks,
        }
    }

    fn handle_pd_fault(&mut self, pd_id: usize, out: &mut BufferedConsole<1024>) {
        let Ok((role, esr, elr)) = newos_user_rt::domain_get_fault_info(pd_id) else {
            return;
        };
        let _ = writeln!(
            out,
            "[supervisor-pd] isolated fault pd={pd_id} role={role:?} ESR={esr:#x} ELR={elr:#018x}"
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
            return;
        }
        let idx = (role as usize).min(MAX_ROLES - 1);
        let now = newos_user_rt::read_cycles().unwrap_or(0);
        if now.saturating_sub(self.window_start_cycles[idx]) > self.window_ticks {
            self.window_start_cycles[idx] = now;
            self.restart_counts[idx] = 0;
            self.backoff_ms[idx] = 10;
        }
        if self.restart_counts[idx] >= MAX_RESTARTS_IN_WINDOW {
            let _ = writeln!(
                out,
                "[supervisor] circuit-breaker tripped for {role:?} (>= {MAX_RESTARTS_IN_WINDOW} crashes/10s)"
            );
            out.flush();
            return;
        }
        let delay = self.backoff_ms[idx];
        let _ = newos_user_rt::sleep_ms(delay);
        self.backoff_ms[idx] = (delay.saturating_mul(2)).min(1_000);
        self.restart_counts[idx] += 1;
        match newos_user_rt::domain_respawn(role) {
            Ok(new_pd_id) => {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] respawned {role:?} as pd={new_pd_id} (backoff={delay}ms)"
                );
                out.flush();
            }
            Err(e) => {
                let _ = writeln!(out, "[supervisor-pd] respawn failed for {role:?}: {e:?}");
                out.flush();
            }
        }
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
    let wdt = {
        let mut candidate = newos_wdt::Bcm2712Watchdog::new(CapWdtTransport);
        if candidate.arm(8_000).is_ok() {
            let _ = writeln!(
                out,
                "[supervisor] BCM2712 hardware watchdog armed (8000 ms)"
            );
            out.flush();
            Some(candidate)
        } else {
            None
        }
    };

    let freq = newos_user_rt::timer_freq_hz().max(1);
    let mut tracker = RestartTracker::new(freq.saturating_mul(10)); // 10 s intensity window

    loop {
        match newos_user_rt::notify_wait(
            CapId::BOOTSTRAP_FAULT_NOTIF,
            newos_abi::supervisor_notif::WAIT_MASK,
            2_000_000_000,
        ) {
            Ok((bits, _timed_out)) => {
                #[cfg(feature = "wdt")]
                if let Some(ref armed_wdt) = wdt {
                    let _ = armed_wdt.pet();
                }
                if bits == 0 {
                    continue;
                }
                if let Some(status) = newos_abi::supervisor_notif::decode_shutdown(bits) {
                    newos_user_rt::exit(status);
                }
                for pd_id in 1..8usize {
                    if (bits & (1u64 << pd_id)) != 0 {
                        tracker.handle_pd_fault(pd_id, out);
                    }
                }
            }
            Err(_) => {
                let _ = newos_user_rt::sleep_ms(50);
            }
        }
    }
}

fn destroy_domain_retry(thread_cap: CapId) -> Result<(), SysError> {
    for attempt in 0..250usize {
        match newos_user_rt::domain_destroy(thread_cap) {
            Ok(()) => return Ok(()),
            Err(SysError::WouldBlock) => {
                if attempt < 16 {
                    let _ = newos_user_rt::yield_now();
                } else {
                    let _ = newos_user_rt::sleep_ms(2);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(SysError::WouldBlock)
}

fn run_ipc_and_ring_selftest(out: &mut BufferedConsole<1024>) {
    const PING_PAYLOAD: u64 = 0xA110_C0DE;
    const RING_BURST: usize = 32;
    const ROUNDTRIPS: u64 = 100;

    // Multi-process TTBR0_EL1 IPC ping-pong with isolated EL0 `worker` process (1-syscall `IpcCall`)
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
}

fn run_shell_selftest(out: &mut BufferedConsole<1024>) {
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
}

#[cfg(all(
    feature = "net",
    any(feature = "ipv4", all(feature = "ipv6", feature = "udp"))
))]
fn run_net_selftest(out: &mut BufferedConsole<1024>) {
    // EL0 Networking: capability-scoped NIC (Pi 5 RP1 GEM or QEMU VirtIO-net) + live DHCPv4 / IPv6 check
    let detected_nic =
        newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off));
    let mac = detected_nic
        .as_ref()
        .map_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], NicKind::mac);
    #[cfg(all(feature = "ipv4", any(feature = "udp", feature = "icmp")))]
    if let Some(nic) = detected_nic {
        run_net_direct_selftest(nic, mac, out);
    } else {
        run_net_pd_selftest(mac, out);
    }
    #[cfg(all(feature = "ipv4", not(any(feature = "udp", feature = "icmp"))))]
    if let Some(nic) = detected_nic {
        run_net_direct_selftest(nic, mac, out);
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
}

#[cfg(all(feature = "net", feature = "ipv4"))]
fn run_net_direct_selftest(nic: NicKind, mac: [u8; 6], out: &mut BufferedConsole<1024>) {
    let cfg = match newos_net::live_dhcp_v4(CapMmioDmaTransport, nic, &VIRTIO_DMA, &GEM_DMA) {
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
            .or(NetConfig::QEMU_DEFAULT.gateway)
            .unwrap_or([10, 0, 2, 2]);
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
    #[cfg(not(feature = "icmp"))]
    let _ = cfg;
}

#[cfg(all(
    feature = "net",
    feature = "ipv4",
    any(feature = "udp", feature = "icmp")
))]
fn run_net_pd_selftest(mac: [u8; 6], out: &mut BufferedConsole<1024>) {
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
    #[cfg(not(feature = "udp"))]
    let _ = mac;

    #[cfg(feature = "icmp")]
    if !newos_user_rt::sys_info().interactive_shell
        && let Ok(status_word) = net_pd_call(net_ipc::encode_poll_status())
    {
        let (_flags, ip) = net_ipc::decode_status_reply(status_word);
        let gw = net_pd_call(net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX))
            .ok()
            .and_then(|w| net_ipc::decode_gateway_prefix_reply(w).0)
            .unwrap_or([10, 0, 2, 2]);
        if ip != [0, 0, 0, 0] {
            match net_pd_ping(gw) {
                Ok((seq, rtt_ms)) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] EL0 LIVE ICMP ping {}.{}.{}.{} (via net-pd): OK (seq={seq}, rtt={rtt_ms}ms)",
                        gw[0], gw[1], gw[2], gw[3],
                    );
                }
                Err(msg) => {
                    let _ = writeln!(
                        out,
                        "[supervisor-pd] FAIL: live ICMP ping via net-pd: {msg}"
                    );
                    out.flush();
                    newos_user_rt::exit(ShutdownStatus::Failed);
                }
            }
        }
    }
}

fn run_phase1_el1_selftest(out: &mut BufferedConsole<1024>) {
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
}

fn run_phase2_worker_cycle(
    cycle: usize,
    log_rx: &mut IpcLogAssembler<256>,
    out: &mut BufferedConsole<1024>,
) -> u64 {
    if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, 0xDEAD_C0DE) != Err(SysError::InvalidCapability)
    {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Phase 2 worker crash trigger (cycle={cycle})"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    let Ok((fault_bits, timed_out)) =
        newos_user_rt::notify_wait(CapId::BOOTSTRAP_FAULT_NOTIF, !0u64, 1_000_000_000)
    else {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Phase 2 fault NotifyWait (cycle={cycle})"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
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
    if newos_user_rt::domain_respawn(newos_abi::DomainRoleId::Worker) != Ok(worker_pd) {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Phase 2 DomainRespawn(Worker) (cycle={cycle})"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    drain_worker_boot_log(log_rx, out);
    let probe = 0xBEEF_0001u64 + cycle as u64;
    if newos_user_rt::ipc_call(CapId::BOOTSTRAP_EP, probe) != Ok((0x5E14, probe + 1)) {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: Phase 2 respawned worker IPC check (cycle={cycle})"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    rem_frames
}

fn run_phase2_worker_chaos_selftest(
    log_rx: &mut IpcLogAssembler<256>,
    out: &mut BufferedConsole<1024>,
) {
    // Phase 2 Chaos Respawn & Zero-Leak Reclamation self-test:
    // First confirm no child protection domain faulted unexpectedly during boot (e.g., stack overflow).
    let pre_phase2_faults = newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF).unwrap_or(0)
        & newos_abi::supervisor_notif::FAULT_PD_MASK;
    if pre_phase2_faults != 0 {
        let _ = writeln!(
            out,
            "[supervisor-pd] FAIL: unexpected boot EL0 fault bits before Phase 2 ({pre_phase2_faults:#x})"
        );
        out.flush();
        newos_user_rt::exit(ShutdownStatus::Failed);
    }
    // Deliberately crash `worker` twice via `udf #0` (`0xDEAD_C0DE`), verify fault notification +
    // `DomainGetFaultInfo`, verify `DomainRespawn` restores IPC service, and prove exact 0-frame leak.
    let mut rem_after_cycle = [0u64; 2];
    for (cycle, rem_slot) in rem_after_cycle.iter_mut().enumerate() {
        *rem_slot = run_phase2_worker_cycle(cycle, log_rx, out);
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
}

#[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
fn verify_respawned_net_pd(out: &mut BufferedConsole<1024>) {
    // Wait briefly for respawned `net-pd` to re-initialize VirtIO-Net and respond on BOOTSTRAP_NET_EP.
    for _ in 0..20usize {
        if net_pd_ping([10, 0, 2, 2]).is_ok() {
            return;
        }
        let _ = newos_user_rt::sleep_ms(25);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] FAIL: Phase 2b respawned net-pd did not pass live ICMP ping"
    );
    out.flush();
    newos_user_rt::exit(ShutdownStatus::Failed);
}

fn run_phase2b_server_chaos_selftest(out: &mut BufferedConsole<1024>) {
    // Phase 2b All-Server Chaos Respawn & Zero-Leak Verification:
    // Destroy and respawn every isolated permanent server (Shell, Net, Key, Ssh) via its
    // deterministic child `Thread` capability and verify frame reclamation + post-respawn liveness.
    let servers = [
        (
            "Shell",
            CapId::BOOTSTRAP_SHELL_THREAD,
            newos_abi::DomainRoleId::Shell,
        ),
        (
            "Net",
            CapId::BOOTSTRAP_NET_THREAD,
            newos_abi::DomainRoleId::Net,
        ),
        (
            "Key",
            CapId::BOOTSTRAP_KEY_THREAD,
            newos_abi::DomainRoleId::Key,
        ),
        (
            "Ssh",
            CapId::BOOTSTRAP_SSH_THREAD,
            newos_abi::DomainRoleId::Ssh,
        ),
    ];
    let mut respawned_count = 0usize;
    #[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
    let mut net_respawned = false;
    for (name, cap, role) in servers {
        match destroy_domain_retry(cap) {
            Ok(()) => {}
            Err(SysError::InvalidCapability) => continue,
            Err(e) => {
                let _ = writeln!(
                    out,
                    "[supervisor-pd] FAIL: Phase 2b DomainDestroy({name}) error: {e:?}"
                );
                out.flush();
                newos_user_rt::exit(ShutdownStatus::Failed);
            }
        }
        let Ok((_rem, reclaimed)) = newos_user_rt::mem_stats() else {
            let _ = writeln!(out, "[supervisor-pd] FAIL: Phase 2b MemStats({name})");
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        };
        if reclaimed == 0 {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2b expected reclaimed frames > 0 after destroying {name}"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        if let Err(e) = newos_user_rt::domain_respawn(role) {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2b DomainRespawn({name}) error: {e:?}"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
        respawned_count += 1;
        #[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
        if role == newos_abi::DomainRoleId::Net {
            net_respawned = true;
        }
    }
    if respawned_count > 0 {
        let _ = newos_user_rt::sleep_ms(30);
        let post_faults = newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF).unwrap_or(0)
            & newos_abi::supervisor_notif::FAULT_PD_MASK;
        if post_faults != 0 {
            let _ = writeln!(
                out,
                "[supervisor-pd] FAIL: Phase 2b unexpected fault after server respawn ({post_faults:#x})"
            );
            out.flush();
            newos_user_rt::exit(ShutdownStatus::Failed);
        }
    }
    #[cfg(all(feature = "net", feature = "ipv4", feature = "icmp"))]
    if net_respawned {
        verify_respawned_net_pd(out);
    }
    let _ = writeln!(
        out,
        "[supervisor-pd] Phase 2b multi-server chaos respawn (respawned={respawned_count}): OK"
    );
    out.flush();
}

fn run_phase3a_aarch64_bench(out: &mut BufferedConsole<1024>) {
    // Phase 3a On-Target AArch64 Cycle & Tail-Latency Benchmark Suite (256 samples each):
    // Measures real EL0<->EL1<->EL0 IpcCall round-trip, NotifySignal+NotifyWait fastpath,
    // and shared-memory SpscRing 4 KiB framed byte burst on AArch64 CNTVCT_EL0.
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

pub fn main() -> ! {
    let mut out = BufferedConsole::<1024>::new();
    let mut log_rx = IpcLogAssembler::<256>::new();
    let info = newos_user_rt::sys_info();
    let _ = newos_user_rt::set_fault_handler(supervisor_recover);

    let boot_notif = newos_user_rt::notify_poll(CapId::BOOTSTRAP_FAULT_NOTIF).unwrap_or(0);
    if (boot_notif & newos_abi::supervisor_notif::SUPERVISOR_RESPAWNED_BIT) != 0 {
        if info.interactive_shell {
            let _ = writeln!(
                out,
                "[supervisor-pd] resumed in fresh TTBR0_EL1 VSpace after PD 0 respawn"
            );
            out.flush();
            run_root_supervisor(&mut out)
        }
        let _ = writeln!(
            out,
            "[supervisor-pd] Phase 2c PD 0 fresh-VSpace respawn: OK"
        );
        let _ = writeln!(
            out,
            "[supervisor-pd] triggering deliberate EL0 hardware fault (`udf #0`) to verify crash isolation..."
        );
        out.flush();
        newos_user_rt::trigger_user_fault()
    }

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

    run_ipc_and_ring_selftest(&mut out);
    run_shell_selftest(&mut out);
    #[cfg(all(
        feature = "net",
        any(feature = "ipv4", all(feature = "ipv6", feature = "udp"))
    ))]
    run_net_selftest(&mut out);
    run_phase1_el1_selftest(&mut out);
    run_phase2_worker_chaos_selftest(&mut log_rx, &mut out);
    run_phase2b_server_chaos_selftest(&mut out);
    run_phase3a_aarch64_bench(&mut out);

    // Phase 2c: Request a full fresh-VSpace PD 0 respawn via `ThreadExit`.
    // On re-entry, `main()` observes `SUPERVISOR_RESPAWNED_BIT`, logs Phase 2c OK, and triggers
    // the deliberate `udf #0` EL0 fault to verify in-place `supervisor_recover()` as well.
    let _ = writeln!(
        out,
        "[supervisor-pd] triggering fresh-VSpace PD 0 respawn (`ThreadExit`) to verify supervisor self-healing..."
    );
    out.flush();
    newos_user_rt::thread_exit()
}
