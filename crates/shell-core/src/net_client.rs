//! Capability-isolated `newos-net-pd` IPC client for EL0 shell domains.
//!
//! Shared by both `newos-shell-pd` (standalone interactive shell) and `newos-supervisor-pd`
//! (fallback/test shell) so both domains execute `net [dhcp|ping|resolve]` over
//! `CapId::BOOTSTRAP_NET_EP` with zero NIC MMIO or `smoltcp` dependencies.

use core::fmt::{self, Write};
use core::net::Ipv4Addr;
use newos_abi::{SysError, net_ipc};

use crate::shell::{Record, RecordStream};

/// Fixed-capacity UTF-8 buffer implementing `core::fmt::Write` so shell commands can
/// format text and route it through `ShellHost::write_debug` (serial + SSH).
pub struct StackStrWriter<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackStrWriter<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> Default for StackStrWriter<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Write for StackStrWriter<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
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

/// Transport boundary for calling `newos-net-pd` over `CapId::BOOTSTRAP_NET_EP`.
pub trait NetPdClient {
    /// Send a single register-only `IpcCall` request word to `newos-net-pd` and return the reply word.
    ///
    /// # Errors
    /// Returns [`SysError`] if the endpoint capability is absent, lacks rights, or blocks.
    fn ipc_call(&mut self, req: u64) -> Result<u64, SysError>;

    /// Sleep for approximately `ms` milliseconds between non-blocking status polls.
    fn sleep_ms(&mut self, ms: u64);
}

/// Structured error returned by `newos-net-pd` diagnostic/control IPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetPdError {
    Ipc(SysError),
    HostnameTooLong,
    DnsStartFailed,
    DnsTimeout,
    DnsFailed,
    PingUnavailable,
    PingTimeout,
    PingFailed,
}

impl fmt::Display for NetPdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Ipc(_) => "net-pd IPC error",
            Self::HostnameTooLong => "hostname too long",
            Self::DnsStartFailed => "dns query failed (no IPv4 or invalid hostname)",
            Self::DnsTimeout => "dns query timed out",
            Self::DnsFailed => "dns query failed",
            Self::PingUnavailable => "no IPv4 address or ICMP unavailable",
            Self::PingTimeout => "ICMP EchoReply timed out",
            Self::PingFailed => "ping failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for NetPdError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ipc(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SysError> for NetPdError {
    fn from(err: SysError) -> Self {
        Self::Ipc(err)
    }
}

/// Invoke `newos-net-pd` with bounded `WouldBlock` retry.
///
/// # Errors
/// Returns [`SysError`] if `newos-net-pd` is unreachable or stays busy past the retry bound.
pub fn call_with_retry<C: NetPdClient>(client: &mut C, req: u64) -> Result<u64, SysError> {
    for _ in 0..500 {
        match client.ipc_call(req) {
            Ok(reply) => return Ok(reply),
            Err(SysError::WouldBlock) => client.sleep_ms(1),
            Err(e) => return Err(e),
        }
    }
    Err(SysError::WouldBlock)
}

/// Poll `newos-net-pd` status word (`OP_POLL_STATUS`).
///
/// # Errors
/// Returns [`SysError`] if `BOOTSTRAP_NET_EP` is absent or `newos-net-pd` is unreachable.
pub fn poll_status<C: NetPdClient>(client: &mut C) -> Result<u64, SysError> {
    call_with_retry(client, net_ipc::encode_poll_status())
}

#[must_use]
const fn driver_name(driver_id: u8) -> &'static str {
    match driver_id {
        net_ipc::DRIVER_VIRTIO => "virtio-net",
        net_ipc::DRIVER_GEM => "rpi5-rp1-gem",
        _ => "net-pd",
    }
}

#[must_use]
fn parse_ipv4(raw: &str) -> Option<[u8; 4]> {
    raw.parse::<Ipv4Addr>().ok().map(|addr| addr.octets())
}

/// Resolve a hostname to an IPv4 address via `newos-net-pd`.
///
/// # Errors
/// Returns [`NetPdError`] on IPC failure, oversized hostname, or DNS timeout/failure.
pub fn resolve_hostname<C: NetPdClient>(client: &mut C, host: &str) -> Result<[u8; 4], NetPdError> {
    call_with_retry(client, net_ipc::encode_dns_chunk(b""))?;
    for chunk in host.as_bytes().chunks(net_ipc::MAX_CHUNK_BYTES) {
        let res = call_with_retry(client, net_ipc::encode_dns_chunk(chunk))?;
        if res == u64::MAX {
            return Err(NetPdError::HostnameTooLong);
        }
    }
    let start_rep = call_with_retry(client, net_ipc::encode_dns_start())?;
    let (start_status, _) = net_ipc::decode_dns_reply(start_rep);
    if start_status == net_ipc::DNS_ERR {
        return Err(NetPdError::DnsStartFailed);
    }
    for _ in 0..550 {
        let poll_rep = call_with_retry(client, net_ipc::encode_dns_poll())?;
        let (status, ip) = net_ipc::decode_dns_reply(poll_rep);
        match status {
            net_ipc::DNS_OK => return Ok(ip),
            net_ipc::DNS_TIMEOUT => return Err(NetPdError::DnsTimeout),
            net_ipc::DNS_ERR => return Err(NetPdError::DnsFailed),
            _ => client.sleep_ms(10),
        }
    }
    Err(NetPdError::DnsTimeout)
}

/// Send an `ICMPv4` echo request via `newos-net-pd` and wait for the reply.
///
/// # Errors
/// Returns [`NetPdError`] if ICMP is unavailable, times out, or fails.
pub fn ping_ipv4<C: NetPdClient>(
    client: &mut C,
    target: [u8; 4],
) -> Result<(u16, u32), NetPdError> {
    let start_rep = call_with_retry(client, net_ipc::encode_ping_start(target))?;
    let (start_status, _, _) = net_ipc::decode_ping_reply(start_rep);
    if start_status == net_ipc::PING_ERR {
        return Err(NetPdError::PingUnavailable);
    }
    for _ in 0..350 {
        let poll_rep = call_with_retry(client, net_ipc::encode_ping_poll())?;
        let (status, seq, rtt_ms) = net_ipc::decode_ping_reply(poll_rep);
        match status {
            net_ipc::PING_OK => return Ok((seq, rtt_ms)),
            net_ipc::PING_TIMEOUT => return Err(NetPdError::PingTimeout),
            net_ipc::PING_ERR => return Err(NetPdError::PingFailed),
            _ => client.sleep_ms(10),
        }
    }
    Err(NetPdError::PingTimeout)
}

/// Dispatch `net [dhcp|ping|resolve]` against `newos-net-pd` over `CapId::BOOTSTRAP_NET_EP`.
pub fn handle_net_via_net_pd<C: NetPdClient, W: Write>(
    client: &mut C,
    subcmd: &str,
    arg: Option<&str>,
    stream: &mut RecordStream,
    out: &mut W,
    initial_status_word: u64,
) {
    match subcmd {
        "dhcp" => handle_dhcp(client, stream, out),
        "ping" => handle_ping(client, arg, stream, out),
        "resolve" => handle_resolve(client, arg, stream, out),
        _ => handle_info(client, stream, out, initial_status_word),
    }
}

fn handle_dhcp<C: NetPdClient, W: Write>(client: &mut C, stream: &mut RecordStream, out: &mut W) {
    if call_with_retry(client, net_ipc::encode_dhcp_renew()).is_err() {
        let _ = writeln!(out, "net dhcp: net-pd IPC error");
        return;
    }
    let mut ip = [0u8; 4];
    let mut prefix_len = 0u8;
    let mut gw = [0u8; 4];
    let mut dns = [0u8; 4];
    let mut driver_id = net_ipc::DRIVER_UNKNOWN;
    for _ in 0..500 {
        if let Ok(st) = call_with_retry(client, net_ipc::encode_poll_status()) {
            let (_, cur_ip) = net_ipc::decode_status_reply(st);
            if cur_ip != [0, 0, 0, 0] {
                ip = cur_ip;
                if let Ok(info) = call_with_retry(
                    client,
                    net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX),
                ) {
                    let (g, p, d) = net_ipc::decode_gateway_prefix_reply(info);
                    gw = g.unwrap_or([0; 4]);
                    prefix_len = p;
                    driver_id = d;
                }
                if let Ok(dinfo) =
                    call_with_retry(client, net_ipc::encode_get_net_info(net_ipc::INFO_DNS))
                {
                    dns = net_ipc::decode_dns_info_reply(dinfo).unwrap_or([0; 4]);
                }
                break;
            }
        }
        client.sleep_ms(10);
    }
    if ip == [0, 0, 0, 0] {
        let _ = writeln!(out, "net dhcp: DHCPv4 lease timed out");
        return;
    }
    let _ = writeln!(
        out,
        "net dhcp ({}, via net-pd): ip={}.{}.{}.{}/{}, gw={}.{}.{}.{}, dns={}.{}.{}.{}",
        driver_name(driver_id),
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

fn handle_ping<C: NetPdClient, W: Write>(
    client: &mut C,
    arg: Option<&str>,
    stream: &mut RecordStream,
    out: &mut W,
) {
    let target = match arg {
        None => {
            let gw = call_with_retry(
                client,
                net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX),
            )
            .ok()
            .and_then(|w| net_ipc::decode_gateway_prefix_reply(w).0);
            gw.unwrap_or([10, 0, 2, 2])
        }
        Some(raw) => {
            if let Some(ip) = parse_ipv4(raw) {
                ip
            } else if raw.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                let _ = writeln!(out, "net ping: invalid IPv4 address '{raw}'");
                return;
            } else {
                match resolve_hostname(client, raw) {
                    Ok(ip) => ip,
                    Err(e) => {
                        let _ = writeln!(out, "net ping: could not resolve '{raw}' ({e})");
                        return;
                    }
                }
            }
        }
    };
    match ping_ipv4(client, target) {
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

fn handle_resolve<C: NetPdClient, W: Write>(
    client: &mut C,
    arg: Option<&str>,
    stream: &mut RecordStream,
    out: &mut W,
) {
    let Some(host) = arg else {
        let _ = writeln!(out, "usage: net resolve <hostname>");
        return;
    };
    match resolve_hostname(client, host) {
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

fn handle_info<C: NetPdClient, W: Write>(
    client: &mut C,
    stream: &mut RecordStream,
    out: &mut W,
    initial_status_word: u64,
) {
    let (_flags, ip) = net_ipc::decode_status_reply(initial_status_word);
    let (gw_opt, prefix_len, driver_id) = call_with_retry(
        client,
        net_ipc::encode_get_net_info(net_ipc::INFO_GATEWAY_PREFIX),
    )
    .map_or(
        (None, 0, net_ipc::DRIVER_UNKNOWN),
        net_ipc::decode_gateway_prefix_reply,
    );
    let dns_opt = call_with_retry(client, net_ipc::encode_get_net_info(net_ipc::INFO_DNS))
        .ok()
        .and_then(net_ipc::decode_dns_info_reply);
    let mac = call_with_retry(client, net_ipc::encode_get_net_info(net_ipc::INFO_MAC))
        .map_or([0; 6], net_ipc::decode_mac_reply);
    let gw = gw_opt.unwrap_or([0; 4]);
    let dns = dns_opt.unwrap_or([0; 4]);
    let _ = writeln!(
        out,
        "nic: driver={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (via net-pd)",
        driver_name(driver_id),
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

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNetPd {
        ip: [u8; 4],
        prefix_len: u8,
        gw: Option<[u8; 4]>,
        dns: Option<[u8; 4]>,
        mac: [u8; 6],
        driver_id: u8,
        dns_buf: [u8; 128],
        dns_len: usize,
        dns_result: (u8, [u8; 4]),
        ping_target: Option<[u8; 4]>,
        ping_result: (u8, u16, u32),
        sleeps: usize,
    }

    impl MockNetPd {
        fn new() -> Self {
            Self {
                ip: [10, 0, 2, 15],
                prefix_len: 24,
                gw: Some([10, 0, 2, 2]),
                dns: Some([10, 0, 2, 3]),
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                driver_id: net_ipc::DRIVER_VIRTIO,
                dns_buf: [0; 128],
                dns_len: 0,
                dns_result: (net_ipc::DNS_OK, [142, 250, 74, 206]),
                ping_target: None,
                ping_result: (net_ipc::PING_OK, 7, 12),
                sleeps: 0,
            }
        }
    }

    impl NetPdClient for MockNetPd {
        fn ipc_call(&mut self, req: u64) -> Result<u64, SysError> {
            let (op, buf, len) = net_ipc::decode_request(req);
            match op {
                net_ipc::OP_POLL_STATUS => Ok(net_ipc::encode_status_reply(0, self.ip)),
                net_ipc::OP_GET_NET_INFO => match net_ipc::decode_get_net_info_selector(req) {
                    net_ipc::INFO_GATEWAY_PREFIX => Ok(net_ipc::encode_gateway_prefix_reply(
                        self.gw,
                        self.prefix_len,
                        self.driver_id,
                    )),
                    net_ipc::INFO_DNS => Ok(net_ipc::encode_dns_info_reply(self.dns)),
                    net_ipc::INFO_MAC => Ok(net_ipc::encode_mac_reply(self.mac)),
                    _ => Ok(0),
                },
                net_ipc::OP_DHCP_RENEW => Ok(1),
                net_ipc::OP_PING_START => {
                    self.ping_target = Some(net_ipc::decode_ping_start(req));
                    if self.ping_result.0 == net_ipc::PING_ERR {
                        Ok(net_ipc::encode_ping_reply(net_ipc::PING_ERR, 0, 0))
                    } else {
                        Ok(net_ipc::encode_ping_reply(
                            net_ipc::PING_PENDING,
                            self.ping_result.1,
                            0,
                        ))
                    }
                }
                net_ipc::OP_PING_POLL => Ok(net_ipc::encode_ping_reply(
                    self.ping_result.0,
                    self.ping_result.1,
                    self.ping_result.2,
                )),
                net_ipc::OP_DNS_CHUNK_BASE => {
                    if len == 0 {
                        self.dns_len = 0;
                        Ok(0)
                    } else if self.dns_len + len <= self.dns_buf.len() {
                        self.dns_buf[self.dns_len..self.dns_len + len].copy_from_slice(&buf[..len]);
                        self.dns_len += len;
                        Ok(self.dns_len as u64)
                    } else {
                        Ok(u64::MAX)
                    }
                }
                net_ipc::OP_DNS_START => {
                    Ok(net_ipc::encode_dns_reply(net_ipc::DNS_PENDING, [0; 4]))
                }
                net_ipc::OP_DNS_POLL => Ok(net_ipc::encode_dns_reply(
                    self.dns_result.0,
                    self.dns_result.1,
                )),
                _ => Ok(0),
            }
        }

        fn sleep_ms(&mut self, _ms: u64) {
            self.sleeps += 1;
        }
    }

    #[test]
    fn ping_ipv4_emits_reply_and_metric() {
        let mut client = MockNetPd::new();
        let mut stream = RecordStream::new();
        let mut out = StackStrWriter::<512>::new();
        let status = poll_status(&mut client).expect("status");

        handle_net_via_net_pd(
            &mut client,
            "ping",
            Some("8.8.8.8"),
            &mut stream,
            &mut out,
            status,
        );

        assert_eq!(client.ping_target, Some([8, 8, 8, 8]));
        assert!(
            out.as_str()
                .contains("ICMP EchoReply from 8.8.8.8 (seq=7, rtt=12ms, via net-pd)")
        );
        assert_eq!(
            stream.first(),
            Some(Record::Metric {
                label: "icmp.reply.seq",
                value: 7,
                unit: "(ok)",
            })
        );
    }

    #[test]
    fn ping_hostname_resolves_dns_then_pings_target() {
        let mut client = MockNetPd::new();
        let mut stream = RecordStream::new();
        let mut out = StackStrWriter::<512>::new();
        let status = poll_status(&mut client).expect("status");

        handle_net_via_net_pd(
            &mut client,
            "ping",
            Some("google.com"),
            &mut stream,
            &mut out,
            status,
        );

        assert_eq!(&client.dns_buf[..client.dns_len], b"google.com");
        assert_eq!(client.ping_target, Some([142, 250, 74, 206]));
        assert!(
            out.as_str()
                .contains("ICMP EchoReply from 142.250.74.206 (seq=7, rtt=12ms, via net-pd)")
        );
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn ping_invalid_ipv4_reports_error_without_ipc() {
        let mut client = MockNetPd::new();
        let mut stream = RecordStream::new();
        let mut out = StackStrWriter::<512>::new();
        let status = poll_status(&mut client).expect("status");

        handle_net_via_net_pd(
            &mut client,
            "ping",
            Some("999.0.0.1"),
            &mut stream,
            &mut out,
            status,
        );

        assert_eq!(client.ping_target, None);
        assert!(
            out.as_str()
                .contains("net ping: invalid IPv4 address '999.0.0.1'")
        );
        assert!(stream.is_empty());
    }

    #[test]
    fn info_dhcp_and_resolve_work_via_net_pd() {
        let mut client = MockNetPd::new();
        let mut stream = RecordStream::new();
        let mut out = StackStrWriter::<512>::new();
        let status = poll_status(&mut client).expect("status");

        handle_net_via_net_pd(&mut client, "", None, &mut stream, &mut out, status);
        assert!(out.as_str().contains("nic: driver=virtio-net"));
        assert!(out.as_str().contains("ipv4: 10.0.2.15/24"));
        assert_eq!(stream.len(), 1);

        stream.clear();
        let mut out_dhcp = StackStrWriter::<512>::new();
        handle_net_via_net_pd(
            &mut client,
            "dhcp",
            None,
            &mut stream,
            &mut out_dhcp,
            status,
        );
        assert!(
            out_dhcp
                .as_str()
                .contains("net dhcp (virtio-net, via net-pd)")
        );
        assert_eq!(stream.len(), 1);

        stream.clear();
        let mut out_dns = StackStrWriter::<512>::new();
        handle_net_via_net_pd(
            &mut client,
            "resolve",
            Some("google.com"),
            &mut stream,
            &mut out_dns,
            status,
        );
        assert!(out_dns.as_str().contains("google.com -> 142.250.74.206"));
        assert_eq!(stream.len(), 1);
    }
}
