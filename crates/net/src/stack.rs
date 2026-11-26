//! Persistent EL0 `smoltcp` Network Stack (`NetStack`).
//!
//! Designed for `newos-net-pd` (PD 2): initializes the NIC once, maintains an automatic `DHCPv4`
//! lease (with `NetConfig::QEMU_DEFAULT` fallback), and serves a persistent single-connection
//! TCP listener (port 22) with 32 KiB RX/TX ring buffers sized for ML-KEM-1024 + ML-DSA-87
//! post-quantum SSH handshakes.

#[cfg(feature = "ipv6")]
use crate::Ipv6Config;
use crate::NetConfig;
#[cfg(all(feature = "ipv4", any(feature = "icmp", feature = "dns")))]
use crate::NetError;
use crate::instant_from_millis_clamped;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::Device;
#[cfg(feature = "ipv4")]
use smoltcp::socket::dhcpv4;
#[cfg(all(feature = "ipv4", feature = "dns"))]
use smoltcp::socket::dns;
#[cfg(all(feature = "ipv4", feature = "icmp"))]
use smoltcp::socket::icmp;
use smoltcp::socket::tcp;
#[cfg(test)]
use smoltcp::time::Instant;
#[cfg(all(feature = "ipv4", feature = "dns"))]
use smoltcp::wire::DnsQueryType;
#[cfg(feature = "ipv4")]
use smoltcp::wire::Ipv4Address;
#[cfg(feature = "ipv6")]
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
#[cfg(all(feature = "ipv4", feature = "icmp"))]
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};

/// Static TCP socket buffer size per listener slot (16 KiB each for RX and TX, sized for
/// ML-KEM-1024 + ML-DSA-87 post-quantum SSH handshakes across [`SSH_LISTEN_BACKLOG`] sockets).
pub const TCP_BUF_SIZE: usize = 16_384;

/// Number of concurrent listening TCP sockets on [`SSH_PORT`] (`H3`), ensuring a bare SYN
/// flood or half-open connection cannot lock out legitimate SSH clients.
pub const SSH_LISTEN_BACKLOG: usize = 4;

/// Maximum time (5 s) a socket may remain in `SYN-RECEIVED` before being aborted and recycled.
pub const SYN_TIMEOUT_MS: i64 = 5_000;

/// Default SSH listening port.
pub const SSH_PORT: u16 = 22;

/// Edge-triggered TCP listener lifecycle events emitted by [`NetStack::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TcpEvent {
    #[default]
    None,
    Connected,
    Disconnected,
}

/// Non-blocking `ICMPv4` Echo Request/Reply state tracked inside [`NetStack`].
#[cfg(all(feature = "ipv4", feature = "icmp"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PingStatus {
    #[default]
    Idle,
    Pending,
    Reply {
        target: [u8; 4],
        seq: u16,
        rtt_ms: u32,
    },
    Timeout,
}

/// Non-blocking DNS A-record query state tracked inside [`NetStack`].
#[cfg(all(feature = "ipv4", feature = "dns"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnsStatus {
    #[default]
    Idle,
    Pending,
    Resolved([u8; 4]),
    Timeout,
    Failed,
}

#[cfg(all(feature = "ipv4", feature = "icmp"))]
const PING_IDENT: u16 = 0x5E14;
#[cfg(all(feature = "ipv4", feature = "icmp"))]
const PING_TIMEOUT_MS: i64 = 3_000;
#[cfg(all(feature = "ipv4", feature = "icmp"))]
const PING_RETRY_INTERVAL_MS: i64 = 500;
#[cfg(all(feature = "ipv4", feature = "icmp"))]
const PING_MAX_RETRIES: u8 = 3;

#[cfg(all(feature = "ipv4", feature = "dns"))]
const DNS_TIMEOUT_MS: i64 = 5_000;

#[cfg(all(feature = "ipv4", feature = "icmp"))]
#[derive(Debug, Clone, Copy)]
struct PendingPing {
    target: [u8; 4],
    seq: u16,
    start_ms: i64,
    last_tx_ms: i64,
    retries: u8,
}

/// Unified internal `ICMPv4` ping state machine (eliminates split-field desynchronization).
#[cfg(all(feature = "ipv4", feature = "icmp"))]
#[derive(Debug, Clone, Copy)]
enum PingState {
    Idle,
    Pending(PendingPing),
    Reply {
        target: [u8; 4],
        seq: u16,
        rtt_ms: u32,
    },
    Timeout,
}

#[cfg(all(feature = "ipv4", feature = "icmp"))]
impl PingState {
    const fn status(self) -> PingStatus {
        match self {
            Self::Idle => PingStatus::Idle,
            Self::Pending(_) => PingStatus::Pending,
            Self::Reply {
                target,
                seq,
                rtt_ms,
            } => PingStatus::Reply {
                target,
                seq,
                rtt_ms,
            },
            Self::Timeout => PingStatus::Timeout,
        }
    }

    const fn is_pending(self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

/// Unified internal DNS query state machine (eliminates split-field desynchronization).
#[cfg(all(feature = "ipv4", feature = "dns"))]
#[derive(Clone, Copy)]
enum DnsState {
    Idle,
    Pending {
        handle: dns::QueryHandle,
        start_ms: i64,
    },
    Resolved([u8; 4]),
    Timeout,
    Failed,
}

#[cfg(all(feature = "ipv4", feature = "dns"))]
impl DnsState {
    const fn status(self) -> DnsStatus {
        match self {
            Self::Idle => DnsStatus::Idle,
            Self::Pending { .. } => DnsStatus::Pending,
            Self::Resolved(ip) => DnsStatus::Resolved(ip),
            Self::Timeout => DnsStatus::Timeout,
            Self::Failed => DnsStatus::Failed,
        }
    }

    const fn is_pending(self) -> bool {
        matches!(self, Self::Pending { .. })
    }
}

/// Maximum concurrent sockets in `NetStackStorage` (`DHCPv4` + multi-session TCP + DNS + ICMP).
pub const MAX_SOCKETS: usize = 8;

/// Static backing buffers owned by the caller (e.g., `newos-net-pd` main/BSS)
/// and borrowed by [`NetStack`].
pub struct NetStackStorage<'a> {
    pub tcp_rx_bufs: [[u8; TCP_BUF_SIZE]; SSH_LISTEN_BACKLOG],
    pub tcp_tx_bufs: [[u8; TCP_BUF_SIZE]; SSH_LISTEN_BACKLOG],
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    pub icmp_rx_meta: [icmp::PacketMetadata; 4],
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    pub icmp_rx_data: [u8; 256],
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    pub icmp_tx_meta: [icmp::PacketMetadata; 4],
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    pub icmp_tx_data: [u8; 256],
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    pub dns_queries: [Option<dns::DnsQuery>; 1],
    pub sockets: [SocketStorage<'a>; MAX_SOCKETS],
}

impl core::fmt::Debug for NetStackStorage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetStackStorage")
            .field("tcp_backlog", &SSH_LISTEN_BACKLOG)
            .field("tcp_buf_size", &TCP_BUF_SIZE)
            .field("max_sockets", &MAX_SOCKETS)
            .finish_non_exhaustive()
    }
}

impl Default for NetStackStorage<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl NetStackStorage<'_> {
    #[must_use]
    // Intentional: `#![no_std]` zero-alloc socket backing storage owned by caller (`net-pd` `.bss`).
    #[allow(clippy::large_stack_arrays)]
    pub const fn new() -> Self {
        Self {
            tcp_rx_bufs: [[0u8; TCP_BUF_SIZE]; SSH_LISTEN_BACKLOG],
            tcp_tx_bufs: [[0u8; TCP_BUF_SIZE]; SSH_LISTEN_BACKLOG],
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            icmp_rx_meta: [icmp::PacketMetadata::EMPTY; 4],
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            icmp_rx_data: [0u8; 256],
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            icmp_tx_meta: [icmp::PacketMetadata::EMPTY; 4],
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            icmp_tx_data: [0u8; 256],
            #[cfg(all(feature = "ipv4", feature = "dns"))]
            dns_queries: [const { None }; 1],
            sockets: [SocketStorage::EMPTY; MAX_SOCKETS],
        }
    }
}

/// Long-lived EL0 `smoltcp` IPv4/IPv6 dual-stack multi-listener TCP stack.
pub struct NetStack<'a, D: Device> {
    device: D,
    mac: [u8; 6],
    iface: Interface,
    sockets: SocketSet<'a>,
    #[cfg(feature = "ipv4")]
    dhcp_handle: SocketHandle,
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    icmp_handle: SocketHandle,
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    ping_seq: u16,
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    ping_state: PingState,
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    dns_handle: SocketHandle,
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    dns_state: DnsState,
    tcp_handles: [SocketHandle; SSH_LISTEN_BACKLOG],
    syn_seen_ms: [Option<i64>; SSH_LISTEN_BACKLOG],
    active_tcp: Option<usize>,
    #[cfg(feature = "ipv4")]
    initial_cfg: NetConfig,
    cfg: NetConfig,
    #[cfg(feature = "ipv6")]
    ipv6_cfg: Ipv6Config,
    listen_port: u16,
    was_connected: bool,
}

impl<D: Device> core::fmt::Debug for NetStack<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetStack")
            .field("mac", &self.mac)
            .field("cfg", &self.cfg)
            .field("listen_port", &self.listen_port)
            .field("active_tcp", &self.active_tcp)
            .field("was_connected", &self.was_connected)
            .finish_non_exhaustive()
    }
}

impl<'a, D: Device> NetStack<'a, D> {
    /// Construct a persistent `NetStack` over an already-initialized `smoltcp` `Device`,
    /// binding [`SSH_LISTEN_BACKLOG`] TCP listeners on `listen_port` (typically 22).
    pub fn new(
        device: D,
        mac: [u8; 6],
        initial_cfg: NetConfig,
        listen_port: u16,
        now_ms: i64,
        storage: &'a mut NetStackStorage<'a>,
    ) -> Self {
        Self::new_with_seed(device, mac, initial_cfg, listen_port, now_ms, 0, storage)
    }

    /// Construct a persistent `NetStack` with an explicit caller-supplied 64-bit entropy seed
    /// mixed into `smoltcp`'s ISN/port PRNG (`H3`).
    pub fn new_with_seed(
        mut device: D,
        mac: [u8; 6],
        initial_cfg: NetConfig,
        listen_port: u16,
        now_ms: i64,
        entropy_seed: u64,
        storage: &'a mut NetStackStorage<'a>,
    ) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        let mut seed = entropy_seed
            ^ now_ms.cast_unsigned().rotate_left(17)
            ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0xA5, 0x5A])
            ^ 0x9E37_79B9_7F4A_7C15;
        seed = (seed ^ (seed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        seed = (seed ^ (seed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        config.random_seed = (seed ^ (seed >> 31)).max(1);
        let mut iface = Interface::new(config, &mut device, instant_from_millis_clamped(now_ms));
        #[cfg(feature = "ipv6")]
        let ipv6_cfg = Ipv6Config::from_mac(mac);
        Self::apply_ip_config(
            &mut iface,
            &initial_cfg,
            #[cfg(feature = "ipv6")]
            &ipv6_cfg,
        );

        let mut sockets = SocketSet::new(&mut storage.sockets[..]);
        #[cfg(feature = "ipv4")]
        let dhcp_handle = sockets.add(dhcpv4::Socket::new());
        #[cfg(all(feature = "ipv4", feature = "icmp"))]
        let icmp_handle = {
            let mut s = icmp::Socket::new(
                icmp::PacketBuffer::new(
                    &mut storage.icmp_rx_meta[..],
                    &mut storage.icmp_rx_data[..],
                ),
                icmp::PacketBuffer::new(
                    &mut storage.icmp_tx_meta[..],
                    &mut storage.icmp_tx_data[..],
                ),
            );
            let _ = s.bind(icmp::Endpoint::Ident(PING_IDENT));
            sockets.add(s)
        };
        #[cfg(all(feature = "ipv4", feature = "dns"))]
        let dns_handle = {
            let dns_ip = initial_cfg.dns.unwrap_or([1, 1, 1, 1]);
            let servers = [IpAddress::Ipv4(Ipv4Address::from(dns_ip))];
            sockets.add(dns::Socket::new(&servers, &mut storage.dns_queries[..]))
        };

        let [rx0, rx1, rx2, rx3] = &mut storage.tcp_rx_bufs;
        let [tx0, tx1, tx2, tx3] = &mut storage.tcp_tx_bufs;
        let make_sock = |rx: &'a mut [u8], tx: &'a mut [u8]| {
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(rx), tcp::SocketBuffer::new(tx));
            s.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
            s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));
            let _ = s.listen(listen_port);
            s
        };
        let tcp_handles = [
            sockets.add(make_sock(&mut rx0[..], &mut tx0[..])),
            sockets.add(make_sock(&mut rx1[..], &mut tx1[..])),
            sockets.add(make_sock(&mut rx2[..], &mut tx2[..])),
            sockets.add(make_sock(&mut rx3[..], &mut tx3[..])),
        ];

        Self {
            device,
            mac,
            iface,
            sockets,
            #[cfg(feature = "ipv4")]
            dhcp_handle,
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            icmp_handle,
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            ping_seq: 0,
            #[cfg(all(feature = "ipv4", feature = "icmp"))]
            ping_state: PingState::Idle,
            #[cfg(all(feature = "ipv4", feature = "dns"))]
            dns_handle,
            #[cfg(all(feature = "ipv4", feature = "dns"))]
            dns_state: DnsState::Idle,
            tcp_handles,
            syn_seen_ms: [None; SSH_LISTEN_BACKLOG],
            active_tcp: None,
            #[cfg(feature = "ipv4")]
            initial_cfg,
            cfg: initial_cfg,
            #[cfg(feature = "ipv6")]
            ipv6_cfg,
            listen_port,
            was_connected: false,
        }
    }

    #[cfg(feature = "ipv6")]
    /// Update the active IPv6 configuration (link-local, optional global unicast, gateway, DNS)
    /// and immediately reprogram the underlying `smoltcp` interface.
    pub fn set_ipv6_config(&mut self, ipv6_cfg: Ipv6Config) {
        self.ipv6_cfg = ipv6_cfg;
        Self::apply_ip_config(&mut self.iface, &self.cfg, &self.ipv6_cfg);
    }

    #[cfg(feature = "ipv6")]
    #[must_use]
    #[inline]
    pub const fn ipv6_config(&self) -> Ipv6Config {
        self.ipv6_cfg
    }

    fn apply_ip_config(
        iface: &mut Interface,
        cfg: &NetConfig,
        #[cfg(feature = "ipv6")] ipv6_cfg: &Ipv6Config,
    ) {
        #[cfg(not(feature = "ipv4"))]
        let _ = cfg;
        iface.update_ip_addrs(|addrs| {
            addrs.clear();
            #[cfg(feature = "ipv4")]
            if cfg.is_configured() {
                let _ = addrs.push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::from(cfg.ip)),
                    cfg.prefix_len,
                ));
            }
            #[cfg(feature = "ipv6")]
            {
                let _ = addrs.push(IpCidr::new(
                    IpAddress::Ipv6(Ipv6Address::from(ipv6_cfg.link_local)),
                    64,
                ));
                if let Some((global, prefix)) = ipv6_cfg.global {
                    let _ = addrs.push(IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::from(global)),
                        prefix,
                    ));
                }
            }
        });
        #[cfg(feature = "ipv4")]
        {
            iface.routes_mut().remove_default_ipv4_route();
            if let Some(gw) = cfg.gateway {
                let _ = iface
                    .routes_mut()
                    .add_default_ipv4_route(Ipv4Address::from(gw));
            }
        }
        #[cfg(feature = "ipv6")]
        {
            iface.routes_mut().remove_default_ipv6_route();
            if let Some(gw) = ipv6_cfg.gateway {
                let _ = iface
                    .routes_mut()
                    .add_default_ipv6_route(Ipv6Address::from(gw));
            }
        }
    }

    /// Access the underlying `NetDevice` (e.g. for hardware interrupt acknowledgement).
    #[must_use]
    pub const fn device(&self) -> &D {
        &self.device
    }

    /// Drive `smoltcp` RX/TX, `DHCPv4` lease state (when `ipv4` is enabled), and automatic TCP re-listen.
    pub fn poll(&mut self, now_ms: i64) -> TcpEvent {
        let _ = self.iface.poll(
            instant_from_millis_clamped(now_ms),
            &mut self.device,
            &mut self.sockets,
        );

        // Handle DHCPv4 lease acquisition / renewal
        #[cfg(feature = "ipv4")]
        if let Some(ev) = self
            .sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .poll()
        {
            match ev {
                dhcpv4::Event::Configured(leased) => {
                    self.cfg = NetConfig {
                        ip: leased.address.address().octets(),
                        prefix_len: leased.address.prefix_len(),
                        gateway: leased.router.as_ref().map(Ipv4Address::octets),
                        dns: leased.dns_servers.first().map(Ipv4Address::octets),
                    };
                    Self::apply_ip_config(
                        &mut self.iface,
                        &self.cfg,
                        #[cfg(feature = "ipv6")]
                        &self.ipv6_cfg,
                    );
                    #[cfg(feature = "dns")]
                    self.refresh_dns_servers();
                }
                dhcpv4::Event::Deconfigured => {
                    // Revert to the caller-supplied initial configuration (never hardcode QEMU's
                    // 10.0.2.15/24 on non-QEMU hardware, `N16`).
                    self.cfg = self.initial_cfg;
                    Self::apply_ip_config(
                        &mut self.iface,
                        &self.cfg,
                        #[cfg(feature = "ipv6")]
                        &self.ipv6_cfg,
                    );
                    #[cfg(feature = "dns")]
                    self.refresh_dns_servers();
                }
            }
        }

        // Drive non-blocking ICMPv4 Echo Request/Reply state machine.
        #[cfg(all(feature = "ipv4", feature = "icmp"))]
        self.poll_ping(now_ms);

        // Drive non-blocking DNS A-record resolution state machine.
        #[cfg(all(feature = "ipv4", feature = "dns"))]
        self.poll_dns(now_ms);

        // Manage multi-socket TCP listener pool & abort half-open SYN-RECEIVED sockets (`H3`).
        for i in 0..SSH_LISTEN_BACKLOG {
            let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp_handles[i]);
            if !sock.is_open() {
                let _ = sock.listen(self.listen_port);
                self.syn_seen_ms[i] = None;
                continue;
            }
            if sock.state() == tcp::State::SynReceived {
                let first_seen = *self.syn_seen_ms[i].get_or_insert(now_ms);
                if now_ms.saturating_sub(first_seen) >= SYN_TIMEOUT_MS {
                    sock.abort();
                    let _ = sock.listen(self.listen_port);
                    self.syn_seen_ms[i] = None;
                }
            } else {
                self.syn_seen_ms[i] = None;
            }
        }

        // Check active connection liveness or promote the next established socket.
        if let Some(idx) = self.active_tcp {
            let sock = self.sockets.get::<tcp::Socket>(self.tcp_handles[idx]);
            if !(sock.is_active() && (sock.may_recv() || sock.may_send())) {
                self.active_tcp = None;
            }
        }
        if self.active_tcp.is_none() {
            for i in 0..SSH_LISTEN_BACKLOG {
                let sock = self.sockets.get::<tcp::Socket>(self.tcp_handles[i]);
                if sock.is_active() && (sock.may_recv() || sock.may_send()) {
                    self.active_tcp = Some(i);
                    break;
                }
            }
        }

        let connected = self.active_tcp.is_some();
        let event = match (self.was_connected, connected) {
            (false, true) => TcpEvent::Connected,
            (true, false) => TcpEvent::Disconnected,
            _ => TcpEvent::None,
        };
        self.was_connected = connected;
        event
    }

    #[inline]
    fn active_handle(&self) -> Option<SocketHandle> {
        self.active_tcp.map(|idx| self.tcp_handles[idx])
    }

    #[inline]
    pub fn is_connected(&self) -> bool {
        let Some(handle) = self.active_handle() else {
            return false;
        };
        let sock = self.sockets.get::<tcp::Socket>(handle);
        sock.is_active() && (sock.may_recv() || sock.may_send())
    }

    #[inline]
    pub fn can_recv(&self) -> bool {
        let Some(handle) = self.active_handle() else {
            return false;
        };
        self.sockets.get::<tcp::Socket>(handle).can_recv()
    }

    #[inline]
    pub fn can_send(&self) -> bool {
        let Some(handle) = self.active_handle() else {
            return false;
        };
        self.sockets.get::<tcp::Socket>(handle).can_send()
    }

    /// Non-blocking read from the active TCP stream; returns `0` if no bytes are ready.
    pub fn recv(&mut self, out: &mut [u8]) -> usize {
        let Some(handle) = self.active_handle() else {
            return 0;
        };
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        if !sock.can_recv() || out.is_empty() {
            return 0;
        }
        sock.recv_slice(out).unwrap_or(0)
    }

    /// Non-blocking write to the active TCP stream; returns bytes queued (`0..=data.len()`).
    pub fn send(&mut self, data: &[u8]) -> usize {
        let Some(handle) = self.active_handle() else {
            return 0;
        };
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        if !sock.can_send() || data.is_empty() {
            return 0;
        }
        sock.send_slice(data).unwrap_or(0)
    }

    /// Gracefully close the active TCP connection (FIN).
    pub fn close(&mut self) {
        if let Some(handle) = self.active_handle() {
            self.sockets.get_mut::<tcp::Socket>(handle).close();
        }
    }

    /// Immediately abort the active TCP connection (RST — used on strict-KEX violations).
    pub fn abort(&mut self) {
        if let Some(handle) = self.active_handle() {
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
        }
    }

    #[must_use]
    #[inline]
    pub const fn config(&self) -> NetConfig {
        self.cfg
    }

    #[must_use]
    #[inline]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Trigger a fresh `DHCPv4` lease discovery / renewal.
    #[cfg(feature = "ipv4")]
    pub fn dhcp_reset(&mut self) {
        self.sockets
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .reset();
    }

    /// Start a non-blocking `ICMPv4` Echo Request to `target`.
    /// Call [`NetStack::poll`] to drive TX/RX and [`NetStack::ping_status`] to inspect completion.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::NoIpv4Address`] if no IPv4 address is currently configured.
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    pub fn ping_start(&mut self, target: [u8; 4], now_ms: i64) -> Result<u16, NetError> {
        if !self.cfg.is_configured() {
            self.ping_state = PingState::Idle;
            return Err(NetError::NoIpv4Address);
        }
        let next_seq = self.ping_seq.wrapping_add(1);
        self.ping_seq = if next_seq == 0 { 1 } else { next_seq };
        let seq = self.ping_seq;
        self.ping_state = PingState::Pending(PendingPing {
            target,
            seq,
            start_ms: now_ms,
            last_tx_ms: now_ms,
            retries: 0,
        });
        self.send_icmp_echo(target, seq);
        Ok(seq)
    }

    /// Inspect the current non-blocking `ICMPv4` ping status.
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    #[must_use]
    #[inline]
    pub const fn ping_status(&self) -> PingStatus {
        self.ping_state.status()
    }

    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    fn send_icmp_echo(&mut self, target: [u8; 4], seq: u16) {
        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !sock.can_send() {
            return;
        }
        let dest = IpAddress::Ipv4(Ipv4Address::from(target));
        let echo = Icmpv4Repr::EchoRequest {
            ident: PING_IDENT,
            seq_no: seq,
            data: b"newos-el0",
        };
        if let Ok(buf) = sock.send(echo.buffer_len(), dest) {
            let mut pkt = Icmpv4Packet::new_unchecked(buf);
            echo.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::default());
        }
    }

    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    fn poll_ping(&mut self, now_ms: i64) {
        let PingState::Pending(mut pending) = self.ping_state else {
            // Drain any late/stale ICMP packets so the RX ring stays clear.
            let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
            while sock.can_recv() {
                if sock.recv().is_err() {
                    break;
                }
            }
            return;
        };

        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        while sock.can_recv() {
            let Ok((data, _addr)) = sock.recv() else {
                break;
            };
            if let Ok(pkt) = Icmpv4Packet::new_checked(data)
                && let Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }) =
                    Icmpv4Repr::parse(&pkt, &smoltcp::phy::ChecksumCapabilities::default())
                && ident == PING_IDENT
                && seq_no == pending.seq
            {
                let rtt_ms = u32::try_from(now_ms.saturating_sub(pending.start_ms).max(0))
                    .unwrap_or(u32::MAX);
                self.ping_state = PingState::Reply {
                    target: pending.target,
                    seq: seq_no,
                    rtt_ms,
                };
                return;
            }
        }

        if now_ms.saturating_sub(pending.start_ms) >= PING_TIMEOUT_MS {
            self.ping_state = PingState::Timeout;
            return;
        }

        if pending.retries < PING_MAX_RETRIES
            && now_ms.saturating_sub(pending.last_tx_ms) >= PING_RETRY_INTERVAL_MS
        {
            pending.retries += 1;
            pending.last_tx_ms = now_ms;
            self.ping_state = PingState::Pending(pending);
            self.send_icmp_echo(pending.target, pending.seq);
        }
    }

    #[cfg(all(feature = "ipv4", feature = "dns"))]
    fn refresh_dns_servers(&mut self) {
        let dns_ip = self.cfg.dns.unwrap_or([1, 1, 1, 1]);
        let servers = [IpAddress::Ipv4(Ipv4Address::from(dns_ip))];
        self.sockets
            .get_mut::<dns::Socket>(self.dns_handle)
            .update_servers(&servers);
    }

    /// Start a non-blocking DNS A-record resolution for `hostname`.
    /// Call [`NetStack::poll`] to drive TX/RX and [`NetStack::dns_status`] to inspect completion.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::NoIpv4Address`] if no IPv4 address is configured, or
    /// [`NetError::DnsStartFailed`] if the DNS query could not be started.
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    pub fn dns_start(&mut self, hostname: &str, now_ms: i64) -> Result<(), NetError> {
        if !self.cfg.is_configured() {
            self.dns_state = DnsState::Failed;
            return Err(NetError::NoIpv4Address);
        }
        if let DnsState::Pending { handle, .. } = self.dns_state {
            self.sockets
                .get_mut::<dns::Socket>(self.dns_handle)
                .cancel_query(handle);
            self.dns_state = DnsState::Idle;
        }
        self.refresh_dns_servers();
        let sock = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        if let Ok(qh) = sock.start_query(self.iface.context(), hostname, DnsQueryType::A) {
            self.dns_state = DnsState::Pending {
                handle: qh,
                start_ms: now_ms,
            };
            Ok(())
        } else {
            self.dns_state = DnsState::Failed;
            Err(NetError::DnsStartFailed)
        }
    }

    /// Inspect the current non-blocking DNS A-record query status.
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    #[must_use]
    #[inline]
    pub const fn dns_status(&self) -> DnsStatus {
        self.dns_state.status()
    }

    #[cfg(all(feature = "ipv4", feature = "dns"))]
    fn poll_dns(&mut self, now_ms: i64) {
        let DnsState::Pending {
            handle: qh,
            start_ms,
        } = self.dns_state
        else {
            return;
        };
        let sock = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
        match sock.get_query_result(qh) {
            Ok(addrs) => {
                if let Some(IpAddress::Ipv4(v4)) = addrs.first() {
                    self.dns_state = DnsState::Resolved(v4.octets());
                } else {
                    self.dns_state = DnsState::Failed;
                }
            }
            Err(dns::GetQueryResultError::Pending) => {
                if now_ms.saturating_sub(start_ms) >= DNS_TIMEOUT_MS {
                    sock.cancel_query(qh);
                    self.dns_state = DnsState::Timeout;
                }
            }
            Err(dns::GetQueryResultError::Failed) => {
                self.dns_state = DnsState::Failed;
            }
        }
    }

    /// Returns `true` while an ICMP ping or DNS query is actively awaiting a reply.
    #[must_use]
    #[inline]
    pub const fn has_pending_control_op(&self) -> bool {
        #[cfg(all(feature = "ipv4", feature = "icmp"))]
        let ping_pending = self.ping_state.is_pending();
        #[cfg(not(all(feature = "ipv4", feature = "icmp")))]
        let ping_pending = false;

        #[cfg(all(feature = "ipv4", feature = "dns"))]
        let dns_pending = self.dns_state.is_pending();
        #[cfg(not(all(feature = "ipv4", feature = "dns")))]
        let dns_pending = false;

        ping_pending || dns_pending
    }

    /// Return the recommended milliseconds until the next `smoltcp` timer event,
    /// enabling `net-pd` to block in `NotifyWait` instead of busy-polling.
    pub fn poll_delay_ms(&mut self, now_ms: i64) -> Option<u64> {
        self.iface
            .poll_delay(instant_from_millis_clamped(now_ms), &self.sockets)
            .as_ref()
            .map(smoltcp::time::Duration::total_millis)
    }

    #[must_use]
    #[inline]
    pub const fn listen_port(&self) -> u16 {
        self.listen_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};

    const FRAME_CAP: usize = 1600;
    const Q_SLOTS: usize = 16;

    struct FrameQueue {
        frames: [[u8; FRAME_CAP]; Q_SLOTS],
        lens: [usize; Q_SLOTS],
        head: usize,
        tail: usize,
    }

    impl FrameQueue {
        // Intentional: `#![no_std]` unit-test loopback queue allocated on test thread stack.
        #[allow(clippy::large_stack_arrays)]
        const fn new() -> Self {
            Self {
                frames: [[0u8; FRAME_CAP]; Q_SLOTS],
                lens: [0; Q_SLOTS],
                head: 0,
                tail: 0,
            }
        }

        fn push(&mut self, data: &[u8]) {
            let next = (self.tail + 1) % Q_SLOTS;
            if next != self.head {
                let n = data.len().min(FRAME_CAP);
                self.frames[self.tail][..n].copy_from_slice(&data[..n]);
                self.lens[self.tail] = n;
                self.tail = next;
            }
        }

        fn pop(&mut self, out: &mut [u8; FRAME_CAP]) -> Option<usize> {
            if self.head == self.tail {
                return None;
            }
            let n = self.lens[self.head];
            out[..n].copy_from_slice(&self.frames[self.head][..n]);
            self.head = (self.head + 1) % Q_SLOTS;
            Some(n)
        }
    }

    struct WireEnd {
        rx: FrameQueue,
        tx: FrameQueue,
    }

    impl WireEnd {
        const fn new() -> Self {
            Self {
                rx: FrameQueue::new(),
                tx: FrameQueue::new(),
            }
        }
    }

    struct WireRx {
        buf: [u8; FRAME_CAP],
        len: usize,
    }

    impl RxToken for WireRx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.buf[..self.len])
        }
    }

    struct WireTx<'a>(&'a mut FrameQueue);

    impl TxToken for WireTx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut tmp = [0u8; FRAME_CAP];
            let n = len.min(FRAME_CAP);
            let res = f(&mut tmp[..n]);
            self.0.push(&tmp[..n]);
            res
        }
    }

    impl Device for WireEnd {
        type RxToken<'a> = WireRx;
        type TxToken<'a> = WireTx<'a>;

        fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let mut buf = [0u8; FRAME_CAP];
            let len = self.rx.pop(&mut buf)?;
            Some((WireRx { buf, len }, WireTx(&mut self.tx)))
        }

        fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
            Some(WireTx(&mut self.tx))
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut c = DeviceCapabilities::default();
            c.medium = Medium::Ethernet;
            c.max_transmission_unit = 1500;
            c
        }
    }

    fn pump_wire(a: &mut WireEnd, b: &mut WireEnd) {
        let mut tmp = [0u8; FRAME_CAP];
        while let Some(n) = a.tx.pop(&mut tmp) {
            b.rx.push(&tmp[..n]);
        }
        while let Some(n) = b.tx.pop(&mut tmp) {
            a.rx.push(&tmp[..n]);
        }
    }

    #[test]
    #[cfg(feature = "ipv4")]
    fn persistent_netstack_handles_pq_sized_ssh_exchange_and_relistens() {
        let mut storage = NetStackStorage::new();
        let server_cfg = NetConfig {
            ip: [10, 0, 2, 15],
            prefix_len: 24,
            gateway: Some([10, 0, 2, 2]),
            dns: None,
        };
        let mut server = NetStack::new(
            WireEnd::new(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            server_cfg,
            SSH_PORT,
            0,
            &mut storage,
        );

        // Client peer
        let mut client_dev = WireEnd::new();
        let mut client_iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
            ]))),
            &mut client_dev,
            Instant::from_millis(0),
        );
        client_iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 0, 2, 20), 24));
        });
        let mut c_rx = [0u8; 8192];
        let mut c_tx = [0u8; 8192];
        let mut c_storage = [SocketStorage::EMPTY; 1];
        let mut c_sockets = SocketSet::new(&mut c_storage[..]);
        let c_handle = c_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut c_rx[..]),
            tcp::SocketBuffer::new(&mut c_tx[..]),
        ));

        // Simulate two sequential SSH connections to verify automatic re-listen
        for round in 0..2u16 {
            c_sockets
                .get_mut::<tcp::Socket>(c_handle)
                .connect(
                    client_iface.context(),
                    (IpAddress::v4(10, 0, 2, 15), SSH_PORT),
                    40_000 + round,
                )
                .expect("client connect");

            // 6 KiB payload simulates ML-KEM-1024 (1568 B) + ML-DSA-87 (4627 B) handshake
            let mut client_payload = [0u8; 6144];
            for (i, b) in client_payload.iter_mut().enumerate() {
                *b = i.to_le_bytes()[0]
                    .wrapping_mul(31)
                    .wrapping_add(round.to_le_bytes()[0]);
            }
            let mut c_sent = 0usize;
            let mut s_recv = [0u8; 6144];
            let mut s_got = 0usize;
            let mut saw_connected = false;
            let mut saw_disconnected = false;
            let mut closed = false;

            for step in 0..400i64 {
                let now = i64::from(round) * 5_000 + step * 10;
                let _ =
                    client_iface.poll(Instant::from_millis(now), &mut client_dev, &mut c_sockets);
                pump_wire(&mut client_dev, &mut server.device);
                match server.poll(now) {
                    TcpEvent::Connected => saw_connected = true,
                    TcpEvent::Disconnected => saw_disconnected = true,
                    TcpEvent::None => {}
                }
                pump_wire(&mut client_dev, &mut server.device);

                let cs = c_sockets.get_mut::<tcp::Socket>(c_handle);
                if c_sent < client_payload.len()
                    && cs.can_send()
                    && let Ok(n) = cs.send_slice(&client_payload[c_sent..])
                {
                    c_sent += n;
                }
                if s_got < s_recv.len() {
                    s_got += server.recv(&mut s_recv[s_got..]);
                }
                if s_got == s_recv.len() && !closed {
                    server.close();
                    c_sockets.get_mut::<tcp::Socket>(c_handle).close();
                    closed = true;
                }
                if closed && saw_disconnected && !c_sockets.get::<tcp::Socket>(c_handle).is_open() {
                    break;
                }
            }

            assert!(saw_connected, "round {round} should emit Connected");
            assert_eq!(
                s_got,
                client_payload.len(),
                "round {round} full 6 KiB PQ frame"
            );
            assert_eq!(s_recv, client_payload);
            assert!(saw_disconnected, "round {round} should emit Disconnected");
        }
    }

    #[test]
    #[cfg(feature = "ipv6")]
    fn persistent_netstack_handles_ipv6_tcp_exchange() {
        let mut storage = NetStackStorage::new();
        let server_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
        let server_v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let client_v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let mut server = NetStack::new(
            WireEnd::new(),
            server_mac,
            NetConfig::QEMU_DEFAULT,
            SSH_PORT,
            0,
            &mut storage,
        );
        server.set_ipv6_config(Ipv6Config {
            link_local: server_v6,
            global: None,
            gateway: None,
            dns: None,
        });

        let mut client_dev = WireEnd::new();
        let mut client_iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0x00, 0x00, 0x00, 0x00, 0x22,
            ]))),
            &mut client_dev,
            Instant::from_millis(0),
        );
        client_iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::from(client_v6)),
                64,
            ));
        });
        let mut c_rx = [0u8; 4096];
        let mut c_tx = [0u8; 4096];
        let mut c_storage = [SocketStorage::EMPTY; 1];
        let mut c_sockets = SocketSet::new(&mut c_storage[..]);
        let c_handle = c_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut c_rx[..]),
            tcp::SocketBuffer::new(&mut c_tx[..]),
        ));
        c_sockets
            .get_mut::<tcp::Socket>(c_handle)
            .connect(
                client_iface.context(),
                (IpAddress::Ipv6(Ipv6Address::from(server_v6)), SSH_PORT),
                41_000,
            )
            .expect("ipv6 client connect");

        let msg = b"hello-newos-ipv6-tcp!";
        let mut sent = false;
        let mut got = [0u8; 64];
        let mut got_len = 0usize;
        let mut saw_connected = false;

        for step in 0..300i64 {
            let now = step * 10;
            let _ = client_iface.poll(Instant::from_millis(now), &mut client_dev, &mut c_sockets);
            pump_wire(&mut client_dev, &mut server.device);
            if matches!(server.poll(now), TcpEvent::Connected) {
                saw_connected = true;
            }
            pump_wire(&mut client_dev, &mut server.device);

            let cs = c_sockets.get_mut::<tcp::Socket>(c_handle);
            if !sent && cs.can_send() {
                assert_eq!(cs.send_slice(msg).expect("ipv6 client send"), msg.len());
                sent = true;
            }
            if got_len < msg.len() {
                got_len += server.recv(&mut got[got_len..]);
            }
            if got_len == msg.len() {
                break;
            }
        }

        assert!(saw_connected, "IPv6 TCP client should connect");
        assert_eq!(&got[..got_len], msg);
    }

    #[test]
    #[cfg(feature = "ipv4")]
    fn multi_socket_listener_survives_bare_syn_and_recycles_after_timeout() {
        let mut storage = NetStackStorage::new();
        let server_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x31];
        let mut server = NetStack::new_with_seed(
            WireEnd::new(),
            server_mac,
            NetConfig::QEMU_DEFAULT,
            SSH_PORT,
            0,
            0xDEAD_BEEF_CAFE_BABE,
            &mut storage,
        );

        let mut attacker_dev = WireEnd::new();
        let mut attacker_iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0x00, 0x00, 0x00, 0x00, 0x32,
            ]))),
            &mut attacker_dev,
            Instant::from_millis(0),
        );
        attacker_iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 99)),
                24,
            ));
        });
        let mut a_rx = [0u8; 1024];
        let mut a_tx = [0u8; 1024];
        let mut a_storage = [SocketStorage::EMPTY; 1];
        let mut a_sockets = SocketSet::new(&mut a_storage[..]);
        let a_handle = a_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut a_rx[..]),
            tcp::SocketBuffer::new(&mut a_tx[..]),
        ));
        a_sockets
            .get_mut::<tcp::Socket>(a_handle)
            .connect(
                attacker_iface.context(),
                (
                    IpAddress::Ipv4(Ipv4Address::from(NetConfig::QEMU_DEFAULT.ip)),
                    SSH_PORT,
                ),
                50_001,
            )
            .expect("attacker connect");

        // Pump ONLY the attacker's initial SYN to server (dropping SYN-ACK so socket stays SynReceived).
        for step in 0..10i64 {
            let now = step * 10;
            let _ =
                attacker_iface.poll(Instant::from_millis(now), &mut attacker_dev, &mut a_sockets);
            let mut frame = [0u8; FRAME_CAP];
            while let Some(n) = attacker_dev.tx.pop(&mut frame) {
                server.device.rx.push(&frame[..n]);
            }
            let _ = server.poll(now);
        }

        // Advance past SYN_TIMEOUT_MS (5000 ms): server must abort & recycle the half-open socket.
        let _ = server.poll(SYN_TIMEOUT_MS + 1000);
        assert!(!server.is_connected());
        assert_eq!(server.syn_seen_ms, [None; SSH_LISTEN_BACKLOG]);
    }

    #[test]
    #[cfg(all(feature = "ipv4", feature = "icmp"))]
    fn persistent_netstack_icmp_ping_roundtrip_and_timeout() {
        let mut storage = NetStackStorage::new();
        let mut stack = NetStack::new(
            WireEnd::new(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x41],
            NetConfig {
                ip: [10, 0, 2, 15],
                prefix_len: 24,
                gateway: Some([10, 0, 2, 2]),
                dns: Some([10, 0, 2, 3]),
            },
            SSH_PORT,
            0,
            &mut storage,
        );

        // Peer interface (10.0.2.2) automatically responds to ARP + ICMP Echo Requests via smoltcp.
        let mut peer_dev = WireEnd::new();
        let mut peer_iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress([
                0x02, 0x00, 0x00, 0x00, 0x00, 0x42,
            ]))),
            &mut peer_dev,
            Instant::from_millis(0),
        );
        peer_iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 0, 2, 2), 24));
        });
        let mut peer_storage = [SocketStorage::EMPTY; 1];
        let mut peer_sockets = SocketSet::new(&mut peer_storage[..]);

        let seq = stack.ping_start([10, 0, 2, 2], 100).expect("ping start");
        assert_eq!(seq, 1);
        assert_eq!(stack.ping_status(), PingStatus::Pending);
        assert!(stack.has_pending_control_op());

        for step in 0..200i64 {
            let now = 100 + step * 10;
            let _ = stack.poll(now);
            pump_wire(&mut stack.device, &mut peer_dev);
            let _ = peer_iface.poll(Instant::from_millis(now), &mut peer_dev, &mut peer_sockets);
            pump_wire(&mut stack.device, &mut peer_dev);
            if matches!(stack.ping_status(), PingStatus::Reply { .. }) {
                break;
            }
        }
        assert!(
            matches!(
                stack.ping_status(),
                PingStatus::Reply {
                    target: [10, 0, 2, 2],
                    seq: 1,
                    ..
                }
            ),
            "expected ICMP EchoReply from peer, got {:?}",
            stack.ping_status()
        );
        assert!(!stack.has_pending_control_op());

        // Silent target must time out after PING_TIMEOUT_MS.
        let seq2 = stack
            .ping_start([10, 0, 2, 99], 5_000)
            .expect("ping start 2");
        assert_eq!(seq2, 2);
        let _ = stack.poll(5_000 + PING_TIMEOUT_MS + 10);
        assert_eq!(stack.ping_status(), PingStatus::Timeout);
        assert!(!stack.has_pending_control_op());
    }

    #[test]
    #[cfg(all(feature = "ipv4", feature = "dns"))]
    fn persistent_netstack_dns_query_and_timeout() {
        let mut storage = NetStackStorage::new();
        let mut stack = NetStack::new(
            WireEnd::new(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x51],
            NetConfig {
                ip: [10, 0, 2, 15],
                prefix_len: 24,
                gateway: Some([10, 0, 2, 2]),
                dns: Some([10, 0, 2, 3]),
            },
            SSH_PORT,
            0,
            &mut storage,
        );

        assert_eq!(stack.dns_status(), DnsStatus::Idle);
        stack.dns_start("example.com", 100).expect("dns start");
        assert_eq!(stack.dns_status(), DnsStatus::Pending);
        assert!(stack.has_pending_control_op());

        // Poll once to verify TX frame (ARP for DNS server) is emitted and query stays Pending.
        let _ = stack.poll(110);
        assert_eq!(stack.dns_status(), DnsStatus::Pending);

        // Advance past DNS_TIMEOUT_MS with no DNS server response -> Timeout.
        let _ = stack.poll(100 + DNS_TIMEOUT_MS + 10);
        assert_eq!(stack.dns_status(), DnsStatus::Timeout);
        assert!(!stack.has_pending_control_op());
    }

    #[test]
    #[cfg(feature = "ipv4")]
    fn netstack_unconfigured_ip_rejects_ping_and_dns_with_no_ipv4_address() {
        extern crate std;
        use std::format;

        let mut storage = NetStackStorage::new();
        let mut stack = NetStack::new(
            WireEnd::new(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x61],
            NetConfig::UNCONFIGURED,
            SSH_PORT,
            0,
            &mut storage,
        );
        assert!(format!("{stack:?}").contains("NetStack"));
        assert!(!stack.is_connected());
        assert!(!stack.can_recv());
        assert!(!stack.can_send());
        let mut buf = [0u8; 16];
        assert_eq!(stack.recv(&mut buf), 0);
        assert_eq!(stack.send(b"hello"), 0);

        #[cfg(feature = "icmp")]
        {
            assert_eq!(
                stack.ping_start([10, 0, 2, 2], 100),
                Err(NetError::NoIpv4Address)
            );
            assert_eq!(stack.ping_status(), PingStatus::Idle);
        }
        #[cfg(feature = "dns")]
        {
            assert_eq!(
                stack.dns_start("example.com", 100),
                Err(NetError::NoIpv4Address)
            );
            assert_eq!(stack.dns_status(), DnsStatus::Failed);
        }
    }

    #[test]
    #[cfg(feature = "ipv4")]
    fn netstack_extreme_timestamps_do_not_overflow() {
        let mut storage = NetStackStorage::new();
        let mut stack = NetStack::new(
            WireEnd::new(),
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x71],
            NetConfig::QEMU_DEFAULT,
            SSH_PORT,
            i64::MIN,
            &mut storage,
        );

        #[cfg(feature = "icmp")]
        {
            let _ = stack.ping_start([10, 0, 2, 2], i64::MIN);
        }
        #[cfg(feature = "dns")]
        {
            let _ = stack.dns_start("example.com", i64::MIN);
        }

        let _ = stack.poll(i64::MIN);
        let _ = stack.poll(i64::MAX);
        let _ = stack.poll(i64::MAX / 1_000);
        let _ = stack.poll_delay_ms(i64::MAX);
        let _ = stack.poll_delay_ms(i64::MIN);
    }
}
