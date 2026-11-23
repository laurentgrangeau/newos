//! Persistent, `no_alloc`, `#![forbid(unsafe_code)]` EL0 `smoltcp` Network Stack (`NetStack`).
//!
//! Designed for `newos-netd` (PID 2): initializes the NIC once, maintains an automatic DHCPv4
//! lease (with `NetConfig::QEMU_DEFAULT` fallback), and serves a persistent single-connection
//! TCP listener (port 22) with 32 KiB RX/TX ring buffers sized for ML-KEM-1024 + ML-DSA-87
//! post-quantum SSH handshakes.

#[cfg(feature = "ipv6")]
use crate::Ipv6Config;
use crate::NetConfig;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::Device;
#[cfg(feature = "ipv4")]
use smoltcp::socket::dhcpv4;
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
#[cfg(feature = "ipv4")]
use smoltcp::wire::Ipv4Address;
#[cfg(feature = "ipv6")]
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

/// Static TCP socket buffer size (32 KiB each for RX and TX) to absorb ML-KEM-1024 (1568 B)
/// and ML-DSA-87 (2592 B pk + 4627 B sig) SSH handshake packets without stalls.
pub const TCP_BUF_SIZE: usize = 32_768;

/// Default SSH listening port.
pub const SSH_PORT: u16 = 22;

/// Edge-triggered TCP listener lifecycle events emitted by [`NetStack::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    None,
    Connected,
    Disconnected,
}

/// Static, `no_alloc` backing buffers owned by the caller (e.g., `newos-netd` main/BSS)
/// and borrowed by [`NetStack`].
pub struct NetStackStorage<'a> {
    pub tcp_rx_buf: [u8; TCP_BUF_SIZE],
    pub tcp_tx_buf: [u8; TCP_BUF_SIZE],
    pub sockets: [SocketStorage<'a>; 2],
}

impl Default for NetStackStorage<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl NetStackStorage<'_> {
    pub const fn new() -> Self {
        Self {
            tcp_rx_buf: [0u8; TCP_BUF_SIZE],
            tcp_tx_buf: [0u8; TCP_BUF_SIZE],
            sockets: [SocketStorage::EMPTY, SocketStorage::EMPTY],
        }
    }
}

/// Long-lived EL0 `smoltcp` IPv4/IPv6 dual-stack TCP listener (`#![forbid(unsafe_code)]`, `no_alloc`).
pub struct NetStack<'a, D: Device> {
    device: D,
    iface: Interface,
    sockets: SocketSet<'a>,
    #[cfg(feature = "ipv4")]
    dhcp_handle: SocketHandle,
    tcp_handle: SocketHandle,
    #[cfg(feature = "ipv4")]
    initial_cfg: NetConfig,
    cfg: NetConfig,
    #[cfg(feature = "ipv6")]
    ipv6_cfg: Ipv6Config,
    listen_port: u16,
    was_connected: bool,
}

impl<'a, D: Device> NetStack<'a, D> {
    /// Construct a persistent `NetStack` over an already-initialized `smoltcp` `Device`,
    /// binding a TCP listener on `listen_port` (typically 22) and configuring IPv4/IPv6.
    pub fn new(
        mut device: D,
        mac: [u8; 6],
        initial_cfg: NetConfig,
        listen_port: u16,
        now_ms: i64,
        storage: &'a mut NetStackStorage<'a>,
    ) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        // Derive a non-zero per-boot random seed from timestamp + MAC via SplitMix64 (`M8`)
        // so TCP ISNs, ephemeral ports, and DNS transaction IDs do not repeat with seed=0.
        let mut seed = (now_ms as u64)
            ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0xA5, 0x5A])
            ^ 0x9E37_79B9_7F4A_7C15;
        seed = (seed ^ (seed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        seed = (seed ^ (seed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        config.random_seed = seed ^ (seed >> 31);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(now_ms));
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

        let mut tcp_sock = tcp::Socket::new(
            tcp::SocketBuffer::new(&mut storage.tcp_rx_buf[..]),
            tcp::SocketBuffer::new(&mut storage.tcp_tx_buf[..]),
        );
        // Enforce TCP inactivity timeout and keep-alive so a stalled peer cannot lock out SSH (`N3`).
        tcp_sock.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
        tcp_sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));
        let _ = tcp_sock.listen(listen_port);
        let tcp_handle = sockets.add(tcp_sock);

        Self {
            device,
            iface,
            sockets,
            #[cfg(feature = "ipv4")]
            dhcp_handle,
            tcp_handle,
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
    #[inline]
    pub fn ipv6_config(&self) -> Ipv6Config {
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
            if cfg.ip != [0, 0, 0, 0] {
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

    /// Drive `smoltcp` RX/TX, DHCPv4 lease state (when `ipv4` is enabled), and automatic TCP re-listen.
    pub fn poll(&mut self, now_ms: i64) -> TcpEvent {
        let _ = self.iface.poll(
            Instant::from_millis(now_ms),
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
                        gateway: leased.router.map(|r| r.octets()),
                        dns: leased.dns_servers.first().map(|d| d.octets()),
                    };
                    Self::apply_ip_config(
                        &mut self.iface,
                        &self.cfg,
                        #[cfg(feature = "ipv6")]
                        &self.ipv6_cfg,
                    );
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
                }
            }
        }

        // Manage single-connection TCP listener lifecycle
        let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        if !sock.is_open() {
            let _ = sock.listen(self.listen_port);
        }
        let connected = sock.is_active() && (sock.may_recv() || sock.may_send());
        let event = match (self.was_connected, connected) {
            (false, true) => TcpEvent::Connected,
            (true, false) => TcpEvent::Disconnected,
            _ => TcpEvent::None,
        };
        self.was_connected = connected;
        event
    }

    #[inline]
    pub fn is_connected(&self) -> bool {
        let sock = self.sockets.get::<tcp::Socket>(self.tcp_handle);
        sock.is_active() && (sock.may_recv() || sock.may_send())
    }

    #[inline]
    pub fn can_recv(&self) -> bool {
        self.sockets.get::<tcp::Socket>(self.tcp_handle).can_recv()
    }

    #[inline]
    pub fn can_send(&self) -> bool {
        self.sockets.get::<tcp::Socket>(self.tcp_handle).can_send()
    }

    /// Non-blocking read from the active TCP stream; returns `0` if no bytes are ready.
    pub fn recv(&mut self, out: &mut [u8]) -> usize {
        let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        if !sock.can_recv() || out.is_empty() {
            return 0;
        }
        sock.recv_slice(out).unwrap_or(0)
    }

    /// Non-blocking write to the active TCP stream; returns bytes queued (`0..=data.len()`).
    pub fn send(&mut self, data: &[u8]) -> usize {
        let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        if !sock.can_send() || data.is_empty() {
            return 0;
        }
        sock.send_slice(data).unwrap_or(0)
    }

    /// Gracefully close the active TCP connection (FIN).
    pub fn close(&mut self) {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).close();
    }

    /// Immediately abort the active TCP connection (RST — used on strict-KEX violations).
    pub fn abort(&mut self) {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).abort();
    }

    #[inline]
    pub fn config(&self) -> NetConfig {
        self.cfg
    }

    #[inline]
    pub fn listen_port(&self) -> u16 {
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
                .unwrap();

            // 6 KiB payload simulates ML-KEM-1024 (1568 B) + ML-DSA-87 (4627 B) handshake
            let mut client_payload = [0u8; 6144];
            for (i, b) in client_payload.iter_mut().enumerate() {
                *b = ((i as u8).wrapping_mul(31)).wrapping_add(round as u8);
            }
            let mut c_sent = 0usize;
            let mut s_recv = [0u8; 6144];
            let mut s_got = 0usize;
            let mut saw_connected = false;
            let mut saw_disconnected = false;
            let mut closed = false;

            for step in 0..400i64 {
                let now = (round as i64) * 5_000 + step * 10;
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
            .unwrap();

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
                assert_eq!(cs.send_slice(msg).unwrap(), msg.len());
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
}
