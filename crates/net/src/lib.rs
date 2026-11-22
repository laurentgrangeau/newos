#![no_std]
#![forbid(unsafe_code)]

//! Ring-3 Networking Stack (`smoltcp` IPv4/UDP/ICMP/DHCPv4/DNS + Capability-Scoped Drivers).
//!
//! Supports:
//! - QEMU `virt`: Modern VirtIO 1.0+ (v2) MMIO (`virtio.rs`)
//! - Raspberry Pi 5 (16 GB): RP1 Cadence GEM (`macb`) Gigabit Ethernet (`gem.rs`)
//!
//! 100% `#![forbid(unsafe_code)]`, zero heap (`no_alloc`), zero network code in Ring 0.

pub mod gem;
pub mod virtio;

pub use gem::{GemDma, GemInfo, GemNetDevice, probe_cadence_gem};
pub use virtio::{VirtioNetDevice, VirtioNetDma, VirtioTransport};

use newos_abi::SysError;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, dns, icmp};
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{
    DnsQueryType, EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr,
    Ipv4Address,
};

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_DEVICE_NET: u32 = 1;
const VIRTIO_MMIO_SLOTS: u64 = 32;
const VIRTIO_MMIO_STRIDE: u64 = 0x200;

const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00C;
const REG_CONFIG_MAC_LO: u64 = 0x100;
const REG_CONFIG_MAC_HI: u64 = 0x104;

/// Discovered VirtIO-MMIO network interface metadata (read purely via MMIO capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioNetInfo {
    pub slot: u8,
    pub version: u32,
    pub vendor_id: u32,
    pub mac: [u8; 6],
}

/// Unified detected Ring-3 NIC (QEMU VirtIO-MMIO v2 or Raspberry Pi 5 RP1 Cadence GEM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicKind {
    Virtio(VirtioNetInfo),
    CadenceGem(GemInfo),
}

impl NicKind {
    pub fn mac(&self) -> [u8; 6] {
        match self {
            NicKind::Virtio(v) => v.mac,
            NicKind::CadenceGem(g) => g.mac,
        }
    }

    pub fn driver_name(&self) -> &'static str {
        match self {
            NicKind::Virtio(_) => "virtio-net-v2",
            NicKind::CadenceGem(_) => "rpi5-rp1-gem",
        }
    }
}

/// Active IPv4 network configuration (acquired via DHCPv4 or static fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetConfig {
    pub ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
}

impl NetConfig {
    pub const QEMU_DEFAULT: Self = Self {
        ip: [10, 0, 2, 15],
        prefix_len: 24,
        gateway: Some([10, 0, 2, 2]),
        dns: Some([10, 0, 2, 3]),
    };
}

/// Probe for either a VirtIO-MMIO network device or a Raspberry Pi 5 RP1 Cadence GEM controller.
pub fn probe_nic<F>(mut read32: F) -> Option<NicKind>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    if let Some(v) = probe_virtio_net(&mut read32) {
        return Some(NicKind::Virtio(v));
    }
    if let Some(g) = probe_cadence_gem(&mut read32) {
        return Some(NicKind::CadenceGem(g));
    }
    None
}

/// Probe all 32 VirtIO-MMIO slots using a capability-gated 32-bit MMIO reader.
pub fn probe_virtio_net<F>(mut read32: F) -> Option<VirtioNetInfo>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    for slot in 0..VIRTIO_MMIO_SLOTS {
        let base = slot * VIRTIO_MMIO_STRIDE;
        let Ok(magic) = read32(base + REG_MAGIC) else {
            return None;
        };
        if magic != VIRTIO_MMIO_MAGIC {
            continue;
        }
        let Ok(device_id) = read32(base + REG_DEVICE_ID) else {
            continue;
        };
        if device_id != VIRTIO_DEVICE_NET {
            continue;
        }
        let version = read32(base + REG_VERSION).unwrap_or(0);
        let vendor_id = read32(base + REG_VENDOR_ID).unwrap_or(0);
        let mac_lo = read32(base + REG_CONFIG_MAC_LO).unwrap_or(0).to_le_bytes();
        let mac_hi = read32(base + REG_CONFIG_MAC_HI).unwrap_or(0).to_le_bytes();
        let mac = [
            mac_lo[0], mac_lo[1], mac_lo[2], mac_lo[3], mac_hi[0], mac_hi[1],
        ];
        return Some(VirtioNetInfo {
            slot: slot as u8,
            version,
            vendor_id,
            mac,
        });
    }
    None
}

/// Fixed-capacity, zero-heap Ring-3 loopback Ethernet `smoltcp::phy::Device` for self-tests.
struct LoopbackEth {
    buf: [u8; 512],
    len: usize,
}

impl LoopbackEth {
    const fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }
}

struct LoopRx<'a> {
    data: &'a mut [u8],
    len: &'a mut usize,
}

impl RxToken for LoopRx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let n = *self.len;
        *self.len = 0;
        f(&self.data[..n])
    }
}

struct LoopTx<'a> {
    data: &'a mut [u8],
    len: &'a mut usize,
}

impl TxToken for LoopTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let n = len.min(self.data.len());
        let res = f(&mut self.data[..n]);
        *self.len = n;
        res
    }
}

impl Device for LoopbackEth {
    type RxToken<'a> = LoopRx<'a>;
    type TxToken<'a> = LoopTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.len == 0 {
            Some(LoopTx {
                data: &mut self.buf,
                len: &mut self.len,
            })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 512;
        caps
    }
}

/// Verify the pure-Rust Ring-3 `smoltcp` Ethernet + IPv4 + UDP stack end-to-end (`no_alloc`).
pub fn verify_smoltcp_ring3_stack(mac: [u8; 6]) -> Result<usize, &'static str> {
    let mut device = LoopbackEth::new();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2));

    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_data = [0u8; 128];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_data = [0u8; 128];

    let mut udp_sock = udp::Socket::new(
        PacketBuffer::new(&mut rx_meta[..], &mut rx_data[..]),
        PacketBuffer::new(&mut tx_meta[..], &mut tx_data[..]),
    );
    udp_sock.bind(5353).map_err(|_| "udp bind failed")?;

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(udp_sock);

    let payload = b"newos-ring3-smoltcp";
    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(payload, (IpAddress::v4(10, 0, 2, 2), 53))
        .map_err(|_| "udp send failed")?;

    let _ = iface.poll(Instant::from_millis(10), &mut device, &mut sockets);
    if device.len < 42 {
        return Err("expected Ethernet/ARP or IPv4 frame from smoltcp");
    }
    if device.buf[6..12] != mac {
        return Err("emitted Ethernet frame source MAC mismatch");
    }
    Ok(device.len)
}

/// Result of a live Ring-3 ICMP Echo Request/Reply round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingResult {
    pub seq: u16,
    pub target: [u8; 4],
}

/// Acquire a live IPv4 address, gateway, and DNS server via `smoltcp` DHCPv4 (`no_alloc`).
pub fn run_dhcp_v4<D: Device>(device: &mut D, mac: [u8; 6]) -> Result<NetConfig, &'static str> {
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, Instant::from_millis(0));

    let dhcp_sock = dhcpv4::Socket::new();
    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(dhcp_sock);

    for step in 0..40_000i64 {
        let now = Instant::from_millis(step);
        let _ = iface.poll(now, device, &mut sockets);
        if let Some(dhcpv4::Event::Configured(cfg)) =
            sockets.get_mut::<dhcpv4::Socket>(handle).poll()
        {
            return Ok(NetConfig {
                ip: cfg.address.address().octets(),
                prefix_len: cfg.address.prefix_len(),
                gateway: cfg.router.map(|r| r.octets()),
                dns: cfg.dns_servers.first().map(|d| d.octets()),
            });
        }
    }
    Err("DHCPv4 lease timed out")
}

/// Resolve a hostname to an IPv4 address via `smoltcp` DNS A-record query (`no_alloc`).
pub fn run_dns_query<D: Device>(
    device: &mut D,
    mac: [u8; 6],
    cfg: &NetConfig,
    hostname: &str,
) -> Result<[u8; 4], &'static str> {
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from(cfg.ip)),
            cfg.prefix_len,
        ));
    });
    if let Some(gw) = cfg.gateway {
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(gw));
    }

    let dns_ip = cfg.dns.unwrap_or([1, 1, 1, 1]);
    let servers = [IpAddress::Ipv4(Ipv4Address::from(dns_ip))];
    let mut queries = [None; 1];
    let dns_sock = dns::Socket::new(&servers, &mut queries[..]);

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(dns_sock);

    let query = sockets
        .get_mut::<dns::Socket>(handle)
        .start_query(iface.context(), hostname, DnsQueryType::A)
        .map_err(|_| "dns start_query failed")?;

    for step in 0..40_000i64 {
        let now = Instant::from_millis(step);
        let _ = iface.poll(now, device, &mut sockets);
        match sockets.get_mut::<dns::Socket>(handle).get_query_result(query) {
            Ok(addrs) => {
                if let Some(IpAddress::Ipv4(v4)) = addrs.first() {
                    return Ok(v4.octets());
                }
                return Err("dns returned no IPv4 address");
            }
            Err(dns::GetQueryResultError::Pending) => {}
            Err(dns::GetQueryResultError::Failed) => return Err("dns query failed"),
        }
    }
    Err("dns query timed out")
}

/// Perform a live ARP + ICMP Echo Request/Reply round-trip to `target` over any `smoltcp` `Device`.
pub fn run_icmp_ping<D: Device>(
    device: &mut D,
    mac: [u8; 6],
    cfg: &NetConfig,
    target: [u8; 4],
) -> Result<PingResult, &'static str> {
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from(cfg.ip)),
            cfg.prefix_len,
        ));
    });
    if let Some(gw) = cfg.gateway {
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(gw));
    }

    let mut rx_meta = [icmp::PacketMetadata::EMPTY; 4];
    let mut rx_data = [0u8; 256];
    let mut tx_meta = [icmp::PacketMetadata::EMPTY; 4];
    let mut tx_data = [0u8; 256];

    let mut icmp_sock = icmp::Socket::new(
        icmp::PacketBuffer::new(&mut rx_meta[..], &mut rx_data[..]),
        icmp::PacketBuffer::new(&mut tx_meta[..], &mut tx_data[..]),
    );
    const IDENT: u16 = 0x5E14;
    const SEQ: u16 = 1;
    icmp_sock
        .bind(icmp::Endpoint::Ident(IDENT))
        .map_err(|_| "icmp bind failed")?;

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(icmp_sock);

    let dest = IpAddress::Ipv4(Ipv4Address::from(target));
    let payload = b"newos-ring3";
    let echo = Icmpv4Repr::EchoRequest {
        ident: IDENT,
        seq_no: SEQ,
        data: payload,
    };

    let mut sent_echo = false;
    for step in 0..25_000i64 {
        let now = Instant::from_millis(step);
        let _ = iface.poll(now, device, &mut sockets);

        let sock = sockets.get_mut::<icmp::Socket>(handle);
        if !sent_echo && sock.can_send() {
            let buf = sock
                .send(echo.buffer_len(), dest)
                .map_err(|_| "icmp send failed")?;
            let mut pkt = Icmpv4Packet::new_unchecked(buf);
            echo.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::default());
            sent_echo = true;
            let _ = iface.poll(now, device, &mut sockets);
        }

        let sock = sockets.get_mut::<icmp::Socket>(handle);
        if sock.can_recv()
            && let Ok((data, _addr)) = sock.recv()
            && let Ok(pkt) = Icmpv4Packet::new_checked(data)
            && let Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }) =
                Icmpv4Repr::parse(&pkt, &smoltcp::phy::ChecksumCapabilities::default())
            && ident == IDENT
            && seq_no == SEQ
        {
            return Ok(PingResult {
                seq: seq_no,
                target,
            });
        }

        // Re-send once after ARP resolution window
        if step == 500 || step == 2_500 {
            let sock = sockets.get_mut::<icmp::Socket>(handle);
            if sock.can_send()
                && let Ok(buf) = sock.send(echo.buffer_len(), dest)
            {
                let mut pkt = Icmpv4Packet::new_unchecked(buf);
                echo.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::default());
            }
        }
    }

    Err("timed out waiting for ICMP EchoReply")
}

/// High-level live DHCPv4 acquisition over either VirtIO-net (QEMU) or RP1 Cadence GEM (Pi 5).
pub fn live_dhcp_v4<T: VirtioTransport>(
    transport: T,
    nic: NicKind,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<NetConfig, &'static str> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err("VirtIO-MMIO v2 (modern) required");
            }
            let mut dev = VirtioNetDevice::init(transport, v.slot, virtio_dma)?;
            run_dhcp_v4(&mut dev, v.mac)
        }
        NicKind::CadenceGem(g) => {
            let mut dev = GemNetDevice::init(transport, g, gem_dma)?;
            run_dhcp_v4(&mut dev, g.mac)
        }
    }
}

/// High-level live ICMP Echo ping over either VirtIO-net (QEMU) or RP1 Cadence GEM (Pi 5).
pub fn live_icmp_ping<T: VirtioTransport>(
    transport: T,
    nic: NicKind,
    cfg: &NetConfig,
    target: [u8; 4],
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<PingResult, &'static str> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err("VirtIO-MMIO v2 (modern) required");
            }
            let mut dev = VirtioNetDevice::init(transport, v.slot, virtio_dma)?;
            run_icmp_ping(&mut dev, v.mac, cfg, target)
        }
        NicKind::CadenceGem(g) => {
            let mut dev = GemNetDevice::init(transport, g, gem_dma)?;
            run_icmp_ping(&mut dev, g.mac, cfg, target)
        }
    }
}

/// High-level live DNS A-record resolution over either VirtIO-net (QEMU) or RP1 Cadence GEM (Pi 5).
pub fn live_dns_resolve<T: VirtioTransport>(
    transport: T,
    nic: NicKind,
    cfg: &NetConfig,
    hostname: &str,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<[u8; 4], &'static str> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err("VirtIO-MMIO v2 (modern) required");
            }
            let mut dev = VirtioNetDevice::init(transport, v.slot, virtio_dma)?;
            run_dns_query(&mut dev, v.mac, cfg, hostname)
        }
        NicKind::CadenceGem(g) => {
            let mut dev = GemNetDevice::init(transport, g, gem_dma)?;
            run_dns_query(&mut dev, g.mac, cfg, hostname)
        }
    }
}

/// Parse a dotted-quad IPv4 string (`"1.1.1.1"`) without heap allocation.
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut idx = 0usize;
    for part in s.split('.') {
        if idx >= 4 || part.is_empty() {
            return None;
        }
        out[idx] = part.parse::<u8>().ok()?;
        idx += 1;
    }
    if idx == 4 { Some(out) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn smoltcp_emits_valid_ethernet_frame_no_alloc() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let frame_len = verify_smoltcp_ring3_stack(mac).expect("smoltcp self-test");
        assert!(frame_len >= 42);
    }

    #[test]
    fn virtio_probe_finds_net_device_and_mac() {
        let info = probe_virtio_net(|off| match off {
            0x400 => Ok(VIRTIO_MMIO_MAGIC),
            0x404 => Ok(2),
            0x408 => Ok(VIRTIO_DEVICE_NET),
            0x40C => Ok(0x554D_4551),
            0x500 => Ok(u32::from_le_bytes([0x52, 0x54, 0x00, 0x12])),
            0x504 => Ok(u32::from_le_bytes([0x34, 0x56, 0x00, 0x00])),
            _ => Ok(0),
        })
        .expect("should find virtio-net at slot 2");
        assert_eq!(info.slot, 2);
        assert_eq!(info.version, 2);
        assert_eq!(info.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    struct MockGemTransport {
        ncr_writes: AtomicU32,
        dmacfg: AtomicU32,
    }

    impl VirtioTransport for &MockGemTransport {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                gem::REG_MID => Ok(0x0007_0109), // Raspberry Pi 5 RP1 Cadence GEM rev 1p09
                gem::REG_SA1B => Ok(u32::from_le_bytes([0xD8, 0x3A, 0xDD, 0xAA])),
                gem::REG_SA1T => Ok(u32::from_le_bytes([0xBB, 0xCC, 0x00, 0x00])),
                _ => Ok(0),
            }
        }

        fn write32(&self, offset: u64, val: u32) -> Result<(), SysError> {
            if offset == gem::REG_NCR {
                self.ncr_writes.fetch_add(1, Ordering::Relaxed);
            } else if offset == gem::REG_DMACFG {
                self.dmacfg.store(val, Ordering::Relaxed);
            }
            Ok(())
        }

        fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError> {
            Ok((r as *const T as usize) as u64)
        }
    }

    #[test]
    fn rpi5_rp1_gem_probe_and_init_64bit_dma() {
        let mock = MockGemTransport {
            ncr_writes: AtomicU32::new(0),
            dmacfg: AtomicU32::new(0),
        };
        let nic =
            probe_nic(|off| (&mock).read32(off)).expect("should detect Pi 5 RP1 Cadence GEM");
        let NicKind::CadenceGem(info) = nic else {
            panic!("expected CadenceGem");
        };
        assert_eq!(info.module_id, 0x0007_0109);
        assert_eq!(info.mac, [0xD8, 0x3A, 0xDD, 0xAA, 0xBB, 0xCC]);

        let dma = GemDma::new();
        let mut dev = GemNetDevice::init(&mock, info, &dma).expect("gem init");
        // Verify 64-bit DMA mode bit (bit 30) was programmed into DMACFG
        assert_ne!(mock.dmacfg.load(Ordering::Relaxed) & (1 << 30), 0);
        // Verify smoltcp TX queues a frame and triggers NCR_TSTART
        let tx = dev.transmit(Instant::from_millis(0)).expect("tx token");
        tx.consume(60, |buf| buf.fill(0xAB));
        assert_eq!(dev.tx_packets, 1);
        assert!(mock.ncr_writes.load(Ordering::Relaxed) >= 3);
    }

    #[test]
    fn parse_ipv4_valid_and_invalid() {
        assert_eq!(parse_ipv4("1.1.1.1"), Some([1, 1, 1, 1]));
        assert_eq!(parse_ipv4("10.0.2.2"), Some([10, 0, 2, 2]));
        assert_eq!(parse_ipv4("10.0.2"), None);
        assert_eq!(parse_ipv4("999.0.0.1"), None);
    }
}
