#![no_std]

//! EL0 Networking Stack (`smoltcp` IPv4/UDP/ICMP/`DHCPv4`/DNS + Capability-Scoped Drivers).
//!
//! Supports:
//! - Raspberry Pi 5 (16 GB): RP1 Cadence GEM (`macb`) Gigabit Ethernet (`gem.rs`)
//! - QEMU `virt` test harness: Modern `VirtIO` 1.0+ (v2) MMIO (`virtio.rs`)
//!
//! EL0 network stack.

#[cfg(feature = "driver-gem")]
pub mod gem;
#[cfg(all(feature = "tcp", any(feature = "ipv4", feature = "ipv6")))]
pub mod stack;
#[cfg(feature = "driver-virtio")]
pub mod virtio;

#[cfg(feature = "driver-gem")]
pub use gem::{GemDma, GemInfo, GemNetDevice, probe_cadence_gem};
pub use smoltcp::phy::Device as NetDevice;
#[cfg(all(feature = "tcp", feature = "ipv4", feature = "dns"))]
pub use stack::DnsStatus;
#[cfg(all(feature = "tcp", feature = "ipv4", feature = "icmp"))]
pub use stack::PingStatus;
#[cfg(all(feature = "tcp", any(feature = "ipv4", feature = "ipv6")))]
pub use stack::{NetStack, NetStackStorage, SSH_PORT, TCP_BUF_SIZE, TcpEvent};
#[cfg(feature = "driver-virtio")]
pub use virtio::{VirtioNetDevice, VirtioNetDma};

use core::num::NonZeroU64;
use newos_abi::SysError;

/// Structured error type for EL0 networking drivers, `smoltcp` operations, and self-tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetError {
    /// Capability-scoped MMIO register read or write failed.
    MmioFailed(SysError),
    /// Virtual-to-physical DMA address translation failed.
    DmaTranslateFailed(SysError),
    /// `VirtIO`-MMIO device is legacy (< v2); modern `VirtIO` 1.0+ is required.
    UnsupportedVirtioVersion,
    /// `VirtIO` device rejected the `FEATURES_OK` status handshake.
    VirtioFeaturesRejected,
    /// `VirtIO` device reported `QUEUE_NUM_MAX` smaller than the driver ring size.
    VirtqueueTooSmall,
    /// Operation requires a configured IPv4 address (currently unconfigured `0.0.0.0`).
    NoIpv4Address,
    /// `DHCPv4` lease acquisition timed out.
    DhcpTimeout,
    /// DNS query could not be started (invalid hostname or query table full).
    DnsStartFailed,
    /// DNS query timed out waiting for a resolver reply.
    DnsTimeout,
    /// DNS resolver reported a query failure.
    DnsQueryFailed,
    /// DNS response contained no matching IPv4/IPv6 address record.
    DnsNoRecord,
    /// `ICMPv4` socket bind failed.
    IcmpBindFailed,
    /// `ICMPv4` Echo Request send failed.
    IcmpSendFailed,
    /// Timed out waiting for an `ICMPv4` Echo Reply.
    IcmpTimeout,
    /// UDP socket bind failed.
    UdpBindFailed,
    /// UDP packet send failed.
    UdpSendFailed,
    /// TCP connect initiation failed.
    TcpConnectFailed,
    /// TCP exchange timed out.
    TcpTimeout,
    /// TCP connection closed before a reply was received.
    TcpClosedEarly,
    /// Self-test emitted frame was shorter than the minimum expected length.
    SelfTestFrameTooShort,
    /// Self-test emitted Ethernet frame had a mismatched source MAC address.
    SelfTestSourceMacMismatch,
    /// Self-test emitted Ethernet frame did not carry IPv6 `EtherType` `0x86DD`.
    SelfTestEtherTypeMismatch,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MmioFailed(err) => write!(f, "MMIO register access failed: {err}"),
            Self::DmaTranslateFailed(err) => write!(f, "DMA virt_to_phys failed: {err}"),
            Self::UnsupportedVirtioVersion => f.write_str("VirtIO-MMIO v2 (modern) required"),
            Self::VirtioFeaturesRejected => f.write_str("VirtIO device rejected FEATURES_OK"),
            Self::VirtqueueTooSmall => f.write_str("virtqueue max size too small"),
            Self::NoIpv4Address => f.write_str("no IPv4 address configured"),
            Self::DhcpTimeout => f.write_str("DHCPv4 lease timed out"),
            Self::DnsStartFailed => f.write_str("DNS start_query failed"),
            Self::DnsTimeout => f.write_str("DNS query timed out"),
            Self::DnsQueryFailed => f.write_str("DNS query failed"),
            Self::DnsNoRecord => f.write_str("DNS returned no matching address record"),
            Self::IcmpBindFailed => f.write_str("ICMP socket bind failed"),
            Self::IcmpSendFailed => f.write_str("ICMP Echo Request send failed"),
            Self::IcmpTimeout => f.write_str("timed out waiting for ICMP EchoReply"),
            Self::UdpBindFailed => f.write_str("UDP socket bind failed"),
            Self::UdpSendFailed => f.write_str("UDP packet send failed"),
            Self::TcpConnectFailed => f.write_str("TCP connect failed"),
            Self::TcpTimeout => f.write_str("TCP exchange timed out"),
            Self::TcpClosedEarly => f.write_str("TCP connection closed before reply"),
            Self::SelfTestFrameTooShort => f.write_str("self-test emitted frame too short"),
            Self::SelfTestSourceMacMismatch => {
                f.write_str("emitted Ethernet frame source MAC mismatch")
            }
            Self::SelfTestEtherTypeMismatch => f.write_str("expected IPv6 EtherType 0x86DD"),
        }
    }
}

impl core::error::Error for NetError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MmioFailed(err) | Self::DmaTranslateFailed(err) => Some(err),
            Self::UnsupportedVirtioVersion
            | Self::VirtioFeaturesRejected
            | Self::VirtqueueTooSmall
            | Self::NoIpv4Address
            | Self::DhcpTimeout
            | Self::DnsStartFailed
            | Self::DnsTimeout
            | Self::DnsQueryFailed
            | Self::DnsNoRecord
            | Self::IcmpBindFailed
            | Self::IcmpSendFailed
            | Self::IcmpTimeout
            | Self::UdpBindFailed
            | Self::UdpSendFailed
            | Self::TcpConnectFailed
            | Self::TcpTimeout
            | Self::TcpClosedEarly
            | Self::SelfTestFrameTooShort
            | Self::SelfTestSourceMacMismatch
            | Self::SelfTestEtherTypeMismatch => None,
        }
    }
}

#[cfg(any(feature = "driver-gem", feature = "driver-virtio"))]
#[inline]
// Intentional: extracts the low 32 bits of a 64-bit DMA physical address (paired with `phys_hi32`).
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn phys_lo32(addr: u64) -> u32 {
    addr as u32
}

#[cfg(any(feature = "driver-gem", feature = "driver-virtio"))]
#[inline]
pub(crate) const fn phys_hi32(addr: u64) -> u32 {
    (addr >> 32) as u32
}

/// Convert a millisecond timestamp into a `smoltcp` [`smoltcp::time::Instant`], clamping extreme
/// values to `±(i64::MAX / 4) / 1_000` (~73,000 years) so neither `Instant::from_millis`'s
/// microsecond multiplication (`* 1_000`) nor `smoltcp`'s internal `Instant + Duration` /
/// `Instant - Instant` timer arithmetic can overflow.
#[cfg(any(
    all(feature = "tcp", any(feature = "ipv4", feature = "ipv6")),
    all(feature = "ipv4", feature = "dns"),
))]
#[inline]
pub(crate) fn instant_from_millis_clamped(now_ms: i64) -> smoltcp::time::Instant {
    const MAX_SAFE_MILLIS: i64 = (i64::MAX / 4) / 1_000;
    const MIN_SAFE_MILLIS: i64 = -MAX_SAFE_MILLIS;
    smoltcp::time::Instant::from_millis(now_ms.clamp(MIN_SAFE_MILLIS, MAX_SAFE_MILLIS))
}

/// Optional interrupt-acknowledgement hook implemented by hardware NIC drivers.
pub trait IrqAckDevice {
    fn ack_interrupts(&self);
}

/// Capability-scoped MMIO + DMA translation & cache-coherency transport injected by EL0 `user-rt`.
pub trait MmioDmaTransport {
    /// Read a 32-bit MMIO register at `offset`.
    ///
    /// # Errors
    ///
    /// Returns a [`SysError`] if the MMIO capability or offset is invalid.
    fn read32(&self, offset: u64) -> Result<u32, SysError>;

    /// Write `val` to a 32-bit MMIO register at `offset`.
    ///
    /// # Errors
    ///
    /// Returns a [`SysError`] if the MMIO capability or offset is invalid.
    fn write32(&self, offset: u64, val: u32) -> Result<(), SysError>;

    /// Translate a pinned EL0 reference `r` to its physical DMA address.
    ///
    /// # Errors
    ///
    /// Returns a [`SysError`] if address translation fails or the memory is not mapped.
    fn virt_to_phys<T>(&self, r: &T) -> Result<u64, SysError>;

    /// Clean data cache lines (`dc cvac`) for `r` before outbound non-coherent DMA.
    ///
    /// # Errors
    ///
    /// Returns a [`SysError`] if the cache maintenance operation fails.
    fn dma_clean<T>(&self, _r: &T) -> Result<(), SysError> {
        Ok(())
    }

    /// Clean & invalidate data cache lines (`dc civac`) for `r` before/after inbound non-coherent DMA.
    ///
    /// # Errors
    ///
    /// Returns a [`SysError`] if the cache maintenance operation fails.
    fn dma_invalidate<T>(&self, _r: &T) -> Result<(), SysError> {
        Ok(())
    }
}
#[cfg(any(feature = "ipv4", all(feature = "ipv6", feature = "udp")))]
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
#[cfg(any(feature = "ipv4", all(feature = "ipv6", feature = "udp")))]
use smoltcp::phy::Device;
#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
use smoltcp::phy::{DeviceCapabilities, Medium, RxToken, TxToken};
#[cfg(feature = "ipv4")]
use smoltcp::socket::dhcpv4;
#[cfg(all(feature = "ipv4", feature = "dns"))]
use smoltcp::socket::dns;
#[cfg(all(feature = "ipv4", feature = "icmp"))]
use smoltcp::socket::icmp;
#[cfg(all(feature = "ipv4", feature = "tcp"))]
use smoltcp::socket::tcp;
#[cfg(all(feature = "udp", any(feature = "ipv4", feature = "ipv6")))]
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata};
#[cfg(any(feature = "ipv4", all(feature = "ipv6", feature = "udp")))]
use smoltcp::time::Instant;
#[cfg(all(feature = "ipv4", feature = "dns"))]
use smoltcp::wire::DnsQueryType;
#[cfg(feature = "ipv4")]
use smoltcp::wire::Ipv4Address;
#[cfg(any(
    all(feature = "ipv4", feature = "ipv6", feature = "dns"),
    all(feature = "ipv6", feature = "udp"),
))]
use smoltcp::wire::Ipv6Address;
#[cfg(any(feature = "ipv4", all(feature = "ipv6", feature = "udp")))]
use smoltcp::wire::{EthernetAddress, HardwareAddress};
#[cfg(all(feature = "ipv4", feature = "icmp"))]
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr};
#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv4", feature = "icmp"),
    all(feature = "ipv4", feature = "dns"),
    all(feature = "ipv4", feature = "tcp"),
    all(feature = "ipv6", feature = "udp"),
))]
use smoltcp::wire::{IpAddress, IpCidr};

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_DEVICE_NET: u32 = 1;
const VIRTIO_MMIO_SLOTS: u8 = 32;
const VIRTIO_MMIO_STRIDE: u64 = 0x200;

const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00C;
const REG_CONFIG_MAC_LO: u64 = 0x100;
const REG_CONFIG_MAC_HI: u64 = 0x104;

/// Discovered `VirtIO`-MMIO network interface metadata (read purely via MMIO capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtioNetInfo {
    pub slot: u8,
    pub version: u32,
    pub vendor_id: u32,
    pub mac: [u8; 6],
}

/// Unified detected EL0 NIC (Raspberry Pi 5 RP1 Cadence GEM or QEMU `VirtIO`-MMIO v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NicKind {
    #[cfg(feature = "driver-virtio")]
    Virtio(VirtioNetInfo),
    #[cfg(feature = "driver-gem")]
    CadenceGem(GemInfo),
}

impl NicKind {
    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        match self {
            #[cfg(feature = "driver-virtio")]
            Self::Virtio(v) => v.mac,
            #[cfg(feature = "driver-gem")]
            Self::CadenceGem(g) => g.mac,
            #[cfg(all(not(feature = "driver-virtio"), not(feature = "driver-gem")))]
            _ => [0; 6],
        }
    }

    #[must_use]
    pub const fn driver_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "driver-virtio")]
            Self::Virtio(_) => "virtio-net-v2",
            #[cfg(feature = "driver-gem")]
            Self::CadenceGem(_) => "rpi5-rp1-gem",
            #[cfg(all(not(feature = "driver-virtio"), not(feature = "driver-gem")))]
            _ => "none",
        }
    }
}

impl core::fmt::Display for NicKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.driver_name())
    }
}

/// Active IPv4 network configuration (acquired via `DHCPv4` or static fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetConfig {
    pub ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
}

impl NetConfig {
    /// Unconfigured placeholder IPv4 configuration (`0.0.0.0/0`, no gateway or DNS).
    pub const UNCONFIGURED: Self = Self {
        ip: [0, 0, 0, 0],
        prefix_len: 0,
        gateway: None,
        dns: None,
    };

    pub const QEMU_DEFAULT: Self = Self {
        ip: [10, 0, 2, 15],
        prefix_len: 24,
        gateway: Some([10, 0, 2, 2]),
        dns: Some([10, 0, 2, 3]),
    };

    /// Returns `true` when a non-zero IPv4 address has been configured.
    #[must_use]
    #[inline]
    pub const fn is_configured(&self) -> bool {
        self.ip[0] != 0 || self.ip[1] != 0 || self.ip[2] != 0 || self.ip[3] != 0
    }
}

impl Default for NetConfig {
    fn default() -> Self {
        Self::UNCONFIGURED
    }
}

/// Active IPv6 network configuration (EUI-64 link-local `fe80::/64`, optional global unicast,
/// gateway, and recursive DNS server).
#[cfg(feature = "ipv6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Config {
    pub link_local: [u8; 16],
    pub global: Option<([u8; 16], u8)>,
    pub gateway: Option<[u8; 16]>,
    pub dns: Option<[u8; 16]>,
}

#[cfg(feature = "ipv6")]
impl Ipv6Config {
    /// Derive a link-local-only IPv6 configuration (`fe80::/64`) from an Ethernet MAC address.
    #[must_use]
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        Self {
            link_local: ipv6_link_local_from_mac(mac),
            global: None,
            gateway: None,
            dns: None,
        }
    }

    #[must_use]
    pub const fn with_global(mut self, addr: [u8; 16], prefix_len: u8) -> Self {
        self.global = Some((addr, prefix_len));
        self
    }

    #[must_use]
    pub const fn with_gateway(mut self, gw: [u8; 16]) -> Self {
        self.gateway = Some(gw);
        self
    }

    #[must_use]
    pub const fn with_dns(mut self, dns: [u8; 16]) -> Self {
        self.dns = Some(dns);
        self
    }
}

/// Probe for either a `VirtIO`-MMIO network device or a Raspberry Pi 5 RP1 Cadence GEM controller.
pub fn probe_nic<F>(mut read32: F) -> Option<NicKind>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    #[cfg(feature = "driver-virtio")]
    if let Some(v) = probe_virtio_net(&mut read32) {
        return Some(NicKind::Virtio(v));
    }
    #[cfg(feature = "driver-gem")]
    if let Some(g) = probe_cadence_gem(&mut read32) {
        return Some(NicKind::CadenceGem(g));
    }
    let _ = &mut read32;
    None
}

/// Probe all 32 `VirtIO`-MMIO slots using a capability-gated 32-bit MMIO reader.
pub fn probe_virtio_net<F>(mut read32: F) -> Option<VirtioNetInfo>
where
    F: FnMut(u64) -> Result<u32, SysError>,
{
    for slot in 0..VIRTIO_MMIO_SLOTS {
        let base = u64::from(slot) * VIRTIO_MMIO_STRIDE;
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
            slot,
            version,
            vendor_id,
            mac,
        });
    }
    None
}

/// Fixed-capacity EL0 loopback Ethernet `smoltcp::phy::Device` for self-tests.
#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
struct LoopbackEth {
    buf: [u8; 512],
    len: usize,
}

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
impl LoopbackEth {
    const fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }
}

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
struct LoopRx<'a> {
    data: &'a mut [u8],
    len: &'a mut usize,
}

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
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

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
struct LoopTx<'a> {
    data: &'a mut [u8],
    len: &'a mut usize,
}

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
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

#[cfg(any(
    all(feature = "ipv4", feature = "udp"),
    all(feature = "ipv6", feature = "udp"),
))]
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

/// Verify the EL0 `smoltcp` Ethernet + IPv4 + UDP stack end-to-end.
///
/// # Errors
///
/// Returns [`NetError::UdpBindFailed`], [`NetError::UdpSendFailed`],
/// [`NetError::SelfTestFrameTooShort`], or [`NetError::SelfTestSourceMacMismatch`] if the
/// loopback self-test fails.
#[cfg(all(feature = "ipv4", feature = "udp"))]
pub fn verify_smoltcp_el0_stack(mac: [u8; 6]) -> Result<usize, NetError> {
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
    udp_sock.bind(5353).map_err(|_| NetError::UdpBindFailed)?;

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(udp_sock);

    let payload = b"newos-el0-smoltcp";
    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(payload, (IpAddress::v4(10, 0, 2, 2), 53))
        .map_err(|_| NetError::UdpSendFailed)?;

    let _ = iface.poll(Instant::from_millis(10), &mut device, &mut sockets);
    if device.len < 42 {
        return Err(NetError::SelfTestFrameTooShort);
    }
    if device.buf[6..12] != mac {
        return Err(NetError::SelfTestSourceMacMismatch);
    }
    Ok(device.len)
}

/// Result of a live EL0 ICMP Echo Request/Reply round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PingResult {
    pub seq: u16,
    pub target: [u8; 4],
}

/// Acquire a live IPv4 address, gateway, and DNS server via `smoltcp` `DHCPv4`.
///
/// # Errors
///
/// Returns [`NetError::DhcpTimeout`] if no lease is configured within the poll budget.
#[cfg(feature = "ipv4")]
pub fn run_dhcp_v4<D: Device>(device: &mut D, mac: [u8; 6]) -> Result<NetConfig, NetError> {
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
                gateway: cfg.router.as_ref().map(Ipv4Address::octets),
                dns: cfg.dns_servers.first().map(Ipv4Address::octets),
            });
        }
    }
    Err(NetError::DhcpTimeout)
}

/// Resolve a hostname to an IPv4 address via `smoltcp` DNS A-record query using a real `NetClock`.
///
/// # Errors
///
/// Returns [`NetError::DnsStartFailed`], [`NetError::DnsTimeout`], [`NetError::DnsQueryFailed`],
/// or [`NetError::DnsNoRecord`] if resolution fails.
#[cfg(all(feature = "ipv4", feature = "dns"))]
pub fn run_dns_query_with_clock<D: Device, C: NetClock>(
    device: &mut D,
    clock: &mut C,
    mac: [u8; 6],
    cfg: &NetConfig,
    hostname: &str,
    timeout_ms: i64,
) -> Result<[u8; 4], NetError> {
    let start_ms = clock.now_millis();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, instant_from_millis_clamped(start_ms));
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
        .map_err(|_| NetError::DnsStartFailed)?;

    loop {
        let now_ms = clock.now_millis();
        if now_ms.saturating_sub(start_ms) > timeout_ms {
            return Err(NetError::DnsTimeout);
        }
        let _ = iface.poll(instant_from_millis_clamped(now_ms), device, &mut sockets);
        match sockets
            .get_mut::<dns::Socket>(handle)
            .get_query_result(query)
        {
            Ok(addrs) => {
                if let Some(IpAddress::Ipv4(v4)) = addrs.first() {
                    return Ok(v4.octets());
                }
                return Err(NetError::DnsNoRecord);
            }
            Err(dns::GetQueryResultError::Pending) => {}
            Err(dns::GetQueryResultError::Failed) => return Err(NetError::DnsQueryFailed),
        }
    }
}

/// Resolve a hostname to an IPv4 address via `smoltcp` DNS A-record query.
///
/// # Errors
///
/// Returns [`NetError::DnsStartFailed`], [`NetError::DnsTimeout`], [`NetError::DnsQueryFailed`],
/// or [`NetError::DnsNoRecord`] if resolution fails.
#[cfg(all(feature = "ipv4", feature = "dns"))]
pub fn run_dns_query<D: Device>(
    device: &mut D,
    mac: [u8; 6],
    cfg: &NetConfig,
    hostname: &str,
) -> Result<[u8; 4], NetError> {
    struct StepClock(i64);
    impl NetClock for StepClock {
        fn now_millis(&mut self) -> i64 {
            let v = self.0;
            self.0 += 1;
            v
        }
    }
    let mut clock = StepClock(0);
    run_dns_query_with_clock(device, &mut clock, mac, cfg, hostname, 40_000)
}

/// Perform a live ARP + ICMP Echo Request/Reply round-trip to `target` over any `smoltcp` `Device`.
///
/// # Errors
///
/// Returns [`NetError::IcmpBindFailed`], [`NetError::IcmpSendFailed`], or
/// [`NetError::IcmpTimeout`] if the ping fails.
#[cfg(all(feature = "ipv4", feature = "icmp"))]
pub fn run_icmp_ping<D: Device>(
    device: &mut D,
    mac: [u8; 6],
    cfg: &NetConfig,
    target: [u8; 4],
) -> Result<PingResult, NetError> {
    const IDENT: u16 = 0x5E14;
    const SEQ: u16 = 1;

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
    icmp_sock
        .bind(icmp::Endpoint::Ident(IDENT))
        .map_err(|_| NetError::IcmpBindFailed)?;

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(icmp_sock);

    let dest = IpAddress::Ipv4(Ipv4Address::from(target));
    let payload = b"newos-el0";
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
                .map_err(|_| NetError::IcmpSendFailed)?;
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

    Err(NetError::IcmpTimeout)
}

/// High-level live `DHCPv4` acquisition over either `VirtIO`-net (QEMU) or RP1 Cadence GEM (Pi 5).
///
/// # Errors
///
/// Returns a [`NetError`] if NIC initialization or `DHCPv4` lease acquisition fails.
#[cfg(all(feature = "ipv4", feature = "driver-virtio", feature = "driver-gem"))]
pub fn live_dhcp_v4<T: MmioDmaTransport>(
    transport: T,
    nic: NicKind,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<NetConfig, NetError> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err(NetError::UnsupportedVirtioVersion);
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

/// High-level live ICMP Echo ping over either `VirtIO`-net (QEMU) or RP1 Cadence GEM (Pi 5).
///
/// # Errors
///
/// Returns a [`NetError`] if NIC initialization or ICMP ping fails.
#[cfg(all(
    feature = "ipv4",
    feature = "icmp",
    feature = "driver-virtio",
    feature = "driver-gem"
))]
pub fn live_icmp_ping<T: MmioDmaTransport>(
    transport: T,
    nic: NicKind,
    cfg: &NetConfig,
    target: [u8; 4],
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<PingResult, NetError> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err(NetError::UnsupportedVirtioVersion);
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

/// High-level live DNS A-record resolution using a real monotonic `NetClock`.
///
/// # Errors
///
/// Returns a [`NetError`] if NIC initialization or DNS resolution fails.
// Intentional: public API preserved for downstream `supervisor-pd` callers.
#[allow(clippy::too_many_arguments)]
#[cfg(all(
    feature = "ipv4",
    feature = "dns",
    feature = "driver-virtio",
    feature = "driver-gem"
))]
pub fn live_dns_resolve_with_clock<T: MmioDmaTransport, C: NetClock>(
    transport: T,
    clock: &mut C,
    nic: NicKind,
    cfg: &NetConfig,
    hostname: &str,
    timeout_ms: i64,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<[u8; 4], NetError> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err(NetError::UnsupportedVirtioVersion);
            }
            let mut dev = VirtioNetDevice::init(transport, v.slot, virtio_dma)?;
            run_dns_query_with_clock(&mut dev, clock, v.mac, cfg, hostname, timeout_ms)
        }
        NicKind::CadenceGem(g) => {
            let mut dev = GemNetDevice::init(transport, g, gem_dma)?;
            run_dns_query_with_clock(&mut dev, clock, g.mac, cfg, hostname, timeout_ms)
        }
    }
}

/// High-level live DNS A-record resolution over either `VirtIO`-net (QEMU) or RP1 Cadence GEM (Pi 5).
///
/// # Errors
///
/// Returns a [`NetError`] if NIC initialization or DNS resolution fails.
#[cfg(all(
    feature = "ipv4",
    feature = "dns",
    feature = "driver-virtio",
    feature = "driver-gem"
))]
pub fn live_dns_resolve<T: MmioDmaTransport>(
    transport: T,
    nic: NicKind,
    cfg: &NetConfig,
    hostname: &str,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<[u8; 4], NetError> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err(NetError::UnsupportedVirtioVersion);
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

/// Monotonic millisecond clock source driving `smoltcp` timers and TCP retransmissions.
pub trait NetClock {
    fn now_millis(&mut self) -> i64;
}

/// Hardware cycle-counter-backed monotonic `NetClock` (wraps `user_rt::read_cycles()`).
pub struct CycleClock<F: FnMut() -> u64> {
    read_cycles: F,
    start_cycles: u64,
    cycles_per_ms: NonZeroU64,
}

impl<F: FnMut() -> u64> core::fmt::Debug for CycleClock<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CycleClock")
            .field("start_cycles", &self.start_cycles)
            .field("cycles_per_ms", &self.cycles_per_ms)
            .finish_non_exhaustive()
    }
}

impl<F: FnMut() -> u64> CycleClock<F> {
    pub fn new(mut read_cycles: F, cycles_per_ms: u64) -> Self {
        let start_cycles = read_cycles();
        Self {
            read_cycles,
            start_cycles,
            cycles_per_ms: NonZeroU64::new(cycles_per_ms).unwrap_or(NonZeroU64::MIN),
        }
    }
}

impl<F: FnMut() -> u64> NetClock for CycleClock<F> {
    #[inline]
    fn now_millis(&mut self) -> i64 {
        let elapsed = (self.read_cycles)().saturating_sub(self.start_cycles);
        i64::try_from(elapsed / self.cycles_per_ms).unwrap_or(i64::MAX)
    }
}

/// Open a live IPv4 TCP connection, send `tx_payload`, read up to `rx_out.len()` reply bytes,
/// and close cleanly.
///
/// # Errors
///
/// Returns [`NetError::TcpConnectFailed`], [`NetError::TcpTimeout`], or
/// [`NetError::TcpClosedEarly`] if the TCP exchange fails.
// Intentional: public API preserved for downstream callers.
#[allow(clippy::too_many_arguments)]
#[cfg(all(feature = "ipv4", feature = "tcp"))]
pub fn run_tcp_exchange<D: Device, C: NetClock>(
    device: &mut D,
    clock: &mut C,
    mac: [u8; 6],
    cfg: &NetConfig,
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    tx_payload: &[u8],
    rx_out: &mut [u8],
    timeout_ms: i64,
) -> Result<usize, NetError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ExchangePhase {
        Active,
        Closing,
    }

    let start_ms = clock.now_millis();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, instant_from_millis_clamped(start_ms));
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

    let mut rx_buf = [0u8; 1024];
    let mut tx_buf = [0u8; 1024];
    let tcp_sock = tcp::Socket::new(
        tcp::SocketBuffer::new(&mut rx_buf[..]),
        tcp::SocketBuffer::new(&mut tx_buf[..]),
    );

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(tcp_sock);

    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv4(Ipv4Address::from(remote_ip)), remote_port),
            local_port,
        )
        .map_err(|_| NetError::TcpConnectFailed)?;

    let mut sent = 0usize;
    let mut received = 0usize;
    let mut phase = ExchangePhase::Active;

    loop {
        let now_ms = clock.now_millis();
        if now_ms.saturating_sub(start_ms) > timeout_ms {
            return Err(NetError::TcpTimeout);
        }
        let _ = iface.poll(instant_from_millis_clamped(now_ms), device, &mut sockets);
        let sock = sockets.get_mut::<tcp::Socket>(handle);

        if sent < tx_payload.len()
            && sock.can_send()
            && let Ok(n) = sock.send_slice(&tx_payload[sent..])
        {
            sent += n;
        }
        if sock.can_recv()
            && received < rx_out.len()
            && let Ok(n) = sock.recv_slice(&mut rx_out[received..])
        {
            received += n;
            if received > 0 && phase == ExchangePhase::Active {
                sock.close();
                phase = ExchangePhase::Closing;
            }
        }
        if phase == ExchangePhase::Closing && !sock.is_active() {
            return Ok(received);
        }
        if !sock.may_recv() && sent == tx_payload.len() && received > 0 {
            return Ok(received);
        }
        if !sock.is_open() {
            if received > 0 || (tx_payload.is_empty() && sent == 0) {
                return Ok(received);
            }
            return Err(NetError::TcpClosedEarly);
        }
    }
}

/// High-level live IPv4 TCP exchange over `VirtIO`-net (QEMU) or RP1 Cadence GEM (Pi 5).
///
/// # Errors
///
/// Returns a [`NetError`] if NIC initialization or the TCP exchange fails.
// Intentional: public API preserved for downstream callers.
#[allow(clippy::too_many_arguments)]
#[cfg(all(
    feature = "ipv4",
    feature = "tcp",
    feature = "driver-virtio",
    feature = "driver-gem"
))]
pub fn live_tcp_exchange<T: MmioDmaTransport, C: NetClock>(
    transport: T,
    clock: &mut C,
    nic: NicKind,
    cfg: &NetConfig,
    remote_ip: [u8; 4],
    remote_port: u16,
    local_port: u16,
    tx_payload: &[u8],
    rx_out: &mut [u8],
    timeout_ms: i64,
    virtio_dma: &VirtioNetDma,
    gem_dma: &GemDma,
) -> Result<usize, NetError> {
    match nic {
        NicKind::Virtio(v) => {
            if v.version < 2 {
                return Err(NetError::UnsupportedVirtioVersion);
            }
            let mut dev = VirtioNetDevice::init(transport, v.slot, virtio_dma)?;
            run_tcp_exchange(
                &mut dev,
                clock,
                v.mac,
                cfg,
                remote_ip,
                remote_port,
                local_port,
                tx_payload,
                rx_out,
                timeout_ms,
            )
        }
        NicKind::CadenceGem(g) => {
            let mut dev = GemNetDevice::init(transport, g, gem_dma)?;
            run_tcp_exchange(
                &mut dev,
                clock,
                g.mac,
                cfg,
                remote_ip,
                remote_port,
                local_port,
                tx_payload,
                rx_out,
                timeout_ms,
            )
        }
    }
}

/// Derive an RFC 4291 EUI-64 IPv6 link-local address (`fe80::/64`) from a 48-bit MAC address.
#[must_use]
pub const fn ipv6_link_local_from_mac(mac: [u8; 6]) -> [u8; 16] {
    [
        0xfe,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// Resolve a hostname to an IPv6 address via `smoltcp` DNS AAAA-record query.
///
/// # Errors
///
/// Returns [`NetError::DnsStartFailed`], [`NetError::DnsTimeout`], [`NetError::DnsQueryFailed`],
/// or [`NetError::DnsNoRecord`] if resolution fails.
#[cfg(all(feature = "ipv4", feature = "ipv6", feature = "dns"))]
pub fn run_dns_query_aaaa_with_clock<D: Device, C: NetClock>(
    device: &mut D,
    clock: &mut C,
    mac: [u8; 6],
    cfg: &NetConfig,
    hostname: &str,
    timeout_ms: i64,
) -> Result<[u8; 16], NetError> {
    let start_ms = clock.now_millis();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, device, instant_from_millis_clamped(start_ms));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from(cfg.ip)),
            cfg.prefix_len,
        ));
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv6(Ipv6Address::from(ipv6_link_local_from_mac(mac))),
            64,
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
        .start_query(iface.context(), hostname, DnsQueryType::Aaaa)
        .map_err(|_| NetError::DnsStartFailed)?;

    loop {
        let now_ms = clock.now_millis();
        if now_ms.saturating_sub(start_ms) > timeout_ms {
            return Err(NetError::DnsTimeout);
        }
        let _ = iface.poll(instant_from_millis_clamped(now_ms), device, &mut sockets);
        match sockets
            .get_mut::<dns::Socket>(handle)
            .get_query_result(query)
        {
            Ok(addrs) => {
                if let Some(IpAddress::Ipv6(v6)) = addrs.first() {
                    return Ok(v6.octets());
                }
                return Err(NetError::DnsNoRecord);
            }
            Err(dns::GetQueryResultError::Pending) => {}
            Err(dns::GetQueryResultError::Failed) => return Err(NetError::DnsQueryFailed),
        }
    }
}

/// Verify the EL0 `smoltcp` Ethernet + IPv6 link-local + UDP stack end-to-end.
///
/// # Errors
///
/// Returns [`NetError::UdpBindFailed`], [`NetError::UdpSendFailed`],
/// [`NetError::SelfTestFrameTooShort`], or [`NetError::SelfTestEtherTypeMismatch`] if the
/// loopback self-test fails.
#[cfg(all(feature = "ipv6", feature = "udp"))]
pub fn verify_smoltcp_ipv6_el0_stack(mac: [u8; 6]) -> Result<usize, NetError> {
    let mut device = LoopbackEth::new();
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    let ll = ipv6_link_local_from_mac(mac);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(Ipv6Address::from(ll)), 64));
    });

    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_data = [0u8; 128];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_data = [0u8; 128];
    let mut udp_sock = udp::Socket::new(
        PacketBuffer::new(&mut rx_meta[..], &mut rx_data[..]),
        PacketBuffer::new(&mut tx_meta[..], &mut tx_data[..]),
    );
    udp_sock.bind(5353).map_err(|_| NetError::UdpBindFailed)?;

    let mut storage = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(udp_sock);

    // Send UDP packet to link-local all-nodes multicast (`ff02::1`) — emits IPv6 frame immediately.
    let all_nodes = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    sockets
        .get_mut::<udp::Socket>(handle)
        .send_slice(b"newos-ipv6", (IpAddress::Ipv6(all_nodes), 5353))
        .map_err(|_| NetError::UdpSendFailed)?;

    let _ = iface.poll(Instant::from_millis(10), &mut device, &mut sockets);
    if device.len < 62 {
        return Err(NetError::SelfTestFrameTooShort);
    }
    // EtherType 0x86DD (IPv6)
    if device.buf[12..14] != [0x86, 0xDD] {
        return Err(NetError::SelfTestEtherTypeMismatch);
    }
    Ok(device.len)
}

/// Parse a strict dotted-quad IPv4 string (`"1.1.1.1"`) without heap allocation.
#[must_use]
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    s.parse::<core::net::Ipv4Addr>()
        .ok()
        .map(|addr| addr.octets())
}

#[cfg(test)]
#[cfg(all(
    feature = "ipv4",
    feature = "ipv6",
    feature = "tcp",
    feature = "udp",
    feature = "icmp",
    feature = "dns",
    feature = "driver-gem",
    feature = "driver-virtio"
))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn smoltcp_emits_valid_ethernet_frame_no_alloc() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let frame_len = verify_smoltcp_el0_stack(mac).expect("smoltcp self-test");
        assert!(frame_len >= 42);
    }

    #[test]
    fn smoltcp_ipv6_link_local_eui64_and_udp_frame() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let ll = ipv6_link_local_from_mac(mac);
        assert_eq!(
            ll,
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56
            ]
        );
        let frame_len = verify_smoltcp_ipv6_el0_stack(mac).expect("smoltcp ipv6 self-test");
        assert!(frame_len >= 62);
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
        dma_cleans: AtomicU32,
        dma_invalidates: AtomicU32,
    }

    impl MmioDmaTransport for &MockGemTransport {
        fn read32(&self, offset: u64) -> Result<u32, SysError> {
            match offset {
                gem::REG_MID => Ok(0x0007_0109), // Raspberry Pi 5 RP1 Cadence GEM rev 1p09
                gem::REG_NSR => Ok(1 << 2),      // MDIO idle
                gem::REG_MAN => Ok(u32::from(gem::BMSR_LSTATUS)),
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
            Ok(core::ptr::from_ref::<T>(r) as usize as u64)
        }

        fn dma_clean<T>(&self, _r: &T) -> Result<(), SysError> {
            self.dma_cleans.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn dma_invalidate<T>(&self, _r: &T) -> Result<(), SysError> {
            self.dma_invalidates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn rpi5_rp1_gem_probe_and_init_64bit_dma() {
        let mock = MockGemTransport {
            ncr_writes: AtomicU32::new(0),
            dmacfg: AtomicU32::new(0),
            dma_cleans: AtomicU32::new(0),
            dma_invalidates: AtomicU32::new(0),
        };
        let nic = probe_nic(|off| (&mock).read32(off)).expect("should detect Pi 5 RP1 Cadence GEM");
        let NicKind::CadenceGem(info) = nic else {
            panic!("expected CadenceGem");
        };
        assert_eq!(info.module_id, 0x0007_0109);
        assert_eq!(info.mac, [0xD8, 0x3A, 0xDD, 0xAA, 0xBB, 0xCC]);

        let dma = GemDma::new();
        let mut dev = GemNetDevice::init(&mock, info, &dma).expect("gem init");
        // Verify 64-bit DMA mode bit (bit 30) was programmed into DMACFG
        assert_ne!(mock.dmacfg.load(Ordering::Relaxed) & (1 << 30), 0);
        // Verify MDIO Clause 22 link-up probe works on BCM54213PE PHY address 1
        assert_eq!(dev.phy_link_up(gem::RPI5_PHY_ADDR), Ok(true));
        // Verify smoltcp TX queues a frame, performs DMA cache clean, and triggers NCR_TSTART
        let tx = dev.transmit(Instant::from_millis(0)).expect("tx token");
        tx.consume(60, |buf| buf.fill(0xAB));
        assert_eq!(dev.tx_packets, 1);
        assert!(mock.ncr_writes.load(Ordering::Relaxed) >= 3);
        assert!(mock.dma_cleans.load(Ordering::Relaxed) >= 4);
        assert!(mock.dma_invalidates.load(Ordering::Relaxed) >= 8);
    }

    #[test]
    fn parse_ipv4_valid_and_invalid() {
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("1.1.1.1"), Some([1, 1, 1, 1]));
        assert_eq!(parse_ipv4("10.0.2.2"), Some([10, 0, 2, 2]));
        assert_eq!(parse_ipv4("10.0.2.15"), Some([10, 0, 2, 15]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("10.0.2"), None);
        assert_eq!(parse_ipv4("999.0.0.1"), None);
        assert_eq!(parse_ipv4("+1.+2.+3.+4"), None);
        assert_eq!(parse_ipv4("01.02.03.04"), None);
        assert_eq!(parse_ipv4("00.0.0.0"), None);
        assert_eq!(parse_ipv4("1.2.3.04"), None);
        assert_eq!(parse_ipv4("+0.0.0.0"), None);
    }

    struct WireQueue {
        frames: [[u8; 512]; 8],
        lens: [usize; 8],
        head: usize,
        tail: usize,
    }

    impl WireQueue {
        const fn new() -> Self {
            Self {
                frames: [[0; 512]; 8],
                lens: [0; 8],
                head: 0,
                tail: 0,
            }
        }

        fn push(&mut self, data: &[u8]) {
            let next = (self.tail + 1) % 8;
            if next != self.head {
                let n = data.len().min(512);
                self.frames[self.tail][..n].copy_from_slice(&data[..n]);
                self.lens[self.tail] = n;
                self.tail = next;
            }
        }

        fn pop<'a>(&mut self, out: &'a mut [u8; 512]) -> Option<&'a [u8]> {
            if self.head == self.tail {
                return None;
            }
            let n = self.lens[self.head];
            out[..n].copy_from_slice(&self.frames[self.head][..n]);
            self.head = (self.head + 1) % 8;
            Some(&out[..n])
        }
    }

    struct WireEndpoint<'a> {
        rx: &'a mut WireQueue,
        tx: &'a mut WireQueue,
        scratch: [u8; 512],
    }

    struct WireRx<'a> {
        frame: &'a [u8],
    }

    impl RxToken for WireRx<'_> {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(self.frame)
        }
    }

    struct WireTx<'a> {
        tx: &'a mut WireQueue,
    }

    impl TxToken for WireTx<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut tmp = [0u8; 512];
            let n = len.min(tmp.len());
            let res = f(&mut tmp[..n]);
            self.tx.push(&tmp[..n]);
            res
        }
    }

    impl Device for WireEndpoint<'_> {
        type RxToken<'a>
            = WireRx<'a>
        where
            Self: 'a;
        type TxToken<'a>
            = WireTx<'a>
        where
            Self: 'a;

        fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.rx.pop(&mut self.scratch)?;
            Some((WireRx { frame }, WireTx { tx: self.tx }))
        }

        fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
            Some(WireTx { tx: self.tx })
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ethernet;
            caps.max_transmission_unit = 512;
            caps
        }
    }

    fn make_test_iface(
        mac: [u8; 6],
        ip: [u8; 4],
        rx: &mut WireQueue,
        tx: &mut WireQueue,
    ) -> Interface {
        let mut dev = WireEndpoint {
            rx,
            tx,
            scratch: [0; 512],
        };
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress(mac))),
            &mut dev,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::from(ip)), 24));
        });
        iface
    }

    #[test]
    fn smoltcp_tcp_handshake_and_echo_exchange_no_alloc() {
        let mut c2s = WireQueue::new();
        let mut s2c = WireQueue::new();

        let client_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

        let mut c_iface = make_test_iface(client_mac, [10, 0, 2, 15], &mut s2c, &mut c2s);
        let mut s_iface = make_test_iface(server_mac, [10, 0, 2, 2], &mut c2s, &mut s2c);

        let mut c_rx = [0u8; 512];
        let mut c_tx = [0u8; 512];
        let mut c_storage = [SocketStorage::EMPTY; 1];
        let mut c_sockets = SocketSet::new(&mut c_storage[..]);
        let c_handle = c_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut c_rx[..]),
            tcp::SocketBuffer::new(&mut c_tx[..]),
        ));

        let mut s_rx = [0u8; 512];
        let mut s_tx = [0u8; 512];
        let mut s_storage = [SocketStorage::EMPTY; 1];
        let mut s_sockets = SocketSet::new(&mut s_storage[..]);
        let s_handle = s_sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut s_rx[..]),
            tcp::SocketBuffer::new(&mut s_tx[..]),
        ));

        s_sockets
            .get_mut::<tcp::Socket>(s_handle)
            .listen(8080)
            .expect("server listen");
        c_sockets
            .get_mut::<tcp::Socket>(c_handle)
            .connect(c_iface.context(), (IpAddress::v4(10, 0, 2, 2), 8080), 49152)
            .expect("client connect");

        let mut cycles = 0u64;
        let mut clock = CycleClock::new(
            || {
                cycles += 1_000;
                cycles
            },
            1_000,
        );

        let mut client_sent = false;
        let mut reply = [0u8; 64];
        let mut reply_len = 0usize;

        for _ in 0..64 {
            let now = Instant::from_millis(clock.now_millis());
            {
                let mut dev = WireEndpoint {
                    rx: &mut s2c,
                    tx: &mut c2s,
                    scratch: [0; 512],
                };
                let _ = c_iface.poll(now, &mut dev, &mut c_sockets);
            }
            {
                let mut dev = WireEndpoint {
                    rx: &mut c2s,
                    tx: &mut s2c,
                    scratch: [0; 512],
                };
                let _ = s_iface.poll(now, &mut dev, &mut s_sockets);
            }

            let cs = c_sockets.get_mut::<tcp::Socket>(c_handle);
            if !client_sent && cs.can_send() {
                cs.send_slice(b"hello-tcp").expect("client send");
                client_sent = true;
            }
            if cs.can_recv() {
                reply_len = cs.recv_slice(&mut reply).expect("client recv");
                break;
            }

            let ss = s_sockets.get_mut::<tcp::Socket>(s_handle);
            if ss.can_recv() && ss.can_send() {
                let mut tmp = [0u8; 64];
                let n = ss.recv_slice(&mut tmp).expect("server recv");
                ss.send_slice(&tmp[..n]).expect("server echo");
            }
        }

        assert_eq!(&reply[..reply_len], b"hello-tcp");
    }

    #[test]
    fn net_error_display_and_error_source() {
        extern crate std;
        use core::error::Error as _;
        use std::format;

        for err in [
            NetError::MmioFailed(SysError::InvalidCapability),
            NetError::DmaTranslateFailed(SysError::InvalidArgument),
        ] {
            assert!(err.source().is_some());
            assert_ne!(format!("{err}"), "");
        }

        for err in [
            NetError::UnsupportedVirtioVersion,
            NetError::VirtioFeaturesRejected,
            NetError::VirtqueueTooSmall,
            NetError::NoIpv4Address,
            NetError::DhcpTimeout,
            NetError::DnsStartFailed,
            NetError::DnsTimeout,
            NetError::DnsQueryFailed,
            NetError::DnsNoRecord,
            NetError::IcmpBindFailed,
            NetError::IcmpSendFailed,
            NetError::IcmpTimeout,
            NetError::UdpBindFailed,
            NetError::UdpSendFailed,
            NetError::TcpConnectFailed,
            NetError::TcpTimeout,
            NetError::TcpClosedEarly,
            NetError::SelfTestFrameTooShort,
            NetError::SelfTestSourceMacMismatch,
            NetError::SelfTestEtherTypeMismatch,
        ] {
            assert!(err.source().is_none());
            assert_ne!(format!("{err}"), "");
        }
    }

    #[test]
    fn cycle_clock_zero_divisor_and_debug() {
        extern crate std;
        use std::format;

        let mut ticks = 0u64;
        let mut clock = CycleClock::new(
            || {
                ticks += 5;
                ticks
            },
            0,
        );
        assert_eq!(clock.now_millis(), 5);
        assert!(format!("{clock:?}").contains("CycleClock"));

        let gem_dma = GemDma::new();
        assert!(format!("{gem_dma:?}").contains("GemDma"));

        let virtio_dma = VirtioNetDma::new();
        assert!(format!("{virtio_dma:?}").contains("VirtioNetDma"));

        let storage = NetStackStorage::new();
        assert!(format!("{storage:?}").contains("NetStackStorage"));

        assert_eq!(NetConfig::default(), NetConfig::UNCONFIGURED);
        assert!(!NetConfig::UNCONFIGURED.is_configured());
        assert!(NetConfig::QEMU_DEFAULT.is_configured());
    }
}
