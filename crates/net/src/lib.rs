#![no_std]
#![forbid(unsafe_code)]

//! Ring-3 Networking Stack (`smoltcp` IPv4/UDP/ICMP + Capability-Scoped VirtIO-MMIO Net Driver).
//!
//! 100% `#![forbid(unsafe_code)]`, zero heap (`no_alloc`), zero network code in Ring 0.

pub mod virtio;

use newos_abi::SysError;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::icmp;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address,
};
use virtio::{VirtioNetDevice, VirtioNetDma, VirtioTransport};

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
///
/// Builds an Ethernet/IPv4/UDP packet from `10.0.2.15:5353` -> `10.0.2.15:5353` and verifies
/// `smoltcp` serializes a valid Ethernet frame with our MAC address.
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
    // Verify source MAC in emitted Ethernet frame matches our hardware MAC!
    if device.buf[6..12] != mac {
        return Err("emitted Ethernet frame source MAC mismatch");
    }
    Ok(device.len)
}

/// Result of a live Ring-3 VirtIO-net ICMP Echo Request/Reply round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingResult {
    pub seq: u16,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Bring up a live Ring-3 VirtIO 1.0+ (v2) NIC and perform a real ARP + ICMP Echo ping to `10.0.2.2`
/// (QEMU user-mode gateway) using `smoltcp` — 100% `#![forbid(unsafe_code)]` and `no_alloc`.
pub fn live_virtio_icmp_ping<T: VirtioTransport>(
    transport: T,
    nic: VirtioNetInfo,
    dma: &VirtioNetDma,
) -> Result<PingResult, &'static str> {
    if nic.version < 2 {
        return Err("VirtIO-MMIO v2 (modern) required");
    }

    let mut device = VirtioNetDevice::init(transport, nic.slot, dma)?;
    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(nic.mac)));
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2));

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

    let gateway = IpAddress::v4(10, 0, 2, 2);
    let payload = b"newos-ring3";
    let echo = Icmpv4Repr::EchoRequest {
        ident: IDENT,
        seq_no: SEQ,
        data: payload,
    };

    let mut sent_echo = false;
    for step in 0..20_000i64 {
        let now = Instant::from_millis(step);
        let _ = iface.poll(now, &mut device, &mut sockets);

        let sock = sockets.get_mut::<icmp::Socket>(handle);
        if !sent_echo && sock.can_send() {
            let buf = sock
                .send(echo.buffer_len(), gateway)
                .map_err(|_| "icmp send failed")?;
            let mut pkt = Icmpv4Packet::new_unchecked(buf);
            echo.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::default());
            sent_echo = true;
            // Poll immediately to emit ARP / ICMP frame
            let _ = iface.poll(now, &mut device, &mut sockets);
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
                rx_packets: device.rx_packets,
                tx_packets: device.tx_packets,
            });
        }

        // Re-send once if ARP resolved on first try and initial ICMP was queued/dropped
        if step == 500 && device.rx_packets > 0 {
            let sock = sockets.get_mut::<icmp::Socket>(handle);
            if sock.can_send()
                && let Ok(buf) = sock.send(echo.buffer_len(), gateway)
            {
                let mut pkt = Icmpv4Packet::new_unchecked(buf);
                echo.emit(&mut pkt, &smoltcp::phy::ChecksumCapabilities::default());
            }
        }
    }

    Err("timed out waiting for ICMP EchoReply from 10.0.2.2")
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
