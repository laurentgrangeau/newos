#![no_std]
#![no_main]

//! Isolated EL0 Network & DMA Plane Protection Domain (`newos-net-pd`, PD 2).
//!
//! Strict least-privilege capability set:
//! - `CapId::BOOTSTRAP_NET_MMIO` (`R|W`) — RP1 Cadence GEM (Pi 5) or VirtIO-Net (QEMU)
//! - `CapId::BOOTSTRAP_VSPACE` (`R` only) — `VirtToPhys` DMA translation only
//! - `CapId::BOOTSTRAP_NET_EP` (`R|W`) — server endpoint for `newos-ssh-pd` (badge 4) & `supervisor-pd` (0x1000)
//! - `CapId::BOOTSTRAP_LOG_EP` (`W`, badge 2) — write-only diagnostic log
//!
//! Explicitly holds ZERO access to `RNG_MMIO`, `KEY_EP`, `AUTH_GATE_EP`, `SSH_SHELL_EP`,
//! `CONSOLE`, `POWER`, `UNTYPED`, `THREAD`, or `CNODE`.

use core::fmt::Write;
use core::panic::PanicInfo;
#[cfg(feature = "tcp")]
use newos_abi::net_ipc;
use newos_abi::{CapId, SysError};
#[cfg(not(feature = "tcp"))]
use newos_net::{CycleClock, MmioDmaTransport, NetClock};
#[cfg(feature = "tcp")]
use newos_net::{
    CycleClock, MmioDmaTransport, NetClock, NetConfig, NetDevice, NetStack, NetStackStorage,
    NicKind, SSH_PORT, TcpEvent,
};
#[cfg(feature = "driver-gem")]
use newos_net::{GemDma, GemNetDevice};
#[cfg(feature = "driver-virtio")]
use newos_net::{VirtioNetDevice, VirtioNetDma};
use newos_user_rt::IpcLogConsole;

/// Static EL0 DMA rings & packet buffers (`Sync` via atomics).
#[cfg(feature = "driver-virtio")]
static VIRTIO_DMA: VirtioNetDma = VirtioNetDma::new();
#[cfg(feature = "driver-gem")]
static GEM_DMA: GemDma = GemDma::new();

#[cfg(any(feature = "driver-virtio", feature = "driver-gem"))]
struct CapNetTransport;

#[cfg(any(feature = "driver-virtio", feature = "driver-gem"))]
impl MmioDmaTransport for CapNetTransport {
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

#[cfg(feature = "tcp")]
fn serve_net_loop<D: NetDevice + newos_net::IrqAckDevice>(
    mut stack: NetStack<'_, D>,
    mut clock: CycleClock<fn() -> u64>,
    out: &mut IpcLogConsole<256>,
) -> ! {
    let mut has_reply = false;
    let mut reply_payload = 0u64;
    let mut last_ip = stack.config().ip;

    const NET_SSH_RING_VADDR: u64 = 0x0000_6000_0000_0000;
    let net_ssh_ring = newos_user_rt::map_shared_ring_pair(
        CapId::BOOTSTRAP_VSPACE,
        CapId::BOOTSTRAP_NET_SSH_RING,
        NET_SSH_RING_VADDR,
    )
    .ok();

    let irq_bound = newos_user_rt::irq_bind(
        CapId::BOOTSTRAP_NET_IRQ,
        CapId::BOOTSTRAP_NET_NOTIF,
        0,
        newos_abi::IrqTriggerMode::LevelHigh,
    )
    .is_ok();
    const IRQ_BIT: u64 = 1 << 0;
    const TX_DOORBELL_BIT: u64 = 1 << 1;
    const SSH_RX_READY_BIT: u64 = 1 << 0;

    let mut ring_buf = [0u8; 256];

    loop {
        // Drain outbound TCP payloads submitted by `ssh-pd` over the shared `SpscRing` (`b_to_a`).
        if let Some(ring) = net_ssh_ring {
            while let Some(n) = ring.b_to_a.try_pop_bytes(&mut ring_buf) {
                if n > 0 {
                    let _ = stack.send(&ring_buf[..n]);
                }
            }
        }

        let now_ms = clock.now_millis();
        match stack.poll(now_ms) {
            TcpEvent::Connected => {
                let _ = writeln!(
                    out,
                    "[net-pd] TCP :{} client connected",
                    stack.listen_port()
                );
                out.flush();
                let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_SSH_NOTIF, SSH_RX_READY_BIT);
            }
            TcpEvent::Disconnected => {
                let _ = writeln!(
                    out,
                    "[net-pd] TCP :{} client disconnected",
                    stack.listen_port()
                );
                out.flush();
                let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_SSH_NOTIF, SSH_RX_READY_BIT);
            }
            TcpEvent::None => {}
        }

        // Forward inbound TCP payloads into the shared `SpscRing` (`a_to_b`) and ring `ssh-pd`'s doorbell.
        if let Some(ring) = net_ssh_ring
            && stack.can_recv()
        {
            let mut pushed_any = false;
            for _ in 0..4 {
                if !stack.can_recv() {
                    break;
                }
                let n = stack.recv(&mut ring_buf);
                if n == 0 {
                    break;
                }
                if ring.a_to_b.try_push_bytes(&ring_buf[..n]) == Ok(n) {
                    pushed_any = true;
                } else {
                    break;
                }
            }
            if pushed_any {
                let _ = newos_user_rt::notify_signal(CapId::BOOTSTRAP_SSH_NOTIF, SSH_RX_READY_BIT);
            }
        }

        let cur_ip = stack.config().ip;
        if cur_ip != last_ip {
            last_ip = cur_ip;
            let _ = writeln!(
                out,
                "[net-pd] IPv4 updated: {}.{}.{}.{}/{}",
                cur_ip[0],
                cur_ip[1],
                cur_ip[2],
                cur_ip[3],
                stack.config().prefix_len
            );
            out.flush();
        }

        match newos_user_rt::ipc_reply_recv(CapId::BOOTSTRAP_NET_EP, reply_payload, has_reply) {
            Ok((badge, req)) => {
                let (op, buf, len) = net_ipc::decode_request(req);
                reply_payload = handle_request(&mut stack, badge, op, &buf[..len]);
                has_reply = true;
            }
            Err(SysError::WouldBlock) => {
                has_reply = false;
                let delay_ms = stack.poll_delay_ms(now_ms).unwrap_or(20).clamp(1, 50);
                let mask = IRQ_BIT | TX_DOORBELL_BIT | newos_abi::RING_PEER_RESET_BIT;
                if let Ok((bits, _timed_out)) = newos_user_rt::notify_wait(
                    CapId::BOOTSTRAP_NET_NOTIF,
                    mask,
                    delay_ms.saturating_mul(1_000_000),
                ) {
                    if (bits & newos_abi::RING_PEER_RESET_BIT) != 0 {
                        stack.abort();
                    }
                    if irq_bound && (bits & IRQ_BIT) != 0 {
                        stack.device().ack_interrupts();
                        let _ = newos_user_rt::irq_ack(CapId::BOOTSTRAP_NET_IRQ);
                    }
                } else {
                    let _ = newos_user_rt::sleep_ms(delay_ms);
                }
            }
            Err(err) => {
                let _ = writeln!(
                    out,
                    "[net-pd] fatal IPC error (code={}); exiting",
                    err as u64
                );
                out.flush();
                newos_user_rt::thread_exit();
            }
        }
    }
}

#[cfg(feature = "tcp")]
fn handle_request<D: NetDevice>(
    stack: &mut NetStack<'_, D>,
    badge: u64,
    op: u8,
    payload: &[u8],
) -> u64 {
    // Only `newos-supervisor-pd` (read-only status) and `newos-ssh-pd` (full TCP stream) are authorized.
    if badge == net_ipc::BADGE_SUPERVISOR {
        if op == net_ipc::OP_POLL_STATUS {
            return encode_status(stack);
        }
        return 0;
    }
    if badge != net_ipc::BADGE_SSH {
        return 0;
    }

    match op {
        net_ipc::OP_POLL_STATUS => encode_status(stack),
        net_ipc::OP_RECV_CHUNK => {
            if !stack.is_connected() && !stack.can_recv() {
                return net_ipc::encode_recv_eof();
            }
            let mut tmp = [0u8; net_ipc::MAX_CHUNK_BYTES];
            let n = stack.recv(&mut tmp);
            net_ipc::encode_recv_reply(&tmp[..n])
        }
        net_ipc::OP_SEND_BASE => stack.send(payload) as u64,
        net_ipc::OP_CLOSE => {
            stack.close();
            1
        }
        net_ipc::OP_ABORT => {
            stack.abort();
            1
        }
        _ => 0,
    }
}

#[cfg(feature = "tcp")]
fn encode_status<D: NetDevice>(stack: &NetStack<'_, D>) -> u64 {
    let mut flags = 0u64;
    if stack.is_connected() {
        flags |= net_ipc::STATUS_CONNECTED;
    }
    if stack.can_recv() {
        flags |= net_ipc::STATUS_RX_AVAIL;
    }
    if stack.can_send() {
        flags |= net_ipc::STATUS_TX_READY;
    }
    net_ipc::encode_status_reply(flags, stack.config().ip)
}

fn read_cycles_or_zero() -> u64 {
    newos_user_rt::read_cycles().unwrap_or(0)
}

newos_user_rt::entry!(main);

fn main() -> ! {
    let mut out = IpcLogConsole::<256>::new(CapId::BOOTSTRAP_LOG_EP);
    let freq_hz = newos_user_rt::timer_freq_hz();
    let cycles_per_ms = (freq_hz / 1_000).max(1);
    let mut clock = CycleClock::new(read_cycles_or_zero as fn() -> u64, cycles_per_ms);

    const NET_DMA_RING_VADDR: u64 = 0x0000_6000_0002_0000;
    if let Ok(iova) = newos_user_rt::dma_map(
        CapId::BOOTSTRAP_IOSPACE,
        CapId::BOOTSTRAP_NET_DMA_RING,
        newos_abi::DMA_FLAG_NON_CACHEABLE,
        NET_DMA_RING_VADDR,
    ) {
        let _ = writeln!(
            out,
            "[net-pd] IoSpace Normal-NC DMA ring pinned (iova={iova:#x})"
        );
        out.flush();
    }

    let Some(nic) =
        newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off))
    else {
        let _ = writeln!(
            out,
            "[net-pd] no NIC detected via BOOTSTRAP_NET_MMIO; exiting"
        );
        out.flush();
        newos_user_rt::thread_exit();
    };

    let mac = nic.mac();
    #[cfg(not(feature = "tcp"))]
    {
        let _ = (clock, mac);
        let _ = writeln!(
            out,
            "[net-pd] online ({}, ipv4={}, ipv6={}, tcp=false; no TCP listener started)",
            nic.driver_name(),
            cfg!(feature = "ipv4"),
            cfg!(feature = "ipv6"),
        );
        out.flush();
        loop {
            let _ = newos_user_rt::notify_wait(CapId::BOOTSTRAP_NET_NOTIF, u64::MAX, 100_000_000);
        }
    }

    #[cfg(feature = "tcp")]
    {
        let _ = writeln!(
            out,
            "[net-pd] online ({}, ipv4={}, ipv6={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, tcp=:{} cntfrq={}Hz)",
            nic.driver_name(),
            cfg!(feature = "ipv4"),
            cfg!(feature = "ipv6"),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            SSH_PORT,
            freq_hz,
        );
        out.flush();

        let mut storage = NetStackStorage::new();
        let now_ms = clock.now_millis();
        let entropy_seed = newos_user_rt::read_cycles().unwrap_or(0) ^ (freq_hz.rotate_left(23));
        match nic {
            #[cfg(feature = "driver-virtio")]
            NicKind::Virtio(v) => match VirtioNetDevice::init(CapNetTransport, v.slot, &VIRTIO_DMA)
            {
                Ok(dev) => {
                    let stack = NetStack::new_with_seed(
                        dev,
                        mac,
                        NetConfig::QEMU_DEFAULT,
                        SSH_PORT,
                        now_ms,
                        entropy_seed,
                        &mut storage,
                    );
                    serve_net_loop(stack, clock, &mut out)
                }
                Err(e) => {
                    let _ = writeln!(out, "[net-pd] virtio-net init failed: {e}");
                    out.flush();
                    newos_user_rt::thread_exit();
                }
            },
            #[cfg(feature = "driver-gem")]
            NicKind::CadenceGem(g) => match GemNetDevice::init(CapNetTransport, g, &GEM_DMA) {
                Ok(dev) => {
                    // On real Raspberry Pi 5 hardware, start unconfigured (0.0.0.0) until DHCPv4
                    // leases an address — never fall back to QEMU's 10.0.2.15/24 on a real LAN.
                    let rpi5_init_cfg = NetConfig {
                        ip: [0, 0, 0, 0],
                        prefix_len: 0,
                        gateway: None,
                        dns: None,
                    };
                    let stack = NetStack::new_with_seed(
                        dev,
                        mac,
                        rpi5_init_cfg,
                        SSH_PORT,
                        now_ms,
                        entropy_seed,
                        &mut storage,
                    );
                    serve_net_loop(stack, clock, &mut out)
                }
                Err(e) => {
                    let _ = writeln!(out, "[net-pd] rpi5-rp1-gem init failed: {e}");
                    out.flush();
                    newos_user_rt::thread_exit();
                }
            },
            #[cfg(all(not(feature = "driver-virtio"), not(feature = "driver-gem")))]
            _ => newos_user_rt::thread_exit(),
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[net-pd] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
