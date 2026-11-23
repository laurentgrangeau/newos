#![no_std]
#![no_main]

//! Isolated EL0 Network & DMA Plane Daemon (`newos-netd`, PID 2).
//!
//! Strict least-privilege capability set:
//! - `CapId::BOOTSTRAP_NET_MMIO` (`R|W`) — RP1 Cadence GEM (Pi 5) or VirtIO-Net (QEMU)
//! - `CapId::BOOTSTRAP_VSPACE` (`R` only) — `VirtToPhys` DMA translation only
//! - `CapId::BOOTSTRAP_NET_EP` (`R|W`) — server endpoint for `newos-sshd` (badge 4) & `init` (0x1000)
//! - `CapId::BOOTSTRAP_LOG_EP` (`W`, badge 2) — write-only diagnostic log
//!
//! Explicitly holds ZERO access to `RNG_MMIO`, `KEY_EP`, `AUTH_GATE_EP`, `SSH_SHELL_EP`,
//! `CONSOLE`, `POWER`, `UNTYPED`, `THREAD`, or `CNODE`.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, SysError, net_ipc};
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

fn serve_net_loop<D: NetDevice>(
    mut stack: NetStack<'_, D>,
    mut clock: CycleClock<fn() -> u64>,
    out: &mut IpcLogConsole<256>,
) -> ! {
    let mut has_reply = false;
    let mut reply_payload = 0u64;
    let mut last_ip = stack.config().ip;

    loop {
        let now_ms = clock.now_millis();
        match stack.poll(now_ms) {
            TcpEvent::Connected => {
                let _ = writeln!(out, "[netd] TCP :{} client connected", stack.listen_port());
                out.flush();
            }
            TcpEvent::Disconnected => {
                let _ = writeln!(
                    out,
                    "[netd] TCP :{} client disconnected",
                    stack.listen_port()
                );
                out.flush();
            }
            TcpEvent::None => {}
        }
        let cur_ip = stack.config().ip;
        if cur_ip != last_ip {
            last_ip = cur_ip;
            let _ = writeln!(
                out,
                "[netd] IPv4 updated: {}.{}.{}.{}/{}",
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
                let _ = newos_user_rt::yield_now();
            }
            Err(err) => {
                let _ = writeln!(out, "[netd] fatal IPC error (code={}); exiting", err as u64);
                out.flush();
                newos_user_rt::thread_exit();
            }
        }
    }
}

fn handle_request<D: NetDevice>(
    stack: &mut NetStack<'_, D>,
    badge: u64,
    op: u8,
    payload: &[u8],
) -> u64 {
    // Only `newos-init` (read-only status) and `newos-sshd` (full TCP stream) are authorized.
    if badge == net_ipc::BADGE_INIT {
        if op == net_ipc::OP_POLL_STATUS {
            return encode_status(stack);
        }
        return 0;
    }
    if badge != net_ipc::BADGE_SSHD {
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

    let Some(nic) =
        newos_net::probe_nic(|off| newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off))
    else {
        let _ = writeln!(
            out,
            "[netd] no NIC detected via BOOTSTRAP_NET_MMIO; exiting"
        );
        out.flush();
        newos_user_rt::thread_exit();
    };

    let mac = nic.mac();
    let _ = writeln!(
        out,
        "[netd] online ({}, ipv4={}, ipv6={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, tcp=:{} cntfrq={}Hz)",
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
    match nic {
        #[cfg(feature = "driver-virtio")]
        NicKind::Virtio(v) => match VirtioNetDevice::init(CapNetTransport, v.slot, &VIRTIO_DMA) {
            Ok(dev) => {
                let stack = NetStack::new(
                    dev,
                    mac,
                    NetConfig::QEMU_DEFAULT,
                    SSH_PORT,
                    now_ms,
                    &mut storage,
                );
                serve_net_loop(stack, clock, &mut out)
            }
            Err(e) => {
                let _ = writeln!(out, "[netd] virtio-net init failed: {e}");
                out.flush();
                newos_user_rt::thread_exit();
            }
        },
        #[cfg(feature = "driver-gem")]
        NicKind::CadenceGem(g) => match GemNetDevice::init(CapNetTransport, g, &GEM_DMA) {
            Ok(dev) => {
                let stack = NetStack::new(
                    dev,
                    mac,
                    NetConfig::QEMU_DEFAULT,
                    SSH_PORT,
                    now_ms,
                    &mut storage,
                );
                serve_net_loop(stack, clock, &mut out)
            }
            Err(e) => {
                let _ = writeln!(out, "[netd] rpi5-rp1-gem init failed: {e}");
                out.flush();
                newos_user_rt::thread_exit();
            }
        },
        #[cfg(all(not(feature = "driver-virtio"), not(feature = "driver-gem")))]
        _ => newos_user_rt::thread_exit(),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = newos_user_rt::ipc_log_write(CapId::BOOTSTRAP_LOG_EP, "[netd] PANIC in EL0\n");
    newos_user_rt::thread_exit()
}
