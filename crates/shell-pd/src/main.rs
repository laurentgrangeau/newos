#![no_std]
#![no_main]

//! Standalone Isolated EL0 Typed Pipeline Shell (`newos-shell-pd`).
//!
//! Runs in its own `TTBR0_EL1` address space supervised by PD 0 (`newos-supervisor-pd`).
//! Holds zero MMIO capabilities and zero `PowerControl` write rights; if `newos-shell-pd`
//! crashes, PD 0 reclaims all of its frames and respawns it automatically.

use core::fmt::Write;
use core::panic::PanicInfo;
use newos_abi::{CapId, ShutdownStatus, SysError, auth_gate_ipc, log_ipc};
use newos_shell_core::shell::{Shell, ShellHost, SysInfo};
use newos_user_rt::{BufferedConsole, IpcLogAssembler};

newos_user_rt::entry!(main);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputSource {
    Console,
    Ssh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshAuthState {
    Closed,
    Authorized { active_source: InputSource },
}

struct StandaloneShellHost {
    log_rx: IpcLogAssembler<256>,
    ssh_in_buf: [u8; 7],
    ssh_in_pos: usize,
    ssh_in_len: usize,
    ssh_auth: SshAuthState,
}

impl StandaloneShellHost {
    const fn new() -> Self {
        Self {
            log_rx: IpcLogAssembler::new(),
            ssh_in_buf: [0; 7],
            ssh_in_pos: 0,
            ssh_in_len: 0,
            ssh_auth: SshAuthState::Closed,
        }
    }

    const fn is_ssh_active(&self) -> bool {
        matches!(
            self.ssh_auth,
            SshAuthState::Authorized {
                active_source: InputSource::Ssh
            }
        )
    }

    fn poll_auth_gate(&mut self) {
        while let Ok((badge, payload)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_AUTH_GATE_EP) {
            if badge != auth_gate_ipc::BADGE_KEY {
                continue;
            }
            if payload == auth_gate_ipc::SESSION_OPEN {
                if matches!(self.ssh_auth, SshAuthState::Closed) {
                    self.ssh_auth = SshAuthState::Authorized {
                        active_source: InputSource::Console,
                    };
                }
            } else if payload == auth_gate_ipc::SESSION_CLOSE {
                self.ssh_auth = SshAuthState::Closed;
                self.ssh_in_pos = 0;
                self.ssh_in_len = 0;
            }
        }
    }
}

impl ShellHost for StandaloneShellHost {
    fn write_debug(&mut self, s: &str) {
        if self.is_ssh_active() {
            // Route SSH shell output exclusively to `ssh-pd` without leaking to serial console (`M14`).
            let bytes = s.as_bytes();
            let mut off = 0usize;
            while off < bytes.len() {
                let end = (off + log_ipc::MAX_CHUNK_BYTES).min(bytes.len());
                let word = log_ipc::encode_chunk(&bytes[off..end]);
                let _ = newos_user_rt::ipc_send(CapId::BOOTSTRAP_SSH_OUT_EP, word);
                off = end;
            }
        } else {
            let mut out = BufferedConsole::<256>::new();
            let _ = out.write_str(s);
            out.flush();
        }
    }

    newos_user_rt::forward_shell_host_syscalls!();

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        self.poll_auth_gate();
        if self.ssh_in_pos < self.ssh_in_len {
            let b = self.ssh_in_buf[self.ssh_in_pos];
            self.ssh_in_pos += 1;
            if let SshAuthState::Authorized { active_source } = &mut self.ssh_auth {
                *active_source = InputSource::Ssh;
            }
            return Ok(b);
        }
        if let SshAuthState::Authorized { active_source } = &mut self.ssh_auth
            && let Ok((_badge, word)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_SSH_SHELL_EP)
        {
            let (chunk, len) = log_ipc::decode_chunk(word);
            if len > 0 {
                self.ssh_in_buf = chunk;
                self.ssh_in_len = len;
                self.ssh_in_pos = 1;
                *active_source = InputSource::Ssh;
                return Ok(chunk[0]);
            }
        }
        let res = newos_user_rt::debug_read_byte();
        if res.is_ok()
            && let SshAuthState::Authorized { active_source } = &mut self.ssh_auth
        {
            *active_source = InputSource::Console;
        }
        res
    }

    fn poll_background_log(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
        self.log_rx.poll_line(CapId::BOOTSTRAP_LOG_EP, out)
    }

    fn trigger_user_fault(&mut self) {
        if self.is_ssh_active() {
            // Do not allow remote SSH users to deliberately fault the shell domain (`M14`).
            self.write_debug("[ssh] fault/crash command is disabled over SSH\n");
            return;
        }
        newos_user_rt::trigger_user_fault()
    }

    fn exit(&mut self, code: ShutdownStatus) -> ! {
        let _ = newos_user_rt::notify_signal(
            CapId::BOOTSTRAP_FAULT_NOTIF,
            newos_abi::supervisor_notif::encode_shutdown(code),
        );
        newos_user_rt::thread_exit()
    }
}

fn main() -> ! {
    if !newos_user_rt::sys_info().interactive_shell {
        // In automated `cargo xtask test` mode, avoid competing with `supervisor-pd` on
        // `BOOTSTRAP_LOG_EP` and PL011 RX while still verifying `shell-pd` spawns in EL0.
        let mut out = BufferedConsole::<64>::new();
        let _ = out.write_str("[shell-pd] online (test mode)\n");
        out.flush();
        loop {
            let _ = newos_user_rt::yield_now();
        }
    }
    let mut sh = Shell::new(StandaloneShellHost::new());
    sh.run_interactive()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let mut out = BufferedConsole::<128>::new();
    let _ = out.write_str("[newos-shell-pd] PANIC in isolated EL0 shell; exiting for respawn\n");
    out.flush();
    newos_user_rt::thread_exit()
}
