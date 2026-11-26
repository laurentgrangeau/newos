//! Host-side `ShellHost` implementation for opaque-box Shell & CAOS E2E tests.
//! Captures all debug output and counts exact syscall invocations.

use newos_abi::{CapId, SysError};
use newos_shell_core::shell::{ShellHost, SysInfo};

/// Deterministic host-side `ShellHost` simulating EL0 `init` + `worker` IPC responder.
#[derive(Debug)]
pub struct MockShellHost {
    pub sys_info_val: SysInfo,
    pub output: String,
    pub debug_write_syscalls: u64,
    pub sys_info_syscalls: u64,
    pub ipc_send_syscalls: u64,
    pub ipc_recv_syscalls: u64,
    pub yield_syscalls: u64,
    pub read_cycles_syscalls: u64,
    pub fault_calls: u64,
    pub ipc_enabled: bool,
    pending_ipc: Option<(u64, u64)>,
    cycles: u64,
}

impl MockShellHost {
    pub fn new(online_cpus: u16, domain_count: u16) -> Self {
        Self {
            sys_info_val: SysInfo {
                online_cpus,
                domain_count,
                interactive_shell: false,
            },
            output: String::new(),
            debug_write_syscalls: 0,
            sys_info_syscalls: 0,
            ipc_send_syscalls: 0,
            ipc_recv_syscalls: 0,
            yield_syscalls: 0,
            read_cycles_syscalls: 0,
            fault_calls: 0,
            ipc_enabled: true,
            pending_ipc: None,
            cycles: 1_000,
        }
    }

    pub fn take_output(&mut self) -> String {
        core::mem::take(&mut self.output)
    }

    pub fn clear_output(&mut self) {
        self.output.clear();
    }
}

impl Default for MockShellHost {
    fn default() -> Self {
        Self::new(2, 2)
    }
}

impl ShellHost for MockShellHost {
    fn write_debug(&mut self, s: &str) {
        self.debug_write_syscalls += 1;
        self.output.push_str(s);
    }

    fn sys_info(&mut self) -> SysInfo {
        self.sys_info_syscalls += 1;
        self.sys_info_val
    }

    fn ipc_send(&mut self, cap: CapId, payload: u64) -> Result<(), SysError> {
        self.ipc_send_syscalls += 1;
        if !self.ipc_enabled || cap != CapId::BOOTSTRAP_EP {
            return Err(SysError::InvalidCapability);
        }
        // Simulate worker responder: replies with (0x5E14, payload.wrapping_add(1)).
        self.pending_ipc = Some((0x5E14, payload.wrapping_add(1)));
        Ok(())
    }

    fn ipc_recv(&mut self, cap: CapId) -> Result<(u64, u64), SysError> {
        self.ipc_recv_syscalls += 1;
        if !self.ipc_enabled || cap != CapId::BOOTSTRAP_EP {
            return Err(SysError::InvalidCapability);
        }
        self.pending_ipc.take().ok_or(SysError::WouldBlock)
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        self.yield_syscalls += 1;
        self.cycles = self.cycles.wrapping_add(50);
        Ok(self.yield_syscalls)
    }

    fn read_cycles(&mut self) -> Result<u64, SysError> {
        self.read_cycles_syscalls += 1;
        Ok(self.cycles)
    }

    fn trigger_user_fault(&mut self) {
        self.fault_calls += 1;
    }
}
