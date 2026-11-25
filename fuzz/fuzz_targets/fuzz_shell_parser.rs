#![no_main]
use libfuzzer_sys::fuzz_target;
use newos_abi::SysError;
use newos_shell_core::shell::{Shell, ShellHost, SysInfo};

struct SinkHost;
impl ShellHost for SinkHost {
    fn write_debug(&mut self, _s: &str) {}
    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            online_cpus: 4,
            domain_count: 6,
            interactive_shell: false,
        }
    }
    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        Err(SysError::WouldBlock)
    }
    fn yield_now(&mut self) -> Result<u64, SysError> {
        Ok(0)
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = core::str::from_utf8(data) {
        let mut sh = Shell::new(SinkHost);
        sh.exec_line(line);
    }
});
