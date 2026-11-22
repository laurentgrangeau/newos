//! Post-UNIX Typed Zero-Copy Pipeline Shell (`newos-sh`) — `#![forbid(unsafe_code)]`, `no_alloc`.
//!
//! Instead of piping untyped ASCII text through regexes, stages pass typed `Record` values
//! (`Proc`, `Object`, `Ref`, `Metric`, `Count`) directly through structured `|` pipelines:
//!   - `put "hello newos" | save @note`
//!   - `objects | where size > 20`
//!   - `refs | where writable == false`
//!   - `procs | where pid == 1 | count`

use core::fmt::{self, Write};
use newos_abi::{CapId, QemuExitCode, SysError};

use crate::caos::{ObjHash, ObjectMeta, ObjectStore, RefMeta, StoreError};

const LINE_BUF_SIZE: usize = 128;
const HISTORY_LEN: usize = 8;
const MAX_STAGES: usize = 6;
const MAX_ARGS: usize = 12;
const MAX_STREAM_RECORDS: usize = 32;

/// Read-only system summary returned by `ShellHost::sys_info()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysInfo {
    pub online_cpus: u16,
    pub proc_count: u16,
    pub interactive_shell: bool,
}

/// Host/OS syscall boundary for `newos-sh`.
///
/// Implemented by EL0 `InitShellHost` (`crates/init`), host `BenchmarkHost`
/// (`crates/bench`), and unit-test mocks.
pub trait ShellHost {
    /// Emit a UTF-8 slice to the debug console (single `DebugWrite` syscall boundary).
    fn write_debug(&mut self, s: &str);

    /// Read current system info (`online_cpus`, `proc_count`, `interactive_shell`).
    fn sys_info(&mut self) -> SysInfo;

    /// Non-blocking 1-byte console read (default: `Err(SysError::WouldBlock)`).
    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        Err(SysError::WouldBlock)
    }

    /// Send a register-only fastpath IPC payload to an endpoint capability.
    fn ipc_send(&mut self, _cap: CapId, _payload: u64) -> Result<(), SysError> {
        Err(SysError::Unsupported)
    }

    /// Receive a pending `(badge, payload)` pair from an endpoint capability.
    fn ipc_recv(&mut self, _cap: CapId) -> Result<(u64, u64), SysError> {
        Err(SysError::WouldBlock)
    }

    /// Synchronous send+receive fastpath (`IpcCall`). Defaults to `ipc_send` + `yield_now` +
    /// `ipc_recv` for hosts that do not override it (e.g. `MockShellHost` in `tests/e2e`).
    fn ipc_call(&mut self, cap: CapId, payload: u64) -> Result<(u64, u64), SysError> {
        self.ipc_send(cap, payload)?;
        let _ = self.yield_now();
        self.ipc_recv(cap)
    }

    /// Yield the current thread's remaining time slice.
    fn yield_now(&mut self) -> Result<u64, SysError> {
        Ok(0)
    }

    /// Read the monotonic CPU cycle counter.
    fn read_cycles(&mut self) -> Result<u64, SysError> {
        Ok(0)
    }

    /// Deliberately trigger an EL0 hardware fault (`crash` command).
    /// EL0 `init` diverges (`!`); host tests may record the call and return.
    fn trigger_user_fault(&mut self) {}

    /// Terminate the root task (`exit` / `shutdown` in `run_interactive`).
    fn exit(&mut self, _code: QemuExitCode) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// Handle the `net [dhcp|ping|resolve]` producer command.
    /// EL0 `init` implements this using `newos-net`; host/bench default is no-op.
    fn handle_net(
        &mut self,
        _subcmd: &str,
        _arg: Option<&str>,
        _stream: &mut RecordStream,
        _silent: bool,
    ) {
    }
}

/// Zero-output `core::fmt::Write` sink (used by `run_self_test` and silent helpers).
pub struct NullWriter;

impl Write for NullWriter {
    #[inline]
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        Ok(())
    }
}

/// Fixed-size stack-buffered `core::fmt::Write` wrapper (`no_alloc`, `#![forbid(unsafe_code)]`).
/// Exported per interface contract; automatically flushes on `Drop`.
pub struct BufferedWriter<const N: usize, W: Write> {
    inner: W,
    buf: [u8; N],
    pos: usize,
}

impl<const N: usize, W: Write> BufferedWriter<N, W> {
    #[inline]
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            buf: [0u8; N],
            pos: 0,
        }
    }

    pub fn inner(&self) -> &W {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    #[inline]
    pub fn flush(&mut self) {
        if self.pos > 0 {
            if let Ok(s) = core::str::from_utf8(&self.buf[..self.pos]) {
                let _ = self.inner.write_str(s);
            }
            self.pos = 0;
        }
    }
}

impl<const N: usize, W: Write> Write for BufferedWriter<N, W> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.is_empty() {
            return Ok(());
        }
        if N == 0 {
            return self.inner.write_str(s);
        }
        let bytes = s.as_bytes();
        if bytes.len() <= N - self.pos {
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            return Ok(());
        }
        self.flush();
        if bytes.len() >= N {
            let mut rest = s;
            while !rest.is_empty() {
                if rest.len() < N {
                    self.buf[..rest.len()].copy_from_slice(rest.as_bytes());
                    self.pos = rest.len();
                    break;
                }
                let mut end = rest.len().min(N);
                while end > 0 && !rest.is_char_boundary(end) {
                    end -= 1;
                }
                if end == 0 {
                    // Single UTF-8 scalar larger than N bytes: forward only that scalar.
                    let char_len = rest.chars().next().map_or(rest.len(), char::len_utf8);
                    self.inner.write_str(&rest[..char_len])?;
                    rest = &rest[char_len..];
                    continue;
                }
                self.inner.write_str(&rest[..end])?;
                rest = &rest[end..];
            }
        } else {
            self.buf[..bytes.len()].copy_from_slice(bytes);
            self.pos = bytes.len();
        }
        Ok(())
    }
}

impl<const N: usize, W: Write> Drop for BufferedWriter<N, W> {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Unbuffered per-fragment `Write` adapter directly invoking `ShellHost::write_debug`
/// (exact M1 baseline parity with `DebugConsole`).
struct HostWriter<'a, H: ShellHost>(&'a mut H);

impl<H: ShellHost> Write for HostWriter<'_, H> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_debug(s);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome {
    Continue,
    Exit(QemuExitCode),
}

/// Typed structured record flowing between `|` pipeline stages (zero text re-parsing).
#[derive(Clone, Copy)]
pub enum Record {
    Proc {
        pid: u64,
        el: u64,
        name: &'static str,
    },
    Object(ObjectMeta),
    Ref(RefMeta),
    Metric {
        label: &'static str,
        value: u64,
        unit: &'static str,
    },
    Count(usize),
}

/// Fixed-capacity, `no_alloc` typed stream passed between pipeline stages.
pub struct RecordStream {
    items: [Option<Record>; MAX_STREAM_RECORDS],
    len: usize,
}

impl Default for RecordStream {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordStream {
    pub const fn new() -> Self {
        Self {
            items: [None; MAX_STREAM_RECORDS],
            len: 0,
        }
    }

    pub fn push(&mut self, rec: Record) {
        if self.len < MAX_STREAM_RECORDS {
            self.items[self.len] = Some(rec);
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn first(&self) -> Option<Record> {
        if self.len > 0 { self.items[0] } else { None }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn truncate(&mut self, limit: usize) {
        if limit < self.len {
            self.len = limit;
        }
    }

    pub(crate) fn retain<F: FnMut(Record) -> bool>(&mut self, mut pred: F) {
        let mut write_idx = 0usize;
        for read_idx in 0..self.len {
            if let Some(rec) = self.items[read_idx]
                && pred(rec)
            {
                if write_idx != read_idx {
                    self.items[write_idx] = Some(rec);
                }
                write_idx += 1;
            }
        }
        self.len = write_idx;
    }

    pub fn render<W: Write>(&self, out: &mut W) {
        if self.len == 0 {
            let _ = out.write_str("(empty stream)\n");
            return;
        }
        match self.items[0] {
            Some(Record::Proc { .. }) => {
                let _ = out.write_str("PID  EL    ISOLATION        NAME\n");
                let mut line = AsciiLine::<96>::new();
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Proc { pid, el, name } = rec {
                        line.clear();
                        line.push_u64_left(*pid, 4);
                        line.push_str(" EL");
                        line.push_u64_left(*el, 3);
                        line.push_str(" TTBR0 VSpace #");
                        line.push_u64(*pid);
                        line.push_str("  ");
                        line.push_str(name);
                        line.push_byte(b'\n');
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Some(Record::Object(_)) => {
                let _ = out.write_str("OBJECT HASH           SIZE\n");
                let mut line = AsciiLine::<64>::new();
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Object(meta) = rec {
                        line.clear();
                        line.push_str("obj:");
                        line.push_hex16(meta.hash.0);
                        line.push_str("  ");
                        line.push_u64(meta.size as u64);
                        line.push_str(" B\n");
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Some(Record::Ref(_)) => {
                let _ = out.write_str("REF              MODE  TARGET                PREV\n");
                let mut line = AsciiLine::<96>::new();
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Ref(meta) = rec {
                        line.clear();
                        line.push_byte(b'@');
                        line.push_str_left(meta.name_str(), 15);
                        line.push_str(if meta.writable {
                            " rw    obj:"
                        } else {
                            " ro    obj:"
                        });
                        line.push_hex16(meta.target.0);
                        match meta.prev {
                            Some(p) => {
                                line.push_str("  obj:");
                                line.push_hex16(p.0);
                                line.push_byte(b'\n');
                            }
                            None => {
                                line.push_str("  -\n");
                            }
                        }
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Some(Record::Metric { .. }) => {
                let _ = out.write_str("METRIC                VALUE\n");
                let mut line = AsciiLine::<96>::new();
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Metric { label, value, unit } = rec {
                        line.clear();
                        line.push_str_left(label, 20);
                        line.push_str("  ");
                        line.push_u64(*value);
                        line.push_byte(b' ');
                        line.push_str(unit);
                        line.push_byte(b'\n');
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Some(Record::Count(c)) => {
                let mut line = AsciiLine::<24>::new();
                line.push_u64(c as u64);
                line.push_byte(b'\n');
                let _ = out.write_str(line.as_str());
            }
            None => {}
        }
    }
}

/// Zero-alloc, `#![forbid(unsafe_code)]` stack line formatter avoiding `core::fmt` overhead on hot paths.
struct AsciiLine<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> AsciiLine<N> {
    #[inline]
    const fn new() -> Self {
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    #[inline]
    fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    fn push_byte(&mut self, b: u8) {
        if self.len < N {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    #[inline]
    fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    #[inline]
    fn push_str_left(&mut self, s: &str, width: usize) {
        self.push_str(s);
        let pad = width.saturating_sub(s.len());
        let n = pad.min(N - self.len);
        self.buf[self.len..self.len + n].fill(b' ');
        self.len += n;
    }

    #[inline]
    fn push_u64(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let digits = &tmp[i..];
        let n = digits.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&digits[..n]);
        self.len += n;
    }

    #[inline]
    fn push_u64_left(&mut self, v: u64, width: usize) {
        let start = self.len;
        self.push_u64(v);
        let written = self.len - start;
        let pad = width.saturating_sub(written);
        let n = pad.min(N - self.len);
        self.buf[self.len..self.len + n].fill(b' ');
        self.len += n;
    }

    #[inline]
    fn push_hex16(&mut self, v: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if N - self.len >= 16 {
            let dst = &mut self.buf[self.len..self.len + 16];
            for (idx, slot) in dst.iter_mut().enumerate() {
                let shift = (15 - idx) * 4;
                *slot = HEX[((v >> shift) & 0xF) as usize];
            }
            self.len += 16;
        }
    }

    #[inline]
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

pub struct Shell<H: ShellHost> {
    store: ObjectStore,
    host: H,
    cached_sys_info: Option<SysInfo>,
    scratch_stream: RecordStream,
    history: [[u8; LINE_BUF_SIZE]; HISTORY_LEN],
    history_lens: [usize; HISTORY_LEN],
    history_count: usize,
}

impl<H: ShellHost> Shell<H> {
    pub fn new(host: H) -> Self {
        Self {
            store: ObjectStore::new(),
            host,
            cached_sys_info: None,
            scratch_stream: RecordStream::new(),
            history: [[0; LINE_BUF_SIZE]; HISTORY_LEN],
            history_lens: [0; HISTORY_LEN],
            history_count: 0,
        }
    }

    #[inline]
    fn sys_info_cached(&mut self) -> SysInfo {
        sys_info_cached_with(&mut self.host, &mut self.cached_sys_info)
    }

    #[inline]
    fn buffered_out(&mut self) -> BufferedWriter<256, HostWriter<'_, H>> {
        BufferedWriter::new(HostWriter(&mut self.host))
    }

    pub fn store(&self) -> &ObjectStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut ObjectStore {
        &mut self.store
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn into_host(self) -> H {
        self.host
    }

    pub fn record_history(&mut self, line: &str) {
        let bytes = line.as_bytes();
        let len = bytes.len().min(LINE_BUF_SIZE);
        if len == 0 {
            return;
        }
        let slot = self.history_count % HISTORY_LEN;
        self.history[slot][..len].copy_from_slice(&bytes[..len]);
        self.history_lens[slot] = len;
        self.history_count += 1;
    }

    /// Automated post-UNIX CAOS + typed-pipeline self-check (run by `cargo xtask test`).
    pub fn run_self_test(&mut self) -> Result<(), &'static str> {
        // 1. Typed pipeline: `put "v1" | save @demo`
        let before_objs = self.store.object_count();
        let _ = self.exec_line_inner("put \"hello caos v1\" | save @demo", true);
        if self.store.object_count() != before_objs + 1 {
            return Err("put | save did not create object");
        }

        // 2. Content deduplication: storing identical bytes must NOT allocate a new object!
        let _ = self.exec_line_inner("put \"hello caos v1\"", true);
        if self.store.object_count() != before_objs + 1 {
            return Err("content deduplication failed");
        }

        // 3. Atomic update + instant rollback: v1 -> v2 -> rollback -> v1
        let _ = self.exec_line_inner("put \"hello caos v2\" | save @demo", true);
        let (_, v2) = self
            .store
            .get_any("@demo")
            .map_err(|_| "missing @demo v2")?;
        if v2 != b"hello caos v2" {
            return Err("@demo did not update to v2");
        }
        let _ = self.exec_line_inner("ref rollback @demo", true);
        let (_, v1) = self
            .store
            .get_any("@demo")
            .map_err(|_| "missing @demo after rollback")?;
        if v1 != b"hello caos v1" {
            return Err("ref rollback did not restore v1");
        }

        // 4. Irreversible capability attenuation (`seal` -> read-only)
        let _ = self.exec_line_inner("ref seal @demo", true);
        let h2 = self.store.put(b"tamper").map_err(|_| "put tamper failed")?;
        if self.store.set_ref("@demo", h2) != Err(StoreError::ReadOnly) {
            return Err("sealed ref allowed write!");
        }

        // 5. Typed pipeline filter & reduction: `procs | where pid == 1 | count` -> 1
        self.scratch_stream.clear();
        eval_pipeline_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            "procs | where pid == 1 | count",
            true,
            &mut self.scratch_stream,
        );
        match self.scratch_stream.first() {
            Some(Record::Count(1)) => {}
            _ => return Err("typed pipeline `procs | where pid == 1 | count` failed"),
        }

        Ok(())
    }

    /// Run the interactive EL0 REPL (`cargo xtask run`).
    pub fn run_interactive(&mut self) -> ! {
        {
            let mut out = self.buffered_out();
            let _ = writeln!(out, "\n================================================================");
            let _ = writeln!(out, "  newos-sh: Post-UNIX Typed Pipeline Shell + EL0 CAOS");
            let _ = writeln!(out, "  100% #![forbid(unsafe_code)] · zero POSIX paths · zero heap");
            let _ = writeln!(out, "  Try: `get @guide`, `objects | where size > 20`, `help`");
            let _ = writeln!(out, "================================================================\n");
        }

        let mut line_buf = [0u8; LINE_BUF_SIZE];
        loop {
            self.host.write_debug("newos λ ");
            let len = self.read_line(&mut line_buf);
            let line = core::str::from_utf8(&line_buf[..len]).unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            self.record_history(line);
            if let ExecOutcome::Exit(code) = self.exec_line(line) {
                self.host.exit(code);
            }
        }
    }

    fn read_line(&mut self, buf: &mut [u8; LINE_BUF_SIZE]) -> usize {
        let mut len = 0usize;
        loop {
            let byte = match self.host.read_debug_byte() {
                Ok(b) => b,
                Err(SysError::WouldBlock) | Err(_) => {
                    let _ = self.host.yield_now();
                    continue;
                }
            };
            match byte {
                b'\r' | b'\n' => {
                    self.host.write_debug("\n");
                    return len;
                }
                0x08 | 0x7F => {
                    if len > 0 {
                        len -= 1;
                        self.host.write_debug("\x08 \x08");
                    }
                }
                0x03 => {
                    self.host.write_debug("^C\n");
                    return 0;
                }
                0x0C => {
                    self.host.write_debug("\x1b[2J\x1b[Hnewos λ ");
                    if let Ok(s) = core::str::from_utf8(&buf[..len]) {
                        self.host.write_debug(s);
                    }
                }
                0x20..=0x7E if len < LINE_BUF_SIZE => {
                    buf[len] = byte;
                    len += 1;
                    let tmp = [byte];
                    if let Ok(s) = core::str::from_utf8(&tmp) {
                        self.host.write_debug(s);
                    }
                }
                _ => {}
            }
        }
    }

    /// Execute a single shell command line, writing output through `ShellHost::write_debug`.
    pub fn exec_line(&mut self, line: &str) -> ExecOutcome {
        self.exec_line_inner(line, false)
    }

    /// Evaluate a typed pipeline silently (no `write_debug` output) and return its `RecordStream`.
    pub fn eval_pipeline(&mut self, line: &str) -> RecordStream {
        let mut stream = RecordStream::new();
        eval_pipeline_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            line,
            true,
            &mut stream,
        );
        stream
    }

    fn exec_line_inner(&mut self, line: &str, silent: bool) -> ExecOutcome {
        let trimmed = line.trim();
        match trimmed {
            "exit" | "shutdown" => {
                if !silent {
                    self.host.write_debug("Shutting down NewOS...\n");
                }
                return ExecOutcome::Exit(QemuExitCode::Success);
            }
            "clear" => {
                if !silent {
                    self.host.write_debug("\x1b[2J\x1b[H");
                }
                return ExecOutcome::Continue;
            }
            "crash" => {
                if !silent {
                    self.host.write_debug(
                        "[newos-sh] triggering deliberate EL0 `udf #0` fault (kernel stays alive)...\n",
                    );
                }
                self.host.trigger_user_fault();
                return ExecOutcome::Continue;
            }
            "history" => {
                if !silent {
                    let total = self.history_count.min(HISTORY_LEN);
                    let start = self.history_count.saturating_sub(total);
                    let mut out = BufferedWriter::<256, _>::new(HostWriter(&mut self.host));
                    for i in 0..total {
                        let idx = (start + i) % HISTORY_LEN;
                        let len = self.history_lens[idx];
                        if let Ok(s) = core::str::from_utf8(&self.history[idx][..len]) {
                            let _ = writeln!(out, "{:>3}  {s}", start + i + 1);
                        }
                    }
                }
                return ExecOutcome::Continue;
            }
            "help" => {
                if !silent {
                    let mut out = self.buffered_out();
                    write_help(&mut out);
                }
                return ExecOutcome::Continue;
            }
            "gc" => {
                let reclaimed = self.store.gc();
                let remaining = self.store.object_count();
                if !silent {
                    let mut out = self.buffered_out();
                    let _ = writeln!(
                        out,
                        "gc: reclaimed {reclaimed} unreachable object(s), {remaining} live"
                    );
                }
                return ExecOutcome::Continue;
            }
            "sys" => {
                let info = self.sys_info_cached();
                let obj_count = self.store.object_count();
                if !silent {
                    let mut out = self.buffered_out();
                    let _ = writeln!(
                        out,
                        "NewOS 0.1.0 aarch64 (Raspberry Pi 5 16 GB) pure-seL4-microkernel (SMP={} CPUs, {} EL0 procs, {} CAOS objects)",
                        info.online_cpus,
                        info.proc_count,
                        obj_count
                    );
                }
                return ExecOutcome::Continue;
            }
            _ => {}
        }

        // Single-stage commands: tokenize once for `get`, `ref`, and single-producer pipelines.
        if !trimmed.contains('|') {
            let mut toks = [""; MAX_ARGS];
            let argc = split_tokens(trimmed, &mut toks);
            if argc > 0 && toks[0] == "get" {
                let Some(spec) = toks.get(1).copied().filter(|s| !s.is_empty()) else {
                    if !silent {
                        self.host.write_debug("usage: get <@ref | obj:hash>\n");
                    }
                    return ExecOutcome::Continue;
                };
                match self.store.get_any(spec) {
                    Ok((hash, bytes)) => {
                        if !silent {
                            let text = core::str::from_utf8(bytes).unwrap_or("<binary>");
                            let mut out = BufferedWriter::<256, _>::new(HostWriter(&mut self.host));
                            let _ = writeln!(out, "[obj:{:016x}, {} B]\n{text}", hash.0, bytes.len());
                        }
                    }
                    Err(e) => {
                        if !silent {
                            let mut out = self.buffered_out();
                            let _ = writeln!(out, "get: {spec}: {e:?}");
                        }
                    }
                }
                return ExecOutcome::Continue;
            }
            if argc > 0 && toks[0] == "ref" {
                self.exec_ref_cmd(&toks[1..argc], silent);
                return ExecOutcome::Continue;
            }

            self.scratch_stream.clear();
            eval_producer_tokens_with(
                &mut self.store,
                &mut self.host,
                &mut self.cached_sys_info,
                &toks[..argc],
                silent,
                &mut self.scratch_stream,
            );
            if !silent {
                let mut out = BufferedWriter::<256, _>::new(HostWriter(&mut self.host));
                self.scratch_stream.render(&mut out);
            }
            return ExecOutcome::Continue;
        }

        // Multi-stage typed pipeline evaluation (`producer | filter | transform ...`)
        self.scratch_stream.clear();
        eval_pipeline_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            trimmed,
            silent,
            &mut self.scratch_stream,
        );
        if !silent {
            let mut out = BufferedWriter::<256, _>::new(HostWriter(&mut self.host));
            self.scratch_stream.render(&mut out);
        }
        ExecOutcome::Continue
    }

    fn exec_ref_cmd(&mut self, args: &[&str], silent: bool) {
        match args {
            ["set", name, hash_str] => {
                let Some(hash) = ObjHash::parse_hex(hash_str) else {
                    if !silent {
                        let mut out = self.buffered_out();
                        let _ = writeln!(out, "ref set: invalid hash `{hash_str}`");
                    }
                    return;
                };
                match self.store.set_ref(name, hash) {
                    Ok(()) => {
                        if !silent {
                            let mut out = self.buffered_out();
                            let _ = writeln!(out, "bound @{name} -> obj:{:016x}", hash.0);
                        }
                    }
                    Err(e) => {
                        if !silent {
                            let mut out = self.buffered_out();
                            let _ = writeln!(out, "ref set: {e:?}");
                        }
                    }
                }
            }
            ["seal", name] => match self.store.seal_ref(name) {
                Ok(()) => {
                    if !silent {
                        let mut out = self.buffered_out();
                        let _ = writeln!(out, "sealed @{name} (irreversibly read-only)");
                    }
                }
                Err(e) => {
                    if !silent {
                        let mut out = self.buffered_out();
                        let _ = writeln!(out, "ref seal: {e:?}");
                    }
                }
            },
            ["rollback", name] => match self.store.rollback_ref(name) {
                Ok(h) => {
                    if !silent {
                        let mut out = self.buffered_out();
                        let _ = writeln!(out, "rolled back @{name} -> obj:{:016x}", h.0);
                    }
                }
                Err(e) => {
                    if !silent {
                        let mut out = self.buffered_out();
                        let _ = writeln!(out, "ref rollback: {e:?}");
                    }
                }
            },
            _ => {
                if !silent {
                    let mut out = self.buffered_out();
                    let _ = writeln!(
                        out,
                        "usage: ref <set <name> <hash> | seal <name> | rollback <name>>"
                    );
                }
            }
        }
    }

}

#[inline]
fn sys_info_cached_with<H: ShellHost>(host: &mut H, cache: &mut Option<SysInfo>) -> SysInfo {
    if let Some(info) = *cache {
        info
    } else {
        let info = host.sys_info();
        *cache = Some(info);
        info
    }
}

fn eval_pipeline_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    cached_sys_info: &mut Option<SysInfo>,
    line: &str,
    silent: bool,
    stream: &mut RecordStream,
) {
    let mut stages = [""; MAX_STAGES];
    let mut stage_count = 0usize;
    for part in line.split('|') {
        if stage_count < MAX_STAGES {
            stages[stage_count] = part.trim();
            stage_count += 1;
        }
    }
    if stage_count == 0 {
        return;
    }

    let mut toks = [""; MAX_ARGS];
    let argc = split_tokens(stages[0], &mut toks);
    eval_producer_tokens_with(store, host, cached_sys_info, &toks[..argc], silent, stream);
    for stage in &stages[1..stage_count] {
        eval_transform_with(store, host, stage, stream, silent);
    }
}

fn eval_producer_tokens_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    cached_sys_info: &mut Option<SysInfo>,
    toks: &[&str],
    silent: bool,
    stream: &mut RecordStream,
) {
    if toks.is_empty() {
        return;
    }

    match toks[0] {
        "procs" => {
            let info = sys_info_cached_with(host, cached_sys_info);
            stream.push(Record::Proc {
                pid: 0,
                el: 0,
                name: "init (newos-sh + CAOS)",
            });
            if info.proc_count > 1 {
                stream.push(Record::Proc {
                    pid: 1,
                    el: 0,
                    name: "worker (IPC responder)",
                });
            }
        }
        "objects" => {
            store.for_each_object(|meta| {
                stream.push(Record::Object(meta));
            });
        }
        "refs" => {
            store.for_each_ref(|meta| {
                stream.push(Record::Ref(meta));
            });
        }
        "put" => {
            let mut buf = [0u8; 128];
            let mut pos = 0usize;
            for (i, arg) in toks[1..].iter().enumerate() {
                if i > 0 && pos < buf.len() {
                    buf[pos] = b' ';
                    pos += 1;
                }
                let b = arg.as_bytes();
                let n = b.len().min(buf.len().saturating_sub(pos));
                buf[pos..pos + n].copy_from_slice(&b[..n]);
                pos += n;
            }
            match store.put(&buf[..pos]) {
                Ok(hash) => stream.push(Record::Object(ObjectMeta { hash, size: pos })),
                Err(e) => {
                    if !silent {
                        let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                        let _ = writeln!(out, "put: {e:?}");
                    }
                }
            }
        }
        "ping" => {
            let val = toks
                .get(1)
                .filter(|s| !s.is_empty())
                .and_then(|s| parse_hex_u64(s))
                .unwrap_or(0xA110_C0DE);
            if let Ok((badge, reply)) = host.ipc_call(CapId::BOOTSTRAP_EP, val) {
                stream.push(Record::Metric {
                    label: "ipc.badge",
                    value: badge,
                    unit: "(cap)",
                });
                stream.push(Record::Metric {
                    label: "ipc.reply",
                    value: reply,
                    unit: "(from worker)",
                });
            }
        }
        "net" => {
            let sub = toks.get(1).copied().unwrap_or("");
            let arg = toks.get(2).copied().filter(|s| !s.is_empty());
            host.handle_net(sub, arg, stream, silent);
        }
        "bench" => {
            const ROUNDTRIPS: u64 = 100;
            let t0 = host.read_cycles().unwrap_or(0);
            for _ in 0..ROUNDTRIPS {
                let _ = host.yield_now();
            }
            let t1 = host.read_cycles().unwrap_or(0);
            let avg = t1.saturating_sub(t0) / (ROUNDTRIPS * 2);
            stream.push(Record::Metric {
                label: "ttbr0.switch.avg",
                value: avg,
                unit: "cycles",
            });
        }
        other => {
            if !silent {
                let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                let _ = writeln!(out, "newos-sh: unknown producer `{other}` (try `help`)");
            }
        }
    }
}

fn eval_transform_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    stage: &str,
    stream: &mut RecordStream,
    silent: bool,
) {
    let mut toks = [""; MAX_ARGS];
    let argc = split_tokens(stage, &mut toks);
    if argc == 0 {
        return;
    }

    match toks[0] {
        "count" => {
            let n = stream.len();
            stream.clear();
            stream.push(Record::Count(n));
        }
        "first" => {
            let limit = toks
                .get(1)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1);
            stream.truncate(limit);
        }
        "save" => {
            let Some(ref_name) = toks.get(1).copied().filter(|s| !s.is_empty()) else {
                if !silent {
                    let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                    let _ = writeln!(out, "usage: ... | save @<name>");
                }
                return;
            };
            if let Some(Record::Object(meta)) = stream.first() {
                if let Err(e) = store.set_ref(ref_name, meta.hash)
                    && !silent
                {
                    let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                    let _ = writeln!(out, "save {ref_name}: {e:?}");
                }
            } else if !silent {
                let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                let _ = writeln!(out, "save: expected an Object record from upstream");
            }
        }
        "where" if argc >= 4 => {
            if let Some(pred) = WherePredicate::parse(toks[1], toks[2], toks[3]) {
                stream.retain(|rec| pred.matches(rec));
            } else {
                stream.clear();
            }
        }
        other => {
            if !silent {
                let mut out = BufferedWriter::<256, _>::new(HostWriter(host));
                let _ = writeln!(out, "newos-sh: unknown stage `{other}` (try `help`)");
            }
        }
    }
}

const HELP_TEXT: &str = concat!(
    "Post-UNIX Typed Pipelines & Capability Object Store (CAOS):\n",
    "  put <text>                  Store immutable deduplicated object -> Object\n",
    "  get <@ref | obj:hash>       Read immutable object content\n",
    "  objects / refs / procs      Emit typed Object / Ref / Proc records\n",
    "  ref set|seal|rollback       Manage capability-gated Refs (atomic rollback)\n",
    "  ping [hex] / bench          TTBR0 IPC round-trip & cycle benchmark\n",
    "  net [dhcp|ping|resolve]     EL0 smoltcp + Pi 5 RP1 GEM / QEMU VirtIO\n",
    "  | where <f> ==|!=|> <v>     Filter typed records (e.g. `objects | where size > 20`)\n",
    "  | save @<name>              Bind upstream Object hash to a named Ref\n",
    "  | first <n> / | count       Slice or count typed streams\n",
    "  sys / crash / clear / exit  System info, EL0 fault test, power off\n",
);

fn write_help<W: Write>(out: &mut W) {
    let _ = out.write_str(HELP_TEXT);
}

#[derive(Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

impl CmpOp {
    fn parse(op: &str) -> Option<Self> {
        match op {
            "==" => Some(Self::Eq),
            "!=" => Some(Self::Ne),
            ">" => Some(Self::Gt),
            "<" => Some(Self::Lt),
            ">=" => Some(Self::Ge),
            "<=" => Some(Self::Le),
            _ => None,
        }
    }

    #[inline]
    fn eval(self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Gt => lhs > rhs,
            Self::Lt => lhs < rhs,
            Self::Ge => lhs >= rhs,
            Self::Le => lhs <= rhs,
        }
    }
}

#[derive(Clone, Copy)]
enum EqOp {
    Eq,
    Ne,
}

impl EqOp {
    fn parse(op: &str) -> Option<Self> {
        match op {
            "==" => Some(Self::Eq),
            "!=" => Some(Self::Ne),
            _ => None,
        }
    }

    #[inline]
    fn eval_eq(self, equal: bool) -> bool {
        match self {
            Self::Eq => equal,
            Self::Ne => !equal,
        }
    }
}

enum WherePredicate<'a> {
    Pid(CmpOp, u64),
    El(CmpOp, u64),
    Size(CmpOp, u64),
    Value(CmpOp, u64),
    Count(CmpOp, u64),
    Name(EqOp, &'a str),
    Label(EqOp, &'a str),
    Writable(EqOp, bool),
}

impl<'a> WherePredicate<'a> {
    fn parse(field: &str, op: &str, rhs: &'a str) -> Option<Self> {
        match field {
            "pid" => Some(Self::Pid(CmpOp::parse(op)?, parse_u64(rhs)?)),
            "el" => Some(Self::El(CmpOp::parse(op)?, parse_u64(rhs)?)),
            "size" => Some(Self::Size(CmpOp::parse(op)?, parse_u64(rhs)?)),
            "value" => Some(Self::Value(CmpOp::parse(op)?, parse_u64(rhs)?)),
            "count" => Some(Self::Count(CmpOp::parse(op)?, parse_u64(rhs)?)),
            "name" => Some(Self::Name(EqOp::parse(op)?, rhs)),
            "label" => Some(Self::Label(EqOp::parse(op)?, rhs)),
            "writable" => {
                let b = match rhs {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                Some(Self::Writable(EqOp::parse(op)?, b))
            }
            _ => None,
        }
    }

    #[inline]
    fn matches(&self, rec: Record) -> bool {
        match (self, rec) {
            (Self::Pid(op, r), Record::Proc { pid, .. }) => op.eval(pid, *r),
            (Self::El(op, r), Record::Proc { el, .. }) => op.eval(el, *r),
            (Self::Name(op, r), Record::Proc { name, .. }) => op.eval_eq(name == *r),
            (Self::Size(op, r), Record::Object(meta)) => op.eval(meta.size as u64, *r),
            (Self::Name(op, r), Record::Ref(meta)) => {
                op.eval_eq(&meta.name[..meta.name_len] == r.as_bytes())
            }
            (Self::Writable(op, r), Record::Ref(meta)) => op.eval_eq(meta.writable == *r),
            (Self::Value(op, r), Record::Metric { value, .. }) => op.eval(value, *r),
            (Self::Label(op, r), Record::Metric { label, .. }) => op.eval_eq(label == *r),
            (Self::Count(op, r), Record::Count(c)) => op.eval(c as u64, *r),
            _ => false,
        }
    }
}

#[inline]
fn parse_u64(rhs: &str) -> Option<u64> {
    rhs.parse::<u64>().ok().or_else(|| parse_hex_u64(rhs))
}

fn split_tokens<'a>(line: &'a str, out: &mut [&'a str; MAX_ARGS]) -> usize {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut count = 0usize;

    while i < bytes.len() && count < MAX_ARGS {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            out[count] = &line[start..i];
            count += 1;
            if i < bytes.len() {
                i += 1;
            }
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out[count] = &line[start..i];
            count += 1;
        }
    }
    count
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(stripped, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHost {
        out_buf: [u8; 4096],
        out_len: usize,
        debug_write_syscalls: u64,
        sys_info_syscalls: u64,
        ipc_send_syscalls: u64,
        ipc_recv_syscalls: u64,
        yield_syscalls: u64,
        cycle_syscalls: u64,
        fault_triggered: bool,
        last_ipc_payload: Option<u64>,
        cycles: u64,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                out_buf: [0u8; 4096],
                out_len: 0,
                debug_write_syscalls: 0,
                sys_info_syscalls: 0,
                ipc_send_syscalls: 0,
                ipc_recv_syscalls: 0,
                yield_syscalls: 0,
                cycle_syscalls: 0,
                fault_triggered: false,
                last_ipc_payload: None,
                cycles: 1000,
            }
        }

        fn output_str(&self) -> &str {
            core::str::from_utf8(&self.out_buf[..self.out_len]).unwrap_or("")
        }
    }

    impl ShellHost for MockHost {
        fn write_debug(&mut self, s: &str) {
            self.debug_write_syscalls += 1;
            let bytes = s.as_bytes();
            let space = self.out_buf.len().saturating_sub(self.out_len);
            let n = bytes.len().min(space);
            self.out_buf[self.out_len..self.out_len + n].copy_from_slice(&bytes[..n]);
            self.out_len += n;
        }

        fn sys_info(&mut self) -> SysInfo {
            self.sys_info_syscalls += 1;
            SysInfo {
                online_cpus: 2,
                proc_count: 2,
                interactive_shell: false,
            }
        }

        fn ipc_send(&mut self, _cap: CapId, payload: u64) -> Result<(), SysError> {
            self.ipc_send_syscalls += 1;
            self.last_ipc_payload = Some(payload);
            Ok(())
        }

        fn ipc_recv(&mut self, _cap: CapId) -> Result<(u64, u64), SysError> {
            self.ipc_recv_syscalls += 1;
            match self.last_ipc_payload.take() {
                Some(p) => Ok((0x5E14, p.wrapping_add(1))),
                None => Err(SysError::WouldBlock),
            }
        }

        fn yield_now(&mut self) -> Result<u64, SysError> {
            self.yield_syscalls += 1;
            self.cycles += 100;
            Ok(self.yield_syscalls)
        }

        fn read_cycles(&mut self) -> Result<u64, SysError> {
            self.cycle_syscalls += 1;
            Ok(self.cycles)
        }

        fn trigger_user_fault(&mut self) {
            self.fault_triggered = true;
        }
    }

    #[test]
    fn self_test_passes_with_zero_debug_writes() {
        let mut sh = Shell::new(MockHost::new());
        assert_eq!(sh.run_self_test(), Ok(()));
        assert_eq!(sh.host().debug_write_syscalls, 0);
        assert_eq!(sh.host().sys_info_syscalls, 1);
    }

    #[test]
    fn exec_line_buffers_output_and_caches_sys_info() {
        let mut sh = Shell::new(MockHost::new());
        assert_eq!(sh.exec_line("objects"), ExecOutcome::Continue);
        assert_eq!(sh.host().debug_write_syscalls, 1);
        assert!(sh.host().output_str().contains("OBJECT HASH"));
        assert!(sh.host().output_str().contains("obj:"));

        assert_eq!(sh.exec_line("sys"), ExecOutcome::Continue);
        assert_eq!(sh.host().sys_info_syscalls, 1);
        assert!(sh.host().output_str().contains("SMP=2 CPUs"));

        // Subsequent `procs` and `sys` reuse the cached `SysInfo` without extra syscalls.
        assert_eq!(sh.exec_line("procs"), ExecOutcome::Continue);
        assert_eq!(sh.exec_line("sys"), ExecOutcome::Continue);
        assert_eq!(sh.host().sys_info_syscalls, 1);
    }

    #[test]
    fn pipelines_filter_slice_count_and_save() {
        let mut sh = Shell::new(MockHost::new());
        let s1 = sh.eval_pipeline("procs | where pid == 1 | count");
        assert!(matches!(s1.first(), Some(Record::Count(1))));

        let s2 = sh.eval_pipeline("objects | where size > 20 | first 1");
        assert_eq!(s2.len(), 1);
        assert!(!s2.is_empty());

        let s3 = sh.eval_pipeline("refs | where writable == false | count");
        assert!(matches!(s3.first(), Some(Record::Count(2))));

        let s4 = sh.eval_pipeline("put \"x\" | save @k");
        assert_eq!(s4.len(), 1);
        assert_eq!(sh.store().get_any("@k").unwrap().1, b"x");
    }

    #[test]
    fn ping_and_bench_invoke_expected_syscalls() {
        let mut sh = Shell::new(MockHost::new());
        let s = sh.eval_pipeline("ping 0x1234");
        assert_eq!(s.len(), 2);
        assert_eq!(sh.host().ipc_send_syscalls, 1);
        assert_eq!(sh.host().yield_syscalls, 1);
        assert_eq!(sh.host().ipc_recv_syscalls, 1);

        let b = sh.eval_pipeline("bench");
        assert_eq!(b.len(), 1);
        assert_eq!(sh.host().cycle_syscalls, 2);
        assert_eq!(sh.host().yield_syscalls, 101);
    }

    #[test]
    fn builtins_exit_clear_crash_history_help_get_ref() {
        let mut sh = Shell::new(MockHost::new());
        sh.record_history("sys");
        assert_eq!(sh.exec_line("history"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("1  sys"));

        assert_eq!(sh.exec_line("help"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("Post-UNIX Typed Pipelines"));

        assert_eq!(sh.exec_line("get @motd"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("NewOS:"));

        assert_eq!(sh.exec_line("clear"), ExecOutcome::Continue);
        assert_eq!(sh.exec_line("crash"), ExecOutcome::Continue);
        assert!(sh.host().fault_triggered);

        assert_eq!(sh.exec_line("exit"), ExecOutcome::Exit(QemuExitCode::Success));
        assert_eq!(
            sh.exec_line("shutdown"),
            ExecOutcome::Exit(QemuExitCode::Success)
        );
    }

    struct CountingSink {
        buf: [u8; 256],
        len: usize,
        writes: usize,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                buf: [0u8; 256],
                len: 0,
                writes: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
        }
    }

    impl Write for CountingSink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.writes += 1;
            let b = s.as_bytes();
            let n = b.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
            self.len += n;
            Ok(())
        }
    }

    #[test]
    fn buffered_writer_coalesces_and_chunks_utf8_without_truncation() {
        let mut sink = CountingSink::new();
        {
            let mut bw = BufferedWriter::<16, _>::new(&mut sink);
            let _ = write!(bw, "a");
            let _ = write!(bw, "b");
            let _ = write!(bw, "c");
            assert_eq!(bw.inner().writes, 0);
            // Multi-byte UTF-8 string longer than 16 bytes ("λ" is 2 bytes)
            let _ = write!(bw, "newos λ 0123456789abcdef");
        } // Drop flushes remaining bytes
        assert_eq!(sink.as_str(), "abcnewos λ 0123456789abcdef");
        // Coalesced "abc" (1) + chunked >16B string (2) = 3 writes instead of 4+
        assert!(sink.writes <= 3);
    }

    #[test]
    fn buffered_writer_handles_oversized_utf8_scalar_without_unchunking_tail() {
        let mut sink = CountingSink::new();
        {
            let mut bw = BufferedWriter::<2, _>::new(&mut sink);
            let _ = write!(bw, "🦀abcdef");
        }
        assert_eq!(sink.as_str(), "🦀abcdef");
        // "🦀" (1 write) + "ab" (1) + "cd" (1) + "ef" (1) = 4 writes (never forwards whole tail)
        assert_eq!(sink.writes, 4);
    }

    #[test]
    fn where_predicate_edge_cases_and_malformed_stage_fallthrough() {
        let mut sh = Shell::new(MockHost::new());
        // Hex RHS comparison
        let hex_match = sh.eval_pipeline("procs | where pid == 0x1 | count");
        assert!(matches!(hex_match.first(), Some(Record::Count(1))));

        // Invalid RHS clears stream cleanly
        let bad_rhs = sh.eval_pipeline("objects | where size > not_a_number");
        assert!(bad_rhs.is_empty());

        // Malformed `where` (< 4 args) falls through to unknown stage with unchanged stream
        assert_eq!(sh.exec_line("objects | where size"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("unknown stage `where`"));
        assert!(sh.host().output_str().contains("OBJECT HASH"));
    }
}
