//! Typed Pipeline Shell (`newos-sh`).
//!
//! Instead of piping untyped ASCII text through regexes, stages pass typed `Record` values
//! (`Proc`, `Object`, `Ref`, `Metric`, `Count`) directly through structured `|` pipelines:
//!   - `put "hello newos" | save @note`
//!   - `objects | where size > 20`
//!   - `refs | where writable == false`
//!   - `procs | where pid == 1 | count`

use core::fmt::{self, Write};
use newos_abi::{CapId, ShutdownStatus, SysError};

use crate::caos::{MAX_BLOB_SIZE, ObjHash, ObjectMeta, ObjectStore, RefMeta, StoreError};

pub const LINE_BUF_SIZE: usize = 128;
const SHELL_OUT_BUF: usize = 1024;
const HISTORY_LEN: usize = 8;
const MAX_STAGES: usize = 6;
const MAX_ARGS: usize = 12;
const MAX_STREAM_RECORDS: usize = 24;

const _: () = {
    assert!(MAX_STREAM_RECORDS >= crate::caos::MAX_OBJECTS);
    assert!(MAX_STREAM_RECORDS >= crate::caos::MAX_REFS);
    assert!(LINE_BUF_SIZE <= u8::MAX as usize);
};

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
    fn exit(&mut self, _code: ShutdownStatus) -> ! {
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

    /// Non-blocking poll for a complete background log line routed over `BOOTSTRAP_LOG_EP`.
    ///
    /// Copies a complete UTF-8 line (excluding trailing `\n`) into `out` and returns
    /// `Some((sender_badge, len))` when a full line is ready, or `None` otherwise.
    fn poll_background_log(&mut self, _out: &mut [u8]) -> Option<(u64, usize)> {
        None
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

/// Fixed-size stack-buffered `core::fmt::Write` wrapper.
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
    Exit(ShutdownStatus),
}

/// Typed structured record flowing between `|` pipeline stages (zero text re-parsing).
#[derive(Clone, Copy)]
pub enum Record {
    Count(usize),
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
}

/// Fixed-capacity typed stream passed between pipeline stages.
pub struct RecordStream {
    items: [Record; MAX_STREAM_RECORDS],
    len: usize,
}

impl Default for RecordStream {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordStream {
    #[inline]
    pub const fn new() -> Self {
        Self {
            items: [Record::Count(0); MAX_STREAM_RECORDS],
            len: 0,
        }
    }

    #[inline]
    pub fn push(&mut self, rec: Record) {
        if self.len < MAX_STREAM_RECORDS {
            self.items[self.len] = rec;
            self.len += 1;
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn first(&self) -> Option<Record> {
        if self.len > 0 {
            Some(self.items[0])
        } else {
            None
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub(crate) fn truncate(&mut self, limit: usize) {
        if limit < self.len {
            self.len = limit;
        }
    }

    #[inline]
    pub(crate) fn retain<F: FnMut(Record) -> bool>(&mut self, mut pred: F) {
        let mut write_idx = 0usize;
        for read_idx in 0..self.len {
            let rec = self.items[read_idx];
            if pred(rec) {
                if write_idx != read_idx {
                    self.items[write_idx] = rec;
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
            Record::Proc { .. } => {
                let _ = out.write_str("PID EL VSPACE NAME\n");
                let mut line = AsciiLine::<96>::new();
                for rec in &self.items[..self.len] {
                    if let Record::Proc { pid, el, name } = rec {
                        line.clear();
                        line.push_u64(*pid);
                        line.push_str(" EL");
                        line.push_u64(*el);
                        line.push_str(" #");
                        line.push_u64(*pid);
                        line.push_byte(b' ');
                        line.push_str(name);
                        line.push_byte(b'\n');
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Record::Object(_) => {
                let _ = out.write_str("OBJECT HASH SIZE\n");
                let mut line = AsciiLine::<48>::new();
                for rec in &self.items[..self.len] {
                    if let Record::Object(meta) = rec {
                        line.clear();
                        line.push_str("obj:");
                        line.push_hex16(meta.hash.0);
                        line.push_byte(b' ');
                        line.push_u64(meta.size as u64);
                        line.push_str("B\n");
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Record::Ref(_) => {
                let _ = out.write_str("REF MODE TARGET PREV\n");
                let mut line = AsciiLine::<96>::new();
                for rec in &self.items[..self.len] {
                    if let Record::Ref(meta) = rec {
                        line.clear();
                        line.push_byte(b'@');
                        line.push_str(meta.name_str());
                        line.push_str(if meta.writable {
                            " rw obj:"
                        } else {
                            " ro obj:"
                        });
                        line.push_hex16(meta.target.0);
                        match meta.prev() {
                            Some(p) => {
                                line.push_str(" obj:");
                                line.push_hex16(p.0);
                                line.push_byte(b'\n');
                            }
                            None => {
                                line.push_str(" -\n");
                            }
                        }
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Record::Metric { .. } => {
                let _ = out.write_str("METRIC VALUE\n");
                let mut line = AsciiLine::<96>::new();
                for rec in &self.items[..self.len] {
                    if let Record::Metric { label, value, unit } = rec {
                        line.clear();
                        line.push_str(label);
                        line.push_byte(b' ');
                        line.push_u64(*value);
                        line.push_byte(b' ');
                        line.push_str(unit);
                        line.push_byte(b'\n');
                        let _ = out.write_str(line.as_str());
                    }
                }
            }
            Record::Count(c) => {
                let mut line = AsciiLine::<24>::new();
                line.push_u64(c as u64);
                line.push_byte(b'\n');
                let _ = out.write_str(line.as_str());
            }
        }
    }
}

/// Stack line formatter avoiding `core::fmt` overhead on hot paths.
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
        let mut n = bytes.len().min(N - self.len);
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
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

const BANNER_TEXT: &str = concat!(
    "\n================================================================\n",
    "  newos-sh: Typed Pipeline Shell + CAOS\n",
    "  Try: `get @guide`, `objects | where size > 20`, `help`\n",
    "================================================================\n\n",
);

const _: () = assert!(BANNER_TEXT.len() <= SHELL_OUT_BUF);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseError {
    UnclosedQuote,
    TooManyStages,
    EmptyStage,
    TooManyArgs,
}

#[inline]
const fn parse_error_msg(err: ParseError) -> &'static str {
    match err {
        ParseError::UnclosedQuote => "newos-sh: unclosed quote\n",
        ParseError::TooManyStages => "newos-sh: too many pipeline stages (max 6)\n",
        ParseError::EmptyStage => "newos-sh: empty pipeline stage\n",
        ParseError::TooManyArgs => "newos-sh: too many arguments (max 12)\n",
    }
}

#[inline]
const fn store_error_str(e: StoreError) -> &'static str {
    match e {
        StoreError::NotFound => "NotFound",
        StoreError::NoSpace => "NoSpace",
        StoreError::TooLarge => "TooLarge",
        StoreError::InvalidName => "InvalidName",
        StoreError::ReadOnly => "ReadOnly",
        StoreError::NoPreviousVersion => "NoPreviousVersion",
        StoreError::CorruptSnapshot => "CorruptSnapshot",
        StoreError::HashCollision => "HashCollision",
    }
}

#[inline]
const fn sys_error_str(e: SysError) -> &'static str {
    match e {
        SysError::InvalidCapability => "InvalidCapability",
        SysError::InsufficientRights => "InsufficientRights",
        SysError::OutOfMemory => "OutOfMemory",
        SysError::InvalidArgument => "InvalidArgument",
        SysError::SlotOccupied => "SlotOccupied",
        SysError::WouldBlock => "WouldBlock",
        SysError::Unsupported => "Unsupported",
    }
}

fn write_store_err<H: ShellHost>(host: &mut H, prefix: &str, e: StoreError) {
    let mut line = AsciiLine::<128>::new();
    line.push_str(prefix);
    line.push_str(store_error_str(e));
    line.push_byte(b'\n');
    host.write_debug(line.as_str());
}

fn write_quoted_err<H: ShellHost>(host: &mut H, prefix: &str, item: &str, suffix: &str) {
    let mut line = AsciiLine::<128>::new();
    line.push_str(prefix);
    line.push_str(item);
    line.push_str(suffix);
    host.write_debug(line.as_str());
}

pub struct Shell<H: ShellHost> {
    store: ObjectStore,
    host: H,
    cached_sys_info: Option<SysInfo>,
    scratch_stream: RecordStream,
    history: [[u8; LINE_BUF_SIZE]; HISTORY_LEN],
    history_lens: [u8; HISTORY_LEN],
    history_count: u32,
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
        let mut len = bytes.len().min(LINE_BUF_SIZE);
        while len > 0 && !line.is_char_boundary(len) {
            len -= 1;
        }
        if len == 0 {
            return;
        }
        let slot = (self.history_count as usize) % HISTORY_LEN;
        self.history[slot][..len].copy_from_slice(&bytes[..len]);
        self.history_lens[slot] = len as u8;
        self.history_count = self.history_count.wrapping_add(1);
    }

    /// Automated CAOS + typed-pipeline self-check (run by `cargo xtask test`).
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
        let _ = eval_pipeline_with(
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
        self.host.write_debug(BANNER_TEXT);

        let mut line_buf = [0u8; LINE_BUF_SIZE];
        loop {
            self.host.write_debug("newos λ ");
            let len = match self.read_line_checked(&mut line_buf) {
                Ok(n) => n,
                Err(_) => self.host.exit(ShutdownStatus::Failed),
            };
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

    fn drain_background_logs(&mut self, current_input: &[u8]) {
        let mut log_buf = [0u8; 256];
        while let Some((_badge, raw_n)) = self.host.poll_background_log(&mut log_buf) {
            let n = raw_n.min(log_buf.len());
            let mut out = AsciiLine::<512>::new();
            out.push_str("\r\x1b[K");
            if let Ok(line) = core::str::from_utf8(&log_buf[..n]) {
                out.push_str(line);
            }
            out.push_str("\nnewos λ ");
            if let Ok(typed) = core::str::from_utf8(current_input) {
                out.push_str(typed);
            }
            self.host.write_debug(out.as_str());
        }
    }

    /// Read a single interactive line into `buf`, returning the number of bytes read
    /// (or `0` on `^C` or fatal host read/yield error).
    pub fn read_line(&mut self, buf: &mut [u8; LINE_BUF_SIZE]) -> usize {
        self.read_line_checked(buf).unwrap_or(0)
    }

    fn read_line_checked(&mut self, buf: &mut [u8; LINE_BUF_SIZE]) -> Result<usize, SysError> {
        let mut len = 0usize;
        let mut utf8_pending = [0u8; 4];
        let mut utf8_pos = 0usize;
        let mut utf8_expected = 0usize;
        loop {
            self.drain_background_logs(&buf[..len]);
            let byte = match self.host.read_debug_byte() {
                Ok(b) => b,
                Err(SysError::WouldBlock) => {
                    self.host.yield_now()?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if utf8_expected > 0 {
                if (byte & 0xC0) == 0x80 {
                    utf8_pending[utf8_pos] = byte;
                    utf8_pos += 1;
                    if utf8_pos == utf8_expected {
                        if len + utf8_expected <= LINE_BUF_SIZE
                            && let Ok(s) = core::str::from_utf8(&utf8_pending[..utf8_expected])
                        {
                            buf[len..len + utf8_expected]
                                .copy_from_slice(&utf8_pending[..utf8_expected]);
                            len += utf8_expected;
                            self.host.write_debug(s);
                        }
                        utf8_pos = 0;
                        utf8_expected = 0;
                    }
                    continue;
                }
                // Invalid continuation byte: discard partial sequence and process current byte.
                utf8_pos = 0;
                utf8_expected = 0;
            }
            match byte {
                b'\r' | b'\n' => {
                    self.host.write_debug("\n");
                    return Ok(len);
                }
                0x08 | 0x7F => {
                    if len > 0 {
                        // Pop one complete UTF-8 scalar (backing over 0x80..=0xBF continuation bytes).
                        len -= 1;
                        while len > 0 && (buf[len] & 0xC0) == 0x80 {
                            len -= 1;
                        }
                        self.host.write_debug("\x08 \x08");
                    }
                }
                0x03 => {
                    self.host.write_debug("^C\n");
                    return Ok(0);
                }
                0x0C => {
                    let mut out = AsciiLine::<160>::new();
                    out.push_str("\x1b[2J\x1b[Hnewos λ ");
                    if let Ok(s) = core::str::from_utf8(&buf[..len]) {
                        out.push_str(s);
                    }
                    self.host.write_debug(out.as_str());
                }
                0x20..=0x7E if len < LINE_BUF_SIZE => {
                    buf[len] = byte;
                    len += 1;
                    let tmp = [byte];
                    if let Ok(s) = core::str::from_utf8(&tmp) {
                        self.host.write_debug(s);
                    }
                }
                0xC2..=0xDF => {
                    utf8_pending[0] = byte;
                    utf8_pos = 1;
                    utf8_expected = 2;
                }
                0xE0..=0xEF => {
                    utf8_pending[0] = byte;
                    utf8_pos = 1;
                    utf8_expected = 3;
                }
                0xF0..=0xF4 => {
                    utf8_pending[0] = byte;
                    utf8_pos = 1;
                    utf8_expected = 4;
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
        let _ = eval_pipeline_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            line,
            true,
            &mut stream,
        );
        stream
    }

    /// Evaluate a typed pipeline silently reusing `self.scratch_stream` (zero stack `RecordStream` init).
    pub fn eval_pipeline_ref(&mut self, line: &str) -> &RecordStream {
        self.scratch_stream.clear();
        let _ = eval_pipeline_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            line,
            true,
            &mut self.scratch_stream,
        );
        &self.scratch_stream
    }

    fn exec_line_inner(&mut self, line: &str, silent: bool) -> ExecOutcome {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ExecOutcome::Continue;
        }
        match trimmed {
            "exit" | "shutdown" => {
                if !silent {
                    self.host.write_debug("Shutting down NewOS...\n");
                }
                return ExecOutcome::Exit(ShutdownStatus::Success);
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
                    let count = self.history_count as usize;
                    let total = count.min(HISTORY_LEN);
                    let start = count.saturating_sub(total);
                    let mut out =
                        BufferedWriter::<SHELL_OUT_BUF, _>::new(HostWriter(&mut self.host));
                    let mut row = AsciiLine::<160>::new();
                    for i in 0..total {
                        let idx = (start + i) % HISTORY_LEN;
                        let len = self.history_lens[idx] as usize;
                        if let Ok(s) = core::str::from_utf8(&self.history[idx][..len]) {
                            row.clear();
                            row.push_u64((start + i + 1) as u64);
                            row.push_str("  ");
                            row.push_str(s);
                            row.push_byte(b'\n');
                            let _ = out.write_str(row.as_str());
                        }
                    }
                }
                return ExecOutcome::Continue;
            }
            "help" => {
                if !silent {
                    self.host.write_debug(HELP_TEXT);
                }
                return ExecOutcome::Continue;
            }
            "gc" => {
                let reclaimed = self.store.gc();
                let remaining = self.store.object_count();
                if !silent {
                    let mut row = AsciiLine::<96>::new();
                    row.push_str("gc: reclaimed ");
                    row.push_u64(reclaimed as u64);
                    row.push_str(", ");
                    row.push_u64(remaining as u64);
                    row.push_str(" live\n");
                    self.host.write_debug(row.as_str());
                }
                return ExecOutcome::Continue;
            }
            "sys" => {
                let info = self.sys_info_cached();
                let obj_count = self.store.object_count();
                if !silent {
                    let mut row = AsciiLine::<96>::new();
                    row.push_str(concat!(
                        "NewOS ",
                        env!("CARGO_PKG_VERSION"),
                        " aarch64 microkernel (SMP="
                    ));
                    row.push_u64(u64::from(info.online_cpus));
                    row.push_str(" CPUs, ");
                    row.push_u64(u64::from(info.proc_count));
                    row.push_str(" procs, ");
                    row.push_u64(obj_count as u64);
                    row.push_str(" objs)\n");
                    self.host.write_debug(row.as_str());
                }
                return ExecOutcome::Continue;
            }
            _ => {}
        }

        // Single-pass stage tokenizer: parses stage 0 directly without a separate `split_pipeline` pass.
        let mut toks = [""; MAX_ARGS];
        let (argc, next_rest) = match next_pipeline_stage(trimmed, &mut toks) {
            Ok(v) => v,
            Err(pe) => {
                if !silent {
                    self.host.write_debug(parse_error_msg(pe));
                }
                return ExecOutcome::Continue;
            }
        };

        if next_rest.is_none() {
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
                            let mut row = AsciiLine::<192>::new();
                            row.push_str("[obj:");
                            row.push_hex16(hash.0);
                            row.push_str(", ");
                            row.push_u64(bytes.len() as u64);
                            row.push_str("B]\n");
                            row.push_str(text);
                            row.push_byte(b'\n');
                            self.host.write_debug(row.as_str());
                        }
                    }
                    Err(e) => {
                        if !silent {
                            let mut row = AsciiLine::<128>::new();
                            row.push_str("get: ");
                            row.push_str(spec);
                            row.push_str(": ");
                            row.push_str(store_error_str(e));
                            row.push_byte(b'\n');
                            self.host.write_debug(row.as_str());
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
            let ok = eval_producer_tokens_with(
                &mut self.store,
                &mut self.host,
                &mut self.cached_sys_info,
                &toks[..argc],
                silent,
                &mut self.scratch_stream,
            );
            if ok && !silent {
                let mut out = BufferedWriter::<SHELL_OUT_BUF, _>::new(HostWriter(&mut self.host));
                self.scratch_stream.render(&mut out);
            }
            return ExecOutcome::Continue;
        }

        // Multi-stage typed pipeline evaluation (`producer | filter | transform ...`)
        self.scratch_stream.clear();
        let ok = eval_pipeline_tail_with(
            &mut self.store,
            &mut self.host,
            &mut self.cached_sys_info,
            &toks[..argc],
            next_rest,
            silent,
            &mut self.scratch_stream,
        );
        if ok && !silent {
            let mut out = BufferedWriter::<SHELL_OUT_BUF, _>::new(HostWriter(&mut self.host));
            self.scratch_stream.render(&mut out);
        }
        ExecOutcome::Continue
    }

    fn exec_ref_cmd(&mut self, args: &[&str], silent: bool) {
        match args {
            ["set", name, hash_str] => {
                let Some(hash) = ObjHash::parse_hex(hash_str) else {
                    if !silent {
                        write_quoted_err(
                            &mut self.host,
                            "ref set: invalid hash `",
                            hash_str,
                            "`\n",
                        );
                    }
                    return;
                };
                match self.store.set_ref(name, hash) {
                    Ok(()) => {
                        if !silent {
                            let mut row = AsciiLine::<96>::new();
                            row.push_str("bound @");
                            row.push_str(name.strip_prefix('@').unwrap_or(name));
                            row.push_str(" -> obj:");
                            row.push_hex16(hash.0);
                            row.push_byte(b'\n');
                            self.host.write_debug(row.as_str());
                        }
                    }
                    Err(e) => {
                        if !silent {
                            write_store_err(&mut self.host, "ref set: ", e);
                        }
                    }
                }
            }
            ["seal", name] => match self.store.seal_ref(name) {
                Ok(()) => {
                    if !silent {
                        let mut row = AsciiLine::<64>::new();
                        row.push_str("sealed @");
                        row.push_str(name.strip_prefix('@').unwrap_or(name));
                        row.push_str(" (ro)\n");
                        self.host.write_debug(row.as_str());
                    }
                }
                Err(e) => {
                    if !silent {
                        write_store_err(&mut self.host, "ref seal: ", e);
                    }
                }
            },
            ["rollback", name] => match self.store.rollback_ref(name) {
                Ok(h) => {
                    if !silent {
                        let mut row = AsciiLine::<96>::new();
                        row.push_str("rollback @");
                        row.push_str(name.strip_prefix('@').unwrap_or(name));
                        row.push_str(" -> obj:");
                        row.push_hex16(h.0);
                        row.push_byte(b'\n');
                        self.host.write_debug(row.as_str());
                    }
                }
                Err(e) => {
                    if !silent {
                        write_store_err(&mut self.host, "ref rollback: ", e);
                    }
                }
            },
            _ => {
                if !silent {
                    self.host.write_debug(
                        "usage: ref <set <name> <hash> | seal <name> | rollback <name>>\n",
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
) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    let mut toks = [""; MAX_ARGS];
    let (argc, next_rest) = match next_pipeline_stage(trimmed, &mut toks) {
        Ok(v) => v,
        Err(pe) => {
            if !silent {
                host.write_debug(parse_error_msg(pe));
            }
            return false;
        }
    };
    eval_pipeline_tail_with(
        store,
        host,
        cached_sys_info,
        &toks[..argc],
        next_rest,
        silent,
        stream,
    )
}

fn eval_pipeline_tail_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    cached_sys_info: &mut Option<SysInfo>,
    producer_toks: &[&str],
    rest: Option<&str>,
    silent: bool,
    stream: &mut RecordStream,
) -> bool {
    let Some(mut rem) = rest else {
        return eval_producer_tokens_with(
            store,
            host,
            cached_sys_info,
            producer_toks,
            silent,
            stream,
        );
    };

    // Parse and validate all downstream pipeline stages ONCE on the stack before executing
    // stage 0 so syntax errors in stage >= 1 never mutate CAOS state or dispatch IPC calls.
    let mut stage_toks = [[""; MAX_ARGS]; MAX_STAGES - 1];
    let mut stage_argcs = [0usize; MAX_STAGES - 1];
    let mut n_transforms = 0usize;
    loop {
        if n_transforms >= MAX_STAGES - 1 {
            stream.clear();
            if !silent {
                host.write_debug(parse_error_msg(ParseError::TooManyStages));
            }
            return false;
        }
        match next_pipeline_stage(rem, &mut stage_toks[n_transforms]) {
            Ok((argc, next)) => {
                stage_argcs[n_transforms] = argc;
                n_transforms += 1;
                match next {
                    Some(n) => rem = n,
                    None => break,
                }
            }
            Err(pe) => {
                stream.clear();
                if !silent {
                    host.write_debug(parse_error_msg(pe));
                }
                return false;
            }
        }
    }

    if !eval_producer_tokens_with(store, host, cached_sys_info, producer_toks, silent, stream) {
        return false;
    }

    for i in 0..n_transforms {
        let argc = stage_argcs[i];
        if !eval_transform_tokens_with(store, host, &stage_toks[i][..argc], stream, silent) {
            stream.clear();
            return false;
        }
    }
    true
}

fn eval_producer_tokens_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    cached_sys_info: &mut Option<SysInfo>,
    toks: &[&str],
    silent: bool,
    stream: &mut RecordStream,
) -> bool {
    if toks.is_empty() {
        return true;
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
            true
        }
        "objects" => {
            store.for_each_object(|meta| {
                stream.push(Record::Object(meta));
            });
            true
        }
        "refs" => {
            store.for_each_ref(|meta| {
                stream.push(Record::Ref(meta));
            });
            true
        }
        "put" => {
            let res = match &toks[1..] {
                [] => store.put(&[]).map(|h| (h, 0)),
                [single] => {
                    let b = single.as_bytes();
                    store.put(b).map(|h| (h, b.len()))
                }
                args => {
                    let mut buf = [0u8; MAX_BLOB_SIZE];
                    let mut pos = 0usize;
                    let mut overflow = false;
                    for (i, arg) in args.iter().enumerate() {
                        let sep = usize::from(i > 0);
                        let b = arg.as_bytes();
                        match pos.checked_add(sep).and_then(|p| p.checked_add(b.len())) {
                            Some(end) if end <= MAX_BLOB_SIZE => {
                                if sep == 1 {
                                    buf[pos] = b' ';
                                    pos += 1;
                                }
                                buf[pos..pos + b.len()].copy_from_slice(b);
                                pos += b.len();
                            }
                            _ => {
                                overflow = true;
                                break;
                            }
                        }
                    }
                    if overflow {
                        Err(StoreError::TooLarge)
                    } else {
                        store.put(&buf[..pos]).map(|h| (h, pos))
                    }
                }
            };
            match res {
                Ok((hash, size)) => {
                    stream.push(Record::Object(ObjectMeta { hash, size }));
                    true
                }
                Err(e) => {
                    if !silent {
                        write_store_err(host, "put: ", e);
                    }
                    false
                }
            }
        }
        "ping" => {
            if toks.len() > 2 {
                if !silent {
                    host.write_debug("usage: ping [hex]\n");
                }
                return false;
            }
            let val = match toks.get(1).copied() {
                None | Some("") => 0xA110_C0DE,
                Some(raw) => match parse_hex_u64(raw) {
                    Some(v) => v,
                    None => {
                        if !silent {
                            write_quoted_err(host, "ping: invalid hex `", raw, "`\n");
                        }
                        return false;
                    }
                },
            };
            match host.ipc_call(CapId::BOOTSTRAP_EP, val) {
                Ok((badge, reply)) => {
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
                    true
                }
                Err(e) => {
                    if !silent {
                        let mut row = AsciiLine::<96>::new();
                        row.push_str("ping: ipc_call failed: ");
                        row.push_str(sys_error_str(e));
                        row.push_byte(b'\n');
                        host.write_debug(row.as_str());
                    }
                    false
                }
            }
        }
        "net" => {
            let sub = toks.get(1).copied().unwrap_or("");
            let arg = toks.get(2).copied().filter(|s| !s.is_empty());
            host.handle_net(sub, arg, stream, silent);
            true
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
            true
        }
        other => {
            if !silent {
                write_quoted_err(
                    host,
                    "newos-sh: unknown producer `",
                    other,
                    "` (try `help`)\n",
                );
            }
            false
        }
    }
}

fn eval_transform_tokens_with<H: ShellHost>(
    store: &mut ObjectStore,
    host: &mut H,
    toks: &[&str],
    stream: &mut RecordStream,
    silent: bool,
) -> bool {
    let argc = toks.len();
    if argc == 0 {
        return true;
    }

    match toks[0] {
        "count" => {
            let n = stream.len();
            stream.clear();
            stream.push(Record::Count(n));
            true
        }
        "first" => {
            if argc > 2 {
                stream.clear();
                if !silent {
                    host.write_debug("usage: ... | first <n>\n");
                }
                return false;
            }
            let limit = if argc == 1 {
                1
            } else {
                let raw = toks[1];
                if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) {
                    match raw.parse::<usize>() {
                        Ok(n) => n,
                        Err(_) => {
                            stream.clear();
                            if !silent {
                                write_quoted_err(host, "first: invalid count `", raw, "`\n");
                            }
                            return false;
                        }
                    }
                } else {
                    stream.clear();
                    if !silent {
                        write_quoted_err(host, "first: invalid count `", raw, "`\n");
                    }
                    return false;
                }
            };
            stream.truncate(limit);
            true
        }
        "save" => {
            let Some(ref_name) = toks.get(1).copied().filter(|s| !s.is_empty()) else {
                stream.clear();
                if !silent {
                    host.write_debug("usage: ... | save @<name>\n");
                }
                return false;
            };
            if let Some(Record::Object(meta)) = stream.first() {
                if let Err(e) = store.set_ref(ref_name, meta.hash) {
                    stream.clear();
                    if !silent {
                        let mut row = AsciiLine::<128>::new();
                        row.push_str("save ");
                        row.push_str(ref_name);
                        row.push_str(": ");
                        row.push_str(store_error_str(e));
                        row.push_byte(b'\n');
                        host.write_debug(row.as_str());
                    }
                    return false;
                }
                true
            } else {
                stream.clear();
                if !silent {
                    host.write_debug("save: expected an Object record from upstream\n");
                }
                false
            }
        }
        "where" => {
            if argc != 4 {
                stream.clear();
                if !silent {
                    host.write_debug("usage: ... | where <field> <op> <value>\n");
                }
                return false;
            }
            if let Some(pred) = WherePredicate::parse(toks[1], toks[2], toks[3]) {
                stream.retain(|rec| pred.matches(rec));
                true
            } else {
                stream.clear();
                if !silent {
                    host.write_debug("where: invalid predicate\n");
                }
                false
            }
        }
        other => {
            stream.clear();
            if !silent {
                write_quoted_err(host, "newos-sh: unknown stage `", other, "` (try `help`)\n");
            }
            false
        }
    }
}

const HELP_TEXT: &str = concat!(
    "Typed Pipelines & CAOS:\n",
    "  put <text>               Store immutable object -> Object\n",
    "  get <@ref | obj:hash>    Read object content\n",
    "  objects / refs / procs   Emit Object / Ref / Proc records\n",
    "  ref set|seal|rollback    Manage capability-gated Refs\n",
    "  ping [hex] / bench       IPC round-trip & cycle bench\n",
    "  net [dhcp|ping|resolve]  EL0 smoltcp + GEM / VirtIO\n",
    "  | where <f> <op> <v>     Filter records\n",
    "  | save @<name>           Bind Object to Ref\n",
    "  | first <n> / | count    Slice or count stream\n",
    "  sys / gc / history / crash / clear / exit\n",
);

const _: () = assert!(HELP_TEXT.len() <= SHELL_OUT_BUF);

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
                op.eval_eq(&meta.name[..meta.name_len as usize] == r.as_bytes())
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
    let b = rhs.as_bytes();
    if b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        u64::from_str_radix(&rhs[2..], 16).ok()
    } else {
        rhs.parse::<u64>().ok()
    }
}

/// Single-pass, quote-aware stage tokenizer.
///
/// Parses tokens up to the next unquoted `|` (or end-of-line) into `out`, returning
/// `(argc, remaining_after_pipe)`. Rejects empty stages, unclosed quotes, and `> MAX_ARGS`.
#[inline]
fn next_pipeline_stage<'a>(
    line: &'a str,
    out: &mut [&'a str; MAX_ARGS],
) -> Result<(usize, Option<&'a str>), ParseError> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut count = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'|' {
            if count == 0 {
                return Err(ParseError::EmptyStage);
            }
            return Ok((count, Some(&line[i + 1..])));
        }
        if count >= MAX_ARGS {
            return Err(ParseError::TooManyArgs);
        }
        if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err(ParseError::UnclosedQuote);
            }
            out[count] = &line[start..i];
            count += 1;
            i += 1;
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'|' {
                if bytes[i] == b'"' {
                    return Err(ParseError::UnclosedQuote);
                }
                i += 1;
            }
            out[count] = &line[start..i];
            count += 1;
        }
    }

    if count == 0 {
        return Err(ParseError::EmptyStage);
    }
    Ok((count, None))
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
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
        assert!(sh.host().output_str().contains("Typed Pipelines"));

        assert_eq!(sh.exec_line("get @motd"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("NewOS"));

        assert_eq!(sh.exec_line("clear"), ExecOutcome::Continue);
        assert_eq!(sh.exec_line("crash"), ExecOutcome::Continue);
        assert!(sh.host().fault_triggered);

        assert_eq!(
            sh.exec_line("exit"),
            ExecOutcome::Exit(ShutdownStatus::Success)
        );
        assert_eq!(
            sh.exec_line("shutdown"),
            ExecOutcome::Exit(ShutdownStatus::Success)
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

        // Malformed `where` (< 4 args) emits usage diagnostic and clears stream
        assert_eq!(sh.exec_line("objects | where size"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("usage: ... | where"));
        assert!(!sh.host().output_str().contains("OBJECT HASH"));
    }

    #[test]
    fn read_line_redraws_prompt_cleanly_on_async_background_log() {
        struct AsyncLogHost {
            out: [u8; 512],
            out_len: usize,
            step: usize,
            log_delivered: bool,
        }
        impl AsyncLogHost {
            fn output(&self) -> &str {
                core::str::from_utf8(&self.out[..self.out_len]).unwrap_or("")
            }
        }
        impl ShellHost for AsyncLogHost {
            fn write_debug(&mut self, s: &str) {
                let bytes = s.as_bytes();
                let n = bytes.len().min(self.out.len() - self.out_len);
                self.out[self.out_len..self.out_len + n].copy_from_slice(&bytes[..n]);
                self.out_len += n;
            }
            fn sys_info(&mut self) -> SysInfo {
                SysInfo {
                    online_cpus: 4,
                    proc_count: 2,
                    interactive_shell: true,
                }
            }
            fn read_debug_byte(&mut self) -> Result<u8, SysError> {
                let b = match self.step {
                    0 => Ok(b'h'),
                    1 => Ok(b'e'),
                    2 => Err(SysError::WouldBlock),
                    3 => Ok(b'l'),
                    4 => Ok(b'p'),
                    _ => Ok(b'\n'),
                };
                self.step += 1;
                b
            }
            fn poll_background_log(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
                if self.step == 3 && !self.log_delivered {
                    self.log_delivered = true;
                    let msg = b"[worker] async log";
                    out[..msg.len()].copy_from_slice(msg);
                    Some((1, msg.len()))
                } else {
                    None
                }
            }
        }

        let mut sh = Shell::new(AsyncLogHost {
            out: [0u8; 512],
            out_len: 0,
            step: 0,
            log_delivered: false,
        });
        let mut line_buf = [0u8; LINE_BUF_SIZE];
        let len = sh.read_line(&mut line_buf);
        assert_eq!(&line_buf[..len], b"help");
        assert_eq!(
            sh.host().output(),
            "he\r\x1b[K[worker] async log\nnewos λ help\n"
        );
    }

    #[test]
    fn quoted_pipe_preserved_in_put_and_save() {
        let mut sh = Shell::new(MockHost::new());
        let s = sh.eval_pipeline("put \"a | b\" | save @x");
        assert_eq!(s.len(), 1);
        assert_eq!(sh.store().get_any("@x").unwrap().1, b"a | b");

        // Single-stage quoted pipe also works without splitting.
        let s2 = sh.eval_pipeline("put \"left | right\"");
        assert_eq!(s2.len(), 1);
        if let Some(Record::Object(meta)) = s2.first() {
            assert_eq!(sh.store().get_by_hash(meta.hash).unwrap(), b"left | right");
        } else {
            panic!("expected Object record");
        }

        // Verify eval_pipeline_ref reuses scratch_stream cleanly.
        let r = sh.eval_pipeline_ref("procs | where pid == 1 | count");
        assert!(matches!(r.first(), Some(Record::Count(1))));
    }

    #[test]
    fn utf8_boundary_truncation_in_ascii_line_and_record_history() {
        // Multi-byte UTF-8 ("λ" = 2B, "🦀" = 4B) straddling AsciiLine capacity
        let mut line = AsciiLine::<5>::new();
        line.push_str("ab🦀"); // 2 + 4 = 6 > 5 -> must truncate before '🦀', keeping "ab"
        assert_eq!(line.as_str(), "ab");

        let mut line2 = AsciiLine::<4>::new();
        line2.push_str("aλz"); // 1 + 2 + 1 = 4 -> fits completely
        assert_eq!(line2.as_str(), "aλz");

        let mut line3 = AsciiLine::<2>::new();
        line3.push_str("aλ"); // 1 + 2 = 3 > 2 -> keeps "a", never returns ""
        assert_eq!(line3.as_str(), "a");

        // Multi-byte UTF-8 straddling LINE_BUF_SIZE (128B) in record_history
        let mut raw = [b'a'; 132];
        // Put 4-byte '🦀' at bytes 126..130 (straddling 128)
        raw[126..130].copy_from_slice("🦀".as_bytes());
        let s = core::str::from_utf8(&raw[..130]).unwrap();
        let mut sh = Shell::new(MockHost::new());
        sh.record_history(s);
        assert_eq!(sh.exec_line("history"), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("1  aaaaaaaa"));
        assert!(!sh.host().output_str().is_empty());
    }

    #[test]
    fn put_oversized_single_and_multi_token_returns_too_large() {
        let mut sh = Shell::new(MockHost::new());
        let before = sh.store().object_count();

        // Single-token > 128B (129 'x' bytes)
        let mut cmd = [b'x'; 133];
        cmd[..4].copy_from_slice(b"put ");
        let cmd_str = core::str::from_utf8(&cmd).unwrap();
        assert_eq!(sh.exec_line(cmd_str), ExecOutcome::Continue);
        assert!(sh.host().output_str().contains("put: TooLarge"));
        assert_eq!(sh.store().object_count(), before);

        // Multi-token > 128B (65 + ' ' + 65 = 131B)
        let mut sh2 = Shell::new(MockHost::new());
        let mut cmd2 = [b'y'; 4 + 65 + 1 + 65];
        cmd2[..4].copy_from_slice(b"put ");
        cmd2[4 + 65] = b' ';
        let cmd2_str = core::str::from_utf8(&cmd2).unwrap();
        assert_eq!(sh2.exec_line(cmd2_str), ExecOutcome::Continue);
        assert!(sh2.host().output_str().contains("put: TooLarge"));
        assert_eq!(sh2.store().object_count(), before);
    }

    #[test]
    fn parse_errors_diagnosed_cleanly() {
        let cases = [
            ("put \"abc", "unclosed quote"),
            ("objects | | count", "empty pipeline stage"),
            ("| count", "empty pipeline stage"),
            ("objects |", "empty pipeline stage"),
            (
                "objects | first 1 | first 1 | first 1 | first 1 | first 1 | count",
                "too many pipeline stages",
            ),
            ("put 1 2 3 4 5 6 7 8 9 10 11 12", "too many arguments"),
        ];
        for (cmd, expected) in cases {
            let mut sh = Shell::new(MockHost::new());
            assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
            assert!(
                sh.host().output_str().contains(expected),
                "cmd `{cmd}` output `{}` did not contain `{expected}`",
                sh.host().output_str()
            );
        }
    }

    #[test]
    fn where_first_ping_invalid_args_and_ipc_error_diagnosed() {
        // Invalid `where` field/op/rhs/argc (including unprefixed hex "dead")
        for cmd in [
            "objects | where badfield == 1",
            "objects | where size ~~ 1",
            "objects | where size == dead",
            "objects | where size == 1 extra",
        ] {
            let mut sh = Shell::new(MockHost::new());
            assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
            let out = sh.host().output_str();
            assert!(
                out.contains("where: invalid predicate") || out.contains("usage: ... | where"),
                "unexpected output for `{cmd}`: `{out}`"
            );
        }

        // Invalid `first` count & extra args
        {
            let mut sh = Shell::new(MockHost::new());
            assert_eq!(sh.exec_line("objects | first abc"), ExecOutcome::Continue);
            assert!(sh.host().output_str().contains("first: invalid count"));
        }
        {
            let mut sh = Shell::new(MockHost::new());
            assert_eq!(sh.exec_line("objects | first 1 2"), ExecOutcome::Continue);
            assert!(sh.host().output_str().contains("usage: ... | first"));
        }

        // Invalid `ping` hex
        {
            let mut sh = Shell::new(MockHost::new());
            assert_eq!(sh.exec_line("ping zzz"), ExecOutcome::Continue);
            assert!(sh.host().output_str().contains("ping: invalid hex"));
        }

        // `ping` with IPC error from host
        struct FailIpcHost {
            out: [u8; 256],
            len: usize,
        }
        impl ShellHost for FailIpcHost {
            fn write_debug(&mut self, s: &str) {
                let b = s.as_bytes();
                let n = b.len().min(self.out.len() - self.len);
                self.out[self.len..self.len + n].copy_from_slice(&b[..n]);
                self.len += n;
            }
            fn sys_info(&mut self) -> SysInfo {
                SysInfo {
                    online_cpus: 1,
                    proc_count: 1,
                    interactive_shell: false,
                }
            }
            fn ipc_call(&mut self, _cap: CapId, _payload: u64) -> Result<(u64, u64), SysError> {
                Err(SysError::InvalidCapability)
            }
        }
        let mut sh = Shell::new(FailIpcHost {
            out: [0u8; 256],
            len: 0,
        });
        assert_eq!(sh.exec_line("ping 0x42"), ExecOutcome::Continue);
        let out = core::str::from_utf8(&sh.host().out[..sh.host().len]).unwrap();
        assert!(out.contains("ping: ipc_call failed: InvalidCapability"));
    }

    #[test]
    fn read_line_breaks_on_fatal_error_and_coalesces_ctrl_l() {
        // 1. Fatal read_debug_byte error breaks immediately with 0 yield_now calls.
        struct FatalReadHost {
            yields: usize,
        }
        impl ShellHost for FatalReadHost {
            fn write_debug(&mut self, _s: &str) {}
            fn sys_info(&mut self) -> SysInfo {
                SysInfo {
                    online_cpus: 1,
                    proc_count: 1,
                    interactive_shell: true,
                }
            }
            fn read_debug_byte(&mut self) -> Result<u8, SysError> {
                Err(SysError::InvalidCapability)
            }
            fn yield_now(&mut self) -> Result<u64, SysError> {
                self.yields += 1;
                Ok(0)
            }
        }
        let mut sh = Shell::new(FatalReadHost { yields: 0 });
        let mut buf = [0u8; LINE_BUF_SIZE];
        assert_eq!(sh.read_line(&mut buf), 0);
        assert_eq!(sh.host().yields, 0);

        // 2. Ctrl-L coalesces screen clear + prompt + buffer into 1 write_debug syscall,
        //    and drain_background_logs clamps n > 256 and emits 1 write_debug syscall.
        struct CtrlLAndLogHost {
            writes: usize,
            step: usize,
            log_sent: bool,
            last_write_len: usize,
        }
        impl ShellHost for CtrlLAndLogHost {
            fn write_debug(&mut self, s: &str) {
                self.writes += 1;
                self.last_write_len = s.len();
            }
            fn sys_info(&mut self) -> SysInfo {
                SysInfo {
                    online_cpus: 1,
                    proc_count: 1,
                    interactive_shell: true,
                }
            }
            fn read_debug_byte(&mut self) -> Result<u8, SysError> {
                let r = match self.step {
                    0 => Ok(b'a'),
                    1 => Ok(0x0C), // Ctrl-L
                    _ => Ok(b'\n'),
                };
                self.step += 1;
                r
            }
            fn poll_background_log(&mut self, out: &mut [u8]) -> Option<(u64, usize)> {
                if self.step == 1 && !self.log_sent {
                    self.log_sent = true;
                    out.fill(b'z');
                    // Deliberately return bogus length > out.len() to verify clamping!
                    Some((1, 999))
                } else {
                    None
                }
            }
        }
        let mut sh2 = Shell::new(CtrlLAndLogHost {
            writes: 0,
            step: 0,
            log_sent: false,
            last_write_len: 0,
        });
        let n = sh2.read_line(&mut buf);
        assert_eq!(&buf[..n], b"a");
        // 1 write for 'a' + 1 coalesced write for log + 1 coalesced write for Ctrl-L + 1 write for '\n' = 4
        assert_eq!(sh2.host().writes, 4);
    }

    #[test]
    fn help_fits_in_single_debug_write_syscall() {
        let mut sh = Shell::new(MockHost::new());
        assert_eq!(sh.exec_line("help"), ExecOutcome::Continue);
        assert_eq!(sh.host().debug_write_syscalls, 1);
        assert!(sh.host().output_str().len() <= 1024);
        assert!(sh.host().output_str().contains("Typed Pipelines"));
    }

    #[test]
    fn syntax_error_in_later_pipeline_stage_causes_no_side_effects() {
        let mut sh = Shell::new(MockHost::new());
        let base_objs = sh.store().object_count();
        let bad_cmds = [
            r#"put "leak1" |"#,
            r#"put "leak2" | | count"#,
            r#"put "leak3" | where "unclosed"#,
            r#"put "leak4" | first 1 | first 1 | first 1 | first 1 | first 1 | count"#,
            r#"put "leak5" | where a b c d e f g h i j k l"#,
            r#"put "leak6" | save @leakref |"#,
            r#"ping 0x10 |"#,
        ];
        for cmd in bad_cmds {
            sh.host_mut().out_len = 0;
            assert_eq!(sh.exec_line(cmd), ExecOutcome::Continue);
            assert!(
                sh.host().output_str().contains("newos-sh:"),
                "missing diagnostic for `{cmd}`"
            );
            assert_eq!(
                sh.store().object_count(),
                base_objs,
                "CAOS mutated for `{cmd}`"
            );
            assert!(
                sh.store().get_any("@leakref").is_err(),
                "@leakref created for `{cmd}`"
            );
            assert_eq!(
                sh.host().ipc_send_syscalls,
                0,
                "IPC send dispatched for `{cmd}`"
            );
            assert_eq!(
                sh.host().ipc_recv_syscalls,
                0,
                "IPC recv dispatched for `{cmd}`"
            );
        }
    }

    #[test]
    fn failed_transform_clears_eval_pipeline_stream() {
        let mut sh = Shell::new(MockHost::new());
        for cmd in [
            "objects | bogus_stage",
            "procs | save @x",
            r#"put "abc" | save @motd"#,
        ] {
            assert!(
                sh.eval_pipeline(cmd).is_empty(),
                "eval_pipeline(`{cmd}`) should be empty"
            );
            assert!(
                sh.eval_pipeline_ref(cmd).is_empty(),
                "eval_pipeline_ref(`{cmd}`) should be empty"
            );
        }
    }

    #[test]
    fn read_line_supports_utf8_input_and_scalar_backspace() {
        struct Utf8InputHost {
            input: [u8; 32],
            len: usize,
            pos: usize,
        }
        impl ShellHost for Utf8InputHost {
            fn write_debug(&mut self, _s: &str) {}
            fn sys_info(&mut self) -> SysInfo {
                SysInfo {
                    online_cpus: 4,
                    proc_count: 2,
                    interactive_shell: true,
                }
            }
            fn read_debug_byte(&mut self) -> Result<u8, SysError> {
                if self.pos < self.len {
                    let b = self.input[self.pos];
                    self.pos += 1;
                    Ok(b)
                } else {
                    Err(SysError::WouldBlock)
                }
            }
        }

        // Type "aλ🦀", backspace once (pops 4-byte '🦀'), type "b\n" -> "aλb"
        let mut input = [0u8; 32];
        let mut n = 0usize;
        for &b in "aλ🦀".as_bytes() {
            input[n] = b;
            n += 1;
        }
        input[n] = 0x7F; // backspace
        n += 1;
        input[n] = b'b';
        n += 1;
        input[n] = b'\n';
        n += 1;

        let mut sh = Shell::new(Utf8InputHost {
            input,
            len: n,
            pos: 0,
        });
        let mut line_buf = [0u8; LINE_BUF_SIZE];
        let len = sh.read_line(&mut line_buf);
        assert_eq!(core::str::from_utf8(&line_buf[..len]), Ok("aλb"));
    }
}
