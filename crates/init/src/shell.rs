//! Post-UNIX Typed Zero-Copy Pipeline Shell (`newos-sh`) — `#![forbid(unsafe_code)]`, `no_alloc`.
//!
//! Instead of piping untyped ASCII text through regexes, stages pass typed `Record` values
//! (`Proc`, `Object`, `Ref`, `Metric`, `Count`) directly through structured `|` pipelines:
//!   - `put "hello newos" | save @note`
//!   - `objects | where size > 20`
//!   - `refs | where writable == false`
//!   - `procs | where pid == 1 | count`

use core::fmt::Write;
use newos_abi::{CapId, QemuExitCode, SysError};
use newos_user_rt::DebugConsole;

use crate::caos::{ObjHash, ObjectMeta, ObjectStore, RefMeta, StoreError};

const LINE_BUF_SIZE: usize = 128;
const HISTORY_LEN: usize = 8;
const MAX_STAGES: usize = 6;
const MAX_ARGS: usize = 12;
const MAX_STREAM_RECORDS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome {
    Continue,
    Exit(QemuExitCode),
}

/// Typed structured record flowing between `|` pipeline stages (zero text re-parsing).
#[derive(Clone, Copy)]
pub enum Record {
    Proc {
        pid: u64,
        ring: u64,
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

    pub fn first(&self) -> Option<Record> {
        if self.len > 0 { self.items[0] } else { None }
    }

    fn render<W: Write>(&self, out: &mut W) {
        if self.len == 0 {
            let _ = writeln!(out, "(empty stream)");
            return;
        }
        match self.items[0] {
            Some(Record::Proc { .. }) => {
                let _ = writeln!(out, "PID  RING  ISOLATION      NAME");
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Proc { pid, ring, name } = rec {
                        let _ = writeln!(out, "{pid:<4} {ring:<5} CR3 VSpace #{pid}  {name}");
                    }
                }
            }
            Some(Record::Object(_)) => {
                let _ = writeln!(out, "OBJECT HASH           SIZE");
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Object(meta) = rec {
                        let _ = writeln!(out, "obj:{:016x}  {} B", meta.hash.0, meta.size);
                    }
                }
            }
            Some(Record::Ref(_)) => {
                let _ = writeln!(out, "REF              MODE  TARGET                PREV");
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Ref(meta) = rec {
                        let mode = if meta.writable { "rw  " } else { "ro  " };
                        match meta.prev {
                            Some(p) => {
                                let _ = writeln!(
                                    out,
                                    "@{:<15} {mode}  obj:{:016x}  obj:{:016x}",
                                    meta.name_str(),
                                    meta.target.0,
                                    p.0
                                );
                            }
                            None => {
                                let _ = writeln!(
                                    out,
                                    "@{:<15} {mode}  obj:{:016x}  -",
                                    meta.name_str(),
                                    meta.target.0
                                );
                            }
                        }
                    }
                }
            }
            Some(Record::Metric { .. }) => {
                let _ = writeln!(out, "METRIC                VALUE");
                for rec in self.items[..self.len].iter().flatten() {
                    if let Record::Metric { label, value, unit } = rec {
                        let _ = writeln!(out, "{label:<20}  {value} {unit}");
                    }
                }
            }
            Some(Record::Count(c)) => {
                let _ = writeln!(out, "{c}");
            }
            None => {}
        }
    }
}

pub struct Shell {
    store: ObjectStore,
    history: [[u8; LINE_BUF_SIZE]; HISTORY_LEN],
    history_lens: [usize; HISTORY_LEN],
    history_count: usize,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            store: ObjectStore::new(),
            history: [[0; LINE_BUF_SIZE]; HISTORY_LEN],
            history_lens: [0; HISTORY_LEN],
            history_count: 0,
        }
    }

    fn record_history(&mut self, line: &str) {
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
        let mut sink = NullWriter;

        // 1. Typed pipeline: `put "v1" | save @demo`
        let before_objs = self.store.object_count();
        let _ = self.exec_line("put \"hello caos v1\" | save @demo", &mut sink);
        if self.store.object_count() != before_objs + 1 {
            return Err("put | save did not create object");
        }

        // 2. Content deduplication: storing identical bytes must NOT allocate a new object!
        let _ = self.exec_line("put \"hello caos v1\"", &mut sink);
        if self.store.object_count() != before_objs + 1 {
            return Err("content deduplication failed");
        }

        // 3. Atomic update + instant rollback: v1 -> v2 -> rollback -> v1
        let _ = self.exec_line("put \"hello caos v2\" | save @demo", &mut sink);
        let (_, v2) = self
            .store
            .get_any("@demo")
            .map_err(|_| "missing @demo v2")?;
        if v2 != b"hello caos v2" {
            return Err("@demo did not update to v2");
        }
        let _ = self.exec_line("ref rollback @demo", &mut sink);
        let (_, v1) = self
            .store
            .get_any("@demo")
            .map_err(|_| "missing @demo after rollback")?;
        if v1 != b"hello caos v1" {
            return Err("ref rollback did not restore v1");
        }

        // 4. Irreversible capability attenuation (`seal` -> read-only)
        let _ = self.exec_line("ref seal @demo", &mut sink);
        let h2 = self.store.put(b"tamper").map_err(|_| "put tamper failed")?;
        if self.store.set_ref("@demo", h2) != Err(StoreError::ReadOnly) {
            return Err("sealed ref allowed write!");
        }

        // 5. Typed pipeline filter & reduction: `procs | where pid == 1 | count` -> 1
        let stream = self.eval_pipeline("procs | where pid == 1 | count", &mut sink);
        match stream.first() {
            Some(Record::Count(1)) => {}
            _ => return Err("typed pipeline `procs | where pid == 1 | count` failed"),
        }

        Ok(())
    }

    /// Run the interactive Ring-3 REPL (`cargo xtask run`).
    pub fn run_interactive(&mut self) -> ! {
        let mut out = DebugConsole;
        let _ = writeln!(out, "\n================================================================");
        let _ = writeln!(out, "  newos-sh: Post-UNIX Typed Pipeline Shell + Ring-3 CAOS");
        let _ = writeln!(out, "  100% #![forbid(unsafe_code)] · zero POSIX paths · zero heap");
        let _ = writeln!(out, "  Try: `get @guide`, `objects | where size > 20`, `help`");
        let _ = writeln!(out, "================================================================\n");

        let mut line_buf = [0u8; LINE_BUF_SIZE];
        loop {
            let _ = out.write_str("newos λ ");
            let len = self.read_line(&mut line_buf, &mut out);
            let line = core::str::from_utf8(&line_buf[..len]).unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            self.record_history(line);
            if let ExecOutcome::Exit(code) = self.exec_line(line, &mut out) {
                newos_user_rt::exit(code);
            }
        }
    }

    fn read_line<W: Write>(&self, buf: &mut [u8; LINE_BUF_SIZE], out: &mut W) -> usize {
        let mut len = 0usize;
        loop {
            let byte = match newos_user_rt::debug_read_byte() {
                Ok(b) => b,
                Err(SysError::WouldBlock) | Err(_) => {
                    let _ = newos_user_rt::yield_now();
                    continue;
                }
            };
            match byte {
                b'\r' | b'\n' => {
                    let _ = out.write_str("\n");
                    return len;
                }
                0x08 | 0x7F => {
                    if len > 0 {
                        len -= 1;
                        let _ = out.write_str("\x08 \x08");
                    }
                }
                0x03 => {
                    let _ = out.write_str("^C\n");
                    return 0;
                }
                0x0C => {
                    let _ = out.write_str("\x1b[2J\x1b[Hnewos λ ");
                    if let Ok(s) = core::str::from_utf8(&buf[..len]) {
                        let _ = out.write_str(s);
                    }
                }
                0x20..=0x7E => {
                    if len < LINE_BUF_SIZE {
                        buf[len] = byte;
                        len += 1;
                        let tmp = [byte];
                        if let Ok(s) = core::str::from_utf8(&tmp) {
                            let _ = out.write_str(s);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub fn exec_line<W: Write>(&mut self, line: &str, out: &mut W) -> ExecOutcome {
        let trimmed = line.trim();
        if trimmed == "exit" || trimmed == "shutdown" {
            let _ = writeln!(out, "Shutting down NewOS...");
            return ExecOutcome::Exit(QemuExitCode::Success);
        }
        if trimmed == "clear" {
            let _ = out.write_str("\x1b[2J\x1b[H");
            return ExecOutcome::Continue;
        }
        if trimmed == "crash" {
            let _ = writeln!(
                out,
                "[newos-sh] triggering deliberate Ring-3 #UD fault (kernel stays alive)..."
            );
            newos_user_rt::trigger_user_fault();
        }
        if trimmed == "history" {
            let total = self.history_count.min(HISTORY_LEN);
            let start = self.history_count.saturating_sub(total);
            for i in 0..total {
                let idx = (start + i) % HISTORY_LEN;
                let len = self.history_lens[idx];
                if let Ok(s) = core::str::from_utf8(&self.history[idx][..len]) {
                    let _ = writeln!(out, "{:>3}  {s}", start + i + 1);
                }
            }
            return ExecOutcome::Continue;
        }
        if trimmed == "help" {
            self.write_help(out);
            return ExecOutcome::Continue;
        }
        if trimmed == "sys" {
            let info = newos_user_rt::sys_info();
            let _ = writeln!(
                out,
                "NewOS 0.1.0 x86_64 pure-seL4-microkernel (SMP={} CPUs, {} Ring-3 procs, {} CAOS objects)",
                info.online_cpus,
                info.proc_count,
                self.store.object_count()
            );
            return ExecOutcome::Continue;
        }

        // Single-stage side-effecting commands (`get`, `ref`)
        if !trimmed.contains('|') {
            let mut toks = [""; MAX_ARGS];
            let argc = split_tokens(trimmed, &mut toks);
            if argc > 0 && toks[0] == "get" {
                let Some(spec) = toks.get(1).copied().filter(|s| !s.is_empty()) else {
                    let _ = writeln!(out, "usage: get <@ref | obj:hash>");
                    return ExecOutcome::Continue;
                };
                match self.store.get_any(spec) {
                    Ok((hash, bytes)) => {
                        let text = core::str::from_utf8(bytes).unwrap_or("<binary>");
                        let _ = writeln!(out, "[obj:{:016x}, {} B]\n{text}", hash.0, bytes.len());
                    }
                    Err(e) => {
                        let _ = writeln!(out, "get: {spec}: {e:?}");
                    }
                }
                return ExecOutcome::Continue;
            }
            if argc > 0 && toks[0] == "ref" {
                self.exec_ref_cmd(&toks[1..argc], out);
                return ExecOutcome::Continue;
            }
        }

        // Full typed pipeline evaluation (`producer | filter | transform ...`)
        let stream = self.eval_pipeline(trimmed, out);
        stream.render(out);
        ExecOutcome::Continue
    }

    fn exec_ref_cmd<W: Write>(&mut self, args: &[&str], out: &mut W) {
        match args {
            ["set", name, hash_str] => {
                let Some(hash) = ObjHash::parse_hex(hash_str) else {
                    let _ = writeln!(out, "ref set: invalid hash `{hash_str}`");
                    return;
                };
                match self.store.set_ref(name, hash) {
                    Ok(()) => {
                        let _ = writeln!(out, "bound @{name} -> obj:{:016x}", hash.0);
                    }
                    Err(e) => {
                        let _ = writeln!(out, "ref set: {e:?}");
                    }
                }
            }
            ["seal", name] => match self.store.seal_ref(name) {
                Ok(()) => {
                    let _ = writeln!(out, "sealed @{name} (irreversibly read-only)");
                }
                Err(e) => {
                    let _ = writeln!(out, "ref seal: {e:?}");
                }
            },
            ["rollback", name] => match self.store.rollback_ref(name) {
                Ok(h) => {
                    let _ = writeln!(out, "rolled back @{name} -> obj:{:016x}", h.0);
                }
                Err(e) => {
                    let _ = writeln!(out, "ref rollback: {e:?}");
                }
            },
            _ => {
                let _ = writeln!(out, "usage: ref <set <name> <hash> | seal <name> | rollback <name>>");
            }
        }
    }

    fn eval_pipeline<W: Write>(&mut self, line: &str, out: &mut W) -> RecordStream {
        let mut stages = [""; MAX_STAGES];
        let mut stage_count = 0usize;
        for part in line.split('|') {
            if stage_count < MAX_STAGES {
                stages[stage_count] = part.trim();
                stage_count += 1;
            }
        }
        if stage_count == 0 {
            return RecordStream::new();
        }

        let mut stream = self.eval_producer(stages[0], out);
        for stage in &stages[1..stage_count] {
            stream = self.eval_transform(stage, stream, out);
        }
        stream
    }

    fn eval_producer<W: Write>(&mut self, stage: &str, out: &mut W) -> RecordStream {
        let mut toks = [""; MAX_ARGS];
        let argc = split_tokens(stage, &mut toks);
        let mut stream = RecordStream::new();
        if argc == 0 {
            return stream;
        }

        match toks[0] {
            "procs" => {
                let info = newos_user_rt::sys_info();
                stream.push(Record::Proc {
                    pid: 0,
                    ring: 3,
                    name: "init (newos-sh + CAOS)",
                });
                if info.proc_count > 1 {
                    stream.push(Record::Proc {
                        pid: 1,
                        ring: 3,
                        name: "worker (IPC responder)",
                    });
                }
            }
            "objects" => {
                let mut metas = [None; MAX_STREAM_RECORDS];
                let n = self.store.collect_objects(&mut metas);
                for meta in metas[..n].iter().flatten() {
                    stream.push(Record::Object(*meta));
                }
            }
            "refs" => {
                let mut metas = [None; MAX_STREAM_RECORDS];
                let n = self.store.collect_refs(&mut metas);
                for meta in metas[..n].iter().flatten() {
                    stream.push(Record::Ref(*meta));
                }
            }
            "put" => {
                let mut buf = [0u8; 128];
                let mut pos = 0usize;
                for (i, arg) in toks[1..argc].iter().enumerate() {
                    if i > 0 && pos < buf.len() {
                        buf[pos] = b' ';
                        pos += 1;
                    }
                    let b = arg.as_bytes();
                    let n = b.len().min(buf.len().saturating_sub(pos));
                    buf[pos..pos + n].copy_from_slice(&b[..n]);
                    pos += n;
                }
                match self.store.put(&buf[..pos]) {
                    Ok(hash) => stream.push(Record::Object(ObjectMeta { hash, size: pos })),
                    Err(e) => {
                        let _ = writeln!(out, "put: {e:?}");
                    }
                }
            }
            "ping" => {
                let val = toks
                    .get(1)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| parse_hex_u64(s))
                    .unwrap_or(0xA110_C0DE);
                if newos_user_rt::ipc_send(CapId::BOOTSTRAP_EP, val).is_ok() {
                    let _ = newos_user_rt::yield_now();
                    if let Ok((badge, reply)) = newos_user_rt::ipc_recv(CapId::BOOTSTRAP_EP) {
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
            }
            "net" => {
                let nic = newos_net::probe_virtio_net(|off| {
                    newos_user_rt::mmio_read32(CapId::BOOTSTRAP_NET_MMIO, off)
                });
                let mac = nic
                    .map(|n| n.mac)
                    .unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
                if let Some(n) = nic {
                    stream.push(Record::Metric {
                        label: "virtio.net.slot",
                        value: u64::from(n.slot),
                        unit: "(mmio cap)",
                    });
                    stream.push(Record::Metric {
                        label: "virtio.net.ver",
                        value: u64::from(n.version),
                        unit: "(virtio)",
                    });
                    if toks.get(1).copied() == Some("ping") {
                        match newos_net::live_virtio_icmp_ping(
                            crate::CapVirtioTransport,
                            n,
                            &crate::VIRTIO_DMA,
                        ) {
                            Ok(res) => {
                                stream.push(Record::Metric {
                                    label: "icmp.reply.seq",
                                    value: u64::from(res.seq),
                                    unit: "(from 10.0.2.2)",
                                });
                                stream.push(Record::Metric {
                                    label: "nic.rx.frames",
                                    value: res.rx_packets,
                                    unit: "frames",
                                });
                                stream.push(Record::Metric {
                                    label: "nic.tx.frames",
                                    value: res.tx_packets,
                                    unit: "frames",
                                });
                            }
                            Err(e) => {
                                let _ = writeln!(out, "net ping: {e}");
                            }
                        }
                    }
                } else if let Ok(frame_len) = newos_net::verify_smoltcp_ring3_stack(mac) {
                    stream.push(Record::Metric {
                        label: "smoltcp.tx.frame",
                        value: frame_len as u64,
                        unit: "bytes (Ring-3 IPv4)",
                    });
                }
            }
            "bench" => {
                const ROUNDTRIPS: u64 = 100;
                let t0 = newos_user_rt::read_cycles().unwrap_or(0);
                for _ in 0..ROUNDTRIPS {
                    let _ = newos_user_rt::yield_now();
                }
                let t1 = newos_user_rt::read_cycles().unwrap_or(0);
                let avg = t1.saturating_sub(t0) / (ROUNDTRIPS * 2);
                stream.push(Record::Metric {
                    label: "cr3.switch.avg",
                    value: avg,
                    unit: "cycles",
                });
            }
            other => {
                let _ = writeln!(out, "newos-sh: unknown producer `{other}` (try `help`)");
            }
        }
        stream
    }

    fn eval_transform<W: Write>(
        &mut self,
        stage: &str,
        input: RecordStream,
        out: &mut W,
    ) -> RecordStream {
        let mut toks = [""; MAX_ARGS];
        let argc = split_tokens(stage, &mut toks);
        if argc == 0 {
            return input;
        }

        match toks[0] {
            "count" => {
                let mut res = RecordStream::new();
                res.push(Record::Count(input.len()));
                res
            }
            "first" => {
                let limit = toks
                    .get(1)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1);
                let mut res = RecordStream::new();
                for rec in input.items[..input.len.min(limit)].iter().flatten() {
                    res.push(*rec);
                }
                res
            }
            "save" => {
                let Some(ref_name) = toks.get(1).copied().filter(|s| !s.is_empty()) else {
                    let _ = writeln!(out, "usage: ... | save @<name>");
                    return input;
                };
                if let Some(Record::Object(meta)) = input.first() {
                    if let Err(e) = self.store.set_ref(ref_name, meta.hash) {
                        let _ = writeln!(out, "save {ref_name}: {e:?}");
                    }
                } else {
                    let _ = writeln!(out, "save: expected an Object record from upstream");
                }
                input
            }
            "where" if argc >= 4 => {
                let field = toks[1];
                let op = toks[2];
                let rhs = toks[3];
                let mut res = RecordStream::new();
                for rec in input.items[..input.len].iter().flatten() {
                    if matches_where(*rec, field, op, rhs) {
                        res.push(*rec);
                    }
                }
                res
            }
            other => {
                let _ = writeln!(out, "newos-sh: unknown stage `{other}` (try `help`)");
                input
            }
        }
    }

    fn write_help<W: Write>(&self, out: &mut W) {
        let _ = writeln!(out, "Post-UNIX Typed Pipelines & Capability Object Store (CAOS):");
        let _ = writeln!(out, "  put <text>                  Store immutable deduplicated object -> Object");
        let _ = writeln!(out, "  get <@ref | obj:hash>       Read immutable object content");
        let _ = writeln!(out, "  objects / refs / procs      Emit typed Object / Ref / Proc records");
        let _ = writeln!(out, "  ref set|seal|rollback       Manage capability-gated Refs (atomic rollback)");
        let _ = writeln!(out, "  ping [hex] / bench / net    CR3 IPC, cycle bench, Ring-3 smoltcp & VirtIO-net");
        let _ = writeln!(out, "  | where <f> ==|!=|> <v>     Filter typed records (e.g. `objects | where size > 20`)");
        let _ = writeln!(out, "  | save @<name>              Bind upstream Object hash to a named Ref");
        let _ = writeln!(out, "  | first <n> / | count       Slice or count typed streams");
        let _ = writeln!(out, "  sys / crash / clear / exit  System info, Ring-3 fault test, power off");
    }
}

fn matches_where(rec: Record, field: &str, op: &str, rhs: &str) -> bool {
    match rec {
        Record::Proc { pid, ring, name } => match field {
            "pid" => compare_u64(pid, op, rhs),
            "ring" => compare_u64(ring, op, rhs),
            "name" => compare_str(name, op, rhs),
            _ => false,
        },
        Record::Object(meta) => match field {
            "size" => compare_u64(meta.size as u64, op, rhs),
            _ => false,
        },
        Record::Ref(meta) => match field {
            "name" => compare_str(meta.name_str(), op, rhs),
            "writable" => compare_bool(meta.writable, op, rhs),
            _ => false,
        },
        Record::Metric { value, label, .. } => match field {
            "value" => compare_u64(value, op, rhs),
            "label" => compare_str(label, op, rhs),
            _ => false,
        },
        Record::Count(c) => field == "count" && compare_u64(c as u64, op, rhs),
    }
}

fn compare_u64(lhs: u64, op: &str, rhs: &str) -> bool {
    let Some(r) = rhs.parse::<u64>().ok().or_else(|| parse_hex_u64(rhs)) else {
        return false;
    };
    match op {
        "==" => lhs == r,
        "!=" => lhs != r,
        ">" => lhs > r,
        "<" => lhs < r,
        ">=" => lhs >= r,
        "<=" => lhs <= r,
        _ => false,
    }
}

fn compare_bool(lhs: bool, op: &str, rhs: &str) -> bool {
    let r = match rhs {
        "true" => true,
        "false" => false,
        _ => return false,
    };
    match op {
        "==" => lhs == r,
        "!=" => lhs != r,
        _ => false,
    }
}

fn compare_str(lhs: &str, op: &str, rhs: &str) -> bool {
    match op {
        "==" => lhs == rhs,
        "!=" => lhs != rhs,
        _ => false,
    }
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

struct NullWriter;

impl Write for NullWriter {
    fn write_str(&mut self, _s: &str) -> core::fmt::Result {
        Ok(())
    }
}
