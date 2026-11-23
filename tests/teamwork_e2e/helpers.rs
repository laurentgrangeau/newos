use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;

use newos_abi::{CapId, ShutdownStatus, SysError};
use newos_shell_core::shell::{RecordStream, ShellHost, SysInfo};

// ============================================================================
// Sentinel types for `catch_unwind` around `Shell::run_interactive` (-> !)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitSentinel(pub ShutdownStatus);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YieldLimitExceeded(pub usize);

// ============================================================================
// MockShellHost & DefaultIpcFallbackHost
// ============================================================================

pub struct MockShellHost {
    pub output: String,
    pub write_debug_calls: usize,
    pub write_debug_bytes: usize,
    pub max_chunk_bytes: usize,
    pub sys_info_calls: usize,
    pub sys_info_val: SysInfo,
    pub ipc_call_calls: usize,
    pub ipc_send_calls: usize,
    pub ipc_recv_calls: usize,
    pub yield_calls: usize,
    pub fault_triggers: usize,
    pub net_calls: usize,
    pub read_queue: VecDeque<Result<u8, SysError>>,
    pub ipc_call_fn: Option<fn(CapId, u64) -> Result<(u64, u64), SysError>>,
    pub ipc_send_res: Result<(), SysError>,
    pub ipc_recv_res: Result<(u64, u64), SysError>,
    pub max_yields_before_panic: Option<usize>,
    pub exit_via_sentinel: bool,
    pub cycle_counter: u64,
}

impl Default for MockShellHost {
    fn default() -> Self {
        Self::new()
    }
}

impl MockShellHost {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            write_debug_calls: 0,
            write_debug_bytes: 0,
            max_chunk_bytes: 0,
            sys_info_calls: 0,
            sys_info_val: SysInfo {
                online_cpus: 4,
                proc_count: 2,
                interactive_shell: true,
            },
            ipc_call_calls: 0,
            ipc_send_calls: 0,
            ipc_recv_calls: 0,
            yield_calls: 0,
            fault_triggers: 0,
            net_calls: 0,
            read_queue: VecDeque::new(),
            ipc_call_fn: Some(|_cap, payload| Ok((0xBEEF, payload ^ 0x5A5A_5A5A))),
            ipc_send_res: Ok(()),
            ipc_recv_res: Ok((0xCAFE, 0x1234)),
            max_yields_before_panic: None,
            exit_via_sentinel: true,
            cycle_counter: 1000,
        }
    }

    pub fn clear_output(&mut self) {
        self.output.clear();
        self.write_debug_calls = 0;
        self.write_debug_bytes = 0;
        self.max_chunk_bytes = 0;
    }

    pub fn push_input_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.read_queue.push_back(Ok(b));
        }
    }
}

impl ShellHost for MockShellHost {
    fn write_debug(&mut self, s: &str) {
        self.write_debug_calls += 1;
        self.write_debug_bytes += s.len();
        if s.len() > self.max_chunk_bytes {
            self.max_chunk_bytes = s.len();
        }
        self.output.push_str(s);
    }

    fn sys_info(&mut self) -> SysInfo {
        self.sys_info_calls += 1;
        self.sys_info_val
    }

    fn read_debug_byte(&mut self) -> Result<u8, SysError> {
        self.read_queue
            .pop_front()
            .unwrap_or(Err(SysError::WouldBlock))
    }

    fn ipc_send(&mut self, _cap: CapId, _payload: u64) -> Result<(), SysError> {
        self.ipc_send_calls += 1;
        self.ipc_send_res
    }

    fn ipc_recv(&mut self, _cap: CapId) -> Result<(u64, u64), SysError> {
        self.ipc_recv_calls += 1;
        self.ipc_recv_res
    }

    fn ipc_call(&mut self, cap: CapId, payload: u64) -> Result<(u64, u64), SysError> {
        self.ipc_call_calls += 1;
        if let Some(f) = self.ipc_call_fn {
            f(cap, payload)
        } else {
            Err(SysError::Unsupported)
        }
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        self.yield_calls += 1;
        if let Some(limit) = self.max_yields_before_panic {
            if self.yield_calls > limit {
                std::panic::panic_any(YieldLimitExceeded(self.yield_calls));
            }
        }
        Ok(self.yield_calls as u64)
    }

    fn read_cycles(&mut self) -> Result<u64, SysError> {
        self.cycle_counter = self.cycle_counter.wrapping_add(137);
        Ok(self.cycle_counter)
    }

    fn trigger_user_fault(&mut self) {
        self.fault_triggers += 1;
    }

    fn exit(&mut self, code: ShutdownStatus) -> ! {
        if self.exit_via_sentinel {
            std::panic::panic_any(ExitSentinel(code));
        }
        panic!("MockShellHost::exit({code:?})");
    }

    fn handle_net(
        &mut self,
        _subcmd: &str,
        _arg: Option<&str>,
        _stream: &mut RecordStream,
        _silent: bool,
    ) {
        self.net_calls += 1;
    }
}

/// Host that intentionally relies on the default `ShellHost::ipc_call` fallback
/// (`ipc_send` -> `yield_now` -> `ipc_recv`).
pub struct DefaultIpcFallbackHost {
    pub output: String,
    pub ipc_send_calls: usize,
    pub ipc_recv_calls: usize,
    pub yield_calls: usize,
    pub last_payload: u64,
}

impl DefaultIpcFallbackHost {
    pub fn new() -> Self {
        Self {
            output: String::new(),
            ipc_send_calls: 0,
            ipc_recv_calls: 0,
            yield_calls: 0,
            last_payload: 0,
        }
    }
}

impl ShellHost for DefaultIpcFallbackHost {
    fn write_debug(&mut self, s: &str) {
        self.output.push_str(s);
    }

    fn sys_info(&mut self) -> SysInfo {
        SysInfo {
            online_cpus: 2,
            proc_count: 2,
            interactive_shell: false,
        }
    }

    fn ipc_send(&mut self, _cap: CapId, payload: u64) -> Result<(), SysError> {
        self.ipc_send_calls += 1;
        self.last_payload = payload;
        Ok(())
    }

    fn ipc_recv(&mut self, _cap: CapId) -> Result<(u64, u64), SysError> {
        self.ipc_recv_calls += 1;
        Ok((0x42, self.last_payload.wrapping_add(1)))
    }

    fn yield_now(&mut self) -> Result<u64, SysError> {
        self.yield_calls += 1;
        Ok(self.yield_calls as u64)
    }
}

// ============================================================================
// Valid / Mutatable AArch64 ELF64 Binary Builder
// ============================================================================

pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;
pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

pub struct ElfSegSpec {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_vaddr: u64,
    pub p_memsz: u64,
    pub data: Vec<u8>,
}

pub fn build_elf64(entry: u64, phentsize: u16, segs: &[ElfSegSpec]) -> Vec<u8> {
    let ehdr_size = 64usize;
    let phoff = ehdr_size as u64;
    let stride = phentsize as usize;
    let ph_table_size = stride * segs.len();
    let mut data_offset = ehdr_size + ph_table_size;

    let mut offsets = Vec::with_capacity(segs.len());
    for seg in segs {
        offsets.push(data_offset);
        data_offset += seg.data.len();
    }

    let mut buf = vec![0u8; data_offset];
    // e_ident
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    // e_type = ET_EXEC (2), e_machine = EM_AARCH64 (183), e_version = 1
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&183u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry, e_phoff
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    buf[32..40].copy_from_slice(&phoff.to_le_bytes());
    // e_ehsize = 64, e_phentsize, e_phnum
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&phentsize.to_le_bytes());
    buf[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());

    for (i, seg) in segs.iter().enumerate() {
        let off = ehdr_size + i * stride;
        let file_off = offsets[i] as u64;
        let file_sz = seg.data.len() as u64;
        buf[off..off + 4].copy_from_slice(&seg.p_type.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&seg.p_flags.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&file_off.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&seg.p_vaddr.to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&seg.p_vaddr.to_le_bytes());
        buf[off + 32..off + 40].copy_from_slice(&file_sz.to_le_bytes());
        buf[off + 40..off + 48].copy_from_slice(&seg.p_memsz.to_le_bytes());
        buf[off + 48..off + 56].copy_from_slice(&4096u64.to_le_bytes());

        if !seg.data.is_empty() {
            let start = offsets[i];
            buf[start..start + seg.data.len()].copy_from_slice(&seg.data);
        }
    }

    buf
}

// ============================================================================
// Deterministic Zero-Dependency Xorshift64 PRNG
// ============================================================================

pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() as usize) % bound
    }

    pub fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

// ============================================================================
// Pure-std Zero-False-Positive Rust Lexical Scanner for Static Safety Audits
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokKind {
    Ident,
    Punct,
}

#[derive(Debug, Clone)]
pub struct Tok {
    pub kind: TokKind,
    pub text: String,
    pub line: usize,
}

pub struct ScannedFile {
    pub lines: Vec<String>,
    pub tokens: Vec<Tok>,
}

pub fn find_repo_root() -> PathBuf {
    let mut cur = std::env::current_dir().expect("current_dir");
    for _ in 0..8 {
        if cur.join("crates/abi/src/lib.rs").is_file() {
            return cur;
        }
        if !cur.pop() {
            break;
        }
    }
    panic!("could not locate newos repo root from current_dir");
}

pub fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs_files_rec(dir, &mut out);
    out.sort();
    out
}

fn collect_rs_files_rec(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files_rec(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Scans a Rust source file into lexical tokens while skipping line comments,
/// nested block comments, normal/byte/c strings, raw strings, and char/byte literals
/// (preserving lifetimes like `'a` and `'static`).
pub fn scan_rust_source(path: &Path) -> ScannedFile {
    let src = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let lines: Vec<String> = src.lines().map(String::from).collect();
    let bytes = src.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut tokens = Vec::new();

    while i < len {
        let b = bytes[i];

        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Line comment: //...
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            i += 2;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Nested block comment: /* ... */
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < len && depth > 0 {
                if bytes[i] == b'\n' {
                    line += 1;
                    i += 1;
                } else if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }

        // Raw string: r"...", r#"..."#, br#"..."#, cr#"..."#
        if let Some(after_raw) = try_skip_raw_string(bytes, i, &mut line) {
            i = after_raw;
            continue;
        }

        // Byte/C string literal: b"...", c"..."
        if (b == b'b' || b == b'c') && i + 1 < len && bytes[i + 1] == b'"' {
            i = skip_quoted_string(bytes, i + 1, &mut line);
            continue;
        }

        // Byte char literal: b'...'
        if b == b'b' && i + 1 < len && bytes[i + 1] == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i + 1) {
                i = next_i;
                continue;
            }
        }

        // Normal string literal: "..."
        if b == b'"' {
            i = skip_quoted_string(bytes, i, &mut line);
            continue;
        }

        // Char literal vs lifetime
        if b == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i) {
                i = next_i;
                continue;
            }
            // Lifetime apostrophe: emit as punct so following ident is preserved
            tokens.push(Tok {
                kind: TokKind::Punct,
                text: "'".to_string(),
                line,
            });
            i += 1;
            continue;
        }

        // Identifier / keyword
        if is_ident_start(b) {
            let start = i;
            i += 1;
            while i < len && is_ident_continue(bytes[i]) {
                i += 1;
            }
            tokens.push(Tok {
                kind: TokKind::Ident,
                text: src[start..i].to_string(),
                line,
            });
            continue;
        }

        // Number literal (skip cleanly)
        if b.is_ascii_digit() {
            i += 1;
            while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            continue;
        }

        // Single punctuation char (ASCII) or UTF-8 char
        let ch = src[i..].chars().next().unwrap();
        tokens.push(Tok {
            kind: TokKind::Punct,
            text: ch.to_string(),
            line,
        });
        i += ch.len_utf8();
    }

    ScannedFile { lines, tokens }
}

fn skip_quoted_string(bytes: &[u8], quote_pos: usize, line: &mut usize) -> usize {
    let len = bytes.len();
    let mut i = quote_pos + 1;
    while i < len {
        match bytes[i] {
            b'\\' => {
                if i + 1 < len && bytes[i + 1] == b'\n' {
                    *line += 1;
                }
                i = (i + 2).min(len);
            }
            b'"' => return i + 1,
            b'\n' => {
                *line += 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    len
}

fn try_skip_raw_string(bytes: &[u8], pos: usize, line: &mut usize) -> Option<usize> {
    let len = bytes.len();
    let mut i = pos;
    if i < len && (bytes[i] == b'b' || bytes[i] == b'c') {
        i += 1;
    }
    if i >= len || bytes[i] != b'r' {
        return None;
    }
    i += 1;
    let mut hashes = 0usize;
    while i < len && bytes[i] == b'#' {
        hashes += 1;
        i += 1;
    }
    if i >= len || bytes[i] != b'"' {
        return None;
    }
    i += 1;
    while i < len {
        if bytes[i] == b'\n' {
            *line += 1;
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            let mut matched = 0usize;
            while matched < hashes && i + 1 + matched < len && bytes[i + 1 + matched] == b'#' {
                matched += 1;
            }
            if matched == hashes {
                return Some(i + 1 + hashes);
            }
        }
        i += 1;
    }
    Some(len)
}

fn try_skip_char_literal(bytes: &[u8], quote_pos: usize) -> Option<usize> {
    let len = bytes.len();
    if quote_pos + 2 >= len {
        return None;
    }
    if bytes[quote_pos + 1] == b'\\' {
        if bytes[quote_pos + 2] == b'\n' {
            return None;
        }
        // Skip the escaped byte at `quote_pos + 2` (so `'\''` and `b'\''` do not
        // stop on the escaped single quote) and scan for the closing `'`.
        let mut i = quote_pos + 3;
        while i < len {
            if bytes[i] == b'\n' {
                return None;
            }
            if bytes[i] == b'\'' {
                return Some(i + 1);
            }
            i += 1;
        }
        return None;
    }
    // Decode one UTF-8 scalar after `'` and check if immediately followed by `'`
    let rest = std::str::from_utf8(&bytes[quote_pos + 1..]).ok()?;
    let ch = rest.chars().next()?;
    if ch == '\n' || ch == '\'' {
        return None;
    }
    let close_idx = quote_pos + 1 + ch.len_utf8();
    if close_idx < len && bytes[close_idx] == b'\'' {
        Some(close_idx + 1)
    } else {
        None
    }
}

/// Removes all items gated by `#[cfg(test)]` using brace/bracket/paren-depth matching.
pub fn strip_cfg_test(tokens: &[Tok]) -> Vec<Tok> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut i = 0usize;
    let n = tokens.len();

    while i < n {
        if i + 6 < n
            && tokens[i].text == "#"
            && tokens[i + 1].text == "["
            && tokens[i + 2].kind == TokKind::Ident
            && tokens[i + 2].text == "cfg"
            && tokens[i + 3].text == "("
            && tokens[i + 4].kind == TokKind::Ident
            && tokens[i + 4].text == "test"
            && tokens[i + 5].text == ")"
            && tokens[i + 6].text == "]"
        {
            i += 7;
            // Skip any chained attributes before the gated item
            while i + 1 < n && tokens[i].text == "#" && tokens[i + 1].text == "[" {
                i += 2;
                let mut bracket_depth = 1usize;
                while i < n && bracket_depth > 0 {
                    if tokens[i].text == "[" {
                        bracket_depth += 1;
                    } else if tokens[i].text == "]" {
                        bracket_depth -= 1;
                    }
                    i += 1;
                }
            }
            // Skip the item itself: either `{ ... }` or up to top-level `;`
            let mut brace_depth = 0usize;
            let mut bracket_depth = 0usize;
            let mut paren_depth = 0usize;
            let mut saw_brace = false;
            while i < n {
                let t = tokens[i].text.as_str();
                if t == "{" {
                    if bracket_depth == 0 && paren_depth == 0 {
                        saw_brace = true;
                    }
                    brace_depth += 1;
                } else if t == "}" {
                    brace_depth = brace_depth.saturating_sub(1);
                    if saw_brace && brace_depth == 0 && bracket_depth == 0 && paren_depth == 0 {
                        i += 1;
                        break;
                    }
                } else if t == "[" {
                    bracket_depth += 1;
                } else if t == "]" {
                    bracket_depth = bracket_depth.saturating_sub(1);
                } else if t == "(" {
                    paren_depth += 1;
                } else if t == ")" {
                    paren_depth = paren_depth.saturating_sub(1);
                } else if t == ";" && !saw_brace && bracket_depth == 0 && paren_depth == 0 {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        out.push(tokens[i].clone());
        i += 1;
    }

    out
}

/// Returns 1-based line numbers of all `unsafe` items/blocks/attributes in `tokens`.
pub fn find_unsafe_sites(tokens: &[Tok]) -> Vec<usize> {
    let mut sites = Vec::new();
    for i in 0..tokens.len() {
        if tokens[i].kind != TokKind::Ident || tokens[i].text != "unsafe" {
            continue;
        }
        let is_kw_unsafe = tokens.get(i + 1).is_some_and(|next| {
            matches!(next.text.as_str(), "{" | "fn" | "extern" | "impl" | "trait")
        });
        let is_attr_unsafe = i >= 2
            && tokens[i - 2].text == "#"
            && tokens[i - 1].text == "["
            && tokens.get(i + 1).is_some_and(|next| next.text == "(");

        if is_kw_unsafe || is_attr_unsafe {
            sites.push(tokens[i].line);
        }
    }
    sites
}

/// Checks whether a single source line contains `SAFETY:` inside an actual
/// `//` or `/* ... */` comment (skipping string and char literals so
/// `"http://SAFETY:..."` cannot spoof an inline safety comment).
fn inline_comment_has_safety(line: &str) -> bool {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut dummy_line = 1usize;

    while i < len {
        let b = bytes[i];
        // Line comment
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            return line[i..].contains("SAFETY:");
        }
        // Block comment (supports nesting)
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            let start = i;
            let mut depth = 1usize;
            i += 2;
            while i < len && depth > 0 {
                if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if line[start..i].contains("SAFETY:") {
                return true;
            }
            continue;
        }
        // Raw string literal
        if let Some(after_raw) = try_skip_raw_string(bytes, i, &mut dummy_line) {
            i = after_raw;
            continue;
        }
        // Byte/C string literal
        if (b == b'b' || b == b'c') && i + 1 < len && bytes[i + 1] == b'"' {
            i = skip_quoted_string(bytes, i + 1, &mut dummy_line);
            continue;
        }
        // Byte char literal
        if b == b'b' && i + 1 < len && bytes[i + 1] == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i + 1) {
                i = next_i;
                continue;
            }
        }
        // Normal string literal
        if b == b'"' {
            i = skip_quoted_string(bytes, i, &mut dummy_line);
            continue;
        }
        // Char literal
        if b == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i) {
                i = next_i;
                continue;
            }
        }
        i += 1;
    }
    false
}

/// Counts `[` and `]` brackets on a single line outside comments and string/char literals.
fn count_brackets_in_line(line: &str) -> (usize, usize) {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut open = 0usize;
    let mut close = 0usize;
    let mut dummy_line = 1usize;

    while i < len {
        let b = bytes[i];
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < len && depth > 0 {
                if bytes[i] == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if let Some(after_raw) = try_skip_raw_string(bytes, i, &mut dummy_line) {
            i = after_raw;
            continue;
        }
        if (b == b'b' || b == b'c') && i + 1 < len && bytes[i + 1] == b'"' {
            i = skip_quoted_string(bytes, i + 1, &mut dummy_line);
            continue;
        }
        if b == b'b' && i + 1 < len && bytes[i + 1] == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i + 1) {
                i = next_i;
                continue;
            }
        }
        if b == b'"' {
            i = skip_quoted_string(bytes, i, &mut dummy_line);
            continue;
        }
        if b == b'\'' {
            if let Some(next_i) = try_skip_char_literal(bytes, i) {
                i = next_i;
                continue;
            }
        }
        if b == b'[' {
            open += 1;
        } else if b == b']' {
            close += 1;
        }
        i += 1;
    }
    (open, close)
}

/// Checks whether 1-based `line_num` has an inline `SAFETY:` comment or a
/// contiguous preceding comment/attribute prelude containing `SAFETY:`.
pub fn has_safety_comment(lines: &[String], line_num: usize) -> bool {
    if line_num == 0 || line_num > lines.len() {
        return false;
    }
    if inline_comment_has_safety(&lines[line_num - 1]) {
        return true;
    }

    let mut idx = line_num - 1;
    let mut in_block_comment = false;
    let mut attr_bracket_depth = 0usize;
    let mut used_prefix_line = false;

    while idx > 0 {
        idx -= 1;
        let trimmed = lines[idx].trim();

        if in_block_comment {
            if trimmed.contains("SAFETY:") {
                return true;
            }
            if trimmed.contains("/*") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.is_empty() {
            break;
        }

        if attr_bracket_depth > 0 {
            let (open, close) = count_brackets_in_line(trimmed);
            attr_bracket_depth = (attr_bracket_depth + close).saturating_sub(open);
            continue;
        }

        // Multi-line block comment ending on this line (e.g. `*/` without matching `/*` before it)
        if trimmed.ends_with("*/") {
            let has_open_before_close = trimmed
                .rfind("/*")
                .zip(trimmed.rfind("*/"))
                .is_some_and(|(o, c)| o < c);
            if has_open_before_close {
                if inline_comment_has_safety(trimmed) {
                    return true;
                }
                if trimmed.starts_with("/*") {
                    continue;
                }
                break;
            }
            if trimmed.contains("SAFETY:") {
                return true;
            }
            in_block_comment = true;
            continue;
        }

        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            if trimmed.contains("SAFETY:") {
                return true;
            }
            continue;
        }

        if trimmed.starts_with("#[") {
            continue;
        }

        // Multi-line attribute closing line (e.g. `))]` with unbalanced `]`)
        if trimmed.ends_with(']') {
            let (open, close) = count_brackets_in_line(trimmed);
            if close > open {
                attr_bracket_depth = close - open;
                continue;
            }
        }

        // Allow a single immediately preceding expression/binding prefix line
        // (e.g. `let entry =` or `return` ending without `;`, `{`, or `}`).
        if !used_prefix_line
            && !trimmed.ends_with(';')
            && !trimmed.ends_with('{')
            && !trimmed.ends_with('}')
        {
            if inline_comment_has_safety(trimmed) {
                return true;
            }
            used_prefix_line = true;
            continue;
        }

        break;
    }
    false
}

/// Checks whether `#![forbid(unsafe_code)]` appears in `tokens`.
pub fn has_forbid_unsafe_code(tokens: &[Tok]) -> bool {
    for w in tokens.windows(7) {
        if w[0].text == "#"
            && w[1].text == "!"
            && w[2].text == "["
            && w[3].kind == TokKind::Ident
            && w[3].text == "forbid"
            && w[4].text == "("
            && w[5].kind == TokKind::Ident
            && w[5].text == "unsafe_code"
            && w[6].text == ")"
        {
            return true;
        }
    }
    false
}

// ============================================================================
// OnceLock-Cached Offline `newos_bench` Builder & Runner
// ============================================================================

pub struct BenchRun {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

static BENCH_BIN: OnceLock<PathBuf> = OnceLock::new();

fn build_newos_bench_once() -> &'static PathBuf {
    BENCH_BIN.get_or_init(|| {
        let root = find_repo_root();
        let out_dir =
            std::env::temp_dir().join(format!("newos_e2e_bench_bin_{}", std::process::id()));
        fs::create_dir_all(&out_dir).expect("create temp dir for newos_bench");

        let abi_rlib = out_dir.join("libnewos_abi.rlib");
        let kc_rlib = out_dir.join("libnewos_kernel_core.rlib");
        let sc_rlib = out_dir.join("libnewos_shell_core.rlib");
        let bench_bin = out_dir.join("newos_bench");

        let run_rustc = |args: &[String]| {
            let out = Command::new("rustc")
                .current_dir(&root)
                .args(args)
                .output()
                .expect("spawn rustc");
            assert!(
                out.status.success(),
                "rustc failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
                args,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        };

        run_rustc(&[
            "--edition".into(),
            "2024".into(),
            "-C".into(),
            "opt-level=3".into(),
            "--crate-name".into(),
            "newos_abi".into(),
            "--crate-type".into(),
            "lib".into(),
            "crates/abi/src/lib.rs".into(),
            "-o".into(),
            abi_rlib.display().to_string(),
        ]);

        run_rustc(&[
            "--edition".into(),
            "2024".into(),
            "-C".into(),
            "opt-level=3".into(),
            "--crate-name".into(),
            "newos_kernel_core".into(),
            "--crate-type".into(),
            "lib".into(),
            "crates/kernel-core/src/lib.rs".into(),
            "--extern".into(),
            format!("newos_abi={}", abi_rlib.display()),
            "-o".into(),
            kc_rlib.display().to_string(),
        ]);

        run_rustc(&[
            "--edition".into(),
            "2024".into(),
            "-C".into(),
            "opt-level=3".into(),
            "--crate-name".into(),
            "newos_shell_core".into(),
            "--crate-type".into(),
            "lib".into(),
            "crates/shell-core/src/lib.rs".into(),
            "--extern".into(),
            format!("newos_abi={}", abi_rlib.display()),
            "-o".into(),
            sc_rlib.display().to_string(),
        ]);

        run_rustc(&[
            "--edition".into(),
            "2024".into(),
            "-C".into(),
            "opt-level=3".into(),
            "--crate-name".into(),
            "newos_bench".into(),
            "crates/bench/src/main.rs".into(),
            "--extern".into(),
            format!("newos_abi={}", abi_rlib.display()),
            "--extern".into(),
            format!("newos_kernel_core={}", kc_rlib.display()),
            "--extern".into(),
            format!("newos_shell_core={}", sc_rlib.display()),
            "-o".into(),
            bench_bin.display().to_string(),
        ]);

        bench_bin
    })
}

pub fn run_newos_bench(args: &[&str]) -> BenchRun {
    let bin = build_newos_bench_once();
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("execute newos_bench");
    BenchRun {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

pub fn parse_metric_lines(stdout: &str) -> Vec<(String, String, String)> {
    let mut metrics = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("METRIC") {
            if let (Some(name), Some(val), Some(unit)) = (parts.next(), parts.next(), parts.next())
            {
                metrics.push((name.to_string(), val.to_string(), unit.to_string()));
            }
        }
    }
    metrics
}
