//! Parser and validator for `newos_bench` `METRIC` output and `BENCHMARK_RESULTS.md`.

use std::collections::BTreeMap;

/// All 7 kernel speed metric keys (unit: `ns/op`).
pub const KERNEL_SPEED_KEYS: &[&str] = &[
    "kernel.cnode.lookup",
    "kernel.cnode.mint_revoke",
    "kernel.ipc.send_recv",
    "kernel.ipc.notify_signal_poll",
    "kernel.sched.schedule_next",
    "kernel.memory.retype_frame",
    "kernel.ring.spsc_transfer",
];

/// All 3 shell speed metric keys (unit: `ns/op`).
pub const SHELL_SPEED_KEYS: &[&str] = &[
    "shell.caos.put_get_ref",
    "shell.pipeline.eval",
    "shell.session.full",
];

/// All 6 IPC consumption metric keys (exact integer syscall/IPC counts).
pub const IPC_CONSUMPTION_KEYS: &[&str] = &[
    "ipc.shell_session.debug_write_syscalls",
    "ipc.shell_session.sys_info_syscalls",
    "ipc.ping_roundtrip.syscalls_per_op",
    "ipc.ring_burst_32w.notify_syscalls",
    "ipc.idle_poll_100.wasted_worker_ipc",
    "ipc.total_consumption",
];

/// Returns all 16 canonical benchmark metric keys in deterministic order.
pub fn all_metric_keys() -> Vec<&'static str> {
    let mut keys = Vec::with_capacity(16);
    keys.extend_from_slice(KERNEL_SPEED_KEYS);
    keys.extend_from_slice(SHELL_SPEED_KEYS);
    keys.extend_from_slice(IPC_CONSUMPTION_KEYS);
    keys
}

/// One parsed metric entry.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricEntry {
    pub name: String,
    pub value: f64,
    pub unit: String,
}

/// Structured parse/validation errors for benchmark outputs and markdown reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    EmptyInput,
    MalformedLine { line_no: usize, detail: String },
    DuplicateMetric(String),
    InvalidValue { name: String, raw: String },
    InvalidUnit { name: String, unit: String },
    MissingMetrics(Vec<String>),
    MissingSection(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "benchmark input is empty"),
            Self::MalformedLine { line_no, detail } => {
                write!(f, "malformed line {line_no}: {detail}")
            }
            Self::DuplicateMetric(k) => write!(f, "duplicate metric key: {k}"),
            Self::InvalidValue { name, raw } => {
                write!(f, "invalid value for `{name}`: `{raw}`")
            }
            Self::InvalidUnit { name, unit } => {
                write!(f, "invalid unit for `{name}`: `{unit}`")
            }
            Self::MissingMetrics(keys) => {
                write!(f, "missing required metric keys: {}", keys.join(", "))
            }
            Self::MissingSection(sec) => write!(f, "missing required section: {sec}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Structured verification errors for benchmark speed and IPC acceptance invariants.
#[derive(Debug, Clone, PartialEq)]
pub enum BenchVerifyError {
    MissingKey {
        dataset: &'static str,
        key: &'static str,
    },
    InvalidLatency {
        group: &'static str,
        key: &'static str,
        baseline: f64,
        post_opt: f64,
    },
    NotFaster {
        group: &'static str,
        base_sum: f64,
        post_sum: f64,
        geomean_ratio: f64,
        improved: usize,
        total: usize,
    },
    InvalidIpcCount {
        key: &'static str,
        baseline: f64,
        post_opt: f64,
    },
    IpcRegression {
        key: &'static str,
        baseline: f64,
        post_opt: f64,
    },
    InconsistentIpcTotal {
        dataset: &'static str,
        reported_total: f64,
        component_sum: f64,
    },
    IpcNotReduced {
        baseline: f64,
        post_opt: f64,
    },
}

impl std::fmt::Display for BenchVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey { dataset, key } => write!(f, "missing {dataset} key {key}"),
            Self::InvalidLatency {
                group,
                key,
                baseline,
                post_opt,
            } => write!(
                f,
                "invalid or non-positive {group} latency for {key}: base={baseline}, post={post_opt}"
            ),
            Self::NotFaster {
                group,
                base_sum,
                post_sum,
                geomean_ratio,
                improved,
                total,
            } => write!(
                f,
                "{group} not faster: base_sum={base_sum:.2}, post_sum={post_sum:.2}, geomean_ratio={geomean_ratio:.4}, improved={improved}/{total}"
            ),
            Self::InvalidIpcCount {
                key,
                baseline,
                post_opt,
            } => write!(
                f,
                "invalid IPC count for `{key}`: baseline={baseline}, post_opt={post_opt}"
            ),
            Self::IpcRegression {
                key,
                baseline,
                post_opt,
            } => write!(
                f,
                "IPC regression on `{key}`: baseline={baseline}, post_opt={post_opt}"
            ),
            Self::InconsistentIpcTotal {
                dataset,
                reported_total,
                component_sum,
            } => write!(
                f,
                "{dataset} ipc.total_consumption ({reported_total}) != sum of 5 component IPC metrics ({component_sum})"
            ),
            Self::IpcNotReduced { baseline, post_opt } => write!(
                f,
                "ipc.total_consumption did not decrease: baseline={baseline}, post_opt={post_opt}"
            ),
        }
    }
}

impl std::error::Error for BenchVerifyError {}

/// Returns true if `name` is a latency/speed metric (`kernel.*` or `shell.*`).
pub fn is_speed_metric(name: &str) -> bool {
    KERNEL_SPEED_KEYS.contains(&name) || SHELL_SPEED_KEYS.contains(&name)
}

/// Returns true if `name` is an IPC consumption count metric (`ipc.*`).
pub fn is_ipc_metric(name: &str) -> bool {
    IPC_CONSUMPTION_KEYS.contains(&name)
}

fn validate_value_and_unit(name: &str, value: f64, unit: &str) -> Result<(), ParseError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ParseError::InvalidValue {
            name: name.to_string(),
            raw: value.to_string(),
        });
    }
    if is_speed_metric(name) {
        if value <= 0.0 {
            return Err(ParseError::InvalidValue {
                name: name.to_string(),
                raw: value.to_string(),
            });
        }
        if unit != "ns/op" && unit != "ns" {
            return Err(ParseError::InvalidUnit {
                name: name.to_string(),
                unit: unit.to_string(),
            });
        }
    } else if is_ipc_metric(name) {
        if (value.fract()).abs() > 1e-9 {
            return Err(ParseError::InvalidValue {
                name: name.to_string(),
                raw: value.to_string(),
            });
        }
        if unit.is_empty() || unit == "ns/op" {
            return Err(ParseError::InvalidUnit {
                name: name.to_string(),
                unit: unit.to_string(),
            });
        }
    }
    Ok(())
}

/// Parses `METRIC <name> <value> <unit>` lines from `newos_bench` output.
/// Non-`METRIC` lines (such as markdown banners or headings) are ignored.
pub fn parse_metric_lines(stdout: &str) -> Result<BTreeMap<String, MetricEntry>, ParseError> {
    if stdout.trim().is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let mut out = BTreeMap::new();
    for (idx, raw_line) in stdout.lines().enumerate() {
        let line = raw_line.trim();
        if !line.starts_with("METRIC") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 || parts[0] != "METRIC" {
            return Err(ParseError::MalformedLine {
                line_no: idx + 1,
                detail: format!("expected `METRIC <name> <value> <unit>`, got `{line}`"),
            });
        }
        let name = parts[1].trim_matches('`');
        let raw_val = parts[2];
        let unit = parts[3];

        let value: f64 = raw_val.parse().map_err(|_| ParseError::InvalidValue {
            name: name.to_string(),
            raw: raw_val.to_string(),
        })?;
        validate_value_and_unit(name, value, unit)?;

        if out.contains_key(name) {
            return Err(ParseError::DuplicateMetric(name.to_string()));
        }
        out.insert(
            name.to_string(),
            MetricEntry {
                name: name.to_string(),
                value,
                unit: unit.to_string(),
            },
        );
    }

    if out.is_empty() {
        return Err(ParseError::MalformedLine {
            line_no: 1,
            detail: "no METRIC lines found".to_string(),
        });
    }
    Ok(out)
}

/// Validates that all 16 canonical metric keys are present in `metrics`.
pub fn validate_complete_metrics(
    metrics: &BTreeMap<String, MetricEntry>,
) -> Result<(), ParseError> {
    let missing: Vec<String> = all_metric_keys()
        .into_iter()
        .filter(|k| !metrics.contains_key(*k))
        .map(str::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(ParseError::MissingMetrics(missing));
    }
    Ok(())
}

/// Parsed baseline and optional post-optimization metric maps from `BENCHMARK_RESULTS.md`.
#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkReport {
    pub baseline: BTreeMap<String, f64>,
    pub post_opt: Option<BTreeMap<String, f64>>,
}

fn parse_cell_number(metric_name: &str, raw: &str) -> Result<Option<f64>, ParseError> {
    let Some(first_tok) = raw.split_whitespace().next() else {
        return Ok(None);
    };
    let stripped = first_tok.trim_matches(|c| matches!(c, '`' | '*' | '_'));
    let lower = stripped.to_ascii_lowercase();
    if lower.is_empty() || matches!(lower.as_str(), "tbd" | "n/a" | "na" | "-" | "—" | "--") {
        return Ok(None);
    }

    let cleaned = stripped.replace(',', "");
    let v: f64 = cleaned.parse().map_err(|_| ParseError::InvalidValue {
        name: metric_name.to_string(),
        raw: raw.to_string(),
    })?;
    if !v.is_finite() || v < 0.0 {
        return Err(ParseError::InvalidValue {
            name: metric_name.to_string(),
            raw: raw.to_string(),
        });
    }
    if is_speed_metric(metric_name) && v <= 0.0 {
        return Err(ParseError::InvalidValue {
            name: metric_name.to_string(),
            raw: raw.to_string(),
        });
    }
    if is_ipc_metric(metric_name) && v.fract().abs() > 1e-9 {
        return Err(ParseError::InvalidValue {
            name: metric_name.to_string(),
            raw: raw.to_string(),
        });
    }
    Ok(Some(v))
}

fn is_separator_row(cells: &[&str]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|c| {
            let t = c.trim();
            !t.is_empty() && t.chars().all(|ch| ch == '-' || ch == ':' || ch == ' ')
        })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MdSection {
    None,
    Baseline,
    PostOpt,
    Comparison,
}

#[derive(Default)]
struct MdTableCols {
    metric: Option<usize>,
    baseline: Option<usize>,
    post: Option<usize>,
    value: Option<usize>,
}

fn classify_heading(line: &str, current: MdSection) -> MdSection {
    let lower = line.to_ascii_lowercase();
    let has_post = lower.contains("post-opt")
        || lower.contains("post opt")
        || lower.contains("optimized")
        || lower.contains("after");
    let has_baseline = lower.contains("baseline") || lower.contains("before");
    if has_post && !has_baseline {
        MdSection::PostOpt
    } else if lower.contains("comparison") || (has_baseline && has_post) {
        MdSection::Comparison
    } else if has_baseline {
        MdSection::Baseline
    } else {
        current
    }
}

fn insert_section_metric(
    section: MdSection,
    known_key_count: usize,
    baseline: &mut BTreeMap<String, f64>,
    post_opt: &mut BTreeMap<String, f64>,
    name: &str,
    val: f64,
) {
    match section {
        MdSection::PostOpt => {
            post_opt.insert(name.to_string(), val);
        }
        MdSection::Comparison if baseline.len() == known_key_count => {
            post_opt.insert(name.to_string(), val);
        }
        MdSection::Baseline | MdSection::Comparison | MdSection::None => {
            baseline.entry(name.to_string()).or_insert(val);
        }
    }
}

fn parse_md_metric_line(
    line: &str,
    line_no: usize,
    section: MdSection,
    known_key_count: usize,
    baseline: &mut BTreeMap<String, f64>,
    post_opt: &mut BTreeMap<String, f64>,
) -> Result<(), ParseError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(ParseError::MalformedLine {
            line_no,
            detail: format!("malformed METRIC line in markdown: `{line}`"),
        });
    }
    let name = parts[1].trim_matches(|c| matches!(c, '`' | '*' | '_'));
    let val: f64 = parts[2].parse().map_err(|_| ParseError::InvalidValue {
        name: name.to_string(),
        raw: parts[2].to_string(),
    })?;
    validate_value_and_unit(name, val, parts[3])?;
    insert_section_metric(section, known_key_count, baseline, post_opt, name, val);
    Ok(())
}

fn parse_md_table_row(
    line: &str,
    section: MdSection,
    known_keys: &[&str],
    cols: &mut MdTableCols,
    baseline: &mut BTreeMap<String, f64>,
    post_opt: &mut BTreeMap<String, f64>,
) -> Result<(), ParseError> {
    let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
    if is_separator_row(&cells) {
        return Ok(());
    }
    // Detect table header row with `Metric` at any column index.
    let lower_cells: Vec<String> = cells.iter().map(|c| c.to_ascii_lowercase()).collect();
    if let Some(m_col) = lower_cells.iter().position(|c| c.contains("metric")) {
        cols.metric = Some(m_col);
        cols.baseline = lower_cells
            .iter()
            .position(|c| c.contains("baseline") || c.contains("before"));
        cols.post = lower_cells
            .iter()
            .position(|c| c.contains("post") || c.contains("optimized") || c.contains("after"));
        cols.value = lower_cells
            .iter()
            .position(|c| c == "value" || c.contains("value"));
        return Ok(());
    }

    let m_idx = cols.metric.unwrap_or(0);
    let Some(raw_metric) = cells.get(m_idx) else {
        return Ok(());
    };
    let metric_name = raw_metric
        .trim()
        .trim_matches(|c| matches!(c, '`' | '*' | '_'))
        .trim();
    if !known_keys.contains(&metric_name) {
        return Ok(());
    }

    // Case A: unified table with baseline and/or post-opt columns.
    if let Some(b_idx) = cols.baseline {
        if let Some(raw_b) = cells.get(b_idx)
            && let Some(v) = parse_cell_number(metric_name, raw_b)?
        {
            baseline.entry(metric_name.to_string()).or_insert(v);
        }
        if let Some(p_idx) = cols.post
            && let Some(raw_p) = cells.get(p_idx)
            && let Some(v) = parse_cell_number(metric_name, raw_p)?
        {
            post_opt.insert(metric_name.to_string(), v);
        }
        return Ok(());
    }

    // Case B: single-value section table (e.g. | Category | Metric | Value | Unit | or | Metric | Value | Unit |).
    let v_idx = cols.value.unwrap_or(m_idx + 1);
    if let Some(raw_v) = cells.get(v_idx)
        && let Some(v) = parse_cell_number(metric_name, raw_v)?
    {
        insert_section_metric(
            section,
            known_keys.len(),
            baseline,
            post_opt,
            metric_name,
            v,
        );
    }
    Ok(())
}

fn check_missing_keys(known_keys: &[&str], map: &BTreeMap<String, f64>) -> Result<(), ParseError> {
    let missing: Vec<String> = known_keys
        .iter()
        .filter(|k| !map.contains_key(**k))
        .map(|k| (*k).to_string())
        .collect();
    if !missing.is_empty() {
        return Err(ParseError::MissingMetrics(missing));
    }
    Ok(())
}

/// Parses `BENCHMARK_RESULTS.md`, supporting either:
/// 1. A unified comparison markdown table with `Metric`, `Baseline`, and `Post-Opt` columns
///    (with `Metric` in any column, e.g. `| Category | Metric | M1 Baseline | M4 Post-Opt | ... |`), OR
/// 2. Separate `Baseline` and `Post-Optimization` sections containing markdown tables or `METRIC` lines.
pub fn parse_benchmark_results_md(md: &str) -> Result<BenchmarkReport, ParseError> {
    if md.trim().is_empty() {
        return Err(ParseError::EmptyInput);
    }

    let known_keys = all_metric_keys();
    let mut baseline = BTreeMap::new();
    let mut post_opt = BTreeMap::new();
    let mut section = MdSection::None;
    let mut cols = MdTableCols::default();

    for (idx, raw_line) in md.lines().enumerate() {
        let line = raw_line.trim();
        if line.starts_with('#') {
            cols = MdTableCols::default();
            section = classify_heading(line, section);
        } else if line.starts_with("METRIC ") {
            parse_md_metric_line(
                line,
                idx + 1,
                section,
                known_keys.len(),
                &mut baseline,
                &mut post_opt,
            )?;
        } else if line.starts_with('|') && line.ends_with('|') {
            parse_md_table_row(
                line,
                section,
                &known_keys,
                &mut cols,
                &mut baseline,
                &mut post_opt,
            )?;
        }
    }

    if baseline.is_empty() {
        return Err(ParseError::MissingSection("Baseline".to_string()));
    }
    check_missing_keys(&known_keys, &baseline)?;

    let post_opt_map = if post_opt.is_empty() {
        None
    } else {
        check_missing_keys(&known_keys, &post_opt)?;
        Some(post_opt)
    };

    Ok(BenchmarkReport {
        baseline,
        post_opt: post_opt_map,
    })
}

fn verify_speed_group(
    group: &'static str,
    keys: &[&'static str],
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), BenchVerifyError> {
    let mut base_sum = 0.0;
    let mut post_sum = 0.0;
    let mut log_ratio_sum = 0.0;
    let mut improved = 0usize;

    for &key in keys {
        let b = *baseline.get(key).ok_or(BenchVerifyError::MissingKey {
            dataset: "baseline",
            key,
        })?;
        let p = *post_opt.get(key).ok_or(BenchVerifyError::MissingKey {
            dataset: "post-opt",
            key,
        })?;
        if !b.is_finite() || !p.is_finite() || b <= 0.0 || p <= 0.0 {
            return Err(BenchVerifyError::InvalidLatency {
                group,
                key,
                baseline: b,
                post_opt: p,
            });
        }
        base_sum += b;
        post_sum += p;
        log_ratio_sum += (p / b).ln();
        if p < b {
            improved += 1;
        }
    }

    let key_count = f64::from(u32::try_from(keys.len()).expect("key count fits u32"));
    let geomean_ratio = (log_ratio_sum / key_count).exp();
    if !geomean_ratio.is_finite() || post_sum >= base_sum || geomean_ratio >= 1.0 || improved == 0 {
        return Err(BenchVerifyError::NotFaster {
            group,
            base_sum,
            post_sum,
            geomean_ratio,
            improved,
            total: keys.len(),
        });
    }
    Ok(())
}

/// Verifies post-optimization kernel speed is strictly faster than baseline:
/// - Total kernel latency sum is strictly lower (`post_sum < base_sum`)
/// - Geometric mean ratio `(post / base)` is strictly `< 1.0`
pub fn verify_kernel_faster(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), BenchVerifyError> {
    verify_speed_group("kernel", KERNEL_SPEED_KEYS, baseline, post_opt)
}

/// Verifies post-optimization shell speed is strictly faster than baseline.
pub fn verify_shell_faster(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), BenchVerifyError> {
    verify_speed_group("shell", SHELL_SPEED_KEYS, baseline, post_opt)
}

/// Verifies post-optimization IPC consumption is strictly reduced with zero IPC regressions,
/// strict finiteness/non-negativity/integrality, and exact `ipc.total_consumption == sum(components)`.
pub fn verify_ipc_reduced(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), BenchVerifyError> {
    for &key in IPC_CONSUMPTION_KEYS {
        let b = *baseline.get(key).ok_or(BenchVerifyError::MissingKey {
            dataset: "baseline IPC",
            key,
        })?;
        let p = *post_opt.get(key).ok_or(BenchVerifyError::MissingKey {
            dataset: "post-opt IPC",
            key,
        })?;
        if !b.is_finite()
            || !p.is_finite()
            || b < 0.0
            || p < 0.0
            || b.fract().abs() > 1e-9
            || p.fract().abs() > 1e-9
        {
            return Err(BenchVerifyError::InvalidIpcCount {
                key,
                baseline: b,
                post_opt: p,
            });
        }
        if p > b {
            return Err(BenchVerifyError::IpcRegression {
                key,
                baseline: b,
                post_opt: p,
            });
        }
    }

    let component_keys = &IPC_CONSUMPTION_KEYS[..5];
    let base_component_sum: f64 = component_keys.iter().map(|k| baseline[*k]).sum();
    let post_component_sum: f64 = component_keys.iter().map(|k| post_opt[*k]).sum();
    let b_total = baseline["ipc.total_consumption"];
    let p_total = post_opt["ipc.total_consumption"];

    if (b_total - base_component_sum).abs() > 1e-9 {
        return Err(BenchVerifyError::InconsistentIpcTotal {
            dataset: "baseline",
            reported_total: b_total,
            component_sum: base_component_sum,
        });
    }
    if (p_total - post_component_sum).abs() > 1e-9 {
        return Err(BenchVerifyError::InconsistentIpcTotal {
            dataset: "post_opt",
            reported_total: p_total,
            component_sum: post_component_sum,
        });
    }

    let any_component_reduced = component_keys.iter().any(|k| post_opt[*k] < baseline[*k]);
    if !any_component_reduced || p_total >= b_total {
        return Err(BenchVerifyError::IpcNotReduced {
            baseline: b_total,
            post_opt: p_total,
        });
    }
    Ok(())
}
