//! Pure-std parser and validator for `newos_bench` `METRIC` output and `BENCHMARK_RESULTS.md`.
//! Zero external dependencies, `#![forbid(unsafe_code)]`.

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

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Baseline,
        PostOpt,
        Comparison,
    }
    let mut section = Section::None;
    let mut metric_col: Option<usize> = None;
    let mut baseline_col: Option<usize> = None;
    let mut post_col: Option<usize> = None;
    let mut value_col: Option<usize> = None;

    for (idx, raw_line) in md.lines().enumerate() {
        let line = raw_line.trim();
        if line.starts_with('#') {
            let lower = line.to_ascii_lowercase();
            metric_col = None;
            baseline_col = None;
            post_col = None;
            value_col = None;
            let has_post = lower.contains("post-opt")
                || lower.contains("post opt")
                || lower.contains("optimized")
                || lower.contains("after");
            let has_baseline = lower.contains("baseline") || lower.contains("before");
            if has_post && !has_baseline {
                section = Section::PostOpt;
            } else if lower.contains("comparison") || (has_baseline && has_post) {
                section = Section::Comparison;
            } else if has_baseline {
                section = Section::Baseline;
            }
            continue;
        }

        if line.starts_with("METRIC ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 4 {
                return Err(ParseError::MalformedLine {
                    line_no: idx + 1,
                    detail: format!("malformed METRIC line in markdown: `{line}`"),
                });
            }
            let name = parts[1].trim_matches(|c| matches!(c, '`' | '*' | '_'));
            let val: f64 = parts[2].parse().map_err(|_| ParseError::InvalidValue {
                name: name.to_string(),
                raw: parts[2].to_string(),
            })?;
            validate_value_and_unit(name, val, parts[3])?;
            match section {
                Section::PostOpt => {
                    post_opt.insert(name.to_string(), val);
                }
                Section::Comparison if baseline.len() == known_keys.len() => {
                    post_opt.insert(name.to_string(), val);
                }
                _ => {
                    baseline.entry(name.to_string()).or_insert(val);
                }
            }
            continue;
        }

        if line.starts_with('|') && line.ends_with('|') {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            if is_separator_row(&cells) {
                continue;
            }
            // Detect table header row with `Metric` at any column index.
            let lower_cells: Vec<String> = cells.iter().map(|c| c.to_ascii_lowercase()).collect();
            if let Some(m_col) = lower_cells.iter().position(|c| c.contains("metric")) {
                metric_col = Some(m_col);
                baseline_col = lower_cells
                    .iter()
                    .position(|c| c.contains("baseline") || c.contains("before"));
                post_col = lower_cells.iter().position(|c| {
                    c.contains("post") || c.contains("optimized") || c.contains("after")
                });
                value_col = lower_cells
                    .iter()
                    .position(|c| c == "value" || c.contains("value"));
                continue;
            }

            let m_idx = metric_col.unwrap_or(0);
            let Some(raw_metric) = cells.get(m_idx) else {
                continue;
            };
            let metric_name = raw_metric
                .trim()
                .trim_matches(|c| matches!(c, '`' | '*' | '_'))
                .trim();
            if !known_keys.contains(&metric_name) {
                continue;
            }

            // Case A: unified table with baseline and/or post-opt columns.
            if let Some(b_idx) = baseline_col {
                if let Some(raw_b) = cells.get(b_idx)
                    && let Some(v) = parse_cell_number(metric_name, raw_b)?
                {
                    baseline.entry(metric_name.to_string()).or_insert(v);
                }
                if let Some(p_idx) = post_col
                    && let Some(raw_p) = cells.get(p_idx)
                    && let Some(v) = parse_cell_number(metric_name, raw_p)?
                {
                    post_opt.insert(metric_name.to_string(), v);
                }
                continue;
            }

            // Case B: single-value section table (e.g. | Category | Metric | Value | Unit | or | Metric | Value | Unit |).
            let v_idx = value_col.unwrap_or(m_idx + 1);
            if let Some(raw_v) = cells.get(v_idx)
                && let Some(v) = parse_cell_number(metric_name, raw_v)?
            {
                match section {
                    Section::PostOpt => {
                        post_opt.insert(metric_name.to_string(), v);
                    }
                    Section::Comparison if baseline.len() == known_keys.len() => {
                        post_opt.insert(metric_name.to_string(), v);
                    }
                    Section::Baseline | Section::Comparison | Section::None => {
                        baseline.entry(metric_name.to_string()).or_insert(v);
                    }
                }
            }
        }
    }

    if baseline.is_empty() {
        return Err(ParseError::MissingSection("Baseline".to_string()));
    }

    let missing_base: Vec<String> = known_keys
        .iter()
        .filter(|k| !baseline.contains_key(**k))
        .map(|k| (*k).to_string())
        .collect();
    if !missing_base.is_empty() {
        return Err(ParseError::MissingMetrics(missing_base));
    }

    let post_opt_map = if post_opt.is_empty() {
        None
    } else {
        let missing_post: Vec<String> = known_keys
            .iter()
            .filter(|k| !post_opt.contains_key(**k))
            .map(|k| (*k).to_string())
            .collect();
        if !missing_post.is_empty() {
            return Err(ParseError::MissingMetrics(missing_post));
        }
        Some(post_opt)
    };

    Ok(BenchmarkReport {
        baseline,
        post_opt: post_opt_map,
    })
}

/// Verifies post-optimization kernel speed is strictly faster than baseline:
/// - Total kernel latency sum is strictly lower (`post_sum < base_sum`)
/// - Geometric mean ratio `(post / base)` is strictly `< 1.0`
pub fn verify_kernel_faster(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), String> {
    let mut base_sum = 0.0;
    let mut post_sum = 0.0;
    let mut log_ratio_sum = 0.0;
    let mut improved = 0usize;

    for &key in KERNEL_SPEED_KEYS {
        let b = *baseline
            .get(key)
            .ok_or_else(|| format!("missing baseline key {key}"))?;
        let p = *post_opt
            .get(key)
            .ok_or_else(|| format!("missing post-opt key {key}"))?;
        if !b.is_finite() || !p.is_finite() || b <= 0.0 || p <= 0.0 {
            return Err(format!(
                "invalid or non-positive kernel latency for {key}: base={b}, post={p}"
            ));
        }
        base_sum += b;
        post_sum += p;
        log_ratio_sum += (p / b).ln();
        if p < b {
            improved += 1;
        }
    }

    let geomean_ratio = (log_ratio_sum / (KERNEL_SPEED_KEYS.len() as f64)).exp();
    if !geomean_ratio.is_finite() || post_sum >= base_sum || geomean_ratio >= 1.0 || improved == 0 {
        return Err(format!(
            "kernel not faster: base_sum={base_sum:.2}, post_sum={post_sum:.2}, geomean_ratio={geomean_ratio:.4}, improved={improved}/{}",
            KERNEL_SPEED_KEYS.len()
        ));
    }
    Ok(())
}

/// Verifies post-optimization shell speed is strictly faster than baseline.
pub fn verify_shell_faster(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), String> {
    let mut base_sum = 0.0;
    let mut post_sum = 0.0;
    let mut log_ratio_sum = 0.0;
    let mut improved = 0usize;

    for &key in SHELL_SPEED_KEYS {
        let b = *baseline
            .get(key)
            .ok_or_else(|| format!("missing baseline key {key}"))?;
        let p = *post_opt
            .get(key)
            .ok_or_else(|| format!("missing post-opt key {key}"))?;
        if !b.is_finite() || !p.is_finite() || b <= 0.0 || p <= 0.0 {
            return Err(format!(
                "invalid or non-positive shell latency for {key}: base={b}, post={p}"
            ));
        }
        base_sum += b;
        post_sum += p;
        log_ratio_sum += (p / b).ln();
        if p < b {
            improved += 1;
        }
    }

    let geomean_ratio = (log_ratio_sum / (SHELL_SPEED_KEYS.len() as f64)).exp();
    if !geomean_ratio.is_finite() || post_sum >= base_sum || geomean_ratio >= 1.0 || improved == 0 {
        return Err(format!(
            "shell not faster: base_sum={base_sum:.2}, post_sum={post_sum:.2}, geomean_ratio={geomean_ratio:.4}, improved={improved}/{}",
            SHELL_SPEED_KEYS.len()
        ));
    }
    Ok(())
}

/// Verifies post-optimization IPC consumption is strictly reduced with zero IPC regressions,
/// strict finiteness/non-negativity/integrality, and exact `ipc.total_consumption == sum(components)`.
pub fn verify_ipc_reduced(
    baseline: &BTreeMap<String, f64>,
    post_opt: &BTreeMap<String, f64>,
) -> Result<(), String> {
    for &key in IPC_CONSUMPTION_KEYS {
        let b = *baseline
            .get(key)
            .ok_or_else(|| format!("missing baseline IPC key {key}"))?;
        let p = *post_opt
            .get(key)
            .ok_or_else(|| format!("missing post-opt IPC key {key}"))?;
        if !b.is_finite()
            || !p.is_finite()
            || b < 0.0
            || p < 0.0
            || b.fract().abs() > 1e-9
            || p.fract().abs() > 1e-9
        {
            return Err(format!(
                "invalid IPC count for `{key}`: baseline={b}, post_opt={p}"
            ));
        }
        if p > b {
            return Err(format!(
                "IPC regression on `{key}`: baseline={b}, post_opt={p}"
            ));
        }
    }

    let component_keys = &IPC_CONSUMPTION_KEYS[..5];
    let base_component_sum: f64 = component_keys.iter().map(|k| baseline[*k]).sum();
    let post_component_sum: f64 = component_keys.iter().map(|k| post_opt[*k]).sum();
    let b_total = baseline["ipc.total_consumption"];
    let p_total = post_opt["ipc.total_consumption"];

    if (b_total - base_component_sum).abs() > 1e-9 {
        return Err(format!(
            "baseline ipc.total_consumption ({b_total}) != sum of 5 component IPC metrics ({base_component_sum})"
        ));
    }
    if (p_total - post_component_sum).abs() > 1e-9 {
        return Err(format!(
            "post_opt ipc.total_consumption ({p_total}) != sum of 5 component IPC metrics ({post_component_sum})"
        ));
    }

    let any_component_reduced = component_keys.iter().any(|k| post_opt[*k] < baseline[*k]);
    if !any_component_reduced || p_total >= b_total {
        return Err(format!(
            "ipc.total_consumption did not decrease: baseline={b_total}, post_opt={p_total}"
        ));
    }
    Ok(())
}
