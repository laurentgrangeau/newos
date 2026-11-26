//! Tier 1 (Core Functionality) E2E tests for benchmark contract, parser, Cargo.toml, and xtask.
//! 15 tests covering the 16-metric schema, METRIC & markdown parsing, comparison logic, Cargo, and xtask.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::process::Command;

use crate::bench_parser::{
    IPC_CONSUMPTION_KEYS, KERNEL_SPEED_KEYS, SHELL_SPEED_KEYS, all_metric_keys, is_ipc_metric,
    is_speed_metric, parse_benchmark_results_md, parse_metric_lines, validate_complete_metrics,
    verify_ipc_reduced, verify_kernel_faster, verify_shell_faster,
};

fn sample_full_metric_output() -> String {
    let mut s = String::new();
    for (i, k) in (0u32..).zip(KERNEL_SPEED_KEYS) {
        let _ = writeln!(s, "METRIC {k} {:.2} ns/op", f64::from(i).mul_add(5.0, 50.0));
    }
    for (i, k) in (0u32..).zip(SHELL_SPEED_KEYS) {
        let _ = writeln!(
            s,
            "METRIC {k} {:.2} ns/op",
            f64::from(i).mul_add(100.0, 500.0)
        );
    }
    for (i, k) in IPC_CONSUMPTION_KEYS.iter().enumerate() {
        let _ = writeln!(s, "METRIC {k} {} syscalls", 10 + i * 5);
    }
    s
}

fn sample_maps(factor_speed: f64, factor_ipc: f64) -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    for (i, k) in (0u32..).zip(KERNEL_SPEED_KEYS) {
        m.insert(
            (*k).to_string(),
            f64::from(i).mul_add(10.0, 100.0) * factor_speed,
        );
    }
    for (i, k) in (0u32..).zip(SHELL_SPEED_KEYS) {
        m.insert(
            (*k).to_string(),
            f64::from(i).mul_add(100.0, 1000.0) * factor_speed,
        );
    }
    let mut ipc_sum = 0.0;
    for (i, k) in (0u32..).zip(&IPC_CONSUMPTION_KEYS[..5]) {
        let v = (f64::from(20 + i * 10) * factor_ipc).round();
        m.insert((*k).to_string(), v);
        ipc_sum += v;
    }
    m.insert("ipc.total_consumption".to_string(), ipc_sum);
    m
}

#[test]
fn tier1_bench_schema_has_exact_16_unique_metric_keys() {
    assert_eq!(KERNEL_SPEED_KEYS.len(), 7);
    assert_eq!(SHELL_SPEED_KEYS.len(), 3);
    assert_eq!(IPC_CONSUMPTION_KEYS.len(), 6);
    let all = all_metric_keys();
    assert_eq!(all.len(), 16);
    let mut dedup = all;
    dedup.sort_unstable();
    dedup.dedup();
    assert_eq!(dedup.len(), 16);
}

#[test]
fn tier1_bench_metric_category_classification() {
    for &k in KERNEL_SPEED_KEYS {
        assert!(is_speed_metric(k));
        assert!(!is_ipc_metric(k));
    }
    for &k in SHELL_SPEED_KEYS {
        assert!(is_speed_metric(k));
        assert!(!is_ipc_metric(k));
    }
    for &k in IPC_CONSUMPTION_KEYS {
        assert!(is_ipc_metric(k));
        assert!(!is_speed_metric(k));
    }
}

#[test]
fn tier1_bench_parse_complete_metric_lines() {
    let raw = sample_full_metric_output();
    let parsed = parse_metric_lines(&raw).unwrap();
    assert_eq!(parsed.len(), 16);
    assert!(validate_complete_metrics(&parsed).is_ok());
    assert_eq!(parsed["kernel.cnode.lookup"].unit, "ns/op");
    assert_eq!(parsed["ipc.total_consumption"].unit, "syscalls");
}

#[test]
fn tier1_bench_parse_metric_lines_ignores_banners_and_tables() {
    let mut raw = String::from("# NewOS Production Benchmark\n| Metric | Value |\n|---|---|\n");
    raw.push_str(&sample_full_metric_output());
    raw.push_str("\nDone.\n");
    let parsed = parse_metric_lines(&raw).unwrap();
    assert_eq!(parsed.len(), 16);
    assert!(validate_complete_metrics(&parsed).is_ok());
}

#[test]
fn tier1_bench_parse_metric_lines_accepts_backticked_keys() {
    let raw = "METRIC `kernel.cnode.lookup` 12.5 ns/op\nMETRIC `ipc.total_consumption` 42 count\n";
    let parsed = parse_metric_lines(raw).unwrap();
    assert_eq!(parsed["kernel.cnode.lookup"].value, 12.5);
    assert_eq!(parsed["ipc.total_consumption"].value, 42.0);
}

#[test]
fn tier1_bench_parse_markdown_baseline_only_section() {
    let mut md = String::from(
        "# Benchmark Results\n\n## Baseline\n\n| Metric | Value | Unit |\n|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let unit = if is_speed_metric(k) { "ns/op" } else { "count" };
        let _ = writeln!(md, "| `{k}` | 42 | {unit} |");
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline.len(), 16);
    assert!(report.post_opt.is_none());
}

#[test]
fn tier1_bench_parse_markdown_unified_comparison_table() {
    let mut md = String::from(
        "# Benchmark Results\n\n## Comparison\n\n| Metric | Unit | Baseline | Post-Optimization | Delta |\n|---|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let unit = if is_speed_metric(k) { "ns/op" } else { "count" };
        let _ = writeln!(md, "| `{k}` | {unit} | 100.0 | 40.0 | -60% |");
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline.len(), 16);
    let post = report.post_opt.unwrap();
    assert_eq!(post.len(), 16);
    assert_eq!(report.baseline["kernel.cnode.lookup"], 100.0);
    assert_eq!(post["kernel.cnode.lookup"], 40.0);
}

#[test]
fn tier1_bench_parse_markdown_separate_baseline_and_post_opt_sections() {
    let mut md = String::from("# Benchmark Results\n\n## Baseline\n");
    md.push_str(&sample_full_metric_output());
    md.push_str("\n## Post-Optimization\n");
    md.push_str(&sample_full_metric_output());
    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline.len(), 16);
    assert_eq!(report.post_opt.unwrap().len(), 16);
}

#[test]
fn tier1_bench_parse_markdown_handles_commas_and_bold_numbers() {
    let mut md = String::from("## Comparison\n| Metric | Baseline | Post-Opt |\n|---|---|---|\n");
    for k in all_metric_keys() {
        if is_ipc_metric(k) {
            let _ = writeln!(md, "| `{k}` | **1,250** | `625` |");
        } else {
            let _ = writeln!(md, "| `{k}` | **1,250.5** | `625.25` |");
        }
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    let post = report.post_opt.unwrap();
    assert_eq!(report.baseline["shell.session.full"], 1250.5);
    assert_eq!(post["shell.session.full"], 625.25);
    assert_eq!(report.baseline["ipc.total_consumption"], 1250.0);
    assert_eq!(post["ipc.total_consumption"], 625.0);
}

#[test]
fn tier1_bench_verify_kernel_faster_passes_on_improvement() {
    let base = sample_maps(1.0, 1.0);
    let post = sample_maps(0.6, 1.0);
    assert!(verify_kernel_faster(&base, &post).is_ok());
}

#[test]
fn tier1_bench_verify_shell_faster_passes_on_improvement() {
    let base = sample_maps(1.0, 1.0);
    let post = sample_maps(0.5, 1.0);
    assert!(verify_shell_faster(&base, &post).is_ok());
}

#[test]
fn tier1_bench_verify_ipc_reduced_passes_on_reduction() {
    let base = sample_maps(1.0, 1.0);
    let post = sample_maps(1.0, 0.3);
    assert!(verify_ipc_reduced(&base, &post).is_ok());
}

#[test]
fn tier1_bench_cargo_toml_workspace_edition_and_release_profile() {
    let root = crate::workspace_root();
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml"))
        .expect("Cargo.toml must exist at workspace root");
    assert!(cargo_toml.contains("[workspace]"));
    assert!(cargo_toml.contains("edition = \"2024\""));
    assert!(cargo_toml.contains("[profile.release]"));
    assert!(cargo_toml.contains("lto = true"));
    assert!(cargo_toml.contains("codegen-units = 1"));
}

#[test]
fn tier1_bench_xtask_zero_external_deps_manifest() {
    let root = crate::workspace_root();
    let xtask_toml =
        fs::read_to_string(root.join("xtask/Cargo.toml")).expect("xtask/Cargo.toml must exist");
    assert!(xtask_toml.contains("name = \"xtask\""));
    assert!(!xtask_toml.contains("clap"));
    assert!(!xtask_toml.contains("serde"));
}

#[test]
fn tier1_bench_xtask_compiles_offline_with_rustc() {
    let root = crate::workspace_root();
    let xtask_dir = root.join("xtask");
    let out_bin =
        std::env::temp_dir().join(format!("newos_xtask_e2e_check_{}", std::process::id()));
    let status = Command::new("rustc")
        .current_dir(&root)
        .env("CARGO_MANIFEST_DIR", &xtask_dir)
        .args([
            "--edition",
            "2024",
            "--crate-name",
            "xtask",
            "xtask/src/main.rs",
            "-o",
        ])
        .arg(&out_bin)
        .status()
        .expect("invoke rustc on xtask/src/main.rs");
    let exists = out_bin.exists();
    let _ = fs::remove_file(&out_bin);
    assert!(
        status.success(),
        "xtask/src/main.rs must compile cleanly offline with CARGO_MANIFEST_DIR set"
    );
    assert!(exists);
}

#[test]
fn tier1_bench_parse_markdown_4col_category_metric_table_without_raw_lines() {
    let mut md = String::from(
        "# NewOS Benchmark Results\n\n## Baseline (Pre-Optimization)\n\n| Category | Metric | Value | Unit |\n|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let (cat, val, unit) = if KERNEL_SPEED_KEYS.contains(&k) {
            ("Kernel Speed", "12.50", "ns/op")
        } else if SHELL_SPEED_KEYS.contains(&k) {
            ("Shell Speed", "250.00", "ns/op")
        } else {
            ("IPC Consumption", "42", "syscalls")
        };
        let _ = writeln!(md, "| {cat} | `{k}` | {val} | {unit} |");
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline.len(), 16);
    assert!(report.post_opt.is_none());
    assert_eq!(report.baseline["kernel.cnode.lookup"], 12.5);
    assert_eq!(report.baseline["shell.session.full"], 250.0);
    assert_eq!(report.baseline["ipc.total_consumption"], 42.0);
}

#[test]
fn tier1_bench_parse_markdown_6col_category_metric_comparison_table() {
    let mut md = String::from(
        "# NewOS Benchmark Results\n\n## Post-Optimization (M4) & Delta Comparison\n\n| Category | Metric | M1 Baseline | M4 Post-Opt | Delta / Speedup | Unit |\n|---|---|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let (cat, base, post, unit) = if KERNEL_SPEED_KEYS.contains(&k) {
            ("Kernel Speed", "10.00", "4.00", "ns/op")
        } else if SHELL_SPEED_KEYS.contains(&k) {
            ("Shell Speed", "500.00", "200.00", "ns/op")
        } else {
            ("IPC Consumption", "100", "25", "syscalls")
        };
        let _ = writeln!(md, "| {cat} | `{k}` | {base} | {post} | -60% | {unit} |");
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline.len(), 16);
    let post = report
        .post_opt
        .expect("6-col M4 table must populate post_opt");
    assert_eq!(post.len(), 16);
    assert_eq!(report.baseline["kernel.cnode.lookup"], 10.0);
    assert_eq!(post["kernel.cnode.lookup"], 4.0);
    assert_eq!(report.baseline["ipc.total_consumption"], 100.0);
    assert_eq!(post["ipc.total_consumption"], 25.0);
}

#[test]
fn tier1_bench_parse_markdown_bold_backtick_cells_and_inline_units() {
    let mut md = String::from(
        "## Comparison\n| Category | Metric | Baseline | Post-Opt |\n|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        if is_ipc_metric(k) {
            let _ = writeln!(md, "| IPC | **`{k}`** | **`100`** | **40** syscalls |");
        } else {
            let _ = writeln!(md, "| Speed | **`{k}`** | **`50`** | **25** ns/op |");
        }
    }
    let report = parse_benchmark_results_md(&md).unwrap();
    let post = report.post_opt.expect("post_opt must be parsed");
    assert_eq!(report.baseline["kernel.cnode.lookup"], 50.0);
    assert_eq!(post["kernel.cnode.lookup"], 25.0);
    assert_eq!(report.baseline["ipc.total_consumption"], 100.0);
    assert_eq!(post["ipc.total_consumption"], 40.0);
}

#[test]
fn tier1_bench_parse_markdown_post_opt_comparison_heading_routes_metric_lines() {
    let mut md = String::from(
        "# NewOS Benchmark Results\n\n## Baseline (Pre-Optimization)\n\n| Category | Metric | Value | Unit |\n|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let (val, unit) = if is_ipc_metric(k) {
            ("100", "syscalls")
        } else {
            ("1.79", "ns/op")
        };
        let _ = writeln!(md, "| Cat | `{k}` | {val} | {unit} |");
    }
    md.push_str("\n## Post-Optimization (M4) & Delta Comparison\n\n");
    for k in all_metric_keys() {
        let (val, unit) = if is_ipc_metric(k) {
            ("25", "syscalls")
        } else {
            ("0.85", "ns/op")
        };
        let _ = writeln!(md, "METRIC {k} {val} {unit}");
    }

    let report = parse_benchmark_results_md(&md).unwrap();
    assert_eq!(report.baseline["kernel.cnode.lookup"], 1.79);
    assert_eq!(report.baseline["ipc.total_consumption"], 100.0);
    let post = report
        .post_opt
        .expect("METRIC lines under Post-Optimization & Delta Comparison must populate post_opt");
    assert_eq!(post["kernel.cnode.lookup"], 0.85);
    assert_eq!(post["ipc.total_consumption"], 25.0);
}
