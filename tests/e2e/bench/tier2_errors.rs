//! Tier 2 (Boundary & Error Paths) E2E tests for benchmark parser and regression detectors.
//! 15 negative / boundary tests ensuring invalid outputs and regressions are strictly rejected.

use std::collections::BTreeMap;

use crate::bench_parser::{
    IPC_CONSUMPTION_KEYS, KERNEL_SPEED_KEYS, ParseError, SHELL_SPEED_KEYS, all_metric_keys,
    parse_benchmark_results_md, parse_metric_lines, validate_complete_metrics, verify_ipc_reduced,
    verify_kernel_faster, verify_shell_faster,
};

fn baseline_maps() -> BTreeMap<String, f64> {
    let mut m = BTreeMap::new();
    for &k in KERNEL_SPEED_KEYS {
        m.insert(k.to_string(), 100.0);
    }
    for &k in SHELL_SPEED_KEYS {
        m.insert(k.to_string(), 1000.0);
    }
    for &k in &IPC_CONSUMPTION_KEYS[..5] {
        m.insert(k.to_string(), 50.0);
    }
    m.insert("ipc.total_consumption".to_string(), 250.0);
    m
}

#[test]
fn tier2_bench_rejects_empty_metric_output() {
    assert_eq!(parse_metric_lines(""), Err(ParseError::EmptyInput));
    assert_eq!(parse_metric_lines("   \n\t\n"), Err(ParseError::EmptyInput));
}

#[test]
fn tier2_bench_rejects_output_with_no_metric_lines() {
    let err = parse_metric_lines("just some text\nno metrics here\n").unwrap_err();
    assert!(matches!(err, ParseError::MalformedLine { .. }));
}

#[test]
fn tier2_bench_rejects_malformed_metric_arity() {
    let err = parse_metric_lines("METRIC kernel.cnode.lookup 12.5\n").unwrap_err();
    assert!(matches!(err, ParseError::MalformedLine { line_no: 1, .. }));

    let err2 = parse_metric_lines("METRIC kernel.cnode.lookup 12.5 ns/op extra\n").unwrap_err();
    assert!(matches!(err2, ParseError::MalformedLine { line_no: 1, .. }));
}

#[test]
fn tier2_bench_rejects_duplicate_metric_keys() {
    let raw = "METRIC kernel.cnode.lookup 12.5 ns/op\nMETRIC kernel.cnode.lookup 11.0 ns/op\n";
    assert_eq!(
        parse_metric_lines(raw),
        Err(ParseError::DuplicateMetric(
            "kernel.cnode.lookup".to_string()
        ))
    );
}

#[test]
fn tier2_bench_rejects_non_numeric_nan_and_inf_values() {
    for bad in ["abc", "NaN", "inf", "-inf", "-5.0"] {
        let raw = format!("METRIC kernel.cnode.lookup {bad} ns/op\n");
        assert!(
            matches!(
                parse_metric_lines(&raw),
                Err(ParseError::InvalidValue { .. })
            ),
            "value `{bad}` must be rejected"
        );
    }
}

#[test]
fn tier2_bench_rejects_zero_speed_latency() {
    let raw = "METRIC kernel.cnode.lookup 0 ns/op\n";
    assert!(matches!(
        parse_metric_lines(raw),
        Err(ParseError::InvalidValue { .. })
    ));
}

#[test]
fn tier2_bench_rejects_wrong_unit_for_speed_metric() {
    let raw = "METRIC shell.pipeline.eval 120.0 syscalls\n";
    assert!(matches!(
        parse_metric_lines(raw),
        Err(ParseError::InvalidUnit { .. })
    ));
}

#[test]
fn tier2_bench_rejects_fractional_ipc_count() {
    let raw = "METRIC ipc.total_consumption 12.5 syscalls\n";
    assert!(matches!(
        parse_metric_lines(raw),
        Err(ParseError::InvalidValue { .. })
    ));
}

#[test]
fn tier2_bench_rejects_speed_unit_on_ipc_metric() {
    let raw = "METRIC ipc.total_consumption 12 ns/op\n";
    assert!(matches!(
        parse_metric_lines(raw),
        Err(ParseError::InvalidUnit { .. })
    ));
}

#[test]
fn tier2_bench_validate_complete_rejects_missing_keys() {
    let raw = "METRIC kernel.cnode.lookup 15.0 ns/op\n";
    let parsed = parse_metric_lines(raw).unwrap();
    let err = validate_complete_metrics(&parsed).unwrap_err();
    match err {
        ParseError::MissingMetrics(missing) => assert_eq!(missing.len(), 15),
        other => panic!("expected MissingMetrics, got {other:?}"),
    }
}

#[test]
fn tier2_bench_markdown_rejects_empty_and_missing_baseline() {
    assert_eq!(parse_benchmark_results_md(""), Err(ParseError::EmptyInput));
    assert_eq!(
        parse_benchmark_results_md("# Benchmark Results\n\nNo tables yet.\n"),
        Err(ParseError::MissingSection("Baseline".to_string()))
    );
}

#[test]
fn tier2_bench_markdown_rejects_incomplete_post_opt_table() {
    let mut md = String::from("## Comparison\n| Metric | Baseline | Post-Opt |\n|---|---|---|\n");
    for (i, k) in all_metric_keys().into_iter().enumerate() {
        if i == 0 {
            md.push_str(&format!("| `{k}` | 100 | 50 |\n"));
        } else {
            md.push_str(&format!("| `{k}` | 100 | TBD |\n"));
        }
    }
    let err = parse_benchmark_results_md(&md).unwrap_err();
    assert!(matches!(err, ParseError::MissingMetrics(_)));
}

#[test]
fn tier2_bench_verify_kernel_faster_rejects_equal_or_slower() {
    let base = baseline_maps();
    assert!(verify_kernel_faster(&base, &base).is_err());

    let mut slower = base.clone();
    for &k in KERNEL_SPEED_KEYS {
        slower.insert(k.to_string(), 120.0);
    }
    assert!(verify_kernel_faster(&base, &slower).is_err());
}

#[test]
fn tier2_bench_verify_shell_faster_rejects_equal_or_slower() {
    let base = baseline_maps();
    assert!(verify_shell_faster(&base, &base).is_err());

    let mut slower = base.clone();
    for &k in SHELL_SPEED_KEYS {
        slower.insert(k.to_string(), 1500.0);
    }
    assert!(verify_shell_faster(&base, &slower).is_err());
}

#[test]
fn tier2_bench_verify_ipc_reduced_rejects_flat_or_regressed_ipc() {
    let base = baseline_maps();
    assert!(verify_ipc_reduced(&base, &base).is_err());

    // Even if total decreases consistently, a regression on an individual IPC metric must be rejected.
    let mut regressed = base.clone();
    regressed.insert("ipc.shell_session.debug_write_syscalls".to_string(), 10.0);
    regressed.insert("ipc.ping_roundtrip.syscalls_per_op".to_string(), 60.0);
    regressed.insert("ipc.total_consumption".to_string(), 220.0);
    assert!(verify_ipc_reduced(&base, &regressed).is_err());
}

#[test]
fn tier2_bench_verify_kernel_faster_rejects_nan_and_inf() {
    let base = baseline_maps();
    let mut post_nan = base.clone();
    post_nan.insert("kernel.cnode.lookup".to_string(), 50.0);
    post_nan.insert("kernel.ipc.send_recv".to_string(), f64::NAN);
    assert!(verify_kernel_faster(&base, &post_nan).is_err());

    let mut base_inf = base.clone();
    base_inf.insert("kernel.cnode.lookup".to_string(), f64::INFINITY);
    let mut post_ok = base.clone();
    post_ok.insert("kernel.cnode.lookup".to_string(), 50.0);
    assert!(verify_kernel_faster(&base_inf, &post_ok).is_err());

    let mut post_inf = base.clone();
    post_inf.insert("kernel.cnode.lookup".to_string(), f64::INFINITY);
    assert!(verify_kernel_faster(&base, &post_inf).is_err());
}

#[test]
fn tier2_bench_verify_shell_faster_rejects_nan_and_inf() {
    let base = baseline_maps();
    let mut post_nan = base.clone();
    post_nan.insert("shell.caos.put_get_ref".to_string(), 500.0);
    post_nan.insert("shell.pipeline.eval".to_string(), f64::NAN);
    assert!(verify_shell_faster(&base, &post_nan).is_err());

    let mut base_inf = base.clone();
    base_inf.insert("shell.session.full".to_string(), f64::INFINITY);
    let mut post_ok = base.clone();
    post_ok.insert("shell.session.full".to_string(), 500.0);
    assert!(verify_shell_faster(&base_inf, &post_ok).is_err());
}

#[test]
fn tier2_bench_verify_ipc_reduced_rejects_nan_negative_and_fractional() {
    let base = baseline_maps();

    // NaN in post_opt must be rejected.
    let mut post_nan = base.clone();
    post_nan.insert(
        "ipc.shell_session.debug_write_syscalls".to_string(),
        f64::NAN,
    );
    post_nan.insert("ipc.total_consumption".to_string(), 200.0);
    assert!(verify_ipc_reduced(&base, &post_nan).is_err());

    // Negative IPC count must be rejected even if total is consistent.
    let mut post_neg = base.clone();
    post_neg.insert("ipc.shell_session.debug_write_syscalls".to_string(), -10.0);
    post_neg.insert("ipc.total_consumption".to_string(), 190.0);
    assert!(verify_ipc_reduced(&base, &post_neg).is_err());

    // Fractional IPC count must be rejected.
    let mut post_frac = base.clone();
    post_frac.insert("ipc.shell_session.debug_write_syscalls".to_string(), 40.5);
    post_frac.insert("ipc.total_consumption".to_string(), 240.5);
    assert!(verify_ipc_reduced(&base, &post_frac).is_err());
}

#[test]
fn tier2_bench_verify_ipc_reduced_rejects_inconsistent_total_with_flat_components() {
    let base = baseline_maps();
    // All 5 component IPC metrics unchanged, only ipc.total_consumption faked lower.
    let mut cheated = base.clone();
    cheated.insert("ipc.total_consumption".to_string(), 100.0);
    assert!(verify_ipc_reduced(&base, &cheated).is_err());

    // Inconsistent baseline total must also be rejected.
    let mut bad_base = base.clone();
    bad_base.insert("ipc.total_consumption".to_string(), 999.0);
    let mut valid_post = base.clone();
    valid_post.insert("ipc.shell_session.debug_write_syscalls".to_string(), 25.0);
    valid_post.insert("ipc.total_consumption".to_string(), 225.0);
    assert!(verify_ipc_reduced(&bad_base, &valid_post).is_err());
}

#[test]
fn tier2_bench_markdown_rejects_fractional_ipc_and_negative_or_nan_cells() {
    // 1. Fractional IPC in markdown table must return Err(InvalidValue).
    let mut md_frac = String::from(
        "## Comparison\n| Category | Metric | M1 Baseline | M4 Post-Opt |\n|---|---|---|---|\n",
    );
    for k in all_metric_keys() {
        let post = if k == "ipc.total_consumption" {
            "50.5"
        } else {
            "50"
        };
        md_frac.push_str(&format!("| Cat | `{k}` | 100 | {post} |\n"));
    }
    assert!(matches!(
        parse_benchmark_results_md(&md_frac),
        Err(ParseError::InvalidValue { .. })
    ));

    // 2. Negative, NaN, and inf post-opt cells must return Err(InvalidValue) instead of None.
    for bad in ["-5.0", "NaN", "inf"] {
        let mut md_bad = String::from(
            "## Comparison\n| Category | Metric | M1 Baseline | M4 Post-Opt |\n|---|---|---|---|\n",
        );
        for k in all_metric_keys() {
            md_bad.push_str(&format!("| Cat | `{k}` | 100 | {bad} |\n"));
        }
        assert!(
            matches!(
                parse_benchmark_results_md(&md_bad),
                Err(ParseError::InvalidValue { .. })
            ),
            "markdown cell `{bad}` must return Err(InvalidValue)"
        );
    }
}
