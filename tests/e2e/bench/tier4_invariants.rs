//! Tier 4 (Acceptance Invariants) E2E tests verifying `ORIGINAL_REQUEST.md` acceptance criteria:
//! 1. Post-optimization kernel execution is strictly faster than baseline.
//! 2. Post-optimization shell execution is strictly faster than baseline.
//! 3. Post-optimization IPC consumption is strictly reduced compared to baseline.
//!
//! Intentionally RED before M4 records post-optimization results in `BENCHMARK_RESULTS.md`,
//! and GREEN once M4 completes.

use std::fs;

use crate::bench_parser::{
    parse_benchmark_results_md, verify_ipc_reduced, verify_kernel_faster, verify_shell_faster,
};

fn load_baseline_and_post_opt() -> (
    std::collections::BTreeMap<String, f64>,
    std::collections::BTreeMap<String, f64>,
) {
    let content = fs::read_to_string(crate::workspace_root().join("BENCHMARK_RESULTS.md"))
        .expect("BENCHMARK_RESULTS.md must exist with baseline and post-optimization results");
    let report = parse_benchmark_results_md(&content)
        .unwrap_or_else(|e| panic!("failed to parse BENCHMARK_RESULTS.md: {e}"));
    let post = report
        .post_opt
        .expect("BENCHMARK_RESULTS.md must contain post-optimization measurements");
    (report.baseline, post)
}

#[test]
fn tier4_invariant_post_opt_kernel_faster_than_baseline() {
    let (baseline, post_opt) = load_baseline_and_post_opt();
    verify_kernel_faster(&baseline, &post_opt)
        .unwrap_or_else(|e| panic!("Acceptance Criterion failed (faster kernel): {e}"));
}

#[test]
fn tier4_invariant_post_opt_shell_faster_than_baseline() {
    let (baseline, post_opt) = load_baseline_and_post_opt();
    verify_shell_faster(&baseline, &post_opt)
        .unwrap_or_else(|e| panic!("Acceptance Criterion failed (faster shell): {e}"));
}

#[test]
fn tier4_invariant_post_opt_ipc_consumption_strictly_reduced() {
    let (baseline, post_opt) = load_baseline_and_post_opt();
    verify_ipc_reduced(&baseline, &post_opt)
        .unwrap_or_else(|e| panic!("Acceptance Criterion failed (reduced IPC): {e}"));
}
