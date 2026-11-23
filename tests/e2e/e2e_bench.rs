//! Opaque-box E2E test suite for `newos-bench`, `BENCHMARK_RESULTS.md`, `Cargo.toml`, and `xtask`.
//! Standalone benchmark E2E test binary.
//!
//! Compile & run offline with:
//! ```bash
//! rustc --edition 2024 --test --crate-name e2e_bench tests/e2e/e2e_bench.rs -o target/e2e/e2e_bench
//! ./target/e2e/e2e_bench
//! ```

pub(crate) fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join("xtask").exists() {
        manifest_dir.to_path_buf()
    } else {
        manifest_dir.parent().unwrap_or(manifest_dir).to_path_buf()
    }
}

#[path = "common/bench_parser.rs"]
pub(crate) mod bench_parser;

#[path = "bench/tier1_core.rs"]
mod tier1_core;

#[path = "bench/tier2_errors.rs"]
mod tier2_errors;

#[path = "bench/tier3_integration.rs"]
mod tier3_integration;

#[path = "bench/tier4_invariants.rs"]
mod tier4_invariants;
