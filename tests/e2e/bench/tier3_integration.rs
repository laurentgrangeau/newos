//! Tier 3 (Cross-Feature Integration) E2E tests for live `newos_bench`, `BENCHMARK_RESULTS.md`,
//! and `Cargo.toml` / `xtask` production release & benchmark wiring.
//!
//! These tests enforce the genuine M1–M4 acceptance criteria: they are intentionally RED
//! before `crates/bench`, `BENCHMARK_RESULTS.md`, and M2/M4 deliverables exist, and GREEN once
//! implemented.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::SystemTime;

use crate::bench_parser::{
    IPC_CONSUMPTION_KEYS, parse_benchmark_results_md, parse_metric_lines, validate_complete_metrics,
};

static BENCH_BIN: OnceLock<String> = OnceLock::new();

fn newest_mtime_in_dir(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let candidate = if path.is_dir() {
            newest_mtime_in_dir(&path)
        } else {
            entry.metadata().ok().and_then(|m| m.modified().ok())
        };
        if let Some(t) = candidate {
            newest = Some(match newest {
                Some(prev) if prev >= t => prev,
                _ => t,
            });
        }
    }
    newest
}

fn is_bench_binary_fresh(bin: &Path) -> bool {
    let Ok(meta) = fs::metadata(bin) else {
        return false;
    };
    let Ok(bin_mtime) = meta.modified() else {
        return false;
    };
    let root = crate::workspace_root();
    let src_dirs = [
        "crates/abi/src",
        "crates/kernel-core/src",
        "crates/shell-core/src",
        "crates/bench/src",
    ];
    for dir in src_dirs {
        if let Some(src_mtime) = newest_mtime_in_dir(&root.join(dir))
            && src_mtime > bin_mtime
        {
            return false;
        }
    }
    true
}

fn ensure_bench_binary() -> String {
    BENCH_BIN
        .get_or_init(|| {
            let root = crate::workspace_root();
            let workspace_bin = root.join("target/bench/newos_bench");
            if is_bench_binary_fresh(&workspace_bin) {
                return workspace_bin.to_string_lossy().into_owned();
            }
            assert!(
                root.join("crates/bench/src/main.rs").exists(),
                "crates/bench/src/main.rs does not exist yet (awaited from M1)"
            );
            assert!(
                root.join("crates/shell-core/src/lib.rs").exists(),
                "crates/shell-core/src/lib.rs does not exist yet (awaited from M1)"
            );

            let out_dir =
                std::env::temp_dir().join(format!("newos_bench_e2e_{}", std::process::id()));
            fs::create_dir_all(&out_dir).expect("create isolated temp dir for newos_bench");

            let abi_rlib = out_dir.join("libnewos_abi.rlib");
            let kernel_rlib = out_dir.join("libnewos_kernel_core.rlib");
            let shell_rlib = out_dir.join("libnewos_shell_core.rlib");
            let bin_path = out_dir.join("newos_bench");

            let crypto_rlib = out_dir.join("libnewos_crypto.rlib");
            let dep_flag = format!("dependency={}", out_dir.display());
            let ext_crypto = format!("newos_crypto={}", crypto_rlib.display());
            let ext_abi = format!("newos_abi={}", abi_rlib.display());
            let ext_kernel = format!("newos_kernel_core={}", kernel_rlib.display());
            let ext_shell = format!("newos_shell_core={}", shell_rlib.display());

            let steps: [(&str, Vec<String>); 5] = [
                (
                    "newos_crypto",
                    vec![
                        "--edition".into(),
                        "2024".into(),
                        "-C".into(),
                        "opt-level=3".into(),
                        "--crate-name".into(),
                        "newos_crypto".into(),
                        "--crate-type".into(),
                        "lib".into(),
                        "--cfg".into(),
                        "feature=\"sha3\"".into(),
                        "crates/crypto/src/lib.rs".into(),
                        "-o".into(),
                        crypto_rlib.display().to_string(),
                    ],
                ),
                (
                    "newos_abi",
                    vec![
                        "--edition".into(),
                        "2024".into(),
                        "-C".into(),
                        "opt-level=3".into(),
                        "--crate-name".into(),
                        "newos_abi".into(),
                        "--crate-type".into(),
                        "lib".into(),
                        "--cfg".into(),
                        "feature=\"sha3\"".into(),
                        "crates/abi/src/lib.rs".into(),
                        "-L".into(),
                        dep_flag.clone(),
                        "--extern".into(),
                        ext_crypto.clone(),
                        "-o".into(),
                        abi_rlib.display().to_string(),
                    ],
                ),
                (
                    "newos_kernel_core",
                    vec![
                        "--edition".into(),
                        "2024".into(),
                        "-C".into(),
                        "opt-level=3".into(),
                        "--crate-name".into(),
                        "newos_kernel_core".into(),
                        "--crate-type".into(),
                        "lib".into(),
                        "--cfg".into(),
                        "feature=\"smp\"".into(),
                        "--cfg".into(),
                        "feature=\"sched-priority-rr\"".into(),
                        "crates/kernel-core/src/lib.rs".into(),
                        "-L".into(),
                        dep_flag.clone(),
                        "--extern".into(),
                        ext_abi.clone(),
                        "-o".into(),
                        kernel_rlib.display().to_string(),
                    ],
                ),
                (
                    "newos_shell_core",
                    vec![
                        "--edition".into(),
                        "2024".into(),
                        "-C".into(),
                        "opt-level=3".into(),
                        "--crate-name".into(),
                        "newos_shell_core".into(),
                        "--crate-type".into(),
                        "lib".into(),
                        "crates/shell-core/src/lib.rs".into(),
                        "-L".into(),
                        dep_flag.clone(),
                        "--extern".into(),
                        ext_abi.clone(),
                        "-o".into(),
                        shell_rlib.display().to_string(),
                    ],
                ),
                (
                    "newos_bench",
                    vec![
                        "--edition".into(),
                        "2024".into(),
                        "-C".into(),
                        "opt-level=3".into(),
                        "--crate-name".into(),
                        "newos_bench".into(),
                        "crates/bench/src/main.rs".into(),
                        "-L".into(),
                        dep_flag,
                        "--extern".into(),
                        ext_abi,
                        "--extern".into(),
                        ext_kernel,
                        "--extern".into(),
                        ext_shell,
                        "-o".into(),
                        bin_path.display().to_string(),
                    ],
                ),
            ];

            for (name, args) in &steps {
                let out = Command::new("rustc")
                    .current_dir(&root)
                    .args(args)
                    .output()
                    .expect("invoke rustc");
                assert!(
                    out.status.success(),
                    "failed to build {name}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            bin_path.display().to_string()
        })
        .clone()
}

#[test]
fn tier3_bench_live_build_and_execute_all_16_metrics() {
    let bin = ensure_bench_binary();
    let out = Command::new(&bin)
        .output()
        .expect("execute target/bench/newos_bench");
    assert!(
        out.status.success(),
        "newos_bench exited with {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let metrics = parse_metric_lines(&stdout)
        .unwrap_or_else(|e| panic!("failed to parse newos_bench stdout: {e}\nstdout:\n{stdout}"));
    validate_complete_metrics(&metrics)
        .unwrap_or_else(|e| panic!("incomplete newos_bench metrics: {e}"));
}

#[test]
fn tier3_bench_repeated_runs_have_deterministic_ipc_counts() {
    let bin = ensure_bench_binary();
    let run1 = Command::new(&bin).output().expect("run 1");
    let run2 = Command::new(&bin).output().expect("run 2");
    assert!(run1.status.success() && run2.status.success());

    let m1 = parse_metric_lines(&String::from_utf8_lossy(&run1.stdout)).unwrap();
    let m2 = parse_metric_lines(&String::from_utf8_lossy(&run2.stdout)).unwrap();
    validate_complete_metrics(&m1).unwrap();
    validate_complete_metrics(&m2).unwrap();

    for &key in IPC_CONSUMPTION_KEYS {
        assert_eq!(
            m1[key].value, m2[key].value,
            "IPC metric `{key}` must be deterministic across identical runs"
        );
    }
}

#[test]
fn tier3_bench_results_md_exists_with_baseline_and_post_opt() {
    let root = crate::workspace_root();
    let content = fs::read_to_string(root.join("BENCHMARK_RESULTS.md"))
        .expect("BENCHMARK_RESULTS.md must exist with baseline and post-optimization results");
    let report = parse_benchmark_results_md(&content)
        .unwrap_or_else(|e| panic!("failed to parse BENCHMARK_RESULTS.md: {e}"));
    assert!(report.baseline.len() >= 16);
    let post = report
        .post_opt
        .expect("BENCHMARK_RESULTS.md must contain post-optimization measurements (M4)");
    assert!(post.len() >= 16);
}

#[test]
fn tier3_bench_cargo_and_xtask_release_and_bench_contract() {
    let root = crate::workspace_root();
    let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    assert!(
        cargo_toml.contains("crates/shell-core"),
        "Cargo.toml must register workspace member crates/shell-core"
    );
    assert!(
        cargo_toml.contains("crates/bench"),
        "Cargo.toml must register workspace member crates/bench"
    );
    assert!(
        cargo_toml.contains("opt-level = 3"),
        "Cargo.toml [profile.release] must set opt-level = 3 (M2 F9)"
    );

    let xtask_src = fs::read_to_string(root.join("xtask/src/main.rs")).expect("xtask/src/main.rs");
    assert!(
        xtask_src.contains("\"bench\""),
        "xtask/src/main.rs must expose a `bench` subcommand (M2 F9)"
    );
    assert!(
        xtask_src.contains("--release"),
        "xtask/src/main.rs must support `--release` (M2 F9)"
    );
}
