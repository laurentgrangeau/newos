//! Opaque-box E2E test suite for `newos-shell-core` (CAOS + `newos-shell-pd` typed pipeline shell).
//!
//! Compile & run offline with:
//! ```bash
//! rustc --edition 2024 --test --crate-name e2e_shell tests/e2e/e2e_shell.rs \
//!   -L dependency=target/e2e \
//!   --extern newos_abi=target/e2e/libnewos_abi.rlib \
//!   --extern newos_shell_core=target/e2e/libnewos_shell_core.rlib \
//!   -o target/e2e/e2e_shell
//! ./target/e2e/e2e_shell
//! ```

#[path = "common/mock_shell_host.rs"]
pub(crate) mod mock_shell_host;

#[path = "shell/tier1_core.rs"]
mod tier1_core;

#[path = "shell/tier2_errors.rs"]
mod tier2_errors;

#[path = "shell/tier3_integration.rs"]
mod tier3_integration;

#[path = "shell/tier4_invariants.rs"]
mod tier4_invariants;
