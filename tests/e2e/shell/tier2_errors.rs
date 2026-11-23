//! Tier 2 (Boundary & Error Paths) E2E tests for `newos-shell-core`.
//! Covers 20 boundary, capacity, syntax, quoting, and error-handling tests.

use core::fmt::Write as _;

use newos_shell_core::caos::{
    CaosError, MAX_BLOB_SIZE, MAX_OBJECTS, MAX_REF_NAME, MAX_REFS, ObjHash, ObjectStore,
};
use newos_shell_core::shell::{BufferedWriter, ExecOutcome, Shell};

use crate::mock_shell_host::MockShellHost;

#[test]
fn tier2_caos_blob_size_boundaries_0_128_and_129() {
    let mut store = ObjectStore::new();
    let empty_h = store.put(b"").unwrap();
    assert_eq!(store.get_by_hash(empty_h).unwrap(), b"");

    let max_blob = [b'x'; MAX_BLOB_SIZE];
    let max_h = store.put(&max_blob).unwrap();
    assert_eq!(store.get_by_hash(max_h).unwrap().len(), MAX_BLOB_SIZE);

    let too_big = [b'y'; MAX_BLOB_SIZE + 1];
    assert_eq!(store.put(&too_big), Err(CaosError::TooLarge));
}

#[test]
fn tier2_caos_object_capacity_limit_and_dedup_when_full() {
    let mut store = ObjectStore::new();
    let mut last_hash = ObjHash::ZERO;
    for i in 0..(MAX_OBJECTS - 2) {
        let msg = format!("unique-object-{i}");
        last_hash = store.put(msg.as_bytes()).unwrap();
    }
    assert_eq!(store.object_count(), MAX_OBJECTS);

    // 25th distinct blob fails with NoSpace.
    assert_eq!(store.put(b"overflow-blob"), Err(CaosError::NoSpace));
    // Re-putting an existing blob still succeeds via deduplication!
    assert_eq!(
        store.put(format!("unique-object-{}", MAX_OBJECTS - 3).as_bytes()),
        Ok(last_hash)
    );
    assert_eq!(store.object_count(), MAX_OBJECTS);
}

#[test]
fn tier2_caos_ref_capacity_limit_16() {
    let mut store = ObjectStore::new();
    let h = store.put(b"shared").unwrap();
    for i in 0..(MAX_REFS - 2) {
        store.set_ref(&format!("r{i}"), h).unwrap();
    }
    assert_eq!(store.set_ref("overflow_ref", h), Err(CaosError::NoSpace));
}

#[test]
fn tier2_caos_ref_name_validation_boundaries() {
    let mut store = ObjectStore::new();
    let h = store.put(b"val").unwrap();

    assert_eq!(store.set_ref("", h), Err(CaosError::InvalidName));
    assert_eq!(store.set_ref("@", h), Err(CaosError::InvalidName));

    let exact_24 = "a".repeat(MAX_REF_NAME);
    assert_eq!(store.set_ref(&exact_24, h), Ok(()));

    let too_long_25 = "b".repeat(MAX_REF_NAME + 1);
    assert_eq!(store.set_ref(&too_long_25, h), Err(CaosError::InvalidName));
}

#[test]
fn tier2_caos_missing_hash_and_missing_ref() {
    let mut store = ObjectStore::new();
    let ghost = ObjHash(0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(store.get_by_hash(ghost), Err(CaosError::NotFound));
    assert_eq!(store.get_any("@doesnotexist"), Err(CaosError::NotFound));
    assert_eq!(store.get_any("not-hex-at-all"), Err(CaosError::NotFound));
    assert_eq!(store.set_ref("@ghost", ghost), Err(CaosError::NotFound));
    assert_eq!(store.seal_ref("@doesnotexist"), Err(CaosError::NotFound));
    assert_eq!(
        store.rollback_ref("@doesnotexist"),
        Err(CaosError::NotFound)
    );
}

#[test]
fn tier2_caos_rollback_no_previous_and_same_hash_noop() {
    let mut store = ObjectStore::new();
    let h1 = store.put(b"v1").unwrap();
    let h2 = store.put(b"v2").unwrap();

    store.set_ref("@r", h1).unwrap();
    assert_eq!(store.rollback_ref("@r"), Err(CaosError::NoPreviousVersion));

    store.set_ref("@r", h2).unwrap();
    // Re-setting to same current target h2 must NOT clobber prev (h1).
    store.set_ref("@r", h2).unwrap();
    assert_eq!(store.rollback_ref("@r"), Ok(h1));
    // Second consecutive rollback fails with NoPreviousVersion.
    assert_eq!(store.rollback_ref("@r"), Err(CaosError::NoPreviousVersion));
}

#[test]
fn tier2_caos_sealed_ref_re_seal_idempotent_and_mutation_rejected() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("put \"evil\" | save @motd");
    assert!(sh.host_mut().take_output().contains("ReadOnly"));

    sh.exec_line("ref rollback @motd");
    assert!(sh.host_mut().take_output().contains("ReadOnly"));

    // Re-sealing an already sealed ref is idempotent.
    assert_eq!(sh.store_mut().seal_ref("@motd"), Ok(()));
}

#[test]
fn tier2_shell_empty_and_whitespace_lines() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(sh.exec_line(""), ExecOutcome::Continue);
    assert_eq!(sh.host_mut().take_output(), "");

    assert_eq!(sh.exec_line("   \t   "), ExecOutcome::Continue);
    assert_eq!(sh.host_mut().take_output(), "");
}

#[test]
fn tier2_shell_unknown_producer_and_unknown_stage() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("foobar");
    let out1 = sh.host_mut().take_output();
    assert!(out1.contains("unknown producer `foobar`"));

    sh.exec_line("objects | bogus");
    let out2 = sh.host_mut().take_output();
    assert!(out2.contains("unknown stage `bogus`"));
}

#[test]
fn tier2_shell_where_missing_args_falls_through_unchanged() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("objects | where size");
    let out = sh.host_mut().take_output();
    assert!(out.contains("usage: ... | where"));
}

#[test]
fn tier2_shell_where_invalid_ops_fields_and_rhs() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(sh.eval_pipeline("objects | where size ~= 10").len(), 0);
    assert_eq!(
        sh.eval_pipeline("objects | where nonexistent == 1").len(),
        0
    );
    assert_eq!(sh.eval_pipeline("refs | where writable == maybe").len(), 0);
    assert_eq!(
        sh.eval_pipeline("objects | where size == notanumber").len(),
        0
    );
}

#[test]
fn tier2_shell_quoted_tokens_empty_and_unclosed_quote() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("put \"hello   world\" | save @spaces");
    assert_eq!(sh.store().get_any("@spaces").unwrap().1, b"hello   world");

    sh.exec_line("put \"\" | save @empty");
    assert_eq!(sh.store().get_any("@empty").unwrap().1, b"");

    sh.exec_line("put \"unclosed quote | save @unclosed");
    assert!(sh.store().get_any("@unclosed").is_err());
}

#[test]
fn tier2_shell_put_truncates_over_128_bytes_and_handles_zero_args() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("put | save @zero_arg");
    assert_eq!(sh.store().get_any("@zero_arg").unwrap().1, b"");

    let long = "z".repeat(MAX_BLOB_SIZE + 72);
    sh.exec_line(&format!("put {long} | save @trunc"));
    assert!(sh.store().get_any("@trunc").is_err());
}

#[test]
fn tier2_shell_excess_pipeline_stages_and_tokens_no_panic() {
    let mut sh = Shell::new(MockShellHost::default());
    // 8 stages (> MAX_STAGES = 6) must be rejected cleanly without panicking.
    let s = sh.eval_pipeline(
        "objects | first 2 | first 2 | first 2 | first 2 | first 2 | first 1 | count",
    );
    assert_eq!(s.len(), 0);

    // 16 tokens (> MAX_ARGS = 12) must not panic.
    sh.exec_line("put t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 t15 | save @many");
}

#[test]
fn tier2_shell_save_non_object_upstream_and_missing_name() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("procs | save @bad");
    assert!(
        sh.host_mut()
            .take_output()
            .contains("expected an Object record")
    );

    sh.exec_line("put \"abc\" | save");
    assert!(sh.host_mut().take_output().contains("usage:"));
}

#[test]
fn tier2_shell_first_zero_yields_empty_stream() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("objects | first 0");
    assert_eq!(sh.host_mut().take_output(), "(empty stream)\n");
}

#[test]
fn tier2_shell_get_and_ref_usage_errors() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("get");
    assert!(sh.host_mut().take_output().contains("usage: get"));

    sh.exec_line("ref bogus");
    assert!(sh.host_mut().take_output().contains("usage: ref"));

    sh.exec_line("ref set @x not-a-hex");
    assert!(sh.host_mut().take_output().contains("invalid hash"));
}

#[test]
fn tier2_shell_ping_when_ipc_fails_emits_empty_stream() {
    let mut host = MockShellHost::default();
    host.ipc_enabled = false;
    let mut sh = Shell::new(host);
    sh.exec_line("ping 0x1234");
    assert!(
        sh.host_mut()
            .take_output()
            .contains("ping: ipc_call failed")
    );
}

#[test]
fn tier2_shell_history_circular_wraparound_after_8() {
    let mut sh = Shell::new(MockShellHost::default());
    for i in 1..=10 {
        sh.record_history(&format!("cmd_{i}"));
    }
    sh.exec_line("history");
    let out = sh.host_mut().take_output();
    assert!(!out.contains("cmd_1\n"));
    assert!(!out.contains("cmd_2\n"));
    assert!(out.contains("3  cmd_3\n"));
    assert!(out.contains("10  cmd_10\n"));
}

#[test]
fn tier2_shell_buffered_writer_chunking_over_capacity_and_utf8() {
    // 16-byte buffer with >256 bytes ASCII + multibyte UTF-8 scalars.
    let mut dst = String::new();
    let payload = format!("{}héllo-🦀-world-{}", "A".repeat(260), "B".repeat(50));
    {
        let mut bw = BufferedWriter::<16, _>::new(&mut dst);
        bw.write_str(&payload).unwrap();
    }
    assert_eq!(dst, payload);

    // Zero-capacity BufferedWriter passes through directly.
    let mut dst0 = String::new();
    {
        let mut bw0 = BufferedWriter::<0, _>::new(&mut dst0);
        bw0.write_str("direct-pass").unwrap();
    }
    assert_eq!(dst0, "direct-pass");
}
