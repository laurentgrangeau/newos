//! Tier 1 (Feature Coverage) E2E tests for `newos-shell-core` (CAOS + `newos-sh` + pipelines).
//! Covers 22 isolated happy-path tests: 6 CAOS + 10 Shell commands + 6 Pipelines.

use core::fmt::Write as _;

use newos_abi::QemuExitCode;
use newos_shell_core::caos::{CaosError, MAX_OBJECTS, MAX_REFS, ObjHash, ObjectStore};
use newos_shell_core::shell::{BufferedWriter, ExecOutcome, NullWriter, Record, Shell};

use crate::mock_shell_host::MockShellHost;

// ============================================================================
// A. CAOS ObjectStore Direct API (6 tests)
// ============================================================================

#[test]
fn tier1_caos_boot_seeded_refs() {
    let store = ObjectStore::new();
    assert_eq!(store.object_count(), 2);

    let (_, motd) = store.get_any("@motd").unwrap();
    assert_eq!(motd.len(), 63);
    assert!(core::str::from_utf8(motd).unwrap().contains("NewOS"));

    let (_, guide) = store.get_any("@guide").unwrap();
    assert_eq!(guide.len(), 86);

    let mut refs = [None; MAX_REFS];
    let n = store.collect_refs(&mut refs);
    assert_eq!(n, 2);
    for r in refs.iter().take(n).flatten() {
        assert!(!r.writable, "boot refs @motd/@guide must be sealed ro");
        assert!(r.prev.is_none());
    }
}

#[test]
fn tier1_caos_put_get_by_hash_and_hex_formats() {
    let mut store = ObjectStore::new();
    let h = store.put(b"alpha-payload").unwrap();
    assert_ne!(h, ObjHash::ZERO);
    assert_eq!(store.get_by_hash(h).unwrap(), b"alpha-payload");

    let obj_spec = format!("obj:{:016x}", h.0);
    let hex_spec = format!("0x{:016x}", h.0);
    let bare_spec = format!("{:016x}", h.0);
    assert_eq!(store.get_any(&obj_spec).unwrap(), (h, b"alpha-payload".as_slice()));
    assert_eq!(store.get_any(&hex_spec).unwrap(), (h, b"alpha-payload".as_slice()));
    assert_eq!(store.get_any(&bare_spec).unwrap(), (h, b"alpha-payload".as_slice()));
}

#[test]
fn tier1_caos_dedup_identical_content() {
    let mut store = ObjectStore::new();
    let before = store.object_count();
    let h1 = store.put(b"duplicate-blob").unwrap();
    let h2 = store.put(b"duplicate-blob").unwrap();
    assert_eq!(h1, h2);
    assert_eq!(store.object_count(), before + 1);
}

#[test]
fn tier1_caos_ref_create_update_rollback() {
    let mut store = ObjectStore::new();
    let h1 = store.put(b"version-1").unwrap();
    let h2 = store.put(b"version-2").unwrap();

    store.set_ref("@cfg", h1).unwrap();
    assert_eq!(store.get_any("@cfg").unwrap(), (h1, b"version-1".as_slice()));

    store.set_ref("@cfg", h2).unwrap();
    assert_eq!(store.get_any("@cfg").unwrap(), (h2, b"version-2".as_slice()));

    let rolled = store.rollback_ref("@cfg").unwrap();
    assert_eq!(rolled, h1);
    assert_eq!(store.get_any("@cfg").unwrap(), (h1, b"version-1".as_slice()));
}

#[test]
fn tier1_caos_ref_seal_attenuation() {
    let mut store = ObjectStore::new();
    let h1 = store.put(b"locked").unwrap();
    let h2 = store.put(b"tamper").unwrap();
    store.set_ref("@prod", h1).unwrap();
    store.seal_ref("@prod").unwrap();

    // Still readable, but mutation and rollback are rejected with ReadOnly.
    assert_eq!(store.get_any("@prod").unwrap(), (h1, b"locked".as_slice()));
    assert_eq!(store.set_ref("@prod", h2), Err(CaosError::ReadOnly));
    assert_eq!(store.rollback_ref("@prod"), Err(CaosError::ReadOnly));
}

#[test]
fn tier1_caos_collect_objects_and_refs() {
    let mut store = ObjectStore::new();
    let h = store.put(b"snap").unwrap();
    store.set_ref("snapref", h).unwrap();

    let mut objs = [None; MAX_OBJECTS];
    let oc = store.collect_objects(&mut objs);
    assert_eq!(oc, 3);
    assert!(objs[..oc].iter().flatten().any(|m| m.hash == h && m.size == 4));

    let mut refs = [None; MAX_REFS];
    let rc = store.collect_refs(&mut refs);
    assert_eq!(rc, 3);
    assert!(
        refs[..rc]
            .iter()
            .flatten()
            .any(|r| r.name_str() == "snapref" && r.target == h && r.writable)
    );
}

// ============================================================================
// B. Shell Commands & Writers (10 tests)
// ============================================================================

#[test]
fn tier1_shell_put_save_and_get() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(
        sh.exec_line("put \"hello newos\" | save @note"),
        ExecOutcome::Continue
    );
    sh.host_mut().clear_output();

    assert_eq!(sh.exec_line("get @note"), ExecOutcome::Continue);
    let out = sh.host_mut().take_output();
    assert!(out.contains("11 B]"));
    assert!(out.contains("hello newos\n"));
}

#[test]
fn tier1_shell_objects_and_refs_listing() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("objects");
    let out_obj = sh.host_mut().take_output();
    assert!(out_obj.contains("OBJECT HASH           SIZE"));
    assert!(out_obj.contains("63 B"));
    assert!(out_obj.contains("86 B"));

    sh.exec_line("refs");
    let out_ref = sh.host_mut().take_output();
    assert!(out_ref.contains("REF              MODE  TARGET                PREV"));
    assert!(out_ref.contains("@motd"));
    assert!(out_ref.contains("ro  "));
}

#[test]
fn tier1_shell_procs_and_sys() {
    let mut sh = Shell::new(MockShellHost::new(4, 2));
    sh.exec_line("procs");
    let out_p = sh.host_mut().take_output();
    assert!(out_p.contains("PID  EL    ISOLATION        NAME"));
    assert!(out_p.contains("init (newos-sh + CAOS)"));
    assert!(out_p.contains("worker (IPC responder)"));

    sh.exec_line("sys");
    let out_s = sh.host_mut().take_output();
    assert!(out_s.contains("aarch64 (Raspberry Pi 5 16 GB)"));
    assert!(out_s.contains("SMP=4 CPUs"));
    assert!(out_s.contains("2 EL0 procs"));
    assert!(out_s.contains("2 CAOS objects"));
}

#[test]
fn tier1_shell_ref_set_rollback_seal_commands() {
    let mut sh = Shell::new(MockShellHost::default());
    let h1 = sh.store_mut().put(b"v1").unwrap();
    let h2 = sh.store_mut().put(b"v2").unwrap();

    sh.exec_line(&format!("ref set app obj:{:016x}", h1.0));
    assert!(sh.host_mut().take_output().contains("bound @app"));

    sh.exec_line(&format!("ref set app obj:{:016x}", h2.0));
    assert!(sh.host_mut().take_output().contains("bound @app"));

    sh.exec_line("ref rollback app");
    assert!(sh.host_mut().take_output().contains("rolled back @app"));

    sh.exec_line("ref seal app");
    assert!(sh.host_mut().take_output().contains("sealed @app"));
}

#[test]
fn tier1_shell_ping_default_and_explicit_hex() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("ping 0x1234");
    let out1 = sh.host_mut().take_output();
    assert!(out1.contains("ipc.badge"));
    assert!(out1.contains("24084")); // 0x5E14
    assert!(out1.contains("ipc.reply"));
    assert!(out1.contains("4661")); // 0x1235

    sh.exec_line("ping");
    let out2 = sh.host_mut().take_output();
    assert!(out2.contains(&format!("{}", 0xA110_C0DFu64)));
}

#[test]
fn tier1_shell_bench_emits_cycle_metric() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("bench");
    let out = sh.host_mut().take_output();
    assert!(out.contains("ttbr0.switch.avg"));
    assert!(out.contains("cycles"));
    assert!(sh.host().yield_syscalls >= 100);
}

#[test]
fn tier1_shell_help_and_clear() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("help");
    let help_out = sh.host_mut().take_output();
    assert!(help_out.len() > 256, "help text must exceed 256 bytes");
    assert!(help_out.contains("put"));
    assert!(help_out.contains("where"));

    sh.exec_line("clear");
    assert_eq!(sh.host_mut().take_output(), "\x1b[2J\x1b[H");
}

#[test]
fn tier1_shell_exit_and_shutdown_outcomes() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(
        sh.exec_line("exit"),
        ExecOutcome::Exit(QemuExitCode::Success)
    );
    assert!(sh.host_mut().take_output().contains("Shutting down NewOS"));

    assert_eq!(
        sh.exec_line("shutdown"),
        ExecOutcome::Exit(QemuExitCode::Success)
    );
}

#[test]
fn tier1_shell_history_recording_and_listing() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.record_history("sys");
    sh.record_history("procs | count");
    sh.exec_line("history");
    let out = sh.host_mut().take_output();
    assert!(out.contains("1  sys\n"));
    assert!(out.contains("2  procs | count\n"));
}

#[test]
fn tier1_shell_buffered_and_null_writers() {
    let mut null = NullWriter;
    assert!(write!(null, "discarded {}", 123).is_ok());

    let mut backing = String::new();
    {
        let mut bw = BufferedWriter::<64, _>::new(&mut backing);
        write!(bw, "hello ").unwrap();
        write!(bw, "buffered {}", 2024).unwrap();
    } // flush on Drop
    assert_eq!(backing, "hello buffered 2024");
}

// ============================================================================
// C. Typed Pipeline Operators (6 tests)
// ============================================================================

#[test]
fn tier1_pipe_where_u64_all_six_operators() {
    let mut sh = Shell::new(MockShellHost::default());
    // Boot store has sizes 63 (@motd) and 86 (@guide).
    assert_eq!(sh.eval_pipeline("objects | where size == 63").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | where size == 0x3f").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | where size != 63").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | where size > 63").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | where size >= 63").len(), 2);
    assert_eq!(sh.eval_pipeline("objects | where size < 86").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | where size <= 86").len(), 2);
}

#[test]
fn tier1_pipe_where_bool_and_str() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("put \"x\" | save @rw_item");
    assert_eq!(sh.eval_pipeline("refs | where writable == false").len(), 2);
    assert_eq!(sh.eval_pipeline("refs | where writable == true").len(), 1);
    assert_eq!(sh.eval_pipeline("refs | where name == motd").len(), 1);
    assert_eq!(sh.eval_pipeline("refs | where name != motd").len(), 2);
}

#[test]
fn tier1_pipe_save_passthrough_preserves_stream() {
    let mut sh = Shell::new(MockShellHost::default());
    let stream = sh.eval_pipeline("put \"passthrough\" | save @pt | count");
    assert!(matches!(stream.first(), Some(Record::Count(1))));
    assert_eq!(sh.store().get_any("@pt").unwrap().1, b"passthrough");
}

#[test]
fn tier1_pipe_first_default_and_explicit_n() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(sh.eval_pipeline("objects | first").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | first 1").len(), 1);
    assert_eq!(sh.eval_pipeline("objects | first 2").len(), 2);
    assert_eq!(sh.eval_pipeline("objects | first 99").len(), 2);
}

#[test]
fn tier1_pipe_count_on_nonempty_and_empty_streams() {
    let mut sh = Shell::new(MockShellHost::default());
    assert!(matches!(
        sh.eval_pipeline("procs | count").first(),
        Some(Record::Count(2))
    ));
    assert!(matches!(
        sh.eval_pipeline("objects | where size > 9999 | count").first(),
        Some(Record::Count(0))
    ));
}

#[test]
fn tier1_pipe_where_on_count_record() {
    let mut sh = Shell::new(MockShellHost::default());
    assert_eq!(sh.eval_pipeline("procs | count | where count == 2").len(), 1);
    assert_eq!(sh.eval_pipeline("procs | count | where count == 1").len(), 0);
}
