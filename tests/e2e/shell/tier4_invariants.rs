//! Tier 4 (Real-World Application Scenarios & Invariants) E2E tests for `newos-shell-core`.
//! Covers 3 end-to-end operator workflows and behavioral invariants.

use core::fmt::Write as _;

use newos_abi::ShutdownStatus;
use newos_shell_core::caos::{CaosError, ObjHash, ObjectStore};
use newos_shell_core::shell::{BufferedWriter, ExecOutcome, Record, Shell};

use crate::mock_shell_host::MockShellHost;

#[test]
fn tier4_shell_full_interactive_operator_deploy_rollback_seal_session() {
    let mut sh = Shell::new(MockShellHost::new(4, 2));

    let run = |sh: &mut Shell<MockShellHost>, cmd: &str| -> (ExecOutcome, String) {
        sh.record_history(cmd);
        sh.host_mut().clear_output();
        let outcome = sh.exec_line(cmd);
        let out = sh.host_mut().take_output();
        (outcome, out)
    };

    let (o, help_out) = run(&mut sh, "help");
    assert_eq!(o, ExecOutcome::Continue);
    assert!(help_out.len() > 256);

    let (o, sys_out) = run(&mut sh, "sys");
    assert_eq!(o, ExecOutcome::Continue);
    assert!(sys_out.contains("SMP=4 CPUs"));

    let (_, motd_out) = run(&mut sh, "get @motd");
    assert!(motd_out.contains("NewOS"));

    // Deploy v1
    let (_, _) = run(&mut sh, "put \"config v1: mode=safe\" | save @app_cfg");
    let (_, v1_out) = run(&mut sh, "get @app_cfg");
    assert!(v1_out.contains("config v1: mode=safe"));

    // Deploy broken v2
    let (_, _) = run(&mut sh, "put \"config v2: mode=broken\" | save @app_cfg");
    let (_, ref_out) = run(&mut sh, "refs | where name == app_cfg");
    assert!(ref_out.contains("@app_cfg"));
    assert!(ref_out.contains(" rw "));
    assert!(
        !ref_out.contains("  -\n"),
        "updated ref must record PREV hash"
    );

    // Detect failure and rollback to v1
    let (_, rb_out) = run(&mut sh, "ref rollback app_cfg");
    assert!(rb_out.contains("rollback @app_cfg"));
    let (_, restored) = run(&mut sh, "get @app_cfg");
    assert!(restored.contains("config v1: mode=safe"));

    // Seal production config and verify tamper attempt is rejected
    let (_, seal_out) = run(&mut sh, "ref seal app_cfg");
    assert!(seal_out.contains("sealed @app_cfg"));
    let (_, tamper_out) = run(&mut sh, "put \"tamper\" | save @app_cfg");
    assert!(tamper_out.contains("ReadOnly"));

    // Verify IPC health, process isolation, history, and clean exit
    let (_, ping_out) = run(&mut sh, "ping 0xCAFE");
    assert!(ping_out.contains(&format!("{}", 0xCAFFu64)));

    assert!(matches!(
        sh.eval_pipeline("procs | where el == 0 | count").first(),
        Some(Record::Count(2))
    ));

    let (_, hist_out) = run(&mut sh, "history");
    assert!(hist_out.contains("ping 0xCAFE"));

    let (exit_outcome, exit_out) = run(&mut sh, "exit");
    assert_eq!(exit_outcome, ExecOutcome::Exit(ShutdownStatus::Success));
    assert!(exit_out.contains("Shutting down NewOS"));
}

#[test]
fn tier4_shell_self_test_parity_and_caos_determinism_invariants() {
    // 1. Built-in self-test must pass 100% on host MockShellHost.
    let mut sh = Shell::new(MockShellHost::new(2, 2));
    assert_eq!(sh.run_self_test(), Ok(()));

    // 2. Content-hash determinism invariant across independent ObjectStore instances.
    let mut s1 = ObjectStore::new();
    let mut s2 = ObjectStore::new();
    for sample in [b"".as_slice(), b"a", b"newos-caos-invariant", &[0xFF; 128]] {
        let h1 = s1.put(sample).unwrap();
        let h2 = s2.put(sample).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1, ObjHash::hash_bytes(sample));
        assert_ne!(h1, ObjHash::ZERO);
    }

    // 3. Seal irreversibility invariant: once sealed, neither set_ref nor rollback_ref can ever succeed.
    let h_a = s1.put(b"immutable-a").unwrap();
    let h_b = s1.put(b"immutable-b").unwrap();
    s1.set_ref("@sealed_inv", h_a).unwrap();
    s1.set_ref("@sealed_inv", h_b).unwrap();
    s1.seal_ref("@sealed_inv").unwrap();
    for _ in 0..5 {
        assert_eq!(s1.set_ref("@sealed_inv", h_a), Err(CaosError::ReadOnly));
        assert_eq!(s1.rollback_ref("@sealed_inv"), Err(CaosError::ReadOnly));
        assert_eq!(s1.get_any("@sealed_inv").unwrap().0, h_b);
    }
}

#[test]
fn tier4_shell_buffered_vs_unbuffered_exact_output_equivalence() {
    let mut sh = Shell::new(MockShellHost::new(4, 2));
    for i in 0..8 {
        sh.exec_line(&format!("put \"record-item-{i}-payload\" | save @r{i}"));
    }

    // Render objects and refs tables both directly and through BufferedWriter<256> and <32>.
    let obj_stream = sh.eval_pipeline("objects");
    let ref_stream = sh.eval_pipeline("refs");

    let mut direct = String::new();
    obj_stream.render(&mut direct);
    ref_stream.render(&mut direct);
    assert!(
        direct.len() > 256,
        "combined table output must exceed 256 bytes"
    );

    let mut buf256 = String::new();
    {
        let mut bw = BufferedWriter::<256, _>::new(&mut buf256);
        obj_stream.render(&mut bw);
        ref_stream.render(&mut bw);
    }

    let mut buf32 = String::new();
    {
        let mut bw = BufferedWriter::<32, _>::new(&mut buf32);
        obj_stream.render(&mut bw);
        ref_stream.render(&mut bw);
        bw.write_str("").unwrap();
    }

    assert_eq!(buf256, direct);
    assert_eq!(buf32, direct);
}
