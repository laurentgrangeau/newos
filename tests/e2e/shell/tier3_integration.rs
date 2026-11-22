//! Tier 3 (Cross-Feature Combinations) E2E tests for `newos-shell-core`.
//! Covers 5 multi-feature integration scenarios.

use core::fmt::Write as _;

use newos_shell_core::shell::{BufferedWriter, Record, Shell};

use crate::mock_shell_host::MockShellHost;

#[test]
fn tier3_shell_five_stage_caos_pipeline_chain() {
    let mut sh = Shell::new(MockShellHost::default());
    let stream = sh.eval_pipeline("put \"payload-v1\" | save @item | where size == 10 | first 1 | count");
    assert!(matches!(stream.first(), Some(Record::Count(1))));
    assert_eq!(sh.store().get_any("@item").unwrap().1, b"payload-v1");
}

#[test]
fn tier3_shell_ping_pipeline_filter_and_count() {
    let mut sh = Shell::new(MockShellHost::default());
    let s1 = sh.eval_pipeline("ping 0x100 | where label == ipc.reply | where value == 0x101 | count");
    assert!(matches!(s1.first(), Some(Record::Count(1))));

    let s2 = sh.eval_pipeline("ping 0x100 | where value > 0x100 | first 1");
    assert_eq!(s2.len(), 1);
}

#[test]
fn tier3_shell_procs_and_sys_consistency_single_vs_multi_proc() {
    let mut sh1 = Shell::new(MockShellHost::new(1, 1));
    assert!(matches!(
        sh1.eval_pipeline("procs | count").first(),
        Some(Record::Count(1))
    ));
    assert!(matches!(
        sh1.eval_pipeline("procs | where pid == 1 | count").first(),
        Some(Record::Count(0))
    ));
    sh1.exec_line("sys");
    assert!(sh1.host_mut().take_output().contains("1 Ring-3 procs"));

    let mut sh2 = Shell::new(MockShellHost::new(4, 2));
    assert!(matches!(
        sh2.eval_pipeline("procs | count").first(),
        Some(Record::Count(2))
    ));
    assert!(matches!(
        sh2.eval_pipeline("procs | where pid == 1 | count").first(),
        Some(Record::Count(1))
    ));
    sh2.exec_line("sys");
    assert!(sh2.host_mut().take_output().contains("2 Ring-3 procs"));
}

#[test]
fn tier3_shell_refs_audit_across_create_update_seal_lifecycle() {
    let mut sh = Shell::new(MockShellHost::default());
    sh.exec_line("put \"alpha\" | save @a");
    sh.exec_line("put \"beta1\" | save @b");
    sh.exec_line("put \"beta2\" | save @b");
    sh.exec_line("put \"gamma\" | save @c");
    sh.exec_line("ref seal @c");

    assert!(matches!(
        sh.eval_pipeline("refs | where writable == false | count")
            .first(),
        Some(Record::Count(3)) // @motd, @guide, @c
    ));
    assert!(matches!(
        sh.eval_pipeline("refs | where writable == true | count")
            .first(),
        Some(Record::Count(2)) // @a, @b
    ));

    // objects | count must agree with sys CAOS object count (2 boot + 4 new = 6).
    assert!(matches!(
        sh.eval_pipeline("objects | count").first(),
        Some(Record::Count(6))
    ));
    sh.host_mut().clear_output();
    sh.exec_line("sys");
    assert!(sh.host_mut().take_output().contains("6 CAOS objects"));
}

#[test]
fn tier3_shell_buffered_writer_reduces_writes_without_truncating_session() {
    struct CountingWriter {
        writes: usize,
        out: String,
    }
    impl core::fmt::Write for CountingWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            self.writes += 1;
            self.out.push_str(s);
            Ok(())
        }
    }

    let mut sh = Shell::new(MockShellHost::default());
    for cmd in ["help", "objects", "refs", "procs", "sys", "ping 0x42"] {
        sh.exec_line(cmd);
    }
    let session_output = sh.host_mut().take_output();
    assert!(session_output.len() > 512);

    // Feed line-by-line through unbuffered vs BufferedWriter<256> and verify exact parity
    // with strictly fewer underlying write_str calls.
    let mut unbuf = CountingWriter {
        writes: 0,
        out: String::new(),
    };
    let mut buf_inner = CountingWriter {
        writes: 0,
        out: String::new(),
    };
    {
        let mut bw = BufferedWriter::<256, _>::new(&mut buf_inner);
        for line in session_output.split_inclusive('\n') {
            unbuf.write_str(line).unwrap();
            bw.write_str(line).unwrap();
        }
    }
    assert_eq!(buf_inner.out, unbuf.out);
    assert!(
        buf_inner.writes < unbuf.writes,
        "BufferedWriter<256> must reduce write calls: buffered={}, unbuffered={}",
        buf_inner.writes,
        unbuf.writes
    );
}
