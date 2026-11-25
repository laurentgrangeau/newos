//! Phase 5: Dedicated Regression Test Suite.
//!
//! Organized by security/hardening IDs (`H3`, `H5`, `M12`, `N6`, `N12`) and includes
//! deterministic replay of all committed `fuzz/corpus/` seed and crash files so every
//! discovered fuzz crash remains permanently prevented without requiring libFuzzer.

use newos_abi::ring::SpscRing;
use newos_abi::sha3::sha3_512;
use newos_e2e_tests::DeterministicTestEntropy;
use newos_kernel_core::acpi::{parse_gtdt, parse_madt, parse_mcfg, parse_rsdp, parse_spcr};
use newos_kernel_core::elf::parse_elf64;
use newos_key_vault::{KeyVault, VaultError};
use newos_rng::RngError;
use newos_rng::csprng::verify_entropy_health;
use newos_ssh_proto::wire::WireReader;
use std::path::Path;

/// Regression H3 + N6 + M12: Token bucket burst allows 4 KEX signs, rate-limits the 5th,
/// and unflushable 2048-bit Bloom filter rejects replayed exchange hashes even after 80+ KEXes.
#[test]
fn regression_h3_n6_m12_key_vault_rate_limit_and_unflushable_replay_guard() {
    let mut vault = KeyVault::new(DeterministicTestEntropy(0xCAFE_0001), b"reg-m12", &[]).unwrap();
    let first = sha3_512(b"reg-first-kex");
    assert!(vault.sign_kex_hash(&first, 1_000).is_ok());
    for i in 1u8..4 {
        assert!(vault.sign_kex_hash(&sha3_512(&[i]), 1_050).is_ok());
    }
    assert_eq!(
        vault.sign_kex_hash(&sha3_512(b"burst-5"), 1_050).err(),
        Some(VaultError::RateLimited)
    );
    for i in 10u64..80 {
        assert!(
            vault
                .sign_kex_hash(&sha3_512(&i.to_le_bytes()), 2_000 + (i as i64) * 500)
                .is_ok()
        );
    }
    assert_eq!(
        vault.sign_kex_hash(&first, 100_000).err(),
        Some(VaultError::SessionIdMismatch)
    );
}

/// Regression N12: Linear counter TRNG fault (0,1,2,...) must fail NIST SP 800-90B health checks.
#[test]
fn regression_n12_linear_counter_trng_rejected() {
    let mut counter = [0u8; 64];
    for (i, b) in counter.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        verify_entropy_health(&counter),
        Err(RngError::HealthCheckFailed)
    );
}

/// Regression: `SpscRing` must survive adversarial / corrupted framed byte headers without panicking.
#[test]
fn regression_spsc_ring_corrupted_frame_header_no_panic() {
    let ring = SpscRing::<16>::new();
    // Manually push bogus oversized length header (u64::MAX)
    assert!(ring.try_push(u64::MAX).is_ok());
    let mut out = [0u8; 64];
    assert_eq!(ring.try_pop_bytes(&mut out), None);
}

/// Deterministic Fuzz Corpus Replay: Every file under `fuzz/corpus/` is replayed through
/// its corresponding parser in standard `cargo test` so fuzz crashes become permanent regressions.
#[test]
fn regression_replay_all_fuzz_corpus_seeds() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let corpus_root = workspace_root.join("fuzz").join("corpus");
    if !corpus_root.exists() {
        return;
    }

    type CorpusRunner = (&'static str, fn(&[u8]));
    let targets: &[CorpusRunner] = &[
        ("fuzz_ssh_wire", |data| {
            let mut r = WireReader::new(data);
            let _ = r.read_u8();
            let _ = r.read_u32();
            let _ = r.read_string();
            let _ = r.read_str();
        }),
        ("fuzz_elf_loader", |data| {
            let _ = parse_elf64(data);
        }),
        ("fuzz_acpi_tables", |data| {
            let _ = parse_rsdp(data);
            let _ = parse_spcr(data);
            let _ = parse_madt(data);
            let _ = parse_gtdt(data);
            let _ = parse_mcfg(data);
        }),
    ];

    for (name, runner) in targets {
        let dir = corpus_root.join(name);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    let bytes = std::fs::read(entry.path()).expect("read corpus seed");
                    runner(&bytes);
                }
            }
        }
    }
}
