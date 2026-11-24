use std::env;
use std::fs;
use std::path::PathBuf;

const MLDSA87_PK_BYTES: usize = 2592;

fn decode_hex_key(line: &str) -> Option<[u8; MLDSA87_PK_BYTES]> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    // Accept optional `"ssh-mldsa87 "` prefix followed by 5184 hex chars (and optional comment).
    let hex_token = trimmed
        .strip_prefix("ssh-mldsa87 ")
        .unwrap_or(trimmed)
        .split_whitespace()
        .next()?;
    if hex_token.len() != MLDSA87_PK_BYTES * 2 {
        panic!(
            "invalid ML-DSA-87 authorized key length: expected {} hex chars, got {}",
            MLDSA87_PK_BYTES * 2,
            hex_token.len()
        );
    }
    let mut out = [0u8; MLDSA87_PK_BYTES];
    let bytes = hex_token.as_bytes();
    for i in 0..MLDSA87_PK_BYTES {
        let hi = (bytes[i * 2] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex char in authorized key at byte {}", i * 2))
            as u8;
        let lo = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .unwrap_or_else(|| panic!("invalid hex char in authorized key at byte {}", i * 2 + 1))
            as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn main() {
    println!("cargo:rerun-if-env-changed=NEWOS_SSH_AUTHORIZED_KEYS");
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let default_path = workspace_root.join("authorized_keys.mldsa87");
    println!("cargo:rerun-if-changed={}", default_path.display());

    let raw_contents = if let Ok(env_val) = env::var("NEWOS_SSH_AUTHORIZED_KEYS") {
        if std::path::Path::new(&env_val).exists() {
            println!("cargo:rerun-if-changed={env_val}");
            fs::read_to_string(&env_val).expect("failed to read NEWOS_SSH_AUTHORIZED_KEYS file")
        } else {
            env_val
        }
    } else if default_path.exists() {
        fs::read_to_string(&default_path).expect("failed to read authorized_keys.mldsa87")
    } else {
        String::new()
    };

    let mut keys: Vec<[u8; MLDSA87_PK_BYTES]> = Vec::new();
    for line in raw_contents.lines() {
        if let Some(pk) = decode_hex_key(line) {
            keys.push(pk);
        }
    }
    if keys.is_empty() {
        println!(
            "cargo:warning=newos-key-pd: no ML-DSA-87 authorized keys provisioned (fail-closed: all SSH logins will be rejected)"
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut generated = String::from(
        "/// Build-time embedded ML-DSA-87 (FIPS 204) authorized client public keys.\n\
         /// Empty by default (fail-closed: refuses all logins until provisioned).\n\
         pub static AUTHORIZED_KEYS: &[[u8; 2592]] = &[\n",
    );
    for pk in &keys {
        generated.push_str("    [\n");
        for chunk in pk.chunks(16) {
            generated.push_str("        ");
            for b in chunk {
                generated.push_str(&format!("{b:#04x}, "));
            }
            generated.push('\n');
        }
        generated.push_str("    ],\n");
    }
    generated.push_str("];\n");

    // Optional build-time provisioned 32-byte host-key seed (`NEWOS_HOST_KEY_SEED` = 64 hex chars
    // or `host_key.seed` file) so deployments can pin a persistent host fingerprint across reboots.
    println!("cargo:rerun-if-env-changed=NEWOS_HOST_KEY_SEED");
    let seed_path = workspace_root.join("host_key.seed");
    println!("cargo:rerun-if-changed={}", seed_path.display());
    let raw_seed = if let Ok(v) = env::var("NEWOS_HOST_KEY_SEED") {
        Some(v)
    } else if seed_path.exists() {
        Some(fs::read_to_string(&seed_path).expect("failed to read host_key.seed"))
    } else {
        None
    };
    if let Some(hex_seed) = raw_seed.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        assert_eq!(
            hex_seed.len(),
            64,
            "NEWOS_HOST_KEY_SEED must be exactly 64 hex chars (32 bytes)"
        );
        let bytes = hex_seed.as_bytes();
        generated.push_str("pub const HOST_KEY_SEED: Option<[u8; 32]> = Some([\n    ");
        for i in 0..32 {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i * 2 + 1] as char)
                .to_digit(16)
                .expect("invalid hex") as u8;
            generated.push_str(&format!("{:#04x}, ", (hi << 4) | lo));
        }
        generated.push_str("\n]);\n");
    } else {
        generated.push_str("pub const HOST_KEY_SEED: Option<[u8; 32]> = None;\n");
    }

    fs::write(out_dir.join("authorized_keys.rs"), generated)
        .expect("failed to write authorized_keys.rs");
}
