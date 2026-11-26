use std::env;
use std::fmt::{self, Write};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MLDSA87_PK_BYTES: usize = 2592;
const HOST_KEY_SEED_BYTES: usize = 32;

#[derive(Debug)]
enum BuildError {
    MissingEnvVar(&'static str),
    MissingWorkspaceRoot,
    Io {
        context: &'static str,
        source: std::io::Error,
    },
    InvalidKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidSeedLength {
        expected: usize,
        actual: usize,
    },
    InvalidHexChar {
        context: &'static str,
        offset: usize,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvVar(var) => write!(f, "missing required environment variable `{var}`"),
            Self::MissingWorkspaceRoot => {
                f.write_str("CARGO_MANIFEST_DIR does not have a workspace root grandparent")
            }
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::InvalidKeyLength { expected, actual } => write!(
                f,
                "invalid ML-DSA-87 authorized key length: expected {expected} hex chars, got {actual}"
            ),
            Self::InvalidSeedLength { expected, actual } => write!(
                f,
                "NEWOS_HOST_KEY_SEED must be exactly {expected} hex chars (32 bytes), got {actual}"
            ),
            Self::InvalidHexChar { context, offset } => {
                write!(f, "invalid hex char in {context} at byte {offset}")
            }
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

const fn parse_hex_nibble(
    byte: u8,
    context: &'static str,
    offset: usize,
) -> Result<u8, BuildError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BuildError::InvalidHexChar { context, offset }),
    }
}

fn decode_hex_key(line: &str) -> Result<Option<[u8; MLDSA87_PK_BYTES]>, BuildError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // Accept optional `"ssh-mldsa87 "` prefix followed by 5184 hex chars (and optional comment).
    let Some(hex_token) = trimmed
        .strip_prefix("ssh-mldsa87 ")
        .unwrap_or(trimmed)
        .split_whitespace()
        .next()
    else {
        return Ok(None);
    };
    let expected = MLDSA87_PK_BYTES * 2;
    if hex_token.len() != expected {
        return Err(BuildError::InvalidKeyLength {
            expected,
            actual: hex_token.len(),
        });
    }
    let mut out = [0u8; MLDSA87_PK_BYTES];
    let bytes = hex_token.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = parse_hex_nibble(bytes[i * 2], "authorized key", i * 2)?;
        let lo = parse_hex_nibble(bytes[i * 2 + 1], "authorized key", i * 2 + 1)?;
        *slot = (hi << 4) | lo;
    }
    Ok(Some(out))
}

fn load_authorized_keys_source(default_path: &Path) -> Result<String, BuildError> {
    if let Ok(env_val) = env::var("NEWOS_SSH_AUTHORIZED_KEYS") {
        if Path::new(&env_val).exists() {
            println!("cargo:rerun-if-changed={env_val}");
            return fs::read_to_string(&env_val).map_err(|source| BuildError::Io {
                context: "failed to read NEWOS_SSH_AUTHORIZED_KEYS file",
                source,
            });
        }
        return Ok(env_val);
    }
    if default_path.exists() {
        return fs::read_to_string(default_path).map_err(|source| BuildError::Io {
            context: "failed to read authorized_keys.mldsa87",
            source,
        });
    }
    Ok(String::new())
}

fn load_host_key_seed(seed_path: &Path) -> Result<Option<String>, BuildError> {
    if let Ok(v) = env::var("NEWOS_HOST_KEY_SEED") {
        return Ok(Some(v));
    }
    if seed_path.exists() {
        let contents = fs::read_to_string(seed_path).map_err(|source| BuildError::Io {
            context: "failed to read host_key.seed",
            source,
        })?;
        return Ok(Some(contents));
    }
    Ok(None)
}

fn run() -> Result<(), BuildError> {
    println!("cargo:rerun-if-env-changed=NEWOS_SSH_AUTHORIZED_KEYS");
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .map_err(|_| BuildError::MissingEnvVar("CARGO_MANIFEST_DIR"))?,
    );
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or(BuildError::MissingWorkspaceRoot)?;
    let default_path = workspace_root.join("authorized_keys.mldsa87");
    println!("cargo:rerun-if-changed={}", default_path.display());

    let raw_contents = load_authorized_keys_source(&default_path)?;
    let mut keys: Vec<[u8; MLDSA87_PK_BYTES]> = Vec::new();
    for line in raw_contents.lines() {
        if let Some(pk) = decode_hex_key(line)? {
            keys.push(pk);
        }
    }
    if keys.is_empty() {
        println!(
            "cargo:warning=newos-key-pd: no ML-DSA-87 authorized keys provisioned (fail-closed: all SSH logins will be rejected)"
        );
    }

    let out_dir =
        PathBuf::from(env::var("OUT_DIR").map_err(|_| BuildError::MissingEnvVar("OUT_DIR"))?);
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
                let _ = write!(generated, "{b:#04x}, ");
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
    let raw_seed = load_host_key_seed(&seed_path)?;
    if let Some(hex_seed) = raw_seed.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let expected = HOST_KEY_SEED_BYTES * 2;
        if hex_seed.len() != expected {
            return Err(BuildError::InvalidSeedLength {
                expected,
                actual: hex_seed.len(),
            });
        }
        let bytes = hex_seed.as_bytes();
        generated.push_str("pub const HOST_KEY_SEED: Option<[u8; 32]> = Some([\n    ");
        for i in 0..HOST_KEY_SEED_BYTES {
            let hi = parse_hex_nibble(bytes[i * 2], "NEWOS_HOST_KEY_SEED", i * 2)?;
            let lo = parse_hex_nibble(bytes[i * 2 + 1], "NEWOS_HOST_KEY_SEED", i * 2 + 1)?;
            let _ = write!(generated, "{:#04x}, ", (hi << 4) | lo);
        }
        generated.push_str("\n]);\n");
    } else {
        generated.push_str("pub const HOST_KEY_SEED: Option<[u8; 32]> = None;\n");
    }

    fs::write(out_dir.join("authorized_keys.rs"), generated).map_err(|source| BuildError::Io {
        context: "failed to write authorized_keys.rs",
        source,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("newos-key-pd build.rs error: {err}");
            ExitCode::FAILURE
        }
    }
}
