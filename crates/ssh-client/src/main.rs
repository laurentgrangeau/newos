//! `SSHv2` CLI client (`newos-ssh`).
//!
//! Enforces ONLY:
//! - `mlkem1024-sha3-512` (NIST FIPS 203 ML-KEM-1024 + SHA3-512)
//! - `ssh-mldsa87` (NIST FIPS 204 ML-DSA-87)
//! - `chacha20-poly1305@openssh.com` + `kex-strict`
//!
//! Usage:
//! - `newos-ssh keygen [path]`
//! - `newos-ssh -i <key_path> [--fingerprint <base64>] [-p <port>] <user>@<host>`

use ml_dsa::{B32, Keypair, MlDsa87, SigningKey};
use newos_key_vault::encode_base64_64;
use newos_ssh_proto::{ClientState, SshClient, SshError};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use zeroize::Zeroize;

/// RAII wrapper ensuring secret key/seed buffers are always zeroized on normal return, error, or panic.
struct ZeroizeGuard<T: Zeroize>(T);

impl<T: Zeroize> ZeroizeGuard<T> {
    const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> Deref for ZeroizeGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for ZeroizeGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for ZeroizeGuard<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// RAII wrapper for secret `String` buffers that wipes the backing heap allocation in-place on drop.
struct ZeroizeString(String);

impl ZeroizeString {
    const fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ZeroizeString {
    fn drop(&mut self) {
        let mut bytes = core::mem::take(&mut self.0).into_bytes();
        bytes.as_mut_slice().zeroize();
    }
}

/// Structured error type for `newos-ssh` CLI and protocol operations.
///
/// Intentionally omits `Clone`/`PartialEq`/`Eq` because `std::io::Error` does not implement them.
#[derive(Debug)]
enum ClientError {
    Io {
        context: &'static str,
        detail: Option<String>,
        source: io::Error,
    },
    InvalidSeedLength {
        actual: usize,
    },
    InvalidHexChar,
    MissingFlagValue(&'static str),
    InvalidPort(String),
    UnknownFlag(String),
    MissingKeyPath,
    MissingTarget,
    UnauthenticatedConnectionRefused,
    HostKeyMismatch,
    UnexpectedEofDuringHandshake,
    SshProtocol {
        context: &'static str,
        source: SshError,
    },
}

impl ClientError {
    const fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io {
            context,
            detail: None,
            source,
        }
    }

    fn io_detail(context: &'static str, detail: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context,
            detail: Some(detail.into()),
            source,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                context,
                detail: Some(detail),
                source,
            } => write!(f, "{context} {detail}: {source}"),
            Self::Io {
                context,
                detail: None,
                source,
            } => write!(f, "{context}: {source}"),
            Self::InvalidSeedLength { actual } => write!(
                f,
                "invalid ML-DSA-87 seed length: expected 64 hex chars, got {actual}"
            ),
            Self::InvalidHexChar => f.write_str("invalid hex char"),
            Self::MissingFlagValue(flag) => write!(f, "missing value after `{flag}`"),
            Self::InvalidPort(raw) => write!(f, "invalid port `{raw}`"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag `{flag}`"),
            Self::MissingKeyPath => f.write_str("missing `-i <ml-dsa-87-key>`"),
            Self::MissingTarget => f.write_str("missing `<user>@<host>` target"),
            Self::UnauthenticatedConnectionRefused => f.write_str(
                "refusing unauthenticated connection: pass `--fingerprint SHA3-512:<base64>` \
                 (printed by newos-key-pd at boot) or `--insecure-no-host-key-check`",
            ),
            Self::HostKeyMismatch => f.write_str("HOST KEY FINGERPRINT MISMATCH — aborting!"),
            Self::UnexpectedEofDuringHandshake => {
                f.write_str("server closed connection during handshake")
            }
            Self::SshProtocol { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::SshProtocol { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(source: io::Error) -> Self {
        Self::io("I/O error", source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyPolicy<'a> {
    PinFingerprint(&'a str),
    InsecureNoCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectConfig<'a> {
    key_path: &'a str,
    port: u16,
    host_key_policy: HostKeyPolicy<'a>,
    user: &'a str,
    host: &'a str,
}

const fn hex_nibble(byte: u8) -> Result<u8, ClientError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ClientError::InvalidHexChar),
    }
}

fn fill_os_random(buf: &mut [u8]) -> Result<(), ClientError> {
    let mut f = File::open("/dev/urandom").map_err(|e| ClientError::io("open /dev/urandom", e))?;
    f.read_exact(buf)
        .map_err(|e| ClientError::io("read /dev/urandom", e))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], ClientError> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(ClientError::InvalidSeedLength {
            actual: trimmed.len(),
        });
    }
    let mut out = [0u8; 32];
    let bytes = trimmed.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_connect_args(args: &[String]) -> Result<ConnectConfig<'_>, ClientError> {
    let mut key_path: Option<&str> = None;
    let mut port: u16 = 22;
    let mut expected_fp_b64: Option<&str> = None;
    let mut allow_insecure_no_fp = false;
    let mut target: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                i += 1;
                key_path = Some(
                    args.get(i)
                        .ok_or(ClientError::MissingFlagValue("-i"))?
                        .as_str(),
                );
            }
            "-p" => {
                i += 1;
                let raw_port = args.get(i).ok_or(ClientError::MissingFlagValue("-p"))?;
                port = raw_port
                    .parse::<u16>()
                    .map_err(|_| ClientError::InvalidPort(raw_port.clone()))?;
            }
            "--fingerprint" => {
                i += 1;
                expected_fp_b64 = Some(
                    args.get(i)
                        .ok_or(ClientError::MissingFlagValue("--fingerprint"))?
                        .as_str(),
                );
            }
            "--insecure-no-host-key-check" => {
                allow_insecure_no_fp = true;
            }
            other if !other.starts_with('-') => target = Some(other),
            other => return Err(ClientError::UnknownFlag(other.to_string())),
        }
        i += 1;
    }

    let key_path = key_path.ok_or(ClientError::MissingKeyPath)?;
    let target = target.ok_or(ClientError::MissingTarget)?;
    // Refuse to connect without authenticating the server host key unless explicitly bypassed (`N2`).
    let host_key_policy = match (expected_fp_b64, allow_insecure_no_fp) {
        (Some(fp), _) => HostKeyPolicy::PinFingerprint(fp),
        (None, true) => HostKeyPolicy::InsecureNoCheck,
        (None, false) => return Err(ClientError::UnauthenticatedConnectionRefused),
    };
    let (user, host) = target.split_once('@').unwrap_or(("newos", target));
    Ok(ConnectConfig {
        key_path,
        port,
        host_key_policy,
        user,
        host,
    })
}

fn verify_host_fingerprint(
    policy: HostKeyPolicy<'_>,
    fp: &[u8; 64],
) -> Result<String, ClientError> {
    let b64 = encode_base64_64(fp);
    let b64_str = std::str::from_utf8(&b64).expect("encode_base64_64 always emits ASCII");
    if let HostKeyPolicy::PinFingerprint(want) = policy {
        let want_clean = want.strip_prefix("SHA3-512:").unwrap_or(want);
        if want_clean != b64_str {
            return Err(ClientError::HostKeyMismatch);
        }
    }
    Ok(b64_str.to_string())
}

/// Filter raw terminal escape/control sequences from remote output.
fn sanitize_terminal_output(input: &[u8], out: &mut [u8]) -> usize {
    let mut clean_n = 0;
    for &b in input {
        if clean_n >= out.len() {
            break;
        }
        if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7E).contains(&b) {
            out[clean_n] = b;
            clean_n += 1;
        }
    }
    clean_n
}

fn cmd_keygen(path_arg: Option<&str>) -> Result<(), ClientError> {
    let key_path = PathBuf::from(path_arg.unwrap_or("id_mldsa87"));
    let pub_path = PathBuf::from(format!("{}.pub", key_path.display()));

    let mut raw_seed = ZeroizeGuard::new([0u8; 32]);
    fill_os_random(&mut *raw_seed)?;
    let mut seed = ZeroizeGuard::new(B32::default());
    seed.copy_from_slice(&*raw_seed);
    let sk = SigningKey::<MlDsa87>::from_seed(&seed);
    drop(seed);

    let pk_bytes = sk.verifying_key().encode();
    let seed_hex = ZeroizeString::new(encode_hex(&*raw_seed));
    drop(raw_seed);

    // Create private seed file atomically with mode 0600 on Unix (no default-umask race, `N18`).
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&key_path).map_err(|e| {
            ClientError::io_detail("create (0600)", key_path.display().to_string(), e)
        })?;
        writeln!(f, "{}", seed_hex.as_str())
            .map_err(|e| ClientError::io_detail("write", key_path.display().to_string(), e))?;
    }
    drop(seed_hex);

    let pub_line = format!(
        "ssh-mldsa87 {} newos-user\n",
        encode_hex(pk_bytes.as_slice())
    );
    fs::write(&pub_path, &pub_line)
        .map_err(|e| ClientError::io_detail("write", pub_path.display().to_string(), e))?;

    println!("Generated ML-DSA-87 keypair:");
    println!("  Private seed (0600): {}", key_path.display());
    println!("  Public key:          {}", pub_path.display());
    println!(
        "Add {} to authorized_keys.mldsa87 before building newos-key-pd.",
        pub_path.display()
    );
    Ok(())
}

fn load_signing_key(key_file: &str) -> Result<Box<SigningKey<MlDsa87>>, ClientError> {
    let key_text = ZeroizeString::new(
        fs::read_to_string(key_file).map_err(|e| ClientError::io_detail("read", key_file, e))?,
    );
    let seed_bytes = ZeroizeGuard::new(decode_hex_32(key_text.as_str())?);
    drop(key_text);
    let mut dsa_seed = ZeroizeGuard::new(B32::default());
    dsa_seed.copy_from_slice(&*seed_bytes);
    drop(seed_bytes);
    Ok(Box::new(SigningKey::<MlDsa87>::from_seed(&dsa_seed)))
}

fn flush_client_tx(client: &mut SshClient, stream: &mut TcpStream) -> Result<(), ClientError> {
    while !client.pending_tx().is_empty() {
        let n = stream
            .write(client.pending_tx())
            .map_err(|e| ClientError::io("tcp write", e))?;
        client.consume_tx(n);
    }
    Ok(())
}

fn run_handshake(
    client: &mut SshClient,
    stream: &mut TcpStream,
    policy: HostKeyPolicy<'_>,
    cookie: [u8; 16],
    sign_rnd: &[u8; 32],
) -> Result<(), ClientError> {
    let mut net_buf = [0u8; 4096];
    let mut shell_out = [0u8; 4096];
    let mut printed_fp = false;

    while client.state() != ClientState::ShellOpen {
        flush_client_tx(client, stream)?;
        match stream.read(&mut net_buf) {
            Ok(0) => return Err(ClientError::UnexpectedEofDuringHandshake),
            Ok(n) => {
                let _ = client
                    .feed_rx(&net_buf[..n], cookie, *sign_rnd, &mut shell_out)
                    .map_err(|source| ClientError::SshProtocol {
                        context: "SSH protocol error",
                        source,
                    })?;
                if !printed_fp && let Some(fp) = client.host_fingerprint() {
                    let b64_str = verify_host_fingerprint(policy, &fp)?;
                    eprintln!("[newos-ssh] Host ML-DSA-87 fingerprint: SHA3-512:{b64_str}");
                    printed_fp = true;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(ClientError::io("tcp read", e)),
        }
    }
    Ok(())
}

fn run_shell_session(
    client: &mut SshClient,
    stream: &mut TcpStream,
    cookie: [u8; 16],
    sign_rnd: &[u8; 32],
) -> Result<(), ClientError> {
    eprintln!("[newos-ssh] Connected (mlkem1024-sha3-512 + ssh-mldsa87 + chacha20-poly1305)");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut line = String::new();
    let mut net_buf = [0u8; 4096];
    let mut shell_out = [0u8; 4096];

    loop {
        line.clear();
        let n = stdin
            .read_line(&mut line)
            .map_err(|e| ClientError::io("stdin", e))?;
        if n == 0 {
            break;
        }
        client
            .send_shell_input(line.as_bytes())
            .map_err(|source| ClientError::SshProtocol {
                context: "send shell input",
                source,
            })?;
        flush_client_tx(client, stream)?;
        loop {
            match stream.read(&mut net_buf) {
                Ok(0) => return Ok(()),
                Ok(r) => {
                    let out_n = client
                        .feed_rx(&net_buf[..r], cookie, *sign_rnd, &mut shell_out)
                        .map_err(|source| ClientError::SshProtocol {
                            context: "SSH rx",
                            source,
                        })?;
                    if out_n > 0 {
                        let mut clean = [0u8; 4096];
                        let clean_n = sanitize_terminal_output(&shell_out[..out_n], &mut clean);
                        let _ = stdout.write_all(&clean[..clean_n]);
                        let _ = stdout.flush();
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(ClientError::io("tcp read", e)),
            }
        }
    }
    Ok(())
}

#[inline(never)]
fn create_ssh_client(
    user: &str,
    user_sk: Box<SigningKey<MlDsa87>>,
    kem_seed: [u8; 64],
) -> Box<SshClient> {
    Box::new(SshClient::new(user, *user_sk, None, kem_seed))
}

fn cmd_connect(args: &[String]) -> Result<(), ClientError> {
    let cfg = parse_connect_args(args)?;
    let user_sk = load_signing_key(cfg.key_path)?;

    let mut kem_seed = ZeroizeGuard::new([0u8; 64]);
    fill_os_random(&mut *kem_seed)?;
    let mut cookie = [0u8; 16];
    fill_os_random(&mut cookie)?;
    let mut sign_rnd = ZeroizeGuard::new([0u8; 32]);
    fill_os_random(&mut *sign_rnd)?;

    let mut client = create_ssh_client(cfg.user, user_sk, *kem_seed);
    drop(kem_seed);

    let mut stream = TcpStream::connect((cfg.host, cfg.port))
        .map_err(|e| ClientError::io_detail("connect", format!("{}:{}", cfg.host, cfg.port), e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));

    run_handshake(
        &mut client,
        &mut stream,
        cfg.host_key_policy,
        cookie,
        &sign_rnd,
    )?;
    run_shell_session(&mut client, &mut stream, cookie, &sign_rnd)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(args.get(1).map(String::as_str)),
        Some("-h" | "--help") | None => {
            eprintln!("newos-ssh — SSHv2 Client (ML-KEM-1024 + ML-DSA-87)");
            eprintln!("Usage:");
            eprintln!("  newos-ssh keygen [key_path]");
            eprintln!(
                "  newos-ssh -i <key_path> [--fingerprint <SHA3-512:...>] [-p <port>] <user>@<host>"
            );
            Ok(())
        }
        _ => cmd_connect(&args),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[newos-ssh] error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn hex_encode_and_decode_32_roundtrip_and_reject_invalid() {
        let seed: [u8; 32] = core::array::from_fn(|i| {
            u8::try_from(i)
                .expect("seed index < 32")
                .wrapping_mul(7)
                .wrapping_add(3)
        });
        let hex = encode_hex(&seed);
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_hex_32(&hex).ok(), Some(seed));
        assert_eq!(decode_hex_32(&format!("  {hex}\n")).ok(), Some(seed));

        // Wrong length
        assert!(matches!(
            decode_hex_32("deadbeef"),
            Err(ClientError::InvalidSeedLength { actual: 8 })
        ));
        assert!(matches!(
            decode_hex_32(&format!("{hex}00")),
            Err(ClientError::InvalidSeedLength { actual: 66 })
        ));

        // Non-hex character
        let mut bad = hex;
        bad.replace_range(0..1, "z");
        assert!(matches!(
            decode_hex_32(&bad),
            Err(ClientError::InvalidHexChar)
        ));
    }

    #[test]
    fn parse_connect_args_validates_cli_flags_and_enforces_host_key_check() {
        let s = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();

        // Valid pinned fingerprint + custom port
        let args = s(&[
            "-i",
            "id_mldsa87",
            "-p",
            "2222",
            "--fingerprint",
            "SHA3-512:abc",
            "alice@10.0.2.15",
        ]);
        let cfg = parse_connect_args(&args).expect("valid pinned config");
        assert_eq!(
            cfg,
            ConnectConfig {
                key_path: "id_mldsa87",
                port: 2222,
                host_key_policy: HostKeyPolicy::PinFingerprint("SHA3-512:abc"),
                user: "alice",
                host: "10.0.2.15",
            }
        );

        // Valid insecure opt-in + default user & port
        let args_insec = s(&[
            "-i",
            "id_mldsa87",
            "--insecure-no-host-key-check",
            "10.0.2.15",
        ]);
        let cfg_insec = parse_connect_args(&args_insec).expect("valid insecure opt-in");
        assert_eq!(cfg_insec.user, "newos");
        assert_eq!(cfg_insec.port, 22);
        assert_eq!(cfg_insec.host_key_policy, HostKeyPolicy::InsecureNoCheck);

        // Missing -i
        assert!(matches!(
            parse_connect_args(&s(&["newos@127.0.0.1"])),
            Err(ClientError::MissingKeyPath)
        ));
        // Missing target
        assert!(matches!(
            parse_connect_args(&s(&["-i", "id_mldsa87"])),
            Err(ClientError::MissingTarget)
        ));
        // Invalid port
        assert!(matches!(
            parse_connect_args(&s(&["-i", "id_mldsa87", "-p", "notaport", "u@h"])),
            Err(ClientError::InvalidPort(_))
        ));
        // Unknown flag
        assert!(matches!(
            parse_connect_args(&s(&["--bogus", "-i", "id_mldsa87", "u@h"])),
            Err(ClientError::UnknownFlag(_))
        ));
        // Refuses unauthenticated connection without --fingerprint or --insecure-no-host-key-check
        let err = parse_connect_args(&s(&["-i", "id_mldsa87", "newos@127.0.0.1"])).unwrap_err();
        assert!(matches!(err, ClientError::UnauthenticatedConnectionRefused));
        assert!(
            err.to_string()
                .contains("refusing unauthenticated connection")
        );
    }

    #[test]
    fn verify_host_fingerprint_enforces_pin_and_allows_insecure() {
        let fp = [0x42u8; 64];
        let b64_raw = encode_base64_64(&fp);
        let b64 = std::str::from_utf8(&b64_raw).expect("base64 is ASCII");
        let prefixed = format!("SHA3-512:{b64}");

        assert_eq!(
            verify_host_fingerprint(HostKeyPolicy::PinFingerprint(b64), &fp).ok(),
            Some(b64.to_string())
        );
        assert_eq!(
            verify_host_fingerprint(HostKeyPolicy::PinFingerprint(&prefixed), &fp).ok(),
            Some(b64.to_string())
        );
        assert!(matches!(
            verify_host_fingerprint(HostKeyPolicy::PinFingerprint("SHA3-512:wrong"), &fp),
            Err(ClientError::HostKeyMismatch)
        ));
        assert_eq!(
            verify_host_fingerprint(HostKeyPolicy::InsecureNoCheck, &fp).ok(),
            Some(b64.to_string())
        );
    }

    #[test]
    fn sanitize_terminal_output_strips_escape_and_control_bytes() {
        let input = b"hello\x1b[31m world\x07!\t\r\n";
        let mut out = [0u8; 64];
        let n = sanitize_terminal_output(input, &mut out);
        assert_eq!(&out[..n], b"hello[31m world!\t\r\n");
    }

    #[test]
    fn client_error_display_and_source_work() {
        let io_err = ClientError::from(io::Error::other("disk full"));
        assert!(io_err.source().is_some());
        assert!(io_err.to_string().contains("disk full"));

        let proto_err = ClientError::SshProtocol {
            context: "SSH rx",
            source: SshError::CryptoFailure,
        };
        assert!(proto_err.source().is_some());
        assert!(proto_err.to_string().contains("SSH rx"));

        let flag_err = ClientError::MissingFlagValue("-i");
        assert!(flag_err.source().is_none());
        assert!(flag_err.to_string().contains("-i"));
    }

    #[test]
    fn cmd_keygen_creates_private_seed_0600_and_public_key() {
        let tmp_dir = env::temp_dir().join(format!("newos_ssh_client_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp_dir);
        let key_path = tmp_dir.join("test_id_mldsa87");
        let pub_path = tmp_dir.join("test_id_mldsa87.pub");
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(&pub_path);

        cmd_keygen(key_path.to_str()).expect("keygen should succeed");
        let seed_hex = fs::read_to_string(&key_path).expect("read private seed");
        assert!(decode_hex_32(&seed_hex).is_ok());

        let pub_line = fs::read_to_string(&pub_path).expect("read public key");
        assert!(pub_line.starts_with("ssh-mldsa87 "));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path)
                .expect("stat newly created private seed file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Calling keygen again on existing path must fail (create_new atomic guard)
        assert!(cmd_keygen(key_path.to_str()).is_err());

        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(&pub_path);
        let _ = fs::remove_dir(&tmp_dir);
    }
}
