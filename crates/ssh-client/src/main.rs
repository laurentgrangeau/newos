//! SSHv2 CLI client (`newos-ssh`).
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
use newos_ssh_proto::{ClientState, SshClient};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use zeroize::Zeroize;

fn fill_os_random(buf: &mut [u8]) -> Result<(), String> {
    let mut f = File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("read /dev/urandom: {e}"))
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

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "invalid ML-DSA-87 seed length: expected 64 hex chars, got {}",
            trimmed.len()
        ));
    }
    let mut out = [0u8; 32];
    let bytes = trimmed.as_bytes();
    for i in 0..32 {
        let hi = (bytes[i * 2] as char)
            .to_digit(16)
            .ok_or("invalid hex char")? as u8;
        let lo = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or("invalid hex char")? as u8;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn cmd_keygen(path_arg: Option<&str>) -> Result<(), String> {
    let key_path = PathBuf::from(path_arg.unwrap_or("id_mldsa87"));
    let pub_path = PathBuf::from(format!("{}.pub", key_path.display()));

    let mut raw_seed = [0u8; 32];
    fill_os_random(&mut raw_seed)?;
    let mut seed = B32::default();
    seed.copy_from_slice(&raw_seed);
    let sk = SigningKey::<MlDsa87>::from_seed(&seed);
    seed.zeroize();

    let pk_bytes = sk.verifying_key().encode();
    let mut seed_hex = encode_hex(&raw_seed);
    raw_seed.zeroize();

    // Create private seed file atomically with mode 0600 on Unix (no default-umask race, `N18`).
    {
        use std::fs::OpenOptions;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&key_path)
            .map_err(|e| format!("create {} (0600): {e}", key_path.display()))?;
        let write_res = writeln!(f, "{seed_hex}");
        seed_hex.zeroize();
        write_res.map_err(|e| format!("write {}: {e}", key_path.display()))?;
    }

    let pub_line = format!(
        "ssh-mldsa87 {} newos-user\n",
        encode_hex(pk_bytes.as_slice())
    );
    fs::write(&pub_path, &pub_line).map_err(|e| format!("write {}: {e}", pub_path.display()))?;

    println!("Generated ML-DSA-87 keypair:");
    println!("  Private seed (0600): {}", key_path.display());
    println!("  Public key:          {}", pub_path.display());
    println!(
        "Add {} to authorized_keys.mldsa87 before building newos-key-pd.",
        pub_path.display()
    );
    Ok(())
}

fn cmd_connect(args: &[String]) -> Result<(), String> {
    let mut key_path: Option<String> = None;
    let mut port: u16 = 22;
    let mut expected_fp_b64: Option<String> = None;
    let mut allow_insecure_no_fp = false;
    let mut target: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-i" => {
                i += 1;
                key_path = Some(args.get(i).ok_or("missing key path after -i")?.clone());
            }
            "-p" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("missing port after -p")?
                    .parse::<u16>()
                    .map_err(|_| "invalid port")?;
            }
            "--fingerprint" => {
                i += 1;
                expected_fp_b64 = Some(
                    args.get(i)
                        .ok_or("missing base64 value after --fingerprint")?
                        .clone(),
                );
            }
            "--insecure-no-host-key-check" => {
                allow_insecure_no_fp = true;
            }
            other if !other.starts_with('-') => target = Some(other.to_string()),
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }

    let key_file = key_path.ok_or("missing `-i <ml-dsa-87-key>`")?;
    let target = target.ok_or("missing `<user>@<host>` target")?;
    // Refuse to connect without authenticating the server host key unless explicitly bypassed (`N2`).
    if expected_fp_b64.is_none() && !allow_insecure_no_fp {
        return Err(
            "refusing unauthenticated connection: pass `--fingerprint SHA3-512:<base64>` \
             (printed by newos-key-pd at boot) or `--insecure-no-host-key-check`"
                .to_string(),
        );
    }
    let (user, host) = target.split_once('@').unwrap_or(("newos", target.as_str()));

    let mut key_text =
        fs::read_to_string(&key_file).map_err(|e| format!("read {key_file}: {e}"))?;
    let mut seed_bytes = decode_hex_32(&key_text)?;
    key_text.zeroize();
    let mut dsa_seed = B32::default();
    dsa_seed.copy_from_slice(&seed_bytes);
    seed_bytes.zeroize();
    let user_sk = SigningKey::<MlDsa87>::from_seed(&dsa_seed);
    dsa_seed.zeroize();

    let mut kem_seed = [0u8; 64];
    fill_os_random(&mut kem_seed)?;
    let mut cookie = [0u8; 16];
    fill_os_random(&mut cookie)?;
    let mut sign_rnd = [0u8; 32];
    fill_os_random(&mut sign_rnd)?;

    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));

    let mut client = SshClient::new(user, user_sk, None, kem_seed);
    kem_seed.zeroize();

    let mut net_buf = [0u8; 4096];
    let mut shell_out = [0u8; 4096];
    let mut printed_fp = false;

    // 1. Complete PQ-only ML-KEM-1024 + ML-DSA-87 handshake & open shell
    while client.state() != ClientState::ShellOpen {
        while !client.pending_tx().is_empty() {
            let n = stream
                .write(client.pending_tx())
                .map_err(|e| format!("tcp write: {e}"))?;
            client.consume_tx(n);
        }
        match stream.read(&mut net_buf) {
            Ok(0) => return Err("server closed connection during handshake".to_string()),
            Ok(n) => {
                let _ = client
                    .feed_rx(&net_buf[..n], cookie, sign_rnd, &mut shell_out)
                    .map_err(|e| format!("SSH protocol error: {e:?}"))?;
                if !printed_fp && let Some(fp) = client.host_fingerprint() {
                    let b64 = encode_base64_64(&fp);
                    let b64_str = std::str::from_utf8(&b64).unwrap_or("?");
                    eprintln!("[newos-ssh] Host ML-DSA-87 fingerprint: SHA3-512:{b64_str}");
                    if let Some(ref want) = expected_fp_b64 {
                        let want_clean = want.strip_prefix("SHA3-512:").unwrap_or(want);
                        if want_clean != b64_str {
                            return Err("HOST KEY FINGERPRINT MISMATCH — aborting!".to_string());
                        }
                    }
                    printed_fp = true;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(format!("tcp read: {e}")),
        }
    }

    eprintln!("[newos-ssh] Connected (mlkem1024-sha3-512 + ssh-mldsa87 + chacha20-poly1305)");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let n = stdin
            .read_line(&mut line)
            .map_err(|e| format!("stdin: {e}"))?;
        if n == 0 {
            break;
        }
        client
            .send_shell_input(line.as_bytes())
            .map_err(|e| format!("send shell input: {e:?}"))?;
        while !client.pending_tx().is_empty() {
            let w = stream
                .write(client.pending_tx())
                .map_err(|e| format!("tcp write: {e}"))?;
            client.consume_tx(w);
        }
        loop {
            match stream.read(&mut net_buf) {
                Ok(0) => return Ok(()),
                Ok(r) => {
                    let out_n = client
                        .feed_rx(&net_buf[..r], cookie, sign_rnd, &mut shell_out)
                        .map_err(|e| format!("SSH rx: {e:?}"))?;
                    if out_n > 0 {
                        // Filter raw terminal escape/control sequences from remote output.
                        let mut clean = [0u8; 4096];
                        let mut clean_n = 0;
                        for &b in &shell_out[..out_n] {
                            if b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7E).contains(&b)
                            {
                                clean[clean_n] = b;
                                clean_n += 1;
                            }
                        }
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
                Err(e) => return Err(format!("tcp read: {e}")),
            }
        }
    }
    Ok(())
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
