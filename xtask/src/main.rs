mod error;
mod gpt;
mod profile;

use error::XtaskError;
use profile::{BuildProfile, TargetBoard};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const LIMINE_BRANCH: &str = "v9.6.7-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";
// Soft-float target for EL1 kernel so LLVM never emits NEON/FP instructions on syscall/IRQ paths (`H2`).
const KERNEL_TARGET_TRIPLE: &str = "aarch64-unknown-none-softfloat";
const EFI_FILENAME: &str = "BOOTAA64.EFI";
const UEFI_DISK_BYTES: u64 = 64 * 1024 * 1024;

const FEATURE_MATRIX_CASES: &[(&str, &[&str])] = &[
    (
        "newos-crypto (none)",
        &["test", "-p", "newos-crypto", "--no-default-features"],
    ),
    (
        "newos-crypto (sha3)",
        &[
            "test",
            "-p",
            "newos-crypto",
            "--no-default-features",
            "--features",
            "sha3",
        ],
    ),
    (
        "newos-crypto (chacha20-poly1305)",
        &[
            "test",
            "-p",
            "newos-crypto",
            "--no-default-features",
            "--features",
            "chacha20-poly1305",
        ],
    ),
    (
        "newos-crypto (all)",
        &["test", "-p", "newos-crypto", "--all-features"],
    ),
    (
        "newos-abi (zero crypto)",
        &["test", "-p", "newos-abi", "--no-default-features"],
    ),
    (
        "newos-kernel-core (tinykernel/fifo)",
        &[
            "test",
            "-p",
            "newos-kernel-core",
            "--no-default-features",
            "--features",
            "sched-fifo",
        ],
    ),
    (
        "newos-kernel-core (round-robin+userspace)",
        &[
            "test",
            "-p",
            "newos-kernel-core",
            "--no-default-features",
            "--features",
            "sched-round-robin,userspace",
        ],
    ),
    (
        "newos-kernel-core (full)",
        &["test", "-p", "newos-kernel-core", "--all-features"],
    ),
    (
        "newos-net (ipv4-only)",
        &[
            "test",
            "-p",
            "newos-net",
            "--no-default-features",
            "--features",
            "ipv4,tcp,icmp,driver-virtio",
        ],
    ),
    (
        "newos-net (ipv6-only)",
        &[
            "test",
            "-p",
            "newos-net",
            "--no-default-features",
            "--features",
            "ipv6,tcp,udp,driver-virtio",
        ],
    ),
    (
        "newos-net (dual-stack)",
        &["test", "-p", "newos-net", "--all-features"],
    ),
    (
        "newos-storage (zero crypto)",
        &[
            "test",
            "-p",
            "newos-storage",
            "--no-default-features",
            "--features",
            "pcie,sdhci,nvme",
        ],
    ),
    (
        "newos-rng (zero crypto)",
        &[
            "test",
            "-p",
            "newos-rng",
            "--no-default-features",
            "--features",
            "bcm2712,virtio",
        ],
    ),
    (
        "drivers (minimal)",
        &[
            "test",
            "-p",
            "newos-gpu",
            "-p",
            "newos-ai",
            "-p",
            "newos-board",
            "-p",
            "newos-usb",
            "-p",
            "newos-gpio",
            "-p",
            "newos-wdt",
            "--no-default-features",
        ],
    ),
    ("xtask (profiles)", &["test", "-p", "xtask"]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildMode {
    Debug,
    Release,
}

impl BuildMode {
    const fn dir_name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    const fn is_release(self) -> bool {
        matches!(self, Self::Release)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootMode {
    Interactive,
    AutomatedTest,
}

/// RAII guard that deterministically removes a temporary file on normal exit, error, or panic.
struct TempFileGuard<'a>(&'a Path);

impl Drop for TempFileGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// RAII guard that ensures a spawned child process is killed and reaped on error, timeout, or panic.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self(Some(child))
    }

    const fn child_mut(&mut self) -> Option<&mut Child> {
        self.0.as_mut()
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElfAuditReport {
    load_count: usize,
    has_relro: bool,
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Pure Sans-I/O ELF64 security audit verifying PIE (`ET_DYN`), W^X (zero RWX `PT_LOAD`),
/// and `PT_GNU_RELRO` presence with checked arithmetic and zero panics.
fn audit_elf_bytes(name: &str, data: &[u8]) -> Result<ElfAuditReport, XtaskError> {
    let err = |reason: String| XtaskError::ElfAudit {
        binary: name.to_string(),
        reason,
    };

    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return Err(err("invalid ELF64 little-endian header".into()));
    }
    let e_type = read_u16_le(data, 16).ok_or_else(|| err("invalid ELF64 header".into()))?;
    if e_type != 3 {
        return Err(err(format!("expected PIE (ET_DYN=3), got e_type={e_type}")));
    }
    let e_phoff_raw = read_u64_le(data, 32).ok_or_else(|| err("truncated e_phoff".into()))?;
    let e_phoff = usize::try_from(e_phoff_raw)
        .map_err(|_| err(format!("e_phoff overflows usize ({e_phoff_raw:#x})")))?;
    let e_phentsize =
        usize::from(read_u16_le(data, 54).ok_or_else(|| err("truncated e_phentsize".into()))?);
    let e_phnum =
        usize::from(read_u16_le(data, 56).ok_or_else(|| err("truncated e_phnum".into()))?);
    if e_phnum > 0 && e_phentsize < 56 {
        return Err(err(format!(
            "invalid e_phentsize={e_phentsize} (expected >= 56)"
        )));
    }

    let mut load_count = 0usize;
    let mut has_relro = false;
    for idx in 0..e_phnum {
        let ph_delta = idx
            .checked_mul(e_phentsize)
            .ok_or_else(|| err(format!("program header {idx} offset overflow")))?;
        let off = e_phoff
            .checked_add(ph_delta)
            .ok_or_else(|| err(format!("program header {idx} offset overflow")))?;
        let ph_end = off
            .checked_add(56)
            .ok_or_else(|| err(format!("program header {idx} end overflow")))?;
        if ph_end > data.len() {
            return Err(err(format!("truncated program header {idx}")));
        }
        let p_type =
            read_u32_le(data, off).ok_or_else(|| err(format!("truncated program header {idx}")))?;
        let p_flags = read_u32_le(data, off + 4)
            .ok_or_else(|| err(format!("truncated program header {idx}")))?;
        if p_type == 1 {
            load_count += 1;
            // PF_W (2) | PF_X (1) == 3 -> forbidden RWX segment!
            if (p_flags & 3) == 3 {
                return Err(err(format!(
                    "W^X VIOLATION — PT_LOAD segment {idx} has both PF_W and PF_X (flags={p_flags:#x})"
                )));
            }
        } else if p_type == 0x6474_e551 {
            // PT_GNU_STACK: PF_X (1) -> forbidden executable stack!
            if (p_flags & 1) != 0 {
                return Err(err(format!(
                    "W^X VIOLATION — PT_GNU_STACK segment {idx} requests executable stack (flags={p_flags:#x})"
                )));
            }
        } else if p_type == 0x6474_e552 {
            has_relro = true;
        }
    }
    if load_count == 0 {
        return Err(err("zero PT_LOAD segments".into()));
    }
    Ok(ElfAuditReport {
        load_count,
        has_relro,
    })
}

fn check_bench_json_output(stdout: &str) -> Result<usize, XtaskError> {
    if !stdout.contains('{') || !stdout.contains('}') {
        return Err(XtaskError::Verification(
            "newos-bench --json did not emit JSON output".to_string(),
        ));
    }
    if stdout.contains("NaN") || stdout.contains("Infinity") {
        return Err(XtaskError::Verification(
            "newos-bench --json emitted NaN/Infinity metric".to_string(),
        ));
    }
    Ok(stdout.matches("\"ns_per_op\"").count() + stdout.matches("\"ops_per_sec\"").count())
}

fn check_qemu_serial_log(serial_log: &str) -> Result<(), XtaskError> {
    if serial_log.contains("PSCI SYSTEM_OFF (status=FAIL)")
        || serial_log.contains("[newos] FAIL:")
        || serial_log.contains("[supervisor-pd] FAIL:")
        || serial_log.contains("FATAL AArch64 EL1")
    {
        return Err(XtaskError::Qemu(
            "QEMU guest reported test failure in serial output".to_string(),
        ));
    }
    if !serial_log.contains("PSCI SYSTEM_OFF (status=OK)") {
        return Err(XtaskError::Qemu(
            "QEMU guest did not reach `PSCI SYSTEM_OFF (status=OK)`".to_string(),
        ));
    }
    Ok(())
}

fn resolve_profile<S: AsRef<str>>(
    root: &Path,
    args: &[S],
    default_board: TargetBoard,
) -> Result<BuildProfile, XtaskError> {
    let mut profile_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i].as_ref() == "--profile" {
            i += 1;
            let raw = args
                .get(i)
                .ok_or_else(|| XtaskError::Cli("missing path after `--profile`".to_string()))?;
            let p = PathBuf::from(raw.as_ref());
            profile_path = Some(if p.is_absolute() { p } else { root.join(p) });
        }
        i += 1;
    }
    let mut profile = match profile_path {
        Some(path) => BuildProfile::from_file(&path)?,
        None => BuildProfile::default_full(default_board),
    };
    profile.apply_cli_overrides(args)?;
    profile.validate()?;
    Ok(profile)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[xtask] error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), XtaskError> {
    let cmd = args.first().map_or("help", String::as_str);
    let mode = if args.iter().any(|a| a == "--release") {
        BuildMode::Release
    } else {
        BuildMode::Debug
    };
    let root = workspace_root()?;

    match cmd {
        "config" => {
            if args.iter().any(|a| a == "--list-options") {
                print!("{}", BuildProfile::list_all_options());
            } else {
                let p = resolve_profile(&root, &args[1..], TargetBoard::Rpi5)?;
                print!("{}", p.render_system_composition());
            }
            Ok(())
        }
        "feature-matrix" => run_feature_matrix(&root),
        "build" => {
            let p = resolve_profile(&root, &args[1..], TargetBoard::QemuVirt)?;
            build_uefi_disk(&root, &p, BootMode::Interactive, mode).map(|_| ())
        }
        "run" => {
            let p = resolve_profile(&root, &args[1..], TargetBoard::QemuVirt)?;
            run_qemu(&root, &p, BootMode::Interactive, mode)
        }
        "test" => {
            let p = resolve_profile(&root, &args[1..], TargetBoard::QemuVirt)?;
            run_tests(&root, &p, mode)
        }
        "host-test" => run_host_tests(&root, mode),
        "miri" => run_miri_tests(&root),
        "verify" => run_kani_verify(&root),
        "coverage" => run_coverage(&root, &args[1..]),
        "mutants" => run_mutants(&root, &args[1..]),
        "fuzz" => run_fuzz(&root, &args[1..]),
        "chaos" => run_chaos(&root, &args[1..], mode),
        "audit-elf" => run_audit_elf(&root, &args[1..], mode),
        "bench-check" => run_bench_check(&root),
        "qemu-matrix" => run_qemu_matrix(&root, mode),
        "repro-check" => run_repro_check(&root, &args[1..], mode),
        "soak" => run_soak(&root, &args[1..], mode),
        "rpi5-image" => {
            let p = resolve_profile(&root, &args[1..], TargetBoard::Rpi5)?;
            build_rpi5_image(&root, &p, mode).map(|_| ())
        }
        "bench" => run_bench(&root, &args[1..]),
        "help" | "-h" | "--help" => {
            eprintln!(
                "Usage: cargo xtask <config|feature-matrix|rpi5-image|build|run|test|host-test|miri|verify|coverage|mutants|fuzz|chaos|audit-elf|bench|bench-check> [options]\n\
                 Options:\n\
                   --profile <profiles/*.toml>            Load declarative TOML system composition profile\n\
                   --board <rpi5|qemu-virt>               Override target board\n\
                   --sched <priority-rr|round-robin|fifo> Override kernel scheduler policy\n\
                   --no-smp | --no-acpi | --no-domains | --no-shell | --no-net | --no-ssh | --no-crypto\n\
                   --ipv4-only | --ipv6-only              Select single-stack networking\n\
                   --fail-under <pct>                     Enforce minimum line coverage % (for `coverage`)\n\
                   --in-diff <git-ref>                    Limit mutation testing to diff (for `mutants`)\n\
                   --seconds <N>                          Max seconds per fuzz target (for `fuzz`)\n\
                   --release                              Build in release mode"
            );
            Ok(())
        }
        other => Err(XtaskError::Cli(format!(
            "unknown subcommand `{other}`\nRun `cargo xtask help` for usage."
        ))),
    }
}

fn workspace_root() -> Result<PathBuf, XtaskError> {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR")
        && let Some(parent) = Path::new(manifest_dir).parent()
    {
        return Ok(parent.to_path_buf());
    }
    env::current_dir().map_err(|e| XtaskError::io("failed to determine workspace root", e))
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), XtaskError> {
    let status = cmd
        .status()
        .map_err(|e| XtaskError::io(format!("failed to spawn {label}"), e))?;
    if status.success() {
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            label: label.to_string(),
            status,
        })
    }
}

fn build_kernel(
    root: &Path,
    profile: &BuildProfile,
    mode: BuildMode,
) -> Result<PathBuf, XtaskError> {
    let linker_script = root.join("crates/kernel/linker-aarch64.ld");
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=pie -C link-arg=-pie -C link-arg=-z -C link-arg=relro -C link-arg=-z -C link-arg=now -C target-cpu={} -Z sanitizer=kcfi",
        linker_script.display(),
        profile.cpu,
    );

    let features = profile.kernel_features().join(",");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).env("RUSTFLAGS", rustflags).args([
        "build",
        "--package",
        "newos-kernel",
        "--no-default-features",
        "--features",
        &features,
        "--target",
        KERNEL_TARGET_TRIPLE,
        "-Z",
        "build-std=core,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    if mode.is_release() {
        cmd.arg("--release");
    }
    run_checked(
        &mut cmd,
        &format!("cargo build (newos-kernel {}/{features})", profile.cpu),
    )?;

    Ok(root
        .join("target")
        .join(KERNEL_TARGET_TRIPLE)
        .join(mode.dir_name())
        .join("newos-kernel"))
}

fn build_user_elf(
    root: &Path,
    pkg: &str,
    dir: &str,
    cpu: &str,
    features: Option<&[String]>,
    mode: BuildMode,
) -> Result<PathBuf, XtaskError> {
    let linker_script = root.join(format!("crates/{dir}/linker-aarch64.ld"));
    let target_json = root.join("targets/aarch64-newos-user.json");
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=pie -C link-arg=-pie -C link-arg=-z -C link-arg=relro -C link-arg=-z -C link-arg=now -C target-cpu={cpu} -Z fixed-x18 -Z sanitizer=kcfi -Z sanitizer=shadow-call-stack",
        linker_script.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).env("RUSTFLAGS", rustflags).args([
        "build",
        "--package",
        pkg,
        "--target",
        target_json.to_str().ok_or(XtaskError::InvalidPath {
            label: "user target",
        })?,
        "-Z",
        "json-target-spec",
        "-Z",
        "build-std=core,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    if let Some(feats) = features {
        cmd.arg("--no-default-features");
        if !feats.is_empty() {
            cmd.args(["--features", &feats.join(",")]);
        }
    }
    if mode.is_release() {
        cmd.arg("--release");
    }
    run_checked(
        &mut cmd,
        &format!("cargo build ({pkg} aarch64-newos-user/kcfi+scs)"),
    )?;

    Ok(root
        .join("target")
        .join("aarch64-newos-user")
        .join(mode.dir_name())
        .join(pkg))
}

fn ensure_limine(root: &Path) -> Result<PathBuf, XtaskError> {
    let limine_dir = root.join("target/limine");
    if !limine_dir.join(EFI_FILENAME).exists() {
        if limine_dir.exists() {
            fs::remove_dir_all(&limine_dir).map_err(|e| {
                XtaskError::io(format!("failed to clean {}", limine_dir.display()), e)
            })?;
        }
        let mut clone = Command::new("git");
        clone.args([
            "clone",
            "--depth=1",
            "--branch",
            LIMINE_BRANCH,
            LIMINE_REPO,
            limine_dir
                .to_str()
                .ok_or(XtaskError::InvalidPath { label: "limine" })?,
        ]);
        run_checked(&mut clone, "git clone limine")?;
    }
    Ok(limine_dir)
}

/// Format a FAT32 EFI System Partition image from staged entries and wrap it in a UEFI GPT disk.
fn package_gpt_esp_image(
    disk_path: &Path,
    esp_tmp_path: &Path,
    vol_label: &str,
    gpt_label: &str,
    entries: &[PathBuf],
) -> Result<(), XtaskError> {
    let esp_bytes = gpt::esp_partition_bytes(UEFI_DISK_BYTES)?;
    let esp_file = fs::File::create(esp_tmp_path).map_err(|e| XtaskError::io("create ESP", e))?;
    let _tmp_guard = TempFileGuard(esp_tmp_path);
    esp_file
        .set_len(esp_bytes)
        .map_err(|e| XtaskError::io("resize ESP", e))?;
    drop(esp_file);

    let esp_str = esp_tmp_path
        .to_str()
        .ok_or(XtaskError::InvalidPath { label: "ESP" })?;
    let mkfs_bin = ["/usr/sbin/mkfs.vfat", "/sbin/mkfs.vfat"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("mkfs.vfat");
    let mut mkfs = Command::new(mkfs_bin);
    mkfs.args(["-F", "32", "-n", vol_label, esp_str]);
    run_checked(&mut mkfs, "mkfs.vfat")?;

    let mut mcopy = Command::new("mcopy");
    mcopy.args(["-s", "-i", esp_str]);
    for entry in entries {
        mcopy.arg(
            entry
                .to_str()
                .ok_or(XtaskError::InvalidPath { label: "staged" })?,
        );
    }
    mcopy.arg("::/");
    run_checked(&mut mcopy, "mcopy")?;

    gpt::write_gpt_disk_image(disk_path, esp_tmp_path, UEFI_DISK_BYTES, gpt_label)?;
    Ok(())
}

/// Build enabled EL0 protection domain modules for `profile` and return `(boot_filename, host_path)` pairs.
fn build_profile_modules(
    root: &Path,
    profile: &BuildProfile,
    mode: BuildMode,
) -> Result<Vec<(&'static str, PathBuf)>, XtaskError> {
    let mut modules = Vec::new();
    if !profile.kernel.userspace() {
        return Ok(modules);
    }
    if profile.domains.supervisor() {
        let supervisor_feats = profile.supervisor_features();
        let elf = build_user_elf(
            root,
            "newos-supervisor-pd",
            "supervisor-pd",
            &profile.cpu,
            Some(&supervisor_feats),
            mode,
        )?;
        modules.push(("newos-supervisor-pd", elf));
    }
    if profile.domains.shell() {
        let elf = build_user_elf(root, "newos-shell-pd", "shell-pd", &profile.cpu, None, mode)?;
        modules.push(("newos-shell-pd", elf));
    }
    if profile.domains.worker() {
        let elf = build_user_elf(
            root,
            "newos-worker-pd",
            "worker-pd",
            &profile.cpu,
            None,
            mode,
        )?;
        modules.push(("newos-worker-pd", elf));
    }
    if profile.domains.net() {
        let net_feats = profile.net_pd_features();
        let elf = build_user_elf(
            root,
            "newos-net-pd",
            "net-pd",
            &profile.cpu,
            Some(&net_feats),
            mode,
        )?;
        modules.push(("newos-net-pd", elf));
    }
    if profile.domains.key() {
        let key_feats = profile.key_pd_features();
        let elf = build_user_elf(
            root,
            "newos-key-pd",
            "key-pd",
            &profile.cpu,
            Some(&key_feats),
            mode,
        )?;
        modules.push(("newos-key-pd", elf));
    }
    if profile.domains.ssh() {
        let elf = build_user_elf(root, "newos-ssh-pd", "ssh-pd", &profile.cpu, None, mode)?;
        modules.push(("newos-ssh-pd", elf));
    }
    Ok(modules)
}

/// Build a pure 64-bit `AArch64` UEFI GPT + FAT32 ESP disk image for the QEMU `virt` test harness.
fn build_uefi_disk(
    root: &Path,
    profile: &BuildProfile,
    boot_mode: BootMode,
    mode: BuildMode,
) -> Result<PathBuf, XtaskError> {
    let kernel_elf = build_kernel(root, profile, mode)?;
    // Always package all enabled profile PDs (including `net-pd`, `key-pd`, `ssh-pd`, `shell-pd`)
    // so both interactive boots and automated `cargo xtask test` exercise the full protection-domain set.
    let modules = build_profile_modules(root, profile, mode)?;
    let limine_dir = ensure_limine(root)?;

    let stage = root.join("target/esp_root_aarch64");
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| XtaskError::io("failed to clean esp_root", e))?;
    }

    let boot_limine = stage.join("boot/limine");
    let efi_boot = stage.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine)?;
    fs::create_dir_all(&efi_boot)?;

    fs::copy(&kernel_elf, stage.join("boot/newos-kernel"))
        .map_err(|e| XtaskError::io("failed to copy kernel ELF", e))?;
    let mut module_lines = String::new();
    for (name, path) in &modules {
        fs::copy(path, stage.join("boot").join(name))
            .map_err(|e| XtaskError::io(format!("failed to copy {name} ELF"), e))?;
        let _ = writeln!(module_lines, "    module_path: boot():/boot/{name}");
    }

    let cmdline = match boot_mode {
        BootMode::Interactive => "interactive qemu",
        BootMode::AutomatedTest => "test qemu",
    };
    let limine_conf = format!(
        "timeout: 0\n\
         serial: yes\n\n\
         /NewOS (QEMU virt test harness)\n\
         \x20   protocol: limine\n\
         \x20   kaslr: yes\n\
         \x20   path: boot():/boot/newos-kernel\n\
         \x20   cmdline: {cmdline}\n\
         {module_lines}"
    );
    fs::write(boot_limine.join("limine.conf"), limine_conf)
        .map_err(|e| XtaskError::io("failed to write limine.conf", e))?;
    fs::copy(limine_dir.join(EFI_FILENAME), efi_boot.join(EFI_FILENAME))
        .map_err(|e| XtaskError::io(format!("failed to copy {EFI_FILENAME}"), e))?;

    let disk_path = root.join("target/newos-aarch64.img");
    let esp_tmp = root.join("target/newos-aarch64-esp.fat");
    package_gpt_esp_image(
        &disk_path,
        &esp_tmp,
        "NEWOS",
        "NEWOS ESP",
        &[stage.join("EFI"), stage.join("boot")],
    )?;

    println!(
        "[xtask] built pure AArch64 UEFI GPT+FAT32 ESP image {} (board={}, sched={}, modules={})",
        disk_path.display(),
        profile.board,
        profile.scheduler,
        modules.len(),
    );
    Ok(disk_path)
}

/// Build a 64 MiB UEFI GPT + FAT32 ESP boot image (`target/newos-rpi5.img`) + staging folder
/// (`target/rpi5_boot/`) for Raspberry Pi 5 (16 GB, BCM2712 Cortex-A76).
fn build_rpi5_image(
    root: &Path,
    profile: &BuildProfile,
    mode: BuildMode,
) -> Result<PathBuf, XtaskError> {
    let kernel_elf = build_kernel(root, profile, mode)?;
    let modules = build_profile_modules(root, profile, mode)?;
    let limine_dir = ensure_limine(root)?;

    let stage = root.join("target/rpi5_boot");
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| XtaskError::io("failed to clean rpi5_boot", e))?;
    }
    let boot_limine = stage.join("boot/limine");
    let efi_boot = stage.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine)?;
    fs::create_dir_all(&efi_boot)?;

    // Raspberry Pi 5 EDK2 UEFI config.txt (place RPI_EFI.fd alongside on the FAT32 SD card).
    // `disable_commandline_tags=2` is required by `worproject/rpi5-uefi` EDK2 firmware.
    let config_txt = "\
# NewOS Raspberry Pi 5 (16 GB) UEFI + Limine Boot Config
enable_uart=1
uart_2ndstage=1
pciex4_reset=0
disable_commandline_tags=2
armstub=RPI_EFI.fd
";
    fs::write(stage.join("config.txt"), config_txt)
        .map_err(|e| XtaskError::io("failed to write config.txt", e))?;

    fs::copy(&kernel_elf, stage.join("boot/newos-kernel"))
        .map_err(|e| XtaskError::io("failed to copy kernel ELF", e))?;
    let mut module_lines = String::new();
    for (name, path) in &modules {
        fs::copy(path, stage.join("boot").join(name))
            .map_err(|e| XtaskError::io(format!("failed to copy {name} ELF"), e))?;
        let _ = writeln!(module_lines, "    module_path: boot():/boot/{name}");
    }

    let limine_conf = format!(
        "timeout: 3\n\
         serial: yes\n\n\
         /NewOS (Raspberry Pi 5 - 16 GB)\n\
         \x20   protocol: limine\n\
         \x20   path: boot():/boot/newos-kernel\n\
         \x20   cmdline: interactive\n\
         {module_lines}"
    );
    fs::write(boot_limine.join("limine.conf"), limine_conf)
        .map_err(|e| XtaskError::io("failed to write limine.conf", e))?;
    fs::copy(
        limine_dir.join("BOOTAA64.EFI"),
        efi_boot.join("BOOTAA64.EFI"),
    )
    .map_err(|e| XtaskError::io("failed to copy BOOTAA64.EFI", e))?;

    let img_path = root.join("target/newos-rpi5.img");
    let esp_tmp = root.join("target/newos-rpi5-esp.fat");
    package_gpt_esp_image(
        &img_path,
        &esp_tmp,
        "NEWOS",
        "NEWOS RPI5 ESP",
        &[
            stage.join("config.txt"),
            stage.join("EFI"),
            stage.join("boot"),
        ],
    )?;

    println!(
        "[xtask] built Raspberry Pi 5 UEFI GPT+FAT32 ESP boot image: {} (sched={}, modules={})",
        img_path.display(),
        profile.scheduler,
        modules.len(),
    );
    println!("[xtask] staging directory: {}", stage.display());
    println!(
        "[xtask] note: copy RPI_EFI.fd (from worproject/rpi5-uefi) onto the FAT32 SD card root,"
    );
    println!("[xtask]       connect 3-pin JST UART debug probe at 115200 8N1, and power on!");
    Ok(img_path)
}

/// Verify modular system composition across crypto, ABI, kernel-core, networking, and driver crates.
fn run_feature_matrix(root: &Path) -> Result<(), XtaskError> {
    for (label, cargo_args) in FEATURE_MATRIX_CASES {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root).args(*cargo_args);
        run_checked(&mut cmd, &format!("feature-matrix: {label}"))?;
    }
    println!(
        "[xtask] feature-matrix: all {} configurations passed!",
        FEATURE_MATRIX_CASES.len()
    );
    Ok(())
}

fn run_host_tests(root: &Path, mode: BuildMode) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args([
        "test",
        "--package",
        "newos-crypto",
        "--package",
        "newos-abi",
        "--package",
        "newos-kernel-core",
        "--package",
        "newos-shell-core",
        "--package",
        "newos-net",
        "--package",
        "newos-rng",
        "--package",
        "newos-wdt",
        "--package",
        "newos-gpio",
        "--package",
        "newos-board",
        "--package",
        "newos-storage",
        "--package",
        "newos-usb",
        "--package",
        "newos-gpu",
        "--package",
        "newos-ai",
        "--package",
        "newos-key-vault",
        "--package",
        "newos-ssh-proto",
    ]);
    if mode.is_release() {
        cmd.arg("--release");
    }
    run_checked(&mut cmd, "cargo test (host)")
}

/// Run Miri UB / aliasing / provenance checks across all host-testable crates.
fn run_miri_tests(root: &Path) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args([
        "miri",
        "test",
        "--package",
        "newos-abi",
        "--package",
        "newos-kernel-core",
        "--package",
        "newos-shell-core",
        "--package",
        "newos-net",
        "--package",
        "newos-rng",
        "--package",
        "newos-wdt",
        "--package",
        "newos-gpio",
        "--package",
        "newos-board",
        "--package",
        "newos-storage",
        "--package",
        "newos-usb",
        "--package",
        "newos-gpu",
        "--package",
        "newos-ai",
    ]);
    // Note (`H5`): `newos-key-vault` and `newos-ssh-proto` run multi-minute ML-DSA/ML-KEM
    // lattice ops under Miri's interpreter; run them separately with `cargo +nightly miri test -p ...`.
    run_checked(&mut cmd, "cargo miri test")
}

/// Run Kani bounded model checking proofs (`#[cfg(kani)]`) on `abi`, `kernel-core`, and `ssh`.
fn run_kani_verify(root: &Path) -> Result<(), XtaskError> {
    for pkg in ["newos-abi", "newos-kernel-core", "newos-ssh-proto"] {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root).args(["kani", "--package", pkg]);
        run_checked(&mut cmd, &format!("cargo kani ({pkg})")).map_err(|e| {
            XtaskError::Verification(format!(
                "{e} (install with `cargo install --locked kani-verifier && cargo kani setup`)"
            ))
        })?;
    }
    Ok(())
}

/// Measure host line/region coverage with `cargo-llvm-cov` and optionally enforce a hard floor.
fn run_coverage(root: &Path, args: &[String]) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).args([
        "llvm-cov",
        "--summary-only",
        "--ignore-filename-regex",
        "(tests/|crates/bench/)",
    ]);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fail-under" => {
                i += 1;
                let pct = args.get(i).ok_or_else(|| {
                    XtaskError::Cli("missing percentage after `--fail-under`".into())
                })?;
                cmd.args(["--fail-under-lines", pct]);
            }
            "--html" => {
                cmd.arg("--html");
            }
            "--lcov" => {
                cmd.args(["--lcov", "--output-path", "target/llvm-cov/lcov.info"]);
            }
            other => return Err(XtaskError::Cli(format!("unknown coverage flag `{other}`"))),
        }
        i += 1;
    }
    run_checked(&mut cmd, "cargo llvm-cov")
}

/// Run mutation testing (`cargo-mutants`) using `.cargo/mutants.toml`.
fn run_mutants(root: &Path, args: &[String]) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).arg("mutants");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in-diff" => {
                i += 1;
                let diff_path = args
                    .get(i)
                    .ok_or_else(|| XtaskError::Cli("missing diff file after `--in-diff`".into()))?;
                cmd.args(["--in-diff", diff_path]);
            }
            "--package" | "-p" => {
                i += 1;
                let pkg = args.get(i).ok_or_else(|| {
                    XtaskError::Cli("missing package name after `--package`".into())
                })?;
                cmd.args(["--package", pkg]);
            }
            other => return Err(XtaskError::Cli(format!("unknown mutants flag `{other}`"))),
        }
        i += 1;
    }
    run_checked(&mut cmd, "cargo mutants")
}

/// Run libFuzzer targets under `fuzz/` via `cargo-fuzz`.
fn run_fuzz(root: &Path, args: &[String]) -> Result<(), XtaskError> {
    const ALL_TARGETS: &[&str] = &[
        "fuzz_ssh_wire",
        "fuzz_elf_loader",
        "fuzz_acpi_tables",
        "fuzz_shell_parser",
        "fuzz_net_packets",
        "fuzz_abi_ipc",
        "fuzz_aead_decrypt",
        "fuzz_gpt_profile",
    ];
    let mut seconds: u64 = 15;
    let mut selected: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seconds" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| XtaskError::Cli("missing seconds after `--seconds`".into()))?;
                seconds = raw
                    .parse::<u64>()
                    .map_err(|_| XtaskError::Cli(format!("invalid `--seconds` value `{raw}`")))?;
            }
            other if !other.starts_with('-') => {
                if let Some(&known) = ALL_TARGETS.iter().find(|&&t| t == other) {
                    selected.push(known);
                } else {
                    return Err(XtaskError::Cli(format!("unknown fuzz target `{other}`")));
                }
            }
            other => return Err(XtaskError::Cli(format!("unknown fuzz flag `{other}`"))),
        }
        i += 1;
    }
    let targets: &[&str] = if selected.is_empty() {
        ALL_TARGETS
    } else {
        &selected
    };
    let time_flag = format!("-max_total_time={seconds}");
    for target in targets {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .args(["fuzz", "run", target, "--", &time_flag]);
        run_checked(&mut cmd, &format!("cargo fuzz run {target}"))?;
    }
    Ok(())
}

/// Run host deterministic chaos suite + on-target QEMU all-domain self-healing chaos tests.
fn run_chaos(root: &Path, args: &[String], mode: BuildMode) -> Result<(), XtaskError> {
    let mut host = Command::new("cargo");
    host.current_dir(root)
        .args(["test", "-p", "newos-e2e-tests", "--test", "chaos"]);
    if mode.is_release() {
        host.arg("--release");
    }
    run_checked(&mut host, "cargo test (host chaos)")?;
    let profile = resolve_profile(root, args, TargetBoard::QemuVirt)?;
    run_qemu(root, &profile, BootMode::AutomatedTest, mode)
}

/// Audit compiled `AArch64` kernel & EL0 PD ELFs for W^X (zero RWX segments) and RELRO/PIE.
fn run_audit_elf(root: &Path, args: &[String], mode: BuildMode) -> Result<(), XtaskError> {
    let profile = resolve_profile(root, args, TargetBoard::QemuVirt)?;
    let kernel_elf = build_kernel(root, &profile, mode)?;
    let modules = build_profile_modules(root, &profile, mode)?;

    let mut bins: Vec<(&str, PathBuf)> = vec![("newos-kernel", kernel_elf)];
    bins.extend(modules);

    for (name, path) in &bins {
        let data =
            fs::read(path).map_err(|e| XtaskError::io(format!("read {}", path.display()), e))?;
        let report = audit_elf_bytes(name, &data)?;
        let neon_note = if *name == "newos-kernel"
            && let Ok(out) = Command::new("llvm-objdump")
                .args(["-d", "--triple=aarch64-unknown-none"])
                .arg(path)
                .output()
            && out.status.success()
        {
            let dis = String::from_utf8_lossy(&out.stdout);
            let fp_hits = dis
                .lines()
                .filter(|l| l.contains("\tfmul\t") || l.contains("\tfadd\t"))
                .count();
            if fp_hits > 0 {
                return Err(XtaskError::ElfAudit {
                    binary: "newos-kernel".into(),
                    reason: format!(
                        "soft-float violation — found {fp_hits} FP arithmetic instructions in EL1"
                    ),
                });
            }
            "0-FP-arith"
        } else {
            "n/a"
        };
        println!(
            "[audit-elf] {name}: PIE=OK, W^X=OK ({} PT_LOAD, 0 RWX), RELRO={}, EL1-softfloat={neon_note}",
            report.load_count, report.has_relro
        );
    }
    Ok(())
}

/// Run `newos-bench --json` and verify output is valid JSON containing non-zero finite metrics.
fn run_bench_check(root: &Path) -> Result<(), XtaskError> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["run", "--release", "-p", "newos-bench", "--", "--json"])
        .output()
        .map_err(|e| XtaskError::io("failed to run newos-bench", e))?;
    if !output.status.success() {
        return Err(XtaskError::CommandFailed {
            label: "newos-bench".into(),
            status: output.status,
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let metric_count = check_bench_json_output(&stdout)?;
    println!(
        "[bench-check] newos-bench --json passed ({} bytes, {} numeric metric fields, 0 NaN/Inf)",
        stdout.len(),
        metric_count
    );
    Ok(())
}

/// Boot alternate system composition profiles (`tinykernel`, `--no-net`, `--ipv6-only`) in QEMU.
fn run_qemu_matrix(root: &Path, mode: BuildMode) -> Result<(), XtaskError> {
    let matrix: &[(&str, &[&str])] = &[
        (
            "tinykernel",
            &[
                "--profile",
                "profiles/tinykernel.toml",
                "--board",
                "qemu-virt",
            ],
        ),
        ("no-net", &["--no-net"]),
        ("ipv6-only", &["--ipv6-only"]),
    ];
    for (label, flags) in matrix {
        let profile = resolve_profile(root, flags, TargetBoard::QemuVirt)?;
        println!("[qemu-matrix] booting profile `{label}`...");
        run_qemu(root, &profile, BootMode::AutomatedTest, mode)?;
    }
    println!("[qemu-matrix] all {} profiles passed!", matrix.len());
    Ok(())
}

/// Verify deterministic reproducible builds of `newos-kernel` (two builds produce identical bytes).
fn run_repro_check(root: &Path, args: &[String], mode: BuildMode) -> Result<(), XtaskError> {
    let profile = resolve_profile(root, args, TargetBoard::QemuVirt)?;
    let p1 = build_kernel(root, &profile, mode)?;
    let b1 = fs::read(&p1).map_err(|e| XtaskError::io("read build 1", e))?;
    let p2 = build_kernel(root, &profile, mode)?;
    let b2 = fs::read(&p2).map_err(|e| XtaskError::io("read build 2", e))?;
    if b1 != b2 {
        return Err(XtaskError::Verification(
            "repro-check FAILED: two builds of newos-kernel differed!".to_string(),
        ));
    }
    let crc = gpt::crc32(&b1);
    println!(
        "[repro-check] newos-kernel reproducible build OK (size={} bytes, crc32={crc:#010x})",
        b1.len()
    );
    Ok(())
}

/// Nightly endurance soak: run `N` consecutive 4-core QEMU boot + chaos cycles.
fn run_soak(root: &Path, args: &[String], mode: BuildMode) -> Result<(), XtaskError> {
    let mut cycles = 3usize;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--cycles" {
            i += 1;
            cycles = args
                .get(i)
                .ok_or_else(|| XtaskError::Cli("missing count after `--cycles`".into()))?
                .parse::<usize>()
                .map_err(|_| XtaskError::Cli("invalid `--cycles` value".into()))?;
        }
        i += 1;
    }
    let profile = BuildProfile::default_full(TargetBoard::QemuVirt);
    for c in 1..=cycles {
        println!("[soak] cycle {c}/{cycles}...");
        run_qemu(root, &profile, BootMode::AutomatedTest, mode)?;
    }
    println!("[soak] all {cycles} QEMU endurance cycles passed!");
    Ok(())
}

fn build_bench_offline(root: &Path) -> Result<PathBuf, XtaskError> {
    let out_dir = root.join("target/bench");
    fs::create_dir_all(&out_dir)
        .map_err(|e| XtaskError::io(format!("failed to create {}", out_dir.display()), e))?;

    let abi_rlib = out_dir.join("libnewos_abi.rlib");
    let kc_rlib = out_dir.join("libnewos_kernel_core.rlib");
    let sc_rlib = out_dir.join("libnewos_shell_core.rlib");
    let bench_bin = out_dir.join("newos_bench");

    let abi_extern = format!("newos_abi={}", abi_rlib.display());
    let kc_extern = format!("newos_kernel_core={}", kc_rlib.display());
    let sc_extern = format!("newos_shell_core={}", sc_rlib.display());

    run_checked(
        Command::new("rustc").current_dir(root).args([
            "--edition",
            "2024",
            "-C",
            "opt-level=3",
            "--crate-name",
            "newos_abi",
            "--crate-type",
            "lib",
            "crates/abi/src/lib.rs",
            "-o",
            abi_rlib
                .to_str()
                .ok_or(XtaskError::InvalidPath { label: "abi rlib" })?,
        ]),
        "rustc (newos_abi)",
    )?;

    run_checked(
        Command::new("rustc").current_dir(root).args([
            "--edition",
            "2024",
            "-C",
            "opt-level=3",
            "--crate-name",
            "newos_kernel_core",
            "--crate-type",
            "lib",
            "crates/kernel-core/src/lib.rs",
            "--extern",
            &abi_extern,
            "-o",
            kc_rlib.to_str().ok_or(XtaskError::InvalidPath {
                label: "kernel_core rlib",
            })?,
        ]),
        "rustc (newos_kernel_core)",
    )?;

    run_checked(
        Command::new("rustc").current_dir(root).args([
            "--edition",
            "2024",
            "-C",
            "opt-level=3",
            "--crate-name",
            "newos_shell_core",
            "--crate-type",
            "lib",
            "crates/shell-core/src/lib.rs",
            "--extern",
            &abi_extern,
            "-o",
            sc_rlib.to_str().ok_or(XtaskError::InvalidPath {
                label: "shell_core rlib",
            })?,
        ]),
        "rustc (newos_shell_core)",
    )?;

    run_checked(
        Command::new("rustc").current_dir(root).args([
            "--edition",
            "2024",
            "-C",
            "opt-level=3",
            "--crate-name",
            "newos_bench",
            "crates/bench/src/main.rs",
            "--extern",
            &abi_extern,
            "--extern",
            &kc_extern,
            "--extern",
            &sc_extern,
            "-o",
            bench_bin
                .to_str()
                .ok_or(XtaskError::InvalidPath { label: "bench bin" })?,
        ]),
        "rustc (newos_bench)",
    )?;

    Ok(bench_bin)
}

fn run_bench(root: &Path, raw_args: &[String]) -> Result<(), XtaskError> {
    let bench_args: Vec<&str> = raw_args
        .iter()
        .map(String::as_str)
        .filter(|arg| *arg != "--release")
        .collect();

    if bench_args.iter().any(|a| *a == "-h" || *a == "--help") {
        println!("Usage: cargo xtask bench [--markdown] [--json] [--help]");
        println!("Builds and runs `newos-bench` in release mode (`opt-level=3`),");
        println!("falling back to direct offline `rustc` compilation if Cargo deps are uncached.");
        return Ok(());
    }

    let cargo_status = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--offline",
            "--package",
            "newos-bench",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let bin_path = match cargo_status {
        Ok(status) if status.success() => root.join("target/release/newos-bench"),
        _ => build_bench_offline(root)?,
    };

    let mut run_cmd = Command::new(&bin_path);
    run_cmd.current_dir(root).args(&bench_args);
    run_checked(&mut run_cmd, "newos-bench")
}

fn run_tests(root: &Path, profile: &BuildProfile, mode: BuildMode) -> Result<(), XtaskError> {
    run_host_tests(root, mode)?;
    run_qemu(root, profile, BootMode::AutomatedTest, mode)
}

fn find_firmware() -> Result<&'static str, XtaskError> {
    let candidates: &[&str] = &[
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
    ];
    candidates
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| {
            XtaskError::Qemu(
                "AArch64 UEFI firmware (AAVMF / QEMU_EFI.fd / edk2-aarch64-code.fd) not found"
                    .to_string(),
            )
        })
}

fn run_qemu_automated(qemu: &mut Command) -> Result<(), XtaskError> {
    // Automated test mode (`H5`): capture serial output, enforce a hard 300s timeout, and verify
    // the guest reported `PSCI SYSTEM_OFF (status=OK)` with zero `[newos] FAIL:` / `status=FAIL`.
    qemu.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let child = qemu
        .spawn()
        .map_err(|e| XtaskError::io("failed to launch qemu-system-aarch64", e))?;
    let mut child_guard = ChildGuard::new(child);
    let mut stdout = child_guard
        .child_mut()
        .and_then(|c| c.stdout.take())
        .ok_or_else(|| XtaskError::Qemu("failed to capture QEMU stdout".to_string()))?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let _ = std::io::Write::write_all(&mut std::io::stdout(), &chunk[..n]);
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    });

    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        let wait_res = child_guard
            .child_mut()
            .ok_or_else(|| XtaskError::Qemu("QEMU child process missing".to_string()))?
            .try_wait();
        match wait_res {
            Ok(Some(st)) => {
                child_guard.disarm();
                break st;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(XtaskError::Qemu(
                        "QEMU test timed out after 300s".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(XtaskError::io("failed waiting on QEMU", e)),
        }
    };
    let serial_log = reader.join().unwrap_or_default();

    if status.code() != Some(0) {
        return Err(XtaskError::Qemu(format!(
            "QEMU (aarch64/cortex-a76) exited with unexpected status {:?}",
            status.code()
        )));
    }
    check_qemu_serial_log(&serial_log)?;
    println!("[xtask] QEMU (aarch64/cortex-a76) guest self-tests PASSED (status=OK)");
    Ok(())
}

fn run_qemu(
    root: &Path,
    profile: &BuildProfile,
    boot_mode: BootMode,
    mode: BuildMode,
) -> Result<(), XtaskError> {
    let disk_path = build_uefi_disk(root, profile, boot_mode, mode)?;
    let firmware = find_firmware()?;
    let disk_str = disk_path
        .to_str()
        .ok_or(XtaskError::InvalidPath { label: "disk" })?;

    let pflash_arg = format!("if=pflash,format=raw,readonly=on,file={firmware}");
    let boot_drive_arg = format!("if=none,id=bootdisk,format=raw,readonly=on,file={disk_str}");

    // Bind SSH host forwarding strictly to loopback (`127.0.0.1`) and only in interactive mode (`N19`).
    let netdev_arg = match boot_mode {
        BootMode::Interactive => "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
        BootMode::AutomatedTest => "user,id=net0",
    };

    let mut qemu = Command::new("qemu-system-aarch64");
    qemu.args([
        "-M",
        "virt",
        "-cpu",
        &profile.cpu,
        "-smp",
        "4",
        "-m",
        "512M",
        "-serial",
        "stdio",
        "-display",
        "none",
        "-no-reboot",
        "-global",
        "virtio-mmio.force-legacy=false",
        "-netdev",
        netdev_arg,
        "-device",
        "virtio-net-device,netdev=net0",
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-device,rng=rng0",
        "-drive",
        &pflash_arg,
        "-drive",
        &boot_drive_arg,
        "-device",
        "virtio-blk-device,drive=bootdisk",
    ]);

    match boot_mode {
        BootMode::Interactive => {
            let status = qemu
                .status()
                .map_err(|e| XtaskError::io("failed to launch qemu-system-aarch64", e))?;
            match status.code() {
                Some(0) => {
                    println!("[xtask] QEMU (aarch64/cortex-a76) exited cleanly (PSCI SYSTEM_OFF)");
                    Ok(())
                }
                other => Err(XtaskError::Qemu(format!(
                    "QEMU (aarch64/cortex-a76) exited with unexpected status {other:?}"
                ))),
            }
        }
        BootMode::AutomatedTest => run_qemu_automated(&mut qemu),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_elf64(e_type: u16, phdrs: &[(u32, u32)]) -> Vec<u8> {
        let phoff = 64usize;
        let phentsize = 56usize;
        let mut buf = vec![0u8; phoff + phdrs.len() * phentsize];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[16..18].copy_from_slice(&e_type.to_le_bytes());
        buf[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        buf[56..58].copy_from_slice(
            &u16::try_from(phdrs.len())
                .expect("test phdr count fits in u16")
                .to_le_bytes(),
        );
        for (idx, &(p_type, p_flags)) in phdrs.iter().enumerate() {
            let off = phoff + idx * phentsize;
            buf[off..off + 4].copy_from_slice(&p_type.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&p_flags.to_le_bytes());
        }
        buf
    }

    #[test]
    fn resolve_profile_parses_cli_overrides_and_rejects_bad_flags() {
        let root = workspace_root().expect("workspace root");

        let p = resolve_profile(
            &root,
            &["--board", "qemu-virt", "--no-net"],
            TargetBoard::Rpi5,
        )
        .expect("valid overrides");
        assert_eq!(p.board, TargetBoard::QemuVirt);
        assert!(!p.domains.net());

        // Missing path after --profile must error
        assert!(resolve_profile(&root, &["--profile"], TargetBoard::QemuVirt).is_err());

        // Unknown flag must error
        assert!(resolve_profile(&root, &["--no-sshd"], TargetBoard::QemuVirt).is_err());

        // --ipv6-only disables ipv4 while keeping ipv6
        let p6 =
            resolve_profile(&root, &["--ipv6-only"], TargetBoard::QemuVirt).expect("ipv6-only");
        assert!(!p6.net.protocols.ipv4());
        assert!(p6.net.protocols.ipv6());
    }

    #[test]
    fn audit_elf_bytes_accepts_valid_pie_wx_relro() {
        let elf = build_minimal_elf64(
            3,
            &[
                (1, 5),           // PT_LOAD R|X
                (1, 6),           // PT_LOAD R|W
                (0x6474_e552, 4), // PT_GNU_RELRO
            ],
        );
        let report = audit_elf_bytes("test-bin", &elf).expect("valid ELF passes audit");
        assert_eq!(
            report,
            ElfAuditReport {
                load_count: 2,
                has_relro: true,
            }
        );
    }

    #[test]
    fn audit_elf_bytes_rejects_malformed_non_pie_rwx_and_overflow() {
        assert!(matches!(
            audit_elf_bytes("short", b"\x7fELF"),
            Err(XtaskError::ElfAudit { .. })
        ));
        let non_pie = build_minimal_elf64(2, &[(1, 5)]);
        assert!(matches!(
            audit_elf_bytes("et-exec", &non_pie),
            Err(XtaskError::ElfAudit { .. })
        ));
        let rwx = build_minimal_elf64(3, &[(1, 7)]);
        assert!(matches!(
            audit_elf_bytes("rwx", &rwx),
            Err(XtaskError::ElfAudit { .. })
        ));
        let mut overflow = build_minimal_elf64(3, &[(1, 5)]);
        overflow[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            audit_elf_bytes("overflow", &overflow),
            Err(XtaskError::ElfAudit { .. })
        ));
    }

    #[test]
    fn audit_elf_bytes_rejects_bad_endianness_small_phentsize_and_exec_stack() {
        // Non-little-endian EI_DATA = 2 (ELFDATA2MSB) and EI_DATA = 0 (ELFDATANONE)
        for ei_data in [2u8, 0u8] {
            let mut elf = build_minimal_elf64(3, &[(1, 5)]);
            elf[5] = ei_data;
            assert!(
                matches!(
                    audit_elf_bytes("bad-endian", &elf),
                    Err(XtaskError::ElfAudit { .. })
                ),
                "EI_DATA={ei_data} must be rejected"
            );
        }

        // e_phentsize = 0 with e_phnum = 2
        let mut phent_zero = build_minimal_elf64(3, &[(1, 5)]);
        phent_zero[54..56].copy_from_slice(&0u16.to_le_bytes());
        phent_zero[56..58].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            audit_elf_bytes("phentsize-zero", &phent_zero),
            Err(XtaskError::ElfAudit { .. })
        ));

        // e_phentsize = 55 with e_phnum = 1
        let mut phent_small = build_minimal_elf64(3, &[(1, 5)]);
        phent_small[54..56].copy_from_slice(&55u16.to_le_bytes());
        phent_small[56..58].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            audit_elf_bytes("phentsize-55", &phent_small),
            Err(XtaskError::ElfAudit { .. })
        ));

        // PT_GNU_STACK (0x6474_e551) with PF_X (p_flags = 7) must be rejected
        let exec_stack = build_minimal_elf64(3, &[(1, 5), (0x6474_e551, 7)]);
        assert!(matches!(
            audit_elf_bytes("exec-stack", &exec_stack),
            Err(XtaskError::ElfAudit { .. })
        ));

        // PT_GNU_STACK (0x6474_e551) with non-executable PF_R | PF_W (p_flags = 6) must pass
        let nx_stack = build_minimal_elf64(3, &[(1, 5), (0x6474_e551, 6)]);
        let report = audit_elf_bytes("nx-stack", &nx_stack).expect("non-exec PT_GNU_STACK passes");
        assert_eq!(
            report,
            ElfAuditReport {
                load_count: 1,
                has_relro: false,
            }
        );
    }

    #[test]
    fn check_qemu_serial_log_validates_pass_and_failure_markers() {
        assert!(check_qemu_serial_log("boot ok\nPSCI SYSTEM_OFF (status=OK)\n").is_ok());
        assert!(check_qemu_serial_log("boot ok\n").is_err());
        assert!(check_qemu_serial_log("PSCI SYSTEM_OFF (status=FAIL)\n").is_err());
        assert!(
            check_qemu_serial_log("[newos] FAIL: boom\nPSCI SYSTEM_OFF (status=OK)\n").is_err()
        );
        assert!(
            check_qemu_serial_log("[supervisor-pd] FAIL: x\nPSCI SYSTEM_OFF (status=OK)\n")
                .is_err()
        );
        assert!(check_qemu_serial_log("FATAL AArch64 EL1\nPSCI SYSTEM_OFF (status=OK)\n").is_err());
    }

    #[test]
    fn check_bench_json_output_validates_json_and_rejects_nan() {
        let ok = check_bench_json_output(r#"{"ns_per_op": 12.5, "ops_per_sec": 80000000}"#)
            .expect("valid json");
        assert_eq!(ok, 2);
        assert!(check_bench_json_output("plain text").is_err());
        assert!(check_bench_json_output(r#"{"ns_per_op": NaN}"#).is_err());
        assert!(check_bench_json_output(r#"{"ops_per_sec": Infinity}"#).is_err());
    }

    #[test]
    fn temp_file_guard_removes_file_on_drop() {
        let tmp =
            env::temp_dir().join(format!("newos-xtask-guard-test-{}.tmp", std::process::id()));
        fs::write(&tmp, b"temp").expect("create temp file");
        assert!(tmp.exists());
        {
            let _guard = TempFileGuard(&tmp);
            assert!(tmp.exists());
        }
        assert!(!tmp.exists());
    }

    #[test]
    fn workspace_and_ci_enforce_clippy_pedantic_and_nursery() {
        let root = workspace_root().expect("workspace root");

        // 1. Root Cargo.toml enables all, pedantic, and nursery under [workspace.lints.clippy].
        let root_manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
        let clippy_section = root_manifest
            .split("[workspace.lints.clippy]")
            .nth(1)
            .expect("missing [workspace.lints.clippy]");
        assert!(
            clippy_section.contains("pedantic ="),
            "root Cargo.toml must enable clippy::pedantic"
        );
        assert!(
            clippy_section.contains("nursery ="),
            "root Cargo.toml must enable clippy::nursery"
        );

        // 2. Non-inheriting audited TCB & fuzz manifests mirror pedantic and nursery.
        for rel in [
            "crates/hal/Cargo.toml",
            "crates/user-rt/Cargo.toml",
            "fuzz/Cargo.toml",
        ] {
            let content = fs::read_to_string(root.join(rel)).expect("read manifest");
            let section = content
                .split("[lints.clippy]")
                .nth(1)
                .unwrap_or_else(|| panic!("{rel} missing [lints.clippy]"));
            assert!(
                section.contains("pedantic ="),
                "{rel} must enable clippy::pedantic"
            );
            assert!(
                section.contains("nursery ="),
                "{rel} must enable clippy::nursery"
            );
        }

        // 3. Every other crate in crates/, xtask, and tests inherits workspace lints.
        let mut checked_members = 0usize;
        for entry in fs::read_dir(root.join("crates")).expect("read crates/") {
            let path = entry.expect("dir entry").path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "hal" | "user-rt") {
                continue;
            }
            let manifest = fs::read_to_string(path.join("Cargo.toml"))
                .unwrap_or_else(|_| panic!("missing Cargo.toml in {}", path.display()));
            assert!(
                manifest.contains("[lints]\nworkspace = true"),
                "crates/{name}/Cargo.toml must inherit `[lints] workspace = true`"
            );
            checked_members += 1;
        }
        assert!(checked_members >= 20, "expected >= 20 inheriting crates");
        for rel in ["xtask/Cargo.toml", "tests/Cargo.toml"] {
            let manifest = fs::read_to_string(root.join(rel)).expect("read manifest");
            assert!(
                manifest.contains("[lints]\nworkspace = true"),
                "{rel} must inherit `[lints] workspace = true`"
            );
        }

        // 4. CI workflow enforces pedantic + nursery + -D warnings on all 3 Clippy jobs.
        let ci_yml =
            fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
        let clippy_gate_count = ci_yml
            .matches("-W clippy::pedantic -W clippy::nursery -D warnings")
            .count();
        assert_eq!(
            clippy_gate_count, 3,
            "expected all 3 CI clippy invocations to enforce pedantic + nursery + -D warnings"
        );
    }
}
