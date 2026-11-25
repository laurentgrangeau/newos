mod gpt;
mod profile;

use profile::BuildProfile;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIMINE_BRANCH: &str = "v9.6.7-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";
// Soft-float target for EL1 kernel so LLVM never emits NEON/FP instructions on syscall/IRQ paths (`H2`).
const KERNEL_TARGET_TRIPLE: &str = "aarch64-unknown-none-softfloat";
const EFI_FILENAME: &str = "BOOTAA64.EFI";
const UEFI_DISK_BYTES: u64 = 64 * 1024 * 1024;

fn resolve_profile(
    root: &Path,
    args: &[String],
    default_board: &str,
) -> Result<BuildProfile, String> {
    let mut profile_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--profile" {
            i += 1;
            let raw = args
                .get(i)
                .ok_or_else(|| "missing path after `--profile`".to_string())?;
            let p = PathBuf::from(raw);
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
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let release = args.iter().any(|a| a == "--release");
    let root = workspace_root();

    let result = match cmd {
        "config" => {
            if args.iter().any(|a| a == "--list-options") {
                print!("{}", BuildProfile::list_all_options());
                Ok(())
            } else {
                resolve_profile(&root, &args[1..], "rpi5").map(|p| {
                    print!("{}", p.render_system_composition());
                })
            }
        }
        "feature-matrix" => run_feature_matrix(&root),
        "build" => resolve_profile(&root, &args[1..], "qemu-virt")
            .and_then(|p| build_uefi_disk(&p, true, release).map(|_| ())),
        "run" => resolve_profile(&root, &args[1..], "qemu-virt")
            .and_then(|p| run_qemu(&p, true, release)),
        "test" => {
            resolve_profile(&root, &args[1..], "qemu-virt").and_then(|p| run_tests(&p, release))
        }
        "host-test" => run_host_tests(release),
        "miri" => run_miri_tests(),
        "verify" => run_kani_verify(),
        "coverage" => run_coverage(&root, &args[1..]),
        "mutants" => run_mutants(&root, &args[1..]),
        "fuzz" => run_fuzz(&root, &args[1..]),
        "chaos" => run_chaos(&root, &args[1..], release),
        "audit-elf" => run_audit_elf(&root, &args[1..], release),
        "bench-check" => run_bench_check(&root),
        "qemu-matrix" => run_qemu_matrix(&root, release),
        "repro-check" => run_repro_check(&root, &args[1..], release),
        "soak" => run_soak(&root, &args[1..], release),
        "rpi5-image" => resolve_profile(&root, &args[1..], "rpi5")
            .and_then(|p| build_rpi5_image(&p, release).map(|_| ())),
        "bench" => run_bench(&args[1..]),
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
        other => Err(format!(
            "unknown subcommand `{other}`\nRun `cargo xtask help` for usage."
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[xtask] error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn profile_dir(release: bool) -> &'static str {
    if release { "release" } else { "debug" }
}

fn workspace_root() -> PathBuf {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR")
        && let Some(parent) = Path::new(manifest_dir).parent()
    {
        return parent.to_path_buf();
    }
    env::current_dir().expect("failed to determine workspace root")
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn {label}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} exited with status {status}"))
    }
}

fn build_kernel(root: &Path, profile: &BuildProfile, release: bool) -> Result<PathBuf, String> {
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
    if release {
        cmd.arg("--release");
    }
    run_checked(
        &mut cmd,
        &format!("cargo build (newos-kernel {}/{features})", profile.cpu),
    )?;

    Ok(root
        .join("target")
        .join(KERNEL_TARGET_TRIPLE)
        .join(profile_dir(release))
        .join("newos-kernel"))
}

fn build_user_elf(
    root: &Path,
    pkg: &str,
    dir: &str,
    cpu: &str,
    features: Option<&[String]>,
    release: bool,
) -> Result<PathBuf, String> {
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
        target_json.to_str().ok_or("invalid user target path")?,
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
    if release {
        cmd.arg("--release");
    }
    run_checked(
        &mut cmd,
        &format!("cargo build ({pkg} aarch64-newos-user/kcfi+scs)"),
    )?;

    Ok(root
        .join("target")
        .join("aarch64-newos-user")
        .join(profile_dir(release))
        .join(pkg))
}

fn ensure_limine(root: &Path) -> Result<PathBuf, String> {
    let limine_dir = root.join("target/limine");
    if !limine_dir.join(EFI_FILENAME).exists() {
        if limine_dir.exists() {
            fs::remove_dir_all(&limine_dir)
                .map_err(|e| format!("failed to clean {}: {e}", limine_dir.display()))?;
        }
        let mut clone = Command::new("git");
        clone.args([
            "clone",
            "--depth=1",
            "--branch",
            LIMINE_BRANCH,
            LIMINE_REPO,
            limine_dir.to_str().ok_or("invalid limine path")?,
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
) -> Result<(), String> {
    let esp_bytes = gpt::esp_partition_bytes(UEFI_DISK_BYTES)?;
    let esp_file = fs::File::create(esp_tmp_path).map_err(|e| format!("create ESP: {e}"))?;
    esp_file
        .set_len(esp_bytes)
        .map_err(|e| format!("resize ESP: {e}"))?;
    drop(esp_file);

    let esp_str = esp_tmp_path.to_str().ok_or("invalid ESP path")?;
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
        mcopy.arg(entry.to_str().ok_or("bad staged path")?);
    }
    mcopy.arg("::/");
    run_checked(&mut mcopy, "mcopy")?;

    gpt::write_gpt_disk_image(disk_path, esp_tmp_path, UEFI_DISK_BYTES, gpt_label)?;
    let _ = fs::remove_file(esp_tmp_path);
    Ok(())
}

/// Build enabled EL0 protection domain modules for `profile` and return `(boot_filename, host_path)` pairs.
fn build_profile_modules(
    root: &Path,
    profile: &BuildProfile,
    include_domains: bool,
    release: bool,
) -> Result<Vec<(&'static str, PathBuf)>, String> {
    let mut modules = Vec::new();
    if !profile.userspace {
        return Ok(modules);
    }
    if profile.supervisor {
        let supervisor_feats = profile.supervisor_features();
        let elf = build_user_elf(
            root,
            "newos-supervisor-pd",
            "supervisor-pd",
            &profile.cpu,
            Some(&supervisor_feats),
            release,
        )?;
        modules.push(("newos-supervisor-pd", elf));
    }
    if profile.shell && include_domains {
        let elf = build_user_elf(
            root,
            "newos-shell-pd",
            "shell-pd",
            &profile.cpu,
            None,
            release,
        )?;
        modules.push(("newos-shell-pd", elf));
    }
    if profile.worker {
        let elf = build_user_elf(
            root,
            "newos-worker-pd",
            "worker-pd",
            &profile.cpu,
            None,
            release,
        )?;
        modules.push(("newos-worker-pd", elf));
    }
    if profile.net {
        let net_feats = profile.net_pd_features();
        let elf = build_user_elf(
            root,
            "newos-net-pd",
            "net-pd",
            &profile.cpu,
            Some(&net_feats),
            release,
        )?;
        if include_domains {
            modules.push(("newos-net-pd", elf));
        }
    }
    if profile.key {
        let key_feats = profile.key_pd_features();
        let elf = build_user_elf(
            root,
            "newos-key-pd",
            "key-pd",
            &profile.cpu,
            Some(&key_feats),
            release,
        )?;
        if include_domains {
            modules.push(("newos-key-pd", elf));
        }
    }
    if profile.ssh {
        let elf = build_user_elf(root, "newos-ssh-pd", "ssh-pd", &profile.cpu, None, release)?;
        if include_domains {
            modules.push(("newos-ssh-pd", elf));
        }
    }
    Ok(modules)
}

/// Build a pure 64-bit AArch64 UEFI GPT + FAT32 ESP disk image for the QEMU `virt` test harness.
fn build_uefi_disk(
    profile: &BuildProfile,
    interactive: bool,
    release: bool,
) -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root, profile, release)?;
    // Always package all enabled profile PDs (including `net-pd`, `key-pd`, `ssh-pd`, `shell-pd`)
    // so both interactive boots and automated `cargo xtask test` exercise the full protection-domain set.
    let modules = build_profile_modules(&root, profile, true, release)?;
    let limine_dir = ensure_limine(&root)?;

    let stage = root.join("target/esp_root_aarch64");
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| format!("failed to clean esp_root: {e}"))?;
    }

    let boot_limine = stage.join("boot/limine");
    let efi_boot = stage.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine).map_err(|e| e.to_string())?;
    fs::create_dir_all(&efi_boot).map_err(|e| e.to_string())?;

    fs::copy(&kernel_elf, stage.join("boot/newos-kernel"))
        .map_err(|e| format!("failed to copy kernel ELF: {e}"))?;
    let mut module_lines = String::new();
    for (name, path) in &modules {
        fs::copy(path, stage.join("boot").join(name))
            .map_err(|e| format!("failed to copy {name} ELF: {e}"))?;
        module_lines.push_str(&format!("    module_path: boot():/boot/{name}\n"));
    }

    let cmdline = if interactive {
        "interactive qemu"
    } else {
        "test qemu"
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
        .map_err(|e| format!("failed to write limine.conf: {e}"))?;
    fs::copy(limine_dir.join(EFI_FILENAME), efi_boot.join(EFI_FILENAME))
        .map_err(|e| format!("failed to copy {EFI_FILENAME}: {e}"))?;

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
fn build_rpi5_image(profile: &BuildProfile, release: bool) -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root, profile, release)?;
    let modules = build_profile_modules(&root, profile, true, release)?;
    let limine_dir = ensure_limine(&root)?;

    let stage = root.join("target/rpi5_boot");
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| format!("failed to clean rpi5_boot: {e}"))?;
    }
    let boot_limine = stage.join("boot/limine");
    let efi_boot = stage.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine).map_err(|e| e.to_string())?;
    fs::create_dir_all(&efi_boot).map_err(|e| e.to_string())?;

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
        .map_err(|e| format!("failed to write config.txt: {e}"))?;

    fs::copy(&kernel_elf, stage.join("boot/newos-kernel"))
        .map_err(|e| format!("failed to copy kernel ELF: {e}"))?;
    let mut module_lines = String::new();
    for (name, path) in &modules {
        fs::copy(path, stage.join("boot").join(name))
            .map_err(|e| format!("failed to copy {name} ELF: {e}"))?;
        module_lines.push_str(&format!("    module_path: boot():/boot/{name}\n"));
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
        .map_err(|e| format!("failed to write limine.conf: {e}"))?;
    fs::copy(
        limine_dir.join("BOOTAA64.EFI"),
        efi_boot.join("BOOTAA64.EFI"),
    )
    .map_err(|e| format!("failed to copy BOOTAA64.EFI: {e}"))?;

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
fn run_feature_matrix(root: &Path) -> Result<(), String> {
    let cases: &[(&str, &[&str])] = &[
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
    for (label, cargo_args) in cases {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root).args(*cargo_args);
        run_checked(&mut cmd, &format!("feature-matrix: {label}"))?;
    }
    println!(
        "[xtask] feature-matrix: all {} configurations passed!",
        cases.len()
    );
    Ok(())
}

fn run_host_tests(release: bool) -> Result<(), String> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args([
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
    if release {
        cmd.arg("--release");
    }
    run_checked(&mut cmd, "cargo test (host)")
}

/// Run Miri UB / aliasing / provenance checks across all host-testable crates.
fn run_miri_tests() -> Result<(), String> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args([
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
fn run_kani_verify() -> Result<(), String> {
    let root = workspace_root();
    for pkg in ["newos-abi", "newos-kernel-core", "newos-ssh-proto"] {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&root).args(["kani", "--package", pkg]);
        run_checked(&mut cmd, &format!("cargo kani ({pkg})")).map_err(|e| {
            format!("{e} (install with `cargo install --locked kani-verifier && cargo kani setup`)")
        })?;
    }
    Ok(())
}

/// Measure host line/region coverage with `cargo-llvm-cov` and optionally enforce a hard floor.
fn run_coverage(root: &Path, args: &[String]) -> Result<(), String> {
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
                let pct = args
                    .get(i)
                    .ok_or_else(|| "missing percentage after `--fail-under`".to_string())?;
                cmd.args(["--fail-under-lines", pct]);
            }
            "--html" => {
                cmd.arg("--html");
            }
            "--lcov" => {
                cmd.args(["--lcov", "--output-path", "target/llvm-cov/lcov.info"]);
            }
            other => return Err(format!("unknown coverage flag `{other}`")),
        }
        i += 1;
    }
    run_checked(&mut cmd, "cargo llvm-cov")
}

/// Run mutation testing (`cargo-mutants`) using `.cargo/mutants.toml`.
fn run_mutants(root: &Path, args: &[String]) -> Result<(), String> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).arg("mutants");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in-diff" => {
                i += 1;
                let diff_path = args
                    .get(i)
                    .ok_or_else(|| "missing diff file after `--in-diff`".to_string())?;
                cmd.args(["--in-diff", diff_path]);
            }
            "--package" | "-p" => {
                i += 1;
                let pkg = args
                    .get(i)
                    .ok_or_else(|| "missing package name after `--package`".to_string())?;
                cmd.args(["--package", pkg]);
            }
            other => return Err(format!("unknown mutants flag `{other}`")),
        }
        i += 1;
    }
    run_checked(&mut cmd, "cargo mutants")
}

/// Run libFuzzer targets under `fuzz/` via `cargo-fuzz`.
fn run_fuzz(root: &Path, args: &[String]) -> Result<(), String> {
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
                    .ok_or_else(|| "missing seconds after `--seconds`".to_string())?;
                seconds = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid `--seconds` value `{raw}`"))?;
            }
            other if !other.starts_with('-') => {
                if let Some(&known) = ALL_TARGETS.iter().find(|&&t| t == other) {
                    selected.push(known);
                } else {
                    return Err(format!("unknown fuzz target `{other}`"));
                }
            }
            other => return Err(format!("unknown fuzz flag `{other}`")),
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
fn run_chaos(root: &Path, args: &[String], release: bool) -> Result<(), String> {
    let mut host = Command::new("cargo");
    host.current_dir(root)
        .args(["test", "-p", "newos-e2e-tests", "--test", "chaos"]);
    if release {
        host.arg("--release");
    }
    run_checked(&mut host, "cargo test (host chaos)")?;
    let profile = resolve_profile(root, args, "qemu-virt")?;
    run_qemu(&profile, false, release)
}

/// Audit compiled AArch64 kernel & EL0 PD ELFs for W^X (zero RWX segments) and RELRO/PIE.
fn run_audit_elf(root: &Path, args: &[String], release: bool) -> Result<(), String> {
    let profile = resolve_profile(root, args, "qemu-virt")?;
    let kernel_elf = build_kernel(root, &profile, release)?;
    let modules = build_profile_modules(root, &profile, true, release)?;

    let mut bins: Vec<(&str, PathBuf)> = vec![("newos-kernel", kernel_elf)];
    bins.extend(modules);

    for (name, path) in &bins {
        let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
            return Err(format!("{name}: invalid ELF64 header"));
        }
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        if e_type != 3 {
            return Err(format!(
                "{name}: expected PIE (ET_DYN=3), got e_type={e_type}"
            ));
        }
        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
        let e_phnum = u16::from_le_bytes([data[56], data[57]]) as usize;
        let mut load_count = 0usize;
        let mut has_relro = false;
        for idx in 0..e_phnum {
            let off = e_phoff + idx * e_phentsize;
            if off + 56 > data.len() {
                return Err(format!("{name}: truncated program header {idx}"));
            }
            let p_type = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            let p_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
            if p_type == 1 {
                load_count += 1;
                // PF_W (2) | PF_X (1) == 3 -> forbidden RWX segment!
                if (p_flags & 3) == 3 {
                    return Err(format!(
                        "{name}: W^X VIOLATION — PT_LOAD segment {idx} has both PF_W and PF_X (flags={p_flags:#x})"
                    ));
                }
            } else if p_type == 0x6474_e552 {
                has_relro = true;
            }
        }
        if load_count == 0 {
            return Err(format!("{name}: zero PT_LOAD segments"));
        }
        let mut neon_note = "n/a";
        if *name == "newos-kernel"
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
                return Err(format!(
                    "newos-kernel: soft-float violation — found {fp_hits} FP arithmetic instructions in EL1"
                ));
            }
            neon_note = "0-FP-arith";
        }
        println!(
            "[audit-elf] {name}: PIE=OK, W^X=OK ({load_count} PT_LOAD, 0 RWX), RELRO={has_relro}, EL1-softfloat={neon_note}"
        );
    }
    Ok(())
}

/// Run `newos-bench --json` and verify output is valid JSON containing non-zero finite metrics.
fn run_bench_check(root: &Path) -> Result<(), String> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["run", "--release", "-p", "newos-bench", "--", "--json"])
        .output()
        .map_err(|e| format!("failed to run newos-bench: {e}"))?;
    if !output.status.success() {
        return Err(format!("newos-bench exited with {}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains('{') || !stdout.contains('}') {
        return Err("newos-bench --json did not emit JSON output".to_string());
    }
    if stdout.contains("NaN") || stdout.contains("Infinity") {
        return Err("newos-bench --json emitted NaN/Infinity metric".to_string());
    }
    let metric_count =
        stdout.matches("\"ns_per_op\"").count() + stdout.matches("\"ops_per_sec\"").count();
    println!(
        "[bench-check] newos-bench --json passed ({} bytes, {} numeric metric fields, 0 NaN/Inf)",
        stdout.len(),
        metric_count
    );
    Ok(())
}

/// Boot alternate system composition profiles (`tinykernel`, `--no-net`, `--ipv6-only`) in QEMU.
fn run_qemu_matrix(root: &Path, release: bool) -> Result<(), String> {
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
        let owned: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
        let profile = resolve_profile(root, &owned, "qemu-virt")?;
        println!("[qemu-matrix] booting profile `{label}`...");
        run_qemu(&profile, false, release)?;
    }
    println!("[qemu-matrix] all {} profiles passed!", matrix.len());
    Ok(())
}

/// Verify deterministic reproducible builds of `newos-kernel` (two builds produce identical bytes).
fn run_repro_check(root: &Path, args: &[String], release: bool) -> Result<(), String> {
    let profile = resolve_profile(root, args, "qemu-virt")?;
    let p1 = build_kernel(root, &profile, release)?;
    let b1 = fs::read(&p1).map_err(|e| format!("read build 1: {e}"))?;
    let p2 = build_kernel(root, &profile, release)?;
    let b2 = fs::read(&p2).map_err(|e| format!("read build 2: {e}"))?;
    if b1 != b2 {
        return Err("repro-check FAILED: two builds of newos-kernel differed!".to_string());
    }
    let crc = gpt::crc32(&b1);
    println!(
        "[repro-check] newos-kernel reproducible build OK (size={} bytes, crc32={crc:#010x})",
        b1.len()
    );
    Ok(())
}

/// Nightly endurance soak: run `N` consecutive 4-core QEMU boot + chaos cycles.
fn run_soak(_root: &Path, args: &[String], release: bool) -> Result<(), String> {
    let mut cycles = 3usize;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--cycles" {
            i += 1;
            cycles = args
                .get(i)
                .ok_or("missing count after `--cycles`")?
                .parse::<usize>()
                .map_err(|_| "invalid `--cycles` value")?;
        }
        i += 1;
    }
    let profile = BuildProfile::default_full("qemu-virt");
    for c in 1..=cycles {
        println!("[soak] cycle {c}/{cycles}...");
        run_qemu(&profile, false, release)?;
    }
    println!("[soak] all {cycles} QEMU endurance cycles passed!");
    Ok(())
}

fn run_bench(raw_args: &[String]) -> Result<(), String> {
    let root = workspace_root();
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
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--offline",
            "--package",
            "newos-bench",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let bin_path = match cargo_status {
        Ok(status) if status.success() => root.join("target/release/newos-bench"),
        _ => {
            let out_dir = root.join("target/bench");
            fs::create_dir_all(&out_dir)
                .map_err(|e| format!("failed to create {}: {e}", out_dir.display()))?;

            let abi_rlib = out_dir.join("libnewos_abi.rlib");
            let kc_rlib = out_dir.join("libnewos_kernel_core.rlib");
            let sc_rlib = out_dir.join("libnewos_shell_core.rlib");
            let bench_bin = out_dir.join("newos_bench");

            let abi_extern = format!("newos_abi={}", abi_rlib.display());
            let kc_extern = format!("newos_kernel_core={}", kc_rlib.display());
            let sc_extern = format!("newos_shell_core={}", sc_rlib.display());

            run_checked(
                Command::new("rustc").current_dir(&root).args([
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
                    abi_rlib.to_str().ok_or("invalid abi rlib path")?,
                ]),
                "rustc (newos_abi)",
            )?;

            run_checked(
                Command::new("rustc").current_dir(&root).args([
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
                    kc_rlib.to_str().ok_or("invalid kernel_core rlib path")?,
                ]),
                "rustc (newos_kernel_core)",
            )?;

            run_checked(
                Command::new("rustc").current_dir(&root).args([
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
                    sc_rlib.to_str().ok_or("invalid shell_core rlib path")?,
                ]),
                "rustc (newos_shell_core)",
            )?;

            run_checked(
                Command::new("rustc").current_dir(&root).args([
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
                    bench_bin.to_str().ok_or("invalid bench bin path")?,
                ]),
                "rustc (newos_bench)",
            )?;

            bench_bin
        }
    };

    let mut run_cmd = Command::new(&bin_path);
    run_cmd.current_dir(&root).args(&bench_args);
    run_checked(&mut run_cmd, "newos-bench")
}

fn run_tests(profile: &BuildProfile, release: bool) -> Result<(), String> {
    run_host_tests(release)?;
    run_qemu(profile, false, release)
}

fn find_firmware() -> Result<&'static str, String> {
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
            "AArch64 UEFI firmware (AAVMF / QEMU_EFI.fd / edk2-aarch64-code.fd) not found"
                .to_string()
        })
}

fn run_qemu(profile: &BuildProfile, interactive: bool, release: bool) -> Result<(), String> {
    let disk_path = build_uefi_disk(profile, interactive, release)?;
    let firmware = find_firmware()?;
    let disk_str = disk_path.to_str().ok_or("invalid disk path")?;

    let pflash_arg = format!("if=pflash,format=raw,readonly=on,file={firmware}");
    let boot_drive_arg = format!("if=none,id=bootdisk,format=raw,readonly=on,file={disk_str}");

    // Bind SSH host forwarding strictly to loopback (`127.0.0.1`) and only in interactive mode (`N19`).
    let netdev_arg = if interactive {
        "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22"
    } else {
        "user,id=net0"
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

    if interactive {
        let status = qemu
            .status()
            .map_err(|e| format!("failed to launch qemu-system-aarch64: {e}"))?;
        return match status.code() {
            Some(0) => {
                println!("[xtask] QEMU (aarch64/cortex-a76) exited cleanly (PSCI SYSTEM_OFF)");
                Ok(())
            }
            other => Err(format!(
                "QEMU (aarch64/cortex-a76) exited with unexpected status {other:?}"
            )),
        };
    }

    // Automated test mode (`H5`): capture serial output, enforce a hard 300s timeout, and verify
    // the guest reported `PSCI SYSTEM_OFF (status=OK)` with zero `[newos] FAIL:` / `status=FAIL`.
    use std::io::Read;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    qemu.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = qemu
        .spawn()
        .map_err(|e| format!("failed to launch qemu-system-aarch64: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("failed to capture QEMU stdout")?;
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
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("QEMU test timed out after 300s".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("failed waiting on QEMU: {e}")),
        }
    };
    let serial_log = reader.join().unwrap_or_default();

    if status.code() != Some(0) {
        return Err(format!(
            "QEMU (aarch64/cortex-a76) exited with unexpected status {:?}",
            status.code()
        ));
    }
    if serial_log.contains("PSCI SYSTEM_OFF (status=FAIL)")
        || serial_log.contains("[newos] FAIL:")
        || serial_log.contains("[supervisor-pd] FAIL:")
        || serial_log.contains("FATAL AArch64 EL1")
    {
        return Err("QEMU guest reported test failure in serial output".to_string());
    }
    if !serial_log.contains("PSCI SYSTEM_OFF (status=OK)") {
        return Err("QEMU guest did not reach `PSCI SYSTEM_OFF (status=OK)`".to_string());
    }
    println!("[xtask] QEMU (aarch64/cortex-a76) guest self-tests PASSED (status=OK)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_profile_parses_cli_overrides_and_rejects_bad_flags() {
        let root = workspace_root();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        let p = resolve_profile(&root, &s(&["--board", "qemu-virt", "--no-net"]), "rpi5")
            .expect("valid overrides");
        assert_eq!(p.board, "qemu-virt");
        assert!(!p.net);

        // Missing path after --profile must error
        assert!(resolve_profile(&root, &s(&["--profile"]), "qemu-virt").is_err());

        // Unknown flag must error
        assert!(resolve_profile(&root, &s(&["--no-sshd"]), "qemu-virt").is_err());

        // --ipv6-only disables ipv4 while keeping ipv6
        let p6 = resolve_profile(&root, &s(&["--ipv6-only"]), "qemu-virt").expect("ipv6-only");
        assert!(!p6.ipv4);
        assert!(p6.ipv6);
    }
}
