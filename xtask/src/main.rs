mod gpt;
mod profile;

use profile::BuildProfile;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIMINE_BRANCH: &str = "v9.x-binary";
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
        "test" => run_tests(release),
        "host-test" => run_host_tests(release),
        "miri" => run_miri_tests(),
        "verify" => run_kani_verify(),
        "rpi5-image" => resolve_profile(&root, &args[1..], "rpi5")
            .and_then(|p| build_rpi5_image(&p, release).map(|_| ())),
        "bench" => run_bench(&args[1..]),
        "help" | "-h" | "--help" => {
            eprintln!(
                "Usage: cargo xtask <config|feature-matrix|rpi5-image|build|run|test|host-test|miri|verify|bench> [options]\n\
                 Options:\n\
                   --profile <profiles/*.toml>            Load declarative TOML system composition profile\n\
                   --board <rpi5|qemu-virt>               Override target board\n\
                   --sched <priority-rr|round-robin|fifo> Override kernel scheduler policy\n\
                   --no-smp | --no-acpi | --no-domains | --no-shell | --no-net | --no-ssh | --no-crypto\n\
                   --ipv4-only | --ipv6-only              Select single-stack networking\n\
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
        let elf = build_user_elf(root, "newos-key-pd", "key-pd", &profile.cpu, None, release)?;
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
    let modules = build_profile_modules(&root, profile, interactive, release)?;
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

/// Run Kani bounded model checking proofs (`#[cfg(kani)]`) on `SpscRing`, `CNode`, and `UntypedInventory`.
fn run_kani_verify() -> Result<(), String> {
    let root = workspace_root();
    for pkg in ["newos-abi", "newos-kernel-core"] {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&root).args(["kani", "--package", pkg]);
        run_checked(&mut cmd, &format!("cargo kani ({pkg})")).map_err(|e| {
            format!("{e} (install with `cargo install --locked kani-verifier && cargo kani setup`)")
        })?;
    }
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

fn run_tests(release: bool) -> Result<(), String> {
    run_host_tests(release)?;
    let profile = BuildProfile::default_full("qemu-virt");
    run_qemu(&profile, false, release)
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
