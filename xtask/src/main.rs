use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIMINE_BRANCH: &str = "v9.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";
const TARGET_TRIPLE: &str = "aarch64-unknown-none";
const TARGET_CPU: &str = "cortex-a76";
const EFI_FILENAME: &str = "BOOTAA64.EFI";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let release = args.iter().any(|a| a == "--release");

    let result = match cmd {
        "build" => build_iso(true, release).map(|_| ()),
        "run" => run_qemu(true, release),
        "test" => run_tests(release),
        "host-test" => run_host_tests(release),
        "rpi5-image" => build_rpi5_image(release).map(|_| ()),
        "bench" => run_bench(&args[1..]),
        "help" | "-h" | "--help" => {
            eprintln!(
                "Usage: cargo xtask <rpi5-image|build|run|test|host-test|bench> [--release]\n\
                 Target: Raspberry Pi 5 16 GB (BCM2712 Cortex-A76, aarch64-unknown-none)"
            );
            Ok(())
        }
        other => Err(format!(
            "unknown subcommand `{other}`\nUsage: cargo xtask <rpi5-image|build|run|test|host-test|bench> [--release]"
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

fn build_kernel(root: &Path, release: bool) -> Result<PathBuf, String> {
    let linker_script = root.join("crates/kernel/linker-aarch64.ld");
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=static -C target-cpu={TARGET_CPU}",
        linker_script.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).env("RUSTFLAGS", rustflags).args([
        "build",
        "--package",
        "newos-kernel",
        "--target",
        TARGET_TRIPLE,
        "-Z",
        "build-std=core,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    if release {
        cmd.arg("--release");
    }
    run_checked(&mut cmd, "cargo build (newos-kernel aarch64/cortex-a76)")?;

    Ok(root
        .join("target")
        .join(TARGET_TRIPLE)
        .join(profile_dir(release))
        .join("newos-kernel"))
}

fn build_user_elf(root: &Path, pkg: &str, dir: &str, release: bool) -> Result<PathBuf, String> {
    let linker_script = root.join(format!("crates/{dir}/linker-aarch64.ld"));
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=static -C target-cpu={TARGET_CPU}",
        linker_script.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root).env("RUSTFLAGS", rustflags).args([
        "build",
        "--package",
        pkg,
        "--target",
        TARGET_TRIPLE,
        "-Z",
        "build-std=core,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    if release {
        cmd.arg("--release");
    }
    run_checked(&mut cmd, &format!("cargo build ({pkg} aarch64/cortex-a76)"))?;

    Ok(root
        .join("target")
        .join(TARGET_TRIPLE)
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

/// Build a pure 64-bit AArch64 UEFI bootable ISO for the local QEMU `virt` test harness.
fn build_iso(interactive: bool, release: bool) -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root, release)?;
    let init_elf = build_user_elf(&root, "newos-init", "init", release)?;
    let worker_elf = build_user_elf(&root, "newos-worker", "worker", release)?;
    let limine_dir = ensure_limine(&root)?;

    let iso_root = root.join("target/iso_root_aarch64");
    if iso_root.exists() {
        fs::remove_dir_all(&iso_root).map_err(|e| format!("failed to clean iso_root: {e}"))?;
    }

    let boot_limine = iso_root.join("boot/limine");
    let efi_boot = iso_root.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine).map_err(|e| e.to_string())?;
    fs::create_dir_all(&efi_boot).map_err(|e| e.to_string())?;

    fs::copy(&kernel_elf, iso_root.join("boot/newos-kernel"))
        .map_err(|e| format!("failed to copy kernel ELF: {e}"))?;
    fs::copy(&init_elf, iso_root.join("boot/newos-init"))
        .map_err(|e| format!("failed to copy init ELF: {e}"))?;
    fs::copy(&worker_elf, iso_root.join("boot/newos-worker"))
        .map_err(|e| format!("failed to copy worker ELF: {e}"))?;

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
         \x20   path: boot():/boot/newos-kernel\n\
         \x20   cmdline: {cmdline}\n\
         \x20   module_path: boot():/boot/newos-init\n\
         \x20   module_path: boot():/boot/newos-worker\n"
    );
    fs::write(boot_limine.join("limine.conf"), limine_conf)
        .map_err(|e| format!("failed to write limine.conf: {e}"))?;

    fs::copy(
        limine_dir.join("limine-uefi-cd.bin"),
        boot_limine.join("limine-uefi-cd.bin"),
    )
    .map_err(|e| format!("failed to copy limine-uefi-cd.bin: {e}"))?;
    fs::copy(limine_dir.join(EFI_FILENAME), efi_boot.join(EFI_FILENAME))
        .map_err(|e| format!("failed to copy {EFI_FILENAME}: {e}"))?;

    let iso_path = root.join("target/newos-aarch64.iso");
    let mut xorriso = Command::new("xorriso");
    xorriso.args([
        "-as",
        "mkisofs",
        "-R",
        "-r",
        "-J",
        "--efi-boot",
        "boot/limine/limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label",
        iso_root.to_str().ok_or("invalid iso_root path")?,
        "-o",
        iso_path.to_str().ok_or("invalid iso path")?,
    ]);
    run_checked(&mut xorriso, "xorriso")?;

    println!("[xtask] built pure AArch64 UEFI ISO {}", iso_path.display());
    Ok(iso_path)
}

/// Build a 64 MiB FAT32 boot image (`target/newos-rpi5.img`) + staging folder (`target/rpi5_boot/`)
/// for Raspberry Pi 5 (16 GB, BCM2712 Cortex-A76, 3-pin JST Debug UART `0x10_7D00_1000`).
fn build_rpi5_image(release: bool) -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root, release)?;
    let init_elf = build_user_elf(&root, "newos-init", "init", release)?;
    let worker_elf = build_user_elf(&root, "newos-worker", "worker", release)?;
    let limine_dir = ensure_limine(&root)?;

    let stage = root.join("target/rpi5_boot");
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| format!("failed to clean rpi5_boot: {e}"))?;
    }
    let boot_limine = stage.join("boot/limine");
    let efi_boot = stage.join("EFI/BOOT");
    fs::create_dir_all(&boot_limine).map_err(|e| e.to_string())?;
    fs::create_dir_all(&efi_boot).map_err(|e| e.to_string())?;

    // Raspberry Pi 5 EDK2 UEFI config.txt (place RPI_EFI.fd alongside on the FAT32 SD card)
    let config_txt = "\
# NewOS Raspberry Pi 5 (16 GB) UEFI + Limine Boot Config
arm_64bit=1
enable_uart=1
uart_2ndstage=1
pciex4_reset=0
disable_commandline_tags=2
armstub=RPI_EFI.fd
";
    fs::write(stage.join("config.txt"), config_txt)
        .map_err(|e| format!("failed to write config.txt: {e}"))?;

    let limine_conf = "\
timeout: 3
serial: yes

/NewOS (Raspberry Pi 5 - 16 GB)
    protocol: limine
    path: boot():/boot/newos-kernel
    cmdline: interactive
    module_path: boot():/boot/newos-init
    module_path: boot():/boot/newos-worker
";
    fs::write(boot_limine.join("limine.conf"), limine_conf)
        .map_err(|e| format!("failed to write limine.conf: {e}"))?;

    fs::copy(&kernel_elf, stage.join("boot/newos-kernel"))
        .map_err(|e| format!("failed to copy kernel ELF: {e}"))?;
    fs::copy(&init_elf, stage.join("boot/newos-init"))
        .map_err(|e| format!("failed to copy init ELF: {e}"))?;
    fs::copy(&worker_elf, stage.join("boot/newos-worker"))
        .map_err(|e| format!("failed to copy worker ELF: {e}"))?;
    fs::copy(
        limine_dir.join("BOOTAA64.EFI"),
        efi_boot.join("BOOTAA64.EFI"),
    )
    .map_err(|e| format!("failed to copy BOOTAA64.EFI: {e}"))?;

    // Create a 64 MiB FAT32 filesystem image using mkfs.vfat + mcopy (`dosfstools` + `mtools`)
    let img_path = root.join("target/newos-rpi5.img");
    let img_file = fs::File::create(&img_path).map_err(|e| format!("create img: {e}"))?;
    img_file
        .set_len(64 * 1024 * 1024)
        .map_err(|e| format!("resize img: {e}"))?;
    drop(img_file);

    let img_str = img_path.to_str().ok_or("invalid img path")?;
    let mkfs_bin = ["/usr/sbin/mkfs.vfat", "/sbin/mkfs.vfat"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("mkfs.vfat");
    let mut mkfs = Command::new(mkfs_bin);
    mkfs.args(["-F", "32", "-n", "NEWOS", img_str]);
    run_checked(&mut mkfs, "mkfs.vfat")?;

    let mut mcopy = Command::new("mcopy");
    mcopy.args([
        "-s",
        "-i",
        img_str,
        stage.join("config.txt").to_str().ok_or("bad path")?,
        stage.join("EFI").to_str().ok_or("bad path")?,
        stage.join("boot").to_str().ok_or("bad path")?,
        "::/",
    ]);
    run_checked(&mut mcopy, "mcopy")?;

    println!(
        "[xtask] built Raspberry Pi 5 FAT32 boot image: {}",
        img_path.display()
    );
    println!("[xtask] staging directory: {}", stage.display());
    println!(
        "[xtask] note: copy RPI_EFI.fd (from worproject/rpi5-uefi) onto the FAT32 SD card root,"
    );
    println!("[xtask]       connect 3-pin JST UART debug probe at 115200 8N1, and power on!");
    Ok(img_path)
}

fn run_host_tests(release: bool) -> Result<(), String> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args([
        "test",
        "--package",
        "newos-abi",
        "--package",
        "newos-kernel-core",
        "--package",
        "newos-shell-core",
        "--package",
        "newos-net",
    ]);
    if release {
        cmd.arg("--release");
    }
    run_checked(&mut cmd, "cargo test (host)")
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
    run_qemu(false, release)
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

fn run_qemu(interactive: bool, release: bool) -> Result<(), String> {
    let iso_path = build_iso(interactive, release)?;
    let firmware = find_firmware()?;
    let iso_str = iso_path.to_str().ok_or("invalid iso path")?;

    let mut qemu = Command::new("qemu-system-aarch64");
    qemu.args([
        "-M",
        "virt",
        "-cpu",
        TARGET_CPU,
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
        "user,id=net0",
        "-device",
        "virtio-net-device,netdev=net0",
        "-bios",
        firmware,
        "-cdrom",
        iso_str,
    ]);
    let status = qemu
        .status()
        .map_err(|e| format!("failed to launch qemu-system-aarch64: {e}"))?;

    match status.code() {
        Some(0) => {
            println!("[xtask] QEMU (aarch64/cortex-a76) exited cleanly (PSCI SYSTEM_OFF)");
            Ok(())
        }
        other => Err(format!(
            "QEMU (aarch64/cortex-a76) exited with unexpected status {other:?}"
        )),
    }
}
