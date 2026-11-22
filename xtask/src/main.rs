use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIMINE_BRANCH: &str = "v9.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";
const QEMU_X86_SUCCESS_EXIT_CODE: i32 = (0x10 << 1) | 1; // 33

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    fn target_triple(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-unknown-none",
            Self::Aarch64 => "aarch64-unknown-none",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn efi_filename(self) -> &'static str {
        match self {
            Self::X86_64 => "BOOTX64.EFI",
            Self::Aarch64 => "BOOTAA64.EFI",
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let mut arch = Arch::X86_64;
    for pair in args.windows(2) {
        if pair[0] == "--arch" {
            match pair[1].as_str() {
                "x86_64" => arch = Arch::X86_64,
                "aarch64" | "arm64" | "rpi5" => arch = Arch::Aarch64,
                other => {
                    eprintln!("[xtask] unsupported arch `{other}` (use x86_64 or aarch64)");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    let result = match cmd {
        "build" => build_iso(arch, true).map(|_| ()),
        "run" => run_qemu(arch, false, true),
        "test" => run_tests(arch),
        "host-test" => run_host_tests(),
        _ => {
            eprintln!("Usage: cargo xtask <build|run|test|host-test> [--arch x86_64|aarch64]");
            Ok(())
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[xtask] error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live inside workspace root")
        .to_path_buf()
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

fn build_kernel(root: &Path, arch: Arch) -> Result<PathBuf, String> {
    let linker_script = root.join(format!("crates/kernel/linker-{}.ld", arch.name()));
    let rustflags = match arch {
        Arch::X86_64 => format!(
            "-C link-arg=-T{} -C relocation-model=static -C code-model=kernel",
            linker_script.display()
        ),
        Arch::Aarch64 => format!(
            "-C link-arg=-T{} -C relocation-model=static",
            linker_script.display()
        ),
    };

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .env("RUSTFLAGS", rustflags)
        .args([
            "build",
            "--package",
            "newos-kernel",
            "--target",
            arch.target_triple(),
            "-Z",
            "build-std=core,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ]);
    run_checked(&mut cmd, &format!("cargo build (newos-kernel {})", arch.name()))?;

    Ok(root
        .join("target")
        .join(arch.target_triple())
        .join("debug")
        .join("newos-kernel"))
}

fn build_user_elf(root: &Path, arch: Arch, pkg: &str, dir: &str) -> Result<PathBuf, String> {
    let linker_script = root.join(format!("crates/{dir}/linker-{}.ld", arch.name()));
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=static",
        linker_script.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .env("RUSTFLAGS", rustflags)
        .args([
            "build",
            "--package",
            pkg,
            "--target",
            arch.target_triple(),
            "-Z",
            "build-std=core,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ]);
    run_checked(&mut cmd, &format!("cargo build ({pkg} {})", arch.name()))?;

    Ok(root
        .join("target")
        .join(arch.target_triple())
        .join("debug")
        .join(pkg))
}

fn ensure_limine(root: &Path) -> Result<PathBuf, String> {
    let limine_dir = root.join("target/limine");
    if !limine_dir.join("BOOTX64.EFI").exists() || !limine_dir.join("BOOTAA64.EFI").exists() {
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

/// Build a pure 64-bit UEFI-only bootable ISO for `x86_64` or `aarch64` (zero legacy BIOS).
fn build_iso(arch: Arch, interactive: bool) -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root, arch)?;
    let init_elf = build_user_elf(&root, arch, "newos-init", "init")?;
    let worker_elf = build_user_elf(&root, arch, "newos-worker", "worker")?;
    let limine_dir = ensure_limine(&root)?;

    let iso_root = root.join(format!("target/iso_root_{}", arch.name()));
    if iso_root.exists() {
        fs::remove_dir_all(&iso_root)
            .map_err(|e| format!("failed to clean iso_root: {e}"))?;
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

    let cmdline = if interactive { "interactive" } else { "test" };
    let limine_conf = format!(
        "timeout: 0\n\
         serial: yes\n\n\
         /NewOS\n\
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
    let efi_name = arch.efi_filename();
    fs::copy(limine_dir.join(efi_name), efi_boot.join(efi_name))
        .map_err(|e| format!("failed to copy {efi_name}: {e}"))?;

    let iso_path = root.join(format!("target/newos-{}.iso", arch.name()));
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

    println!("[xtask] built pure UEFI ISO ({}) {}", arch.name(), iso_path.display());
    Ok(iso_path)
}

fn run_host_tests() -> Result<(), String> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(["test", "--package", "newos-abi", "--package", "newos-kernel-core"]);
    run_checked(&mut cmd, "cargo test (host)")
}

fn run_tests(arch: Arch) -> Result<(), String> {
    run_host_tests()?;
    run_qemu(arch, true, false)
}

fn find_firmware(arch: Arch) -> Result<&'static str, String> {
    let candidates: &[&str] = match arch {
        Arch::X86_64 => &[
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/ovmf/OVMF.fd",
        ],
        Arch::Aarch64 => &[
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        ],
    };
    candidates
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| format!("UEFI firmware not found for {}", arch.name()))
}

fn run_qemu(arch: Arch, expect_success_exit: bool, interactive: bool) -> Result<(), String> {
    let iso_path = build_iso(arch, interactive)?;
    let firmware = find_firmware(arch)?;
    let iso_str = iso_path.to_str().ok_or("invalid iso path")?;

    let status = match arch {
        Arch::X86_64 => {
            let mut qemu = Command::new("qemu-system-x86_64");
            qemu.args([
                "-M",
                "q35",
                "-smp",
                "2",
                "-m",
                "256M",
                "-serial",
                "stdio",
                "-display",
                "none",
                "-no-reboot",
                "-device",
                "isa-debug-exit,iobase=0xf4,iosize=0x04",
                "-drive",
                &format!("if=pflash,unit=0,format=raw,readonly=on,file={firmware}"),
                "-cdrom",
                iso_str,
            ]);
            if Path::new("/dev/kvm").exists() {
                qemu.args(["-enable-kvm", "-cpu", "host"]);
            } else {
                qemu.args(["-cpu", "max"]);
            }
            qemu.status()
                .map_err(|e| format!("failed to launch qemu-system-x86_64: {e}"))?
        }
        Arch::Aarch64 => {
            let mut qemu = Command::new("qemu-system-aarch64");
            qemu.args([
                "-M",
                "virt",
                "-cpu",
                "cortex-a76",
                "-smp",
                "2",
                "-m",
                "512M",
                "-serial",
                "stdio",
                "-display",
                "none",
                "-no-reboot",
                "-bios",
                firmware,
                "-cdrom",
                iso_str,
            ]);
            qemu.status()
                .map_err(|e| format!("failed to launch qemu-system-aarch64: {e}"))?
        }
    };

    match (arch, status.code()) {
        (Arch::X86_64, Some(code)) if code == QEMU_X86_SUCCESS_EXIT_CODE => {
            println!("[xtask] QEMU (x86_64) exited cleanly (isa-debug-exit success)");
            Ok(())
        }
        (Arch::Aarch64, Some(0)) => {
            println!("[xtask] QEMU (aarch64/cortex-a76) exited cleanly (PSCI SYSTEM_OFF)");
            Ok(())
        }
        (_, Some(0)) if !expect_success_exit => Ok(()),
        (_, other) => Err(format!(
            "QEMU ({}) exited with unexpected status {other:?}",
            arch.name()
        )),
    }
}
