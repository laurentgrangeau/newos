use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const LIMINE_BRANCH: &str = "v9.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";
const TARGET_TRIPLE: &str = "x86_64-unknown-none";
const QEMU_SUCCESS_EXIT_CODE: i32 = (0x10 << 1) | 1; // 33

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let result = match cmd {
        "build" => build_iso().map(|_| ()),
        "run" => run_qemu(false),
        "test" => run_tests(),
        "host-test" => run_host_tests(),
        _ => {
            eprintln!("Usage: cargo xtask <build|run|test|host-test>");
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

fn build_kernel(root: &Path) -> Result<PathBuf, String> {
    let linker_script = root.join("crates/kernel/linker-x86_64.ld");
    let rustflags = format!(
        "-C link-arg=-T{} -C relocation-model=static -C code-model=kernel",
        linker_script.display()
    );

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .env("RUSTFLAGS", rustflags)
        .args([
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
    run_checked(&mut cmd, "cargo build (newos-kernel)")?;

    Ok(root
        .join("target")
        .join(TARGET_TRIPLE)
        .join("debug")
        .join("newos-kernel"))
}

fn build_user_elf(root: &Path, pkg: &str, linker_rel: &str) -> Result<PathBuf, String> {
    let linker_script = root.join(linker_rel);
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
            TARGET_TRIPLE,
            "-Z",
            "build-std=core,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ]);
    run_checked(&mut cmd, &format!("cargo build ({pkg})"))?;

    Ok(root
        .join("target")
        .join(TARGET_TRIPLE)
        .join("debug")
        .join(pkg))
}

fn ensure_limine(root: &Path) -> Result<PathBuf, String> {
    let limine_dir = root.join("target/limine");
    if !limine_dir.join("BOOTX64.EFI").exists() {
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

/// Build a pure 64-bit UEFI-only bootable ISO (zero legacy BIOS / MBR stages).
fn build_iso() -> Result<PathBuf, String> {
    let root = workspace_root();
    let kernel_elf = build_kernel(&root)?;
    let init_elf = build_user_elf(&root, "newos-init", "crates/init/linker-x86_64.ld")?;
    let worker_elf = build_user_elf(&root, "newos-worker", "crates/worker/linker-x86_64.ld")?;
    let limine_dir = ensure_limine(&root)?;

    let iso_root = root.join("target/iso_root");
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

    let limine_conf = "\
timeout: 0
serial: yes

/NewOS
    protocol: limine
    path: boot():/boot/newos-kernel
    module_path: boot():/boot/newos-init
    module_path: boot():/boot/newos-worker
";
    fs::write(boot_limine.join("limine.conf"), limine_conf)
        .map_err(|e| format!("failed to write limine.conf: {e}"))?;

    fs::copy(
        limine_dir.join("limine-uefi-cd.bin"),
        boot_limine.join("limine-uefi-cd.bin"),
    )
    .map_err(|e| format!("failed to copy limine-uefi-cd.bin: {e}"))?;
    fs::copy(
        limine_dir.join("BOOTX64.EFI"),
        efi_boot.join("BOOTX64.EFI"),
    )
    .map_err(|e| format!("failed to copy BOOTX64.EFI: {e}"))?;

    let iso_path = root.join("target/newos.iso");
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

    println!("[xtask] built pure UEFI ISO {}", iso_path.display());
    Ok(iso_path)
}

fn run_host_tests() -> Result<(), String> {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(["test", "--package", "newos-abi", "--package", "newos-kernel-core"]);
    run_checked(&mut cmd, "cargo test (host)")
}

fn run_tests() -> Result<(), String> {
    run_host_tests()?;
    run_qemu(true)
}

fn find_ovmf() -> Result<&'static str, String> {
    let ovmf_candidates = [
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
    ];
    ovmf_candidates
        .into_iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| "OVMF UEFI firmware not found (NewOS requires 64-bit UEFI)".to_string())
}

fn run_qemu(expect_success_exit: bool) -> Result<(), String> {
    let iso_path = build_iso()?;
    let ovmf = find_ovmf()?;

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
        &format!("if=pflash,unit=0,format=raw,readonly=on,file={ovmf}"),
        "-cdrom",
        iso_path.to_str().ok_or("invalid iso path")?,
    ]);

    if Path::new("/dev/kvm").exists() {
        qemu.args(["-enable-kvm", "-cpu", "host"]);
    } else {
        qemu.args(["-cpu", "max"]);
    }

    let status = qemu
        .status()
        .map_err(|e| format!("failed to launch qemu-system-x86_64: {e}"))?;

    match status.code() {
        Some(code) if code == QEMU_SUCCESS_EXIT_CODE => {
            println!("[xtask] QEMU exited cleanly (isa-debug-exit success)");
            Ok(())
        }
        Some(0) if !expect_success_exit => Ok(()),
        other => Err(format!(
            "QEMU exited with unexpected status {other:?} (expected {QEMU_SUCCESS_EXIT_CODE})"
        )),
    }
}
