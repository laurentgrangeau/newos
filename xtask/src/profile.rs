//! Zero-dependency declarative TOML system composition & TCB profile parser,
//! dependency validator, and Cargo feature resolver for NewOS (`xtask`).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProfile {
    pub arch: String,
    pub board: String,
    pub cpu: String,

    // [kernel]
    pub scheduler: String,
    pub smp: bool,
    pub userspace: bool,
    pub elf_attestation: bool,
    pub acpi: bool,

    // [domains]
    pub supervisor: bool,
    pub worker: bool,
    pub shell: bool,
    pub net: bool,
    pub key: bool,
    pub ssh: bool,

    // [net]
    pub net_enabled: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub tcp: bool,
    pub udp: bool,
    pub icmp: bool,
    pub dns: bool,
    pub net_drivers: Vec<String>,

    // [crypto]
    pub crypto_algorithms: Vec<String>,

    // [drivers]
    pub storage_drivers: Vec<String>,
    pub rng_drivers: Vec<String>,
    pub gpu_drivers: Vec<String>,
    pub ai_drivers: Vec<String>,
    pub usb_drivers: Vec<String>,
    pub gpio_drivers: Vec<String>,
    pub wdt_drivers: Vec<String>,
    pub board_drivers: Vec<String>,
}

impl BuildProfile {
    /// Default full profile matching the legacy `cargo xtask` behavior.
    pub fn default_full(board: &str) -> Self {
        Self {
            arch: "aarch64".into(),
            board: board.into(),
            cpu: "cortex-a76".into(),
            scheduler: "priority-rr".into(),
            smp: true,
            userspace: true,
            elf_attestation: true,
            acpi: true,
            supervisor: true,
            worker: true,
            shell: true,
            net: true,
            key: true,
            ssh: true,
            net_enabled: true,
            ipv4: true,
            ipv6: true,
            tcp: true,
            udp: true,
            icmp: true,
            dns: true,
            net_drivers: vec!["gem".into(), "virtio".into()],
            crypto_algorithms: vec![
                "sha3".into(),
                "chacha20-poly1305".into(),
                "ml-kem-1024".into(),
                "ml-dsa-87".into(),
            ],
            storage_drivers: vec![
                "pcie".into(),
                "sdhci".into(),
                "nvme".into(),
                "caos-snapshot".into(),
            ],
            rng_drivers: vec!["bcm2712".into(), "virtio".into(), "csprng".into()],
            gpu_drivers: vec!["v3d".into(), "iommu".into()],
            ai_drivers: vec!["compute".into(), "hailo".into()],
            usb_drivers: vec!["xhci".into()],
            gpio_drivers: vec!["rp1".into()],
            wdt_drivers: vec!["bcm2712".into()],
            board_drivers: vec![
                "mailbox".into(),
                "thermal".into(),
                "rtc".into(),
                "rp1-bus".into(),
            ],
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read profile {}: {e}", path.display()))?;
        Self::parse_toml(&content)
    }

    /// Parse a NewOS TOML build profile without external crate dependencies.
    pub fn parse_toml(input: &str) -> Result<Self, String> {
        let mut p = Self::default_full("rpi5");
        let mut section = String::new();

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line_no = line_idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_string();
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(format!(
                    "profile syntax error on line {line_no}: expected `key = value`, got `{line}`"
                ));
            };
            let key = k.trim();
            let val = v.trim();
            match (section.as_str(), key) {
                ("target", "arch") => p.arch = parse_str(val, line_no)?,
                ("target", "board") => p.board = parse_str(val, line_no)?,
                ("target", "cpu") => p.cpu = parse_str(val, line_no)?,

                ("kernel", "scheduler") => p.scheduler = parse_str(val, line_no)?,
                ("kernel", "smp") => p.smp = parse_bool(val, line_no)?,
                ("kernel", "userspace") => p.userspace = parse_bool(val, line_no)?,
                ("kernel", "elf_attestation") => p.elf_attestation = parse_bool(val, line_no)?,
                ("kernel", "acpi") => p.acpi = parse_bool(val, line_no)?,

                ("domains", "supervisor") => p.supervisor = parse_bool(val, line_no)?,
                ("domains", "worker") => p.worker = parse_bool(val, line_no)?,
                ("domains", "shell") => p.shell = parse_bool(val, line_no)?,
                ("domains", "net") => p.net = parse_bool(val, line_no)?,
                ("domains", "key") => p.key = parse_bool(val, line_no)?,
                ("domains", "ssh") => p.ssh = parse_bool(val, line_no)?,

                ("net", "enabled") => p.net_enabled = parse_bool(val, line_no)?,
                ("net", "ipv4") => p.ipv4 = parse_bool(val, line_no)?,
                ("net", "ipv6") => p.ipv6 = parse_bool(val, line_no)?,
                ("net", "tcp") => p.tcp = parse_bool(val, line_no)?,
                ("net", "udp") => p.udp = parse_bool(val, line_no)?,
                ("net", "icmp") => p.icmp = parse_bool(val, line_no)?,
                ("net", "dns") => p.dns = parse_bool(val, line_no)?,
                ("net", "drivers") => p.net_drivers = parse_str_array(val, line_no)?,

                ("crypto", "algorithms") => p.crypto_algorithms = parse_str_array(val, line_no)?,

                ("drivers", "storage") => p.storage_drivers = parse_str_array(val, line_no)?,
                ("drivers", "rng") => p.rng_drivers = parse_str_array(val, line_no)?,
                ("drivers", "gpu") => p.gpu_drivers = parse_str_array(val, line_no)?,
                ("drivers", "ai") => p.ai_drivers = parse_str_array(val, line_no)?,
                ("drivers", "usb") => p.usb_drivers = parse_str_array(val, line_no)?,
                ("drivers", "gpio") => p.gpio_drivers = parse_str_array(val, line_no)?,
                ("drivers", "wdt") => p.wdt_drivers = parse_str_array(val, line_no)?,
                ("drivers", "board") => p.board_drivers = parse_str_array(val, line_no)?,

                (sec, k) => {
                    return Err(format!(
                        "unknown config option `[{sec}].{k}` on line {line_no}"
                    ));
                }
            }
        }
        Ok(p)
    }

    /// Apply ergonomic CLI overrides on top of a loaded system composition profile.
    pub fn apply_cli_overrides(&mut self, args: &[String]) -> Result<(), String> {
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--board" => {
                    i += 1;
                    let b = args
                        .get(i)
                        .ok_or_else(|| "missing value for `--board`".to_string())?;
                    self.board = b.clone();
                }
                "--sched" => {
                    i += 1;
                    let s = args
                        .get(i)
                        .ok_or_else(|| "missing value for `--sched`".to_string())?;
                    self.scheduler = s.clone();
                }
                "--no-smp" => self.smp = false,
                "--no-acpi" => self.acpi = false,
                "--no-domains" => {
                    self.userspace = false;
                    self.supervisor = false;
                    self.worker = false;
                    self.shell = false;
                    self.net = false;
                    self.key = false;
                    self.ssh = false;
                }
                "--no-shell" => {
                    self.shell = false;
                    self.ssh = false;
                }
                "--no-net" => {
                    self.net_enabled = false;
                    self.ipv4 = false;
                    self.ipv6 = false;
                    self.net = false;
                    self.ssh = false;
                }
                "--no-ssh" => {
                    self.ssh = false;
                    self.key = false;
                }
                "--ipv4-only" => {
                    self.net_enabled = true;
                    self.ipv4 = true;
                    self.ipv6 = false;
                }
                "--ipv6-only" => {
                    self.net_enabled = true;
                    self.ipv4 = false;
                    self.ipv6 = true;
                }
                "--no-crypto" => {
                    self.crypto_algorithms.clear();
                    self.elf_attestation = false;
                    self.key = false;
                    self.ssh = false;
                    self.storage_drivers.retain(|d| d != "caos-snapshot");
                    self.rng_drivers.retain(|d| d != "csprng");
                }
                _ => {}
            }
            i += 1;
        }
        Ok(())
    }

    /// Enforce explicit capability/feature dependency invariants across the system composition.
    pub fn validate(&self) -> Result<(), String> {
        if self.arch != "aarch64" {
            return Err(format!(
                "unsupported arch `{}` (currently supported: `aarch64`)",
                self.arch
            ));
        }
        if !matches!(self.board.as_str(), "rpi5" | "qemu-virt") {
            return Err(format!(
                "unsupported board `{}` (currently supported: `rpi5`, `qemu-virt`)",
                self.board
            ));
        }
        if !matches!(
            self.scheduler.as_str(),
            "priority-rr" | "round-robin" | "fifo"
        ) {
            return Err(format!(
                "unsupported scheduler `{}` (supported: `priority-rr`, `round-robin`, `fifo`)",
                self.scheduler
            ));
        }
        if !self.userspace
            && (self.supervisor || self.worker || self.shell || self.net || self.key || self.ssh)
        {
            return Err(
                "Profile error: EL0 protection domains enabled while `[kernel].userspace = false`"
                    .into(),
            );
        }
        if self.shell && !self.supervisor {
            return Err(
                "Profile error: `[domains].shell = true` requires `supervisor = true`".into(),
            );
        }
        if self.net && (!self.net_enabled || (!self.ipv4 && !self.ipv6)) {
            return Err(
                "Profile error: `[domains].net = true` requires `[net].enabled = true` and at least one of `ipv4` or `ipv6`"
                    .into(),
            );
        }
        if self.elf_attestation && !self.has_crypto("sha3") {
            return Err(
                "Profile error: `[kernel].elf_attestation = true` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            );
        }
        if self.key && !(self.has_crypto("sha3") && self.has_crypto("ml-dsa-87")) {
            return Err(
                "Profile error: `[domains].key = true` requires `sha3` and `ml-dsa-87` in `[crypto].algorithms`"
                    .into(),
            );
        }
        if self.ssh {
            if !self.net || !self.key || !self.shell {
                return Err(
                    "Profile error: `[domains].ssh = true` requires `net`, `key`, and `shell`"
                        .into(),
                );
            }
            for req in ["sha3", "chacha20-poly1305", "ml-kem-1024", "ml-dsa-87"] {
                if !self.has_crypto(req) {
                    return Err(format!(
                        "Profile error: `[domains].ssh = true` requires `{req}` in `[crypto].algorithms`"
                    ));
                }
            }
        }
        if self.storage_drivers.iter().any(|d| d == "caos-snapshot") && !self.has_crypto("sha3") {
            return Err(
                "Profile error: `storage` driver `caos-snapshot` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            );
        }
        if self.rng_drivers.iter().any(|d| d == "csprng") && !self.has_crypto("sha3") {
            return Err(
                "Profile error: `rng` driver `csprng` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn has_crypto(&self, alg: &str) -> bool {
        self.crypto_algorithms.iter().any(|a| a == alg)
    }

    /// Resolve Cargo `--features` list for `newos-kernel` (`--no-default-features`).
    pub fn kernel_features(&self) -> Vec<String> {
        let mut feats = vec![format!("arch-{}", self.arch)];
        match self.board.as_str() {
            "rpi5" => feats.push("board-rpi5".into()),
            "qemu-virt" => feats.push("board-qemu-virt".into()),
            _ => {}
        }
        feats.push(format!("sched-{}", self.scheduler));
        if self.smp {
            feats.push("smp".into());
        }
        if self.userspace {
            feats.push("userspace".into());
        }
        if self.elf_attestation {
            feats.push("elf-attestation".into());
        }
        if self.acpi {
            feats.push("acpi".into());
        }
        feats
    }

    /// Resolve Cargo `--features` list for `newos-supervisor-pd` (`--no-default-features`).
    pub fn supervisor_features(&self) -> Vec<String> {
        let mut feats = Vec::new();
        if self.shell {
            feats.push("shell".into());
        }
        if self.net_enabled && self.shell {
            feats.push("net".into());
            if self.ipv4 {
                feats.push("ipv4".into());
            }
            if self.ipv6 {
                feats.push("ipv6".into());
            }
        }
        if self.ssh {
            feats.push("ssh".into());
        }
        if self.worker {
            feats.push("worker-supervisor".into());
        }
        if !self.wdt_drivers.is_empty() {
            feats.push("wdt".into());
        }
        feats
    }

    /// Resolve Cargo `--features` list for `newos-net-pd` (`--no-default-features`).
    pub fn net_pd_features(&self) -> Vec<String> {
        let mut feats = Vec::new();
        if self.ipv4 {
            feats.push("ipv4".into());
        }
        if self.ipv6 {
            feats.push("ipv6".into());
        }
        for drv in &self.net_drivers {
            feats.push(format!("driver-{drv}"));
        }
        feats
    }

    /// Render a resolved system composition & TCB summary for `cargo xtask config`.
    pub fn render_system_composition(&self) -> String {
        let yn = |b: bool| if b { "y" } else { "n" };
        let list = |v: &[String]| {
            if v.is_empty() {
                "none".to_string()
            } else {
                v.join(", ")
            }
        };
        let mut out = String::new();
        let _ = writeln!(out, "NewOS System Composition & TCB Configuration");
        let _ = writeln!(out, "============================================");
        let _ = writeln!(out, "Target:");
        let _ = writeln!(
            out,
            "  ARCH={}  BOARD={}  CPU={}",
            self.arch, self.board, self.cpu
        );
        let _ = writeln!(out, "Kernel (EL1):");
        let _ = writeln!(
            out,
            "  SCHEDULER={}  SMP=[{}]  USERSPACE=[{}]  ELF_ATTEST=[{}]  ACPI=[{}]",
            self.scheduler,
            yn(self.smp),
            yn(self.userspace),
            yn(self.elf_attestation),
            yn(self.acpi)
        );
        let _ = writeln!(
            out,
            "  newos-kernel features: {}",
            self.kernel_features().join(",")
        );
        let _ = writeln!(out, "Protection Domains (EL0):");
        let _ = writeln!(
            out,
            "  SUPERVISOR=[{}]  WORKER=[{}]  SHELL=[{}]  NET=[{}]  KEY=[{}]  SSH=[{}]",
            yn(self.supervisor),
            yn(self.worker),
            yn(self.shell),
            yn(self.net),
            yn(self.key),
            yn(self.ssh)
        );
        let _ = writeln!(out, "Networking:");
        let _ = writeln!(
            out,
            "  NET=[{}]  IPv4=[{}]  IPv6=[{}]  TCP=[{}]  UDP=[{}]  ICMP=[{}]  DNS=[{}]",
            yn(self.net_enabled),
            yn(self.ipv4),
            yn(self.ipv6),
            yn(self.tcp),
            yn(self.udp),
            yn(self.icmp),
            yn(self.dns)
        );
        let _ = writeln!(out, "  NIC drivers: {}", list(&self.net_drivers));
        let _ = writeln!(out, "Cryptography:");
        let _ = writeln!(out, "  Algorithms: {}", list(&self.crypto_algorithms));
        let _ = writeln!(out, "Hardware Drivers:");
        let _ = writeln!(out, "  Storage: {}", list(&self.storage_drivers));
        let _ = writeln!(out, "  RNG:     {}", list(&self.rng_drivers));
        let _ = writeln!(out, "  GPU:     {}", list(&self.gpu_drivers));
        let _ = writeln!(out, "  AI/NPU:  {}", list(&self.ai_drivers));
        let _ = writeln!(out, "  USB:     {}", list(&self.usb_drivers));
        let _ = writeln!(out, "  GPIO:    {}", list(&self.gpio_drivers));
        let _ = writeln!(out, "  WDT:     {}", list(&self.wdt_drivers));
        let _ = writeln!(out, "  Board:   {}", list(&self.board_drivers));
        out
    }

    /// Return an exhaustive CLI reference of all supported TOML profile options and valid values.
    pub fn list_all_options() -> &'static str {
        "\
NewOS Profile Options Reference (profiles/*.toml)
=================================================

[target]
  arch              string     \"aarch64\"
  board             string     \"rpi5\" | \"qemu-virt\"
  cpu               string     \"cortex-a76\" | any LLVM AArch64 target-cpu

[kernel]
  scheduler         string     \"priority-rr\" | \"round-robin\" | \"fifo\"
  smp               bool       true | false
  userspace         bool       true | false  (false = pure EL1 kernel)
  elf_attestation   bool       true | false  (depends on crypto: sha3)
  acpi              bool       true | false

[domains]
  supervisor        bool       true | false  (depends on kernel.userspace)
  worker            bool       true | false  (depends on kernel.userspace)
  shell             bool       true | false  (depends on domains.supervisor)
  net               bool       true | false  (depends on net.enabled + ipv4|ipv6)
  key               bool       true | false  (depends on crypto: sha3, ml-dsa-87)
  ssh               bool       true | false  (depends on net, key, shell, all 4 PQ crypto)

[net]
  enabled           bool       true | false
  ipv4              bool       true | false
  ipv6              bool       true | false
  tcp               bool       true | false
  udp               bool       true | false
  icmp              bool       true | false
  dns               bool       true | false
  drivers           string[]   \"gem\", \"virtio\" (subset or [])

[crypto]
  algorithms        string[]   \"sha3\", \"chacha20-poly1305\", \"ml-kem-1024\", \"ml-dsa-87\" (subset or [])

[drivers]
  storage           string[]   \"pcie\", \"sdhci\", \"nvme\", \"caos-snapshot\" (caos-snapshot needs sha3)
  rng               string[]   \"bcm2712\", \"virtio\", \"csprng\" (csprng needs sha3)
  gpu               string[]   \"v3d\", \"iommu\"
  ai                string[]   \"compute\", \"hailo\"
  usb               string[]   \"xhci\"
  gpio              string[]   \"rp1\"
  wdt               string[]   \"bcm2712\"
  board             string[]   \"mailbox\", \"thermal\", \"rtc\", \"rp1-bus\"

See profiles/OPTIONS.md for full descriptions and CLI overrides.
"
    }
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_str(val: &str, line_no: usize) -> Result<String, String> {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        Ok(val[1..val.len() - 1].to_string())
    } else {
        Err(format!(
            "line {line_no}: expected quoted string, got `{val}`"
        ))
    }
}

fn parse_bool(val: &str, line_no: usize) -> Result<bool, String> {
    match val {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("line {line_no}: expected boolean, got `{val}`")),
    }
}

fn parse_str_array(val: &str, line_no: usize) -> Result<Vec<String>, String> {
    if !(val.starts_with('[') && val.ends_with(']')) {
        return Err(format!("line {line_no}: expected `[...]`, got `{val}`"));
    }
    let inner = val[1..val.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    for part in inner.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        items.push(parse_str(trimmed, line_no)?);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn all_shipped_profiles_parse_and_validate() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profiles = [
            "profiles/tinykernel.toml",
            "profiles/minimal-supervisor.toml",
            "profiles/rpi5-net.toml",
            "profiles/rpi5-full.toml",
            "profiles/qemu-virt-full.toml",
        ];
        for rel in profiles {
            let p = BuildProfile::from_file(&root.join(rel))
                .unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
            p.validate()
                .unwrap_or_else(|e| panic!("profile {rel} failed validation: {e}"));
        }
    }

    #[test]
    fn tinykernel_profile_has_zero_userspace_and_zero_crypto() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let p = BuildProfile::from_file(&root.join("profiles/tinykernel.toml")).unwrap();
        assert!(!p.userspace);
        assert!(!p.smp);
        assert_eq!(p.scheduler, "fifo");
        assert!(p.crypto_algorithms.is_empty());
        assert_eq!(
            p.kernel_features(),
            vec!["arch-aarch64", "board-rpi5", "sched-fifo"]
        );
    }

    #[test]
    fn validation_rejects_broken_profile_dependencies() {
        let mut p = BuildProfile::default_full("rpi5");
        p.crypto_algorithms.clear();
        assert!(p.validate().is_err());

        let mut p2 = BuildProfile::default_full("rpi5");
        p2.apply_cli_overrides(&["--no-crypto".into()]).unwrap();
        p2.validate()
            .expect("--no-crypto override must leave valid profile");
        assert!(p2.crypto_algorithms.is_empty());
        assert!(!p2.ssh && !p2.key && !p2.elf_attestation);

        let mut p3 = BuildProfile::default_full("rpi5");
        p3.apply_cli_overrides(&["--ipv6-only".into()]).unwrap();
        p3.validate().expect("--ipv6-only must be valid");
        assert!(!p3.ipv4 && p3.ipv6);
    }
}
