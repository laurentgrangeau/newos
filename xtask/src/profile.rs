//! Zero-dependency declarative TOML system composition & TCB profile parser,
//! dependency validator, and Cargo feature resolver for `NewOS` (`xtask`).

use crate::error::XtaskError;
use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::fs;
use std::path::Path;
use std::str::FromStr;

/// Supported hardware/emulator target boards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetBoard {
    Rpi5,
    QemuVirt,
}

impl TargetBoard {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rpi5 => "rpi5",
            Self::QemuVirt => "qemu-virt",
        }
    }

    #[must_use]
    pub const fn kernel_feature(self) -> &'static str {
        match self {
            Self::Rpi5 => "board-rpi5",
            Self::QemuVirt => "board-qemu-virt",
        }
    }
}

impl fmt::Display for TargetBoard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TargetBoard {
    type Err = XtaskError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rpi5" => Ok(Self::Rpi5),
            "qemu-virt" => Ok(Self::QemuVirt),
            other => Err(XtaskError::ProfileValidation(format!(
                "unsupported board `{other}` (currently supported: `rpi5`, `qemu-virt`)"
            ))),
        }
    }
}

/// Supported EL1 kernel scheduler policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerPolicy {
    PriorityRr,
    RoundRobin,
    Fifo,
}

impl SchedulerPolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PriorityRr => "priority-rr",
            Self::RoundRobin => "round-robin",
            Self::Fifo => "fifo",
        }
    }

    #[must_use]
    pub const fn kernel_feature(self) -> &'static str {
        match self {
            Self::PriorityRr => "sched-priority-rr",
            Self::RoundRobin => "sched-round-robin",
            Self::Fifo => "sched-fifo",
        }
    }
}

impl fmt::Display for SchedulerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SchedulerPolicy {
    type Err = XtaskError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "priority-rr" => Ok(Self::PriorityRr),
            "round-robin" => Ok(Self::RoundRobin),
            "fifo" => Ok(Self::Fifo),
            other => Err(XtaskError::ProfileValidation(format!(
                "unsupported scheduler `{other}` (supported: `priority-rr`, `round-robin`, `fifo`)"
            ))),
        }
    }
}

/// Compact bitset for `[kernel]` feature toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KernelOptions(u8);

impl KernelOptions {
    const SMP: u8 = 1 << 0;
    const USERSPACE: u8 = 1 << 1;
    const ELF_ATTESTATION: u8 = 1 << 2;
    const ACPI: u8 = 1 << 3;

    #[must_use]
    pub const fn all() -> Self {
        Self(Self::SMP | Self::USERSPACE | Self::ELF_ATTESTATION | Self::ACPI)
    }

    #[must_use]
    pub const fn smp(self) -> bool {
        (self.0 & Self::SMP) != 0
    }

    #[must_use]
    pub const fn userspace(self) -> bool {
        (self.0 & Self::USERSPACE) != 0
    }

    #[must_use]
    pub const fn elf_attestation(self) -> bool {
        (self.0 & Self::ELF_ATTESTATION) != 0
    }

    #[must_use]
    pub const fn acpi(self) -> bool {
        (self.0 & Self::ACPI) != 0
    }

    const fn set_flag(&mut self, bit: u8, enabled: bool) {
        if enabled {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub const fn set_smp(&mut self, enabled: bool) {
        self.set_flag(Self::SMP, enabled);
    }

    pub const fn set_userspace(&mut self, enabled: bool) {
        self.set_flag(Self::USERSPACE, enabled);
    }

    pub const fn set_elf_attestation(&mut self, enabled: bool) {
        self.set_flag(Self::ELF_ATTESTATION, enabled);
    }

    pub const fn set_acpi(&mut self, enabled: bool) {
        self.set_flag(Self::ACPI, enabled);
    }
}

/// Compact bitset for `[domains]` EL0 protection domain selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainSet(u8);

impl DomainSet {
    const SUPERVISOR: u8 = 1 << 0;
    const WORKER: u8 = 1 << 1;
    const SHELL: u8 = 1 << 2;
    const NET: u8 = 1 << 3;
    const KEY: u8 = 1 << 4;
    const SSH: u8 = 1 << 5;

    #[must_use]
    pub const fn all() -> Self {
        Self(Self::SUPERVISOR | Self::WORKER | Self::SHELL | Self::NET | Self::KEY | Self::SSH)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn clear(&mut self) {
        self.0 = 0;
    }

    #[must_use]
    pub const fn supervisor(self) -> bool {
        (self.0 & Self::SUPERVISOR) != 0
    }

    #[must_use]
    pub const fn worker(self) -> bool {
        (self.0 & Self::WORKER) != 0
    }

    #[must_use]
    pub const fn shell(self) -> bool {
        (self.0 & Self::SHELL) != 0
    }

    #[must_use]
    pub const fn net(self) -> bool {
        (self.0 & Self::NET) != 0
    }

    #[must_use]
    pub const fn key(self) -> bool {
        (self.0 & Self::KEY) != 0
    }

    #[must_use]
    pub const fn ssh(self) -> bool {
        (self.0 & Self::SSH) != 0
    }

    const fn set_flag(&mut self, bit: u8, enabled: bool) {
        if enabled {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub const fn set_supervisor(&mut self, enabled: bool) {
        self.set_flag(Self::SUPERVISOR, enabled);
    }

    pub const fn set_worker(&mut self, enabled: bool) {
        self.set_flag(Self::WORKER, enabled);
    }

    pub const fn set_shell(&mut self, enabled: bool) {
        self.set_flag(Self::SHELL, enabled);
    }

    pub const fn set_net(&mut self, enabled: bool) {
        self.set_flag(Self::NET, enabled);
    }

    pub const fn set_key(&mut self, enabled: bool) {
        self.set_flag(Self::KEY, enabled);
    }

    pub const fn set_ssh(&mut self, enabled: bool) {
        self.set_flag(Self::SSH, enabled);
    }
}

/// Compact bitset for `[net]` protocol selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetProtocols(u8);

impl NetProtocols {
    const IPV4: u8 = 1 << 0;
    const IPV6: u8 = 1 << 1;
    const TCP: u8 = 1 << 2;
    const UDP: u8 = 1 << 3;
    const ICMP: u8 = 1 << 4;
    const DNS: u8 = 1 << 5;

    #[must_use]
    pub const fn all() -> Self {
        Self(Self::IPV4 | Self::IPV6 | Self::TCP | Self::UDP | Self::ICMP | Self::DNS)
    }

    pub const fn clear(&mut self) {
        self.0 = 0;
    }

    #[must_use]
    pub const fn has_ip(self) -> bool {
        self.ipv4() || self.ipv6()
    }

    #[must_use]
    pub const fn ipv4(self) -> bool {
        (self.0 & Self::IPV4) != 0
    }

    #[must_use]
    pub const fn ipv6(self) -> bool {
        (self.0 & Self::IPV6) != 0
    }

    #[must_use]
    pub const fn tcp(self) -> bool {
        (self.0 & Self::TCP) != 0
    }

    #[must_use]
    pub const fn udp(self) -> bool {
        (self.0 & Self::UDP) != 0
    }

    #[must_use]
    pub const fn icmp(self) -> bool {
        (self.0 & Self::ICMP) != 0
    }

    #[must_use]
    pub const fn dns(self) -> bool {
        (self.0 & Self::DNS) != 0
    }

    const fn set_flag(&mut self, bit: u8, enabled: bool) {
        if enabled {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub const fn set_ipv4(&mut self, enabled: bool) {
        self.set_flag(Self::IPV4, enabled);
    }

    pub const fn set_ipv6(&mut self, enabled: bool) {
        self.set_flag(Self::IPV6, enabled);
    }

    pub const fn set_tcp(&mut self, enabled: bool) {
        self.set_flag(Self::TCP, enabled);
    }

    pub const fn set_udp(&mut self, enabled: bool) {
        self.set_flag(Self::UDP, enabled);
    }

    pub const fn set_icmp(&mut self, enabled: bool) {
        self.set_flag(Self::ICMP, enabled);
    }

    pub const fn set_dns(&mut self, enabled: bool) {
        self.set_flag(Self::DNS, enabled);
    }

    /// Iterate over enabled Cargo feature names for network protocols.
    pub fn feature_names(self) -> impl Iterator<Item = &'static str> {
        [
            (self.ipv4(), "ipv4"),
            (self.ipv6(), "ipv6"),
            (self.tcp(), "tcp"),
            (self.udp(), "udp"),
            (self.icmp(), "icmp"),
            (self.dns(), "dns"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
    }
}

/// `[net]` section configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetConfig {
    pub enabled: bool,
    pub protocols: NetProtocols,
    pub drivers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProfile {
    pub arch: String,
    pub board: TargetBoard,
    pub cpu: String,

    // [kernel]
    pub scheduler: SchedulerPolicy,
    pub kernel: KernelOptions,

    // [domains]
    pub domains: DomainSet,

    // [net]
    pub net: NetConfig,

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
    #[must_use]
    pub fn default_full(board: TargetBoard) -> Self {
        Self {
            arch: "aarch64".into(),
            board,
            cpu: "cortex-a76".into(),
            scheduler: SchedulerPolicy::PriorityRr,
            kernel: KernelOptions::all(),
            domains: DomainSet::all(),
            net: NetConfig {
                enabled: true,
                protocols: NetProtocols::all(),
                drivers: vec!["gem".into(), "virtio".into()],
            },
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

    /// Minimal empty profile used as the base for `parse_toml` so omitted keys never
    /// silently enable SSH, networking, crypto, or hardware drivers (`M9`).
    #[must_use]
    pub fn minimal_empty() -> Self {
        Self {
            arch: "aarch64".into(),
            board: TargetBoard::Rpi5,
            cpu: "cortex-a76".into(),
            scheduler: SchedulerPolicy::PriorityRr,
            kernel: KernelOptions::default(),
            domains: DomainSet::default(),
            net: NetConfig::default(),
            crypto_algorithms: Vec::new(),
            storage_drivers: Vec::new(),
            rng_drivers: Vec::new(),
            gpu_drivers: Vec::new(),
            ai_drivers: Vec::new(),
            usb_drivers: Vec::new(),
            gpio_drivers: Vec::new(),
            wdt_drivers: Vec::new(),
            board_drivers: Vec::new(),
        }
    }

    /// Load and parse a `NewOS` TOML build profile from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`XtaskError::Io`] if reading `path` fails, or [`XtaskError::ProfileParse`] /
    /// [`XtaskError::ProfileValidation`] if the TOML syntax or values are invalid.
    pub fn from_file(path: &Path) -> Result<Self, XtaskError> {
        let content = fs::read_to_string(path)
            .map_err(|e| XtaskError::io(format!("failed to read profile {}", path.display()), e))?;
        Self::parse_toml(&content)
    }

    /// Parse a `NewOS` TOML build profile without external crate dependencies.
    ///
    /// Rejects duplicate keys, unknown sections/keys, and starts from [`Self::minimal_empty`]
    /// so omitted keys never silently leave features enabled (`M9`).
    ///
    /// # Errors
    ///
    /// Returns [`XtaskError::ProfileParse`] on syntax, duplicate-key, or unknown-key errors, or
    /// [`XtaskError::ProfileValidation`] on invalid board/scheduler values.
    pub fn parse_toml(input: &str) -> Result<Self, XtaskError> {
        let mut p = Self::minimal_empty();
        let mut section: &str = "";
        let mut seen_keys: BTreeSet<(&str, &str)> = BTreeSet::new();

        for (line_idx, raw_line) in input.lines().enumerate() {
            let line_no = line_idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim();
                if !matches!(
                    section,
                    "target" | "kernel" | "domains" | "net" | "crypto" | "drivers"
                ) {
                    return Err(XtaskError::ProfileParse {
                        line: line_no,
                        message: format!("unknown profile section `[{section}]`"),
                    });
                }
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(XtaskError::ProfileParse {
                    line: line_no,
                    message: format!("profile syntax error: expected `key = value`, got `{line}`"),
                });
            };
            let key = k.trim();
            let val = v.trim();
            let canonical_key = if section == "kernel" && key == "elf_measurement" {
                "elf_attestation"
            } else {
                key
            };
            if !seen_keys.insert((section, canonical_key)) {
                return Err(XtaskError::ProfileParse {
                    line: line_no,
                    message: format!("duplicate config option `[{section}].{key}`"),
                });
            }
            p.apply_toml_kv(section, key, val, line_no)?;
        }
        Ok(p)
    }

    fn apply_toml_kv(
        &mut self,
        section: &str,
        key: &str,
        val: &str,
        line_no: usize,
    ) -> Result<(), XtaskError> {
        match (section, key) {
            ("target", "arch") => self.arch = parse_str(val, line_no)?,
            ("target", "board") => self.board = parse_str(val, line_no)?.parse()?,
            ("target", "cpu") => self.cpu = parse_str(val, line_no)?,

            ("kernel", "scheduler") => self.scheduler = parse_str(val, line_no)?.parse()?,
            ("kernel", "smp") => self.kernel.set_smp(parse_bool(val, line_no)?),
            ("kernel", "userspace") => self.kernel.set_userspace(parse_bool(val, line_no)?),
            ("kernel", "elf_attestation" | "elf_measurement") => {
                self.kernel.set_elf_attestation(parse_bool(val, line_no)?);
            }
            ("kernel", "acpi") => self.kernel.set_acpi(parse_bool(val, line_no)?),

            ("domains", "supervisor") => self.domains.set_supervisor(parse_bool(val, line_no)?),
            ("domains", "worker") => self.domains.set_worker(parse_bool(val, line_no)?),
            ("domains", "shell") => self.domains.set_shell(parse_bool(val, line_no)?),
            ("domains", "net") => self.domains.set_net(parse_bool(val, line_no)?),
            ("domains", "key") => self.domains.set_key(parse_bool(val, line_no)?),
            ("domains", "ssh") => self.domains.set_ssh(parse_bool(val, line_no)?),

            ("net", "enabled") => self.net.enabled = parse_bool(val, line_no)?,
            ("net", "ipv4") => self.net.protocols.set_ipv4(parse_bool(val, line_no)?),
            ("net", "ipv6") => self.net.protocols.set_ipv6(parse_bool(val, line_no)?),
            ("net", "tcp") => self.net.protocols.set_tcp(parse_bool(val, line_no)?),
            ("net", "udp") => self.net.protocols.set_udp(parse_bool(val, line_no)?),
            ("net", "icmp") => self.net.protocols.set_icmp(parse_bool(val, line_no)?),
            ("net", "dns") => self.net.protocols.set_dns(parse_bool(val, line_no)?),
            ("net", "drivers") => self.net.drivers = parse_str_array(val, line_no)?,

            ("crypto", "algorithms") => self.crypto_algorithms = parse_str_array(val, line_no)?,

            ("drivers", "storage") => self.storage_drivers = parse_str_array(val, line_no)?,
            ("drivers", "rng") => self.rng_drivers = parse_str_array(val, line_no)?,
            ("drivers", "gpu") => self.gpu_drivers = parse_str_array(val, line_no)?,
            ("drivers", "ai") => self.ai_drivers = parse_str_array(val, line_no)?,
            ("drivers", "usb") => self.usb_drivers = parse_str_array(val, line_no)?,
            ("drivers", "gpio") => self.gpio_drivers = parse_str_array(val, line_no)?,
            ("drivers", "wdt") => self.wdt_drivers = parse_str_array(val, line_no)?,
            ("drivers", "board") => self.board_drivers = parse_str_array(val, line_no)?,

            (sec, k) => {
                return Err(XtaskError::ProfileParse {
                    line: line_no,
                    message: format!("unknown config option `[{sec}].{k}`"),
                });
            }
        }
        Ok(())
    }

    /// Apply ergonomic CLI overrides on top of a loaded system composition profile.
    ///
    /// Rejects any unrecognized flag so typos like `--no-sshd` never silently leave SSH on (`M9`).
    ///
    /// # Errors
    ///
    /// Returns [`XtaskError::Cli`] on missing flag arguments or unknown CLI options, or
    /// [`XtaskError::ProfileValidation`] on unsupported `--board` / `--sched` values.
    pub fn apply_cli_overrides<S: AsRef<str>>(&mut self, args: &[S]) -> Result<(), XtaskError> {
        let mut i = 0;
        while i < args.len() {
            match args[i].as_ref() {
                "--profile" => {
                    i += 1;
                    if args.get(i).is_none() {
                        return Err(XtaskError::Cli("missing value for `--profile`".into()));
                    }
                }
                "--release" | "--debug" | "--list-options" => {}
                "--board" => {
                    i += 1;
                    let b = args
                        .get(i)
                        .ok_or_else(|| XtaskError::Cli("missing value for `--board`".into()))?;
                    self.board = b.as_ref().parse()?;
                }
                "--sched" => {
                    i += 1;
                    let s = args
                        .get(i)
                        .ok_or_else(|| XtaskError::Cli("missing value for `--sched`".into()))?;
                    self.scheduler = s.as_ref().parse()?;
                }
                "--no-smp" => self.kernel.set_smp(false),
                "--no-acpi" => self.kernel.set_acpi(false),
                "--no-domains" => {
                    self.kernel.set_userspace(false);
                    self.domains.clear();
                }
                "--no-shell" => {
                    self.domains.set_shell(false);
                    self.domains.set_ssh(false);
                }
                "--no-net" => {
                    self.net.enabled = false;
                    self.net.protocols.clear();
                    self.domains.set_net(false);
                    self.domains.set_ssh(false);
                }
                "--no-ssh" => {
                    self.domains.set_ssh(false);
                    self.domains.set_key(false);
                }
                "--ipv4-only" => {
                    self.net.enabled = true;
                    self.net.protocols.set_ipv4(true);
                    self.net.protocols.set_ipv6(false);
                }
                "--ipv6-only" => {
                    self.net.enabled = true;
                    self.net.protocols.set_ipv4(false);
                    self.net.protocols.set_ipv6(true);
                }
                "--no-crypto" => {
                    self.crypto_algorithms.clear();
                    self.kernel.set_elf_attestation(false);
                    self.domains.set_key(false);
                    self.domains.set_ssh(false);
                    self.storage_drivers.retain(|d| d != "caos-snapshot");
                    self.rng_drivers.retain(|d| d != "csprng");
                }
                unknown => {
                    return Err(XtaskError::Cli(format!(
                        "unknown CLI option `{unknown}` (run `cargo xtask help` for valid options)"
                    )));
                }
            }
            i += 1;
        }
        Ok(())
    }

    /// Enforce explicit capability/feature dependency invariants across the system composition.
    ///
    /// # Errors
    ///
    /// Returns [`XtaskError::ProfileValidation`] if any target, driver, algorithm, or cross-domain
    /// dependency invariant is violated.
    pub fn validate(&self) -> Result<(), XtaskError> {
        self.validate_drivers()?;
        self.validate_dependencies()
    }

    fn validate_drivers(&self) -> Result<(), XtaskError> {
        if self.arch != "aarch64" {
            return Err(XtaskError::ProfileValidation(format!(
                "unsupported arch `{}` (currently supported: `aarch64`)",
                self.arch
            )));
        }
        for alg in &self.crypto_algorithms {
            if !matches!(
                alg.as_str(),
                "sha3" | "chacha20-poly1305" | "ml-kem-1024" | "ml-dsa-87"
            ) {
                return Err(XtaskError::ProfileValidation(format!(
                    "Profile error: unknown crypto algorithm `{alg}`"
                )));
            }
        }
        for drv in &self.net.drivers {
            if !matches!(drv.as_str(), "gem" | "virtio") {
                return Err(XtaskError::ProfileValidation(format!(
                    "Profile error: unknown net driver `{drv}`"
                )));
            }
        }
        for (cat, list, allowed) in [
            (
                "storage",
                &self.storage_drivers,
                &["pcie", "sdhci", "nvme", "caos-snapshot"][..],
            ),
            (
                "rng",
                &self.rng_drivers,
                &["bcm2712", "virtio", "csprng"][..],
            ),
            ("gpu", &self.gpu_drivers, &["v3d", "iommu"][..]),
            ("ai", &self.ai_drivers, &["compute", "hailo"][..]),
            ("usb", &self.usb_drivers, &["xhci"][..]),
            ("gpio", &self.gpio_drivers, &["rp1"][..]),
            ("wdt", &self.wdt_drivers, &["bcm2712"][..]),
            (
                "board",
                &self.board_drivers,
                &["mailbox", "thermal", "rtc", "rp1-bus"][..],
            ),
        ] {
            for drv in list {
                if !allowed.contains(&drv.as_str()) {
                    return Err(XtaskError::ProfileValidation(format!(
                        "Profile error: unknown `[drivers].{cat}` entry `{drv}`"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_dependencies(&self) -> Result<(), XtaskError> {
        if self.scheduler == SchedulerPolicy::Fifo && self.kernel.userspace() {
            return Err(XtaskError::ProfileValidation(
                "Profile error: cooperative scheduler `fifo` cannot be combined with `[kernel].userspace = true` (`M6`)"
                    .into(),
            ));
        }
        if !self.kernel.userspace() && !self.domains.is_empty() {
            return Err(XtaskError::ProfileValidation(
                "Profile error: EL0 protection domains enabled while `[kernel].userspace = false`"
                    .into(),
            ));
        }
        if self.domains.shell() && !self.domains.supervisor() {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `[domains].shell = true` requires `supervisor = true`".into(),
            ));
        }
        if self.domains.net() && (!self.net.enabled || !self.net.protocols.has_ip()) {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `[domains].net = true` requires `[net].enabled = true` and at least one of `ipv4` or `ipv6`"
                    .into(),
            ));
        }
        if self.kernel.elf_attestation() && !self.has_crypto("sha3") {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `[kernel].elf_attestation = true` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            ));
        }
        if self.domains.key() && !(self.has_crypto("sha3") && self.has_crypto("ml-dsa-87")) {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `[domains].key = true` requires `sha3` and `ml-dsa-87` in `[crypto].algorithms`"
                    .into(),
            ));
        }
        if self.domains.ssh() {
            if !self.domains.net() || !self.domains.key() || !self.domains.shell() {
                return Err(XtaskError::ProfileValidation(
                    "Profile error: `[domains].ssh = true` requires `net`, `key`, and `shell`"
                        .into(),
                ));
            }
            for req in ["sha3", "chacha20-poly1305", "ml-kem-1024", "ml-dsa-87"] {
                if !self.has_crypto(req) {
                    return Err(XtaskError::ProfileValidation(format!(
                        "Profile error: `[domains].ssh = true` requires `{req}` in `[crypto].algorithms`"
                    )));
                }
            }
        }
        if self.storage_drivers.iter().any(|d| d == "caos-snapshot") && !self.has_crypto("sha3") {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `storage` driver `caos-snapshot` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            ));
        }
        if self.rng_drivers.iter().any(|d| d == "csprng") && !self.has_crypto("sha3") {
            return Err(XtaskError::ProfileValidation(
                "Profile error: `rng` driver `csprng` requires `sha3` in `[crypto].algorithms`"
                    .into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn has_crypto(&self, alg: &str) -> bool {
        self.crypto_algorithms.iter().any(|a| a == alg)
    }

    /// Resolve Cargo `--features` list for `newos-kernel` (`--no-default-features`).
    #[must_use]
    pub fn kernel_features(&self) -> Vec<String> {
        let mut feats = vec![
            format!("arch-{}", self.arch),
            self.board.kernel_feature().into(),
            self.scheduler.kernel_feature().into(),
        ];
        if self.kernel.smp() {
            feats.push("smp".into());
        }
        if self.kernel.userspace() {
            feats.push("userspace".into());
        }
        if self.kernel.elf_attestation() {
            feats.push("elf-measurement".into());
        }
        if self.kernel.acpi() {
            feats.push("acpi".into());
        }
        if !self.wdt_drivers.is_empty() {
            feats.push("mmio-wdt".into());
        }
        if !self.gpio_drivers.is_empty() {
            feats.push("mmio-gpio".into());
        }
        if self.board_drivers.iter().any(|d| d == "mailbox") {
            feats.push("mmio-mbox".into());
        }
        if self.board_drivers.iter().any(|d| d == "thermal") {
            feats.push("mmio-thermal".into());
        }
        if self.board_drivers.iter().any(|d| d == "rp1-bus") {
            feats.push("mmio-rp1-uart".into());
        }
        if self.storage_drivers.iter().any(|d| d == "sdhci") {
            feats.push("mmio-sdhci".into());
        }
        if !self.usb_drivers.is_empty() {
            feats.push("mmio-xhci".into());
        }
        if self.gpu_drivers.iter().any(|d| d == "v3d") {
            feats.push("mmio-v3d".into());
        }
        feats
    }

    /// Resolve Cargo `--features` list for `newos-supervisor-pd` (`--no-default-features`).
    #[must_use]
    pub fn supervisor_features(&self) -> Vec<String> {
        let mut feats = Vec::new();
        if self.domains.shell() {
            feats.push("shell".into());
            if self.has_crypto("sha3") {
                feats.push("crypto-sha3".into());
            }
        }
        if self.net.enabled && self.domains.shell() {
            feats.push("net".into());
            feats.extend(self.net.protocols.feature_names().map(str::to_owned));
        }
        if self.domains.ssh() {
            feats.push("ssh".into());
        }
        if self.domains.worker() {
            feats.push("worker-supervisor".into());
        }
        if !self.wdt_drivers.is_empty() {
            feats.push("wdt".into());
        }
        feats
    }

    /// Resolve Cargo `--features` list for `newos-net-pd` (`--no-default-features`).
    #[must_use]
    pub fn net_pd_features(&self) -> Vec<String> {
        let mut feats: Vec<String> = self
            .net
            .protocols
            .feature_names()
            .map(str::to_owned)
            .collect();
        for drv in &self.net.drivers {
            feats.push(format!("driver-{drv}"));
        }
        feats
    }

    /// Resolve Cargo `--features` list for `newos-key-pd` (`--no-default-features`).
    #[must_use]
    pub fn key_pd_features(&self) -> Vec<String> {
        let mut feats = Vec::new();
        for drv in &self.rng_drivers {
            match drv.as_str() {
                "bcm2712" => feats.push("driver-bcm2712".into()),
                "virtio" => feats.push("driver-virtio".into()),
                "csprng" => feats.push("csprng".into()),
                _ => {}
            }
        }
        feats
    }

    /// Render a resolved system composition & TCB summary for `cargo xtask config`.
    #[must_use]
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
            yn(self.kernel.smp()),
            yn(self.kernel.userspace()),
            yn(self.kernel.elf_attestation()),
            yn(self.kernel.acpi())
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
            yn(self.domains.supervisor()),
            yn(self.domains.worker()),
            yn(self.domains.shell()),
            yn(self.domains.net()),
            yn(self.domains.key()),
            yn(self.domains.ssh())
        );
        let _ = writeln!(out, "Networking:");
        let _ = writeln!(
            out,
            "  NET=[{}]  IPv4=[{}]  IPv6=[{}]  TCP=[{}]  UDP=[{}]  ICMP=[{}]  DNS=[{}]",
            yn(self.net.enabled),
            yn(self.net.protocols.ipv4()),
            yn(self.net.protocols.ipv6()),
            yn(self.net.protocols.tcp()),
            yn(self.net.protocols.udp()),
            yn(self.net.protocols.icmp()),
            yn(self.net.protocols.dns())
        );
        let _ = writeln!(out, "  NIC drivers: {}", list(&self.net.drivers));
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
    #[must_use]
    pub const fn list_all_options() -> &'static str {
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

fn parse_str(val: &str, line_no: usize) -> Result<String, XtaskError> {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        Ok(val[1..val.len() - 1].to_string())
    } else {
        Err(XtaskError::ProfileParse {
            line: line_no,
            message: format!("expected quoted string, got `{val}`"),
        })
    }
}

fn parse_bool(val: &str, line_no: usize) -> Result<bool, XtaskError> {
    match val {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(XtaskError::ProfileParse {
            line: line_no,
            message: format!("expected boolean, got `{val}`"),
        }),
    }
}

fn parse_str_array(val: &str, line_no: usize) -> Result<Vec<String>, XtaskError> {
    if !(val.starts_with('[') && val.ends_with(']')) {
        return Err(XtaskError::ProfileParse {
            line: line_no,
            message: format!("expected `[...]`, got `{val}`"),
        });
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
            .expect("xtask crate has workspace root parent")
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
            .expect("xtask crate has workspace root parent")
            .to_path_buf();
        let p = BuildProfile::from_file(&root.join("profiles/tinykernel.toml"))
            .expect("tinykernel profile parses");
        assert!(!p.kernel.userspace());
        assert!(!p.kernel.smp());
        assert_eq!(p.scheduler, SchedulerPolicy::Fifo);
        assert_eq!(p.crypto_algorithms, [] as [String; 0]);
        assert_eq!(
            p.kernel_features(),
            vec!["arch-aarch64", "board-rpi5", "sched-fifo"]
        );
    }

    #[test]
    fn validation_rejects_broken_profile_dependencies() {
        let mut p = BuildProfile::default_full(TargetBoard::Rpi5);
        p.crypto_algorithms.clear();
        assert!(p.validate().is_err());

        let mut p2 = BuildProfile::default_full(TargetBoard::Rpi5);
        p2.apply_cli_overrides(&["--no-crypto"])
            .expect("--no-crypto parses");
        p2.validate()
            .expect("--no-crypto override must leave valid profile");
        assert_eq!(p2.crypto_algorithms, [] as [String; 0]);
        assert!(!p2.domains.ssh() && !p2.domains.key() && !p2.kernel.elf_attestation());

        let mut p3 = BuildProfile::default_full(TargetBoard::Rpi5);
        p3.apply_cli_overrides(&["--ipv6-only"])
            .expect("--ipv6-only parses");
        p3.validate().expect("--ipv6-only must be valid");
        assert!(!p3.net.protocols.ipv4() && p3.net.protocols.ipv6());

        // M9: unknown CLI flags like `--no-sshd` must fail closed instead of leaving SSH enabled.
        let mut p4 = BuildProfile::default_full(TargetBoard::QemuVirt);
        assert!(p4.apply_cli_overrides(&["--no-sshd"]).is_err());

        // M6: cooperative `fifo` scheduler must be rejected when `userspace = true`.
        let mut p5 = BuildProfile::default_full(TargetBoard::QemuVirt);
        p5.scheduler = SchedulerPolicy::Fifo;
        assert!(p5.validate().is_err());

        // M9: duplicate keys, empty unknown sections, and unknown drivers/algorithms must be rejected.
        assert!(BuildProfile::parse_toml("[kernel]\nsmp = true\nsmp = false\n").is_err());
        assert!(matches!(
            BuildProfile::parse_toml("[bogus]\n"),
            Err(XtaskError::ProfileParse { .. })
        ));
        assert!(matches!(
            BuildProfile::parse_toml("[]\n"),
            Err(XtaskError::ProfileParse { .. })
        ));
        let mut p6 = BuildProfile::default_full(TargetBoard::Rpi5);
        p6.crypto_algorithms.push("md5".into());
        assert!(p6.validate().is_err());
        let mut p7 = BuildProfile::default_full(TargetBoard::Rpi5);
        p7.net.drivers.push("e1000".into());
        assert!(p7.validate().is_err());
    }

    #[test]
    fn target_board_and_scheduler_policy_parse_and_display() {
        assert_eq!("rpi5".parse::<TargetBoard>().ok(), Some(TargetBoard::Rpi5));
        assert_eq!(
            "qemu-virt".parse::<TargetBoard>().ok(),
            Some(TargetBoard::QemuVirt)
        );
        assert!("x86".parse::<TargetBoard>().is_err());
        assert_eq!(TargetBoard::Rpi5.to_string(), "rpi5");
        assert_eq!(TargetBoard::QemuVirt.to_string(), "qemu-virt");

        assert_eq!(
            "priority-rr".parse::<SchedulerPolicy>().ok(),
            Some(SchedulerPolicy::PriorityRr)
        );
        assert_eq!(
            "round-robin".parse::<SchedulerPolicy>().ok(),
            Some(SchedulerPolicy::RoundRobin)
        );
        assert_eq!(
            "fifo".parse::<SchedulerPolicy>().ok(),
            Some(SchedulerPolicy::Fifo)
        );
        assert!("edf".parse::<SchedulerPolicy>().is_err());
        assert_eq!(SchedulerPolicy::Fifo.to_string(), "fifo");
    }

    #[test]
    fn bitsets_toggle_and_iterate_protocol_features() {
        let mut protos = NetProtocols::default();
        assert!(!protos.has_ip());
        protos.set_ipv4(true);
        protos.set_tcp(true);
        protos.set_dns(true);
        assert!(protos.has_ip());
        let feats: Vec<&str> = protos.feature_names().collect();
        assert_eq!(feats, vec!["ipv4", "tcp", "dns"]);
        protos.clear();
        assert!(!protos.has_ip());
        assert!(protos.feature_names().next().is_none());
    }
}
