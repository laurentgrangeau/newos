# NewOS Build Profile Options Reference

Every `.toml` file under `profiles/` (or passed via `cargo xtask <cmd> --profile <path>`) configures NewOS using the following exhaustive set of options. Any omitted option inherits the `default_full` value.

You can also inspect this reference from the CLI at any time:
```bash
cargo xtask config --list-options
cargo xtask config --profile profiles/tinykernel.toml
```

---

## `[target]` — Target Architecture, Board & CPU

| Key | Type | Valid Values | Default | Description |
|---|---|---|---|---|
| `arch` | `string` | `"aarch64"` | `"aarch64"` | Target CPU architecture (`newos-hal/arch-*`). |
| `board` | `string` | `"rpi5"`, `"qemu-virt"` | `"rpi5"` | Target board / SoC descriptor (`newos-hal/board-*`). |
| `cpu` | `string` | Any LLVM AArch64 `-C target-cpu` (e.g., `"cortex-a76"`, `"generic"`) | `"cortex-a76"` | CPU tuning passed to `rustc` and QEMU `-cpu`. |

---

## `[kernel]` — EL1 Microkernel Core (`newos-kernel` / `newos-kernel-core` / `newos-hal`)

| Key | Type | Valid Values | Default | Dependencies | Description |
|---|---|---|---|---|---|
| `scheduler` | `string` | `"priority-rr"`, `"round-robin"`, `"fifo"` | `"priority-rr"` | — | Compile-time scheduler policy: preemptive priority+RR (`priority-rr`), flat preemptive RR (`round-robin`), or cooperative non-preemptive FIFO (`fifo`, minimal overhead for tinykernel). |
| `smp` | `bool` | `true`, `false` | `true` | — | Enables multi-core AP bring-up and `SmpScheduler` work-stealing (`false` = single-core uniprocessor). |
| `userspace` | `bool` | `true`, `false` | `true` | Required by any `[domains].* = true` | Enables EL0 ELF64 loader and isolated EL0 protection domain spawning (`false` = pure EL1 kernel). |
| `elf_attestation` | `bool` | `true`, `false` | `true` | Requires `"sha3"` in `[crypto].algorithms` | Measures loaded EL0 ELF binaries with FIPS 202 SHA3-512 at boot. |
| `acpi` | `bool` | `true`, `false` | `true` | — | Enables ACPI RSDP/XSDT/FADT/SPCR/MADT/GTDT/MCFG hardware discovery (`false` = static `BoardDescriptor` only). |

---

## `[domains]` — Optional EL0 Protection Domains

| Key | Type | Valid Values | Default | Dependencies | Description |
|---|---|---|---|---|---|
| `supervisor` | `bool` | `true`, `false` | `true` | Requires `[kernel].userspace = true` | Builds and loads the EL0 supervisor protection domain (`newos-supervisor-pd`). Without `shell`, compiles into a bare minimal supervisor. |
| `worker` | `bool` | `true`, `false` | `true` | Requires `[kernel].userspace = true` | Builds and loads isolated EL0 IPC worker protection domain (`newos-worker-pd`). |
| `shell` | `bool` | `true`, `false` | `true` | Requires `supervisor = true` | Builds and stages the standalone EL0 `newos-shell-pd` typed pipeline shell + CAOS binary (`crates/shell-pd`) alongside `newos-supervisor-pd` shell support. |
| `net` | `bool` | `true`, `false` | `true` | Requires `[net].enabled = true` and `ipv4` or `ipv6` | Builds and loads isolated EL0 network/DMA protection domain (`newos-net-pd`). |
| `key` | `bool` | `true`, `false` | `true` | Requires `"sha3"` and `"ml-dsa-87"` in `[crypto].algorithms` | Builds and loads isolated EL0 hardware-entropy & ML-DSA-87 signing vault protection domain (`newos-key-pd`). |
| `ssh` | `bool` | `true`, `false` | `true` | Requires `net = true`, `key = true`, `shell = true`, and all 4 PQ algorithms in `[crypto].algorithms` | Builds and loads isolated EL0 SSHv2 protection domain (`newos-ssh-pd`). |

---

## `[net]` — Networking Stack (`newos-net` / `newos-net-pd`)

| Key | Type | Valid Values | Default | Dependencies | Description |
|---|---|---|---|---|---|
| `enabled` | `bool` | `true`, `false` | `true` | — | Master switch for networking support. |
| `ipv4` | `bool` | `true`, `false` | `true` | — | Enables IPv4, ARP, and DHCPv4 (`newos-net/ipv4`). Can be used alone or dual-stack with `ipv6`. |
| `ipv6` | `bool` | `true`, `false` | `true` | — | Enables IPv6, EUI-64 link-local (`fe80::/64`), NDP, static/global unicast, and IPv6 routing (`newos-net/ipv6`). Can be used alone or dual-stack with `ipv4`. |
| `tcp` | `bool` | `true`, `false` | `true` | — | Enables TCP sockets (`newos-net/tcp`). |
| `udp` | `bool` | `true`, `false` | `true` | — | Enables UDP sockets (`newos-net/udp`). |
| `icmp` | `bool` | `true`, `false` | `true` | — | Enables ICMPv4 / ICMPv6 sockets (`newos-net/icmp`). |
| `dns` | `bool` | `true`, `false` | `true` | — | Enables DNS A (`ipv4`) / AAAA (`ipv6`) resolver (`newos-net/dns`). |
| `drivers` | `string[]` | `"gem"`, `"virtio"` (any subset or `[]`) | `["gem", "virtio"]` | — | NIC hardware drivers compiled into `newos-net` / `newos-net-pd`: Raspberry Pi 5 RP1 Cadence GEM (`gem`) and QEMU VirtIO-Net v2 (`virtio`). |

---

## `[crypto]` — Modular Cryptographic Algorithms (`newos-crypto`)

| Key | Type | Valid Values | Default | Dependencies | Description |
|---|---|---|---|---|---|
| `algorithms` | `string[]` | `"sha3"`, `"chacha20-poly1305"`, `"ml-kem-1024"`, `"ml-dsa-87"` (any subset or `[]`) | all 4 | — | Individual cryptographic primitives compiled into `newos-crypto`. Set to `[]` for a 100% crypto-free build. |

- `"sha3"`: FIPS 202 `SHA3-512` hash + `SHAKE256` XOF.
- `"chacha20-poly1305"`: RFC 8439 / OpenSSH `chacha20-poly1305@openssh.com` AEAD.
- `"ml-kem-1024"`: NIST FIPS 203 ML-KEM-1024 key encapsulation.
- `"ml-dsa-87"`: NIST FIPS 204 ML-DSA-87 digital signatures.

---

## `[drivers]` — Hardware & Peripheral Drivers

Every key is a `string[]` (pass `[]` to omit all drivers in that subsystem):

| Key | Crate | Valid Values | Default | Dependencies | Description |
|---|---|---|---|---|---|
| `storage` | `newos-storage` | `"pcie"`, `"sdhci"`, `"nvme"`, `"caos-snapshot"` | all 4 | `"caos-snapshot"` requires `"sha3"` | PCIe ECAM enumerator, BCM2712 microSD SDHCI, NVMe 1.4 SSD, and SHA3-verified CAOS snapshots. |
| `rng` | `newos-rng` | `"bcm2712"`, `"virtio"`, `"csprng"` | all 3 | `"csprng"` requires `"sha3"` | BCM2712 `iproc-rng200`, QEMU VirtIO-RNG v2, and SHAKE256-conditioned ChaCha20 CSPRNG. |
| `gpu` | `newos-gpu` | `"v3d"`, `"iommu"` | all 2 | — | VideoCore VII (V3D 7.1) compute/probe driver and BCM2712 IOMMU. |
| `ai` | `newos-ai` | `"compute"`, `"hailo"` | all 2 | — | ARMv8.2-A NEON/DotProd inference kernels and PCIe Hailo-8/8L/10H AI HAT+ NPU driver. |
| `usb` | `newos-usb` | `"xhci"` | `["xhci"]` | — | RP1 dual Synopsys xHCI USB 3.0 / 2.0 host controller driver. |
| `gpio` | `newos-gpio` | `"rp1"` | `["rp1"]` | — | RP1 40-pin Bank 0 GPIO driver. |
| `wdt` | `newos-wdt` | `"bcm2712"` | `["bcm2712"]` | — | BCM2712 hardware power-management watchdog driver (gates `newos-supervisor-pd/wdt` in PD 0 Supervisor). |
| `board` | `newos-board` | `"mailbox"`, `"thermal"`, `"rtc"`, `"rp1-bus"` | all 4 | — | VideoCore Property Mailbox, AVS TMON thermal/fan controller, RTC, and RP1 UART/SPI/I2C/PWM bus drivers. |

---

## CLI Overrides (`cargo xtask <config|build|run|rpi5-image> ...`)

Any profile option can also be overridden from the command line:

| Flag | Effect |
|---|---|
| `--profile <path>` | Load a base TOML profile (default: full profile) |
| `--board <rpi5\|qemu-virt>` | Override `[target].board` |
| `--sched <priority-rr\|round-robin\|fifo>` | Override `[kernel].scheduler` |
| `--no-smp` | Set `[kernel].smp = false` |
| `--no-acpi` | Set `[kernel].acpi = false` |
| `--no-domains` | Disable `userspace` and all EL0 protection domains |
| `--no-shell` | Disable `shell` and `ssh` |
| `--no-net` | Disable networking (`net.enabled`, `ipv4`, `ipv6`, `net`, `ssh`) |
| `--no-ssh` | Disable `ssh` and `key` |
| `--ipv4-only` | Enable IPv4 and disable IPv6 |
| `--ipv6-only` | Enable IPv6 and disable IPv4 |
| `--no-crypto` | Clear `[crypto].algorithms` and disable crypto-dependent features (`elf_attestation`, `key`, `ssh`, `caos-snapshot`, `csprng`) |
| `--release` | Build with release profile |
