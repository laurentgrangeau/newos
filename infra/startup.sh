#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/newos-startup.log"
DONE_MARKER="/var/log/newos-setup-done"

exec > >(tee -a "${LOG_FILE}") 2>&1

if [[ -f "${DONE_MARKER}" ]]; then
  echo "[newos-startup] Setup already completed, skipping."
  exit 0
fi

echo "[newos-startup] Starting Debian OS-dev VM provisioning..."
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  tmux \
  vim \
  htop \
  pkg-config \
  build-essential \
  clang \
  lld \
  llvm \
  gdb \
  qemu-system-arm \
  qemu-utils \
  qemu-efi-aarch64 \
  mtools \
  dosfstools \
  libssl-dev

# Restrict /dev/kvm to the `kvm` group (0660) instead of world-writable 0666 (`M15`)
cat <<'EOF' > /etc/udev/rules.d/99-kvm.rules
KERNEL=="kvm", GROUP="kvm", MODE="0660"
EOF
if [[ -e /dev/kvm ]]; then
  chgrp kvm /dev/kvm || true
  chmod 0660 /dev/kvm
fi

# Install pinned Rust toolchain (nightly-2026-11-21 + OS-dev components & targets) in /opt/rust
export RUSTUP_HOME="/opt/rust/rustup"
export CARGO_HOME="/opt/rust/cargo"
mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}"

RUSTUP_INIT="$(mktemp)"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "${RUSTUP_INIT}"
sh "${RUSTUP_INIT}" -y --no-modify-path --default-toolchain nightly-2026-11-21
rm -f "${RUSTUP_INIT}"

export PATH="${PATH}:${CARGO_HOME}/bin"

rustup component add rust-src llvm-tools-preview clippy rustfmt
rustup target add aarch64-unknown-none aarch64-unknown-none-softfloat

# Install Rust OS-dev cargo utilities
cargo install --locked cargo-binutils

# Make /opt/rust readable/executable (NOT world-writable) by non-root users (`M15`)
chmod -R a+rX,go-w /opt/rust

cat <<'EOF' > /etc/profile.d/rust.sh
export RUSTUP_HOME="/opt/rust/rustup"
export CARGO_HOME="/opt/rust/cargo"
export PATH="${PATH}:${CARGO_HOME}/bin"
EOF
chmod 0644 /etc/profile.d/rust.sh

touch "${DONE_MARKER}"
echo "[newos-startup] Provisioning complete!"
