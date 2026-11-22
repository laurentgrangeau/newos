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
  nasm \
  gdb \
  qemu-system-x86 \
  qemu-system-arm \
  qemu-utils \
  ovmf \
  qemu-efi-aarch64 \
  xorriso \
  grub-pc-bin \
  grub-common \
  mtools \
  dosfstools \
  libssl-dev

# Allow non-root SSH users on this dev VM to use /dev/kvm immediately
cat <<'EOF' > /etc/udev/rules.d/99-kvm.rules
KERNEL=="kvm", GROUP="kvm", MODE="0666"
EOF
if [[ -e /dev/kvm ]]; then
  chmod 0666 /dev/kvm
fi

# Install Rust toolchain (nightly + OS-dev components & targets) in /opt/rust
export RUSTUP_HOME="/opt/rust/rustup"
export CARGO_HOME="/opt/rust/cargo"
mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}"

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --no-modify-path --default-toolchain nightly

export PATH="${CARGO_HOME}/bin:${PATH}"

rustup component add rust-src llvm-tools-preview clippy rustfmt
rustup target add x86_64-unknown-none aarch64-unknown-none

# Install common Rust OS-dev cargo utilities
cargo install bootimage cargo-binutils

# Make /opt/rust usable by any SSH user on this dev VM
chmod -R a+rwX /opt/rust

cat <<'EOF' > /etc/profile.d/rust.sh
export RUSTUP_HOME="/opt/rust/rustup"
export CARGO_HOME="/opt/rust/cargo"
export PATH="${CARGO_HOME}/bin:${PATH}"
EOF
chmod 0644 /etc/profile.d/rust.sh

touch "${DONE_MARKER}"
echo "[newos-startup] Provisioning complete!"
