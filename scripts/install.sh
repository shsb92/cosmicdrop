#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

APP_ID="dev.cosmicdrop.CosmicDrop"
PREFIX="${PREFIX:-/usr/local}"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Run with sudo:  sudo ./scripts/install.sh" >&2
    exit 1
fi

cd "$(dirname "$0")/.."
PROJECT_DIR="$(pwd)"

# Under sudo, PATH and $HOME are reset (to /root), so cargo from rustup is
# not on PATH, and rustup looks for its toolchains in $HOME/.rustup which is
# now /root/.rustup (empty). Point HOME-independent tooling at the invoking
# user's cargo/rustup directories and prepend cargo's bin to PATH.
SUDO_USER_HOME="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"
export CARGO_HOME="${CARGO_HOME:-$SUDO_USER_HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$SUDO_USER_HOME/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found. Install rustup/cargo or set CARGO_HOME/RUSTUP_HOME." >&2
    exit 1
fi

echo "Building release binary..."
cargo build --release

BIN_DIR="$PREFIX/bin"
DATA_DIR="$PREFIX/share"
ICON_DIR="$DATA_DIR/icons/hicolor/scalable/apps"

install -d "$BIN_DIR" "$DATA_DIR/cosmicdrop" "$ICON_DIR" "$DATA_DIR/applications"

echo "Installing binary..."
install -m 0755 "$PROJECT_DIR/target/release/cosmicdrop" "$BIN_DIR/cosmicdrop"

echo "Installing desktop entry..."
install -Dm 0644 "$PROJECT_DIR/data/$APP_ID.desktop" \
    "$DATA_DIR/applications/$APP_ID.desktop"

echo "Installing app icon..."
install -Dm 0644 "$PROJECT_DIR/res/icons/$APP_ID.svg" "$ICON_DIR/$APP_ID.svg"

echo "Done. The applet desktop entry (with X-CosmicApplet=true) is installed."
echo "Add it to your panel via:  Settings > Desktop > Panel > Add Applet."
echo "If it does not appear, restart the panel (or log out and back in)."
