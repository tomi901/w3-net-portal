#!/usr/bin/env bash
set -euo pipefail

BIN="w3-net-portal-cli"
DIST_DIR="$(dirname "$0")/dist"
TARGET_DIR="$DIST_DIR/$BIN"

cargo build --release

rm -rf "$DIST_DIR"
mkdir -p "$TARGET_DIR"

cp "target/release/$BIN" setup.sh LICENSE README.md "$TARGET_DIR/"

echo "Built distributable at $TARGET_DIR"
