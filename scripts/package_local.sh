#!/usr/bin/env bash
# Local packaging for Linux/macOS: builds sagashield-mcp and tars dist/.
# Usage: ./scripts/package_local.sh
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
UNAME="$(uname -s)"
ARCH="$(uname -m)"
case "$UNAME" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) echo "unsupported OS: $UNAME" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64)  TRIPLE_ARCH=x64 ;;
  arm64|aarch64) TRIPLE_ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
TARBALL="dist/sagashield-v${VERSION}-${OS}-${TRIPLE_ARCH}.tar.gz"

echo "[1/4] cargo build --release --bin sagashield-mcp"
cargo build --release --bin sagashield-mcp

echo "[2/4] staging dist/"
mkdir -p dist stage
cp target/release/sagashield-mcp stage/
cp README.md LICENSE-MIT stage/

echo "[3/4] packing $TARBALL"
rm -f "$TARBALL"
tar -czf "$TARBALL" -C stage .

echo "[4/4] SHA256SUMS.txt"
if command -v sha256sum >/dev/null; then
  sha256sum "$TARBALL" > dist/SHA256SUMS.txt
else
  shasum -a 256 "$TARBALL" > dist/SHA256SUMS.txt
fi

rm -rf stage
echo "OK: $TARBALL"
cat dist/SHA256SUMS.txt
