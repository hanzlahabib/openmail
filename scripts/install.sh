#!/usr/bin/env bash
# Install the openmail-mcp binary from a GitHub release.
#
# Env:
#   OPENMAIL_REPO         owner/name of the release repository (required unless OPENMAIL_BASE_URL is set)
#   OPENMAIL_VERSION      release tag (default: latest)
#   OPENMAIL_BASE_URL     override the download directory URL (mirrors, tests; supports file://)
#   OPENMAIL_INSTALL_DIR  install directory (default: ~/.local/bin)
#   OPENMAIL_KEEP_BACKUP  set to 1 to keep a <bin>.bak of a replaced binary (upgrade.sh sets this)
set -euo pipefail

tmp=""
BIN_NAME="openmail-mcp"
SUMS_NAME="SHA-256SUMS" # matches scripts/checksums.sh

die() { echo "install.sh: $*" >&2; exit 1; }

if [[ "$(id -u)" -eq 0 ]]; then
  die "refusing to run as root; run as an unprivileged user (installs to ~/.local/bin)"
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum -- "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 -- "$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum"
fi

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) die "unsupported architecture: $arch" ;;
  esac
  case "$os" in
    Linux) echo "${arch}-unknown-linux-gnu" ;;
    Darwin) echo "${arch}-apple-darwin" ;;
    *) die "unsupported OS: $os (Windows: use scripts/install.ps1)" ;;
  esac
}

base_url() {
  if [[ -n "${OPENMAIL_BASE_URL:-}" ]]; then
    echo "${OPENMAIL_BASE_URL%/}"
    return
  fi
  [[ -n "${OPENMAIL_REPO:-}" ]] || die "set OPENMAIL_REPO=<owner>/<repo> (or OPENMAIL_BASE_URL)"
  [[ "$OPENMAIL_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "OPENMAIL_REPO must look like owner/name"
  local version="${OPENMAIL_VERSION:-latest}"
  if [[ "$version" == "latest" ]]; then
    echo "https://github.com/${OPENMAIL_REPO}/releases/latest/download"
  else
    echo "https://github.com/${OPENMAIL_REPO}/releases/download/${version}"
  fi
}

main() {
  local target asset url install_dir
  target="$(detect_target)"
  asset="${BIN_NAME}-${target}.tar.gz"
  url="$(base_url)"
  install_dir="${OPENMAIL_INSTALL_DIR:-$HOME/.local/bin}"

  tmp="$(mktemp -d)"
  trap '[[ -z "$tmp" ]] || rm -rf -- "$tmp"' EXIT

  echo "Downloading ${asset} from ${url}"
  curl --proto '=https,file' --tlsv1.2 -fsSL -o "$tmp/$asset" "$url/$asset" || die "download failed: $url/$asset"
  curl --proto '=https,file' --tlsv1.2 -fsSL -o "$tmp/$SUMS_NAME" "$url/$SUMS_NAME" || die "download failed: $url/$SUMS_NAME"

  # Verify BEFORE extracting anything.
  local expected actual
  expected="$(awk -v f="$asset" '{ n=$2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$tmp/$SUMS_NAME")"
  [[ -n "$expected" ]] || die "no checksum entry for $asset in $SUMS_NAME"
  actual="$(sha256_of "$tmp/$asset")"
  if [[ "$expected" != "$actual" ]]; then
    die "checksum mismatch for $asset (expected $expected, got $actual); nothing was installed"
  fi
  echo "Checksum OK"

  mkdir "$tmp/x"
  tar -xzf "$tmp/$asset" -C "$tmp/x" || die "extract failed"
  local src
  src="$(find "$tmp/x" -type f -name "$BIN_NAME" | head -n1)"
  [[ -n "$src" ]] || die "archive does not contain $BIN_NAME"

  mkdir -p "$install_dir"
  local dest="$install_dir/$BIN_NAME"
  if [[ -e "$dest" && "${OPENMAIL_KEEP_BACKUP:-0}" == "1" ]]; then
    cp -p -- "$dest" "$dest.bak"
    echo "Backed up previous binary to $dest.bak"
  fi
  # Stage next to the target then rename: atomic, and safe if the old binary is running.
  install -m 0755 "$src" "$dest.new"
  mv -f -- "$dest.new" "$dest"
  echo "Installed $dest"

  case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) echo "Note: $install_dir is not on your PATH." ;;
  esac
}

main "$@"
