#!/usr/bin/env bash
# Remove the openmail-mcp binary. Config and data are KEPT unless --purge is given.
# Usage: scripts/uninstall.sh [--purge]
set -euo pipefail

die() { echo "uninstall.sh: $*" >&2; exit 1; }

if [[ "$(id -u)" -eq 0 ]]; then
  die "refusing to run as root"
fi

install_dir="${OPENMAIL_INSTALL_DIR:-$HOME/.local/bin}"
config_dir="${OPENMAIL_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/openmail}"

rm -f -- "$install_dir/openmail-mcp" "$install_dir/openmail-mcp.bak" "$install_dir/openmail-mcp.new"
echo "Removed binary from $install_dir"

if [[ "${1:-}" == "--purge" ]]; then
  [[ -n "$config_dir" && "$config_dir" != "/" && "$config_dir" != "$HOME" ]] || die "unsafe config dir: $config_dir"
  rm -rf -- "$config_dir"
  echo "Purged $config_dir"
else
  echo "Kept configuration in $config_dir (use --purge to delete it)"
fi
