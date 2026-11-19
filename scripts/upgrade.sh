#!/usr/bin/env bash
# Upgrade openmail-mcp in place, keeping a backup for rollback.
# Usage: scripts/upgrade.sh            # install latest (or OPENMAIL_VERSION), backup old binary
#        scripts/upgrade.sh --rollback # restore the previous binary from <bin>.bak
# Takes the same env as install.sh.
set -euo pipefail

die() { echo "upgrade.sh: $*" >&2; exit 1; }

if [[ "$(id -u)" -eq 0 ]]; then
  die "refusing to run as root"
fi

install_dir="${OPENMAIL_INSTALL_DIR:-$HOME/.local/bin}"
dest="$install_dir/openmail-mcp"

if [[ "${1:-}" == "--rollback" ]]; then
  [[ -f "$dest.bak" ]] || die "no backup at $dest.bak"
  mv -f -- "$dest.bak" "$dest"
  echo "Rolled back to previous binary"
  exit 0
fi

[[ -x "$dest" ]] || die "openmail-mcp is not installed at $dest; use install.sh"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENMAIL_KEEP_BACKUP=1 exec "$here/install.sh"
