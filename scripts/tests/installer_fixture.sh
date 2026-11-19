#!/usr/bin/env bash
# Local-fixture test for install/upgrade/rollback/uninstall; no network.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"; trap 'rm -rf -- "$work"' EXIT
case "$(uname -m)" in x86_64|amd64) a=x86_64;; *) a=aarch64;; esac
case "$(uname -s)" in Linux) t="$a-unknown-linux-gnu";; *) t="$a-apple-darwin";; esac
rel="$work/rel"; mkdir -p "$rel" "$work/pkg" "$work/home"
printf '#!/bin/sh\necho v1\n' > "$work/pkg/openmail-mcp"; chmod +x "$work/pkg/openmail-mcp"
tar -czf "$rel/openmail-mcp-$t.tar.gz" -C "$work/pkg" openmail-mcp
"$here/checksums.sh" "$rel" >/dev/null
export HOME="$work/home" OPENMAIL_BASE_URL="file://$rel" OPENMAIL_INSTALL_DIR="$work/bin"
fail() { echo "FAIL: $*" >&2; exit 1; }

"$here/install.sh" >/dev/null || fail "good install"
[[ "$("$work/bin/openmail-mcp")" == v1 ]] || fail "binary content"

# upgrade -> v2 with backup, then rollback
printf '#!/bin/sh\necho v2\n' > "$work/pkg/openmail-mcp"
tar -czf "$rel/openmail-mcp-$t.tar.gz" -C "$work/pkg" openmail-mcp; "$here/checksums.sh" "$rel" >/dev/null
"$here/upgrade.sh" >/dev/null || fail "upgrade"
[[ "$("$work/bin/openmail-mcp")" == v2 && -f "$work/bin/openmail-mcp.bak" ]] || fail "upgrade result"
"$here/upgrade.sh" --rollback >/dev/null
[[ "$("$work/bin/openmail-mcp")" == v1 ]] || fail "rollback"

# tampered archive: checksum must fail, binary must stay v1
printf '#!/bin/sh\necho evil\n' > "$work/pkg/openmail-mcp"
tar -czf "$rel/openmail-mcp-$t.tar.gz" -C "$work/pkg" openmail-mcp   # SUMS not regenerated
if out="$("$here/install.sh" 2>&1)"; then fail "tampered archive was accepted"; fi
grep -q "checksum mismatch" <<<"$out" || fail "wrong error: $out"
[[ "$("$work/bin/openmail-mcp")" == v1 ]] || fail "binary changed after mismatch"

# uninstall keeps config by default
mkdir -p "$work/home/.config/openmail"; touch "$work/home/.config/openmail/config.toml"
"$here/uninstall.sh" >/dev/null
[[ ! -e "$work/bin/openmail-mcp" && -f "$work/home/.config/openmail/config.toml" ]] || fail "uninstall"
echo "installer fixture tests passed"
