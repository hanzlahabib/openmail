#!/usr/bin/env bash
# Smoke test for scripts/perf.sh using a stub binary (test-only fake).
# Asserts the report is generated, records the environment, and that
# unmeasurable metrics stay "NOT MEASURED" instead of being invented.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/sh\necho "openmail-mcp 0.0.0-stub"\n' > "$tmp/openmail-mcp"; chmod +x "$tmp/openmail-mcp"
env -u OPENMAIL_PERF_CONFIG "$ROOT/scripts/perf.sh" --bin "$tmp/openmail-mcp" --report "$tmp/r.md" --runs 5 >/dev/null
fail() { echo "FAIL: $1" >&2; exit 1; }
grep -q '^| CPU | .*threads' "$tmp/r.md" || fail "CPU row missing"
grep -q '^| rustc |' "$tmp/r.md" || fail "rustc row missing"
grep -Eq 'Binary size \| [0-9.]+ MiB \([0-9]+ bytes\)' "$tmp/r.md" || fail "binary size not measured"
grep -Eq 'median [0-9.]+ ms' "$tmp/r.md" || fail "latency not measured"
grep -q 'Idle RSS.*NOT MEASURED' "$tmp/r.md" || fail "idle RSS must be NOT MEASURED without config"
grep -q 'Concurrent IMAP sessions | NOT MEASURED' "$tmp/r.md" || fail "concurrency must be NOT MEASURED without config"
echo "perf_smoke: OK"
