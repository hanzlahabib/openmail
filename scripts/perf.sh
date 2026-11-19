#!/usr/bin/env bash
# OpenMail scale benchmark. Starts a disposable GreenMail (tests/infra/docker-compose.perf.yml),
# provisions N users, drives the real release `openmail-mcp` over stdio as an MCP client, and
# rewrites docs/PERFORMANCE_REPORT.md from what was measured. Needs docker, python3, openssl.
#
# Usage: scripts/perf.sh [--bin PATH] [--report PATH] [--accounts 1,10,50,100] [--messages N]
#                        [--check] [--write-budgets] [--keep-infra]
#   --check          fail (exit 1) if any figure exceeds tests/performance/budgets.json
#   --write-budgets  (re)derive budgets.json from this run (baseline x 1.5)
#   OPENMAIL_PERF_BIN  binary to measure (default: release build under $CARGO_TARGET_DIR or ./target)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PERF="$ROOT/tests/performance"
REPORT="$ROOT/docs/PERFORMANCE_REPORT.md"
BUDGETS="$PERF/budgets.json"
BIN="${OPENMAIL_PERF_BIN:-}"
ACCOUNTS="1,10,50,100"
MESSAGES=200
CHECK=0
WRITE_BUDGETS=0
KEEP_INFRA=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --report) REPORT="$2"; shift 2 ;;
    --accounts) ACCOUNTS="$2"; shift 2 ;;
    --messages) MESSAGES="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    --write-budgets) WRITE_BUDGETS=1; shift ;;
    --keep-infra) KEEP_INFRA=1; shift ;;
    -h|--help) sed -n 2,13p "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BIN" ]; then
  for c in "${CARGO_TARGET_DIR:-$ROOT/target}/release/openmail-mcp"; do
    [ -x "$c" ] && { BIN="$c"; break; }
  done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "no release openmail-mcp found; build with 'cargo build --release -p openmail-cli' or pass --bin" >&2; exit 1; }
case "$BIN" in */debug/*) echo "refusing to benchmark a debug build: $BIN" >&2; exit 1 ;; esac
for tool in docker python3 openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 2; }

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
  [ "$KEEP_INFRA" -eq 1 ] || docker compose -f "$ROOT/tests/infra/docker-compose.perf.yml" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

driver_args=(--bin "$BIN" --accounts "$ACCOUNTS" --messages "$MESSAGES" --out "$PERF/results.json" --compose-up)
[ "$WRITE_BUDGETS" -eq 1 ] && driver_args+=(--write-budgets "$BUDGETS")
[ "$CHECK" -eq 1 ] && driver_args+=(--check-budgets "$BUDGETS")
rc=0
python3 "$PERF/perf_driver.py" "${driver_args[@]}" || rc=$?
[ -s "$PERF/results.json" ] || { echo "driver produced no results" >&2; exit 1; }

# Budgets are only quoted in the report when they exist.
render_args=(--results "$PERF/results.json" --bin "$BIN" --out "$REPORT" --findings "$PERF/findings.md"
  --rustc "$(rustc --version 2>/dev/null || true)" --commit "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || true)" --profile release)
[ -f "$BUDGETS" ] && render_args+=(--budgets "$BUDGETS")
python3 "$PERF/render_report.py" "${render_args[@]}"
echo "wrote $REPORT"
exit "$rc"
