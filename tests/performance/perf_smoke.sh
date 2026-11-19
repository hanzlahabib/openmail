#!/usr/bin/env bash
# Smoke test for the report renderer and perf.sh argument handling (no docker needed).
# The JSON below is a hand-written FIXTURE for the renderer only: it proves that a metric which is
# absent renders as "NOT MEASURED" and that present numbers are copied verbatim, never recomputed
# or invented. Real measurements come from scripts/perf.sh against GreenMail.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

"$ROOT/scripts/perf.sh" --help | grep -q -- '--check' || fail "perf.sh --help"
"$ROOT/scripts/perf.sh" --bin /nonexistent >/dev/null 2>&1 && fail "perf.sh must reject a missing binary"

printf '#!/bin/sh\necho "openmail-mcp 0.0.0-stub"\n' > "$tmp/openmail-mcp"; chmod +x "$tmp/openmail-mcp"
cat > "$tmp/r.json" <<'JSON'
{"meta":{"messages_per_account":200,"greenmail_image":"greenmail/standalone@sha256:x"},
 "results":[{"accounts":7,"messages_per_account":200,"global_cap":8,"startup_to_initialize_ms":12.34,
  "sessions_opened_by_startup":0,"idle_rss_untouched_mib":9.0,"idle_rss_after_all_accounts_mib":11.1,
  "idle_sessions_after_all_accounts":2,
  "cold_connect":{"samples":7,"failed":0,"p50_ms":96.0,"p95_ms":101.0,"max_ms":101.0},
  "search_serial":{"samples":60,"failed":0,"wrong_hit_count":0,"expected_hits":20,"p50_ms":144.5,"p95_ms":159.0,"max_ms":185.0},
  "load":{"concurrency":32,"requests":100,"errors":0,"wall_s":1.0,"requests_per_s":99.5,"messages_returned_per_s":600.0,
   "search_p50_ms":400.0,"search_p95_ms":1200.0,"get_message_p50_ms":300.0,"get_message_p95_ms":800.0,
   "cpu_percent_of_one_core":9.7,"peak_rss_mib_vmhwm":16.1,"peak_threads":17,"peak_sessions_proxy":8,
   "peak_sessions_kernel_greenmail_port":8,"sessions_accepted_during_load":84},
  "burst_all_accounts":{"in_flight":7,"ok":7,"peak_sessions_proxy":7,"peak_sessions_kernel_greenmail_port":7},
  "shutdown":{"exit":0,"ms":3.5}}]}
JSON
python3 "$ROOT/tests/performance/render_report.py" --results "$tmp/r.json" --bin "$tmp/openmail-mcp" --out "$tmp/r.md"
grep -q '| Startup → `initialize` answered (ms) | 12.34 |' "$tmp/r.md" || fail "number not copied verbatim"
grep -Eq 'Binary size \(release\) \| [0-9.]+ MiB \([0-9]+ bytes\)' "$tmp/r.md" || fail "binary size missing"
grep -q '^| 7 | NOT MEASURED | NOT MEASURED' "$tmp/r.md" || fail "absent recovery data must render as NOT MEASURED"
grep -q 'N=7' "$tmp/r.md" || fail "scale column missing"
echo "perf_smoke: OK"
