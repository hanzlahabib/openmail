#!/usr/bin/env bash
# OpenMail performance harness. Measures a built openmail-mcp binary and
# rewrites docs/PERFORMANCE_REPORT.md. Anything it cannot measure on this
# machine stays "NOT MEASURED" together with the reason; nothing is estimated.
#
# Usage: scripts/perf.sh [--bin PATH] [--report PATH] [--runs N] [--sessions N]
#   OPENMAIL_PERF_BIN     binary to measure (default: newest release/debug build
#                         under $CARGO_TARGET_DIR, ./target, or $PATH)
#   OPENMAIL_PERF_CONFIG  config.toml for a TEST account on a reachable test
#                         IMAP server. Without it, idle RSS and concurrent
#                         session numbers are NOT MEASURED.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="$ROOT/docs/PERFORMANCE_REPORT.md"
BIN="${OPENMAIL_PERF_BIN:-}"
RUNS=30
SESSIONS=8
IDLE_SETTLE_S=3
NA="NOT MEASURED"

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --report) REPORT="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --sessions) SESSIONS="$2"; shift 2 ;;
    -h|--help) sed -n 2,14p "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BIN" ]; then
  for c in "${CARGO_TARGET_DIR:-$ROOT/target}"/release/openmail-mcp \
           "${CARGO_TARGET_DIR:-$ROOT/target}"/debug/openmail-mcp; do
    [ -x "$c" ] && { BIN="$c"; break; }
  done
fi
[ -z "$BIN" ] && BIN="$(command -v openmail-mcp || true)"
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "no openmail-mcp binary found; build one or pass --bin" >&2; exit 1; }
CONFIG="${OPENMAIL_PERF_CONFIG:-}"

# ---------- environment ----------
cpu_model="$(awk -F: '/model name/{gsub(/^ +/,"",$2);print $2;exit}' /proc/cpuinfo 2>/dev/null || true)"
cpu_threads="$(nproc 2>/dev/null || echo "$NA")"
mem_total="$(awk '/MemTotal/{printf "%.1f GiB",$2/1048576}' /proc/meminfo 2>/dev/null || true)"
os_name="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
kernel="$(uname -sr)"
rustc_v="$(rustc --version 2>/dev/null || echo "$NA (rustc --version failed or not on PATH)")"
bin_version="$("$BIN" --version 2>&1 | head -1 || true)"
bin_kind="release"; case "$BIN" in */debug/*) bin_kind="debug (unoptimised, numbers are not representative)";; esac
virt="native"; grep -qi microsoft /proc/version 2>/dev/null && virt="WSL2 (virtualised, timings are noisy)"

# ---------- binary size ----------
bin_bytes="$(stat -c %s "$BIN")"
bin_mib="$(awk -v b="$bin_bytes" 'BEGIN{printf "%.2f",b/1048576}')"

# ---------- startup latency (--version, wall clock, ms) ----------
lat_file="$(mktemp)"; trap 'rm -f "$lat_file"' EXIT
for _ in $(seq 1 "$RUNS"); do
  s=$(date +%s%N); "$BIN" --version >/dev/null 2>&1 || true; e=$(date +%s%N)
  echo $(( (e - s) / 1000 )) >> "$lat_file"   # microseconds
done
read -r lat_min lat_med lat_p95 lat_max < <(sort -n "$lat_file" | awk '
  {a[NR]=$1} END{printf "%.2f %.2f %.2f %.2f\n", a[1]/1000, a[int((NR+1)/2)]/1000, a[int(NR*0.95 > 1 ? NR*0.95 : 1)]/1000, a[NR]/1000}')

# ---------- peak RSS of a short-lived run (/usr/bin/time -v) ----------
peak_rss="$NA"
if [ -x /usr/bin/time ]; then
  kb="$(/usr/bin/time -v "$BIN" --version 2>&1 >/dev/null | awk -F: '/Maximum resident set size/{gsub(/ /,"",$2);print $2}')"
  [ -n "$kb" ] && peak_rss="$(awk -v k="$kb" 'BEGIN{printf "%.1f MiB",k/1024}')"
else
  peak_rss="$NA (/usr/bin/time missing)"
fi

# ---------- idle RSS: `serve` over stdio with stdin held open ----------
idle_rss="$NA (set OPENMAIL_PERF_CONFIG to a test config)"
idle_note=""
if [ -n "$CONFIG" ]; then
  fifo_dir="$(mktemp -d)"; mkfifo "$fifo_dir/in"
  "$BIN" --config "$CONFIG" serve --transport stdio <"$fifo_dir/in" >/dev/null 2>"$fifo_dir/err" &
  pid=$!
  exec 9>"$fifo_dir/in"                       # keep the write end open => no EOF
  sleep "$IDLE_SETTLE_S"
  if kill -0 "$pid" 2>/dev/null; then
    kb="$(awk '/VmRSS/{print $2}' "/proc/$pid/status")"
    idle_rss="$(awk -v k="$kb" 'BEGIN{printf "%.1f MiB",k/1024}')"
    idle_note="sampled ${IDLE_SETTLE_S}s after start, stdin held open"
  else
    idle_rss="$NA (serve exited within ${IDLE_SETTLE_S}s: $(head -c 160 "$fifo_dir/err" | tr '\n' ' '))"
  fi
  exec 9>&-; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  rm -rf "$fifo_dir"
fi

# ---------- concurrent IMAP sessions: N parallel `accounts test` ----------
conc="$NA (set OPENMAIL_PERF_CONFIG to a test config for a reachable test IMAP server)"
if [ -n "$CONFIG" ] && [ -x /usr/bin/time ]; then
  tmp="$(mktemp -d)"; ok=0
  s=$(date +%s%N)
  for i in $(seq 1 "$SESSIONS"); do
    /usr/bin/time -v -o "$tmp/t$i" "$BIN" --config "$CONFIG" accounts test >/dev/null 2>&1 &
  done
  for j in $(jobs -p); do wait "$j" 2>/dev/null || true; done
  e=$(date +%s%N)
  for i in $(seq 1 "$SESSIONS"); do
    grep -q "Exit status: 0" "$tmp/t$i" 2>/dev/null && ok=$((ok + 1))
  done
  sum_kb="$(cat "$tmp"/t* | awk -F: '/Maximum resident set size/{gsub(/ /,"",$2);s+=$2} END{print s+0}')"
  conc="$SESSIONS parallel processes, $ok exited 0, wall $(( (e - s) / 1000000 )) ms, summed peak RSS $(awk -v k="$sum_kb" 'BEGIN{printf "%.1f MiB",k/1024}')"
  [ "$ok" -eq 0 ] && conc="$conc (all failed: connectivity not exercised, treat as $NA)"
  rm -rf "$tmp"
fi

# ---------- report ----------
mkdir -p "$(dirname "$REPORT")"
cat > "$REPORT" <<EOF
# OpenMail performance report

Generated by \`scripts/perf.sh\` on $(date -u +%Y-%m-%dT%H:%M:%SZ). Real measurements only;
anything the harness could not measure says \`$NA\` and why. Re-run the script to refresh.

## Environment

| Item | Value |
|---|---|
| CPU | ${cpu_model:-$NA} (${cpu_threads} threads) |
| RAM | ${mem_total:-$NA} |
| OS / kernel | $os_name / $kernel |
| Virtualisation | $virt |
| rustc | $rustc_v |
| Binary | \`$(basename "$BIN")\` — $bin_version |
| Build profile | $bin_kind |

## Results

| Metric | Value | Method |
|---|---|---|
| Binary size | $bin_mib MiB ($bin_bytes bytes) | \`stat -c %s\` |
| Startup latency (\`--version\`) | min $lat_min ms / median $lat_med ms / p95 $lat_p95 ms / max $lat_max ms | $RUNS runs, wall clock via \`date +%s%N\` (includes fork+exec) |
| Peak RSS (\`--version\`) | $peak_rss | \`/usr/bin/time -v\`, Maximum resident set size |
| Idle RSS (\`serve --transport stdio\`) | $idle_rss | VmRSS from /proc/PID/status${idle_note:+; $idle_note} |
| Concurrent IMAP sessions | $conc | parallel \`accounts test\` against a test server |

## Not measured / limits

- Startup latency is for \`--version\`, which does not load config or open the network; it is a floor, not time-to-first-tool-call.
- Idle RSS and concurrent sessions need \`OPENMAIL_PERF_CONFIG\` pointing at a test account on a reachable test IMAP server (never a real mailbox). Without it they stay \`$NA\`.
- Concurrent sessions are separate processes (CLI-level), not N sessions inside one server process; per-process connection-pool memory is therefore NOT MEASURED.
- Throughput (messages/s), search latency on large mailboxes and CPU time are NOT MEASURED.
EOF
echo "wrote $REPORT"
