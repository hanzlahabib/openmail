#!/usr/bin/env bash
# Emit a config with N fake read-only accounts (default 50) on stdout.
# Usage: gen-many.sh [N] > many.toml   (N <= 500, the configured-account cap)
set -euo pipefail
n="${1:-50}"
[[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= 500 )) || { echo "N must be 1-500" >&2; exit 2; }
printf 'version = 1\n\n[limits]\n# Many mailboxes must not mean many live sessions.\nmax_global_connections = 8\n'
for ((i = 1; i <= n; i++)); do
  id=$(printf 'acct-%03d' "$i")
  printf '\n[[account]]\nid = "%s"\ndisplay_name = "Account %d"\nemail = "user%d@example.com"\nauth = "password"\ncredential = { kind = "env", var = "OPENMAIL_%s_PASSWORD" }\nmax_connections = 1\n[account.imap]\nhost = "imap.example.com"\nport = 993\ntls = "implicit"\n' \
    "$id" "$i" "$i" "$(printf '%03d' "$i")"
done
