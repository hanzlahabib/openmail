#!/usr/bin/env bash
# Add a mailbox to a server install without ever putting its password in a chat, argv or shell history.
# Usage (as root on the server):  openmail-account.sh <id> <email> <imap-host> [imap-port]
# Appends a read-only [[account]] to /etc/openmail/config.toml and stores the password you type
# (hidden) in /etc/openmail/env as OPENMAIL_<ID>_PASSWORD. Restart the service afterwards.
set -euo pipefail
id=${1:?account id (a-z0-9_-)}; email=${2:?email}; host=${3:?imap host}; port=${4:-993}
[[ $id =~ ^[a-z0-9_-]{1,64}$ ]] || { echo "invalid id" >&2; exit 1; }
cfg=${OPENMAIL_CONFIG:-/etc/openmail/config.toml}; envf=${OPENMAIL_ENV:-/etc/openmail/env}
var="OPENMAIL_$(echo "$id" | tr 'a-z-' 'A-Z_')_PASSWORD"
grep -q "^id = \"$id\"" "$cfg" && { echo "account $id already exists in $cfg" >&2; exit 1; }
read -rsp "IMAP password for $email (input hidden): " pw; echo
[[ -n $pw ]] || { echo "empty password" >&2; exit 1; }
umask 077
cat >> "$cfg" <<TOML

[[account]]
id = "$id"
display_name = "$id"
email = "$email"
auth = "password"
read_only = true

[account.imap]
host = "$host"
port = $port
tls = "implicit"

[account.credential]
kind = "env"
var = "$var"
TOML
sed -i "/^$var=/d" "$envf"; printf '%s=%s\n' "$var" "$pw" >> "$envf"
echo "added $id (read-only). Run: systemctl restart openmail-mcp && openmail-mcp --config $cfg doctor"
