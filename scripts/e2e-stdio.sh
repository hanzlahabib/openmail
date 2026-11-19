#!/usr/bin/env bash
# End-to-end proof: real openmail-mcp binary <-> real GreenMail (docker) over stdio MCP.
# Needs docker. No insecure TLS options: a private test CA is generated per run and handed to
# the binary via SSL_CERT_FILE. Usage: scripts/e2e-stdio.sh [extra cargo test args]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 2; }
docker image inspect greenmail/standalone:2.1.3 >/dev/null 2>&1 || docker pull greenmail/standalone:2.1.3
cd "$ROOT"
OPENMAIL_REQUIRE_DOCKER=1 exec cargo test -p openmail-cli --test e2e_stdio "$@" -- --nocapture --test-threads=3
