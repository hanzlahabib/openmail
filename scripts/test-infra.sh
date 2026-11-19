#!/usr/bin/env bash
# Disposable OpenMail test mail server: up | down | seed | status
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/tests/infra/docker-compose.yml")
HOST="${OPENMAIL_TEST_HOST:-127.0.0.1}"
IMAP_PORT="${OPENMAIL_TEST_IMAP_PORT:-13143}"

wait_healthy() {
  for _ in $(seq 1 60); do
    if python3 -c "import socket,sys; s=socket.create_connection(('$HOST',$IMAP_PORT),2); sys.exit(0 if s.recv(64).startswith(b'* OK') else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for IMAP on $HOST:$IMAP_PORT" >&2
  return 1
}

case "${1:-}" in
  up)     "${COMPOSE[@]}" up -d --wait --wait-timeout 90 || "${COMPOSE[@]}" up -d; wait_healthy; "$0" seed ;;
  down)   "${COMPOSE[@]}" down -v --remove-orphans ;;
  seed)   python3 "$ROOT/tests/infra/seed.py" ;;
  status) "${COMPOSE[@]}" ps
          python3 - <<PY
import imaplib
for u, p in [("alice","alicepass"),("bob","bobpass"),("carol","carolpass")]:
    i = imaplib.IMAP4("$HOST", $IMAP_PORT); i.login(u, p)
    n = i.select("INBOX", readonly=True)[1][0].decode()
    print(f"{u}: {n} messages"); i.logout()
PY
          ;;
  *) echo "usage: $0 up|down|seed|status" >&2; exit 2 ;;
esac
