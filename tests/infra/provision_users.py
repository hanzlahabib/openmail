#!/usr/bin/env python3
"""Provision N GreenMail users (REST) and fill each INBOX with M deterministic messages (IMAP APPEND).

TEST-ONLY. Targets the perf container (tests/infra/docker-compose.perf.yml). Idempotent: users that
already exist are kept and their INBOX is emptied before re-seeding, so mailbox size is exact.
Usage: provision_users.py N MESSAGES_PER_USER [--host H] [--imap-port P] [--api-port P]
"""
import argparse
import imaplib
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# One message in KEYWORD_EVERY carries the search keyword, so search hit counts are known exactly.
KEYWORD_EVERY = 10
KEYWORD = "quarterly-invoice"
# Body size: representative short business mail (~2 KiB), identical for every message.
BODY_FILLER = ("The quick brown fox jumps over the lazy dog. " * 45).strip()


def user_name(i: int) -> str:
    return f"perf{i:03d}"


def password(i: int) -> str:
    return f"pw-{user_name(i)}-perf"


def build_message(user: str, n: int) -> bytes:
    kw = f" {KEYWORD}" if n % KEYWORD_EVERY == 0 else ""
    day = 1 + (n % 28)
    return (
        f"From: sender{n % 17}@example.com\r\nTo: {user}@openmail.test\r\n"
        f"Subject: Message {n}{kw}\r\nDate: {day:02d} Jan 2025 09:{n % 60:02d}:00 +0000\r\n"
        f"Message-ID: <{user}-{n}@perf.test>\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n{BODY_FILLER}{kw}\r\n"
    ).encode()


def create_user(api: str, i: int) -> None:
    body = json.dumps(
        {"login": user_name(i), "email": f"{user_name(i)}@openmail.test", "password": password(i)}
    ).encode()
    req = urllib.request.Request(
        f"{api}/api/user", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        # GreenMail answers 400 "...already exists" for a duplicate email; anything else is real.
        if b"already exists" not in e.read():
            raise


def seed(host: str, port: int, i: int, count: int) -> None:
    imap = imaplib.IMAP4(host, port)
    imap.login(user_name(i), password(i))
    imap.select("INBOX")
    _, data = imap.search(None, "ALL")
    if data[0]:
        imap.store("1:*", "+FLAGS", "\\Deleted")
        imap.expunge()
    for n in range(1, count + 1):
        typ, resp = imap.append("INBOX", None, None, build_message(user_name(i), n))
        if typ != "OK":
            raise RuntimeError(f"APPEND failed for {user_name(i)}: {resp}")
    imap.logout()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("users", type=int)
    p.add_argument("messages", type=int)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--imap-port", type=int, default=23143)
    p.add_argument("--api-port", type=int, default=28080)
    a = p.parse_args()
    api = f"http://{a.host}:{a.api_port}"
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(lambda i: create_user(api, i), range(a.users)))
        list(ex.map(lambda i: seed(a.host, a.imap_port, i, a.messages), range(a.users)))
    print(f"provisioned {a.users} users x {a.messages} messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
