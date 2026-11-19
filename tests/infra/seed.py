#!/usr/bin/env python3
"""Seed tests/fixtures/eml into GreenMail via IMAP APPEND. Filename prefix = target user."""
import imaplib
import os
import pathlib
import sys

HOST = os.environ.get("OPENMAIL_TEST_HOST", "127.0.0.1")
PORT = int(os.environ.get("OPENMAIL_TEST_IMAP_PORT", "13143"))
PASSWORDS = {"alice": "alicepass", "bob": "bobpass", "carol": "carolpass"}
EML = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "eml"


def main() -> int:
    counts = {}
    for user, pw in PASSWORDS.items():
        files = sorted(EML.glob(f"{user}-*.eml"))
        imap = imaplib.IMAP4(HOST, PORT)
        imap.login(user, pw)
        imap.select("INBOX")
        _, data = imap.search(None, "ALL")
        if data[0]:  # idempotent: reseed from scratch
            imap.store("1:*", "+FLAGS", "\\Deleted")
            imap.expunge()
        for f in files:
            typ, resp = imap.append("INBOX", None, None, f.read_bytes())
            if typ != "OK":
                print(f"APPEND failed for {f.name}: {resp}", file=sys.stderr)
                return 1
        counts[user] = len(files)
        imap.logout()
    print("seeded:", counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
