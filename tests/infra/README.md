# OpenMail test infra (TEST ONLY)

Disposable GreenMail 2.1.3 (image pinned by digest in `docker-compose.yml`), bound to 127.0.0.1 only.
Never expose these ports or reuse these credentials anywhere real.

`scripts/test-infra.sh up|down|seed|status` — `up` starts the container, waits for IMAP, seeds; `seed` is idempotent (clears INBOX, re-appends); `down` removes container and volumes.

| Service | Host port | Notes |
|---|---|---|
| IMAP | 13143 | plain, LOGIN/PLAIN |
| IMAPS | 13993 | self-signed cert |
| SMTP | 13025 | AUTH PLAIN/LOGIN/XOAUTH2 |
| SMTPS | 13465 | self-signed cert |
| REST API | 18080 | GreenMail admin API |

| User (IMAP login) | Password | Address |
|---|---|---|
| alice | alicepass | alice@openmail.test |
| bob | bobpass | bob@openmail.test |
| carol | carolpass | carol@openmail.test |

Login name is the local part. Messages sent over SMTP to these addresses are delivered locally.

## Fixture corpus (`tests/fixtures/eml/`, regenerate with `tests/infra/gen_fixtures.py`)
File prefix = target mailbox. alice(12): plain, multipart/alternative, attachments, latin1/shift_jis/koi8-r charsets, RFC 2047 subject, 3 malformed MIME (unclosed boundary, bad CTE/charset, 40-deep nesting), 2 duplicate Message-IDs. bob(5): cross-mailbox duplicate ID, prompt-injection bodies (direct, tool-call, hidden HTML, subject). carol(30): one long In-Reply-To/References thread. Injection text is hostile DATA for security tests.

## Not done
No Dovecot/Postfix variant; no STARTTLS/OAuth realism (GreenMail only); uses the default docker bridge (`network_mode: bridge`) because custom networks fail on hosts with exhausted address pools.
