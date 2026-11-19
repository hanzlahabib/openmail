# Fastmail

Checked 2026-11-19. Search results pointed at Fastmail help articles (e.g. <https://www.fastmail.help/hc/en-us/articles/1500000278342>)
but their text was not read; values come from third-party pages that agree with each other. UNVERIFIED.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `imap.fastmail.com` | 993 | implicit TLS |
| SMTP | `smtp.fastmail.com` | 465 (587 STARTTLS fallback) | implicit TLS |

Username: full address. Auth: app password (Settings > Privacy & Security), not the login password. One
third-party page claimed the regular password works; it conflicts with the rest and is treated as outdated.
Quirk: a Basic plan was reported to exclude IMAP/SMTP access.
