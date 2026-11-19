# Provider setup matrix

Checked 2026-11-19 by web search only (no page was fetched in full). Status per row:
**verified** = an official provider page appeared in the results and its snippet matched;
**UNVERIFIED** = only third-party pages or no official page was reached. Re-check UNVERIFIED rows
against the cited official URL before relying on them. The `openmail init` presets
(`crates/openmail-cli/src/init.rs`) use the same hosts and ports as this table.

| Provider | IMAP | SMTP | Auth | Status | Page |
|---|---|---|---|---|---|
| Gmail / Workspace | `imap.gmail.com:993` TLS | `smtp.gmail.com:465` TLS (or 587 STARTTLS) | App password (needs 2-Step Verification) or OAuth | host/ports UNVERIFIED (third-party only); LSA removal date reported by secondary sources | [gmail.md](gmail.md) |
| Microsoft 365 / Outlook.com | `outlook.office365.com:993` TLS | `smtp.office365.com:587` STARTTLS | OAuth only for IMAP; SMTP AUTH basic auth still possible for now | auth change verified (Microsoft Learn); hosts UNVERIFIED | [microsoft365.md](microsoft365.md) |
| Fastmail | `imap.fastmail.com:993` TLS | `smtp.fastmail.com:465` TLS (587 STARTTLS fallback) | App password | UNVERIFIED (Fastmail help URLs seen, not read) | [fastmail.md](fastmail.md) |
| iCloud Mail | `imap.mail.me.com:993` TLS | `smtp.mail.me.com:587` STARTTLS | App-specific password | verified (Apple support snippet) | [icloud.md](icloud.md) |
| Yahoo Mail | `imap.mail.yahoo.com:993` TLS | `smtp.mail.yahoo.com:465` TLS (or 587) | App password | verified (Yahoo help snippet) | [yahoo.md](yahoo.md) |
| Proton Mail (Bridge) | `127.0.0.1:1143` STARTTLS | `127.0.0.1:1025` STARTTLS | Bridge-generated password | UNVERIFIED (third-party only) | [proton-bridge.md](proton-bridge.md) |
| Generic IMAP / Dovecot / cPanel | your server, 993 TLS | your server, 465 TLS or 587 STARTTLS | Account password | cPanel ports verified (docs.cpanel.net); Dovecot generic | [generic-imap.md](generic-imap.md) |

OpenMail refuses plaintext transports; every row above is TLS or STARTTLS.
