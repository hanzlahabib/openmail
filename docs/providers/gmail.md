# Gmail / Google Workspace

Checked 2026-11-19. Sources: a web search returned only third-party pages; Google's own page
(<https://support.google.com/mail/answer/7126229>) was **not** read. Treat everything below as UNVERIFIED
until compared with it.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `imap.gmail.com` | 993 | implicit TLS |
| SMTP | `smtp.gmail.com` | 465 (587 with STARTTLS also reported) | implicit TLS |

Username: full address.

## Auth
- App password: 16-character password from <https://myaccount.google.com/apppasswords>; requires 2-Step Verification.
- OAuth ("Sign in with Google") is the alternative; see the `openmail-oauth` crate.
- The normal account password does not work over IMAP/SMTP. Third-party sources report Google ended "less secure
  app" access on 2024-09-30 (UNVERIFIED).

## Prerequisites and quirks
- Workspace: an admin may have to enable IMAP and app passwords or OAuth access; SMTP settings can differ per
  organisation, ask the administrator.
- Google label/folder mapping differs from plain IMAP folders (labels appear as folders, `[Gmail]/...` prefixes).
  This is general knowledge, not checked in this pass.
