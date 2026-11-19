# Microsoft 365 / Outlook

Checked 2026-11-19. Sources: Microsoft Learn,
<https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online>
(basic auth removed for IMAP/POP in Exchange Online, as reported in search results; page not read in full), and
Message Center post MC786329 via <https://mc.merill.net/message/MC786329>.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `outlook.office365.com` | 993 | implicit TLS (UNVERIFIED host/port) |
| SMTP | `smtp.office365.com` | 587 | STARTTLS (UNVERIFIED host/port) |

## Auth
- IMAP: OAuth 2.0 only (basic auth is gone). Scopes used by `openmail-oauth` are
  `https://outlook.office.com/IMAP.AccessAsUser.All` and `https://outlook.office.com/SMTP.Send`; this scope
  string was not confirmed against Microsoft docs in this pass (UNVERIFIED).
- SMTP AUTH basic auth: per MC786329 (updated 2026-01-27) removal is paused; a final date is to be announced in
  2027. New tenants created after December 2026 will have it off by default. Plan on OAuth.

## Prerequisites and quirks
- An Entra app registration is required for OAuth. The tenant admin must allow IMAP/SMTP AUTH on the mailbox
  (`Set-CASMailbox` / per-mailbox SMTP AUTH setting); not re-checked here.
- Personal Outlook.com accounts use a different endpoint family; not verified here.
