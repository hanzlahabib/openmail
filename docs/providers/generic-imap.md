# Generic IMAP / Dovecot / cPanel

Checked 2026-11-19. cPanel: <https://docs.cpanel.net/cpanel/meridian/email/connecting-email-to-a-mail-client-or-device/>
(appeared in results, matches the values below). Dovecot specifics are general knowledge, not looked up.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `mail.<your-domain>` or the host the provider gives | 993 | implicit TLS |
| SMTP | same | 465 (implicit TLS) or 587 (STARTTLS) | |

- Username: usually the full address. Password: the mailbox password. Basic password auth over TLS is the norm.
- cPanel: Email > Email Accounts > Connect Devices lists the exact host and ports for each mailbox.
- Certificate: the server certificate must match the hostname you configure. A mismatch (common when using the
  server IP or a shared-hosting hostname) fails TLS validation; use the hostname on the certificate.
- Some shared hosts also expose plaintext/non-standard ports (25, 26, 143); OpenMail does not use plaintext.
- Autodiscovery in other clients often guesses wrong for cPanel mailboxes; always set hosts manually.
