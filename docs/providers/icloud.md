# iCloud Mail

Checked 2026-11-19 against Apple's support page "iCloud Mail server settings for other email client apps"
(<https://support.apple.com/en-us/102525>, snippet seen in search results). Verified.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `imap.mail.me.com` | 993 | SSL/TLS required |
| SMTP | `smtp.mail.me.com` | 587 | STARTTLS; authentication required |

- Username: the full iCloud address (not just the local part).
- Password: an app-specific password (Apple Account > Sign-In and Security > App-Specific Passwords). It is
  shown once; revoke and regenerate if lost. Requires two-factor authentication on the Apple Account (general knowledge).
- POP is not supported.
