# Proton Mail via Proton Mail Bridge

Checked 2026-11-19. Official page <https://proton.me/mail/bridge> only appeared as a title in results; all values
below are from third-party pages. UNVERIFIED.

Proton does not expose IMAP/SMTP directly; the Bridge desktop app runs locally and serves them.

| | Host | Port | TLS |
|---|---|---|---|
| IMAP | `127.0.0.1` | 1143 | STARTTLS |
| SMTP | `127.0.0.1` | 1025 | STARTTLS |

- Ports can be changed in Bridge settings (or collide with other software); read the real values from the Bridge window.
- Username and password are the ones Bridge shows for the account. The Bridge password is not the Proton account password.
- Bridge uses a self-signed certificate. Export it from Bridge and trust it explicitly rather than disabling
  verification. OpenMail's TLS settings should pin/trust that cert; this page does not document the config key.
- Bridge is reported to require a paid Proton plan and must be running whenever OpenMail connects.
