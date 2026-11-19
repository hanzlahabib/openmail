# openmail-oauth notes

## Provider endpoints (checked 2026-11-19)
- Google: endpoints from https://accounts.google.com/.well-known/openid-configuration (authorization `o/oauth2/v2/auth`, token `oauth2.googleapis.com/token`, device `oauth2.googleapis.com/device/code`). Device flow: https://developers.google.com/identity/protocols/oauth2/limited-input-device (response field is `verification_url`; handled by serde alias). Scope `https://mail.google.com/` for IMAP/SMTP XOAUTH2: https://developers.google.com/gmail/imap/xoauth2-protocol
- Microsoft identity platform v2.0: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token,devicecode}` — https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow and .../v2-oauth2-device-code. Scopes `https://outlook.office.com/IMAP.AccessAsUser.All`, `.../SMTP.Send`, `offline_access`: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth (scopes confirmed by fetch; the Microsoft URL paths follow the documented pattern but were not re-fetched).
- XOAUTH2 format: `base64("user=" user "\x01auth=Bearer " token "\x01\x01")`.

## Not done
- No loopback redirect listener (caller receives the code and calls `exchange_code`).
- No persistence of `TokenSet` (SecretSource/keyring wiring belongs to the caller).
- No client-assertion / client-credentials (app-only) Microsoft flow.
- Not wired into imap/smtp crates (not owned by this task).

## Verification caveat
Final fmt/clippy/test were run with the `stable` toolchain (14 tests pass). The pinned `1.100` toolchain was being corrupted by concurrent rustup repairs from parallel agents, so it could not be used for the last run.
Device-flow `slow_down` backoff is implemented but not covered by a test (tests use interval 0).
