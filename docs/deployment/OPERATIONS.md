# Operations handbook

Status legend: **[built]** exists today, **[planned]** documented intent only. Do not rely on a
**[planned]** procedure; the manual fallback is given where one exists.

## State inventory

| What | Where | Status |
|---|---|---|
| Config (TOML, no secrets) | `$XDG_CONFIG_HOME/openmail-mcp/config.toml` or `--config`/`OPENMAIL_CONFIG` | [built] |
| Brief store (SQLite: cursors, briefs, runs, delivery state) | `briefs.db` (`openmail-briefs`) | [built] |
| Send outbox / idempotency / audit records | `openmail-smtp` | [planned] (not yet persisted) |
| Send approvals | `openmail-security` | [planned] (not yet persisted) |
| Secrets | env vars / OS keyring, referenced by `CredentialRef` | [built] |
| Mail itself | your mail provider (OpenMail keeps no mailbox copy) | n/a |

## Backups

1. **Config**: copy the file; it contains no secrets (`deny_unknown_fields`, credentials are references only).
2. **SQLite stores**: never `cp` a live database. Use a consistent snapshot:
   `sqlite3 briefs.db ".backup '/backup/briefs-$(date +%F).db'"` (or stop the service, then copy).
   Include any `-wal`/`-shm` files only when copying a stopped database.
3. **Secrets**: back up the secret manager / env file separately and encrypted; never alongside config.
4. Test restore on a scratch directory: `sqlite3 restored.db "PRAGMA integrity_check;"` must print `ok`.

Backups are manual today; scheduled backups are **[planned]**. Outbox/approval stores will be added to this
list when they exist.

## Secret rotation

- **Mailbox app password**: create the new one at the provider, update the env file/keyring entry,
  `systemctl restart openmail-mcp`, run `openmail-mcp doctor`, then revoke the old one at the provider.
- **HTTP bearer token** (remote): write a new file (mode 600), restart, update clients, delete the old one.
  Single shared token: rotation is a brief outage for all clients. Zero-downtime dual tokens: **[planned]**.
- **OAuth refresh tokens**: see OAuth revocation below.
- Rotate immediately if a secret appeared in logs, a ticket or a repo; assume exposure from first appearance.

## Updates and rollback

```sh
scripts/upgrade.sh              # keeps openmail-mcp.bak next to the binary
openmail-mcp doctor             # config + connectivity after the upgrade
scripts/upgrade.sh --rollback   # restore previous binary
```

Back up SQLite stores **before** upgrading. Rollback restores the binary only; if the new version
migrated a store (`schema_migrations`), restore the pre-upgrade backup too, because an older binary
may refuse or mishandle a newer schema. See INSTALL.md for checksum verification.

## Upgrade compatibility

- Config: unknown keys are rejected, so a config written for a newer version can fail on an older binary. Keep config in version control.
- `ErrorCode` values are append-only; clients should tolerate new codes.
- `MessageRef` format `v1` is frozen. References held across a UIDVALIDITY change return `StaleReference`; re-list and retry.
- SQLite migrations are forward-only and tracked in `schema_migrations`; there is no down-migration. Rollback = restore the backup.

## Monitoring

- Remote: `GET /healthz` (liveness) and `GET /readyz` (readiness) [built]. Keep `/readyz` internal.
- Metrics: `openmail-observe` renders Prometheus text; counters: `imap_connection_failures`, `auth_failures`,
  `mcp_request_failures`, `rate_limit_rejections`, `smtp_attempts`, `smtp_uncertain`, `failed_mailbox_scans`,
  `retries`. A built-in scrape endpoint is **[planned]**: the host decides whether to expose the text.
- Suggested alerts: any `smtp_uncertain` increase; sustained `auth_failures` (credential expired or probing);
  rising `imap_connection_failures` (provider outage, network, or revoked credential).
- Logs go to stderr via tracing (`OPENMAIL_LOG`, default `warn`). Use `journalctl -u openmail-mcp`.
  Mailbox content is untrusted data; do not raise log levels in shared systems without checking redaction.

## Mail-server failures

| Symptom | Check | Action |
|---|---|---|
| IMAP connect/timeouts | `openmail-mcp accounts test <name>`, provider status page | wait; tools return typed errors, no data loss |
| Auth failures | app password revoked/expired, provider forced 2FA/app-password change | rotate secret, restart, `doctor` |
| `StaleReference` | mailbox rebuilt/UIDVALIDITY changed | re-run search/list to get new refs |
| SMTP rejected | provider rate limit, from-address not allowed | fix config; do not retry blindly |
| Provider IP block | many failed logins from one host | stop service, rotate secret, retry after cooldown |

## OAuth revocation

If a refresh token is compromised or an account is offboarded: revoke the app's access at the provider
(Google: account permissions page; Microsoft: My Apps / Entra enterprise app), delete the stored
`TokenSet` from the keyring/secret store, then re-authorize via device flow when needed. OpenMail
does not persist tokens itself (caller/keyring responsibility). Programmatic revoke command: **[planned]**.

## Incident handling

1. **Contain**: `systemctl stop openmail-mcp` (or remove the client's token). Accounts default to `read_only = true`; confirm none were changed to writable unexpectedly (`openmail-mcp accounts list`).
2. **Assess**: `journalctl -u openmail-mcp --since ...`; check `auth_failures`, unexpected sends (provider "Sent" folder is the ground truth).
3. **Eradicate**: rotate every secret the process could read (mailbox, bearer token, OAuth). Revoke OAuth grants.
4. **Recover**: patch/upgrade, restore config from version control, restart, `doctor`.
5. **Review**: record timeline and what the authorization policy let through; open an issue (no secrets or message content in it).
Suspected prompt injection through mail content: treat as an incident if a send or delete occurred that the user did not intend; send approvals are the control that should have stopped it.

## UNCERTAIN-send recovery

An SMTP send can time out after the message was handed to the server, so success is unknown. OpenMail
reports this as an uncertain outcome (`DeliveryUncertain`; briefs record `DeliveryState::Uncertain`; counter `smtp_uncertain`)
rather than guessing. **Do not blindly resend**: that can duplicate mail.

1. Find the message: check the account's **Sent** folder (and, for a recipient you control, their inbox) for the Message-ID/subject/time.
2. Found → treat as delivered; mark it resolved in your own records.
3. Not found after a few minutes (allow for provider queueing) → resend once, deliberately.
4. For brief digests, the next run does not re-send an Uncertain delivery automatically; verify as above, then trigger the brief manually.
Idempotent-send keys and an operator command to resolve uncertain records are **[planned]** with the outbox store; until then this is a manual check.

## Data deletion

- Remove an account: delete its block from config, remove its secret (env/keyring), revoke OAuth, restart.
- Remove derived data: delete `briefs.db` (stop the service first); it is rebuilt empty on next start and loses only brief history and cursors, which may cause one re-summarization of recent mail.
- Full removal: `scripts/uninstall.sh --purge` deletes the binary and config dir; separately delete state directories (`/var/lib/openmail`) and backups.
- Mailbox contents are never copied by OpenMail; delete mail at the provider. A per-account purge command is **[planned]**.

## Not done

No scheduled backup tooling, no restore command, no built-in metrics endpoint, no automated downgrade path,
no outbox/approval stores to document yet. Commands in this file were not executed against a live deployment.
