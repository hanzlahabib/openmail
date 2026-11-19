# Managing mailboxes on a server

Three different logins exist; do not mix them up:

| Layer | What it is | Where it is set |
|---|---|---|
| ChatGPT / MCP client -> OpenMail | the **OpenMail owner password** on the OpenMail consent page (built-in OAuth) | `openmail-mcp oauth hash-password` |
| OpenMail -> mail server | each **mailbox's IMAP/SMTP password** (ideally an app password) | `openmail-mcp accounts add` (below) |
| Operator | you, with shell access to the server | SSH |

A mailbox password is never typed into ChatGPT or the OAuth page.

## Add, list, test, remove (on the server)

```sh
# prompts for the password with hidden input; use --password-stdin in scripts/Docker
openmail-mcp --config /etc/openmail/config.toml accounts add work \
  --email me@example.com --imap-host imap.example.com
openmail-mcp --config /etc/openmail/config.toml accounts add sales \
  --email sales@example.com --imap-host imap.example.com \
  --smtp-host smtp.example.com --allow drafts          # writable: drafts only
openmail-mcp --config /etc/openmail/config.toml accounts list
openmail-mcp --config /etc/openmail/config.toml accounts test          # real IMAP/SMTP login per account
systemctl restart openmail-mcp                                         # the server loads accounts at start

openmail-mcp --config /etc/openmail/config.toml accounts add work ... --replace   # rotate a password
openmail-mcp --config /etc/openmail/config.toml accounts remove sales             # config + secret only
```

Layout beside the main config: `accounts.d/<id>.toml` (one account per file, same format as the main config) and
`secrets/<id>` (only the password, mode 600 in a 700 directory). The server merges `accounts.d/` at startup, so
mailboxes survive restarts, upgrades and container recreation as long as the config directory is a volume.
`remove` deletes those two files only; **it never touches the mailbox or any message on the mail server.**
A broken or duplicate drop-in stops the server with an error naming the file instead of silently dropping a mailbox.
Accounts defined in the main `config.toml` keep working unchanged (use `kind = "env"`, `"file"` or `"keyring"`).

## Why a mailbox shows `imap_ok=false`

`mail_test_connection` (and `accounts test`) return a `failure` classification, never server text or secrets:

| `failure` | Meaning | Fix |
|---|---|---|
| `credential_missing` | the server has no password for this account (unset/empty env var, missing secret file) | run `accounts add ... --replace` or set the variable |
| `auth_rejected` | the mail server refused the login | wrong password/username, app password needed, IMAP disabled |
| `connection_failed` | DNS, port, firewall or TLS problem | check host, port, `tls` mode, certificate |
| `timeout` | no answer in time | network/provider |
| `config_invalid` | e.g. a secret file readable by others | `chmod 600` it |

## Docker

Mount the config directory as a volume (`/etc/openmail`) so `accounts.d/` and `secrets/` persist, or provide secrets
with Docker secrets and `credential = { kind = "file", path = "/run/secrets/work" }`.

## Not built yet (planned)

MCP tools for managing accounts (`admin_*`) and a web onboarding form are not implemented: they need an
`accounts.manage` OAuth scope, explicit owner confirmation and live reload of the account registry, and must never
accept mailbox passwords through chat. Until then, mailbox changes are made on the server as above.
