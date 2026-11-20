# Remote (Streamable HTTP) deployment

Status legend: **[built]** exists in code today, **[planned]** documented intent, not implemented.

## What the binary enforces today [built]

`openmail-mcp serve --transport http --bind <host:port>` serves the real MCP service over
in-process TLS (rustls). It refuses to start unless **both** TLS and authentication are configured:

| Env var | Meaning |
|---|---|
| `OPENMAIL_HTTP_TLS_CERT`, `OPENMAIL_HTTP_TLS_KEY` | PEM certificate chain and key paths |
| `OPENMAIL_HTTP_AUTH_TOKEN_FILE` | static bearer token file (constant-time compare). Must be mode 600; the principal may read every configured account, with the actions in `OPENMAIL_HTTP_STATIC_ACTIONS` (default `read`) |
| `OPENMAIL_HTTP_JWT_ISSUER`, `_AUDIENCE`, `_JWKS_URL`, `_SCOPE_ACCOUNTS` | **instead of** the token file: validate OAuth JWTs (ES/RS/PS/EdDSA only) against the issuer's JWKS. `_AUDIENCE` is this server's `/mcp` URL; `_SCOPE_ACCOUNTS` maps scopes to accounts, e.g. `mail:work=work,shared;mail:home=home` |
| `OPENMAIL_HTTP_PUBLIC_URL` | public base URL (`https://mail-mcp.example.com`), advertised in `WWW-Authenticate`; its host joins the `Host` allowlist |
| `OPENMAIL_HTTP_ALLOWED_HOSTS`, `_ALLOWED_ORIGINS` | extra comma-separated `Host` values / browser `Origin`s to accept |

Configure exactly one authentication mode: static token file, external JWT, or built-in OAuth. Token scopes `mail:read|organize|draft|send|delete`
grant those actions; the accounts a token may touch come only from the scope mapping, and account
permissions in the config still apply on top. A token limited to account A cannot name account B
(the answer is the same `ACCESS_DENIED` as for an unknown account).

Paths only; secrets never go on the command line. Endpoints: `POST|GET|DELETE /mcp`
(authenticated), `GET /.well-known/oauth-protected-resource` (RFC 9728), `GET /healthz`,
`GET /readyz`. Requests carrying a disallowed `Origin` get 403, bodies over 1 MiB 413, more than
20 req/s per client address 429. An MCP session is bound to the principal that created it; another
principal presenting its id gets 404. On SIGTERM `/readyz` flips to 503, open streams are cancelled
and in-flight requests get 10 s to finish.

Because the listener itself demands TLS, a reverse proxy must re-encrypt to the upstream
(`https://127.0.0.1:8765`). Use a certificate the proxy trusts (internal CA or pinned self-signed).
Terminating TLS at the proxy and speaking plain HTTP to the upstream is **not** supported.

Keep `--bind` on `127.0.0.1` when a proxy fronts it; bind a public interface only without a proxy.

## Built-in OAuth authorization server (no third-party IdP)

ChatGPT and Claude connectors only speak OAuth. `serve --transport http` can be its own single-owner
authorization server, free and self-hosted (crate `openmail-authserver`): authorization code + PKCE (S256, mandatory),
public clients only, RFC 7591 dynamic client registration restricted to allowlisted redirect hosts
(`chatgpt.com`, `chat.openai.com`, `platform.openai.com`, `claude.ai`, `claude.com`, loopback; add more with
`OPENMAIL_OAUTH_REDIRECT_HOSTS`), RFC 8414 metadata, RFC 8707 `resource`, RFC 9207 `iss`, ES256 JWT access tokens
(1 h) and rotating refresh tokens (30 d). The owner signs in on the consent page with a password (Argon2id hash);
5 wrong attempts pause sign-in for 5 minutes.

```sh
read -rs P; printf %s "$P" | openmail-mcp oauth hash-password > /etc/openmail/owner.hash   # >= 12 characters
chmod 600 /etc/openmail/owner.hash
```

| Env var | Meaning |
|---|---|
| `OPENMAIL_OAUTH_OWNER_PASSWORD_HASH_FILE` | enables the built-in server (instead of the token file or external JWT); file must be mode 600 |
| `OPENMAIL_HTTP_PUBLIC_URL` | required: the public https origin; becomes the issuer, resource is `<origin>/mcp` |
| `OPENMAIL_OAUTH_SCOPES` | grantable scopes, default `mail:read` (read-only); each maps to every configured account |
| `OPENMAIL_OAUTH_REDIRECT_HOSTS` | extra redirect hosts |
| `OPENMAIL_STATE_DIR` | where `oauth/` (signing key, registered clients, hashed refresh tokens) lives |

The proxy must pass these paths to the service unauthenticated: `/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server`, `/authorize`, `/token`, `/register`, `/jwks.json`, plus `/mcp`.
**Registration is closed after the first successful login.** Anyone on the internet could otherwise register a client that looks like your assistant and lure you to the consent page. To add another connector later, open a window on the server: `openmail-ctl oauth registration open --minutes 10` (it closes by itself; `... close` ends it). The consent page shows the redirect host and how recently the client was registered, and a page dies after 5 wrong passwords (30 failures overall pause sign-in for 5 minutes).

Limits: one owner, no consent memory (each new connection asks again), no token revocation endpoint (delete
`oauth/oauth.db` to revoke everything, change the password hash to stop new sign-ins).

## Token

```sh
umask 077
head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > /etc/openmail/token
```

Mode 600, owned by the service user. Clients send `Authorization: Bearer <token>`.

## Caddy

```caddyfile
mail-mcp.example.com {
    encode zstd gzip
    reverse_proxy https://127.0.0.1:8765 {
        transport http {
            tls_trust_pool file /etc/openmail/tls/ca.pem
        }
        flush_interval -1          # do not buffer Streamable HTTP / SSE responses
    }
    request_body { max_size 1MB }
}
```

Caddy obtains and renews the public certificate itself (ports 80/443 must be reachable).
`tls_trust_pool` is the Caddy 2.8+ spelling; older versions use `tls_trusted_ca_certs`.

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name mail-mcp.example.com;
    ssl_certificate     /etc/letsencrypt/live/mail-mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail-mcp.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 1m;
    proxy_ssl_trusted_certificate /etc/openmail/tls/ca.pem;
    proxy_ssl_verify on;

    location = /mcp {
        proxy_pass https://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;          # streaming responses
        proxy_read_timeout 3600s;
        proxy_set_header Authorization $http_authorization;
    }
    location ~ ^/(?:[.]well-known/oauth-(?:protected-resource|authorization-server)|authorize|token|register|jwks[.]json|healthz)$ {
        proxy_pass https://127.0.0.1:8765;
    }
    location / { return 404; }
}
```

The upstream certificate must be valid for `127.0.0.1` as shown. If it uses a DNS name,
configure `proxy_ssl_name` for that certificate name and enable `proxy_ssl_server_name`.
For a static-token deployment, retain protected-resource discovery and health checks and omit
the built-in authorization server routes.

## Service user and systemd unit

Never run as root. One unprivileged user, no shell, no sudo, no docker group.

```sh
sudo useradd -r -m -d /var/lib/openmail -s /usr/sbin/nologin openmail
sudo install -d -m 700 -o openmail -g openmail /etc/openmail /etc/openmail/tls
sudo install -m 600 -o openmail -g openmail token /etc/openmail/token
sudo install -m 600 -o openmail -g openmail /dev/null /etc/openmail/env   # mailbox credentials
```

`/etc/openmail/env` (mode 600) holds e.g. `OPENMAIL_A_PASSWORD=...` referenced by the config's
`credential = { kind = "env", var = "..." }`, plus the three `OPENMAIL_HTTP_*` paths.

`/etc/systemd/system/openmail-mcp.service`:

```ini
[Unit]
Description=OpenMail MCP (Streamable HTTP)
After=network-online.target
Wants=network-online.target

[Service]
User=openmail
Group=openmail
EnvironmentFile=/etc/openmail/env
ExecStart=/usr/local/bin/openmail-mcp serve --transport http --bind 127.0.0.1:8765 --config /etc/openmail/config.toml
Restart=on-failure
RestartSec=5
StateDirectory=openmail
ConfigurationDirectory=openmail
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/openmail

[Install]
WantedBy=multi-user.target
```

Verify the hardening with `systemd-analyze security openmail-mcp` and check
`ps -o user= -C openmail-mcp` prints `openmail`. The unit has not been exercised against a real
build in this repo's CI: **treat it as a reviewed template, not a tested artifact.**

## Firewall

Only 80/443 (proxy) and SSH need to be reachable; 8765 must not be.

```sh
sudo ufw default deny incoming
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable
```

Outbound must allow IMAP (993) / SMTP (465/587) to your mail provider and, for OAuth accounts,
HTTPS to the provider's token endpoint. Docker users: published ports bypass ufw; bind
`127.0.0.1:8765:8765` and run the container with `user:` set to a non-root UID.

## Smoke test

```sh
curl -fsS https://mail-mcp.example.com/healthz
curl -si -X POST https://mail-mcp.example.com/mcp | head -1          # expect 401 without a token
curl -si -H "Authorization: Bearer $(cat /etc/openmail/token)" -X POST \
     https://mail-mcp.example.com/mcp | head -1                      # authenticated: not 401
```

## Not done

- No automated test of the proxy snippets or the unit file; no mTLS; no per-client static tokens
  (use JWT mode for per-client identity); no systemd socket activation; JWT mode is tested against
  a local JWKS in the test suite. Built-in OAuth provides dynamic client registration at `/register`.
