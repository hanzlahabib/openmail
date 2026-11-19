# Remote (Streamable HTTP) deployment

Status legend: **[built]** exists in code today, **[planned]** documented intent, not implemented.

## What the binary enforces today [built]

`openmail-mcp serve --transport http --bind <host:port>` refuses to start unless **both**:

| Env var | Meaning |
|---|---|
| `OPENMAIL_HTTP_TLS_CERT`, `OPENMAIL_HTTP_TLS_KEY` | PEM certificate chain and key paths |
| `OPENMAIL_HTTP_AUTH_TOKEN_FILE` | file holding the static bearer token (constant-time compare) |

Paths only; secrets never go on the command line. Endpoints: `POST /mcp` (authenticated),
`GET /healthz`, `GET /readyz`. A JWT/JWKS mode exists in `openmail-remote` (`auth.rs`); the CLI
wiring for it is **[planned]** — the CLI currently resolves only the static-token inputs above.

Because the listener itself demands TLS, a reverse proxy must re-encrypt to the upstream
(`https://127.0.0.1:8765`). Use a certificate the proxy trusts (internal CA or pinned self-signed).
Terminating TLS at the proxy and speaking plain HTTP to the upstream is **not** supported.

Keep `--bind` on `127.0.0.1` when a proxy fronts it; bind a public interface only without a proxy.

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

    location /mcp {
        proxy_pass https://127.0.0.1:8765;
        proxy_ssl_trusted_certificate /etc/openmail/tls/ca.pem;
        proxy_ssl_verify on;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;          # streaming responses
        proxy_read_timeout 3600s;
        proxy_set_header Authorization $http_authorization;
    }
    location = /healthz { proxy_pass https://127.0.0.1:8765; proxy_ssl_trusted_certificate /etc/openmail/tls/ca.pem; }
    location / { return 404; }        # do not expose /readyz or anything else publicly
}
```

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

- No automated test of the proxy snippets or the unit file; JWT mode not selectable from the CLI;
  no mTLS; no per-client tokens (single shared static token); no systemd socket activation.
