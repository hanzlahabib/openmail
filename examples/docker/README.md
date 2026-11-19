# Running OpenMail MCP in Docker

1. `cp examples/docker/config.example.toml examples/docker/config.toml` and edit (fake values in the example).
2. `install -m 600 /dev/null .env` and put secrets there (`KEY=value` lines).
3. `docker compose up -d --build`; the server listens on `127.0.0.1:8765` only.

The container runs as uid 10001 with a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, and no Docker socket. Binding `0.0.0.0` inside the container requires
bearer auth to be configured (the server refuses otherwise).
