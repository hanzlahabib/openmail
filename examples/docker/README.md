# Running OpenMail MCP in Docker

The image runs the **stdio** transport (the MCP client speaks over stdin/stdout). The http transport
refuses to start without TLS and a bearer token file and is not wired end to end yet, so the image
exposes no port and has no healthcheck (`HEALTHCHECK NONE`): a stdio process has no listener to probe.

1. `cp examples/docker/config.example.toml examples/docker/config.toml` and edit (fake values in the example).
   The config holds no secrets. The container user (uid 10001) must be able to read it: `chmod 644`
   (`openmail-mcp doctor` warns about the broad mode; that is expected for a secret-free file).
2. `install -m 600 /dev/null .env` and put secrets there (`OPENMAIL_PERSONAL_PASSWORD=...`).
3. `docker compose build`, then point your MCP client at
   `docker compose run --rm -T openmail-mcp` (or `docker run -i --rm --read-only ... openmail-mcp:local`).

The container runs as uid 10001 with a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, and no Docker socket.
