# Remote MCP examples

`openmail-mcp serve --transport http` listens on loopback (`127.0.0.1:8765`) and serves MCP at `/mcp`.
Expose it only behind TLS (reverse proxy). Remote clients present an OAuth access token (JWT);
the server validates it and never passes it through to mail servers.
`mail-mcp.example.com` is a placeholder host.

- `vscode-mcp.json`: VS Code remote entry, token prompted at connect time.
- `claude-desktop-remote.json`: Claude Desktop via the `mcp-remote` bridge.
- Claude Code: `../claude-code/add-remote.sh`.
