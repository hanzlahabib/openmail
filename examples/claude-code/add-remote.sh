#!/usr/bin/env bash
# Register a locally running `openmail-mcp serve --transport http` with Claude Code.
claude mcp add --transport http openmail-remote http://127.0.0.1:8765/mcp
