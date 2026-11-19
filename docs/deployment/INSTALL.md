# Installing openmail-mcp

Installers download a release archive and `SHA-256SUMS` from your release repository, verify the
archive checksum **before extracting**, then install to `~/.local/bin`. They refuse to run as root.
No default repository is baked in: set `OPENMAIL_REPO`.

## Linux / macOS

```sh
export OPENMAIL_REPO=<owner>/<repo>        # required
export OPENMAIL_VERSION=v0.1.0             # optional, default: latest
scripts/install.sh
```

| Variable | Meaning |
|---|---|
| `OPENMAIL_REPO` | `owner/name` of the GitHub repo hosting releases |
| `OPENMAIL_VERSION` | release tag, default `latest` |
| `OPENMAIL_BASE_URL` | override the download directory (mirror, `file://` fixture) |
| `OPENMAIL_INSTALL_DIR` | default `~/.local/bin` |

Expected release assets: `openmail-mcp-<tag>-<target>.tar.gz` as `release.yml` produces them (targets:
`x86_64`/`aarch64` × `unknown-linux-gnu` / `apple-darwin`; the archive holds a `openmail-mcp-<tag>-<target>/`
directory containing `openmail-mcp`) and `SHA-256SUMS` from `scripts/checksums.sh`. The installer reads the
archive name from `SHA-256SUMS` (so `latest` works without knowing the tag); a plain
`openmail-mcp-<target>.tar.gz` is also accepted.

### Upgrade and rollback

```sh
scripts/upgrade.sh             # installs the new binary, keeps openmail-mcp.bak
scripts/upgrade.sh --rollback  # restores the previous binary
```

### Uninstall

```sh
scripts/uninstall.sh           # removes the binary, KEEPS config in ~/.config/openmail
scripts/uninstall.sh --purge   # also deletes the config directory
```

## Windows (PowerShell, non-elevated)

```powershell
$env:OPENMAIL_REPO = '<owner>/<repo>'
.\scripts\install.ps1              # install (to %LOCALAPPDATA%\Programs\openmail)
.\scripts\install.ps1 -Upgrade     # install with backup
.\scripts\install.ps1 -Rollback
.\scripts\install.ps1 -Uninstall [-Purge]
```

Asset: `openmail-mcp-<tag>-<x86_64|aarch64>-pc-windows-msvc.zip`, resolved from `SHA-256SUMS`.

## Verification

Run 2026-11-19 on Linux x86_64 (WSL2), rustc 1.100.0, Docker 26.1.3. Source for the image and reproducibility
builds was `git archive HEAD` (c5d649b) because the shared tree had other agents' uncommitted edits.

**Defects found and fixed**
- `install.sh` / `install.ps1` requested `openmail-mcp-<target>.tar.gz`, but `release.yml` publishes
  `openmail-mcp-<tag>-<target>.tar.gz`: every real install would have 404'd. Both now resolve the archive name
  from `SHA-256SUMS` (a first fix attempt was off by one and caught by running against the real layout).
- `Dockerfile` default `CMD` was `serve --transport http`, which exits immediately
  (`refusing --transport http without TLS: set OPENMAIL_HTTP_TLS_CERT and OPENMAIL_HTTP_TLS_KEY`); the container
  would crash-loop and the TCP healthcheck could never pass. Default is now stdio, `HEALTHCHECK NONE`, no `EXPOSE`;
  `compose.yaml` follows (no port, healthcheck disabled, no restart policy, `.env` optional).
- `examples/docker/config.example.toml` was invalid (`[[accounts]]`; `doctor`: `unknown field accounts`). Replaced
  with a valid example matching the README schema. A 0600 host config is unreadable by uid 10001; documented `chmod 644`.

**Docker** (`docker build -t openmail-mcp:t40 .`, ~200 s cold): builds; image **95.6 MB**.
- `docker run --rm --entrypoint id` -> `uid=10001(openmail) gid=10001(openmail)`; `Config.User=10001:10001`.
- `--read-only --cap-drop ALL --security-opt no-new-privileges` with the example config: MCP `initialize` over
  stdin returns `serverInfo openmail-mcp 0.1.0`; `touch /x` -> `Read-only file system`.
- `doctor` in the container passes config parsing with the new example. `docker compose config -q` valid.
- Not done: compose `up`/`run` against a real IMAP server; http transport in a container (not wired; needs TLS + token file).

**Release tarball** built with the `release.yml` layout (`openmail-mcp-v0.1.0-x86_64-unknown-linux-gnu/{openmail-mcp,LICENSE,README.md}`),
`scripts/checksums.sh` wrote `SHA-256SUMS`. `install.sh` against `OPENMAIL_BASE_URL=file://...` with a temp `HOME`:
fresh install OK (`openmail-mcp 0.1.0`); upgrade kept `openmail-mcp.bak` byte-identical to the old binary;
`upgrade.sh --rollback` restored it; stale-checksum archive refused with `checksum mismatch ... nothing was installed`
and the installed binary untouched; missing SUMS entry refused; `uninstall.sh` removed the binary and kept
`~/.config/openmail/config.toml`. Refuse-root verified by running install/upgrade/uninstall as root in a
`debian:bookworm-slim` container (each exits 1 with "refusing to run as root"). `scripts/tests/installer_fixture.sh` passes.

**shellcheck** (user-local, already installed): `install.sh`, `upgrade.sh`, `uninstall.sh`, `checksums.sh` clean.
Two info-level notes (SC2015, SC1091) remain in `scripts/perf.sh`, which this task does not own.

**Reproducibility**: two release builds of the same source at the same path in clean target dirs with
`--locked`, `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)` and
`RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo"` produced identical
`openmail-mcp` SHA-256 `4c87e26cceb5dca1626c7f6e684ede431babeb809baee653d9639bddefebd692` (same machine and
toolchain only; not cross-machine). The `.tar.gz` is **not** reproducible: two packagings of the same binary gave
different archive hashes (tar/gzip embed mtimes); `release.yml` (not owned here) would need `tar --sort=name
--mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0 --numeric-owner` and `gzip -n`. Also `release.yml` builds with
unpinned `stable` and does not set the remap flags, so CI release binaries are not covered by this result.

**Not tested**: `install.ps1` (no `pwsh` here; its edit is unexecuted), macOS/aarch64/Windows targets, the real
GitHub release flow, signatures (SHA-256 only, sums from the same origin), Docker image publish.
