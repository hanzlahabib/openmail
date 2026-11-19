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

Expected release assets: `openmail-mcp-<target>.tar.gz` (targets: `x86_64`/`aarch64` ×
`unknown-linux-gnu` / `apple-darwin`; the archive contains the `openmail-mcp` binary) and
`SHA-256SUMS` as produced by `scripts/checksums.sh`.

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

Asset: `openmail-mcp-<x86_64|aarch64>-pc-windows-msvc.zip`.

## Verification status

- `scripts/*.sh` pass `shellcheck`.
- `scripts/tests/installer_fixture.sh` (local `file://` fixture, no network) covers install, upgrade,
  rollback, tampered-archive rejection (binary left untouched) and config-preserving uninstall.
- **Not done:** `install.ps1` has not been executed or linted (no PowerShell available here); no
  signature verification beyond SHA-256 (sums come from the same release origin); no automatic PATH edit.
