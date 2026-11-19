#!/usr/bin/env bash
# Supply-chain gate: cargo-deny (advisories, licenses, bans, sources), optional
# cargo-audit, and an optional CycloneDX SBOM.
# Usage: scripts/audit.sh [--sbom <dir>]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

sbom_dir=""
if [[ "${1:-}" == "--sbom" ]]; then
  sbom_dir="${2:?usage: audit.sh [--sbom <dir>]}"
fi

if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "audit.sh: cargo-deny not found (cargo install cargo-deny --locked)" >&2
  exit 1
fi

echo "== cargo deny check =="
cargo deny --locked check advisories licenses bans sources

if command -v cargo-audit >/dev/null 2>&1; then
  echo "== cargo audit =="
  cargo audit --deny warnings
else
  echo "audit.sh: cargo-audit not installed; skipping (cargo-deny already checks RustSec)" >&2
fi

if [[ -n "$sbom_dir" ]]; then
  if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "audit.sh: cargo-cyclonedx not found (cargo install cargo-cyclonedx --locked)" >&2
    exit 1
  fi
  mkdir -p "$sbom_dir"
  echo "== SBOM -> $sbom_dir =="
  cargo cyclonedx --format json --override-filename sbom
  # cargo-cyclonedx writes next to each crate manifest; collect them.
  find crates -name 'sbom.json' -print0 | while IFS= read -r -d '' f; do
    crate="$(basename "$(dirname "$f")")"
    mv "$f" "$sbom_dir/${crate}.cdx.json"
  done
fi
