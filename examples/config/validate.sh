#!/usr/bin/env bash
# Validate all example configs (incl. generated 50 and 500 accounts) and client JSON.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
./gen-many.sh 50 > "$tmp/many-50.toml"
./gen-many.sh 500 > "$tmp/many-500.toml"
cargo run -q --manifest-path validator/Cargo.toml -- \
  *.toml "$tmp"/many-50.toml "$tmp"/many-500.toml $(find .. -name '*.json' -not -path '*/validator/*')
