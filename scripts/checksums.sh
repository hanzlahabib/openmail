#!/usr/bin/env bash
# Write a SHA-256SUMS file covering every release artifact in a directory.
# Usage: scripts/checksums.sh <dir> [output-name]   (default output: SHA-256SUMS)
set -euo pipefail

dir="${1:?usage: checksums.sh <dir> [output-name]}"
out="${2:-SHA-256SUMS}"

if [[ ! -d "$dir" ]]; then
  echo "checksums.sh: not a directory: $dir" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd=(shasum -a 256)
else
  echo "checksums.sh: need sha256sum or shasum" >&2
  exit 1
fi

cd "$dir"
rm -f -- "$out"

# Plain-file listing, sorted for a reproducible SUMS file; never hash the SUMS file itself.
mapfile -t files < <(find . -maxdepth 1 -type f ! -name "$out" -printf '%P\n' | LC_ALL=C sort)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "checksums.sh: no files to hash in $dir" >&2
  exit 1
fi

"${hash_cmd[@]}" -- "${files[@]}" > "$out"
echo "wrote $dir/$out (${#files[@]} files)"
