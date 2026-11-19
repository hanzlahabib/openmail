# Supply chain

Policy lives in `deny.toml`; the gate is `scripts/audit.sh`. Open-source product: no
silenced advisories without a written entry in "Accepted advisories" below.

## Run it

```bash
cargo install cargo-deny --locked        # once
scripts/audit.sh                         # advisories + licenses + bans + sources
scripts/audit.sh --sbom target/sbom      # also write CycloneDX SBOMs (needs cargo-cyclonedx)
```

`cargo-audit` is optional: `audit.sh` runs it when installed, but cargo-deny already
checks the same RustSec database (`advisories`), so it was not installed for this run.

## Policy (deny.toml)

- **advisories**: vulnerabilities, unmaintained, unsound and yanked crates fail. `ignore = []`.
- **licenses** allowlist: MIT, Apache-2.0 (+ LLVM-exception), BSD-2/3-Clause, ISC,
  Unicode-3.0, MPL-2.0.
- **bans**: duplicate versions warn; wildcard requirements warn (see "Not done").
- **sources**: crates.io only; unknown registries and all git dependencies denied.

### License additions

The first run rejected two licenses outside the base list. Both are permissive and were
added deliberately:

| License | Crate | Pulled in by |
|---|---|---|
| Zlib | foldhash 0.2.0 | hashbrown <- hashlink <- rusqlite <- openmail-briefs |
| CDLA-Permissive-2.0 | webpki-root-certs 1.0.12 | rustls-platform-verifier <- reqwest |

## Accepted advisories

None. No advisory is ignored.

## Recorded run — 2026-11-19, cargo-deny 0.20.2, RustSec db commit date 2026-11-19

**Caveat on "current lockfile".** The committed `Cargo.lock` was stale against the
in-progress wave-2 manifests (other tasks add `jsonwebtoken`, etc.), so
`cargo deny --locked` aborted with this verbatim error:

```text
error: cannot update the lock file .../Cargo.lock because --locked was passed to prevent this
`cargo metadata` exited with an error
```

The audit was therefore run on a scratch copy of the tree (so the shared `Cargo.lock`
was not modified), letting cargo extend the existing lock (adds pem, simple_asn1,
num-bigint, num-integer, …; existing pins kept). **Re-run `scripts/audit.sh` once the
lockfile is regenerated and committed; that run is the authoritative one.**

### Run 1 (first policy draft) — verbatim verdict and errors

```text
error[rejected]: failed to satisfy license requirements   (foldhash 0.2.0, license = "Zlib")
error[rejected]: failed to satisfy license requirements   (webpki-root-certs 1.0.12, license = "CDLA-Permissive-2.0")
error[wildcard]: found 2 wildcard dependencies for crate 'openmail-smtp' ... (same for imap, security, mcp, briefs; 1 each for remote, oauth, cli)
advisories ok, bans FAILED, licenses FAILED, sources ok
```

### Run 2 (current deny.toml) — verbatim diagnostics headers and verdict

```text
warning[duplicate]: found 2 duplicate entries for crate 'base64'
warning[duplicate]: found 2 duplicate entries for crate 'block-buffer'
warning[duplicate]: found 2 duplicate entries for crate 'cpufeatures'
warning[duplicate]: found 2 duplicate entries for crate 'crypto-common'
warning[duplicate]: found 2 duplicate entries for crate 'digest'
warning[wildcard]: found 2 wildcard dependencies for crate 'openmail-briefs'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 1 wildcard dependency for crate 'openmail-cli'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 2 wildcard dependencies for crate 'openmail-imap'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 2 wildcard dependencies for crate 'openmail-mcp'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 1 wildcard dependency for crate 'openmail-oauth'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 1 wildcard dependency for crate 'openmail-remote'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 2 wildcard dependencies for crate 'openmail-security'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[wildcard]: found 2 wildcard dependencies for crate 'openmail-smtp'. allow-wildcard-paths is enabled, but does not apply to public crates as crates.io disallows path dependencies.
warning[duplicate]: found 2 duplicate entries for crate 'sha2'
warning[duplicate]: found 2 duplicate entries for crate 'syn'
warning[duplicate]: found 2 duplicate entries for crate 'winnow'
warning[license-not-encountered]: license was not encountered
warning[license-not-encountered]: license was not encountered

advisories ok, bans ok, licenses ok, sources ok
```

Exit code 0. `advisories ok`: no RustSec vulnerability, unmaintained, unsound or yanked
crate in the resolved graph. Warnings are duplicate major versions (base64 0.22/0.23,
sha2/digest 0.10/0.11 via `jsonwebtoken` vs `openmail-oauth`/`openmail-remote`, syn 2/3,
winnow) and two unused license allowances (BSD-2-Clause, MPL-2.0 — kept as policy).

## SBOM

```bash
cargo install cargo-cyclonedx --locked
scripts/audit.sh --sbom target/sbom       # one <crate>.cdx.json per workspace crate
```

Attach the SBOMs and `SHA-256SUMS` (`scripts/checksums.sh`) to each release.
cargo-cyclonedx was not installed in this run, so no SBOM was generated here.

## Reproducible builds

```bash
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo"
cargo build --release --locked
sha256sum target/release/openmail*
```

- `--locked` fails the build if `Cargo.lock` is out of date; always commit the lockfile.
- `--remap-path-prefix` strips the builder's absolute paths from binaries and panic
  messages. Use the same `$PWD` (e.g. a fixed `/build` checkout) when comparing hashes.
- `SOURCE_DATE_EPOCH` pins embedded timestamps for any build script that honours it.
- Use the same compiler version (record `rustc -Vv`) and target triple; `rust-toolchain.toml` only selects stable.
- Build twice in clean checkouts and compare `sha256sum`; a mismatch is a release blocker.
  Reproducibility was **not** verified in this run (no release build performed).

## Not done / follow-ups

- Authoritative run on the regenerated lockfile (see caveat above).
- `bans.wildcards` is `warn` because workspace crates lack `publish = false`; flip to
  `deny` after adding it (workspace `Cargo.toml`, owned elsewhere).
- cargo-audit and cargo-cyclonedx not installed; SBOM and reproducibility check unexecuted.
- Duplicate-version warnings (jsonwebtoken's newer RustCrypto stack vs sha2 0.10) are
  not yet resolved.
- Environment note: concurrent `rustup` toolchain syncs (rust-toolchain.toml channel
  update) failed in this shared tree; the run used `RUSTUP_TOOLCHAIN=stable`
  (cargo 1.100.0).
