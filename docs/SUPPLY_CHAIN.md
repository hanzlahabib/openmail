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

## Keyring backends (Linux behaviour and prerequisites)

`keyring` 4's `v1` API hard-wires the zbus Secret Service store, which pulled the
unmaintained `zvariant`, `zbus_names` and `zvariant_derive` crates
(RUSTSEC-2026-0370/0371/0372). `openmail-security` therefore depends on `keyring-core` 1
and per-platform store crates directly (`crates/openmail-security/src/secret.rs`);
`keyring` itself is no longer a dependency of any crate.

| Platform | Store | Notes |
|---|---|---|
| Linux | `dbus-secret-service-keyring-store` (libdbus, `vendored` build, `crypto-rust`) tried first, then `linux-keyutils-keyring-store` | Secret Service needs a running session bus plus GNOME Keyring/KWallet; entries persist. Without one (headless/CI), the kernel keyutils keyring is used: it needs no daemon, but entries live in the kernel keyring and are **not persisted across reboots**. A build host needs a C compiler (libdbus is built from source). |
| macOS | `apple-native-keyring-store` (`keychain`) | cfg-gated, compiles only on macOS. **Not built or tested here.** |
| Windows | `windows-native-keyring-store` | cfg-gated, compiles only on Windows. **Not built or tested here.** |

A store that is reachable but lacks the entry is authoritative (`NoEntry`); the fallback is only
used when the first store is unavailable. `kind = "env"` credential refs never consult the keyring
(test `env_refs_never_touch_the_keyring`). Residual: `cargo tree -i zvariant` now matches nothing.

## Accepted advisories

| Advisory | Crate | Why accepted | Review by |
|---|---|---|---|
| RUSTSEC-2026-0441 | pin-utils 0.1.1 (unmaintained, repo archived 2026-10-01) | Only reachable via async-imap 0.12.0, the latest release; no safe upgrade exists. Tiny macro crate, no vulnerability or soundness advisory. | 2027-02-20 |

Not ignored, owned elsewhere (`openmail-briefs`, handled by the orchestrator): RUSTSEC-2026-0543
(chrono) and RUSTSEC-2026-0555 (chrono-tz). These still fail `cargo deny check advisories`.

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

## Recorded run — 2026-11-20 (T43, cargo-deny 0.20.2, working-tree lockfile)

```text
$ cargo deny check
error[unmaintained]: chrono is unmaintained          (RUSTSEC-2026-0543)  -> openmail-briefs, async-imap, rmcp, schemars
error[unmaintained]: chrono-tz is unmaintained       (RUSTSEC-2026-0555)  -> openmail-briefs
advisories FAILED, bans ok, licenses ok, sources ok
```

Cleared by T43: RUSTSEC-2026-0370/0371/0372 (zvariant, zbus_names, zvariant_derive; zbus stack
removed) and RUSTSEC-2026-0441 (pin-utils; justified ignore above). Remaining failures are the two
chrono advisories, left to the orchestrator because `openmail-briefs` owns them. Bans/licenses/sources
are ok; duplicate-version and wildcard warnings are unchanged in kind (the zbus removal did not add
new ones). `cargo audit` is not installed; cargo-deny reads the same RustSec database.
`cargo test -p openmail-security` (39 + integration) and `clippy -D warnings` pass.
Not verifiable here: macOS Keychain and Windows Credential Manager builds.
Note: the workspace `Cargo.toml` still declares `keyring = "4"`, which cargo now flags as an unused
workspace dependency (warning); removing it needs a workspace manifest change (not owned by T43).

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
