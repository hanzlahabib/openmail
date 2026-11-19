# License audit

**Scope: results are valid only for the current `Cargo.lock` (287 third-party crates plus 10 workspace crates, all features, all targets).** Re-run `scripts/license-audit.sh` after any dependency change; `--check` fails if `THIRD_PARTY_LICENSES.md` is stale.

## Conclusion

OpenMail MCP is MIT-licensed (`LICENSE`, workspace `license = "MIT"`). **Every dependency in the current lockfile is compatible with distributing OpenMail under MIT.** No GPL, AGPL, or unknown-license crate was found, and no LGPL crate is *required*.

This is an engineering assessment from SPDX metadata, not legal advice. Crate-declared license fields were not independently checked against the shipped license texts (cargo-deny's `confidence-threshold = 0.9` text check covers the allow-list run only).

## Method

1. `cargo metadata --locked` over the lockfile; every non-workspace package's SPDX `license` field is read. `scripts/license-audit.sh` evaluates each expression (`OR` = any branch, `AND` = all branches, `WITH` exceptions ignored) and fails when no non-copyleft choice exists or the field is empty.
2. `cargo deny --locked check licenses` against the allow-list in `deny.toml` (passes: `licenses ok`).
3. `cargo-license` was not installed; the metadata query gives the same data, so it was not needed.
4. Toolchain note: the pinned `1.100` toolchain was mid-reinstall during the run, so the audit ran with the `stable` toolchain (also 1.100.0) through `OPENMAIL_CARGO_TOOLCHAIN=stable`. The lockfile and results do not depend on this.

## Results

| License expression (as declared) | Crates |
|---|---|
| MIT OR Apache-2.0 (incl. `MIT/Apache-2.0`, reversed order) | ~194 (approximate; exact list in THIRD_PARTY_LICENSES.md) |
| MIT | 44 |
| Unicode-3.0 (incl. `(MIT OR Apache-2.0) AND Unicode-3.0`) | 19 |
| Unlicense OR MIT | 5 |
| BSD-3-Clause, ISC, Zlib, Apache-2.0, CDLA-Permissive-2.0 and their combinations | ~20 |
| Other permissive dual/multi-license choices (BSL-1.0, BSD-1-Clause, MIT-0, CC0-1.0) | ~6 |
| Copyleft, mandatory | **0** |
| Missing / unknown license field | **0** |

Full per-crate list: `THIRD_PARTY_LICENSES.md`.

### Flagged items

- **`r-efi` 6.0.0: `MIT OR Apache-2.0 OR LGPL-2.1-or-later`.** LGPL appears only as an optional third choice. We use it under MIT/Apache-2.0, so no LGPL obligation applies. It is a target-specific (UEFI) dependency reached via `getrandom`; it is in the lockfile, but we do not rely on the LGPL option. Not a blocker.
- **Combined AND-expressions** (`ISC AND (Apache-2.0 OR ISC) AND ... AND BSD-3-Clause`) and `webpki-root-certs` (`CDLA-Permissive-2.0`, CA bundle data) are all permissive. Their attribution requirements (copyright notice retention) apply when shipping binaries; `THIRD_PARTY_LICENSES.md` lists them, but the full license texts are not bundled by this audit.
- cargo-deny warns that `BSD-2-Clause` and `MPL-2.0` in `deny.toml` are currently unused. This is harmless; MPL-2.0 is file-level copyleft and, if a crate ever starts using it, is compatible with MIT distribution as long as the MPL files stay under MPL.

## Not done

- Bundling full license texts and NOTICE files in release artifacts (only the SPDX list is generated).
- Auditing non-Rust components (Docker base image, GreenMail test containers, installer scripts' downloads).
- Verifying license fields against actual repository contents.
