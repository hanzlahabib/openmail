## What and why
<!-- One or two sentences. Link the issue. -->

## Checks
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy -p <crate> --all-targets -- -D warnings`
- [ ] `cargo test -p <crate>`
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if user-visible)
- [ ] No secrets, real hosts or mailbox content in the diff

## Security-sensitive?
- [ ] No
- [ ] Yes - completed [docs/development/security-checklist.md](../docs/development/security-checklist.md)

## Not done / not tested
<!-- Be explicit. -->
