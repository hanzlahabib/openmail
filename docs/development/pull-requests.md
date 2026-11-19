# Pull request process

1. Fork or branch from `main`; never push directly to `main`.
2. Keep the PR focused and small enough to review.
3. Before opening: `cargo fmt --all -- --check`, `cargo clippy -p <crate> --all-targets -- -D warnings`, `cargo test -p <crate>` for each touched crate.
4. Fill in the PR template honestly, including what is not done or not tested.
5. CI must pass (fmt, clippy, cross-OS tests, MSRV, deny, audit, docs).
6. At least one maintainer review; security-sensitive PRs also need the checklist in [security-checklist.md](security-checklist.md).
7. Address review feedback with new commits; maintainers may squash on merge.
