# Wave 3 rules — security hardening on the `integration` branch (tree: /home/hanzla/development/openmail)
Read docs/SECURITY_REVIEW.md first (independent review findings F1-F6), then docs/ARCHITECTURE.md and the code you own. Rust 1.100, edition 2024.
- You share this tree with 2 other agents + an E2E agent. Edit ONLY your Owns paths. Never `git add -A/.`, `git stash/checkout/reset/clean/rebase`. Commit only your paths: `git add <paths> && git commit -m "<msg>" -- <paths>` (retry on index.lock). Small frequent commits.
- Do not edit workspace Cargo.toml. Dependencies go in your crate's Cargo.toml.
- Build: `export CARGO_TARGET_DIR=/home/hanzla/development/openmail-worktrees/targets/<id> CARGO_BUILD_JOBS=3`; always `-p <crate>`; clippy `-- -D warnings` + tests green with real assertions that FAIL without your fix (prove it: show the test failing against the old behaviour or reason precisely why it would).
- No mock production code, no println in libs, no unwrap/expect outside tests. Never push/publish. Report honestly what is not done. Last line: `WAVE3-DONE <id>`.
