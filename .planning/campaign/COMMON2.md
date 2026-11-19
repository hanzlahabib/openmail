# OpenMail MCP — wave 2 rules (30 agents share ONE worktree: /home/USER/development/openmail-worktrees/wave2, branch wave2)
Read docs/ARCHITECTURE.md and crates/openmail-core/src/*.rs (frozen contracts). Rust 1.100, edition 2024. Open-source product: no real secrets, no real hosts, fake creds only.
TIME BOX: ~20 minutes. Ship the smallest REAL, tested slice of your task, commit it, and say honestly what is not done. A working subset beats a broad stub.

SHARED-TREE RULES (violations break other agents)
- Edit ONLY the files listed under "Owns" in your task. Never touch other files, never run `git add -A`, `git add .`, `git stash`, `git checkout`, `git reset`, `git clean`, `git rebase`.
- Commit only your own paths: `git add <your paths> && git commit -m "<msg>" -- <your paths>` ; if you hit index.lock, wait 2s and retry. Commit early and often (a power cut already happened once). No AI attribution in messages.
- Do NOT edit workspace Cargo.toml. Put dependencies with explicit versions in YOUR crate's Cargo.toml (check `cargo info <crate>` for version/license/MSRV; avoid unmaintained crates). Do not edit openmail-core, imap, smtp, security, mcp crates (other agents own them).
- Build with your own target dir and limited jobs: `export CARGO_TARGET_DIR=/home/USER/development/openmail-worktrees/targets/<your-task-id> CARGO_BUILD_JOBS=3`, and always `cargo <cmd> -p <your-crate>` (never --workspace). If another agent's crate breaks the build of your crate's deps, report it, do not fix it.
- Never push, publish, or create remotes. No println! in library code (tracing). No unwrap/expect outside tests. No mock/placeholder production code; fakes only in #[cfg(test)]/tests.
- Done = fmt + `cargo clippy -p <crate> --all-targets -- -D warnings` + `cargo test -p <crate>` green with real assertions (for non-Rust tasks: you ran the validators named in your task). Write facts into the file your task names; list what is NOT done. Last line printed: `WAVE2-DONE <task-id>`.
