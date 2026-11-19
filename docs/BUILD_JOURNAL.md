# Build journal

## 2026-11-19 — Foundation
- Empty directory. `rustc 1.88.0` installed; `cargo info` showed `mail-parser 1.0.1` needs 1.98 and `rusqlite 0.43` needs 1.89.
- `rustup update stable` → 1.100.0.
- First `git init -b main` failed (git 2.25 has no `-b`); used `git symbolic-ref HEAD refs/heads/main`.
- Scaffolded 7-crate workspace; `cargo test -p openmail-core` → 10 passed (config validation, MessageRef round-trip).

## 2026-11-19 — Power outage during wave 1
- Host rebooted mid-wave; all four agent sessions died. Worktrees held uncommitted work (imap 4 files, security 8, mcp 14, smtp 8).
- Recovery: WIP-snapshot commit in each worktree (nothing lost), relaunched `cld --model claude-sonnet-5-5 --continue` per pane, told agents to verify existing code then continue and to commit frequently.
- Lesson: agents must commit small and often; orchestrator snapshots before any restart.
