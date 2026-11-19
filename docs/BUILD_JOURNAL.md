# Build journal

## 2026-11-19 — Foundation
- Empty directory. `rustc 1.88.0` installed; `cargo info` showed `mail-parser 1.0.1` needs 1.98 and `rusqlite 0.43` needs 1.89.
- `rustup update stable` → 1.100.0.
- First `git init -b main` failed (git 2.25 has no `-b`); used `git symbolic-ref HEAD refs/heads/main`.
- Scaffolded 7-crate workspace; `cargo test -p openmail-core` → 10 passed (config validation, MessageRef round-trip).
