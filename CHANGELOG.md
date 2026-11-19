# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

No release has been published yet; everything below is unreleased work in progress.

## [Unreleased]

### Added
- Cargo workspace (Rust 1.100, edition 2024) with crates: `openmail-core`, `openmail-imap`, `openmail-smtp`, `openmail-security`, `openmail-mcp`, `openmail-briefs`, `openmail-cli`, `openmail-oauth`, `openmail-remote`, `openmail-observe`. Several crates are partial; see `docs/ARCHITECTURE.md` for per-crate status.
- Core domain models, TOML config validation (accounts default to read-only), append-only error codes and `MessageRef`.
- `openmail-mcp` CLI command surface (clap): init, doctor, accounts, serve, brief.
- Provider setup pages and compatibility matrix; protocol compatibility research.
- Checksum-verified installers, upgrade with rollback, and uninstall scripts (shell and PowerShell).
- CI workflows: fmt, clippy, cross-OS tests, MSRV, cargo-deny, cargo-audit, docs; Dependabot.
- Contributor documentation, issue and pull request templates, Code of Conduct.

### Security
- Accounts are read-only by default; sends are designed to require explicit approval. Not yet independently audited.
