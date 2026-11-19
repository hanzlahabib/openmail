# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately; do not open a public issue.

- Contact: TODO(owner): set a security contact address or enable GitHub private vulnerability reporting once the public repository exists.
- Include: affected version/commit, a description, reproduction steps, and the impact you observed.
- Do not include real mailbox contents or credentials in a report.

## What to expect (targets, not yet a commitment until the owner confirms)

- Acknowledgement within 3 business days.
- A fix or mitigation plan within 30 days for confirmed issues, coordinated disclosure afterwards.
- Credit in the release notes unless you prefer otherwise.

## Scope

In scope: the `openmail-mcp` binary and all crates in this workspace — credential handling, authorization,
send approvals, redaction, rate limiting, MIME/attachment handling, config parsing, transport security.
Out of scope: vulnerabilities in a mail provider, in the MCP client, or in third-party dependencies
without an OpenMail-specific exploit path (report those upstream).

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Security design in brief

See `docs/THREAT_MODEL.md`. Key rules: accounts are read-only by default; sending needs a human-granted,
single-use approval bound to the exact message; secrets are never stored in config or logged; mailbox text is
untrusted data and never grants permission.
