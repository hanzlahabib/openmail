# Security-sensitive change checklist

Complete this in the PR description when you touch authentication, OAuth/token handling, credential storage, authorization/approval policy, send paths, redaction, remote/HTTP serving, or anything that parses mailbox content.

- [ ] Default stays least-privilege (`read_only = true`; sends require approval).
- [ ] No secret, token or mailbox content in logs, errors, `Debug` output, test fixtures or docs.
- [ ] Authorization enforced in `openmail-security`, not only in tool descriptions.
- [ ] Mailbox-derived text stays `Untrusted<T>` end to end (no prompt-injection path to a privileged action).
- [ ] New network listeners bind to loopback by default and require authentication when exposed.
- [ ] Inputs bounded (sizes, counts, timeouts); no unbounded allocation from remote data.
- [ ] Errors use existing `ErrorCode`s or append a new one; no information leaks across accounts.
- [ ] Tests cover the denial path, not just the happy path.
- [ ] `scripts/audit.sh` passes; new dependencies reviewed for licence and maintenance.
- [ ] `CHANGELOG.md` notes the behaviour change.
