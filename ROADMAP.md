# Roadmap

OpenMail is a v0.1.0 **pre-release**. This file says what v1.0 needs and what is deliberately not planned. Gates and their evidence live in `docs/RELEASE_READINESS.md`.

## Before v1.0 (in order)
1. **Independent security audit** of the OAuth server, approval and send-policy code, and the MCP tool surface. Internal review findings are in `docs/SECURITY_REVIEW.md`.
2. **First end-to-end release run**: the release workflow already builds, generates a CycloneDX SBOM and attests build provenance; it has not yet been exercised on a tag. Signed binaries and a verified Docker image follow.
3. **Provider coverage**: Gmail, Microsoft 365 and a stock Dovecot, plus a 50-100 mailbox load run.
4. **Audit log**: a queryable record of which client called which tool on which account, with export.
5. **Owner experience**: an in-browser approval page and an onboarding form, so the CLI is not required for day-to-day use.

## Considered, only on real demand
- Multi-owner or team deployments with OIDC/SSO and roles (today: one owner, by design).
- Admin MCP tools for account management (today: CLI only, deliberately out of band).
- Campaign and cold-email management (today: single sends under owner-chosen approval limits).

## Not planned
- Any tool that lets a model grant its own send approval, change approval mode, or register an OAuth client.
- Hosted multi-tenant service operated by the project.
