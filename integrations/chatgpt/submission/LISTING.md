# ChatGPT listing draft: OpenMail

Status: DRAFT. Not submitted. Fields mirror what OpenAI asks for custom MCP apps; re-check
against the current submission form before using (the form changes).

| Field | Value |
|---|---|
| Name | OpenMail |
| Tagline | Read, search and brief your own mailbox from ChatGPT. Self-hosted, read-only. |
| MCP server URL | `https://mail-mcp.example.com/mcp` (reference deployment; every user hosts their own) |
| Auth | OAuth 2.1 (built-in single-owner authorization server), PKCE S256, dynamic client registration |
| Scopes | `mail:read` only |
| Source / license | https://github.com/hanzlahabib/openmail, MIT |
| Privacy policy | https://github.com/hanzlahabib/openmail/blob/main/PRIVACY.md |
| Support | https://github.com/hanzlahabib/openmail/issues |
| Category | Productivity / Email |

## Description
OpenMail connects ChatGPT to a mailbox you control over standard IMAP. It can list folders, search and read
messages, show threads and attachments metadata, and produce a heuristic daily brief (what needs attention,
mail awaiting a reply). It is read-only in this deployment: it cannot send, delete, move or draft. Mail text
is returned as untrusted data. You run the server yourself; nothing goes to the OpenMail authors.

## Tools exposed with `mail:read` (all `readOnlyHint: true`)
`mail_list_accounts`, `mail_test_connection`, `mail_list_folders`, `mail_get_folder_status`, `mail_list_messages`,
`mail_search_messages`, `mail_get_message`, `mail_get_headers`, `mail_get_thread`, `mail_list_attachments`,
`mail_get_attachment`, `brief_generate`, `brief_get_latest`, `brief_list_action_items`, `brief_get_followups`,
`brief_get_status`. Write tools (organize, draft, send) are not advertised unless the operator grants those
permissions per account; keep them off for ChatGPT.

## Example prompts
- "What needs my attention in my inbox from the last 24 hours?"
- "Find the latest invoice from Acme and summarize it."
- "Which emails I sent this week are still waiting for a reply?"

## Fit for the public directory
OpenMail is a self-hosted, single-owner server: each person runs their own and signs in with their own
password. A shared multi-tenant listing does not match that model, so the supported distribution is a
**custom connector** (developer mode) pointing at your own server. A directory listing would need a hosted
multi-user service with per-user mailboxes and a data-processing agreement, which does not exist.
