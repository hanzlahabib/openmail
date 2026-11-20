# Who approves sending mail

Sending is the one action an agent must not be able to talk itself into. **You, the server owner, choose how much
is delegated, in server configuration only.** No MCP tool can read or change this setting.

Set `OPENMAIL_SEND_APPROVAL` in the service environment (`/etc/openmail/env`) and restart:

| Mode | Behaviour | Use when |
|---|---|---|
| `owner_only` (default) | Every send needs a single-use approval that **you** grant on the server (`openmail-mcp approvals grant <request-id>`). | Normal use. |
| `rules` | You pre-authorize narrow standing rules ("allow always"); a send that matches a live rule proceeds, anything else still needs you. | Repeated sends to known recipients. |
| `delegated` | The connected client's own confirmation (ChatGPT's "allow this action") is the gate. OpenMail only enforces a daily cap per account (`OPENMAIL_SEND_DELEGATED_DAILY_LIMIT`, default 25). | You accept that a compromised or tricked client can send, up to the cap. |

A human-granted token works in every mode. Every automatic decision is logged and counted.

## The "ask, then allow once / allow always" flow

1. The agent calls `mail_send_approved`. Without approval nothing is sent and the error carries a `request_id`,
   the requester and the exact recipients and subject.
2. **Allow once:** on the server run `openmail-ctl approvals list`, then `openmail-ctl approvals grant <request-id>`
   (you type the id back). Give the printed single-use token to the agent; it works for exactly that message, once, for
   5 minutes. **Deny:** `approvals deny <request-id>`.
3. **Allow always** (mode `rules`): create a narrow rule instead of approving each send:
   ```sh
   openmail-ctl approvals rules add --account sales --to @example.com --per-day 20 --days 30 --note "outreach"
   openmail-ctl approvals rules list
   openmail-ctl approvals rules revoke 3
   ```
   A rule is for ONE account and ONE address or `@domain` (never "everyone"), at most 500/day, at most 90 days,
   at most 10 recipients per message. Rules only take effect in `rules` mode.
4. `openmail-ctl approvals mode` prints the active mode.

## Bulk / cold outreach

Even with rules or delegation, send from a warmed, authenticated domain, keep volume low, honour opt-outs, and
remember a shared server IP carries the reputation of every site that sends from it. OpenMail does not provide
campaign management, unsubscribe handling or bounce processing.

Not built yet: an in-browser approval page. Approvals are granted on the server.
