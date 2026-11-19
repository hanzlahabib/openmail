# Architecture diagrams

Companion to [ARCHITECTURE.md](ARCHITECTURE.md). Diagrams show the **target design**; see the README for which parts
are implemented today. Marked **[available]** / **[in development]** as of this commit.

## Crate map

```mermaid
flowchart TD
  cli[openmail-cli] --> mcp[openmail-mcp<br/>in development]
  cli --> remote[openmail-remote<br/>available as library]
  cli --> briefs[openmail-briefs<br/>available as library]
  cli --> observe[openmail-observe<br/>available]
  mcp --> security[openmail-security<br/>in development]
  mcp --> core[openmail-core<br/>available]
  mcp -. generic over MailBackend .-> imap[openmail-imap<br/>in development]
  mcp --> smtp[openmail-smtp<br/>in development]
  smtp --> security
  briefs --> core
  remote --> oauth[openmail-oauth<br/>available as library]
  imap --> core
  smtp --> core
  security --> core
```

Rule: the MCP crate never touches IMAP types, only the `MailBackend` / `MailOrganizer` traits.

## Reading a message (target flow) [in development]

```mermaid
sequenceDiagram
  participant C as MCP client
  participant M as openmail-mcp
  participant S as openmail-security
  participant B as MailBackend (IMAP)
  participant X as Mail server
  C->>M: tool call (message ref)
  M->>S: authorize(account, read)
  S-->>M: allowed
  M->>B: get_message(ref, max_body_bytes)
  B->>X: SELECT + UID FETCH
  X-->>B: UIDVALIDITY + body
  alt UIDVALIDITY changed
    B-->>M: StaleReference
    M-->>C: error: stale_reference
  else ok
    B-->>M: Message (Untrusted text)
    M-->>C: truncated body marked as untrusted data
  end
```

## Sending with approval (target flow) [in development]

```mermaid
sequenceDiagram
  participant C as MCP client
  participant M as openmail-mcp
  participant S as openmail-security
  participant H as Human owner
  participant T as openmail-smtp
  C->>M: send request (idempotency key)
  M->>S: authorize(account, send)
  alt account read_only or send not granted
    S-->>M: ReadOnlyAccount / AccessDenied
    M-->>C: error
  else granted
    S->>H: request approval of exact message
    H-->>S: approve
    S-->>M: approval token
    M->>T: send(message, token, key)
    T-->>M: sent, or DeliveryUncertain (never blind-retried)
    M-->>C: result
  end
```

## Remote request through the HTTP edge [available as library, not linked into CLI]

```mermaid
sequenceDiagram
  participant R as Remote client
  participant E as openmail-remote edge
  participant A as Authenticator (JWT or static bearer)
  participant H as MCP handler
  R->>E: POST /mcp
  E->>E: Origin check, rate limit, body and time limits
  E->>A: validate bearer token
  alt invalid
    A-->>E: AuthError
    E-->>R: 401 + WWW-Authenticate (RFC 9728 metadata URL)
  else valid
    A-->>E: Principal
    E->>H: request (inbound token not forwarded)
    H-->>R: response
  end
```
