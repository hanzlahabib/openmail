# Privacy

OpenMail MCP is software you run yourself. The authors operate no service, receive no data and collect no
telemetry. This document describes what the software does so that you, as the operator, can write your own
policy for anyone you let use it.

- **Your mail** stays on your mail server and your machine. The server reads it over IMAP only when a connected
  client (for example ChatGPT) calls a tool, and returns the results to that client. Whatever a tool returns is
  then processed by that client under the client's own terms (for example OpenAI's). Review what you ask it to read.
- **Credentials** are read from environment variables or the OS keyring at the moment of use and are never stored in
  the config file, logged or returned by any tool.
- **OAuth**: the built-in authorization server stores a signing key, registered client ids and hashed refresh tokens in
  the state directory (mode 0600). The owner password is stored only as an Argon2id hash.
- **Logs** go to stderr, redact secrets and never include message bodies by default.
- **Optional AI summaries** are off unless you configure a provider; the default sends metadata only and never sends
  bodies off-machine unless you explicitly allow it.
- **Retention and deletion**: delete the state directory to remove all OpenMail-held data (clients, tokens, stored briefs).

Questions: open an issue at https://github.com/hanzlahabib/openmail/issues.
