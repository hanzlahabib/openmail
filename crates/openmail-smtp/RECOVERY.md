# Recovering from uncertain deliveries

## What "uncertain" means
Every send has an idempotency key and a row in the outbox (SQLite):
`Pending -> Accepted | Rejected | Uncertain`.

A send becomes **Uncertain** (`ErrorCode::DeliveryUncertain`) when the DATA phase had begun and we never
received the server's final verdict: timeout, dropped connection, or the process died (power loss, kill -9).
The server may or may not have queued the message. OpenMail therefore **never re-sends** a key that is
`Uncertain` or `Accepted`; retrying the same key returns `DeliveryUncertain` (or `AlreadyAccepted`).

`Rejected` is different: the server definitively refused, or we failed before DATA. The same key can be retried.

On startup, `SqliteOutbox::open` converts any row left `Pending` with the DATA marker set into `Uncertain`
(the marker is written durably, `synchronous=FULL`, before the DATA command is sent).

## Operator procedure
1. Identify the attempt: the error / audit trail carries the idempotency key, account and `Message-ID`
   (`SmtpClient::outbox().audit_entries(account, n)`; rows with outcome `uncertain`).
2. Establish what happened, in this order of reliability:
   - the account's **Sent** folder (IMAP) — search by the `Message-ID` header (note: many providers file it there only
     if the client appended it; check the provider's web UI "Sent" too);
   - the recipient or a test recipient (Bcc to yourself on important mail);
   - the SMTP provider's delivery log.
3. Record the verdict:
   - delivered → `client.resolve_uncertain(account, key, Outcome::Delivered, "found in Sent")`
     — state becomes `Accepted`; the key will never send again.
   - not delivered → `client.resolve_uncertain(account, key, Outcome::NotDelivered, "not in Sent or logs")`
     — state becomes `Rejected`; the same key (with identical content) may now be sent again. A new
     idempotency key is equally valid and avoids reusing the old Message-ID.
4. If you cannot determine the outcome, prefer to treat it as delivered for time-critical mail that is
   unsafe to duplicate (payments, invitations) and as not delivered for mail where a duplicate is harmless.

`resolve_uncertain` only works on `Uncertain` records and appends an audit row
(`operator_resolved_delivered` / `operator_resolved_not_delivered`) with your note.

## What is recorded
Audit rows hold: timestamp, account, idempotency key, Message-ID, recipient count, attempt number, outcome,
the caller's approval token and an optional detail. Never subject, body, attachment data or addresses.
