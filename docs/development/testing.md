# Testing

## Unit and crate tests
```bash
cargo test -p <crate>
```
Assertions must be real. Use the production field names in fixtures. Tests must not write outside temp directories.

## Disposable test mail server (Docker)
`scripts/test-infra.sh` drives `tests/infra/docker-compose.yml`, a local IMAP server seeded with fake accounts (`alice`, `bob`, `carol`; throwaway passwords).

```bash
scripts/test-infra.sh up       # start, wait for IMAP, seed
scripts/test-infra.sh status   # containers + message counts
scripts/test-infra.sh seed     # re-seed
scripts/test-infra.sh down     # stop and delete volumes
```
Overrides: `OPENMAIL_TEST_HOST` (default `127.0.0.1`), `OPENMAIL_TEST_IMAP_PORT` (default `13143`). Tests that need the server must skip cleanly when it is not reachable. Never point tests at a real mailbox.

## Other scripts
- `scripts/audit.sh` - dependency/licence/advisory checks (`deny.toml`).
- `scripts/perf.sh` - performance harness; anything it cannot measure is reported as NOT MEASURED, never estimated.
- `tests/performance/perf_smoke.sh`, `scripts/tests/installer_fixture.sh` - smoke and installer tests.
