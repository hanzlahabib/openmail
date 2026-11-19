# syntax=docker/dockerfile:1
ARG RUST_VERSION=1.100

FROM rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p openmail-cli --bin openmail-mcp \
 && install -D target/release/openmail-mcp /out/openmail-mcp

FROM debian:bookworm-slim AS runtime
# uid 10001: fixed, high, unprivileged, no login shell; config is mounted read-only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 openmail \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin openmail
COPY --from=build /out/openmail-mcp /usr/local/bin/openmail-mcp
USER 10001:10001
ENV OPENMAIL_CONFIG=/config/config.toml
# Default transport is stdio: run with `docker run -i` and let the MCP client speak over stdin/stdout.
# The http transport refuses to start without TLS + a bearer token file (OPENMAIL_HTTP_TLS_CERT,
# OPENMAIL_HTTP_TLS_KEY, OPENMAIL_HTTP_AUTH_TOKEN_FILE) and its backend is not wired end to end yet,
# so no port is exposed and there is no TCP healthcheck: a stdio process has no listener to probe.
HEALTHCHECK NONE
ENTRYPOINT ["openmail-mcp"]
CMD ["serve"]
