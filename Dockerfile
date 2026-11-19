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
EXPOSE 8765
# bash /dev/tcp avoids shipping curl; a successful TCP connect to the HTTP port.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8765"]
ENTRYPOINT ["openmail-mcp"]
CMD ["serve", "--transport", "http", "--bind", "0.0.0.0:8765"]
