FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin ghost-scanner

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin scanner

WORKDIR /app

COPY --from=builder /app/target/release/ghost-scanner /usr/local/bin/ghost-scanner

RUN mkdir -p /app/reports \
    && chown -R scanner:scanner /app

USER scanner

ENV RUST_LOG=info
ENV SCANNER_OUTPUT_DIR=/app/reports
ENV PORT=8081

EXPOSE 8081

CMD ["sh", "-lc", "exec /usr/local/bin/ghost-scanner serve --host 0.0.0.0 --port ${PORT:-8081}"]
