# Stage 1: Build the static-linked Rust binary in release mode
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /usr/src/zatency-shield

# Install OpenSSL/TLS build dependencies for reqwest
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies before copying source code
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy actual source and build the final release binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Minimal, hardened runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1001 -g root zatency

WORKDIR /app
COPY --from=builder /usr/src/zatency-shield/target/release/zatency-shield /usr/local/bin/zatency-shield

USER 1001
EXPOSE 8080

ENV RUST_LOG=info
ENV UPSTREAM_BASE_URL=https://openai.com

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["zatency-shield"]
