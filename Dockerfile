# ABOUTME: Multi-stage Docker build for the dionaea v2 Rust honeypot.
# ABOUTME: Builds the Rust binary with PyO3 and packages it with Python protocol modules.

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder

RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        libssl-dev \
        pkg-config \
        python3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cargo dependency caching: copy manifests first, build with dummy sources,
# then copy real sources. This way dependency layers are cached across rebuilds.
COPY Cargo.toml Cargo.lock ./
COPY crates/dionaea/Cargo.toml crates/dionaea/Cargo.toml
COPY crates/shell-detect/Cargo.toml crates/shell-detect/Cargo.toml

RUN mkdir -p crates/dionaea/src crates/shell-detect/src && \
    echo 'fn main() {}' > crates/dionaea/src/main.rs && \
    echo '' > crates/dionaea/src/lib.rs && \
    echo '' > crates/shell-detect/src/lib.rs && \
    cargo build --release 2>&1 || true && \
    rm -rf crates/*/src

# Copy real source and build
COPY crates/ crates/
RUN cargo build --release


# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

RUN apt-get update && \
    apt-get -qq install -y --no-install-recommends \
        libssl3 \
        libcap2-bin \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r dionaea && \
    useradd -r -d /opt/dionaea -g dionaea dionaea

WORKDIR /opt/dionaea

# Copy binary
COPY --from=builder /build/target/release/dionaea bin/dionaea

# Copy config and Python protocol modules
COPY conf/ conf/
COPY modules/python/dionaea/ modules/python/dionaea/

# Create data directories
RUN mkdir -p \
        var/dionaea/bistreams \
        var/dionaea/downloads \
        var/dionaea/shellcode \
        var/log/dionaea && \
    chown -R dionaea:dionaea var/

# Copy entrypoint
COPY docker/entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh

# Allow binding privileged ports without running as root
RUN setcap cap_net_bind_service=+ep bin/dionaea

ENV DIONAEA_DIONAEA__USER=dionaea \
    DIONAEA_DIONAEA__GROUP=dionaea

ENTRYPOINT ["/opt/dionaea/entrypoint.sh"]
