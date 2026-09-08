# SagaShield MCP server — multi-stage build.
#
#   docker build -t sagashield-mcp:0.3.0 .
#   docker run -i --rm -v sagashield-data:/data sagashield-mcp:0.3.0
#
# Final image target: <30 MB (distroless/cc + stripped binary).

# ---- Stage 1: builder -------------------------------------------------------
FROM rust:1.80-slim AS builder

WORKDIR /build
# Dependency layer first for better caching.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --bin sagashield-mcp \
    && strip target/release/sagashield-mcp
# Writable dirs prepared here (distroless has no shell for chown at runtime).
RUN mkdir -p /out/data

# ---- Stage 2: minimal runtime -----------------------------------------------
FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder --chown=65532:65532 \
    /build/target/release/sagashield-mcp /usr/local/bin/sagashield-mcp
# /data is pre-owned by nonroot (65532); the server creates ./workspace and
# ./sagashield-mcp.db inside it. Mount a volume to persist sagas.
COPY --from=builder --chown=65532:65532 /out/data /data

# Non-root execution: distroless ships uid 65532 (nonroot).
USER 65532:65532

# SQLite WAL lives here (mount a volume to persist sagas across restarts).
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/sagashield-mcp"]
