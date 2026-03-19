# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM oven/bun:1 AS builder

WORKDIR /app

# Copy workspace root files
COPY package.json bun.lock tsconfig.json ./
COPY packages/cli/package.json packages/cli/

# Install dependencies
RUN bun install --frozen-lockfile

# Copy source
COPY packages/cli/src packages/cli/src
COPY packages/cli/tsconfig.json packages/cli/

# Build standalone binary
RUN cd packages/cli && bun build src/index.ts --compile --outfile /app/vs-mcpaudit

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM oven/bun:1-slim

# Install Node.js + npm for spawning MCP servers via npx
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scan

# Copy compiled binary
COPY --from=builder /app/vs-mcpaudit /usr/local/bin/vs-mcpaudit

# Pre-accept legal notice for non-interactive container use
ENV AGENTAUDIT_ACCEPT=true

ENTRYPOINT ["vs-mcpaudit"]
CMD ["--help"]
