# syntax=docker/dockerfile:1
# QA smoke-test image — mounts ossiq source at /app and runs it via uv.
# Build: docker build -f qa/Dockerfile -t ossiq-qa .
FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git jq ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
      https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# uv — copy binary from official image; lands in /usr/local/bin (world-accessible)
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /usr/local/bin/

# Non-root user
RUN useradd -m -u 1000 qarunner

# Create runtime mount-point directories with correct ownership before dropping privileges
RUN mkdir -p /workspace /cache /qa_logs && chown qarunner:qarunner /workspace /cache /qa_logs

USER qarunner

# Redirect uv venv out of /app so a read-only bind mount still works.
# OSSIQ_SKIP_FRONTEND_BUILD skips the hatch build hook's npm steps — spa_app.html
# is already committed to the source tree so rebuilding it here is unnecessary.
ENV UV_PROJECT_ENVIRONMENT=/home/qarunner/.venv \
    PYTHONUNBUFFERED=1 \
    OSSIQ_SKIP_FRONTEND_BUILD=1

WORKDIR /app

# Pre-build the venv while /app is writable (the read-only bind mount replaces it at runtime).
# uv sync installs Python deps and runs the hatch editable build hook, which does
# `npm install + npm run build` in frontend/. Those writes can't happen on the read-only
# bind mount, so we do them here once during image build instead.
COPY --chown=qarunner:qarunner . /app
RUN uv sync

# Mount points (populated at runtime):
#   /app       — ossiq source, read-only bind mount (overlays the COPY above)
#   /workspace — manifest workspaces, named volume
#   /cache     — ossiq HTTP cache SQLite, named volume
#   /qa_logs   — output logs, bind mount to host ./qa_logs
