# syntax=docker/dockerfile:1
# GH-174 agent image: Node 22, Python 3.12, uv, and the claude CLI, plus ossiq from this checkout.
# The image itself is the sandbox: run.py starts one throwaway container per run, and eval.py locks
# each manifest in one.
# Build: just exp-build
FROM python:3.12-slim-bookworm

# Pinned so every run in a batch drives the same CLI; run.py records the version in batch.json.
ARG CLAUDE_CODE_VERSION=2.1.308

RUN apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /usr/local/bin/

RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
    && npm cache clean --force

# ossiq from uv.lock into its own venv. Only the binary is linked into /opt/ossiq-bin, and run.py
# puts that on PATH in the ossiq arm alone: the venv's python must never shadow the project's.
COPY pyproject.toml uv.lock README.md LICENSE hatch_build.py /opt/ossiq-src/
COPY src /opt/ossiq-src/src
RUN cd /opt/ossiq-src \
    && UV_PROJECT_ENVIRONMENT=/opt/ossiq uv sync --frozen --no-dev --no-editable \
    && mkdir /opt/ossiq-bin && ln -s /opt/ossiq/bin/ossiq /opt/ossiq-bin/ossiq

# Claude Code refuses --dangerously-skip-permissions as root.
RUN useradd -m -u 1000 runner
USER runner
WORKDIR /work
