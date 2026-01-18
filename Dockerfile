# syntax=docker/dockerfile:1

# =============================================================================
# OSS IQ CLI - Docker Image
# =============================================================================
# Single-stage build installing ossiq from PyPI
# Base: python:3.14-slim-bookworm (~50MB compressed)
#
# Usage:
#   docker build -t ossiq/ossiq-cli .
#   docker run --rm -e OSSIQ_GITHUB_TOKEN=$OSSIQ_GITHUB_TOKEN \
#     -v /path/to/project:/project:ro ossiq/ossiq-cli scan /project
# =============================================================================

FROM python:3.14-slim-bookworm

# Labels for container metadata (OCI standard)
LABEL org.opencontainers.image.title="OSS IQ CLI" \
      org.opencontainers.image.description="Analyze open-source dependency risk by cross-referencing version lag, CVEs, and maintainer activity" \
      org.opencontainers.image.vendor="OSS IQ" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/ossiq/ossiq" \
      org.opencontainers.image.documentation="https://github.com/ossiq/ossiq#readme"

# Copy uv binary from official image (pinned version for reproducibility)
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /bin/

# Create non-root user for security
RUN groupadd --gid 1000 ossiq \
    && useradd --uid 1000 --gid ossiq --shell /bin/bash --create-home ossiq

WORKDIR /app

# Set uv environment variables for optimal builds
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python3.14

# Install ossiq from PyPI with pinned version
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python ossiq==0.1.3

# Copy entrypoint script
COPY --chown=ossiq:ossiq docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    # Ensure Python output is not buffered (important for Docker logs)
    PYTHONUNBUFFERED=1 \
    # Disable Python bytecode generation at runtime
    PYTHONDONTWRITEBYTECODE=1

# Set ownership of the virtual environment to ossiq user
RUN chown -R ossiq:ossiq /app/.venv

# Switch to non-root user
USER ossiq

# Default working directory for project analysis
WORKDIR /project

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
