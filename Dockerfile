# syntax=docker/dockerfile:1

# --- Stage 1: Builder ---
# To Test Build: docker build -t ossiq-test --build-arg TAG_VERSION=0.1.3 .
FROM python:3.13-slim-bookworm AS builder

# Install build dependencies for Rust/C extensions (Fixes "cc not found")
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /bin/

WORKDIR /app

# Argument to allow passing the tag from GitHub Actions
ARG TAG_VERSION

# Set uv environment variables for optimal builds
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python3.13

# Install ossiq into a virtual environment
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python ossiq==${TAG_VERSION}

# --- Stage 2: Final Runtime ---
# To test image: docker run --rm ossiq-test --version
FROM python:3.13-slim-bookworm

# Labels for container metadata
LABEL org.opencontainers.image.title="OSS IQ CLI" \
      org.opencontainers.image.description="Analyze open-source dependency risk" \
      org.opencontainers.image.vendor="OSS IQ" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Create non-root user
RUN groupadd --gid 1000 ossiq \
    && useradd --uid 1000 --gid ossiq --shell /bin/bash --create-home ossiq

WORKDIR /app

# Copy the pre-built virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv

# Copy entrypoint script (Make sure this file exists in your repo)
COPY --chown=ossiq:ossiq docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Ensure ownership for the non-root user
RUN chown -R ossiq:ossiq /app/.venv

USER ossiq
WORKDIR /project

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]