# syntax=docker/dockerfile:1
# Smoke-matrix image: Node 22, Python 3.12, uv, and ossiq from this checkout.
# The image is the sandbox: smoke_matrix.py starts one throwaway container per step, so npm
# installs, `uv sync` and sdist builds never run on the host.
# Build: just qa-build  (docker build -f qa/Dockerfile -t ossiq-qa .)
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /usr/local/bin/

# ossiq from uv.lock into its own venv. Only the binary is linked into /opt/ossiq-bin, which goes
# on PATH: the venv's python must never shadow the python of the project under test.
COPY pyproject.toml uv.lock README.md LICENSE hatch_build.py /opt/ossiq-src/
COPY src /opt/ossiq-src/src
RUN cd /opt/ossiq-src \
    && UV_PROJECT_ENVIRONMENT=/opt/ossiq uv sync --frozen --no-dev --no-editable \
    && mkdir /opt/ossiq-bin && ln -s /opt/ossiq/bin/ossiq /opt/ossiq-bin/ossiq
ENV PATH="/opt/ossiq-bin:${PATH}"

RUN useradd -m -u 1000 qarunner \
    && mkdir -p /work /cache && chown qarunner:qarunner /work /cache
USER qarunner
WORKDIR /work
