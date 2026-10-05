# OSS IQ CLI

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Make better dependency decisions — before and after installation.

**OSS IQ** checks every package your project depends on: version drift, CVEs, maintenance health,
and what an update would pull in transitively. It then recommends what to add, what to update,
and what to replace. Free and open source.

This image runs the `ossiq` CLI. A container has no system keyring, so `ossiq auth login` can't
store a GitHub login here: pass a GitHub token in `OSSIQ_GITHUB_TOKEN` instead.

## Quick Start

```bash
# Pass a GitHub token: 5,000 API requests an hour instead of 60
export OSSIQ_GITHUB_TOKEN=$(gh auth token)

# Show dependency status
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status /project
```

## Usage Examples

```bash
# Generate an interactive HTML report
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli html -o /output/report.html /project

# Show all packages, including up-to-date ones
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status --full /project

# Narrow to CVE-affected packages only
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status --update-strategy security /project

# Export metrics to JSON for CI/CD pipelines
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli export -o /output/metrics.json /project

# Show help
docker run --rm ossiq/ossiq-cli --help
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OSSIQ_GITHUB_TOKEN` | For `export`; recommended for every command | GitHub token. Without one, GitHub allows 60 API requests an hour |
| `OSSIQ_CUTOFF_DATE` | No | Treat versions after this date as invisible (`YYYY-MM-DD`). Enables time-travel QA. |
| `OSSIQ_COOLDOWN_PERIOD` | No | Versions younger than N days receive a freshness penalty (default: `7`) |
| `OSSIQ_VERBOSE` | No | Enable verbose output (`true`/`false`) |

## Image Tags

| Tag | Description |
|-----|-------------|
| `ossiq/ossiq-cli:latest` | Latest stable release |
| `ossiq/ossiq-cli:0.1.10` | Specific version |
| `ossiq/ossiq-cli:0.1` | Latest patch in minor version |

## CI/CD Integration (GitHub Actions)

```yaml
jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Analyze dependencies
        run: |
          docker run --rm \
            -e OSSIQ_GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }} \
            -v ${{ github.workspace }}:/project:ro \
            ossiq/ossiq-cli status /project
```

## Dependency Update Plan

`plan` shows what the solver recommends without touching any files. `apply` executes those changes with automatic rollback on failure.

```bash
# Preview recommended updates (read-only)
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli plan /project

# Apply updates non-interactively (for CI)
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project \
  ossiq/ossiq-cli apply --yes /project
```

Mount the project directory **without** `:ro` for `apply`, because it writes to your files.

## Supported Ecosystems

| Ecosystem | Files |
|-----------|-------|
| NPM | `package.json` + `package-lock.json` |
| Python (uv) | `pyproject.toml` + `uv.lock` |
| Python (pip lock) | `pyproject.toml` + `pylock.toml` |
| Python (pip classic) | `requirements.txt` |

## Data Sources

OSS IQ aggregates data from [OSV](https://osv.dev/), [npm Registry](https://www.npmjs.com/), [PyPI](https://pypi.org/), and [GitHub](https://github.com/) to cross-reference vulnerabilities, version history, and maintainer activity.

## Documentation

- Documentation: <https://ossiq.dev>
- Source code: <https://github.com/ossiq/ossiq>

## License

AGPL-3.0-only
