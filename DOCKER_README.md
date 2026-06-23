# OSS IQ CLI

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Quantify Maintenance Health. Control Your Drift.

**OSS IQ** is a free & open-source CLI tool that analyzes dependency drift at scale. Track version lag and transitive risk directly from your dependency files. It helps to move from reactive CVE-chasing to a planned, predictable maintenance rhythm.

In a typical project with hundreds of dependencies, OSS IQ answers:
- How many dependencies have critical vulnerabilities?
- How far behind the latest versions are we?
- Which packages are unmaintained or abandoned?
- Which newer versions of dependencies would work best for my project?

## Quick Start

```bash
# Set your GitHub token (required for deep analysis)
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
  ossiq/ossiq-cli status -p html -o /output/report.html /project

# Show all packages, including up-to-date ones
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status --full /project

# Narrow to CVE-affected packages only
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status --security /project

# Export metrics to JSON for CI/CD pipelines
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli export -f json -o /output/metrics.json /project

# Show help
docker run --rm ossiq/ossiq-cli --help
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OSSIQ_GITHUB_TOKEN` | Yes | GitHub Personal Access Token for API access |
| `OSSIQ_CUTOFF_DATE` | No | Treat versions after this date as invisible (`YYYY-MM-DD`). Enables time-travel QA. |
| `OSSIQ_COOLDOWN_PERIOD` | No | Versions younger than N days receive a freshness penalty (default: `7`) |
| `OSSIQ_VERBOSE` | No | Enable verbose output (`true`/`false`) |

## Image Tags

| Tag | Description |
|-----|-------------|
| `ossiq/ossiq-cli:latest` | Latest stable release |
| `ossiq/ossiq-cli:0.1.19` | Specific version |
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
  -v /path/to/your/project:/project \
  ossiq/ossiq-cli plan /project

# Apply updates non-interactively (for CI)
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project \
  ossiq/ossiq-cli apply --yes /project
```

Note: mount the project directory **without** `:ro` when running `apply` or `plan --script`, since those commands write to your files.

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

Full documentation and source code: https://github.com/ossiq/ossiq

## License

AGPL-3.0-only
