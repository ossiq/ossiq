# OSS IQ CLI

> Know Your Dependency Risk in Minutes, Not Weeks.

**OSS IQ** is a CLI tool that analyzes open-source dependency risk by cross-referencing version lag, CVEs, and maintainer activity to produce actionable intelligence about project dependencies.

## Quick Start

```bash
# Set your GitHub token (required)
export OSSIQ_GITHUB_TOKEN=$(gh auth token)

# Scan a project
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli scan /project
```

## Usage Examples

```bash
# Generate HTML report
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli scan -p html -o /output/report.html /project

# Export to JSON for CI/CD pipelines
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli export -f json -o /output/metrics.json /project

# Show help
docker run --rm ossiq/ossiq-cli --help
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OSSIQ_GITHUB_TOKEN` | Yes | GitHub Personal Access Token for API access |
| `OSSIQ_VERBOSE` | No | Enable verbose output (true/false) |
| `OSSIQ_PRESENTATION` | No | Output format: console, html |

## Supported Ecosystems

- **NPM** - `package.json` + `package-lock.json`
- **Python (uv)** - `pyproject.toml` + `uv.lock`
- **Python (pip)** - `pyproject.toml` + `pylock.toml` or `requirements.txt`

## Documentation

Full documentation: https://github.com/ossiq/ossiq

## License

AGPL-3.0-only
