# OSS IQ

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Know Your Dependency Risk in Minutes, Not Weeks.

**OSS IQ** is a free & open-source CLI tool that provides deep visibility into the risk profile of your open-source ecosystem. It helps you move from reactive CVE-chasing to a planned, predictable maintenance rhythm by analyzing both direct and transitive dependencies to identify security vulnerabilities, version lag, and maintenance "red flags" before they reach production.

![OSS IQ HTML Report](https://ossiq.dev/img/ossiq-report-html-light.png)

## What is OSS IQ?

In a typical project with hundreds of dependencies, how do you answer these questions?
- How many dependencies have critical vulnerabilities?
- How far behind the latest versions are we?
- Which packages are unmaintained or abandoned?
- Which newer versions of dependencies would work best for my project?

`npm audit` tells you about vulnerabilities, but not which ones matter. Your framework might be years old, turning a simple upgrade into a multi-week project. Without a centralized view, you are always reacting, not planning.

OSS IQ bridges the gap between raw dependency data and actionable intelligence. It analyzes version lag, CVEs, transitive dependencies, and maintainer activity to produce a single, holistic view of your project dependencies.

## How It Works

1.  **Run OSS IQ**: Point the CLI to your project's manifest file (`package.json`, `pyproject.toml`, etc.). OSS IQ supports NPM and Python (uv, pip).
2.  **Analyze Everything**: The tool cross-references version lag, CVEs, and maintainer activity against public databases in real-time.
3.  **Get Your Report**: See a high-level health score and drill down into specific risks. The output is available as a rich console summary, an interactive HTML report, JSON export, or CSV export.
4.  **Build Quality Gates**: Use the metrics and scores to set policies and build automated quality gates in your CI/CD pipelines.

## Quick Start

### 1. GitHub Token

OSS IQ performs deep analysis by mining software repository history, which can involve hundreds of API requests to GitHub. To avoid being rate-limited, it's. best to provide a GitHub Personal Access Token (PAT).

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
```

### 2. Run OSS IQ

The fastest way is to run directly from [PyPI](https://pypi.org/) with [uvx](https://docs.astral.sh/uv/) with no install required:

```bash
# JavaScript / npm
uvx --from ossiq ossiq-cli scan /path/to/your/project

# Python / uv / pip
uvx --from ossiq ossiq-cli scan /path/to/your/project

# Generate HTML report
uvx --from ossiq ossiq-cli scan --presentation=html --output report.html /path/to/your/project
```

OSS IQ automatically detects the dependency manifest (`package.json`, `pyproject.toml`, etc.) in the target directory.

If you prefer a persistent install:

```bash
# Install with uv
uv add ossiq

# Or with pip
pip install ossiq

# Then run directly
ossiq-cli scan /path/to/your/project
```

### Using Docker

OSS IQ CLI is available as a Docker image for easy deployment without installing Python dependencies.

```bash
# Pull the latest image
docker pull ossiq/ossiq-cli

# Set your GitHub token (required)
export OSSIQ_GITHUB_TOKEN=$(gh auth token)

# Scan a local project
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli scan /project

# Generate an HTML report
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli scan -p html -o /output/report.html /project

# Export to JSON for CI/CD pipelines
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli export -f json -o /output/metrics.json /project
```

**Docker Image Tags:**
- `ossiq/ossiq-cli:latest` - Latest stable release
- `ossiq/ossiq-cli:0.1.3` - Specific version
- `ossiq/ossiq-cli:0.1` - Latest patch in minor version

**CI/CD Integration Example (GitHub Actions):**

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
            ossiq/ossiq-cli scan /project
```

### Development Mode

To contribute or run from source:

```bash
# Clone the repository
git clone https://github.com/ossiq/ossiq.git
cd ossiq

# Install dependencies
uv sync

# Run the CLI
uv run hatch run ossiq-cli scan /path/to/your/project

# Generate HTML report
uv run hatch run ossiq-cli scan -p html -o ./test_report.html /path/to/your/project
```

### Package Deep-Dive

Inspect a single package in detail — drift status, CVEs, transitive vulnerabilities, and its exact path in the dependency tree:

```bash
ossiq-cli package /path/to/your/project react
ossiq-cli package /path/to/your/project lodash --registry-type npm
```

The output mirrors the structure of the dependency detail panel:

```
[01] DRIFT STATUS       — version lag bar, releases behind, latest version
[02] DEPENDENCY TREE TRACE — ancestry path from root to the package
[03] POLICY COMPLIANCE  — declared constraint vs. resolved vs. latest
[04] SECURITY ADVISORIES — direct CVEs with severity and source
[05] VIA TRANSITIVE DEPENDENCIES — CVEs in packages pulled in by this one
```

If the package appears in multiple places in the tree (hoisted duplicates, diamond dependencies), each occurrence is shown separately with a **SHARED NODE** indicator.

## Key Features

-   **Security Blind Spots**: Go beyond `npm audit` to see which vulnerabilities actually matter and how to prioritize them.
-   **Silent Tech Debt**: Track your version lag in releases and in time (e.g., "your React version is 2 years old") to quantify technical debt.
-   **Multiple Output Formats**: Generate reports as interactive HTML, JSON, CSV exports, or a rich console view.
-   **CI/CD Integration**: Use scores and metrics to build quality gates and enforce dependency policies automatically.

## Supported Ecosystems

### NPM

**Supported:**
- **[npm](https://docs.npmjs.com/cli/v11/commands/npm)** – Package manager for JavaScript (`package.json` + `package-lock.json`)

**Not yet supported:**
- **[Yarn](https://yarnpkg.com/)** and **[pnpm](https://pnpm.io/)** – See the [issue tracker](https://github.com/ossiq/ossiq/issues) for roadmap status.

### Python

**Supported:**
- **[uv](https://docs.astral.sh/uv/)** – Fast Rust-based package manager (`pyproject.toml` + `uv.lock`)
- **[pip lock](https://pip.pypa.io/en/stable/cli/pip_lock/)** – [pylock.toml](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec) lockfile format (`pyproject.toml` + `pylock.toml`)
- **[pip classic](https://pip.pypa.io/en/stable/reference/requirements-file-format/)** – Traditional `requirements.txt` (best with `pip freeze` output)

**Not yet supported:**
- **[Poetry](https://python-poetry.org/)** – Consider exporting to `pylock.toml` as a workaround ([discussion](https://github.com/orgs/python-poetry/discussions/10322))

## Data Sources

OSS IQ aggregates data from the following public sources:

| Source | Purpose |
|---|---|
| [OSV](https://osv.dev/) | Open-source vulnerability database (CVEs, security advisories) |
| [ClearlyDefined](https://clearlydefined.io/) | License and curation data for open-source packages |
| [NPM Registry](https://www.npmjs.com/) | Package metadata and version history for JavaScript packages |
| [PyPI](https://pypi.org/) | Package metadata and version history for Python packages |
| [GitHub](https://github.com/) | Repository activity, releases, and maintainer signals |

## FAQ

**How is this different from `npm audit` or `pip-audit`?**
Audit tools are great at finding known vulnerabilities. OSS IQ goes further by also analyzing non-security risks, such as how far behind you are from the latest version (technical debt) and whether a package is still actively maintained. We give you the full picture of dependency health, not just one part of it.

**What ecosystems does OSS IQ support?**
OSS IQ currently supports npm for JavaScript and multiple dependency managers for Python (uv and classic pip). Yarn, pnpm, and Poetry support are on the roadmap — see the [issue tracker](https://github.com/ossiq/ossiq/issues) for status.

**Is OSS IQ free?**
Yes, OSS IQ is a completely free and open-source tool, licensed under the AGPL v3 license.

## License

This project is licensed under the **GNU Affero General Public License v3.0**. See the [LICENSE](LICENSE) file for details.