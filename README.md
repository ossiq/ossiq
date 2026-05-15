# OSS IQ

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)
> Quantify Maintenance Health. Control Your Drift.

**OSS IQ** is a free & open-source CLI tool that analyzes dependency drift at scale. Track version lag and transitive risk directly from your dependency files. It helps to move from reactive CVE-chasing to a planned, predictable maintenance rhythm.

![OSS IQ HTML Report](https://ossiq.dev/_images/ossiq-cli-report-2026-03-14.png)

## What is OSS IQ?

In a typical project with hundreds of dependencies, how do you answer these questions?
- How many dependencies have critical vulnerabilities?
- How far behind the latest versions are we?
- Which packages are unmaintained or abandoned?
- Which newer versions of dependencies would work best for my project?

## Key Features

- **Security Blind Spots**: Go beyond `npm audit` to see which vulnerabilities actually matter and how to prioritize them.
- **Multiple Output Formats**: CLI and interactive HTML per-project dependencies exploration tools as well as export into clearly defined JSON or CSV schemas.
- **CI/CD Integration**: Use scores and metrics to build quality gates and enforce dependency policies automatically.
- **Peer Dependency Analysis**: Detect peer constraint violations, compliance-by-override status, and dead-end configurations where no compatible version exists across both npm and Python ecosystems.
- **Transitive Impact Simulation**: Before recommending an update, simulate the full transitive cascade — see exactly which downstream packages would change, whether conflicts arise, and get a fallback recommendation when the best version is blocked.

OSS IQ bridges the gap between raw dependency data and actionable intelligence. It analyzes version lag, CVEs, transitive dependencies, and maintainer activity to produce a single, holistic view of your project dependencies.

## How It Works

1.  **Run OSS IQ**: Point the CLI to your project's manifest file (`package.json`, `pyproject.toml`, etc.). OSS IQ supports NPM and Python (uv, pip).
2.  **Analyze Everything**: Version lag, CVEs, transitive dependencies, and license compliance—all cross-referenced against public databases (OSV, npm, PyPI) using MSR Engine.
3.  **Get Your Report**: See your dependencies drift report, drill into each package details, and get a prioritized list of what to fix first.
4.  **Build Quality Gates**: Use your project metrics to set up policies and drive organization behavior.

## Quick Start

### 1. Run OSS IQ

The fastest way is to run directly from [PyPI](https://pypi.org/) with [uvx](https://docs.astral.sh/uv/) with no install required:

```bash
# JavaScript / npm
uvx --from ossiq ossiq-cli scan /path/to/your/project

# Python / uv / pip
uvx --from ossiq ossiq-cli scan /path/to/your/project

# Generate HTML report
uvx --from ossiq ossiq-cli scan --presentation=html --output report.html /path/to/your/project

# Include full transitive dependency recommendations
uvx --from ossiq ossiq-cli scan --transitive /path/to/your/project

# Narrow to CVE-affected packages only (security-first workflow)
uvx --from ossiq ossiq-cli scan --security /path/to/your/project
```

OSS IQ automatically detects the dependency manifest (`package.json`, `pyproject.toml`, etc.) in the target directory.


#### GitHub Token

OSS IQ performs deep analysis by mining software repository history, which can involve hundreds of API requests to GitHub. To avoid being rate-limited, it's. best to provide a GitHub Personal Access Token (PAT).

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
```


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
[01] DRIFT STATUS            — version lag bar, releases behind, latest version
[02] DEPENDENCY TREE TRACE   — ancestry path from root to the package
[03] POLICY COMPLIANCE       — declared constraint vs. resolved vs. latest
[04] SECURITY ADVISORIES     — direct CVEs with severity and source
[05] VIA TRANSITIVE DEPENDENCIES — CVEs in packages pulled in by this one
[08] PEER REQUIREMENTS       — per-requirement status: ok / violation / compliance-via-override
```

If the package appears in multiple places in the tree (hoisted duplicates, diamond dependencies), each occurrence is shown separately with a **SHARED NODE** indicator.

### Atomic Dependency Update

Generate a safe, copy-pasteable bash script that upgrades your dependencies to the versions recommended by the HPDR solver:

```bash
ossiq-cli update /path/to/your/project
```

The solver runs automatically and outputs a script tailored to your package manager. **Review the script before running it** — it is designed to be atomic so that **no unvetted versions are pulled in by the package manager's own resolver**.

Before emitting the script, the solver simulates the full transitive impact of each recommendation. When the top candidate would create a downstream conflict, it falls back to the next-best version automatically. The plan table shows a `↳` sub-row for each transitive package that would also move, and marks non-actionable entries with `✗`.

**npm** — backs up `package.json`, injects all recommended versions as `overrides` in one pass, runs `npm install`, then removes the overrides block.

**uv / pip** — writes all recommended versions to a temporary constraints file, syncs with that constraint so the resolver cannot pick unvetted versions, then deletes the file.

Options mirror the `scan` command:

| Option | Description |
|---|---|
| `--production` | Limit to production dependencies only |
| `--registry-type npm\|pypi` | Narrow to a specific ecosystem |
| `--security` | Include only CVE-affected packages in the update plan |
| `--allow-prerelease` | Include pre-release candidates in solver |
| `--allow-prerelease-package <name>` | Allow pre-release for a specific package (repeatable) |

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
| [NPM Registry](https://www.npmjs.com/) | Package metadata and version history for JavaScript packages |
| [PyPI](https://pypi.org/) | Package metadata and version history for Python packages |
| [GitHub](https://github.com/) | Repository activity, releases, and maintainer signals |

## FAQ

**Why another Software Composition Analysis tool?**

OSS IQ is not another vulnerability scanner. It helps platform teams evaluate open-source dependencies as long-term engineering assets by analyzing lockfiles, dependency graphs, and maintenance signals, producing stable scores suitable for CI and platform governance.

**How is OSS IQ different from npm audit or pip-audit?**

Audit tools are great at finding known vulnerabilities. OSS IQ goes further by also analyzing non-security risks, such as how far behind you are from the latest version (technical debt) and whether a package is still actively maintained. We give you the full picture of dependency health, not just one part of it.


**What ecosystems are supported?**

OSS IQ currently supports popular ecosystems like npm for JavaScript and multiple dependency managers for Python (uv and classic pip). We are always working to add support for more ecosystems.

**Is OSS IQ free?**

Yes, OSS IQ is a completely free and open-source tool, licensed under the AGPL v3 license.

## License

This project is licensed under the **GNU Affero General Public License v3.0**. See the [LICENSE](LICENSE) file for details.