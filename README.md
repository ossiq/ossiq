# OSS IQ

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

> Make better dependency decisions — before and after installation.

OSS IQ checks every package your project depends on: version drift, CVEs, maintenance health, and
what an update would pull in transitively. It then tells you, or your coding agent, what to add,
what to update, and what to replace. Audit tools such as `npm audit` find known vulnerabilities;
OSS IQ also scores the risks that have no CVE.

Free and open source (AGPL v3), for npm, uv and pip projects.

![OSS IQ console report](https://ossiq.dev/_static/images/ossiq-cli-report-2026-07-13.png)

## Install

Run it without installing, from your project directory:

```bash
uvx ossiq status          # PyPI, through uv
npx @ossiq/cli status     # npm: a native binary, no Python needed
```

Or install it permanently:

| Channel | Install | Needs |
|---|---|---|
| PyPI | `uv tool install ossiq` or `pipx install ossiq` | Python 3.11+ |
| npm | `npm install -g @ossiq/cli` | Node.js only |
| Docker | `docker pull ossiq/ossiq-cli` | Docker; see the [image page](https://hub.docker.com/r/ossiq/ossiq-cli) |

The npm package ships native binaries for macOS (arm64, x64), Linux with glibc (arm64, x64) and
Windows (x64). On Windows on Arm and on Alpine Linux, install from PyPI.

## Log in to GitHub

OSS IQ reads repository activity from GitHub, and a full scan needs hundreds of API requests.
Log in once to raise GitHub's limit from 60 requests an hour to 5,000:

```bash
ossiq auth login
```

Open the URL it prints, enter the code, and approve **OSS IQ**. The token goes to your operating
system's secret store (macOS Keychain, Windows Credential Manager or Secret Service on Linux),
never to a file. It has no scopes, expires after 8 hours, and refreshes by itself.

In CI and containers, set `OSSIQ_GITHUB_TOKEN` instead. See
[Log in to GitHub](https://ossiq.dev/how-to/github-login.html) for CI, agents and troubleshooting.

## Check your dependencies

```bash
ossiq status                    # dependency health for the whole project
ossiq info requests             # one package: drift, CVEs, tree path, peer requirements
ossiq add requests              # install the recommended version, after a health check
ossiq plan                      # what the solver would update (read-only)
ossiq apply                     # apply the plan, with rollback on failure
ossiq html --output report.html # a self-contained HTML report to share
ossiq export --output scan.json # versioned JSON for CI gates
```

Each command takes an optional project path (default: `.`). Every option is in the
[reference](https://ossiq.dev/reference.html).

## Use with coding agents

Give Claude Code, Codex or GitHub Copilot the same check before they edit your manifest:

```bash
ossiq install skills            # all three tools
ossiq install skills claude     # or one: claude, codex, copilot
```

This writes a `SKILL.md` and registers a local MCP server (`ossiq mcp`). The agent gets two
read-only tools:

| Tool | Answers |
|---|---|
| `ossiq_evaluate_dependency` | Should I add this package, and at which version? |
| `ossiq_evaluate_updates` | Which existing dependencies should I update, and in what order? |

If the agent needs a GitHub login, it shows you the code and retries after you approve.

## Supported ecosystems

| Ecosystem | Supported | Not yet |
|---|---|---|
| JavaScript | [npm](https://docs.npmjs.com/cli/v11/commands/npm) (`package.json` + `package-lock.json`) | [Yarn](https://yarnpkg.com/), [pnpm](https://pnpm.io/) |
| Python | [uv](https://docs.astral.sh/uv/) (`pyproject.toml` + `uv.lock`), [pip lock](https://pip.pypa.io/en/stable/cli/pip_lock/) (`pylock.toml`), [pip](https://pip.pypa.io/en/stable/reference/requirements-file-format/) (`requirements.txt`) | [Poetry](https://python-poetry.org/): export to `pylock.toml` instead |

Data comes from [OSV](https://osv.dev/), the [npm registry](https://www.npmjs.com/),
[PyPI](https://pypi.org/) and [GitHub](https://github.com/).

## Documentation

- [Getting started](https://ossiq.dev/getting-started.html)
- [Log in to GitHub](https://ossiq.dev/how-to/github-login.html)
- [Reference](https://ossiq.dev/reference.html)
- [Tutorials](https://ossiq.dev/tutorials/index.html), including a
  [GitHub Actions quality gate](https://ossiq.dev/tutorials/tutorial-github-actions.html)
- [Verifying a release](https://ossiq.dev/how-to/verifying-a-release.html)

## Contributing

```bash
git clone https://github.com/ossiq/ossiq.git
cd ossiq
uv sync
uv run ossiq status

# Point the agent skill and MCP server at your checkout instead of PyPI
uv run ossiq install skills --dev "$(pwd)"
```

Issues and pull requests are welcome; start with the
[issue tracker](https://github.com/ossiq/ossiq/issues).

## License

Licensed under the [GNU Affero General Public License v3.0](https://github.com/ossiq/ossiq/blob/main/LICENSE).
