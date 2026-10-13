# OSS IQ

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

> Solve dependency upgrades in one go, through your coding agent or your terminal.

OSS IQ maps the blast radius of a dependency upgrade before you make it: everything the new
version moves across your dependency graph. It checks each package's version drift, CVEs and
maintenance health, then gives you or your coding agent a deterministic, solver-backed update
plan. `ossiq apply` writes the plan and rolls back if the install fails.

Audit tools such as `npm audit` list the CVEs already in your tree, and Dependabot opens a pull
request for every update. OSS IQ answers what neither does: can you move this dependency, and
what happens if you do?

In the OSS IQ agent benchmark, a coding agent given an OSS IQ report spent 41% less per dependency
update than the same agent unassisted. It also took 60% less time and 8 turns instead of 22, and
all ten runs of one upgrade produced the same dependency tree. The benchmark used two test
projects with six dependencies each. It measures cost and time, not correctness: the unassisted
agent also got every update right. [ossiq.dev](https://ossiq.dev/) gives the method.

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

Every PyPI wheel, release binary and npm package carries signed SLSA Build Level 3 provenance.
To check an artifact before you run it, see
[Verifying a release](https://ossiq.dev/how-to/verifying-a-release.html). The Docker image
installs from PyPI and sits outside that chain.

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

## Five questions, one command each

| Question | Command | What you get |
|---|---|---|
| What state is my project in? | `ossiq status` | Version drift, CVEs and maintenance health for every direct and transitive dependency |
| Is this package worth depending on? | `ossiq info requests` | One package inside your project: drift, CVEs, tree path, peer requirements |
| Is it safe to add right now? | `ossiq add requests` | A quality gate in front of `npm install` and `uv add`. It installs the recommended version after you confirm, and critical warnings block the add |
| What can I upgrade without breaking the tree? | `ossiq plan`, then `ossiq apply` | `plan` previews what the solver would update and writes nothing. `apply` writes it after you confirm, and rolls back if the install fails |
| Can my coding agent do all of this? | `ossiq install skills` | The same checks for Claude Code, OpenAI Codex and GitHub Copilot: see [Use with coding agents](#use-with-coding-agents) |

To share a scan or gate CI on it, write a report:

```bash
ossiq html --output report.html # a self-contained HTML report to share
ossiq export --output scan.json # versioned JSON for CI gates
```

Every command except `install skills` takes an optional project path (default: `.`). Every
option is in the [reference](https://ossiq.dev/reference.html).

## Use with coding agents

Give Claude Code, OpenAI Codex or GitHub Copilot the same check before they edit your manifest.
The agent gets a solved plan instead of researching versions itself:

```bash
ossiq install skills            # all three tools
ossiq install skills claude     # or one: claude, codex, copilot
```

All three tools get the skill. Claude Code and Codex also get a local MCP server (`ossiq mcp`)
with three read-only tools:

| Tool | Answers |
|---|---|
| `ossiq_evaluate_dependency` | Should I add this package, and at which version? |
| `ossiq_evaluate_updates` | Which existing dependencies should I update, and in what order? |
| `ossiq_update_context` | What breaks if I move this package to a specific version, and is there a better one? |

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
- [Explanation](https://ossiq.dev/explanation/index.html), starting with
  [the update pyramid](https://ossiq.dev/recommendations/update-pyramid.html)
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
