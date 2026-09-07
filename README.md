# OSS IQ

[![PyPI version](https://img.shields.io/pypi/v/ossiq.svg)](https://pypi.org/project/ossiq)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

> Make better dependency decisions - before and after installation.

**OSS IQ** helps developers and code agents answer:

**Should I add it? Update it? Refactor it out?**

Before you add a new dependency, OSS IQ checks whether 
the package and version is healthy, maintained and appropriate for your project -
helping to avoid deprecated, outdated or too fresh dependencies getting in.

OSS IQ helps you understand when and how to upgrade your existing dependencies,
verifies that they're compatible with your project, and supplies coding agents
such as **Claude** and **Codex** with the **validated context** they need to safely make the upgrade.

You can run OSS IQ from the command line, or hook it up to coding agents with both **SKILL.md** and local **MCP server**.

Free and open source (AGPL v3), for npm, uv, and pip.

![OSS IQ HTML Report](https://ossiq.dev/_static/images/ossiq-cli-report-2026-07-13.png)

**Start where you are:**

| You want to | Go to |
|---|---|
| Stop your coding agent from adding a risky package | [Coding agents](#coding-agents) |
| Check, plan, and apply updates yourself | [The CLI workflow](#the-cli-workflow) |
| Give your team a report to prioritize from | [Reports and exports](#reports-and-exports) |

## Quick start

No install required - run it from your project directory:

```bash
uvx --from ossiq ossiq-cli status
```

OSS IQ detects the manifest (`package.json`, `pyproject.toml`, `requirements.txt`) in the target directory. A full scan makes hundreds of GitHub API calls, so [add a token](#github-token) before you rely on the results.

If you prefer a persistent install:

```bash
uv add ossiq      # or: pip install ossiq
ossiq-cli status
```

## Coding agents

Give Claude Code, Codex, or GitHub Copilot a skill and a local MCP server, so they check dependency health *before* they edit your manifest:

```bash
# Install for all three tools
uvx --from ossiq ossiq-cli install skills

# Or target one: claude, codex, copilot
uvx --from ossiq ossiq-cli install skills claude
```

This writes `SKILL.md` and registers `ossiq` as a local stdio MCP server (`ossiq-cli mcp`) for Claude Code (`~/.claude/`) and Codex (`~/.codex/`), and adds the skill to Copilot's `~/.copilot/copilot-instructions.md`. Re-running is safe — existing config is merged, not overwritten.

The agent gets two read-only tools:

| Tool | Answers |
|---|---|
| `ossiq_evaluate_dependency` | Should I add this package, and at which version? |
| `ossiq_evaluate_updates` | Which existing dependencies should I bump, and in what order? |

Both return the same compact decision the CLI produces with `--format agent`:

```bash
ossiq-cli info requests --format agent
```

```json
{
  "operation": "add",
  "package": "requests",
  "next_action": "install with caution",
  "recommended_version": "2.31.0",
  "reasons": ["recommend 2.31.0 rather than latest 2.32.0", "single maintainer — bus factor risk"],
  "cves": [],
  "warnings": ["SINGLE_MAINTAINER"]
}
```

The install command prompts for a GitHub token (or takes `--github-token`; blank skips) and stores it in `~/.ossiq/config` and in each tool's MCP entry, so agent scans get the higher rate limit too. Files written, token handling, and running from a local checkout with `--dev`: [Reference → install skills](https://ossiq.dev/reference.html#install-skills).

## The CLI workflow

```bash
ossiq-cli status              # dependency health for the whole project
ossiq-cli status --full       # every package, every column (EPSS, update mode, lag, maintenance state)
ossiq-cli status --security   # CVE-affected packages only
ossiq-cli info requests       # one package: drift, CVEs, tree path, peer requirements
ossiq-cli add requests        # quality-gated install of the recommended version
ossiq-cli plan                # what the solver would change — read-only
ossiq-cli apply               # execute the plan, with rollback on failure
```

Each takes an optional project path (default: `.`) and `--registry-type npm|pypi` to disambiguate a polyglot repo. `info` prints drift status, the dependency tree trace, policy compliance, direct and transitive CVEs, and peer requirements — one section per concern, [documented here](https://ossiq.dev/reference.html#info-package-report).

### `add` — a gate in front of `uv add` and `npm install`

Package managers install the newest version that satisfies your constraints. `ossiq-cli add` installs the *recommended* one: it runs the same analysis as `info`, shows drift, CVEs, transitive vulnerabilities and maintainer signals before touching a file, blocks critically unhealthy packages unless you pass `--force`, and confirms the exact spec before installing.

```bash
ossiq-cli add lodash --registry-type npm
ossiq-cli add requests --version 2.31.0   # pin yourself, bypassing the recommendation
```

### `plan` and `apply` — updates with their transitive cascade

`plan` is a faithful preview of the matching `apply`: every flag is accepted by both. The solver simulates the full transitive impact of each recommendation before committing to it — the table shows a `↳` sub-row for each transitive package that would also move, falls back to the next-best version when the top candidate would cause a downstream conflict, and marks non-actionable entries with `✗`.

- **npm** — backs up `package.json`, injects all recommended versions as `overrides` in one pass, runs `npm install --ignore-scripts`, then removes the overrides block.
- **uv / pip** — rewrites specifiers in `pyproject.toml` or `requirements.txt` in place, then runs `uv lock --upgrade-package` / `pip install -c <constraints>`. Changes are rolled back automatically if the update fails.

The solver resolves in a single pass against your *current* lockfile, so a second `plan` can legitimately show more: applying re-resolves the tree, and the new constraints unlock recommendations that were not visible before. Repeat `apply` → `plan` until it reports no updates; most projects converge in one or two passes.

<details>
<summary><b>All <code>plan</code> / <code>apply</code> flags</b></summary>

| Option | Description |
|---|---|
| `--production` | Limit to production dependencies only |
| `--registry-type npm\|pypi` | Narrow to a specific ecosystem |
| `--security` | Include only CVE-affected packages (direct and transitive) |
| `--allow-prerelease` | Include pre-release versions across all packages |
| `--allow-prerelease-package <name>` | Allow pre-release for one package (repeatable) |
| `--ignore <name>`, `-i` | Exclude a package from the plan entirely (repeatable) |
| `--override <pkg>==<ver>` | Force an exact version, bypassing the solver and the cooldown (repeatable) |
| `--pin-all` | Write `==new_version` for every updated direct dependency, converting `^`, `~=`, `>=` to exact pins |
| `--rewrite-versions` | Include already-pinned (`==x.y.z`) dependencies and rewrite their version |
| `--yes`, `-y` | (`apply` only) Skip the confirmation prompt |

</details>

<details>
<summary><b>Pinning workflow — <code>--pin-all</code> and <code>--rewrite-versions</code></b></summary>

Packages pinned with an exact specifier (`==x.y.z`) are **frozen** by default, so an intentional lock is never upgraded by accident. The two flags together let you run a fully pinned dependency file:

```bash
# 1. Migrate all direct deps to exact pins
ossiq-cli apply --pin-all

# 2. Later, preview what is available (pinned deps stay hidden)
ossiq-cli plan

# 3. Upgrade and re-pin in one pass — optionally holding some back
ossiq-cli apply --pin-all --rewrite-versions
ossiq-cli apply --pin-all --rewrite-versions --ignore requests --ignore django
```

| Flags | `>=x` (declared) | `~=x` (narrowed) | `==x` (pinned) |
|---|---|---|---|
| *(none)* | lockfile-only update | rewrite `~=new` | frozen / skipped |
| `--pin-all` | rewrite `==new` | rewrite `==new` | frozen / skipped |
| `--rewrite-versions` | lockfile-only update | rewrite `~=new` | rewrite `==new` |
| `--pin-all --rewrite-versions` | rewrite `==new` | rewrite `==new` | rewrite `==new` |

</details>

### Cooldown — freshness as a supply-chain guard

`--cooldown-period` (default: 7 days) keeps you off releases that were published minutes ago, where supply-chain attacks land. Versions younger than the cooldown are heavily penalized inside the solver, and any recommendation still younger than it after solving is withheld into a *"Held for cooldown"* section and never applied.

Two deliberate exceptions: a **CVE fix bypasses the hold** when the installed version is vulnerable (tagged `CVE`, with a `cooldown bypassed` note), and **brand-new transitive dependencies** are resolved by npm/uv at apply time, so the plan projects their version and age and flags fresh ones with `⚠`.

When the only version that fixes a CVE is itself still quarantined, you are trading a *known* risk against a *statistical* one. Three levers, from automatic to manual:

1. **Default** — the fix is applied regardless of age. For most teams a concrete CVE beats a hypothetical supply-chain risk.
2. **`--security`** — `ossiq-cli apply --security --yes` patches vulnerabilities and touches nothing else, while your regular cadence stays on cooldown.
3. **`--override pkg==version`** — force a version you have vetted yourself: `ossiq-cli apply --override urllib3==2.0.7`. For a transitive package this writes a *persistent* entry (`overrides` in `package.json`, `override-dependencies` under `[tool.uv]`), and `status` keeps reporting it with the `OVERRIDE` constraint type until you remove it.

Full solver rules: [Reference → update solver](https://ossiq.dev/reference.html#update-solver).

## Reports and exports

```bash
# Single self-contained HTML file — share it, attach it to a ticket
ossiq-cli html --output report.html

# Machine-readable output for pipelines and spreadsheets
ossiq-cli export --output metrics.json
ossiq-cli export --output metrics.csv --output-format=csv
```

The HTML report is the view for planning work rather than fixing one package: sort by drift or severity, drill into any dependency's tree path, CVEs, peer requirements and recommended version, and decide what to read release notes for before it enters the backlog. Exports use versioned schemas (`--schema-version`) so a metric you gate on today keeps its meaning tomorrow — see [Reference → outputs](https://ossiq.dev/reference.html#outputs) and the [GitHub Actions quality-gate tutorial](https://ossiq.dev/tutorials/tutorial-github-actions.html).

## Configuration

### GitHub token

OSS IQ mines repository history, which can take hundreds of GitHub API requests per run. Without a token you will be rate-limited at 60 requests/hour.

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)

# Or persist it
echo "OSSIQ_GITHUB_TOKEN=$(gh auth token)" >> ~/.ossiq/config
```

A read-only fine-grained token scoped to public repositories is the safer choice — see [Getting started → GitHub token](https://ossiq.dev/getting-started.html#github-personal-access-token).

### Config file

Every `OSSIQ_*` environment variable can also live in `~/.ossiq/config` (dotenv format: `KEY=value`, `#` comments):

```bash
# ~/.ossiq/config
OSSIQ_GITHUB_TOKEN=ghp_your_token
OSSIQ_COOLDOWN_PERIOD=14
OSSIQ_CACHE_TTL=48
```

Point at a different file with `ossiq-cli --config ./ossiq.conf status`. Values resolve highest-wins: CLI flags → environment variables → config file → built-in defaults.

### Time controls

Two global options change how OSS IQ perceives time. They apply to `status`, `export`, `plan`, `apply`, and `info`, and combine freely.

| Option | Env var | Default | Effect |
|---|---|---|---|
| `--cutoff-date YYYY-MM-DD` | `OSSIQ_CUTOFF_DATE` | today | Treat versions published after this date as invisible (23:59:59 UTC). Reproduces a past state of your dependencies. |
| `--cooldown-period N` | `OSSIQ_COOLDOWN_PERIOD` | `7` | Soft-penalize versions younger than N days in the solver. `0` disables the penalty. |

```bash
# Time-travel view with a wider freshness buffer
ossiq-cli --cutoff-date 2025-01-01 --cooldown-period 14 status

# Same thing from the environment, for CI
OSSIQ_CUTOFF_DATE=2025-01-01 OSSIQ_COOLDOWN_PERIOD=14 ossiq-cli status
```

## Supported ecosystems

| Ecosystem | Supported | Not yet |
|---|---|---|
| JavaScript | [npm](https://docs.npmjs.com/cli/v11/commands/npm) (`package.json` + `package-lock.json`) | [Yarn](https://yarnpkg.com/), [pnpm](https://pnpm.io/) — see the [issue tracker](https://github.com/ossiq/ossiq/issues) |
| Python | [uv](https://docs.astral.sh/uv/) (`pyproject.toml` + `uv.lock`), [pip lock](https://pip.pypa.io/en/stable/cli/pip_lock/) ([`pylock.toml`](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec)), [pip classic](https://pip.pypa.io/en/stable/reference/requirements-file-format/) (`requirements.txt`, best with `pip freeze` output) | [Poetry](https://python-poetry.org/) — export to `pylock.toml` as a workaround ([discussion](https://github.com/orgs/python-poetry/discussions/10322)) |

Analysis aggregates public data from [OSV](https://osv.dev/) (advisories), the [npm registry](https://www.npmjs.com/) and [PyPI](https://pypi.org/) (metadata and version history), and [GitHub](https://github.com/) (repository activity and maintainer signals).

## Docker

```bash
docker pull ossiq/ossiq-cli
export OSSIQ_GITHUB_TOKEN=$(gh auth token)

# Status
docker run --rm -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro \
  ossiq/ossiq-cli status /project

# HTML report or JSON export into ./reports
docker run --rm -e OSSIQ_GITHUB_TOKEN \
  -v /path/to/your/project:/project:ro -v $(pwd)/reports:/output \
  ossiq/ossiq-cli html -o /output/report.html /project
```

Tags: `latest`, `0.1` (latest patch in the minor), `0.1.9` (exact version).

<details>
<summary><b>GitHub Actions example</b></summary>

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

</details>

## Contributing

```bash
git clone https://github.com/ossiq/ossiq.git
cd ossiq
uv sync

uv run hatch run ossiq-cli status
uv run hatch run ossiq-cli html -o ./test_report.html

# Point the agent skill and MCP server at your checkout instead of PyPI
uv run hatch run ossiq-cli install skills --dev "$(pwd)"
```

Issues and pull requests are welcome — start with the [issue tracker](https://github.com/ossiq/ossiq/issues). If OSS IQ saves you a maintenance afternoon, a ⭐ helps other people find it.

## FAQ

**How is this different from `npm audit` or `pip-audit`?**
Audit tools find known vulnerabilities. OSS IQ also scores the risks that have no CVE: how far behind you are, whether a package is still maintained, what a version bump would drag in transitively, and which version to move to. It produces stable scores meant for CI gates and platform governance, not one-off alerts.

**Is it free?**
Yes — free and open source under AGPL v3.

**Which ecosystems?**
npm for JavaScript, and uv, pip lock, and classic pip for Python. More are on the roadmap.

**Where are the full docs?**
[ossiq.dev](https://ossiq.dev) — [getting started](https://ossiq.dev/getting-started.html), [reference](https://ossiq.dev/reference.html), and [tutorials](https://ossiq.dev/tutorials/index.html).

## License

Licensed under the **GNU Affero General Public License v3.0**. See [LICENSE](LICENSE).
