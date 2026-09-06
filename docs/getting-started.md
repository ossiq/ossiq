---
title: Getting Started
description: OSS IQ scores every package your project depends on - drift, CVEs, transitive impact, and maintainer activity - so you and your coding agents can decide what to add, what to update, and what to refactor out.
---

# Getting Started

**OSS IQ** helps developers and coding agents answer three questions about every package:

**Should I add it? Update it? Refactor it out?**

Before a new dependency lands, OSS IQ checks whether the package and version is healthy,
maintained, and appropriate for your project, keeping deprecated, outdated, or too-fresh
releases out. For the dependencies you already have, it shows when and how to upgrade,
verifies the upgrade is compatible with the rest of your tree, and supplies agents such as
**Claude** and **Codex** with the **validated context** they need to make the change safely.

This page takes you from nothing to a first scan, then through each way of working:
[coding agents](#coding-agents), [the CLI](#the-cli-workflow), and
[reports and exports](#reports-and-exports).

## GitHub Personal Access Token

OSS IQ mines repository history to judge maintenance health, which can take hundreds of GitHub
API requests per run. Unauthenticated requests are capped at 60 per hour, so a full scan needs a
[Personal Access Token (PAT)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#about-personal-access-tokens).
The token only raises the rate limit - **no scopes or permissions are needed**.

The quickest option is to reuse your existing session:

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token);
```

The safer option is a separate **read-only** token: create a fine-grained token in
[GitHub Settings → Developer Settings → Fine-grained tokens](https://github.com/settings/personal-access-tokens/new)
with **Repository access** set to **Public repositories** and no additional permissions.

```bash
export OSSIQ_GITHUB_TOKEN=replace-with-generated-token;
```

To keep it, store it in `~/.ossiq/config` instead, where every `OSSIQ_*` variable can live:

```bash
echo "OSSIQ_GITHUB_TOKEN=$(gh auth token)" >> ~/.ossiq/config
```

## Your first scan

Point `ossiq-cli` at an existing Python or JavaScript project and OSS IQ detects the manifest
for you. No install required:

```bash
uvx --from ossiq ossiq-cli status testdata/npm/project1/
```

Supported manifests are the ones your package manager already writes: for **npm**,
[package.json](https://docs.npmjs.com/cli/v7/configuring-npm/package-json) with
[package-lock.json](https://docs.npmjs.com/cli/v8/configuring-npm/package-lock-json); for
**Python**, [pylock.toml](https://packaging.python.org/en/latest/specifications/pylock-toml/#pylock-toml-spec),
[uv.lock](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), or classic
[requirements.txt](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

You can also install [ossiq](https://pypi.org/project/ossiq/) permanently with `uv add ossiq`
or `pip install ossiq`, then call `ossiq-cli` directly.

The report gives you a project-level risk score, then breaks it down per package into security
signals (vulnerabilities) and maintenance signals (activity, overhead, health):

![OSS IQ Terminal/CLI Report](/_static/images/ossiq-cli-report-2026-07-13.png)

Every table, column, and status marker in this report, including the *Transitive Recommendations*
and *Peer Constraint Status* sections, is documented in
[Reference → Console Reports](reference.md#console-reports).

## Coding agents

Give Claude Code, OpenAI Codex, or GitHub Copilot the same health check before they add or
upgrade a dependency. `ossiq-cli install skills` writes a `SKILL.md` and registers a local stdio
MCP server (`ossiq-cli mcp`):

```bash
# Install for all three tools
uvx --from ossiq ossiq-cli install skills

# Or target a single tool
uvx --from ossiq ossiq-cli install skills claude
uvx --from ossiq ossiq-cli install skills codex
uvx --from ossiq ossiq-cli install skills copilot
```

| Tool | Skill location | MCP server |
|---|---|---|
| Claude Code | `~/.claude/skills/ossiq/SKILL.md` | registered in `~/.claude/mcp.json` |
| OpenAI Codex | `~/.codex/skills/ossiq/SKILL.md` | registered in `~/.codex/mcp.json` |
| GitHub Copilot | appended to `~/.copilot/copilot-instructions.md` | - |

The command asks for a [GitHub token](#github-personal-access-token) (or takes it via
`--github-token`; leave the prompt blank to skip). The token is stored in `~/.ossiq/config` and
in each tool's MCP server entry where one exists, so your own runs and the agent's runs both get
the higher rate limit. Re-running `install skills` is safe: it merges into existing config rather
than overwriting it.

Once installed, the agent has two read-only tools:

| Tool | Answers |
|---|---|
| `ossiq_evaluate_dependency` | Should I add this package, and at which version? |
| `ossiq_evaluate_updates` | Which existing dependencies should I bump, and in what order? |

Both return the same compact decision the CLI produces with `--format agent`: a `next_action` per
package (`install`, `install with caution`, `do not install` when adding; `Update Immediately`,
`Check Release Notes`, `Check for the Fix`, `Consider alternative`, `Find alternative` when
updating), the recommended version, CVEs, and supply-chain warnings.

```bash
uvx --from ossiq ossiq-cli info requests --format agent
```

For exactly which files are written, how the token is stored, and how to run the integration from
a local checkout with `--dev`, see [Reference → install skills](reference.md#install-skills).

## The CLI workflow

```bash
ossiq-cli status              # dependency health for the whole project
ossiq-cli status --full       # every package, every column
ossiq-cli status --security   # CVE-affected packages only
ossiq-cli info sphinx         # one package: drift, CVEs, tree path, peer requirements
ossiq-cli add requests        # quality-gated install of the recommended version
ossiq-cli plan                # what the solver would change - read-only
ossiq-cli apply               # execute the plan, with rollback on failure
```

Each takes an optional project path (default: `.`) and `--registry-type npm|pypi` to
disambiguate a polyglot repo.

### Package details

```bash
uvx --from ossiq ossiq-cli info sphinx
```

![OSS IQ Terminal/CLI Package Details](/_static/images/ossiq-cli-package-2026-07-13.png)

The section-by-section breakdown of this report - drift status, policy compliance,
recommendation rationale, peer requirements, and transitive CVEs - is in
[Reference → Console Reports](reference.md#console-reports).

### Gated package add

`ossiq-cli add` is a quality-gated alternative to running `uv add` or `npm install` directly.
Package managers install the newest version that satisfies your constraints; `ossiq-cli add`
installs the **recommended** one. It runs the same analysis as `info`, shows drift status, CVEs,
transitive vulnerabilities, and maintainer signals before touching a file, and blocks packages
flagged as critically unhealthy unless you pass `--force`.

```bash
# Check health signals and install the recommended version
uvx --from ossiq ossiq-cli add requests

# Pin an exact version yourself (bypasses the solver recommendation)
uvx --from ossiq ossiq-cli add requests --version 2.31.0

# Override critical-warning blocks (use with care)
uvx --from ossiq ossiq-cli add requests --force
```

### Plan and apply updates

`ossiq-cli plan` shows what the solver recommends without touching any files; `ossiq-cli apply`
executes those changes and rolls them back if the install fails. Every flag is accepted by both,
so a `plan` is a faithful preview of the matching `apply`.

```bash
ossiq-cli plan                    # read-only preview
ossiq-cli apply                   # prompts for confirmation
ossiq-cli apply --security --yes  # patch CVE-affected packages only, unattended
```

Before recommending a version, the solver simulates its full transitive cascade, falls back to the
next-best candidate when the top one would conflict, and holds back releases younger than
`--cooldown-period` (default: 7 days) unless they fix a CVE in an installed version. The solver
resolves in a single pass against your current lockfile, so re-running `plan` after `apply` can
surface further updates; repeat until it reports none. Full rules are in
[Reference → Update Solver](#update-solver).

## Reports and exports

### HTML report

 1. Generate a single self-contained HTML file:
    ```bash
    uvx --from ossiq ossiq-cli html --output report.html
    ```

 2. Open `report.html` for the table view of your dependencies:
    ![OSS IQ HTML Report](/_static/images/ossiq-html-report-2026-06-20.png)

 3. Click the **Transitive Dependencies** tab at the top:
    ![OSS IQ Transitive Dependencies Report](/_static/images/ossiq-html-transitive-dependencies-2026-06-20.png)

 4. Click a dependency node (blue circle) to read its details:
    ![OSS IQ Transitive Dependencies Package Details](/_static/images/ossiq-html-transitive-dependencies-package-2026-06-20.png)

    Here the report tells you that [vue](https://www.npmjs.com/package/vue) is resolved at
    `3.5.38`, which is also the latest published version.

This is the view for planning work rather than fixing one package: sort by drift or severity,
drill into any dependency, and decide what to read release notes for before it enters the backlog.

### JSON and CSV export

```bash
# One JSON document
uvx --from ossiq ossiq-cli export --output-format=json --output=./scan_export.json .

# A directory of CSVs: summary.csv, packages.csv, cves.csv, and datapackage.json
uvx --from ossiq ossiq-cli export --output-format=csv --output=./scan_export_csv .
```

The CSV target directory is created automatically if it does not exist. Both formats carry a
`schema_version`, which you can pin with `--schema-version`: within a version, fields are never
renamed or removed, so a metric you gate on in CI today keeps its meaning tomorrow. See
[Reference → Outputs](reference.md#outputs) and
[Reference → Export Schema Stability](reference.md#export-schema-stability).
