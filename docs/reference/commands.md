---
title: Commands
description: "Every ossiq command with its arguments, options and exit codes: status, info, add, update-context, plan, apply, export, html, install skills, auth and mcp."
---

# Commands

Every `ossiq` command, with its arguments, options and exit codes. Part of the
[reference](../reference.md).

| Command | What it does | Writes |
|---|---|---|
| [`status`](#status) | Reports drift, CVEs and a recommendation for every dependency | Nothing |
| [`info`](#info) | Reports one package in depth | Nothing |
| [`add`](#add) | Checks a package's health, then installs it after you confirm | Manifest and lockfile |
| [`update-context`](#update-context) | Compares a package's installed version with a target you name | Nothing |
| [`plan`](#plan-and-apply) | Previews the updates `apply` would make | Nothing |
| [`apply`](#plan-and-apply) | Shows the plan, then writes it after you confirm | Manifest and lockfile |
| [`export`](#export) | Writes the scan as JSON | One `.json` file |
| [`html`](#html) | Writes the scan as a self-contained HTML report | One `.html` file |
| [`install skills`](#install-skills) | Sets up coding agents to call OSS IQ | Files under your home directory |
| [`auth`](#auth) | Logs in to GitHub, shows the login, or removes it | The system secret store |
| [`mcp`](#mcp) | Runs a local MCP server over stdio | Nothing |

Global options, such as `--cooldown-period` and `--cutoff-date`, go before the command:
`ossiq --cooldown-period 14 status`. They are listed with their environment variables in
[Settings](configuration.md#settings).

Most commands take an optional `PROJECT_PATH`, which defaults to the current directory.

(cmd-status)=
## `status`

```bash
ossiq status [OPTIONS] [PROJECT_PATH]
```

Prints the project report. By default it shows only the packages that need action.
[`status` report](reports.md#status-report) describes every column and marker.

| Option | Description |
|---|---|
| `--full` | Show every package and the detail columns: EPSS, update mode, lag and maintenance state |
| `--format console\|agent`, `-f` | Print the console report (default) or the [agent format](export-and-agent-format.md#agent-format) |
| `--lag-threshold-delta DELTA`, `-l` | Highlight a lag longer than this. Units: `y`, `m`, `w`, `d`, `h`; a bare number is days. Default: `1y` |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--production` | Leave out development dependencies |
| `--update-strategy TIER` | Target one tier of the update pyramid: `security`, `deprecation`, `standard` (default), `latest` or `cutting-edge`. See [Update strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the recommendations (repeatable) |
| `--allow-partial` | Accept a result built on incomplete data. See [Incomplete security data](update-rules.md#incomplete-security-data) |

(cmd-info)=
## `info`

```bash
ossiq info [OPTIONS] PACKAGE_NAME [PROJECT_PATH]
```

Prints the report for one package. `PACKAGE_NAME` matches the package name or its npm alias
exactly, ignoring case. For a package that is not installed, `info` evaluates it as a candidate.
[`info` report](reports.md#info-report) describes every section.

| Option | Description |
|---|---|
| `--format console\|agent`, `-f` | Print the console report (default) or the [agent format](export-and-agent-format.md#agent-format) |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--update-strategy TIER` | Target one tier of the update pyramid. See [Update strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the recommendations (repeatable) |

(cmd-add)=
## `add`

```bash
ossiq add [OPTIONS] PACKAGE_NAME [PROJECT_PATH]
```

Shows the package's CVEs, downloads, maintainers and health warnings, then asks before it
installs. Without `--version`, it installs the recommended version, which is not always the
newest. A critical warning blocks the install.

| Option | Description |
|---|---|
| `--version VERSION`, `-v` | Install this exact version, for example `1.2.3` |
| `--force` | Install even when a critical warning is present |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |

`add` exits with status 1 when a critical warning blocks it. The
[Warnings](reports.md#warnings) section of the `info` report lists what counts as critical.

(cmd-update-context)=
## `update-context`

```bash
ossiq update-context [OPTIONS] PACKAGE_NAME [PROJECT_PATH]
```

Compares the installed version of a package with a target version you name, which need not be
the one OSS IQ recommends. It reports module-system breaks, engine compatibility and rejected
releases along the way, as JSON in the
[agent format](export-and-agent-format.md#update-context-comparison).

| Option | Description |
|---|---|
| `--to VERSION` | Evaluate this target version. Default: the recommended version |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--allow-prerelease` | Include pre-release versions for every package |

(plan-and-apply-options)=
## `plan` and `apply`

```bash
ossiq plan [OPTIONS] [PROJECT_PATH]
ossiq apply [OPTIONS] [PROJECT_PATH]
```

`plan` and `apply` accept the same options, so a `plan` previews the matching `apply` exactly.
[Update rules](update-rules.md) describes how each target version is picked.

| Option | Description |
|---|---|
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--production` | Leave out development dependencies |
| `--update-strategy TIER` | Target one tier of the update pyramid: `security`, `deprecation`, `standard` (default), `latest` or `cutting-edge`. See [Update strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the plan (repeatable) |
| `--override PKG==VERSION` | Force an exact version, bypassing the solver and the cooldown (repeatable). See [Forced versions](update-rules.md#forced-versions) |
| `--pin-all` | Write an exact `==version` for every updated direct dependency |
| `--rewrite-versions` | Include dependencies already pinned with `==x.y.z`, and rewrite their pin |
| `--allow-partial` | `plan` only. Accept a result built on incomplete data. See [Incomplete security data](update-rules.md#incomplete-security-data) |
| `--yes`, `-y` | `apply` only. Skip the confirmation prompts |

Both commands exit with status 2 when `--override` names a package that is not in the project.

An exact pin (`==x.y.z`) is frozen by default, so an update never moves an intentional pin.
`--pin-all` and `--rewrite-versions` change how each kind of specifier is written:

| Flags | `>=x` (declared) | `~=x` (narrowed) | `==x` (pinned) |
|---|---|---|---|
| *(none)* | lockfile-only update | rewrite to `~=new` | skipped |
| `--pin-all` | rewrite to `==new` | rewrite to `==new` | skipped |
| `--rewrite-versions` | lockfile-only update | rewrite to `~=new` | rewrite to `==new` |
| `--pin-all --rewrite-versions` | rewrite to `==new` | rewrite to `==new` | rewrite to `==new` |

To keep every direct dependency pinned, pin once, then upgrade and re-pin in one pass:

```bash
ossiq apply --pin-all
ossiq apply --pin-all --rewrite-versions --ignore django
```

### Install passes (npm)

npm refuses a tree where an installed package's peer range excludes a version that another update places
beside it, even when the finished tree is valid. When that applies, `plan` groups the updates under
**Pass 1 of N**, and names the package that goes first and the range that makes it wait. `apply` runs the
passes in that order: every pass but the last only writes `package-lock.json`, and the last one installs. A
failure in any pass restores `package.json` and `package-lock.json`. A plan with no such conflict is one
pass and reads as before.

(cmd-export)=
## `export`

```bash
ossiq export [OPTIONS] [PROJECT_PATH]
```

Writes the scan to one JSON file. [JSON export](export-and-agent-format.md#json-export)
describes the document.

| Option | Description |
|---|---|
| `--output PATH`, `-o` | Write to this file. Default: `./ossiq_export_report_{project_name}.json`. Environment variable: `OSSIQ_OUTPUT` |
| `--schema-version 1.5\|1.6`, `-s` | Write this schema version. Default: the latest. Environment variable: `OSSIQ_SCHEMA_VERSION` |
| `--full` | Write the full report: every transitive package, the dependency tree, provenance URLs and the raw upstream signals. Default: every direct dependency, plus the transitive packages that need attention |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--production` | Leave out development dependencies |
| `--update-strategy TIER` | Target one tier of the update pyramid. See [Update strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the recommendations (repeatable) |
| `--allow-partial` | Accept a result built on incomplete data. See [Incomplete security data](update-rules.md#incomplete-security-data) |

(cmd-html)=
## `html`

```bash
ossiq html [OPTIONS] [PROJECT_PATH]
```

Writes the scan to one self-contained HTML file. [HTML report](reports.md#html-report)
describes what it shows.

| Option | Description |
|---|---|
| `--output PATH`, `-o` | Write to this file. Default: `./ossiq_scan_report_{project_name}.html`. Environment variable: `OSSIQ_OUTPUT` |
| `--lag-threshold-delta DELTA`, `-l` | Highlight a lag longer than this. Units: `y`, `m`, `w`, `d`, `h`; a bare number is days. Default: `1y` |
| `--registry-type npm\|pypi`, `-r` | Analyze one ecosystem of a polyglot repository |
| `--production` | Leave out development dependencies |
| `--update-strategy TIER` | Target one tier of the update pyramid. See [Update strategy](#update-strategy) |
| `--strategy-override PKG=TIER` | Run one package at a different tier (repeatable) |
| `--allow-prerelease` | Include pre-release versions for every package |
| `--allow-prerelease-package NAME` | Include pre-release versions for one package (repeatable) |
| `--ignore NAME`, `-i` | Leave a package out of the recommendations (repeatable) |

(install-skills)=
## `install skills`

```bash
ossiq install skills [TOOL] [--via uvx|npx|ossiq] [--dev PATH]
```

Installs the OSS IQ skill and a local MCP server so AI coding agents check dependency health before they add or update a package. For the task-oriented walkthrough, see [Coding agents](../getting-started.md#coding-agents).

| Argument / option | Default | Description |
|---|---|---|
| `TOOL` | `all` | Which tool to install for: `claude`, `codex`, `copilot`, or `all`. |
| `--via` | detected | How the skill and MCP server run OSS IQ: `uvx`, `npx`, or a bare `ossiq` on `PATH`. By default this matches the channel you ran the command from (see [How the skill runs OSS IQ](#install-skills-runner)). Cannot be combined with `--dev`. |
| `--dev` | — | Path to a local ossiq source checkout. Switches the installed skill and MCP server to run from that checkout instead of the PyPI release (see [Development mode](#install-skills-dev)). |

### What the command writes

All changes are made under your home directory; the command never touches the current project.

| Tool | Skill | MCP server |
|---|---|---|
| `claude` | writes `~/.claude/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.claude/mcp.json` |
| `codex` | writes `~/.codex/skills/ossiq/SKILL.md` | adds an `ossiq` entry to `mcpServers` in `~/.codex/mcp.json` |
| `copilot` | inserts a fenced block into `~/.copilot/copilot-instructions.md` | — (Copilot has no MCP server registry) |

The MCP entry registers a **local stdio server** — the tool launches OSS IQ's `mcp` command as a subprocess on your machine, through the same runner the skill uses. No remote service is involved, and nothing is sent anywhere beyond the registry and GitHub API calls a normal scan makes.

The command is **idempotent** — safe to re-run at any time (for example after switching development mode on or off):

- `mcp.json` is merged: only the `ossiq` entry under `mcpServers` is replaced; every other server entry is preserved.
- The Copilot instructions block is delimited by `<!-- ossiq-skill:start -->` / `<!-- ossiq-skill:end -->` markers. On re-run the block between the markers is replaced; the rest of the file — including your own instructions — is untouched.

(install-skills-runner)=
### How the skill runs OSS IQ

Every command in the installed skill, and the MCP entry, runs OSS IQ the way you ran
`install skills`. The command prints the result, for example
`the skill runs ossiq as: npx --yes @ossiq/cli`.

| You ran | Skill commands | MCP server |
|---|---|---|
| `uvx ossiq install skills`, or any PyPI install with `uvx` on `PATH` | `uvx ossiq …` | `<path to uvx> ossiq mcp` |
| `npx @ossiq/cli install skills`, or `ossiq` installed with `npm install -g` | `npx --yes @ossiq/cli …` | `<path to npx> --yes @ossiq/cli mcp`; on Windows `cmd /c npx --yes @ossiq/cli mcp` |
| a PyPI install without `uv`, or a standalone binary | `ossiq …` | `<absolute path to ossiq> mcp` |

A permanent install gets its channel's runner too: `uvx` uses a copy installed with
`uv tool install`, and both runners work from any directory. To write a bare `ossiq` instead,
pass `--via ossiq`. The `npx` entry needs `node` on the `PATH` your MCP client starts servers with.

(install-skills-login)=
### GitHub login

The command writes no GitHub token, either to `mcp.json` or to a config file. The MCP server uses
your [GitHub login](#auth) from the system secret store. Without a login, the first tool call
returns a login code for the agent to show you; see
[Log in through an MCP client](../how-to/github-login.md#log-in-through-an-mcp-client). The command
prints `auth login`, through the same runner, as the next step.

(install-skills-dev)=
### Development mode (`--dev`)

When you are working on ossiq itself, `--dev <path>` points every installed integration at your local checkout instead of the PyPI release:

```bash
ossiq install skills claude --dev ~/Projects/ossiq
```

Two substitutions are made:

- **MCP server** — registered as `uv run --directory <path> ossiq mcp`, so the server always runs your current working tree.
- **SKILL.md** — every command in the skill text runs `uvx --from <path> --no-cache ossiq`. The `--no-cache` flag makes `uvx` rebuild from source on each call, so the agent picks up your edits without a reinstall.

To switch back to the released package, re-run the command without `--dev`.

(auth)=
## `auth`

```bash
ossiq auth login [--no-wait | --resume]
ossiq auth status
ossiq auth logout
```

Logs in to GitHub with a one-time code, through the
[OAuth device flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow).
Scans can then make 5,000 GitHub API requests an hour instead of 60. For step-by-step instructions,
see [Log in to GitHub](../how-to/github-login.md).

| Command | What it does |
|---|---|
| `auth login` | Prints a URL and a one-time code. With a terminal, waits for approval and stores the login; without one, exits with status 75. Does nothing when a working login exists |
| `auth login --no-wait` | Prints the code and exits with status 75, even with a terminal |
| `auth login --resume` | Checks a login started earlier, by `auth login` or by a scan, and stores it once approved |
| `auth status` | Shows which token scans use, its source, GitHub account, scope, expiry and secret store. Always exits 0 |
| `auth logout` | Deletes the stored login from this machine. GitHub lists the authorization until you revoke it at [github.com/settings/applications](https://github.com/settings/applications) |

`auth` exit codes:

| Status | Meaning |
|---|---|
| `0` | Done: logged in, already logged in, logged out, or nothing to remove |
| `1` | Failed: no login to resume, login cancelled or expired, GitHub unreachable, or no secret store. The message names the cause and the next step |
| `75` | Waiting for approval. Approve the code on GitHub, then run `ossiq auth login --resume` or the next scan |

Which token a scan uses, where the login is stored and how long it lasts are in
[GitHub token](configuration.md#github-token).

(cmd-mcp)=
## `mcp`

```bash
ossiq mcp
```

Runs a local MCP server over stdio, for a coding agent to start as a subprocess. It takes no
options. [`install skills`](#install-skills) registers it for you, and
[MCP tools](export-and-agent-format.md#mcp-tools) lists the three tools it serves.

## Exit codes

Findings never change the exit code: a scan that reports CVEs still exits 0. To gate CI, check
the [JSON export](export-and-agent-format.md#json-export) yourself.

| Status | Meaning | Commands |
|---|---|---|
| `0` | The command finished | All |
| `1` | An error stopped the command. The message has a title and a hint. This includes "Security Data Incomplete" and a critical warning that blocks `add` | All |
| `2` | A usage error: an unknown option, or `--override` naming a package that is not in the project | All |
| `75` | A GitHub login is waiting for approval. A scan that shows a login code without a terminal exits this way too | `auth login`, scanning commands |

Pass the global `--traceback` option to print a full traceback in place of the error message.
