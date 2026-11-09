# Manual QA

Pre-release validation process for ossiq. One person, under 45 minutes.

## Structure

| File | Area | Cases |
|------|------|-------|
| [01-general.md](manual/01-general.md) | CLI basics, verbosity, ecosystem detection, helpers group | TC-G01–G08 |
| [02-console-scan.md](manual/02-console-scan.md) | `scan` + `package` commands, all package-state variations | TC-C01–C10 |
| [03-html-report.md](manual/03-html-report.md) | HTML scan output, dependency table, explorer | TC-H01–H05 |
| [04-solver.md](manual/04-solver.md) | HPDR solver correctness (solver always active) | TC-S01, TC-S03–S10 |
| [05-export.md](manual/05-export.md) | JSON export | TC-E01–E06 |
| [06-transitive-impacts.md](manual/06-transitive-impacts.md) | `--security`/`--full` flags, impact sub-rows, update command | TC-T01–T07 |
| [07-update-command.md](manual/07-update-command.md) | `update plan`/`execute`, `--pin-all`, `--rewrite-versions`, `--ignore`, UV specifier rewrite, NPM helpers | TC-U01–U21 |
| [10-llm-integration.md](manual/10-llm-integration.md) | `install skills`, the MCP server, the agent JSON contract, the MCP login challenge | TC-L01–L10 |
| [11-github-login.md](manual/11-github-login.md) | `auth login`/`status`/`logout`, the scan's login prompt, opt-outs, no secret store | TC-O01–O11 |
| [release-checklist.md](manual/release-checklist.md) | Abbreviated checklist for GitHub Issues | — |

## Release Process

1. Create a new GitHub Issue — paste the content of `release-checklist.md` as the body
2. Title it `Release QA — v[VERSION]`
3. Work through the checklist against the release branch
4. Link the issue in the release PR body
5. Close the issue when all items pass, then tag and merge

## Running the full suite

All commands run from the repo root:

```bash
# Unit tests first
uv run just qa

# Then work through each SOP file in order
```

## Update-Strategy Regression

### What it is and why it exists

`qa/update_strategies_regression.py` checks that each `--update-strategy` tier does what it
promises, on real registry data, through the real CLI:

| Tier | Promise checked |
|------|-----------------|
| `security` | Moves only packages with an exploitable CVE, by the smallest diff that clears it |
| `standard` | Moves on any drift, and `apply` writes nothing outside the declared constraint |
| `latest` | Widens constraints to reach the newest stable release, and `apply` writes the widening |
| `cutting-edge` | As `latest`, with prereleases admitted |

The projects live in `testdata/regression/update-strategies/<name>/`: a real manifest and lockfile
with deliberately old dependencies, plus an `expectations.toml` that records, per package and per
tier, what OSS IQ should recommend and why that package is in the fixture. Each project pins
`--cutoff-date`, so releases published later are invisible and the expected versions hold for
good. The script also pins the cooldown, passes an empty `--config`, `--no-stability` (GitHub
maintenance state can't be frozen) and `--no-probe-runtime` (the manifest's `engines` /
`requires-python` floor decides), and strips other `OSSIQ_*` variables from the environment. That
leaves two things that can move a result: OSS IQ's code, and the advisory databases.

### Running it

```bash
just qa-strategies                                   # every fixture, every tier, apply included
just qa-strategies --fixture npm --tier security     # narrow it down while debugging
just qa-strategies --skip-apply                      # no npm/uv needed
just qa-strategies --fresh                           # --no-cache: live registry + advisory data
just qa-strategies --ossiq-cmd "uvx --from dist/ossiq-X.Y.Z-py3-none-any.whl ossiq"   # a built wheel
```

It needs network, a GitHub login (`uv run ossiq auth login`, or `OSSIQ_GITHUB_TOKEN`), and `npm` /
`uv` on `PATH` unless you pass `--skip-apply`. A full run takes about a minute with a warm cache.
For a release, run it with `--fresh` against the built artifact.

For every fixture and tier it runs `export`, `status --format agent` and `plan` against a pristine
copy, then `apply --yes` against a throwaway copy, and checks:

- **Expectations**: each export verdict (recommended version, withheld, needs widening, escalated)
  matches `expectations.toml`.
- **Invariants** that hold for any project: `security` moves only on `exploitable_cve`; a withheld
  package has no target and isn't labelled "Update Immediately"; no tier recommends or applies a
  lower version than the tier below it; no prerelease below `cutting-edge`; no downgrade; the
  widening flag agrees with a reference range check (`packaging` for PEP 440, `univers` plus npm's
  prerelease rule).
- **Surfaces agree**: plan's update and widening tables, the agent JSON and the lockfile `apply`
  left behind all match the export, and `export`/`status`/`plan` don't touch the project.

### Reading the result

The console ends with one matrix per fixture: the target per tier, `^` when it needs widening, `!`
when the selector escalated past the tier's reach, and the cell's worst status. Every non-passing
check is listed below the matrix.

| Status | Meaning | Fails the run |
|--------|---------|---------------|
| `PASS` | As expected | no |
| `FAIL` | A regression, or an expectation that needs updating | **yes** (exit 1) |
| `XFAIL` | A failure in a cell marked `known_issue` | no |
| `XPASS` | A `known_issue` cell no longer fails: remove the marker | no |
| `WARN` | Advisory IDs for an installed version changed since the expectations were written | no |

Exit status 2 means the run couldn't start: invalid `expectations.toml`, `npm`/`uv` missing, or
a GitHub login still pending.

Logs go to `qa_logs/update_strategies/<timestamp>/`: `summary.log`, `report.json` (every
observation and check, for diffing two runs), and `<fixture>/<tier>/` with each command's
transcript plus the raw `export.json`.

**When something FAILs**, check for a WARN on the same package first. A new advisory against an
old release can legitimately change what `security` picks, and the summary calls that out. If
the advisories didn't change, it's the code. Either way, if the new behaviour is correct, update
`expectations.toml` (including `advisories`) in the same change.

### `expectations.toml`

```toml
ecosystem = "npm"            # npm | pypi
cutoff_date = "2024-12-20"   # --cutoff-date: releases after this are invisible
cooldown_period = 7          # --cooldown-period

# Why this package is in the fixture: the tier behaviour it exercises.
[packages.semver]
installed = "5.7.1"          # must match the lockfile
declared = "^5.7.1"          # must match the manifest
advisories = ["GHSA-c2qf-rxjj-qqgw"]   # CVE IDs export reports for `installed`
security = { recommended = "5.7.2" }
standard = { recommended = "5.7.2", known_issue = "why it currently fails" }
latest = { recommended = "7.6.3", widening = true }
cutting-edge = { recommended = "7.6.3", widening = true }
```

Each tier cell takes `recommended` (version string) or `withheld = true` (the tier admits no motive
for this package), plus `widening`, `escalation` (both default `false`) and an optional
`known_issue`. Unknown keys are an error, so a typo can't silently skip a check. Write the cell as
the behaviour *should* be. When it doesn't yet, add `known_issue` instead of recording the bug as
expected. `tests/test_update_strategies_regression.py` loads every fixture offline as part of
`just qa`, so a fixture edited without its expectations fails CI before anyone runs the
regression.

### Adding a package or a fixture

Prefer packages without dependencies of their own, so a difference between tiers comes from the
strategy alone. Pick a `cutoff_date` that makes the case you need visible. A prerelease must be
older than `cooldown_period` at the cutoff, or the cooldown holds it back.

To get a lockfile with old versions installed under a range: declare exact versions, lock, then
relax the manifest to the ranges you want and lock again. Both npm and uv keep a locked version
that still satisfies the new range:

```bash
npm install --package-lock-only --ignore-scripts   # package.json with exact versions
# edit package.json to ranges
npm install --package-lock-only --ignore-scripts

uv lock                                            # pyproject.toml with == pins
# edit pyproject.toml to ranges
uv lock
```

Don't use uv's `--exclude-newer` for this: it ends up in `uv.lock`, where OSS IQ treats it as a
release cutoff the installer enforces. Then run `just qa-strategies --fixture <name> --keep-workdirs`
and write the expectations from the matrix, after checking each value against the registry
yourself. The matrix shows what OSS IQ does, not what it should do.

---

## Agent Dependency-Freshness Experiment (GH-174)

### What it is

`qa/agent_freshness/` measures how stale, vulnerable or made-up the versions are when a coding
agent writes a manifest, and whether installing OSS IQ's skill and MCP server changes that. It runs
Claude Code on 4 prompts in 2 arms, 3 times each, with two models: `opus` (Claude Opus 5.5) and
`sonnet` (Claude Sonnet 5.5). Both use the CLI's default effort. That is 24 runs per model.

| Arm | What the agent has beyond its defaults |
|-----|-----------------------------------------|
| `baseline` | nothing |
| `ossiq` | the shipped ossiq skill and MCP server, with OSS IQ's default settings (a 7-day cooldown) |

Each prompt asks for a feature in a small starter project and never mentions dependencies,
packages, installs or versions. The agent picks them as a side effect of getting the feature to
work, which is the moment OSS IQ is meant to gate. A prompt is the ecosystem's preamble, the
request and a closing sentence, all in `experiment.toml`. The closing sentence is always: "Check
that it works by running it, and leave the project ready for a teammate to clone and run."

| Task | Ecosystem | Request |
|------|-----------|---------|
| `T1` | PyPI (uv) | Make `main.py` a web service with user accounts: register with an email and a password, log in for a session token, and a `/me` route that rejects requests without a valid token. |
| `T2` | PyPI (uv) | Add `report.py`, which reads an Excel `.xlsx` file with the columns date, region and amount and prints the total per region for each month. |
| `T3` | npm | Turn `src/index.js` into an HTTP server with `POST /photos`, which accepts a PNG or JPEG upload of at most 2 MB, saves it in `./uploads` and answers with the file name. |
| `T4` | npm | Add `npm run backup -- <file>`, which uploads the file to the S3 bucket named in `S3_BUCKET` and prints the object key. |

The tasks are meant to probe different checks. `T1` needs several packages at once. `T1` and `T2`
have older packages that are still popular. `T4` has a package that releases almost daily.

Each run is a throwaway container (`qa/agent_freshness/Dockerfile`) with a copy of a starter
project (`qa/agent_freshness/starters/`, which declares no dependencies) and a fresh HOME, so runs
share no memory. Never mount your own `~/.claude`: if the ossiq skill is installed there, it
contaminates the baseline arm.

`eval.py` scores each manifest against npm, PyPI and OSV directly, without importing ossiq, because
OSS IQ can't be both an arm and the judge. For every declared dependency it records, as of the
run's start:

- whether the name exists, and whether any release matches the pin
- whether the pin is exact or a range
- days and major versions behind the newest stable release
- whether the package or version is deprecated, yanked, archived or Inactive
- OSV advisories against the pinned version

It also locks each manifest from scratch (`uv lock`, or `npm install --package-lock-only`) on a copy
without the agent's lockfile. The lock runs in the experiment image, never on the host, because
resolving can build an sdist and so run code from a package the agent picked. A fresh manifest that
doesn't resolve is worse than a stale one that does.

The result is counts, not statistics. Three repeats show whether output varies; they can't show
that one arm is significantly better.

### Running it

Credentials go in the environment and never into a file in the repo:

- `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or `ANTHROPIC_API_KEY`
- `OSSIQ_GITHUB_TOKEN` for the ossiq arm

```bash
uv run just qa                                   # unit tests, including this experiment's
just exp-build                                   # image; re-run after changing src/ or the CLI pin
just exp-run --smoke                             # 4 cells (2 models x 2 arms): the model answers, only ossiq sees OSS IQ
just exp-run --batch pilot --tasks T1,T3 --reps 1
just exp-eval --batch pilot                      # then read the transcripts against the scores
git commit qa/agent_freshness/experiment.toml   # freeze the prompts and models
just exp-run --batch main-opus --models opus     # 24 runs; re-run the same command to resume
just exp-run --batch main-sonnet --models sonnet
just exp-eval --batch main-opus                  # the same day, so registry data matches the runs
just exp-eval --batch main-sonnet
```

Fix every smoke failure before the pilot, and leave pilot runs out of the results. A run counts as
finished when the agent writes its closing `result` event or hits the timeout. Anything else is
marked `failed` and retried the next time you run the same command. That covers a killed container
and an empty transcript.

A batch records the sha256 of `experiment.toml` in `batch.json` and refuses to continue once it
changes, so a changed prompt or model list means a new batch. Run both arms of a batch on the same
day: the run order interleaves them, so they see the same registry.

The prompt reaches the agent on stdin. As an argument it would appear in the agent's own process
arguments, so an agent that cleans up a test server with `pkill -f main.py` would kill itself.

Run each model as its own batch and compare the two reports. `summary.md` and `summary.html` group
by arm, so one batch holding both models would pool them.

### Reading the result

Everything lands in `qa_logs/agent_freshness/<batch>/`:

| File | Contents |
|------|----------|
| `batch.json` | git sha, image id, `claude` and ossiq versions, the frozen experiment |
| `<run_id>/` | `workspace/` (what the agent wrote), `transcript.jsonl`, `stderr.log`, `meta.json`, `resolve.json` (the lock command, exit code and output) |
| `runs.csv` | one row per run: pins, worst lag, CVE and deprecation counts, names and versions not found, whether it resolves, OSS IQ use, cost |
| `pins.csv` | one row per declared dependency |
| `summary.md` | per arm: pins, inexact pins, median and max days behind, pins with CVEs, deprecated, not found, resolves, OSS IQ use; then the 10 worst pins |
| `summary.html` | the same tables with two charts: days behind per pin (one dot each, a median line per arm), and the share of pins or runs hit by each problem. Open it in a browser; it has no script and no external files |
| `registry/` | the npm, PyPI and OSV answers the scores used; `--refresh` fetches them again and re-runs the locks |

Check these before drawing a conclusion:

- **Did the ossiq arm use OSS IQ?** `ossiq_used` and `ossiq_skill_used` in `runs.csv` say so. A
  run that ignored the skill is a finding about the skill, so report it and don't drop it.
- **Did OSS IQ answer?** OSS IQ needs a manifest before it can evaluate a package. In an empty
  directory, `ossiq info` and the MCP tool fail with "Unable to identify Package Manager". That is
  why each run starts from a starter project. `ossiq_no_project` marks runs where OSS IQ still found
  none; expect zero. The npm starter has no lockfile on purpose, because OSS IQ treats an npm
  lockfile with no dependencies as a parse error.
- **Lag is not the headline.** The prompts don't ask for pins, so an install resolves to the newest
  release and the baseline's lag is near zero. OSS IQ's solver penalizes versions younger than its
  cooldown (7 days by default), so a little lag in the ossiq arm is expected, not a defect. The
  `not exact` column is high in both arms and says little. Read the package choices in `pins.csv`
  and the CVE, deprecated and not-found counts.
- **Name the limits:** two models, one date, 4 prompts and 3 repeats. Newer models may already pin
  recent versions, and that is a result too.

---

## Automated Matrix

### What it is and why it exists

`just qa` runs against synthetic `testdata/` and can't catch what only the real CLI, the real
registries and the real package managers produce. `qa/smoke_matrix.py` automates the cases from
`qa/manual/` that don't need a browser, a person or a GitHub login: it runs `ossiq` against tiny
projects (one or two dependencies, locked at an old version) and checks what it printed and what it
left in the manifest, lockfile and export.

Every step is one throwaway Docker container (`qa/Dockerfile`: Node 22, Python 3.12, uv, ossiq from
this checkout). The host only copies files and reads results, so `npm install`, `uv sync` and sdist
builds never run on your machine, and each case gets a fresh HOME, so nothing from `~/.claude` or
`~/.config/ossiq` leaks in.

```bash
just qa-matrix                                   # build the image, then run every case (about a minute)
just qa-matrix --cases npm-security,uv-standard  # a few cases
just qa-matrix --dry-run                         # list the cases and their commands
just qa-matrix --parallel 1                      # if "database is locked" shows up in a log
```

`OSSIQ_GITHUB_TOKEN` is optional. Without it GitHub data is rate-limited and some maintenance
signals are missing; the cases don't depend on them. It is handed to docker by name, so its value is
never in a command line or a log. Exit status: 0 when no case failed, 1 when one did, 2 when the run
couldn't start (invalid `cases.toml`, unknown case id, image not built).

### Why the assertions look the way they do

Registries move, so a case says how far a result must have got, not what it is today:

| Check | Example | Use for |
|-------|---------|---------|
| `at_least` / `below` | `locked = { semver = { at_least = "5.7.2", below = "6.0.0" } }` | anything a newer release can change |
| `equals` | `locked = { left-pad = { equals = "1.3.0" } }` | releases that cannot change: left-pad 1.3.0 is the last left-pad, uuid 3.4.0 the last 3.x, attrs 21.1.0 is yanked for good, or a version the step forces (`--override idna==3.7`) |
| `pinned` / `changed` | `declared = { idna = { equals = ">=3.0" } }` | what `apply` did to the manifest |

### What every step checks

Without being asked: the exit code (`rc`, default 0, or `"nonzero"`); no Python traceback;
`status`, `plan`, `export` and `info` leave the manifest, lockfile and `.ossiq.yaml` byte-identical;
and after `apply` or `add` every direct dependency is locked at a version its declared spec admits.
A case adds `stdout` / `stderr` / `output` text rules (`has`, `lacks`, `once`, `json`), `locked` and
`declared` version rules, an export to read (`report` + `packages`), and `files` under the case
directory (`workspace/...`, `home/...`). A case stops at its first failing step.

### Projects (`qa/smoke/projects/`)

| Project | Declares | Why |
|---------|----------|-----|
| `npm-semver` | `semver ^5.7.1` (locked 5.7.1), dev `ms ^2.0.0` (2.0.0) | a CVE, a major to widen into, a dev dependency |
| `npm-deprecated` | `left-pad ^1.3.0`, `uuid ^3.4.0` | both deprecated; left-pad has no successor |
| `npm-transitive` | `debug ^2.6.9`, which brings `ms 2.0.0` | a transitive package to `--override` |
| `uv-ranges` | `idna>=3.0` (3.4), `urllib3~=1.26.5` (1.26.5) | a bare `>=` is lockfile-only, a `~=` is rewritten |
| `uv-pinned` | `attrs==23.1.0` | `==` pins and `--rewrite-versions` |
| `uv-yanked` | `attrs==21.1.0` | a yanked release |
| `uv-no-lock` | `idna>=3.0`, no lockfile | a PEP 621 project before its first lock |
| `pip-classic` | `requirements.txt` with `idna==3.4` | pip detection |
| `mixed` | an npm and a uv project in one directory | `--registry-type` |
| `empty` | nothing | "Unable to identify Package Manager", and the `install` / `auth` commands |

To add a project, write the manifest with exact versions, lock it in the image, relax the versions
to the ranges you want and lock again (both npm and uv keep a locked version that still satisfies
the new range), then check each claim against the registry before writing it into a case:

```bash
docker run --rm -v "$PWD/qa/smoke/projects/NAME":/work -w /work ossiq-qa \
  sh -c 'npm install --package-lock-only --ignore-scripts'   # or: uv lock
```

Don't use uv's `--exclude-newer`: it ends up in `uv.lock`, where OSS IQ reads it as a release
cutoff. `tests/test_smoke_matrix.py` checks that every project's lockfile still satisfies its
manifest, and that every case in `cases.toml` is valid, as part of `just qa`.

### Adding a case

Add a `[[cases]]` table to `qa/smoke/cases.toml` with an `id`, a `project`, a `why` and `covers` (the
SOP ids it automates). Unknown keys are an error, so a typo can't silently skip a check. Write the
expectation as the behaviour *should* be; when it isn't yet, add `known_issue = "GH-NNN: ..."`: the
case reports XFAIL instead of failing, and XPASS once it passes so the marker can go.

### Reading the result

```
qa_logs/smoke/<UTC timestamp>/
  summary.log     one line per case; the failing checks are indented under it
  run.json        git sha, dirty flag, image id, ossiq version, every case's status and problems
  <case>/
    workspace/    the project as the last step left it (node_modules and .venv are removed)
    home/         the container's HOME: .claude/, .copilot/, ...
    01.log, ...   one transcript per step: the docker command, exit code, stdout, stderr
```

| Status | Meaning | Fails the run |
|--------|---------|---------------|
| `PASS` | every step passed | no |
| `FAIL` | a check failed: read the indented lines, then `<case>/NN.log` | **yes** |
| `XFAIL` | a case marked `known_issue` still fails | no |
| `XPASS` | a case marked `known_issue` passes: remove the marker | no |

When something fails, re-run that case alone, then replay its command by hand from the transcript's
`CMD:` line. The image holds a snapshot of the checkout, so rebuild it (`just qa-build`) after
changing `src/`.

### Still manual

Not automatable here: everything in a browser (TC-H02, H03, H07-H13), a live agent (TC-L09), the
GitHub device flow and keyring (TC-L10, O02-O05, O07, O09, O11), forcing an `apply` to fail for the
rollback check (TC-U21), the published npm package (TC-L12), constraint widening that needs a major
release that doesn't exist yet (TC-C11), `apply` on a pip-classic project (it would `pip install`
into the container's Python), and the repo-root runs of TC-T04 to T06 (the security tier is covered
by the tier cases).
