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

The unit test suite (`uv run just qa`) runs against synthetic `testdata/` fixtures with
predictable, hand-crafted manifests. It cannot catch problems that only appear with real
package metadata: solver edge cases on non-trivial constraint graphs, API shape regressions,
apply correctness against real lockfile structures, or crashes on packages with unusual
metadata.

`qa/smoke-matrix.sh` fills that gap. It runs the full
`status → export → plan → apply → re-export` pipeline against 20 real-world repos at pinned
git tags, fetching only the manifest files ossiq actually reads (no full repo clones). It is
the last gate before a release.

**What a PASS means for a target:**
- ossiq can parse the manifest at that tag without crashing
- The solver produces a recommendation (or correctly produces none)
- `apply --yes` writes updated manifests without crashing or corrupting them
- A post-apply export reflects the applied state consistently

**What a SKIP means:** the required manifest files were absent at the pinned tag, or the
export returned 0 packages. Skips are not failures — they indicate the target has nothing
testable at that tag.

---

### Architecture

```
Host machine
│
├── justfile (just qa-build / just qa-matrix)
├── qa/Dockerfile          → image: ossiq-qa
├── qa/smoke-matrix.sh     → orchestration script (runs inside container)
└── qa_logs/               ← bind mount; logs written here by the container

Docker container (ossiq-qa, non-root qarunner UID 1000)
│
├── /app          read-only bind mount ← ossiq source (pyproject.toml, src/, ...)
├── /workspace    named volume         ← per-target manifest dirs (cleaned after each PASS)
├── /cache        named volume         ← ossiq SQLite HTTP cache (persists across runs)
└── /qa_logs      bind mount           → qa_logs/ on host
```

**ossiq is never installed in the image.** It is invoked via `uv run hatch run ossiq`
from `/app`, using the source mount. The uv venv is written to
`/home/qarunner/.venv` (set via `UV_PROJECT_ENVIRONMENT`) so the read-only `/app` mount
is never written to.

**Per-target flow inside the script:**
1. Parse target entry (`ecosystem|repo|tag|cutoff`)
2. Fetch manifest files from the GitHub Contents API (raw bytes, no clone)
3. Run the 9-step pipeline against the fetched workspace directory
4. Write `PASS`, `SKIP`, or `FAIL:stepNN` to `result.log`
5. On PASS: delete the workspace dir (logs are kept)
6. Accumulate counters; print summary; exit 1 if any FAIL

---

### Environment variables

All script behaviour is controlled through environment variables. The justfile recipe passes
these into the container via `-e`. Override any of them to change paths or inject credentials.

| Variable | Default (in container) | Purpose |
|----------|----------------------|---------|
| `OSSIQ_GITHUB_TOKEN` | *(required)* | Token for `gh api` manifest fetches and `ossiq --github-token`. Needs read-only access to public repos. |
| `OSSIQ_QA_WORKSPACE` | `/workspace` | Directory where per-target manifest dirs are created. Mapped to named volume `ossiq-qa-workspace`. |
| `OSSIQ_QA_LOGS` | `/qa_logs` | Log root. Mapped to `./qa_logs/` on the host so logs survive container exit. |
| `OSSIQ_QA_CACHE` | `/cache/ossiq_cache.sqlite3` | ossiq's SQLite HTTP cache. Mapped to named volume `ossiq-qa-cache` so expensive registry calls are reused across runs. |

The script also bridges `OSSIQ_GITHUB_TOKEN → GH_TOKEN` internally so the `gh` CLI
(which reads `GH_TOKEN`, not `OSSIQ_GITHUB_TOKEN`) picks up the same token without extra
configuration.

---

### Justfile recipes

```bash
just qa-build    # build the ossiq-qa Docker image (run once; re-run after Dockerfile changes)
just qa-matrix   # run the full 20-target matrix inside Docker
```

`qa-build` runs:
```bash
docker build -f qa/Dockerfile -t ossiq-qa .
```

`qa-matrix` runs:
```bash
mkdir -p qa_logs
docker run --rm \
    -v "$(pwd)":/app:ro \
    -v ossiq-qa-workspace:/workspace \
    -v ossiq-qa-cache:/cache \
    -v "$(pwd)/qa_logs":/qa_logs \
    -e OSSIQ_GITHUB_TOKEN \
    --user 1000:1000 \
    ossiq-qa \
    bash /app/qa/smoke-matrix.sh
```

The named volumes (`ossiq-qa-workspace`, `ossiq-qa-cache`) are created automatically by
Docker on first use. To reset the cache between runs: `docker volume rm ossiq-qa-cache`.

---

### Reading logs

After a run, logs land in `./qa_logs/` on the host:

```
qa_logs/
  summary.log                         # chronological PASS/SKIP/FAIL/WARN for all targets
  npm_express_4.18.2/
    result.log                        # single word outcome: PASS | SKIP | FAIL:step07
    03_status.log                     # ossiq status stdout+stderr
    04_export.log                     # ossiq export stdout+stderr
    04_pre_export.json                # JSON export before apply
    06_plan.log
    07_apply.log
    07b_npm_install.log               # npm --package-lock-only (npm targets only)
    08_status_post.log
    09_export.log
    09_post_export.json               # JSON export after apply
    09_comparison.json                # [{package, expected, got, ok}] diff
```

To triage a failure:

```bash
# What failed and why
grep FAIL qa_logs/summary.log

# Which step failed for a specific target
cat qa_logs/npm_express_4.18.2/result.log

# Read the step log
cat qa_logs/npm_express_4.18.2/07_apply.log

# Inspect the version comparison
jq '.[] | select(.ok == false)' qa_logs/npm_express_4.18.2/09_comparison.json
```

---

### Adding a target

Add a pipe-separated entry to the `TARGETS` array in `qa/smoke-matrix.sh`:

```bash
"ecosystem|owner/repo|tag|cutoff_date"
```

Rules:
- `ecosystem`: `npm` or `pypi`
- `tag`: the exact git tag string as it appears on GitHub (e.g. `v4.18.2` or `4.18.2`)
- `cutoff_date`: ISO date (YYYY-MM-DD), approximately tag release date + 12 months — this
  is the date ossiq treats as "today" when computing recommendations. Set it too close to
  the tag and there will be no recommendations (nothing is outdated yet); too far and
  all packages will look ancient.
- For npm: the repo must have **both** `package.json` and `package-lock.json` at the tag.
  Many repos only have `package.json` in VCS — those will SKIP.
- For pypi: the repo needs `uv.lock`, `requirements.txt`, or both alongside `pyproject.toml`.
  A bare `pyproject.toml` with no lockfile will SKIP.

### Skipped targets

A SKIP is not a test failure. It means one of:
- Required manifest files were not found at the pinned tag (the repo didn't commit them)
- Export returned 0 packages (manifest parsed but empty — e.g. a meta-package)

Skips are logged in `summary.log` with a reason and counted separately in the final summary.
If a target you expect to pass is SKIP-ing, check the tag name spelling and whether the
lockfile exists at that ref on GitHub.
