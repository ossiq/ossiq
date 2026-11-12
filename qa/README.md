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

It needs network, a GitHub login (`uv run ossiq auth login`, or `OSSIQ_GITHUB_TOKEN` in the
environment or your ossiq config file), and `npm` / `uv` on `PATH` unless you pass `--skip-apply`.
A full run takes about a minute with a warm cache.
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

## Automated Matrix

### What it is and why it exists

`just qa` runs against synthetic `testdata/` and can't catch what only the real CLI, the real
registries and the real package managers produce. `qa/smoke_matrix.py` is the regression engine for
that: it automates the cases from `qa/manual/` that don't need a browser, a person or a GitHub
login. It runs `ossiq` against tiny projects (one or two dependencies, locked at an old version) and
checks what it printed and what it left in the manifest, lockfile and export. It covers `status`,
`plan`, `apply`, `add`, `export`, and `ossiq upgrade` (console, `--interactive` and the
`--format agent` loop a coding agent runs) on npm, pnpm and uv, plus pip and pylock projects, which
the CLI can scan but cannot always change.

Every step is one throwaway Docker container (`qa/Dockerfile`: Node 22, pnpm, Python 3.12, uv, ossiq
from this checkout). The host only copies files and reads results, so `npm install`, `uv sync` and sdist
builds never run on your machine, and each case gets a fresh HOME, so nothing from `~/.claude` or
`~/.config/ossiq` leaks in.

```bash
just qa-matrix                                   # build the image, then run every case (about 4 minutes)
just qa-matrix --cases npm-security,uv-standard  # a few cases
just qa-matrix --cases 'pnpm-*,*-upgrade-*'      # patterns work too
just qa-matrix --dry-run                         # list the cases and their commands
just qa-matrix --parallel 1                      # if "database is locked" shows up in a log
```

`OSSIQ_GITHUB_TOKEN` is optional. Without it GitHub data is rate-limited and some maintenance
signals are missing; the cases don't depend on them. When the environment doesn't set it, the runner
takes it from your ossiq config file. It is handed to docker by name, so its value is never in a
command line or a log. Exit status: 0 when no case failed, 1 when one did, 2 when the run
couldn't start (invalid `cases.toml`, unknown case id, image not built).

### Why the assertions look the way they do

Registries move, so a case says how far a result must have got, not what it is today:

| Check | Example | Use for |
|-------|---------|---------|
| `at_least` / `below` | `locked = { semver = { at_least = "5.7.2", below = "6.0.0" } }` | anything a newer release can change |
| `equals` | `locked = { left-pad = { equals = "1.3.0" } }` | releases that cannot change: left-pad 1.3.0 is the last left-pad, uuid 3.4.0 the last 3.x, attrs 21.1.0 is yanked for good, or a version the step forces (`--override idna==3.7`) |
| `pinned` / `changed` | `declared = { idna = { equals = ">=3.0" } }` | what `apply` did to the manifest |

### What every step checks

Without being asked: the exit code (`rc`, default 0, or `"nonzero"`); no Python traceback (so a
project's own failing test must not print one: see `uv-upgrade/check.py`); `status`, `plan`, `export`,
`info` and the upgrade subcommands that only read (`start`, `status`, `test`, `continue`, `finish`,
`changelog`) leave the manifest, lockfile and `.ossiq.yaml` byte-identical; and after `apply`, `add`,
`upgrade apply`, `rollback`, `skip` or `abort` every direct dependency is locked at a version its
declared spec admits. For pnpm the lockfile is `pnpm-lock.yaml`; for pip, which has none, it is the
`.venv` the step installed into.
A case adds `stdout` / `stderr` / `output` text rules (`has`, `lacks`, `once`, `json`), `locked` and
`declared` version rules, an export to read (`report` + `packages`), and `files` under the case
directory (`workspace/...`, `home/...`). A case stops at its first failing step.

### Projects (`qa/smoke/projects/`)

| Project | Declares | Why |
|---------|----------|-----|
| `npm-semver` | `semver ^5.7.1` (locked 5.7.1), dev `ms ^2.0.0` (2.0.0) | a CVE, a major to widen into, a dev dependency |
| `npm-deprecated` | `left-pad ^1.3.0`, `uuid ^3.4.0` | both deprecated; left-pad has no successor |
| `npm-transitive` | `debug ^2.6.9`, which brings `ms 2.0.0` | a transitive package to `--override` |
| `npm-lockstep` | `vue ^3.5.30` (3.5.30), with its exact-pinned `@vue/*` family | `@vue/server-renderer` peer-pins vue back; only vue owns its copy, so the old copy must not hold vue below the renderer's CVE fix |
| `uv-ranges` | `idna>=3.0` (3.4), `urllib3~=1.26.5` (1.26.5) | a bare `>=` is lockfile-only, a `~=` is rewritten |
| `uv-pinned` | `attrs==23.1.0` | `==` pins and `--rewrite-versions` |
| `uv-yanked` | `attrs==21.1.0` | a yanked release |
| `uv-no-lock` | `idna>=3.0`, no lockfile | a PEP 621 project before its first lock |
| `uv-extras` | `requests~=2.32.5` (2.32.5); extras `mkdocs-material~=9.7.1` (9.7.1), `idna~=3.4.0` (3.4) | `~=` ranges in extras; an extra whose newer releases need `requests` past its range |
| `uv-constrained` | `requests~=2.31.0` (2.31.0, brings `urllib3` 1.26.5), `packaging>=21.3` (21.3); `[tool.uv] constraint-dependencies` caps `urllib3<2`, `packaging<22`, `requests<2.33`, and `attrs<23` (not installed) | uv applies the caps to every lock, so no tier may recommend past one: a transitive cap that holds urllib3 on releases that all carry advisories (it stays put, and says why), a direct cap inside a looser range, a direct `~=` that has to widen under its cap, and an `add` under a cap |
| `pnpm-semver` | `semver ^5.7.1` (5.7.1), dev `ms ^2.0.0` (2.0.0) | the npm tier and flag cases on pnpm |
| `pnpm-transitive` | `debug ^2.6.9`, which brings `ms 2.0.0` | a transitive package to `--override` into `pnpm-workspace.yaml` |
| `pnpm-overridden` | `pnpm-semver` plus `overrides: semver: 5.7.1` in `pnpm-workspace.yaml` (recorded in the lockfile) | a user override the plan must hold back |
| `pip-classic` | `requirements.txt` with `idna==3.4` | pip detection |
| `pip-pinned` | `requirements.txt` with `idna==3.4`, `urllib3==1.26.5` | pip scan, `add`, and `apply` into a venv |
| `pip-constrained` | `requirements.txt` with `-c constraints.txt` and `idna>=3.4`; `constraints.txt` caps `idna<3.8` | pip intersects a `-c` range with every requirement: the scan takes 3.7 as installed and recommends nothing past the cap |
| `pylock` | `pyproject.toml` and `pylock.toml` with `idna>=3.0`, `urllib3~=1.26.5` | a project OSS IQ can scan but not change |
| `npm-upgrade`, `pnpm-upgrade` | `semver ^5.7.1` (CVE), `escape-string-regexp ^4.0.0`; `test.js` and `fix/test.js` | two upgrade steps: one that passes, one that breaks the test at the latest tier |
| `uv-upgrade` | `idna~=3.4` (CVE), `packaging~=21.3`; `check.py` and `fix/check.py` | the same two steps for uv |
| `mixed` | an npm and a uv project in one directory | `--registry-type` |
| `empty` | nothing | "Unable to identify Package Manager", and the `install` / `auth` commands |

### Upgrade cases

`ossiq upgrade` is checked on `npm-upgrade`, `pnpm-upgrade` and `uv-upgrade`, which share one shape.
Their first dependency has a CVE, so it is always step 1 (CVEs queue first). The second has none and
stays put at the standard tier, but at `--update-strategy latest` it moves to a release that breaks
the project's test (`escape-string-regexp` 5 is ES-module only, `packaging` 22 dropped
`LegacyVersion`): that is step 2. The mended test is in `fix/`. A step first installs the project,
because `upgrade start` runs the test command before it changes anything.

The `*-upgrade-agent-loop` cases are the scripted stand-in for an LLM: they call each subcommand with
`--format agent`, check the JSON and the exit status (0, or 3 when the step needs attention), copy
`fix/` over the test with an `sh -c` step the way an agent would edit the code, and run `upgrade test`
until it passes. No model runs, so the cases are free and repeatable. A real agent session
(TC-L09) stays manual.

| Case | What it checks |
|------|----------------|
| `*-upgrade-happy` | A one-step session: start, apply, tests pass, continue, session gone |
| `*-upgrade-agent-loop` | The agent contract end to end, including `continue` and `finish` refusing on a failing step |
| `*-upgrade-rollback-skip` | A failing step rolled back, applied again, then skipped with a reason; the kept step stays |
| `*-upgrade-abort` | `abort` restores the manifest and lockfile after a kept step and a failing one |
| `*-upgrade-interactive` | The menu drives a session from two keystrokes |
| `uv-constrained-upgrade` | A session queues no move past a `[tool.uv]` cap, so `upgrade apply` installs instead of being refused |
| `upgrade-menu`, `upgrade-guards`, `upgrade-config`, `upgrade-scope`, `upgrade-no-tests`, `upgrade-nothing`, `upgrade-baseline-fails`, `upgrade-no-session`, `upgrade-corrupt`, `upgrade-changelog` | What does not depend on the package manager, on `npm-upgrade` |
| `pip-upgrade-refused`, `pylock-scan` | pip and pylock projects are refused cleanly and no session is left behind |

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

Not automatable here: everything in a browser (TC-H02, H03, H07-H13), a live agent (TC-L09, the
`*-upgrade-agent-loop` cases replay the contract but no model runs), the GitHub device flow and
keyring (TC-L10, O02-O05, O07, O09, O11), the published npm package (TC-L12), constraint widening
that needs a major release that doesn't exist yet (TC-C11), the "versions to install changed since
the preview" refusal of `upgrade apply` (a release has to appear between two commands), the `w` key
of the upgrade menu (it opens a browser), and the repo-root runs of TC-T04 to T06 (the security tier
is covered by the tier cases).

### Known failures

`pip-apply` is marked `known_issue`: `ossiq apply` on a pinned `requirements.txt` hands pip a
constraints file (`idna==3.x`) next to `idna==3.4` and pip answers `ResolutionImpossible`, which OSS
IQ reports as an unexpected error. `pip-add` installs into the venv but leaves `requirements.txt`
unchanged; the case checks only the venv. `pnpm add ms@2.1.3` saves `2.1.3` where `npm install ms@2.1.3`
saves `^2.1.3`: OSS IQ keeps what the package manager wrote, so the pnpm cases check that the package
was written and locked, not its range.
