# Manual QA

Pre-release validation process for ossiq-cli. One person, under 45 minutes.

## Structure

| File | Area | Cases |
|------|------|-------|
| [01-general.md](manual/01-general.md) | CLI basics, verbosity, ecosystem detection, helpers group | TC-G01–G08 |
| [02-console-scan.md](manual/02-console-scan.md) | `scan` + `package` commands, all package-state variations | TC-C01–C10 |
| [03-html-report.md](manual/03-html-report.md) | HTML scan output, dependency table, explorer | TC-H01–H05 |
| [04-solver.md](manual/04-solver.md) | HPDR solver correctness (solver always active) | TC-S01, TC-S03–S10 |
| [05-export.md](manual/05-export.md) | JSON and CSV export | TC-E01–E05 |
| [06-transitive-impacts.md](manual/06-transitive-impacts.md) | `--security`/`--full` flags, impact sub-rows, update command | TC-T01–T07 |
| [07-update-command.md](manual/07-update-command.md) | `update plan`/`execute`, `--pin-all`, `--rewrite-versions`, `--ignore`, UV specifier rewrite, NPM helpers | TC-U01–U21 |
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

**ossiq is never installed in the image.** It is invoked via `uv run hatch run ossiq-cli`
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
