# Release QA — v[VERSION]

> Create a GitHub Issue with this content before each release. Title: `Release QA — v[VERSION]`.
> Link the issue in the release PR. Close only after all items pass.

## Release branch / tag
<!-- e.g. feature/GH-76 or v0.5.0 -->

---

## 01 — General ([details](01-general.md))

- [ ] TC-G07: `uv run just qa` — all tests pass
- [ ] TC-G01: `--version`, `--help`, `status --help`, `html --help`, `plan --help`, `apply --help` all work; `status --help` lists `--security`, `--ignore` but NOT `--presentation`; `html --help` lists `--output`, `--security`, `--ignore` but NOT `--presentation`; `plan --help` lists `--pin-all`, `--rewrite-versions`, `--override`, `--ignore` (NOT `--script`); `apply --help` lists `--yes`, `--pin-all`, `--rewrite-versions`, `--override`, `--ignore`
- [ ] TC-G03/G04: Ecosystem auto-detected (PyPI and npm)
- [ ] TC-G02: `--verbose` shows settings panel; without it, panel is absent
- [ ] TC-G09: values from `~/.config/ossiq/config` are picked up (visible in `--verbose` settings panel)
- [ ] TC-G10: `--config <custom-file>` loads a custom config file; nonexistent path shows clean error (no traceback)
- [ ] TC-G11: precedence — env var overrides config file; CLI flag overrides env var

## 02 — Console Scan ([details](02-console-status.md))

- [ ] TC-C01: PyPI scan renders table with all expected columns
- [ ] TC-C02: npm scan renders table
- [ ] TC-C03: `--production` flag excludes dev dependencies
- [ ] TC-C04: Yanked packages show `[YANKED]` in Installed column
- [ ] TC-C05: Deprecated npm packages show `[DEPRECATED]`
- [ ] TC-C09: `info` command renders detail view for a known package
- [ ] TC-C10: `info` command on unknown package shows error (no traceback)
- [ ] TC-C11: pip-classic library scan shows "Constraint widening opportunities" section for range-constrained deps with newer majors available

## 03 — HTML Report ([details](03-html-report.md))

- [ ] TC-H00: `html --help` lists `--output`, `--security`, `--ignore`; `--presentation` is absent
- [ ] TC-H01: `ossiq html --output=reports/test_report.html <path>` generates file without crash
- [ ] TC-H02: Page loads in browser, main table renders, no JS errors
- [ ] TC-H03: Dependencies explorer opens detail panel on click
- [ ] TC-H07: Transitive Dependency Explorer renders D3 tree (nodes visible, no JS error, no blank canvas)
- [ ] TC-H10: Click Super Node navigates into subtree; breadcrumb appears; back edge returns to parent

## 04 — Solver ([details](04-solver.md))

- [ ] TC-S01: Recommended column appears in scan output on PyPI project with pending updates
- [ ] TC-S03: Constrained packages recommended within their declared range; pinned packages have empty Recommended
- [ ] TC-S04: Yanked versions never appear as recommendations
- [ ] TC-S06: npm solver produces valid semver recommendations
- [ ] TC-S09: No crash/traceback on any scan run, including conflict scenarios

## 05 — Export ([details](05-export.md))

- [ ] TC-E02: JSON export produces valid file with `schema_version`, `packages`, and per-package fields
- [ ] TC-E04: npm JSON export has `registry: "npm"`

## 06 — Transitive Impacts ([details](06-transitive-impacts.md))

- [ ] TC-T01: `--security`, `--ignore` in `status --help` (no `--presentation`, no `--full`); `--security`, `--pin-all`, `--ignore` in `plan --help`
- [ ] TC-T02: `status` shows `↳ also updates:` sub-rows under at least one recommendation
- [ ] TC-T03: `status` (no flags) shows all packages including up-to-date ones with no CVEs; table is non-empty on a fully-current project
- [ ] TC-T07: `plan` renders without crash and shows transitive impact sub-rows (`↳ also updates:` / `✗ no actionable update found`)

## 07 — Plan Command: --pin-all, --rewrite-versions, --override, --ignore ([details](07-plan-apply-command.md))

- [ ] TC-U01: `--ignore` on status — ignored package has no recommendation; still visible in table
- [ ] TC-U02: `--ignore` on plan — ignored package absent from plan output
- [ ] TC-U05: UV NARROWED (`~=`) — `apply` rewrites the `pyproject.toml` specifier to `~=<new_version>`, preserving the operator
- [ ] TC-U06: UV DECLARED (`>=`) — `apply` leaves the `pyproject.toml` specifier untouched; `uv.lock` still resolves to the recommended version via `uv lock --upgrade-package`
- [ ] TC-U07: UV `--pin-all` — `apply --pin-all` rewrites every updated direct dependency's specifier to `==<ver>` regardless of original operator
- [ ] TC-U08: NPM `apply` — rewrites direct dependency specifiers in `package.json`, adds transitive-only changes to `overrides`, and runs `npm install --ignore-scripts`
- [ ] TC-U14: `ossiq plan --script` rejected with "No such option" (flag removed in GH-94; script generation and `ossiq helpers` were dropped — `apply` executes updates in-process)
- [ ] TC-U15: `--override pkg==version` on `plan`/`apply` — direct dependency gets its specifier rewritten to the exact forced version; a transitive dependency gets a persistent `override-dependencies` (uv) / `overrides` (npm) entry that survives future scans

## 08 — Gated Package Add

- [ ] TC-A01: `add --help` lists `--version`, `--force`, `--registry-type`
- [ ] TC-A02: `ossiq add requests testdata/pypi/uv` shows health panel (drift, CVEs, health) then prompts for confirmation; entering `n` exits without installing
- [ ] TC-A03: `ossiq add <critically-unhealthy-package>` blocks install and shows warning; exit code non-zero
- [ ] TC-A04: `ossiq add <critically-unhealthy-package> --force` proceeds past warning to confirmation prompt
- [ ] TC-A05: `ossiq add requests --version 2.28.0 testdata/pypi/uv` shows the fixed version in the install spec, not the solver recommendation

## 09 — Automated Matrix ([details](../README.md#automated-matrix))

- [ ] TC-M01: `just qa-matrix` exits 0; `qa_logs/summary.log` final `Results:` line shows `0 failed` (SKIPs acceptable)

## 10 — LLM Integration: `install skills` & MCP Server ([details](10-llm-integration.md))

- [ ] TC-L01: `install skills --help` lists `--dev` and `--via` (no `--github-token`); unknown tool shows clean error, non-zero exit
- [ ] TC-L02: `install skills claude --dev $(pwd)` writes `~/.claude/skills/ossiq/SKILL.md` (dev path substituted) and upserts `ossiq` into `~/.claude/mcp.json` preserving other server entries; re-run is idempotent
- [ ] TC-L03: `install skills` asks for no token, writes none to `mcp.json` or `~/.config/ossiq/config`, and prints `<runner> auth login` as the next step
- [ ] TC-L04: copilot install idempotent — two runs leave one `ossiq-skill:start` block; user content preserved
- [ ] TC-L05: MCP stdio handshake — `initialize` + `tools/list` return valid JSON-RPC listing `ossiq_evaluate_dependency` and `ossiq_evaluate_updates`; notifications get no reply; stdout is JSON-only
- [ ] TC-L06: MCP `tools/call ossiq_evaluate_dependency` returns add-decision JSON; unknown package → `isError`, server stays alive
- [ ] TC-L07: MCP `tools/call ossiq_evaluate_updates` returns `updates` list; unknown tool name → `isError`, no crash
- [ ] TC-L08: `info <pkg> <path> --format agent` and `status <path> --format agent` emit pure valid JSON matching the SKILL.md contract
- [ ] TC-L09: (optional, live) after install, Claude Code `/mcp` shows ossiq connected; skill triggers on an "is it safe to add X" prompt
- [ ] TC-L10: logged out, the first MCP `tools/call` returns the login challenge (`isError: false`, `_meta.auth_status: PENDING_USER_ACTION`, no `device_code`); a second call returns the same code; after approval the call scans
- [ ] TC-L11: `install skills` writes `uvx ossiq` commands and a uvx MCP entry by default; `--via npx` / `--via ossiq` switch both; `--via` with `--dev` exits 1
- [ ] TC-L12: `npx --yes @ossiq/cli@X.Y.Z install skills claude` writes `npx --yes @ossiq/cli` commands, no `uvx`, and an npx MCP entry (not an `_npx` cache path)

## 11 — GitHub Login ([details](11-github-login.md))

- [ ] TC-O01: `--help` lists `auth`; `auth login --help` lists `--no-wait`, `--resume` and exit status 75
- [ ] TC-O02: `auth login` in a terminal shows the URL and code, waits, and prints `✓ Logged in as @<you>` after approval; a second run says `Already logged in`
- [ ] TC-O03: `auth status` shows `Source: GitHub login (system keyring)`, `Scope: none (public data only)`, an expiry ~8 h ahead, and the platform's store; no token in the output
- [ ] TC-O04: `auth login --no-wait` exits 75; `--resume --no-wait` before approval exits 75 with the same code; `--resume` after approval exits 0; `--resume` with nothing pending prints `Nothing To Resume`, exit 1
- [ ] TC-O05: logged out, a scan with stderr redirected writes the code to stderr and exits 75 with stdout empty; after approval the next scan runs authenticated
- [ ] TC-O06: `OSSIQ_GITHUB_AUTH=off` and `CI=true` scans show no login code, run unauthenticated and exit 0
- [ ] TC-O07: `OSSIQ_GITHUB_TOKEN` and `GITHUB_TOKEN` outrank the login in `auth status`
- [ ] TC-O08: `auth logout` removes the login and prints the revoke hint; a second logout prints `Nothing to remove`, exit 0
- [ ] TC-O09: after revoking OSS IQ on github.com, the next scan discards the login and shows a new code
- [ ] TC-O10: in a container, `auth status` exits 0 with `Storage: none available`; `auth login` fails at once with `Credential Store Unavailable`, exit 1
- [ ] TC-O11: (optional, macOS) a rebuilt binary raises one Keychain dialog and the `Waiting for the system keyring...` line; Always Allow makes later runs silent


## Notes
<!-- Anything unexpected observed during QA -->
