# Release QA — v[VERSION]

> Create a GitHub Issue with this content before each release. Title: `Release QA — v[VERSION]`.
> Link the issue in the release PR. Close only after all items pass.

## Release branch / tag
<!-- e.g. feature/GH-76 or v0.5.0 -->

---

## 01 — General ([details](01-general.md))

- [ ] TC-G07: `uv run just qa` — all tests pass
- [ ] TC-G01: `--version`, `--help`, `status --help`, `html --help`, `plan --help`, `apply --help` all work; `status --help` lists `--security`, `--ignore` but NOT `--presentation`; `html --help` lists `--output`, `--security`, `--ignore` but NOT `--presentation`; `plan --help` lists `--pin-all`, `--rewrite-versions`, `--script`, `--ignore`; `apply --help` lists `--yes`, `--pin-all`, `--rewrite-versions`, `--ignore`
- [ ] TC-G03/G04: Ecosystem auto-detected (PyPI and npm)
- [ ] TC-G02: `--verbose` shows settings panel; without it, panel is absent
- [ ] TC-G08: `helpers --help` lists `npm`; `helpers npm --help` lists `freeze-state`, `restore-state`, `overrides-diff`

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
- [ ] TC-H01: `ossiq-cli html --output=reports/test_report.html <path>` generates file without crash
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
- [ ] TC-E03: CSV export produces file with header row and correct row count
- [ ] TC-E04: npm JSON export has `registry: "npm"`

## 06 — Transitive Impacts ([details](06-transitive-impacts.md))

- [ ] TC-T01: `--security`, `--ignore` in `status --help` (no `--presentation`, no `--full`); `--security`, `--pin-all`, `--ignore` in `plan --help`
- [ ] TC-T02: `status` shows `↳ also updates:` sub-rows under at least one recommendation
- [ ] TC-T03: `status` (no flags) shows all packages including up-to-date ones with no CVEs; table is non-empty on a fully-current project
- [ ] TC-T07: `plan` renders without crash, shows transitive impact sub-rows; `plan --script` produces an update script block

## 07 — Plan Command: --pin-all, --rewrite-versions, --ignore, Specifier Rewrite, NPM Helpers ([details](07-plan-apply-command.md))

- [ ] TC-U01: `--ignore` on status — ignored package has no recommendation; still visible in table
- [ ] TC-U02: `--ignore` on plan — ignored package absent from plan and generated script
- [ ] TC-U05: UV NARROWED (`~=`): script contains `sed` with `~=<new_version>`; no `--upgrade-package` for that entry
- [ ] TC-U06: UV DECLARED (`>=`): no `sed`; `uv lock --upgrade-package <pkg>==<ver>` present
- [ ] TC-U07: UV `--pin-all`: all direct dep `sed` lines use `==<ver>` regardless of original specifier
- [ ] TC-U08: NPM generated script has zero `node -e` lines; uses `ossiq helpers npm freeze-state` / `restore-state`
- [ ] TC-U09: `ossiq helpers npm freeze-state` creates `.ossiq_npm_state.json` and locks `package.json` overrides
- [ ] TC-U10: `ossiq helpers npm restore-state` restores original overrides and deletes state file
- [ ] TC-U11: `ossiq helpers npm overrides-diff` prints diff table without modifying any file
- [ ] TC-U14: `ossiq plan --npm-overrides-diff` rejected with "No such option" (flag removed)

## 08 — Gated Package Add

- [ ] TC-A01: `add --help` lists `--version`, `--force`, `--registry-type`
- [ ] TC-A02: `ossiq-cli add requests testdata/pypi/uv` shows health panel (drift, CVEs, health) then prompts for confirmation; entering `n` exits without installing
- [ ] TC-A03: `ossiq-cli add <critically-unhealthy-package>` blocks install and shows warning; exit code non-zero
- [ ] TC-A04: `ossiq-cli add <critically-unhealthy-package> --force` proceeds past warning to confirmation prompt
- [ ] TC-A05: `ossiq-cli add requests --version 2.28.0 testdata/pypi/uv` shows the fixed version in the install spec, not the solver recommendation

## 09 — Automated Matrix ([details](README.md#automated-matrix))

- [ ] TC-M01: `just qa-matrix` exits 0 with `FAIL=0`; SKIPs acceptable; `qa_logs/summary.log` shows no FAILs


## Notes
<!-- Anything unexpected observed during QA -->
