# Manual QA

Pre-release validation process for ossiq-cli. One person, under 45 minutes.

## Structure

| File | Area | Cases |
|------|------|-------|
| [01-general.md](01-general.md) | CLI basics, verbosity, ecosystem detection | TC-G01–G07 |
| [02-console-scan.md](02-console-scan.md) | `scan` + `package` commands, all package-state variations | TC-C01–C10 |
| [03-html-report.md](03-html-report.md) | HTML scan output, dependency table, explorer | TC-H01–H05 |
| [04-solver.md](04-solver.md) | HPDR solver correctness | TC-S01–S10 |
| [05-export.md](05-export.md) | JSON and CSV export | TC-E01–E05 |
| [release-checklist.md](release-checklist.md) | Abbreviated checklist for GitHub Issues | — |

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
