# 07 — Plan Command: --pin-all, --rewrite-versions, --ignore, NPM Helpers

`plan` shows solver recommendations read-only. `apply` executes them. Both share the same option surface.

Run from repo root. UV specifier and helpers tests require network (registry lookups).

**Precondition:**

```bash
uv run hatch run ossiq-cli plan --help
uv run hatch run ossiq-cli plan --help | grep -E "pin-all|rewrite-versions|ignore|script"
uv run hatch run ossiq-cli apply --help | grep -E "yes|pin-all|rewrite-versions"
uv run hatch run ossiq-cli helpers --help
uv run hatch run ossiq-cli helpers npm --help
```

- [ ] `plan --help` lists `--script`, `--pin-all`, `--rewrite-versions`, `--ignore`
- [ ] `--pin-all` listed in `plan --help`
- [ ] `--rewrite-versions` listed in `plan --help`
- [ ] `--script` listed in `plan --help`
- [ ] `--yes` / `-y` listed in `apply --help`
- [ ] `--ignore` / `-i` listed in both `plan` and `apply` help outputs
- [ ] `helpers --help` shows `npm` subcommand
- [ ] `helpers npm --help` shows `freeze-state`, `restore-state`, `overrides-diff`

---

## TC-U01: `--ignore/-i` on status — recommendation excluded, package still visible

```bash
# Identify a package with a pending recommendation first
uv run hatch run ossiq-cli status testdata/pypi/version-constraint

# Now ignore it (substitute actual package name)
uv run hatch run ossiq-cli status --ignore requests testdata/pypi/version-constraint
```

- [ ] Ignored package row still appears in the table (not hidden)
- [ ] Recommended cell for the ignored package is empty (no recommendation generated)
- [ ] All other packages retain their recommendations
- [ ] No crash or traceback

---

## TC-U02: `--ignore/-i` on plan — package absent from plan

```bash
uv run hatch run ossiq-cli plan --ignore requests testdata/pypi/version-constraint
```

- [ ] `requests` does not appear in the plan table
- [ ] Other packages (if any) still appear in plan
- [ ] No crash

---

## TC-U03: `--ignore/-i` on export — flag accepted, no crash

```bash
uv run hatch run ossiq-cli export --ignore requests --output-format=json --output=reports/ignore_export.json testdata/pypi/version-constraint
```

- [ ] Export completes without crash
- [ ] Output file is valid JSON

---

## TC-U04: `--ignore/-i` on info — flag accepted, no crash

```bash
uv run hatch run ossiq-cli info --ignore requests testdata/pypi/version-constraint pydantic
```

- [ ] Command completes without crash
- [ ] Detail view renders for `pydantic`

---

## TC-U05: UV smart specifier — NARROWED (`~=`): sed line with new compatible-release version

```bash
uv run hatch run ossiq-cli plan --script testdata/pypi/version-constraint
```

Inspect the generated script block for `requests` (specifier `~= 2.31.0`):

- [ ] Script contains a `sed` line for `requests` that rewrites the specifier (e.g. `requests~=2.32.3`)
- [ ] The `~=` operator is preserved; only the version number changes
- [ ] No `--upgrade-package requests` line in the `uv lock` call
- [ ] Script has no `node -e` or inline JavaScript

---

## TC-U06: UV smart specifier — DECLARED (`>=`): no sed; upgrade-package instead

```bash
uv run hatch run ossiq-cli plan --script testdata/pypi/version-constraint
```

Inspect the generated script block for `pydantic` (specifier `>= 2.0.0`):

- [ ] No `sed` line for `pydantic` in the script
- [ ] `uv lock` call includes `--upgrade-package pydantic==<recommended_version>`
- [ ] `pyproject.toml` is not modified for this package

---

## TC-U07: UV `--pin-all` flag — all direct deps pinned exactly with `==`

```bash
uv run hatch run ossiq-cli plan --pin-all --script testdata/pypi/version-constraint
```

- [ ] Script contains a `sed` line for every direct dep with a pending update
- [ ] Each `sed` replacement uses `==<version>` (exact pin), regardless of original specifier
- [ ] No crash

---

## TC-U08: NPM generated script — no inline JavaScript, uses helpers subcommands

```bash
uv run hatch run ossiq-cli plan --script testdata/npm/version-constrained
```

Inspect the generated script block:

- [ ] Zero `node -e` lines anywhere in the script
- [ ] Script calls `ossiq helpers npm freeze-state "<path>" --registry-type npm` (or similar flags)
- [ ] Script calls `npm install`
- [ ] Script calls `ossiq helpers npm restore-state "<path>"`
- [ ] ROLLBACK comment references `ossiq helpers npm restore-state`
- [ ] No crash

---

## TC-U09: `ossiq helpers npm freeze-state` — writes state file and locks overrides

> Requires an npm project with `node_modules` installed. Use `testdata/npm/version-constrained`
> after running `npm install` in that directory, or substitute a real local npm project.

```bash
# One-time setup
(cd testdata/npm/version-constrained && npm install)

# Run freeze-state
uv run hatch run ossiq-cli helpers npm freeze-state testdata/npm/version-constrained --registry-type npm
```

- [ ] `.ossiq_npm_state.json` created in the project directory
- [ ] State file contains `original_overrides`, `recommended_packages`, `locked_overrides` keys
- [ ] `locked_overrides` in state file contains every installed transitive package at its installed version
- [ ] Recommended packages appear in `locked_overrides` at their **new recommended** versions
- [ ] `package.json` `"overrides"` section now contains all locked packages
- [ ] No crash

---

## TC-U10: `ossiq helpers npm restore-state` — restores overrides and deletes state file

> Run after TC-U09 (state file must exist).

```bash
uv run hatch run ossiq-cli helpers npm restore-state testdata/npm/version-constrained
```

- [ ] `.ossiq_npm_state.json` deleted after command completes
- [ ] `package.json` `"overrides"` section is restored to original overrides (minus recommended packages)
- [ ] If original overrides were empty, the `"overrides"` key is removed from `package.json` entirely (not set to `{}`)
- [ ] Confirmation message printed to stdout
- [ ] No crash

---

## TC-U11: `ossiq helpers npm overrides-diff` — read-only diff, no file mutation

> Run while `.ossiq_npm_state.json` exists (e.g. after TC-U09 and before TC-U10).

```bash
uv run hatch run ossiq-cli helpers npm overrides-diff testdata/npm/version-constrained
```

- [ ] Diff table printed showing original vs current overrides
- [ ] Rows prefixed with `=` (unchanged), `+` (added), `-` (removed), or `~` (changed)
- [ ] `package.json` is not modified (verify with `git diff testdata/npm/version-constrained/package.json`)
- [ ] `.ossiq_npm_state.json` is not modified
- [ ] No crash

---

## TC-U12: NPM `--pin-all` — exact versions written to dep sections during freeze-state

```bash
uv run hatch run ossiq-cli helpers npm freeze-state testdata/npm/version-constrained --registry-type npm --pin-all
```

- [ ] Direct dependency entries in `package.json` (`dependencies`, `devDependencies`, etc.) are rewritten to exact versions (no `^`, `~`, or range operators)
- [ ] Exact versions match the recommended versions in the plan
- [ ] No crash

```bash
# Cleanup
uv run hatch run ossiq-cli helpers npm restore-state testdata/npm/version-constrained
```

---

## TC-U13: NPM caret spec — same major version, specifier unchanged in package.json

```bash
uv run hatch run ossiq-cli plan --script testdata/npm/version-constrained
```

Find a package in `testdata/npm/version-constrained/package.json` that uses `^major.x.x` and whose recommended version is within the same major:

- [ ] `package.json` is **not** modified for that package (specifier left as-is)
- [ ] The generated script still installs the new version via the overrides mechanism
- [ ] No crash

---

## TC-U14: Removed flag `--npm-overrides-diff` is rejected

```bash
uv run hatch run ossiq-cli plan --npm-overrides-diff testdata/npm/version-constrained 2>&1 | head -5
```

- [ ] Command exits with a non-zero code
- [ ] Error output contains "No such option" or similar — the flag no longer exists
- [ ] No Python traceback

---

## TC-U15: `plan` shows table only (no script)

```bash
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint
```

- [ ] Plan table is printed (Package / Current / Recommended columns visible)
- [ ] No bash script block printed (no `#!/usr/bin/env bash` line)
- [ ] No crash

---

## TC-U16: `plan --script` emits script only (no table)

```bash
uv run hatch run ossiq-cli plan --script testdata/pypi/version-constraint
```

- [ ] Output starts with `#!/usr/bin/env bash` (no Rich table header)
- [ ] No "OSS IQ — Plan" header line in output
- [ ] Script can be piped cleanly: `ossiq-cli plan --script testdata/pypi/version-constraint | bash` (dry-run review)
- [ ] No crash

---

## TC-U17: `plan --help` shows plan options

```bash
uv run hatch run ossiq-cli plan --help
```

- [ ] Output shows plan help text listing `--script`, `--pin-all`, `--rewrite-versions`, `--ignore`
- [ ] No Python traceback
- [ ] Exit code is zero

---

## TC-U18: `apply` shows plan, prompts, and runs (PyPI project)

> This test modifies `pyproject.toml`. Run on a copy or restore with `git checkout` afterwards.

```bash
# First preview
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint

# Then execute (answer 'y' at prompt)
uv run hatch run ossiq-cli apply testdata/pypi/version-constraint
```

- [ ] Plan table appears before the confirmation prompt
- [ ] Prompt reads "Proceed with N updates?" (where N > 0)
- [ ] Answering `n` exits without modifying any files
- [ ] Answering `y` runs `uv lock` and `uv sync` (output visible in terminal)
- [ ] `pyproject.toml` updated after answering `y` (verify with `git diff`)
- [ ] `uv.lock` updated (verify with `git diff`)
- [ ] "Update complete." printed on success
- [ ] No crash

```bash
# Restore
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U19: `apply --yes` skips confirmation (CI mode)

> This test modifies `pyproject.toml`. Run on a copy or restore with `git checkout` afterwards.

```bash
uv run hatch run ossiq-cli apply --yes testdata/pypi/version-constraint
```

- [ ] No confirmation prompt appears
- [ ] Updates run directly
- [ ] "Update complete." printed on success
- [ ] No crash

```bash
# Restore
git checkout testdata/pypi/version-constraint/pyproject.toml testdata/pypi/version-constraint/uv.lock
```

---

## TC-U20: `--rewrite-versions` includes PINNED deps that are normally frozen

```bash
# Without --rewrite-versions: PINNED deps are frozen and absent from plan
uv run hatch run ossiq-cli plan testdata/pypi/version-constraint

# With --rewrite-versions: PINNED deps appear in plan
uv run hatch run ossiq-cli plan --rewrite-versions testdata/pypi/version-constraint
```

- [ ] Without `--rewrite-versions`: packages with `==x.y.z` specifiers do NOT appear in plan (frozen)
- [ ] With `--rewrite-versions`: packages with `==x.y.z` specifiers DO appear in plan (unfrozen)
- [ ] No crash in either case

---

## TC-U21: `apply` rollback — `pyproject.toml` restored if `uv lock` fails

> Simulate a failure by passing an invalid package path or registry-type mismatch.

```bash
# Make a backup
cp testdata/pypi/version-constraint/pyproject.toml /tmp/pyproject_backup.toml

# Force a failure by using an unreachable registry or an invalid flag combination
# (or temporarily corrupt pyproject.toml mid-test by using a debugger / test hook)

# Verify restoration
diff testdata/pypi/version-constraint/pyproject.toml /tmp/pyproject_backup.toml
```

- [ ] After a failed `apply`, `pyproject.toml` is identical to its pre-run state
- [ ] Error message printed to stderr explaining the failure
- [ ] Exit code non-zero
- [ ] No Python traceback beyond the error message
