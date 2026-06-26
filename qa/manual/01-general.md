# 01 — General: CLI Basics & Ecosystem Detection

Run from repo root. No network-sensitive operations.

---

## TC-G01: Version and help output

```bash
uv run hatch run ossiq-cli --version
uv run hatch run ossiq-cli --help
uv run hatch run ossiq-cli scan --help
uv run hatch run ossiq-cli update --help
uv run hatch run ossiq-cli update plan --help
uv run hatch run ossiq-cli update execute --help
```

- [ ] `--version` prints a semver string
- [ ] `--help` lists `scan`, `package`, `export`, `update`, `helpers` subcommands
- [ ] `status --help` lists `--security`, `--production`, `--allow-prerelease`, `--registry-type`, `--presentation`, `--output`, `--ignore`; `--full` is absent
- [ ] `update --help` lists `plan` and `execute` as subcommands (no direct flags)
- [ ] `update plan --help` lists `--pin-all`, `--rewrite-versions`, `--script`, `--ignore` / `-i`
- [ ] `update execute --help` lists `--yes` / `-y`, `--pin-all`, `--rewrite-versions`, `--ignore` / `-i`

---

## TC-G02: Verbose output

```bash
uv run hatch run ossiq-cli --verbose scan testdata/pypi/version-constraint
```

- [ ] Settings panel is printed before the results table
- [ ] `verbose: True` visible in settings output
- [ ] Without `--verbose`: settings panel absent

---

## TC-G03: Auto-detection — PyPI

```bash
uv run hatch run ossiq-cli scan testdata/pypi/pip-classic
```

- [ ] Header shows `Packages Registry: pypi`
- [ ] No `--registry-type` flag needed

---

## TC-G04: Auto-detection — npm

```bash
uv run hatch run ossiq-cli scan testdata/npm/project1
```

- [ ] Header shows `Packages Registry: npm`

---

## TC-G05: Auto-detection — mixed (PyPI + npm)

```bash
uv run hatch run ossiq-cli scan testdata/mixed
```

- [ ] Both PyPI and npm packages appear in separate tables or clearly marked sections
- [ ] No crash

---

## TC-G06: Registry override

```bash
uv run hatch run ossiq-cli scan --registry-type=pypi testdata/mixed
```

- [ ] Only PyPI packages processed (npm packages absent from output)
- [ ] Settings shows `narrow_registry_type: pypi`

---

## TC-G07: Unit test suite

```bash
uv run just qa
```

- [ ] All tests pass (0 failures; any skips/xfails are expected and documented)

---

## TC-G08: `helpers` command group help

```bash
uv run hatch run ossiq-cli helpers --help
uv run hatch run ossiq-cli helpers npm --help
```

- [ ] `helpers --help` lists `npm` as a subcommand with a description
- [ ] `helpers npm --help` lists `freeze-state`, `restore-state`, and `overrides-diff` with descriptions
- [ ] No crash or traceback
