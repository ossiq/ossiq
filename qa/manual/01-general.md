# 01 — General: CLI Basics & Ecosystem Detection

Run from repo root. No network-sensitive operations.

---

## TC-G01: Version and help output

```bash
uv run hatch run ossiq-cli --version
uv run hatch run ossiq-cli --help
uv run hatch run ossiq-cli status --help
uv run hatch run ossiq-cli plan --help
uv run hatch run ossiq-cli apply --help
```

- [ ] `--version` prints a semver string
- [ ] `--help` lists `status`, `html`, `export`, `info`, `add`, `plan`, `apply`, `install`, `mcp` subcommands (no `scan`, `package`, `update`, or `helpers`)
- [ ] `status --help` lists `--security`, `--production`, `--allow-prerelease`, `--registry-type`, `--ignore`, `--format`; `--presentation` and `--output` are absent (those belong to `html`)
- [ ] `plan --help` lists `--pin-all`, `--rewrite-versions`, `--override`, `--ignore` / `-i` (NOT `--script`)
- [ ] `apply --help` lists `--yes` / `-y`, `--pin-all`, `--rewrite-versions`, `--override`, `--ignore` / `-i`

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
uv run hatch run ossiq-cli status testdata/pypi/pip-classic
```

- [ ] Header shows `Packages Registry: pypi`
- [ ] No `--registry-type` flag needed

---

## TC-G04: Auto-detection — npm

```bash
uv run hatch run ossiq-cli status testdata/npm/project1
```

- [ ] Header shows `Packages Registry: npm`

---

## TC-G05: Auto-detection — mixed (PyPI + npm)

```bash
uv run hatch run ossiq-cli status testdata/mixed
```

- [ ] Both PyPI and npm packages appear in separate tables or clearly marked sections
- [ ] No crash

---

## TC-G06: Registry override

```bash
uv run hatch run ossiq-cli status --registry-type=pypi testdata/mixed
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

## TC-G09: Config file at default location

```bash
echo "OSSIQ_COOLDOWN_PERIOD=14" >> ~/.ossiq/config
uv run hatch run ossiq-cli --verbose status testdata/pypi/uv
# cleanup: remove the line from ~/.ossiq/config afterwards
```

- [ ] Settings panel shows `cooldown_period: 14` (value from the config file)
- [ ] Without the config entry: `cooldown_period: 7` (built-in default)

---

## TC-G10: `--config` option

```bash
printf 'OSSIQ_COOLDOWN_PERIOD=21\n' > /tmp/ossiq-qa-config
uv run hatch run ossiq-cli --config /tmp/ossiq-qa-config --verbose status testdata/pypi/uv
uv run hatch run ossiq-cli --config /tmp/does-not-exist status testdata/pypi/uv
```

- [ ] With the custom file: settings panel shows `cooldown_period: 21`
- [ ] With nonexistent path: clean `Config file not found` error, non-zero exit, no traceback
- [ ] `--help` lists `--config` with the default location

---

## TC-G11: Configuration precedence (CLI > env > config file)

```bash
printf 'OSSIQ_COOLDOWN_PERIOD=21\n' > /tmp/ossiq-qa-config
OSSIQ_COOLDOWN_PERIOD=3 uv run hatch run ossiq-cli --config /tmp/ossiq-qa-config --verbose status testdata/pypi/uv
OSSIQ_COOLDOWN_PERIOD=3 uv run hatch run ossiq-cli --config /tmp/ossiq-qa-config --cooldown-period 1 --verbose status testdata/pypi/uv
```

- [ ] First run: env var wins over config file — `cooldown_period: 3`
- [ ] Second run: CLI flag wins over env var — `cooldown_period: 1`
