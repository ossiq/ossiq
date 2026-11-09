#!/usr/bin/env python3
"""Regression matrix: drive the real `ossiq` CLI against tiny projects in Docker and check what it did.

It covers status, plan, apply, add, export and `upgrade` (console, menu and the `--format agent` loop)
on npm, pnpm, uv, pip and pylock projects.

Each case in qa/smoke/cases.toml names a project under qa/smoke/projects/ (one or two dependencies,
locked at an old version) and a list of steps. A step is one command in a throwaway container
(qa/Dockerfile): the host copies the project into qa_logs/smoke/<run>/<case>/workspace, mounts it
at /work with a fresh HOME, then reads what the command printed and what it left in the manifest,
lockfile and export. npm installs, `uv sync` and sdist builds therefore never run on the host.

Registries move, so a step asserts progress, not a snapshot: "locked at least 5.7.2", "recommended
at least 3.7". Exact versions are only asserted for releases that cannot change - a package whose
last release is the one in the project, or a version the step itself forces.

Every step also gets four checks no case has to ask for: the exit code, no Python traceback,
`status` / `plan` / `export` / `info` and the `upgrade` subcommands that only read leave the manifest
and lockfile byte-identical, and after a command that writes (`apply`, `add`, `upgrade apply`,
`rollback`, `skip`, `abort`) every direct dependency is locked at a version its declared spec admits.

Usage:

    just qa-build                                  # once, and after changing src/
    uv run python qa/smoke_matrix.py               # or: just qa-matrix
    uv run python qa/smoke_matrix.py --cases npm-security,uv-standard
    uv run python qa/smoke_matrix.py --cases 'pnpm-*,*-upgrade-*'     # `*` patterns are accepted
    uv run python qa/smoke_matrix.py --dry-run

Exit status: 0 when no case failed (XFAIL and XPASS allowed), 1 when a case failed, 2 when the run
could not start (invalid cases.toml, unknown case id, image not built).

This is a QA script, not a pytest - it hits the network and is kept out of `just qa`.
"""

import argparse
import fnmatch
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from update_strategies_regression import ECOSYSTEMS as BASE_ECOSYSTEMS
from update_strategies_regression import (
    Ecosystem,
    FixtureError,
    NpmEcosystem,
    PypiEcosystem,
    Status,
    reject_unknown_keys,
    run_logged,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SMOKE_DIR = Path(__file__).resolve().parent / "smoke"
CASES_FILE = SMOKE_DIR / "cases.toml"
PROJECTS_DIR = SMOKE_DIR / "projects"
LOG_ROOT = REPO_ROOT / "qa_logs" / "smoke"

IMAGE = "ossiq-qa"
CACHE_VOLUME = "ossiq-qa-cache"
CONTAINER_HOME = "/home/qarunner"
CONTAINER_WORKSPACE = "/work"
# Container paths stay plain strings: a host Path would write them with backslashes on Windows.
CONTAINER_CACHE_DIR = "/cache"
CONTAINER_CACHE = f"{CONTAINER_CACHE_DIR}/ossiq_cache.sqlite3"
GITHUB_TOKEN_ENV = "OSSIQ_GITHUB_TOKEN"
DEFAULT_TIMEOUT = 300
# Headroom for the host-side backstop over the in-container `timeout`.
HOST_TIMEOUT_SLACK = 60
# Installed trees and package caches: they add up to gigabytes per run and nothing reads them.
BULKY_DIRS = ("workspace/node_modules", "workspace/.venv", "home/.cache", "home/.npm", "home/.local/share/pnpm")
# Files a command that only reads must leave alone.
GUARDED_FILES = (
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "pyproject.toml",
    "uv.lock",
    "pylock.toml",
    "requirements.txt",
    ".ossiq.yaml",
)
# `upgrade apply` is `apply`; the others write the manifest and lockfile too (rollback, skip and abort
# restore them, the menu can do any of it). `start`, `status`, `test`, `continue` and `finish` only read.
MUTATING_COMMANDS = frozenset({"apply", "add", "rollback", "skip", "abort", "--interactive"})
TRACEBACK = "Traceback (most recent call last)"
NONZERO = "nonzero"

CASE_KEYS = frozenset({"id", "project", "why", "covers", "ecosystem", "token", "known_issue", "add_files", "steps"})
STEP_KEYS = frozenset(
    {"run", "rc", "env", "stdin", "timeout", "stdout", "stderr", "output", "locked", "declared", "report"}
    | {"packages", "files"}
)
TEXT_GROUPS = ("stdout", "stderr", "output")
TEXT_KEYS = frozenset({"has", "lacks", "once", "json"})
FILE_KEYS = TEXT_KEYS - {"json"}
VALUE_KEYS = frozenset({"at_least", "below", "equals", "missing", "pinned", "changed"})
REPORT_SECTIONS = ("production_packages", "development_packages", "transitive_packages")

logger = logging.getLogger("ossiq-qa.smoke")


@dataclass(frozen=True)
class Step:
    """One command in a throwaway container, and everything checked about it afterwards."""

    run: tuple[str, ...]
    rc: int | str
    """The expected exit code, or `nonzero` for any failure."""
    env: Mapping[str, str]
    stdin: str | None
    timeout: int
    texts: Mapping[str, Mapping[str, Any]]
    locked: Mapping[str, Mapping[str, Any]]
    declared: Mapping[str, Mapping[str, Any]]
    report: str | None
    packages: Mapping[str, Mapping[str, Mapping[str, Any]]]
    files: Mapping[str, Mapping[str, Any]]

    @property
    def read_only(self) -> bool:
        """Whether the command promises to leave the manifest and lockfile alone."""
        return not MUTATING_COMMANDS.intersection(self.run)


@dataclass(frozen=True)
class Case:
    """A project and the steps run against a fresh copy of it."""

    id: str
    project: str
    why: str
    covers: tuple[str, ...]
    ecosystem: Ecosystem | None
    token: bool
    known_issue: str | None
    add_files: Mapping[str, str]
    steps: tuple[Step, ...]


@dataclass(frozen=True)
class CaseResult:
    """How one case ended."""

    case_id: str
    status: Status
    problems: tuple[str, ...]
    seconds: float


# ---------------------------------------------------------------------------
# cases.toml
# ---------------------------------------------------------------------------


def string_list(where: str, value: Any) -> list[str]:
    """Return *value* when it is a list of strings.

    Raises:
        FixtureError: *value* is anything else.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise FixtureError(f"{where}: expected a list of strings")
    return value


def parse_text_rules(where: str, raw: Mapping[str, Any], allowed: frozenset[str]) -> Mapping[str, Any]:
    """Validate a `has` / `lacks` / `once` / `json` block."""
    reject_unknown_keys(where, raw, allowed)
    for key in ("has", "lacks", "once"):
        string_list(f"{where}.{key}", raw.get(key, []))
    return raw


def parse_value_rules(where: str, raw: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Mapping[str, Any]]:
    """Validate {name: {at_least | below | equals | missing | pinned | changed}}."""
    for name, rule in raw.items():
        reject_unknown_keys(f"{where}.{name}", rule, VALUE_KEYS)
        if not rule:
            raise FixtureError(f"{where}.{name}: an empty rule checks nothing")
        if "missing" in rule and len(rule) > 1:
            raise FixtureError(f"{where}.{name}: `missing` can't be combined with other checks")
    return raw


def parse_step(where: str, raw: Mapping[str, Any]) -> Step:
    """Validate one [[cases.steps]] table and build the step.

    Raises:
        FixtureError: On an unknown key or a value of the wrong shape.
    """
    reject_unknown_keys(where, raw, STEP_KEYS)
    rc = raw.get("rc", 0)
    if rc != NONZERO and (not isinstance(rc, int) or isinstance(rc, bool)):
        raise FixtureError(f"{where}.rc: expected an integer or {NONZERO!r}")
    packages = raw.get("packages", {})
    for name, fields in packages.items():
        parse_value_rules(f"{where}.packages.{name}", fields)
    if bool(packages) != bool(raw.get("report")):
        raise FixtureError(f"{where}: `packages` and `report` go together")
    return Step(
        run=tuple(string_list(f"{where}.run", raw.get("run"))) or fail(f"{where}.run: empty"),
        rc=rc,
        env=dict(raw.get("env", {})),
        stdin=raw.get("stdin"),
        timeout=raw.get("timeout", DEFAULT_TIMEOUT),
        texts={
            group: parse_text_rules(f"{where}.{group}", raw[group], TEXT_KEYS) for group in TEXT_GROUPS if group in raw
        },
        locked=parse_value_rules(f"{where}.locked", raw.get("locked", {})),
        declared=parse_value_rules(f"{where}.declared", raw.get("declared", {})),
        report=raw.get("report"),
        packages=packages,
        files={
            path: parse_text_rules(f"{where}.files.{path}", rules, FILE_KEYS)
            for path, rules in raw.get("files", {}).items()
        },
    )


def fail(message: str) -> Any:
    """Raise a FixtureError, so a validation can be written as an `or` expression.

    Raises:
        FixtureError: Always.
    """
    raise FixtureError(message)


class PnpmEcosystem(NpmEcosystem):
    """npm's semver ranges, read from package.json and pnpm-lock.yaml (lockfileVersion 9)."""

    name = "pnpm"
    toolchain = "pnpm"

    def locked_versions(self, project: Path) -> dict[str, str]:
        lock = yaml.safe_load((project / "pnpm-lock.yaml").read_text(encoding="utf-8")) or {}
        versions: dict[str, str] = {}
        # shortcut: a transitive package locked at several versions reports the last one in file
        # order; when a case needs one of them, key the result by version.
        for entry in lock.get("snapshots") or {}:
            name, _, version = entry.split("(")[0].rpartition("@")  # "@scope/pkg@1.2.3(peer@4)"
            if name:
                versions[name] = version
        importer = (lock.get("importers") or {}).get(".") or {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, meta in (importer.get(section) or {}).items():
                versions[name] = str(meta["version"]).split("(")[0]
        return versions


class PipEcosystem(PypiEcosystem):
    """PEP 440 specifiers in requirements.txt; the venv `apply` installed into stands in for a lockfile."""

    name = "pip"
    toolchain = "pip"

    def declared_specs(self, project: Path) -> dict[str, str]:
        specs: dict[str, str] = {}
        for raw in (project / "requirements.txt").read_text(encoding="utf-8").splitlines():
            line = raw.split("#")[0].strip()
            if line and not line.startswith("-"):  # -c, -r and -e name files, not packages
                requirement = Requirement(line)
                specs[canonicalize_name(requirement.name)] = str(requirement.specifier)
        return specs

    def locked_versions(self, project: Path) -> dict[str, str]:
        sites = sorted((project / ".venv").glob("lib/python*/site-packages"))
        if not sites:
            raise FileNotFoundError("no .venv in the project: nothing was installed")
        versions: dict[str, str] = {}
        for dist_info in sites[0].glob("*.dist-info"):
            name, _, version = dist_info.name.removesuffix(".dist-info").rpartition("-")
            versions[canonicalize_name(name)] = version
        return versions


ECOSYSTEMS: tuple[Ecosystem, ...] = (*BASE_ECOSYSTEMS, PnpmEcosystem(), PipEcosystem())


def detect_ecosystem(project: Path) -> Ecosystem | None:
    """The ecosystem a project is unambiguously in, judged by its files; None for none or both.

    pnpm is an npm project with a pnpm-lock.yaml, pip a requirements.txt with no pyproject.toml.
    """
    names = {
        name
        for name in ("package.json", "pnpm-lock.yaml", "pyproject.toml", "requirements.txt")
        if (project / name).is_file()
    }
    javascript = "package.json" in names
    python = bool(names & {"pyproject.toml", "requirements.txt"})
    if javascript == python:
        return None
    by_name = {eco.name: eco for eco in ECOSYSTEMS}
    if javascript:
        return by_name["pnpm" if "pnpm-lock.yaml" in names else "npm"]
    return by_name["pypi" if "pyproject.toml" in names else "pip"]


def parse_case(raw: Mapping[str, Any], projects_root: Path) -> Case:
    """Validate one [[cases]] table and build the case.

    Raises:
        FixtureError: On an unknown key, a missing project, or a check that needs an ecosystem the
            project doesn't have.
    """
    where = f"case {raw.get('id')}"
    reject_unknown_keys(where, raw, CASE_KEYS)
    for key in ("id", "project", "why", "steps"):
        if key not in raw:
            raise FixtureError(f"{where}: missing `{key}`")
    project = projects_root / raw["project"]
    if not project.is_dir():
        raise FixtureError(f"{where}: no project {project}")
    by_name = {eco.name: eco for eco in ECOSYSTEMS}
    if "ecosystem" in raw and raw["ecosystem"] not in by_name:
        raise FixtureError(f"{where}.ecosystem: expected one of {', '.join(by_name)}")
    ecosystem = by_name[raw["ecosystem"]] if "ecosystem" in raw else detect_ecosystem(project)
    steps = tuple(parse_step(f"{where} step {i}", step) for i, step in enumerate(raw["steps"], 1))
    if ecosystem is None and any(step.locked or step.declared or step.packages for step in steps):
        raise FixtureError(f"{where}: checks on versions need an `ecosystem`, and {raw['project']} has no single one")
    return Case(
        id=raw["id"],
        project=raw["project"],
        why=raw["why"],
        covers=tuple(string_list(f"{where}.covers", raw.get("covers", []))),
        ecosystem=ecosystem,
        token=raw.get("token", True),
        known_issue=raw.get("known_issue"),
        add_files=dict(raw.get("add_files", {})),
        steps=steps,
    )


def parse_cases(raw: Mapping[str, Any], projects_root: Path = PROJECTS_DIR) -> list[Case]:
    """Validate the parsed cases.toml and build its cases.

    Raises:
        FixtureError: On an unknown key, a duplicate case id, or an invalid case.
    """
    reject_unknown_keys("cases.toml", raw, frozenset({"cases"}))
    cases = [parse_case(entry, projects_root) for entry in raw.get("cases", [])]
    ids = [case.id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise FixtureError(f"duplicate case id(s): {', '.join(duplicates)}")
    return cases


def select_cases(cases: Sequence[Case], wanted: str | None) -> list[Case]:
    """Filter *cases* by a comma-separated list of ids or `*` patterns, in the order asked for.

    Raises:
        FixtureError: When an id or pattern matches no case.
    """
    if not wanted:
        return list(cases)
    selected: list[Case] = []
    unmatched: list[str] = []
    for pattern in (part.strip() for part in wanted.split(",") if part.strip()):
        matches = [case for case in cases if fnmatch.fnmatchcase(case.id, pattern)]
        if not matches:
            unmatched.append(pattern)
        selected += [case for case in matches if all(case.id != chosen.id for chosen in selected)]
    if unmatched:
        raise FixtureError(f"unknown case(s): {', '.join(unmatched)}; expected {', '.join(case.id for case in cases)}")
    return selected


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def is_pinned(ecosystem: Ecosystem, spec: str) -> bool:
    """Whether *spec* names exactly one release."""
    if isinstance(ecosystem, NpmEcosystem):  # pnpm reads the same semver ranges
        return re.fullmatch(r"\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]+)?", spec.strip()) is not None
    return spec.strip().startswith("==") and "*" not in spec


def check_value(
    ecosystem: Ecosystem, label: str, actual: Any, rule: Mapping[str, Any], kind: str, before: str | None = None
) -> list[str]:
    """Check one observed value against a rule.

    Args:
        ecosystem: Decides how versions and specs compare.
        label: What is being checked, for the message.
        actual: The observed value; None when the package or field is absent.
        rule: The `at_least` / `below` / `equals` / `missing` / `pinned` / `changed` checks.
        kind: `version`, `spec` or `value`: how `equals` compares.
        before: The spec before the step ran, for `changed`.

    Returns:
        One message per failed check.
    """
    if rule.get("missing"):
        return [] if actual is None else [f"{label} is {actual!r}, expected it missing"]
    if actual is None:
        return [f"{label} not found"]
    problems = []
    if "at_least" in rule and ecosystem.is_older(actual, rule["at_least"]):
        problems.append(f"{label} is {actual}, expected at least {rule['at_least']}")
    if "below" in rule and not ecosystem.is_older(actual, rule["below"]):
        problems.append(f"{label} is {actual}, expected below {rule['below']}")
    if "equals" in rule:
        same = {
            "version": lambda: ecosystem.same_version(actual, rule["equals"]),
            "spec": lambda: ecosystem.same_spec(actual, rule["equals"]),
            "value": lambda: actual == rule["equals"],
        }[kind]()
        if not same:
            problems.append(f"{label} is {actual!r}, expected {rule['equals']!r}")
    if "pinned" in rule and is_pinned(ecosystem, actual) != rule["pinned"]:
        problems.append(f"{label} is {actual}, expected {'a pin' if rule['pinned'] else 'a range'}")
    if "changed" in rule:
        unchanged = before is not None and ecosystem.same_spec(actual, before)
        if unchanged == rule["changed"]:
            problems.append(f"{label} is {actual}, expected it {'changed' if rule['changed'] else 'unchanged'}")
    return problems


def text_problems(label: str, text: str, rules: Mapping[str, Any]) -> list[str]:
    """Check *text* against `has` / `lacks` / `once` / `json` rules."""
    problems = [f"{label} lacks {needle!r}" for needle in rules.get("has", []) if needle not in text]
    problems += [f"{label} has {needle!r}" for needle in rules.get("lacks", []) if needle in text]
    problems += [
        f"{label} has {text.count(needle)} of {needle!r}, expected one"
        for needle in rules.get("once", [])
        if text.count(needle) != 1
    ]
    if rules.get("json"):
        try:
            if not isinstance(json.loads(text), dict):
                problems.append(f"{label} is JSON but not an object")
        except json.JSONDecodeError as error:
            problems.append(f"{label} is not JSON: {error}")
    return problems


def snapshot(workspace: Path) -> dict[str, bytes]:
    """The bytes of every manifest, lockfile and policy file in *workspace*."""
    return {name: (workspace / name).read_bytes() for name in GUARDED_FILES if (workspace / name).is_file()}


def lock_agrees_with_manifest(ecosystem: Ecosystem, workspace: Path) -> list[str]:
    """Every direct dependency must be locked at a version its declared spec admits."""
    try:
        specs = ecosystem.declared_specs(workspace)
        locked = ecosystem.locked_versions(workspace)
    except FileNotFoundError:
        return []  # a project with no lockfile has nothing to disagree with
    except (OSError, ValueError, KeyError) as error:
        return [f"manifest or lockfile unreadable after the command: {error}"]
    problems = []
    for name, spec in specs.items():
        version = locked.get(ecosystem.key(name))
        if version is None:
            problems.append(f"{name} is declared as {spec!r} but not locked")
        elif not ecosystem.admits(spec, version):
            problems.append(f"{name} is locked at {version}, which {spec!r} does not admit")
    return problems


def report_package(ecosystem: Ecosystem, report: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    """Find a package in an export, in any of its sections."""
    for section in REPORT_SECTIONS:
        for package in report.get(section) or []:
            if ecosystem.key(package["package_name"]) == ecosystem.key(name):
                return package
    return None


def version_checks(case: Case, step: Step, workspace: Path, specs_before: Mapping[str, str]) -> list[str]:
    """The `locked`, `declared` and `packages` checks of a step, read from the workspace."""
    ecosystem = case.ecosystem
    if ecosystem is None or not (step.locked or step.declared or step.packages):
        return []
    problems: list[str] = []
    try:
        if step.locked:
            locked = ecosystem.locked_versions(workspace)
            for name, rule in step.locked.items():
                problems += check_value(ecosystem, f"locked {name}", locked.get(ecosystem.key(name)), rule, "version")
        if step.declared:
            declared = ecosystem.declared_specs(workspace)
            for name, rule in step.declared.items():
                key = ecosystem.key(name)
                problems += check_value(
                    ecosystem, f"declared {name}", declared.get(key), rule, "spec", before=specs_before.get(key)
                )
        if step.report:
            report = json.loads((workspace / step.report).read_text(encoding="utf-8"))
            for name, fields in step.packages.items():
                package = report_package(ecosystem, report, name)
                for field_name, rule in fields.items():
                    actual = None if package is None else package.get(field_name)
                    kind = "version" if field_name.endswith("version") else "value"
                    problems += check_value(ecosystem, f"{step.report} {name}.{field_name}", actual, rule, kind)
    except (OSError, ValueError, KeyError) as error:
        problems.append(f"could not read the workspace: {error}")
    return problems


def file_problems(step: Step, case_dir: Path) -> list[str]:
    """The `files` checks: text rules on files under the case directory."""
    problems = []
    for relative, rules in step.files.items():
        path = case_dir / relative
        if not path.is_file():
            problems.append(f"{relative} was not written")
            continue
        problems += text_problems(relative, path.read_text(encoding="utf-8", errors="replace"), rules)
    return problems


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def container_name(run_id: str, case: Case, index: int) -> str:
    """The name of a step's container, so a host-side timeout can remove it."""
    return f"ossiq-smoke-{run_id}-{case.id}-{index}"


def docker_command(case: Case, step: Step, index: int, case_dir: Path, image: str, run_id: str) -> list[str]:
    """The `docker run` for one step.

    The GitHub token is passed by name, so docker copies it from this process and its value stays
    out of `ps` and the transcript. `timeout` inside the container stops a hung command even if
    the host loses the docker client.
    """
    command = ["docker", "run", "--rm", "--name", container_name(run_id, case, index), "--user", "1000:1000"]
    if step.stdin is not None:
        command.append("-i")
    command += [
        "-v",
        f"{case_dir / 'workspace'}:{CONTAINER_WORKSPACE}",
        "-v",
        f"{case_dir / 'home'}:{CONTAINER_HOME}",
        "-v",
        f"{CACHE_VOLUME}:{CONTAINER_CACHE_DIR}",
        "-w",
        CONTAINER_WORKSPACE,
    ]
    values = {
        "HOME": CONTAINER_HOME,
        "NO_COLOR": "1",
        # Wide enough that Rich never wraps a table row or a panel line a check looks for.
        "COLUMNS": "240",
        "OSSIQ_CACHE_DESTINATION": CONTAINER_CACHE,
        **step.env,
    }
    for name, value in values.items():
        command += ["-e", f"{name}={value}"]
    if case.token:
        command += ["-e", GITHUB_TOKEN_ENV]
    return [*command, image, "timeout", "-k", "10", str(step.timeout), *step.run]


def run_step(case: Case, step: Step, index: int, case_dir: Path, image: str, run_id: str) -> list[str]:
    """Run one step in a container and check it.

    Returns:
        One message per failed check; empty when the step passed.
    """
    workspace = case_dir / "workspace"
    before = snapshot(workspace)
    specs_before: Mapping[str, str] = {}
    if case.ecosystem is not None:
        try:
            specs_before = case.ecosystem.declared_specs(workspace)
        except (OSError, ValueError, KeyError):
            specs_before = {}

    command = docker_command(case, step, index, case_dir, image, run_id)
    # The docker client finds its daemon and reads the token through the parent environment.
    result = run_logged(
        command,
        env=os.environ,
        log_path=case_dir / f"{index:02d}.log",
        timeout=step.timeout + HOST_TIMEOUT_SLACK,
        stdin=step.stdin,
    )
    if result.timed_out:
        subprocess.run(["docker", "rm", "-f", container_name(run_id, case, index)], capture_output=True, check=False)
        return [f"timed out after {step.timeout}s (see {result.log_path.name})"]

    problems = []
    if step.rc == NONZERO:
        if result.rc == 0:
            problems.append("exited 0, expected a failure")
    elif result.rc != step.rc:
        problems.append(f"exited {result.rc}, expected {step.rc}")
    combined = f"{result.stdout}\n{result.stderr}"
    if TRACEBACK in combined:
        problems.append("a Python traceback was printed")
    streams = {"stdout": result.stdout, "stderr": result.stderr, "output": combined}
    for group, rules in step.texts.items():
        problems += text_problems(group, streams[group], rules)

    if step.read_only and snapshot(workspace) != before:
        problems.append("changed the manifest or lockfile although the command only reads")
    elif not step.read_only and result.rc == 0 and case.ecosystem is not None:
        problems += lock_agrees_with_manifest(case.ecosystem, workspace)
    problems += version_checks(case, step, workspace, specs_before)
    problems += file_problems(step, case_dir)
    return problems


def classify(case: Case, problems: Sequence[str]) -> Status:
    """PASS or FAIL, or XFAIL / XPASS when the case carries a `known_issue`."""
    if case.known_issue:
        return Status.XFAIL if problems else Status.XPASS
    return Status.FAIL if problems else Status.PASS


def run_case(case: Case, run_dir: Path, image: str, run_id: str) -> CaseResult:
    """Run every step of a case on a fresh copy of its project, stopping at the first failing step."""
    started = datetime.now(UTC)
    case_dir = run_dir / case.id
    shutil.copytree(PROJECTS_DIR / case.project, case_dir / "workspace")
    (case_dir / "home").mkdir()
    for relative, content in case.add_files.items():
        target = case_dir / "workspace" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    problems: list[str] = []
    for index, step in enumerate(case.steps, 1):
        step_problems = run_step(case, step, index, case_dir, image, run_id)
        problems += [f"step {index} `{shlex.join(step.run)}`: {problem}" for problem in step_problems]
        if step_problems:
            break
    for bulky in BULKY_DIRS:
        shutil.rmtree(case_dir / bulky, ignore_errors=True)
    seconds = (datetime.now(UTC) - started).total_seconds()
    return CaseResult(case.id, classify(case, problems), tuple(problems), seconds)


def command_output(command: Sequence[str]) -> str:
    """Run a short command and return its stripped stdout, or an empty string when it fails."""
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def write_run_json(run_dir: Path, image: str, results: Sequence[CaseResult]) -> None:
    """Record what ran against which checkout and image, and how every case ended."""
    record = {
        "created_at": datetime.now(UTC).isoformat(),
        "git_sha": command_output(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"]),
        "git_dirty": bool(command_output(["git", "-C", str(REPO_ROOT), "status", "--porcelain"])),
        "image_id": command_output(["docker", "image", "inspect", "-f", "{{.Id}}", image]),
        "ossiq_version": command_output(["docker", "run", "--rm", image, "ossiq", "--version"]),
        "cases": [
            {"id": r.case_id, "status": str(r.status), "seconds": round(r.seconds, 1), "problems": list(r.problems)}
            for r in results
        ],
    }
    (run_dir / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")


def setup_logging(log_dir: Path | None = None) -> None:
    """Log plain lines to stdout, and timestamped ones to summary.log once the run directory exists."""
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console)
    if log_dir is not None:
        file_handler = logging.FileHandler(log_dir / "summary.log", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
        logger.addHandler(file_handler)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", help="comma-separated case ids or patterns such as 'pnpm-*' (default: all)")
    parser.add_argument("--parallel", type=int, default=4, help="cases at a time (default: 4)")
    parser.add_argument("--image", default=IMAGE, help=f"QA image (default: {IMAGE})")
    parser.add_argument("--dry-run", action="store_true", help="list the cases and their commands, then exit")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the matrix and return the exit status."""
    args = parse_args(argv)
    setup_logging()
    try:
        selected = select_cases(parse_cases(tomllib.loads(CASES_FILE.read_text(encoding="utf-8"))), args.cases)
    except (FixtureError, tomllib.TOMLDecodeError) as error:
        logger.error(f"cases.toml: {error}")
        return 2

    if args.dry_run:
        for case in selected:
            logger.info(f"{case.id}  [{case.project}]  {case.why}")
            for index, step in enumerate(case.steps, 1):
                logger.info(f"    {index}. {shlex.join(step.run)}")
        return 0

    if not command_output(["docker", "image", "inspect", "-f", "{{.Id}}", args.image]):
        logger.error(f"docker image {args.image} not found: run `just qa-build`")
        return 2
    if not os.environ.get(GITHUB_TOKEN_ENV):
        logger.warning(f"{GITHUB_TOKEN_ENV} is not set: GitHub data is rate-limited, so some signals may be missing")

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = LOG_ROOT / run_id
    run_dir.mkdir(parents=True)
    setup_logging(run_dir)
    logger.info(f"{len(selected)} case(s); logs in {run_dir}")

    results: list[CaseResult] = []
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = [pool.submit(run_case, case, run_dir, args.image, run_id) for case in selected]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            logger.info(f"[{result.status:5}] {result.case_id} ({result.seconds:.0f}s)")
            for problem in result.problems:
                logger.info(f"          {problem}")

    write_run_json(run_dir, args.image, results)
    counts = {status: sum(r.status == status for r in results) for status in Status}
    logger.info("  ".join(f"{status}: {count}" for status, count in counts.items() if count))
    return 1 if counts[Status.FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
