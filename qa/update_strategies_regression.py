#!/usr/bin/env python3
"""Regression check for the `--update-strategy` tiers against pinned npm and PyPI projects.

Each project under testdata/regression/update-strategies/ is a real manifest + lockfile with
deliberately old dependencies, next to an `expectations.toml` that writes down, per package and
per tier, what OSS IQ should recommend and why. For every project and tier the script runs the
real CLI - `export`, `status --format agent`, `plan`, and `apply --yes` on a throwaway copy - and
checks:

  1. Expectations: the export's verdict for each package matches `expectations.toml`.
  2. Invariants that hold for any project: security moves only packages with an exploitable CVE,
     no tier recommends or applies less than the tier below it, no prerelease below
     cutting-edge, nothing is downgraded, and the widening flag agrees with a reference range
     check (`packaging` for PEP 440, npm's prerelease rule on top of `univers`).
  3. Surfaces agree: plan's two tables, the agent JSON and what apply actually wrote all match
     the export, and `export`/`status`/`plan` leave the project untouched.

Releases after a project's `cutoff_date` are invisible to OSS IQ, and the runtime, config file and
maintenance signals are pinned as well, so a result moves only when OSS IQ's code changes or an
advisory database does. The second shows up as a WARN listing the advisory IDs that appeared or
disappeared since the expectations were written.

A cell (package x tier) may carry `known_issue`: its failures are reported as XFAIL and do not
fail the run, and once none of them reproduce the cell reports XPASS so the marker can go.

Usage:

    uv run python qa/update_strategies_regression.py
    uv run python qa/update_strategies_regression.py --fixture npm --tier security
    uv run python qa/update_strategies_regression.py --fresh      # bypass the HTTP cache
    uv run python qa/update_strategies_regression.py --ossiq-cmd "uvx --from dist/ossiq-X-py3-none-any.whl ossiq"

Exit status: 0 when nothing failed (XFAIL, XPASS and WARN allowed), 1 when a check failed, 2 when
the run could not start (invalid expectations, missing npm/uv, GitHub login pending).

This is a QA script, not a pytest - it hits the network and is kept out of `just qa`.
"""

import argparse
import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, cast

import semver
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_ROOT = REPO_ROOT / "testdata" / "regression" / "update-strategies"
EXPECTATIONS_FILE = "expectations.toml"
DEFAULT_LOG_ROOT = REPO_ROOT / "qa_logs" / "update_strategies"

COMMAND_TIMEOUT = 300
APPLY_TIMEOUT = 600
# ossiq.commands.auth.EXIT_LOGIN_PENDING, spelled out so `--ossiq-cmd` can point at a build that
# is not the source tree this script imports from.
EXIT_LOGIN_PENDING = 75
WIDENING_RUNGS = frozenset({"in_major", "latest"})
UPDATE_IMMEDIATELY = "Update Immediately"
EXPORT_SECTIONS = ("production_packages", "development_packages")
# Auth only: every other OSSIQ_* variable can change a result, and the flags below pin those.
KEPT_OSSIQ_ENV = frozenset({"OSSIQ_GITHUB_TOKEN", "OSSIQ_GITHUB_AUTH", "OSSIQ_GITHUB_CLIENT_ID"})
# `apply` runs `uv sync` in the fixture copy; either variable would aim that sync at another
# environment - the one running this script, or the QA image's shared venv.
DROPPED_ENV = frozenset({"VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"})

# univers declares its versions with attrs' `attr.s` API, whose generated __init__ ty cannot see.
build_semver = cast(Callable[[str], SemverVersion], SemverVersion)

logger = logging.getLogger("ossiq-qa.update-strategies")


# ---------------------------------------------------------------------------
# Tier contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TierContract:
    """What one tier promises, written here rather than read from `ossiq.strategy`.

    These are the oracle the run is judged against, so they must not come from the code under test.
    """

    name: str
    moves_on_drift: bool
    """False when only an exploitable CVE is a reason to move."""
    writes_widening: bool
    """Whether `apply` may write a target the declared range does not admit."""
    admits_prereleases: bool


# deprecation is left out until a fixture carries an end-of-life package: without one, its column
# would only repeat security's.
TIERS: tuple[TierContract, ...] = (
    TierContract("security", moves_on_drift=False, writes_widening=False, admits_prereleases=False),
    TierContract("standard", moves_on_drift=True, writes_widening=False, admits_prereleases=False),
    TierContract("latest", moves_on_drift=True, writes_widening=True, admits_prereleases=False),
    TierContract("cutting-edge", moves_on_drift=True, writes_widening=True, admits_prereleases=True),
)
TIER_NAMES = tuple(tier.name for tier in TIERS)


# ---------------------------------------------------------------------------
# Ecosystems
# ---------------------------------------------------------------------------


class Ecosystem(ABC):
    """Version semantics and manifest/lockfile reading for one registry, independent of OSS IQ's."""

    name: ClassVar[str]
    toolchain: ClassVar[str]
    """The binary `ossiq apply` shells out to for this ecosystem."""

    @abstractmethod
    def key(self, package: str) -> str:
        """Normalize a package name so the export, plan, agent JSON and lockfile agree on it."""

    @abstractmethod
    def is_older(self, version: str, other: str) -> bool:
        """Whether *version* sorts strictly before *other*."""

    @abstractmethod
    def same_version(self, version: str, other: str) -> bool:
        """Whether two version strings name the same release."""

    @abstractmethod
    def is_prerelease(self, version: str) -> bool:
        """Whether *version* is a prerelease."""

    @abstractmethod
    def admits(self, spec: str, version: str) -> bool:
        """Whether the registry's own semantics let *spec* resolve to *version*."""

    @abstractmethod
    def same_spec(self, spec: str, other: str) -> bool:
        """Whether two constraint strings are the same constraint."""

    @abstractmethod
    def declared_specs(self, project: Path) -> dict[str, str]:
        """Read the manifest's direct dependencies as {key: constraint}."""

    @abstractmethod
    def locked_versions(self, project: Path) -> dict[str, str]:
        """Read the lockfile's top-level packages as {key: version}."""

    @abstractmethod
    def apply_landed(self, locked: str, target: str) -> bool:
        """Whether *locked*, read after `apply`, is what applying *target* should have produced."""


class NpmEcosystem(Ecosystem):
    """npm semver ranges and package-lock.json (lockfileVersion 2 and 3)."""

    name = "npm"
    toolchain = "npm"

    def key(self, package: str) -> str:
        return package

    def is_older(self, version: str, other: str) -> bool:
        return semver.Version.parse(version) < semver.Version.parse(other)

    def same_version(self, version: str, other: str) -> bool:
        return semver.Version.parse(version).compare(other) == 0

    def is_prerelease(self, version: str) -> bool:
        return semver.Version.parse(version).prerelease is not None

    def admits(self, spec: str, version: str) -> bool:
        # univers parses the range grammar but skips npm's prerelease rule: a prerelease only
        # matches a comparator that names a prerelease of the same major.minor.patch, so `^12.0.0`
        # rejects 13.0.0-0 although it sorts below 13.0.0.
        if build_semver(version) not in NpmVersionRange.from_native(spec):
            return False
        parsed = semver.Version.parse(version)
        return parsed.prerelease is None or f"{parsed.major}.{parsed.minor}.{parsed.patch}-" in spec

    def same_spec(self, spec: str, other: str) -> bool:
        return spec.strip() == other.strip()

    def declared_specs(self, project: Path) -> dict[str, str]:
        manifest = json.loads((project / "package.json").read_text(encoding="utf-8"))
        specs: dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            specs.update(manifest.get(section) or {})
        return specs

    def locked_versions(self, project: Path) -> dict[str, str]:
        lock = json.loads((project / "package-lock.json").read_text(encoding="utf-8"))
        # Keyed by install path; a nested copy ("a/node_modules/b") belongs to its parent, not to
        # the direct dependency of the same name.
        return {
            path.removeprefix("node_modules/"): meta["version"]
            for path, meta in (lock.get("packages") or {}).items()
            if path.startswith("node_modules/") and "/node_modules/" not in path and "version" in meta
        }

    def apply_landed(self, locked: str, target: str) -> bool:
        # npm installs the newest release the rewritten range admits, which may postdate the cutoff.
        return not self.is_older(locked, target)


class PypiEcosystem(Ecosystem):
    """PEP 440 specifiers, pyproject.toml and uv.lock."""

    name = "pypi"
    toolchain = "uv"

    def key(self, package: str) -> str:
        return canonicalize_name(package)

    def is_older(self, version: str, other: str) -> bool:
        return Version(version) < Version(other)

    def same_version(self, version: str, other: str) -> bool:
        return Version(version) == Version(other)

    def is_prerelease(self, version: str) -> bool:
        return Version(version).is_prerelease

    def admits(self, spec: str, version: str) -> bool:
        # prereleases=True asks only "may this spec ever resolve here"; `packaging` still applies
        # PEP 440's rule that `<0.22` excludes 0.22's own prereleases.
        return SpecifierSet(spec).contains(version, prereleases=True)

    def same_spec(self, spec: str, other: str) -> bool:
        return SpecifierSet(spec) == SpecifierSet(other)

    def declared_specs(self, project: Path) -> dict[str, str]:
        table = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8")).get("project", {})
        lines = list(table.get("dependencies", []))
        for group in table.get("optional-dependencies", {}).values():
            lines.extend(group)
        requirements = [Requirement(line) for line in lines]
        return {canonicalize_name(req.name): str(req.specifier) for req in requirements}

    def locked_versions(self, project: Path) -> dict[str, str]:
        lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
        return {canonicalize_name(pkg["name"]): pkg["version"] for pkg in lock.get("package", []) if "version" in pkg}

    def apply_landed(self, locked: str, target: str) -> bool:
        # `uv lock --upgrade-package name==target` pins the exact release.
        return self.same_version(locked, target)


ECOSYSTEMS: tuple[Ecosystem, ...] = (NpmEcosystem(), PypiEcosystem())


# ---------------------------------------------------------------------------
# Fixtures and expectations
# ---------------------------------------------------------------------------


class FixtureError(Exception):
    """An expectations file or fixture project that cannot be checked as written."""


class SetupError(Exception):
    """Something outside the fixtures keeps the run from starting."""


@dataclass(frozen=True)
class Outcome:
    """What one tier should do with one package."""

    recommended: str | None
    withheld: bool = False
    widening: bool = False
    escalation: bool = False
    known_issue: str | None = None


@dataclass(frozen=True)
class PackageExpectation:
    """One dependency of a fixture: its starting point and the outcome expected at each tier."""

    name: str
    installed: str
    declared: str
    advisories: frozenset[str]
    outcomes: Mapping[str, Outcome]


@dataclass(frozen=True)
class Fixture:
    """A fixture project directory together with its parsed `expectations.toml`."""

    name: str
    path: Path
    ecosystem: Ecosystem
    cutoff_date: str
    cooldown_period: int
    packages: Mapping[str, PackageExpectation]


FIXTURE_KEYS = frozenset({"ecosystem", "cutoff_date", "cooldown_period", "packages"})
PACKAGE_KEYS = frozenset({"installed", "declared", "advisories", *TIER_NAMES})
OUTCOME_KEYS = frozenset({"recommended", "withheld", "widening", "escalation", "known_issue"})


def reject_unknown_keys(where: str, raw: Mapping[str, Any], allowed: frozenset[str]) -> None:
    """Fail on a misspelt key, which would otherwise silently leave an expectation unchecked."""
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise FixtureError(
            f"{where}: unknown key(s) {', '.join(unknown)}; expected one of {', '.join(sorted(allowed))}"
        )


def parse_outcome(where: str, raw: Any) -> Outcome:
    """Validate one `<tier> = { ... }` inline table.

    Raises:
        FixtureError: A wrong type, an unknown key, or a withheld cell that also names a version.
    """
    if not isinstance(raw, dict):
        raise FixtureError(f"{where}: expected an inline table, got {raw!r}")
    reject_unknown_keys(where, raw, OUTCOME_KEYS)
    recommended = raw.get("recommended")
    known_issue = raw.get("known_issue")
    flags = {flag: raw.get(flag, False) for flag in ("withheld", "widening", "escalation")}
    if recommended is not None and not isinstance(recommended, str):
        raise FixtureError(f"{where}: recommended must be a version string")
    if known_issue is not None and not isinstance(known_issue, str):
        raise FixtureError(f"{where}: known_issue must be a string")
    if not all(isinstance(value, bool) for value in flags.values()):
        raise FixtureError(f"{where}: withheld, widening and escalation must be true or false")
    if flags["withheld"] and recommended is not None:
        raise FixtureError(f"{where}: a withheld package has no recommended version")
    return Outcome(
        recommended=recommended,
        withheld=flags["withheld"],
        widening=flags["widening"],
        escalation=flags["escalation"],
        known_issue=known_issue,
    )


def load_fixture(path: Path) -> Fixture:
    """Parse and validate a fixture's `expectations.toml`.

    Args:
        path: The fixture project directory.

    Returns:
        The fixture, its package keys normalized for its ecosystem.

    Raises:
        FixtureError: The file is missing or invalid.
    """
    expectations = path / EXPECTATIONS_FILE
    try:
        raw = tomllib.loads(expectations.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise FixtureError(f"{expectations}: {exc}") from exc
    reject_unknown_keys(str(expectations), raw, FIXTURE_KEYS)

    ecosystem = next((eco for eco in ECOSYSTEMS if eco.name == raw.get("ecosystem")), None)
    if ecosystem is None:
        names = ", ".join(eco.name for eco in ECOSYSTEMS)
        raise FixtureError(f"{expectations}: ecosystem must be one of {names}, got {raw.get('ecosystem')!r}")
    cutoff_date = raw.get("cutoff_date")
    cooldown_period = raw.get("cooldown_period")
    if not isinstance(cutoff_date, str) or not isinstance(cooldown_period, int):
        raise FixtureError(f"{expectations}: cutoff_date (YYYY-MM-DD) and cooldown_period (days) are required")

    packages: dict[str, PackageExpectation] = {}
    for name, entry in (raw.get("packages") or {}).items():
        where = f"{expectations} [packages.{name}]"
        reject_unknown_keys(where, entry, PACKAGE_KEYS)
        if not isinstance(entry.get("installed"), str) or not isinstance(entry.get("declared"), str):
            raise FixtureError(f"{where}: installed and declared are required strings")
        packages[ecosystem.key(name)] = PackageExpectation(
            name=name,
            installed=entry["installed"],
            declared=entry["declared"],
            advisories=frozenset(entry.get("advisories", [])),
            outcomes={tier: parse_outcome(f"{where} {tier}", entry[tier]) for tier in TIER_NAMES if tier in entry},
        )
    if not packages:
        raise FixtureError(f"{expectations}: no [packages.*] tables")
    return Fixture(
        name=path.name,
        path=path,
        ecosystem=ecosystem,
        cutoff_date=cutoff_date,
        cooldown_period=cooldown_period,
        packages=packages,
    )


def discover_fixtures(root: Path, selected: Sequence[str]) -> list[Fixture]:
    """Load every fixture under *root*, or only the *selected* ones.

    Raises:
        FixtureError: A selected name has no fixture, or a fixture is invalid.
    """
    available = {path.parent.name: path.parent for path in sorted(root.glob(f"*/{EXPECTATIONS_FILE}"))}
    unknown = sorted(set(selected) - set(available))
    if unknown:
        raise FixtureError(f"no fixture named {', '.join(unknown)} under {root}; have {', '.join(available)}")
    return [load_fixture(path) for name, path in available.items() if not selected or name in selected]


# ---------------------------------------------------------------------------
# Running ossiq
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    """One subprocess invocation and where its transcript was written."""

    cmd: tuple[str, ...]
    rc: int
    stdout: str
    stderr: str
    elapsed: float
    log_path: Path
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """Whether the command exited 0 within its timeout."""
        return self.rc == 0 and not self.timed_out

    def describe(self) -> str:
        """Summarize the outcome for a check's detail."""
        outcome = "timed out" if self.timed_out else f"exited {self.rc}"
        return f"{outcome} after {self.elapsed:.1f}s; transcript {self.log_path}"


def run_logged(cmd: Sequence[str], *, env: Mapping[str, str], log_path: Path, timeout: int) -> RunResult:
    """Run *cmd* from the repo root, writing command, output and exit status to *log_path*."""
    start = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(list(cmd), cwd=REPO_ROOT, env=dict(env), capture_output=True, text=True, timeout=timeout)
        rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = -1
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
    elapsed = time.monotonic() - start
    log_path.write_text(
        f"CMD: {shlex.join(cmd)}\nRC:  {'TIMEOUT' if timed_out else rc}\nELAPSED: {elapsed:.1f}s\n"
        f"--- stdout\n{stdout}\n--- stderr\n{stderr}\n",
        encoding="utf-8",
    )
    return RunResult(
        cmd=tuple(cmd),
        rc=rc,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed,
        log_path=log_path,
        timed_out=timed_out,
    )


@dataclass(frozen=True)
class Runner:
    """Invokes ossiq with everything that could vary between machines pinned."""

    ossiq_cmd: tuple[str, ...]
    global_args: tuple[str, ...]
    env: Mapping[str, str]

    def ossiq(self, fixture: Fixture, args: Sequence[str], *, log_path: Path, timeout: int) -> RunResult:
        """Run one ossiq subcommand against *fixture*'s pinned settings.

        Raises:
            SetupError: ossiq is waiting for a GitHub login to be approved.
        """
        pinned = (
            "--cutoff-date",
            fixture.cutoff_date,
            "--cooldown-period",
            str(fixture.cooldown_period),
            # Maintenance signals come from live GitHub state, which no cutoff can freeze.
            "--no-stability",
            # The declared engines / requires-python floor then decides, not this machine's runtime.
            "--no-probe-runtime",
        )
        result = run_logged(
            [*self.ossiq_cmd, *self.global_args, *pinned, *args], env=self.env, log_path=log_path, timeout=timeout
        )
        if result.rc == EXIT_LOGIN_PENDING:
            raise SetupError(
                "ossiq is waiting for a GitHub login: run `uv run ossiq auth login`, or set OSSIQ_GITHUB_TOKEN "
                f"(transcript {log_path})"
            )
        return result


def build_env() -> dict[str, str]:
    """This process's environment, minus anything that would change ossiq's answer."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in DROPPED_ENV and (not key.startswith("OSSIQ_") or key in KEPT_OSSIQ_ENV)
    }
    # Wide enough that Rich never wraps a plan row; parse_plan reads them line by line.
    env.update({"COLUMNS": "240", "NO_COLOR": "1"})
    return env


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observed:
    """One package's verdict at one tier, as `ossiq export` reported it."""

    name: str
    installed: str
    declared: str | None
    recommended: str | None
    rung: str | None
    widening: bool
    strategy_widening: bool | None
    motives: frozenset[str]
    withheld_reason: str | None
    escalation: str | None
    next_action: str | None
    advisories: frozenset[str]

    @classmethod
    def from_export(cls, row: Mapping[str, Any]) -> "Observed":
        """Read one `production_packages` / `development_packages` row."""
        strategy = row.get("strategy")
        return cls(
            name=row["package_name"],
            installed=row["installed_version"],
            declared=row.get("version_constraint_declared"),
            recommended=row.get("recommended_version"),
            rung=row.get("recommended_from_rung"),
            widening=bool(row.get("requires_constraint_widening")),
            strategy_widening=bool(strategy.get("requires_widening")) if strategy else None,
            motives=frozenset(strategy.get("motives") or ()) if strategy else frozenset(),
            withheld_reason=strategy.get("withheld_reason") if strategy else None,
            escalation=strategy.get("escalation") if strategy else None,
            next_action=row.get("next_action"),
            advisories=frozenset(cve["id"] for cve in row.get("cve") or ()),
        )

    @property
    def moves(self) -> bool:
        """Whether the export recommends leaving the installed version."""
        return self.recommended is not None and self.recommended != self.installed

    @property
    def target(self) -> str:
        """The version this tier points at: the recommendation, else where it already is."""
        return self.recommended if self.recommended is not None and self.moves else self.installed


@dataclass(frozen=True)
class PlanSections:
    """`ossiq plan`'s two tables: rows apply will write, and rows held for constraint widening."""

    updates: Mapping[str, tuple[str, ...]]
    widening: Mapping[str, tuple[str, ...]]


def parse_plan(stdout: str, ecosystem: Ecosystem) -> PlanSections:
    """Split plan's console output into its tables, keyed by package and holding each row's cells.

    A row's first cell is the package name (a `CVE` marker may follow it). A blank line ends a table.
    """
    updates: dict[str, tuple[str, ...]] = {}
    widening: dict[str, tuple[str, ...]] = {}
    section: dict[str, tuple[str, ...]] | None = None
    widening_next = False
    for line in stdout.splitlines():
        cells = tuple(line.split())
        if not cells:
            section = None
        elif line.lstrip().startswith("Requires constraint widening"):
            widening_next = True
        elif cells[0] == "Package" and "Current" in cells:
            section = widening if widening_next else updates
            widening_next = False
        elif section is not None:
            section[ecosystem.key(cells[0])] = cells
    return PlanSections(updates=updates, widening=widening)


@dataclass(frozen=True)
class AppliedState:
    """The fixture copy's manifest and lockfile after `ossiq apply --yes`."""

    declared: Mapping[str, str]
    locked: Mapping[str, str]


@dataclass(frozen=True)
class TierRun:
    """Everything observed for one fixture at one tier; a surface is None when its command failed."""

    tier: TierContract
    packages: Mapping[str, Observed]
    echoed_strategy: str | None
    agent: Mapping[str, Mapping[str, Any]] | None = None
    agent_strategy: str | None = None
    plan: PlanSections | None = None
    applied: AppliedState | None = None


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


class Status(StrEnum):
    """Outcome of one check."""

    PASS = "PASS"
    FAIL = "FAIL"
    XFAIL = "XFAIL"
    XPASS = "XPASS"
    WARN = "WARN"


STATUS_SEVERITY = {Status.PASS: 0, Status.WARN: 1, Status.XPASS: 2, Status.XFAIL: 3, Status.FAIL: 4}


@dataclass(frozen=True)
class Check:
    """One verified claim about one fixture, tier and package (either may be None)."""

    fixture: str
    tier: str | None
    package: str | None
    name: str
    status: Status
    detail: str = ""


def verdict(
    fixture: Fixture,
    name: str,
    problems: Sequence[str],
    *,
    tier: str | None = None,
    package: str | None = None,
) -> Check:
    """A check that passed when *problems* is empty and failed listing them otherwise."""
    return Check(fixture.name, tier, package, name, Status.FAIL if problems else Status.PASS, "; ".join(problems))


def writes(tier: TierContract, pkg: Observed) -> bool:
    """Whether `apply` at *tier* should write *pkg*'s recommendation."""
    return pkg.moves and (not pkg.widening or tier.writes_widening)


def applied_target(tier: TierContract, pkg: Observed) -> str:
    """The version `apply` at *tier* should leave *pkg* on."""
    return pkg.target if writes(tier, pkg) else pkg.installed


def fixture_checks(fixture: Fixture) -> list[Check]:
    """The fixture on disk still starts where its expectations say, with nothing left unexpected."""
    eco = fixture.ecosystem
    declared = eco.declared_specs(fixture.path)
    locked = eco.locked_versions(fixture.path)
    checks: list[Check] = []
    for key, expected in fixture.packages.items():
        problems = []
        if key not in declared:
            problems.append("not declared in the manifest")
        elif not eco.same_spec(declared[key], expected.declared):
            problems.append(f"manifest declares {declared[key]!r}, expectations say {expected.declared!r}")
        if key not in locked:
            problems.append("not in the lockfile")
        elif not eco.same_version(locked[key], expected.installed):
            problems.append(f"lockfile has {locked[key]}, expectations say {expected.installed}")
        checks.append(verdict(fixture, "fixture-matches-expectations", problems, package=key))
    unchecked = sorted(set(declared) - set(fixture.packages))
    checks.append(
        verdict(fixture, "every-dependency-has-expectations", [f"no [packages.{name}]" for name in unchecked])
    )
    return checks


def expectation_checks(fixture: Fixture, runs: Sequence[TierRun]) -> list[Check]:
    """Compare each export verdict with `expectations.toml`, plus the inputs the export read."""
    eco = fixture.ecosystem
    checks: list[Check] = []
    for key, expected in fixture.packages.items():
        first = next((run.packages[key] for run in runs if key in run.packages), None)
        if first is not None:
            problems = []
            if not eco.same_version(first.installed, expected.installed):
                problems.append(f"export reads installed {first.installed}, expected {expected.installed}")
            if first.declared is None or not eco.same_spec(first.declared, expected.declared):
                problems.append(f"export reads declared {first.declared!r}, expected {expected.declared!r}")
            checks.append(verdict(fixture, "export-reads-fixture", problems, package=key))
            if first.advisories != expected.advisories:
                appeared = ", ".join(sorted(first.advisories - expected.advisories)) or "none"
                gone = ", ".join(sorted(expected.advisories - first.advisories)) or "none"
                detail = f"advisories changed since expectations were written: +[{appeared}] -[{gone}]"
                checks.append(Check(fixture.name, None, key, "advisories-unchanged", Status.WARN, detail))

        for run in runs:
            outcome = expected.outcomes.get(run.tier.name)
            if outcome is None:
                continue
            observed = run.packages.get(key)
            if observed is None:
                checks.append(
                    verdict(fixture, "expectation", ["missing from the export"], tier=run.tier.name, package=key)
                )
                continue
            checks.append(
                verdict(
                    fixture, "expectation", outcome_mismatches(eco, outcome, observed), tier=run.tier.name, package=key
                )
            )

    for run in runs:
        for key in sorted(set(run.packages) - set(fixture.packages)):
            detail = "exported but has no expectations"
            checks.append(Check(fixture.name, run.tier.name, key, "expectation", Status.WARN, detail))
    return checks


def outcome_mismatches(eco: Ecosystem, outcome: Outcome, observed: Observed) -> list[str]:
    """Each way *observed* differs from *outcome*, phrased as expected-vs-got."""
    mismatches = []
    got = observed.recommended if observed.moves else None
    if (got is None) != (outcome.recommended is None) or (
        got is not None and outcome.recommended is not None and not eco.same_version(got, outcome.recommended)
    ):
        mismatches.append(f"recommended: expected {outcome.recommended or 'none'}, got {got or 'none'}")
    for label, expected, actual in (
        ("withheld", outcome.withheld, bool(observed.withheld_reason)),
        ("widening", outcome.widening, observed.widening),
        ("escalation", outcome.escalation, bool(observed.escalation)),
    ):
        if expected != actual:
            mismatches.append(f"{label}: expected {str(expected).lower()}, got {str(actual).lower()}")
    if mismatches and observed.escalation:
        mismatches.append(f"(escalation: {observed.escalation})")
    return mismatches


def package_invariants(fixture: Fixture, run: TierRun) -> list[Check]:
    """Rules that hold for any package at this tier, whatever expectations.toml says."""
    tier = run.tier
    echo = [] if run.echoed_strategy == tier.name else [f"export metadata.update_strategy is {run.echoed_strategy!r}"]
    checks = [verdict(fixture, "export-echoes-tier", echo, tier=tier.name)]
    for key, pkg in run.packages.items():
        for name, problems in package_rules(fixture.ecosystem, tier, pkg):
            checks.append(verdict(fixture, name, problems, tier=tier.name, package=key))
    return checks


def package_rules(eco: Ecosystem, tier: TierContract, pkg: Observed) -> list[tuple[str, list[str]]]:
    """Each per-package invariant at *tier*, as (check name, problems found)."""
    motive = []
    if not tier.moves_on_drift:
        extra = sorted(pkg.motives - {"exploitable_cve"})
        if extra:
            motive.append(f"admits {', '.join(extra)} at a tier that moves only on a CVE")
        if pkg.moves and "exploitable_cve" not in pkg.motives:
            motive.append(f"moves to {pkg.recommended} without an exploitable_cve motive")

    withheld = []
    if pkg.withheld_reason:
        if pkg.moves:
            withheld.append(f"withheld, yet recommends {pkg.recommended}")
        if pkg.next_action == UPDATE_IMMEDIATELY:
            withheld.append(f"withheld, yet next_action is {UPDATE_IMMEDIATELY!r}")

    widening = []
    if pkg.widening != (pkg.rung in WIDENING_RUNGS):
        widening.append(f"requires_constraint_widening={pkg.widening} with recommended_from_rung={pkg.rung}")
    if pkg.strategy_widening is not None and pkg.moves and pkg.strategy_widening != pkg.widening:
        widening.append(
            f"requires_constraint_widening={pkg.widening} but strategy.requires_widening={pkg.strategy_widening}"
        )
    if pkg.moves and pkg.recommended is not None and pkg.declared:
        admitted = eco.admits(pkg.declared, pkg.recommended)
        if pkg.widening == admitted:
            verb = "admits" if admitted else "does not admit"
            widening.append(
                f"{pkg.declared!r} {verb} {pkg.recommended}, yet requires_constraint_widening={pkg.widening}"
            )

    prerelease = []
    if (
        pkg.moves
        and pkg.recommended is not None
        and not tier.admits_prereleases
        and eco.is_prerelease(pkg.recommended)
        and not eco.is_prerelease(pkg.installed)
    ):
        prerelease.append(f"recommends the prerelease {pkg.recommended}")

    downgrade = []
    if pkg.moves and pkg.recommended is not None and eco.is_older(pkg.recommended, pkg.installed):
        downgrade.append(f"recommends {pkg.recommended}, below installed {pkg.installed}")

    return [
        ("moves-only-on-admitted-motive", motive),
        ("withheld-means-no-move", withheld),
        ("widening-flag-matches-range", widening),
        ("no-prerelease-below-cutting-edge", prerelease),
        ("no-downgrade", downgrade),
    ]


def cross_tier_invariants(fixture: Fixture, runs: Sequence[TierRun]) -> list[Check]:
    """Climbing the pyramid never lowers a recommendation, nor what apply writes.

    Attributed to the higher tier of each adjacent pair, which is where a fix would go.
    """
    eco = fixture.ecosystem
    checks: list[Check] = []
    for lower, higher in zip(runs, runs[1:], strict=False):
        for key, high in higher.packages.items():
            low = lower.packages.get(key)
            if low is None:
                continue
            recommendation = []
            if eco.is_older(high.target, low.target):
                recommendation.append(
                    f"{higher.tier.name} points at {high.target}, below {lower.tier.name}'s {low.target}"
                )
            checks.append(
                verdict(fixture, "recommendation-monotonic", recommendation, tier=higher.tier.name, package=key)
            )
            applied = []
            high_applied, low_applied = applied_target(higher.tier, high), applied_target(lower.tier, low)
            if eco.is_older(high_applied, low_applied):
                applied.append(
                    f"{higher.tier.name} applies {high_applied}, below {lower.tier.name}'s {low_applied} "
                    f"({higher.tier.name} recommends {high.target}"
                    f"{', held for widening' if high.moves and not writes(higher.tier, high) else ''})"
                )
            checks.append(verdict(fixture, "apply-monotonic", applied, tier=higher.tier.name, package=key))
    return checks


def surface_checks(fixture: Fixture, run: TierRun, declared_before: Mapping[str, str]) -> list[Check]:
    """plan, the agent JSON and apply's result must all say what the export says."""
    eco = fixture.ecosystem
    tier = run.tier
    checks: list[Check] = []

    if run.agent is not None:
        echo = [] if run.agent_strategy == tier.name else [f"agent update_strategy is {run.agent_strategy!r}"]
        checks.append(verdict(fixture, "agent-echoes-tier", echo, tier=tier.name))

    for key, pkg in run.packages.items():
        if run.plan is not None:
            checks.append(
                verdict(
                    fixture, "plan-matches-export", plan_problems(run.plan, tier, key, pkg), tier=tier.name, package=key
                )
            )
        if run.agent is not None:
            checks.append(
                verdict(
                    fixture,
                    "agent-matches-export",
                    agent_problems(eco, run.agent.get(key), pkg),
                    tier=tier.name,
                    package=key,
                )
            )
        if run.applied is not None:
            checks.append(
                verdict(
                    fixture,
                    "apply-lands-plan",
                    apply_problems(eco, run.applied, tier, key, pkg, declared_before.get(key)),
                    tier=tier.name,
                    package=key,
                )
            )
    return checks


def plan_problems(plan: PlanSections, tier: TierContract, key: str, pkg: Observed) -> list[str]:
    """A writable move belongs in plan's update table, a held one under widening, no move in neither."""
    expected = None
    if pkg.moves:
        expected = "update" if writes(tier, pkg) else "widening"
    problems = []
    for label, rows in (("update", plan.updates), ("widening", plan.widening)):
        row = rows.get(key)
        if label == expected:
            if row is None:
                problems.append(f"missing from plan's {label} table")
            elif pkg.recommended not in row:
                problems.append(f"plan's {label} row reads {' '.join(row)!r}, not {pkg.recommended}")
        elif row is not None:
            problems.append(f"listed in plan's {label} table: {' '.join(row)!r}")
    return problems


def agent_problems(eco: Ecosystem, entry: Mapping[str, Any] | None, pkg: Observed) -> list[str]:
    """`status --format agent` must name the same target and widening as the export."""
    if entry is None:
        return ["missing from status --format agent"]
    problems = []
    to = entry.get("to")
    if pkg.moves and pkg.recommended is not None:
        if to is None or not eco.same_version(to, pkg.recommended):
            problems.append(f"agent 'to' is {to!r}, export recommends {pkg.recommended}")
    elif to not in (None, pkg.installed):
        problems.append(f"agent 'to' is {to!r}, export recommends no move")
    agent_widening = bool(entry.get("requires_constraint_widening"))
    if agent_widening != pkg.widening:
        problems.append(f"agent requires_constraint_widening={agent_widening}, export {pkg.widening}")
    return problems


def apply_problems(
    eco: Ecosystem, applied: AppliedState, tier: TierContract, key: str, pkg: Observed, declared_before: str | None
) -> list[str]:
    """What apply wrote: the recommendation where the tier writes it, nothing at all elsewhere."""
    locked = applied.locked.get(key)
    declared = applied.declared.get(key)
    if locked is None:
        return ["not in the lockfile after apply"]
    problems = []
    if writes(tier, pkg) and pkg.recommended is not None:
        if not eco.apply_landed(locked, pkg.recommended):
            problems.append(f"lockfile has {locked} after apply, expected {pkg.recommended}")
        if declared is not None and not eco.admits(declared, locked):
            problems.append(f"manifest now declares {declared!r}, which does not admit the locked {locked}")
    else:
        why = "held for widening" if pkg.moves else "no move"
        if not eco.same_version(locked, pkg.installed):
            problems.append(f"lockfile moved {pkg.installed} -> {locked} ({why})")
        if declared_before is not None and declared is not None and not eco.same_spec(declared, declared_before):
            problems.append(f"manifest changed {declared_before!r} -> {declared!r} ({why})")
    return problems


def resolve_known_issues(fixture: Fixture, tiers_run: frozenset[str], checks: Sequence[Check]) -> list[Check]:
    """Downgrade failures in `known_issue` cells to XFAIL, and flag known issues that stopped failing."""
    known = {
        (key, tier): outcome.known_issue
        for key, expected in fixture.packages.items()
        for tier, outcome in expected.outcomes.items()
        if outcome.known_issue and tier in tiers_run
    }
    resolved: list[Check] = []
    reproduced: set[tuple[str | None, str | None]] = set()
    for check in checks:
        issue = known.get((check.package or "", check.tier or ""))
        if issue and check.status is Status.FAIL:
            resolved.append(replace(check, status=Status.XFAIL, detail=f"{check.detail} [known issue: {issue}]"))
            reproduced.add((check.package, check.tier))
        else:
            resolved.append(check)
    for (key, tier), issue in known.items():
        if (key, tier) not in reproduced:
            detail = f"known issue no longer reproduces; remove known_issue from {fixture.name}: {issue}"
            resolved.append(Check(fixture.name, tier, key, "known-issue", Status.XPASS, detail))
    return resolved


# ---------------------------------------------------------------------------
# Per-fixture run
# ---------------------------------------------------------------------------


def fingerprint(project: Path) -> dict[str, str]:
    """Content hash of every file under *project*, keyed by relative path."""
    return {
        str(path.relative_to(project)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(project.rglob("*"))
        if path.is_file()
    }


def command_check(fixture: Fixture, tier: TierContract, name: str, result: RunResult) -> Check:
    """Record whether one ossiq command succeeded, pointing at its transcript either way."""
    problems = [] if result.ok else [result.describe()]
    logger.info("  %-12s %-6s %s (%.1fs)", tier.name, name, "ok" if result.ok else "FAILED", result.elapsed)
    return verdict(fixture, f"command-{name}", problems, tier=tier.name)


def run_tier(
    fixture: Fixture,
    tier: TierContract,
    runner: Runner,
    pristine: Path,
    work: Path,
    logs: Path,
    *,
    skip_apply: bool,
) -> tuple[TierRun | None, list[Check]]:
    """Run export, agent status, plan and (unless skipped) apply for one tier.

    Returns:
        The observations (None when export itself failed) and the command-level checks.
    """
    eco = fixture.ecosystem
    checks: list[Check] = []
    before = fingerprint(pristine)
    strategy = ["--update-strategy", tier.name]

    export_path = logs / "export.json"
    export = runner.ossiq(
        fixture,
        ["export", *strategy, "--output", str(export_path), str(pristine)],
        log_path=logs / "export.log",
        timeout=COMMAND_TIMEOUT,
    )
    checks.append(command_check(fixture, tier, "export", export))
    if not export.ok:
        return None, checks
    document = json.loads(export_path.read_text(encoding="utf-8"))
    packages = {
        eco.key(row["package_name"]): Observed.from_export(row)
        for section in EXPORT_SECTIONS
        for row in document.get(section) or ()
    }

    agent: dict[str, Mapping[str, Any]] | None = None
    agent_strategy: str | None = None
    status = runner.ossiq(
        fixture,
        ["status", "--format", "agent", *strategy, str(pristine)],
        log_path=logs / "status_agent.log",
        timeout=COMMAND_TIMEOUT,
    )
    checks.append(command_check(fixture, tier, "agent", status))
    if status.ok:
        try:
            decision = json.loads(status.stdout)
        except json.JSONDecodeError as exc:
            checks.append(verdict(fixture, "agent-is-json", [f"{exc}; transcript {status.log_path}"], tier=tier.name))
        else:
            agent = {eco.key(entry["package"]): entry for entry in decision.get("updates", [])}
            agent_strategy = decision.get("update_strategy")

    plan = runner.ossiq(
        fixture, ["plan", *strategy, str(pristine)], log_path=logs / "plan.log", timeout=COMMAND_TIMEOUT
    )
    checks.append(command_check(fixture, tier, "plan", plan))
    sections = parse_plan(plan.stdout, eco) if plan.ok else None

    after = fingerprint(pristine)
    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    checks.append(
        verdict(fixture, "read-only-commands-leave-project", [f"modified {path}" for path in changed], tier=tier.name)
    )

    applied: AppliedState | None = None
    if not skip_apply:
        target = work / "apply"
        shutil.copytree(pristine, target)
        result = runner.ossiq(
            fixture, ["apply", "--yes", *strategy, str(target)], log_path=logs / "apply.log", timeout=APPLY_TIMEOUT
        )
        checks.append(command_check(fixture, tier, "apply", result))
        if result.ok:
            applied = AppliedState(declared=eco.declared_specs(target), locked=eco.locked_versions(target))

    run = TierRun(
        tier=tier,
        packages=packages,
        echoed_strategy=(document.get("metadata") or {}).get("update_strategy"),
        agent=agent,
        agent_strategy=agent_strategy,
        plan=sections,
        applied=applied,
    )
    return run, checks


@dataclass(frozen=True)
class FixtureResult:
    """A fixture's observations per tier and every check made on them."""

    fixture: Fixture
    runs: tuple[TierRun, ...]
    checks: tuple[Check, ...] = field(default_factory=tuple)


def run_fixture(
    fixture: Fixture,
    tiers: Sequence[TierContract],
    runner: Runner,
    *,
    log_root: Path,
    work_root: Path,
    skip_apply: bool,
) -> FixtureResult:
    """Run every selected tier against a pristine copy of *fixture* and check the results."""
    logger.info("%s (%s, cutoff %s)", fixture.name, fixture.ecosystem.name, fixture.cutoff_date)
    checks = fixture_checks(fixture)
    pristine = work_root / fixture.name / "pristine"
    shutil.copytree(fixture.path, pristine, ignore=shutil.ignore_patterns(EXPECTATIONS_FILE))
    declared_before = fixture.ecosystem.declared_specs(pristine)

    runs: list[TierRun] = []
    for tier in tiers:
        logs = log_root / fixture.name / tier.name
        logs.mkdir(parents=True, exist_ok=True)
        run, tier_checks = run_tier(
            fixture, tier, runner, pristine, work_root / fixture.name / tier.name, logs, skip_apply=skip_apply
        )
        checks.extend(tier_checks)
        if run is not None:
            runs.append(run)

    checks.extend(expectation_checks(fixture, runs))
    for run in runs:
        checks.extend(package_invariants(fixture, run))
        checks.extend(surface_checks(fixture, run, declared_before))
    checks.extend(cross_tier_invariants(fixture, runs))
    resolved = resolve_known_issues(fixture, frozenset(run.tier.name for run in runs), checks)
    return FixtureResult(fixture=fixture, runs=tuple(runs), checks=tuple(resolved))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def cell_text(pkg: Observed | None, status: Status) -> str:
    """One matrix cell: the target plus markers, then the cell's worst check status."""
    if pkg is None:
        text = "missing"
    elif pkg.withheld_reason:
        text = "withheld"
    elif not pkg.moves:
        text = "="
    else:
        text = f"{pkg.recommended}{'^' if pkg.widening else ''}{'!' if pkg.escalation else ''}"
    return text if status is Status.PASS else f"{text} {status.value.lower()}"


def log_matrix(result: FixtureResult) -> None:
    """Log the package x tier table for one fixture."""
    worst: dict[tuple[str | None, str | None], Status] = {}
    for check in result.checks:
        cell = (check.package, check.tier)
        if STATUS_SEVERITY[check.status] > STATUS_SEVERITY[worst.get(cell, Status.PASS)]:
            worst[cell] = check.status
    header = ["package", "installed", *(run.tier.name for run in result.runs)]
    rows = [header]
    for key, expected in result.fixture.packages.items():
        cells = [cell_text(run.packages.get(key), worst.get((key, run.tier.name), Status.PASS)) for run in result.runs]
        observed = next((run.packages[key] for run in result.runs if key in run.packages), None)
        rows.append([expected.name, observed.installed if observed else expected.installed, *cells])
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    logger.info("")
    logger.info("%s (%s, cutoff %s)", result.fixture.name, result.fixture.ecosystem.name, result.fixture.cutoff_date)
    for row in rows:
        logger.info("  %s", "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)))


def log_report(results: Sequence[FixtureResult], log_root: Path) -> None:
    """Log the matrices, every non-passing check, and the totals."""
    for result in results:
        log_matrix(result)
    logger.info("")
    logger.info("  ^ requires widening (written by apply only at latest/cutting-edge)  ! escalated  = no move")

    checks = [check for result in results for check in result.checks]
    notable = sorted(
        (check for check in checks if check.status is not Status.PASS),
        key=lambda check: (-STATUS_SEVERITY[check.status], check.fixture, check.tier or "", check.package or ""),
    )
    if notable:
        logger.info("")
    for check in notable:
        where = " / ".join(part for part in (check.fixture, check.tier, check.package) if part)
        logger.info("%-5s %s  %s: %s", check.status.value, where, check.name, check.detail)

    drifted = {(c.fixture, c.package) for c in checks if c.name == "advisories-unchanged"}
    suspect = sorted(
        {f"{c.fixture}/{c.package}" for c in checks if c.status is Status.FAIL and (c.fixture, c.package) in drifted}
    )
    if suspect:
        logger.info("")
        logger.info(
            "Advisory data changed for failing package(s) %s: re-check before blaming the code.", ", ".join(suspect)
        )

    counts = {status: sum(1 for check in checks if check.status is status) for status in Status}
    logger.info("")
    logger.info("%s  (logs: %s)", "  ".join(f"{status.value} {count}" for status, count in counts.items()), log_root)


def write_report(results: Sequence[FixtureResult], path: Path, metadata: Mapping[str, Any]) -> None:
    """Write every observation and check as JSON, for diffing two runs."""
    document = {
        **metadata,
        "fixtures": {
            result.fixture.name: {
                "ecosystem": result.fixture.ecosystem.name,
                "cutoff_date": result.fixture.cutoff_date,
                "observed": {
                    run.tier.name: {key: asdict(pkg) for key, pkg in run.packages.items()} for run in result.runs
                },
            }
            for result in results
        },
        "checks": [asdict(check) for result in results for check in result.checks],
    }
    path.write_text(json.dumps(document, indent=2, default=sorted) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Check every --update-strategy tier against the pinned projects in testdata/regression/."
    )
    parser.add_argument(
        "--fixtures-root", type=Path, default=FIXTURES_ROOT, help=f"Directory of fixtures (default: {FIXTURES_ROOT})."
    )
    parser.add_argument("--fixture", action="append", default=[], help="Run only this fixture (repeatable).")
    parser.add_argument(
        "--tier", action="append", default=[], choices=TIER_NAMES, help="Run only this tier (repeatable)."
    )
    parser.add_argument("--skip-apply", action="store_true", help="Do not run `apply`; npm and uv are then not needed.")
    parser.add_argument("--fresh", action="store_true", help="Pass --no-cache, so registry and advisory data is live.")
    parser.add_argument("--cache-destination", type=Path, help="HTTP cache file for ossiq (default: ossiq's own).")
    parser.add_argument(
        "--ossiq-cmd",
        default=shlex.join([sys.executable, "-m", "ossiq.cli"]),
        help="How to invoke ossiq, e.g. to check a built wheel (default: this checkout).",
    )
    parser.add_argument("--output-dir", type=Path, help=f"Where logs go (default: {DEFAULT_LOG_ROOT}/<timestamp>).")
    parser.add_argument("--keep-workdirs", action="store_true", help="Keep the fixture copies apply wrote to.")
    return parser.parse_args(argv)


def setup_logging(log_root: Path) -> None:
    """Log plain lines to stdout and timestamped ones to summary.log."""
    logger.setLevel(logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(message)s"))
    file_handler = logging.FileHandler(log_root / "summary.log", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(console)
    logger.addHandler(file_handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the regression and return the exit status."""
    args = parse_args(argv)
    started = datetime.now(UTC)
    log_root: Path = args.output_dir or DEFAULT_LOG_ROOT / started.strftime("%Y%m%dT%H%M%SZ")
    log_root.mkdir(parents=True, exist_ok=True)
    setup_logging(log_root)
    tiers = [tier for tier in TIERS if not args.tier or tier.name in args.tier]
    work_root = Path(tempfile.mkdtemp(prefix="ossiq-update-strategies-"))
    try:
        fixtures = discover_fixtures(args.fixtures_root, args.fixture)
        if not args.skip_apply:
            missing = sorted({f.ecosystem.toolchain for f in fixtures if shutil.which(f.ecosystem.toolchain) is None})
            if missing:
                raise SetupError(
                    f"apply needs {', '.join(missing)} on PATH; install what is missing or pass --skip-apply"
                )
        # An empty config file replaces ~/.config/ossiq/config, so a developer's own settings
        # cannot leak into the run.
        empty_config = log_root / "ossiq.env"
        empty_config.write_text("", encoding="utf-8")
        cache = ["--no-cache"] if args.fresh else []
        if args.cache_destination and not args.fresh:
            cache = ["--cache-destination", str(args.cache_destination)]
        runner = Runner(
            ossiq_cmd=tuple(shlex.split(args.ossiq_cmd)),
            global_args=("--config", str(empty_config), *cache),
            env=build_env(),
        )
        results = [
            run_fixture(fixture, tiers, runner, log_root=log_root, work_root=work_root, skip_apply=args.skip_apply)
            for fixture in fixtures
        ]
    except (FixtureError, SetupError) as exc:
        logger.error("cannot run: %s", exc)
        return 2
    finally:
        if args.keep_workdirs:
            logger.info("fixture copies kept in %s", work_root)
        else:
            shutil.rmtree(work_root, ignore_errors=True)

    write_report(
        results,
        log_root / "report.json",
        {
            "started": started.isoformat(),
            "ossiq_cmd": args.ossiq_cmd,
            "fresh": args.fresh,
            "apply": not args.skip_apply,
            "tiers": [tier.name for tier in tiers],
        },
    )
    log_report(results, log_root)
    return 1 if any(check.status is Status.FAIL for result in results for check in result.checks) else 0


if __name__ == "__main__":
    sys.exit(main())
