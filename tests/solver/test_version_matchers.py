"""Tests for version_matchers — npm semver and PyPI/PEP 440 constraint matching.

Pipeline under test:
    raw constraint string
        ├── npm  →  npm_version_satisfies_range()
        ├── pypi →  (via) version_satisfies_constraint() with PEP 440 specifier
        └── unified → version_satisfies_constraint()
"""

from __future__ import annotations

import pytest

from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, AffectedRange, Severity
from ossiq.solver.problem import CandidateVersion
from ossiq.solver.version_matchers import (
    cve_affects_version,
    engine_mismatch_reason,
    engine_version_satisfies_requirement,
    has_engine_mismatch,
    npm_version_satisfies_range,
    pypi_version_satisfies_specifier,
    stricter_engine_floor,
    version_satisfies_constraint,
)

# ── npm_version_satisfies_range ────────────────────────────────────────────


@pytest.mark.parametrize(
    "version, range_constraint, expected",
    [
        # caret: compatible with same major
        ("1.3.0", "^1.2.0", True),
        ("2.0.0", "^1.2.0", False),
        ("1.2.0", "^1.2.0", True),
        # tilde: compatible with same minor
        ("1.2.5", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        # a partial version is an X-range: "14" is 14.x.x, "1.2" is 1.2.x
        ("14.1.0", "14", True),
        ("15.0.0", "14", False),
        ("14.0.0", "14", True),
        # comparison operators
        ("1.5.0", ">=1.0.0", True),
        ("0.9.0", ">=1.0.0", False),
        ("0.9.0", "<1.0.0", True),
        ("1.0.0", "<1.0.0", False),
        ("1.2.9", "1.2", True),
        ("1.3.0", "1.2", False),
        ("1.0.0", "<=1.0.0", True),
        # a partial version after an operator is an X-range too: ">1" is >=2.0.0
        ("1.0.1", ">1", False),
        ("2.0.0", ">1", True),
        ("1.9.9", "<=1", True),
        # npm has no != operator: an invalid range passes through rather than blocking
        ("1.0.0", "!=1.0.0", True),
        # || union — bare versions
        ("14.1.0", "12 || 14", True),
        ("16.0.0", "12 || 14", False),
        ("12.5.0", "12 || 14", True),
        # || union — mixed caret + tilde
        ("1.3.0", "^1.2 || ~2.3", True),
        ("2.3.5", "^1.2 || ~2.3", True),
        ("3.0.0", "^1.2 || ~2.3", False),
        # || union — compound comparator ranges across branches
        ("3.5.0", ">=3.0.0 <4.0.0 || >=5.0.0 <6.0.0", True),
        ("5.5.0", ">=3.0.0 <4.0.0 || >=5.0.0 <6.0.0", True),
        ("4.5.0", ">=3.0.0 <4.0.0 || >=5.0.0 <6.0.0", False),
        # npm alias — match against the embedded range, not the aliased name
        ("7.5.0", "npm:wrap-ansi@^7.0.0", True),
        ("8.1.0", "npm:wrap-ansi@^7.0.0", False),
        ("1.2.5", "npm:@scope/pkg@~1.2.0", True),
        ("1.3.0", "npm:@scope/pkg@~1.2.0", False),
        # unparseable version/constraint → pass through (True)
        ("not.a.version", "^1.0.0", True),
        ("1.0.0", "???", True),
        # a prerelease satisfies only a range naming a prerelease of the same major.minor.patch
        ("1.3.0-rc.1", "^1.2.0", False),
        ("2.0.0-beta.3", "^2.0.0-beta.1", True),
        ("2.1.0-beta.1", "^2.0.0-beta.1", False),
        # prerelease floors are real bounds, not pass-throughs
        ("3.5.0", ">=2.9.0 || >=3.0.0-0 <3.0.0", True),
        ("3.5.0", ">=3.0.0-0", True),
        ("2.0.0", ">=3.0.0-0", False),
        ("6.5.0", ">=2.9.0 || >=3.0.0-0 <3.0.0 || >=6.0.1 <8.0.0", True),
        # hyphen range
        ("1.5.0", "1.2.3 - 2.0.0", True),
        # || union — two tildes sharing an upper bound; each branch must hold on its own, or
        # 6.1.13 slips through (@pdfme/common on testdata/npm/version-constrained)
        ("6.1.13", "~5.5.8 || ~5.5.10", False),
        ("5.5.9", "~5.5.8 || ~5.5.10", True),
        ("5.5.11", "~5.5.8 || ~5.5.10", True),
        ("5.6.0", "~5.5.8 || ~5.5.10", False),
        # || union — carets, whose bound pairs stay adjacent even when flattened
        ("1.5.0", "^1.0.0 || ^2.0.0", True),
        ("2.5.0", "^1.0.0 || ^2.0.0", True),
        ("3.0.0", "^1.0.0 || ^2.0.0", False),
        # comparator X-ranges (engines.node ">=14.x")
        ("14.0.0", ">=14.x", True),
        ("13.9.0", ">=14.x", False),
        ("16.0.0", ">= 14.x", True),
        ("1.9.9", "<=1.x", True),
        ("2.0.0", "<=1.x", False),
        ("1.5.0", ">1.x", False),
        ("2.0.0", ">1.x", True),
        ("2.5.0", ">=1.x <3", True),
        # X-ranges under a caret, and wildcard components
        ("0.5.0", "^0.x", True),
        ("1.0.0", "^1.x", True),
        ("1.5.0", "1.*.*", True),
        # an empty range is "*"
        ("1.5.0", "", True),
    ],
)
def test_npm_version_satisfies_range(version: str, range_constraint: str, expected: bool) -> None:
    assert npm_version_satisfies_range(version, range_constraint) == expected


def test_npm_version_satisfies_range_include_prerelease() -> None:
    assert npm_version_satisfies_range("1.3.0-rc.1", ">=1.2.0", include_prerelease=True) is True


# ── _pypi_version_satisfies_specifier ─────────────────────────────────────


@pytest.mark.parametrize(
    "version, specifier, expected",
    [
        ("1.5.0", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
        ("1.2.3", "==1.2.3", True),
        ("1.2.4", "==1.2.3", False),
        ("1.4.2", "~=1.4", True),
        ("1.5.0", "~=1.4", True),  # ~=1.4 → >=1.4,<2.0 (two-component specifier, PEP 440 §8.4)
        ("2.0.0", "~=1.4", False),
        ("1.4.2", "~=1.4.2", True),
        ("1.5.0", "~=1.4.2", False),  # ~=1.4.2 → >=1.4.2,<1.5 (three-component specifier)
        ("1.2.3", "!=1.2.3", False),
        ("1.2.4", "!=1.2.3", True),
    ],
)
def test_pypi_version_satisfies_specifier(version: str, specifier: str, expected: bool) -> None:
    assert pypi_version_satisfies_specifier(version, specifier) == expected


# ── version_satisfies_constraint (unified) ────────────────────────────────


def test_version_satisfies_constraint_none_always_true() -> None:
    assert version_satisfies_constraint("1.2.3", None, ProjectPackagesRegistry.PYPI) is True


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("registry", [ProjectPackagesRegistry.PYPI, ProjectPackagesRegistry.NPM])
def test_version_satisfies_constraint_blank_means_unconstrained(blank: str, registry: ProjectPackagesRegistry) -> None:
    # PyPI publishes an unconstrained requirement as an empty specifier
    assert version_satisfies_constraint("2.34.2", blank, registry) is True


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        ("1.5.0", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
        ("1.2.3", "==1.2.3", True),
        # unknown/unparseable → passthrough True
        ("1.0.0", "???", True),
    ],
)
def test_version_satisfies_constraint_pypi(version: str, constraint: str, expected: bool) -> None:
    assert version_satisfies_constraint(version, constraint, ProjectPackagesRegistry.PYPI) == expected


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        ("1.3.0", "^1.2.0", True),
        ("2.0.0", "^1.2.0", False),
        ("14.1.0", "14 || 16", True),
        ("15.0.0", "14 || 16", False),
        # unknown/unparseable → passthrough True
        ("1.0.0", "???", True),
    ],
)
def test_version_satisfies_constraint_npm(version: str, constraint: str, expected: bool) -> None:
    assert version_satisfies_constraint(version, constraint, ProjectPackagesRegistry.NPM) == expected


# ── engine_version_satisfies_requirement ──────────────────────────────────


@pytest.mark.parametrize(
    "engine_key, context_version, requirement, expected",
    [
        # python → PEP 440
        ("python", "3.11.9", ">=3.9", True),
        ("python", "3.8.0", ">=3.9", False),
        ("python", "3.11.9", ">=3.9,<3.13", True),
        # node → npm semver
        ("node", "18.12.0", ">=16", True),
        ("node", "14.0.0", ">=16", False),
        ("nodejs", "18.0.0", "^18", True),
        ("nodejs", "20.0.0", "^18", False),
        ("node", "20.0.0", ">=14.x", True),
        ("node", "12.22.0", ">=14.x", False),
        # package managers → npm semver. These returned True for everything, so an engines.npm
        # requirement was silently unenforced however far the installed CLI was from it.
        ("npm", "10.2.4", ">=9.0.0", True),
        ("npm", "8.19.2", ">=9.0.0", False),
        # pnpm/yarn are NOT dispatched: nothing probes them, so evaluating a declared floor
        # would check them on some runs and not others. They pass through like any other
        # unevaluable key until OSS IQ has an adapter and a probe.
        ("pnpm", "1.0.0", ">=8", True),
        ("yarn", "1.22.19", ">=4.0.0", True),
        # unknown engine → passthrough True
        ("bun", "1.0.0", ">=1.0.0", True),
    ],
)
def test_engine_version_satisfies_requirement(
    engine_key: str, context_version: str, requirement: str, expected: bool
) -> None:
    assert engine_version_satisfies_requirement(engine_key, context_version, requirement) == expected


def test_engine_version_satisfies_requirement_raw_node_range_fails_open() -> None:
    """Regression: a raw, unreduced range as context_version still fails open here.

    This function is not buggy for its documented contract (a *concrete* context_version) — the
    real fix is at the one caller that used to feed it a raw range:
    adapters.package_managers.api_npm.project_info(), which now reduces engines.node via
    extract_min_node_version() before it ever reaches Project.engine_constraints. See
    tests/adapters/package_managers/test_api_npm.py for that regression instead.
    """
    assert engine_version_satisfies_requirement("node", ">=18.0.0", ">=18.19.0") is True


# ── has_engine_mismatch ────────────────────────────────────────────────────


def _cv(runtime_requirements: dict[str, str] | None) -> CandidateVersion:
    return CandidateVersion(
        version="1.0.0",
        age_days=100,
        is_deprecated=False,
        is_prerelease=False,
        is_yanked=False,
        runtime_requirements=runtime_requirements,
        has_cve=False,
        requires=None,
    )


def test_has_engine_mismatch_no_requirements() -> None:
    assert has_engine_mismatch(_cv(None), {"python": "3.11.9"}) is False


def test_has_engine_mismatch_empty_context() -> None:
    assert has_engine_mismatch(_cv({"python": ">=3.9"}), {}) is False


def test_has_engine_mismatch_satisfied() -> None:
    assert has_engine_mismatch(_cv({"python": ">=3.9"}), {"python": "3.11.9"}) is False


def test_has_engine_mismatch_violated() -> None:
    assert has_engine_mismatch(_cv({"python": ">=3.9"}), {"python": "3.8.0"}) is True


def test_has_engine_mismatch_engine_not_declared() -> None:
    # context has "node" but cv only declares "python" — no mismatch
    assert has_engine_mismatch(_cv({"python": ">=3.9"}), {"node": "18.0.0"}) is False


def test_engine_mismatch_reason_names_the_package_manager_that_mismatches() -> None:
    """The test the engine work could not previously write: with npm unenforceable, a package
    declaring both node and npm could only ever be judged on node."""
    reason = engine_mismatch_reason({"node": ">=18.0.0", "npm": ">=9.0.0"}, {"node": "20.11.0", "npm": "8.19.2"})

    assert reason == "requires npm >=9.0.0, checked against 8.19.2"


def test_engine_mismatch_reason_clear_when_both_engines_satisfied() -> None:
    assert engine_mismatch_reason({"node": ">=18.0.0", "npm": ">=9.0.0"}, {"node": "20.11.0", "npm": "10.2.4"}) is None


def test_engine_mismatch_reason_ignores_a_package_manager_absent_from_the_context() -> None:
    """A probe that did not run is not a conflict — absence of evidence, per the tri-state rule."""
    assert engine_mismatch_reason({"npm": ">=9.0.0"}, {"node": "20.11.0"}) is None


# ── stricter_engine_floor ──────────────────────────────────────────────────


def test_stricter_engine_floor_prefers_the_declared_python_floor() -> None:
    """The reported bug in miniature: 3.13 on this machine, 3.11 promised to everyone else."""
    assert stricter_engine_floor("python", "3.13.2", "3.11") == "3.11"


def test_stricter_engine_floor_prefers_an_older_python_runtime() -> None:
    assert stricter_engine_floor("python", "3.9.6", "3.11") == "3.9.6"


def test_stricter_engine_floor_prefers_the_declared_node_floor() -> None:
    assert stricter_engine_floor("node", "20.11.0", "18.0.0") == "18.0.0"


def test_stricter_engine_floor_prefers_an_older_node_runtime() -> None:
    assert stricter_engine_floor("node", "16.20.0", "18.0.0") == "16.20.0"


def test_stricter_engine_floor_keeps_equal_versions() -> None:
    assert stricter_engine_floor("node", "18.0.0", "18.0.0") == "18.0.0"


def test_stricter_engine_floor_falls_back_to_the_declared_floor() -> None:
    """A probe result nothing can parse resolves to the bound that does not depend on this machine."""
    assert stricter_engine_floor("node", "garbage", "18.0.0") == "18.0.0"
    assert stricter_engine_floor("python", "garbage", "3.11") == "3.11"


# ── cve_affects_version ────────────────────────────────────────────────────


def advisory(
    registry: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM,
    affected_versions: tuple[str, ...] = (),
    affected_ranges: tuple[AffectedRange, ...] = (),
) -> CVE:
    return CVE(
        id="GHSA-test",
        cve_ids=(),
        source=CveDatabase.OSV,
        package_name="pkg",
        package_registry=registry,
        summary="",
        severity=Severity.HIGH,
        affected_versions=affected_versions,
        published=None,
        link="https://osv.dev/GHSA-test",
        affected_ranges=affected_ranges,
    )


# uuid's GHSA-w5hq-g745-h8pq exactly as OSV publishes it: three ranges, no enumerated versions.
UUID_ADVISORY = advisory(
    affected_ranges=(
        AffectedRange(fixed="11.1.1"),
        AffectedRange(introduced="12.0.0", fixed="12.0.1"),
        AffectedRange(introduced="13.0.0", fixed="13.0.1"),
    )
)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("8.3.2", True),
        ("11.0.5", True),
        ("11.1.1-beta.1", True),
        ("11.1.1", False),
        ("12.0.0", True),
        ("12.0.1", False),
        ("13.0.0", True),
        ("13.0.2", False),
        ("14.0.2", False),
    ],
)
def test_cve_affects_version_reads_npm_ranges(version: str, expected: bool) -> None:
    assert cve_affects_version(UUID_ADVISORY, version) is expected


def test_cve_affects_version_last_affected_is_inclusive() -> None:
    cve = advisory(affected_ranges=(AffectedRange(introduced="4.0.0", last_affected="4.5.0"),))

    assert cve_affects_version(cve, "4.5.0") is True
    assert cve_affects_version(cve, "4.5.1") is False
    assert cve_affects_version(cve, "3.9.9") is False


def test_cve_affects_version_prerelease_introduced_bound() -> None:
    # semver's GHSA-c2qf-rxjj-qqgw opens its oldest range at "2.0.0-alpha".
    cve = advisory(affected_ranges=(AffectedRange(introduced="2.0.0-alpha", fixed="5.7.2"),))

    assert cve_affects_version(cve, "2.0.0") is True
    assert cve_affects_version(cve, "1.9.9") is False


def test_cve_affects_version_open_interval_has_no_fix() -> None:
    cve = advisory(affected_ranges=(AffectedRange(introduced="3.0.0"),))

    assert cve_affects_version(cve, "99.0.0") is True
    assert cve_affects_version(cve, "2.9.9") is False


def test_cve_affects_version_pypi_range() -> None:
    cve = advisory(ProjectPackagesRegistry.PYPI, affected_ranges=(AffectedRange(introduced="2.3.0", fixed="2.31.0"),))

    assert cve_affects_version(cve, "2.28.1") is True
    assert cve_affects_version(cve, "2.31.0rc1") is True
    assert cve_affects_version(cve, "2.31.0") is False


def test_cve_affects_version_enumerated_only_behaves_as_before() -> None:
    cve = advisory(ProjectPackagesRegistry.PYPI, affected_versions=("1.0.0", "1.1.0"))

    assert cve_affects_version(cve, "1.1.0") is True
    assert cve_affects_version(cve, "1.2.0") is False


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0", "2.0.0rc1"])
def test_cve_affects_version_every_enumerated_version_is_affected(version: str) -> None:
    """Ranges only ever add exposure: a version OSV enumerates stays affected whatever they say."""
    cve = advisory(
        ProjectPackagesRegistry.PYPI,
        affected_versions=("1.0.0", "1.1.0", "2.0.0rc1"),
        affected_ranges=(AffectedRange(introduced="5.0.0", fixed="5.1.0"),),
    )

    assert cve_affects_version(cve, version) is True


def test_cve_affects_version_fails_closed_on_an_unparseable_version() -> None:
    assert cve_affects_version(UUID_ADVISORY, "not-a-version") is True


def test_cve_affects_version_fails_closed_on_an_unparseable_bound() -> None:
    cve = advisory(affected_ranges=(AffectedRange(introduced="garbage", fixed="1.0.0"),))

    assert cve_affects_version(cve, "5.0.0") is True


def test_cve_affects_version_without_any_evidence_is_clean() -> None:
    assert cve_affects_version(advisory(), "1.0.0") is False
