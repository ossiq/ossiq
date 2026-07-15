"""Tests for version_matchers — npm semver and PyPI/PEP 440 constraint matching.

Pipeline under test:
    raw constraint string
        ├── npm  →  npm_version_satisfies_range()
        ├── pypi →  (via) version_satisfies_constraint() with PEP 440 specifier
        └── unified → version_satisfies_constraint()
"""

from __future__ import annotations

import pytest
from univers.versions import SemverVersion

from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.solver.problem import CandidateVersion
from ossiq.solver.version_matchers import (
    _fallback_evaluate_bounds,
    engine_version_satisfies_requirement,
    has_engine_mismatch,
    npm_version_satisfies_range,
    pypi_version_satisfies_specifier,
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
        # bare version treated as caret range
        ("14.1.0", "14", True),
        ("15.0.0", "14", False),
        ("14.0.0", "14", True),
        # comparison operators
        ("1.5.0", ">=1.0.0", True),
        ("0.9.0", ">=1.0.0", False),
        ("0.9.0", "<1.0.0", True),
        ("1.0.0", "<1.0.0", False),
        ("1.0.0", "<=1.0.0", True),
        ("1.0.1", "!=1.0.0", True),
        ("1.0.0", "!=1.0.0", False),
        # || union — bare versions
        ("14.1.0", "12 || 14", True),
        ("16.0.0", "12 || 14", False),
        ("12.5.0", "12 || 14", True),
        # || union — mixed caret + tilde (delegated to univers)
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
        # prerelease version rejected by default (allow_beta=False)
        ("1.3.0-rc.1", "^1.2.0", False),
        # prerelease suffixes stripped before matching — real match, not pass-through
        ("3.5.0", ">=2.9.0 || >=3.0.0-0 <3.0.0", True),
        ("3.5.0", ">=3.0.0-0", True),
        ("2.0.0", ">=3.0.0-0", False),
        ("6.5.0", ">=2.9.0 || >=3.0.0-0 <3.0.0 || >=6.0.1 <8.0.0", True),
        # hyphen range untouched by prerelease stripping (spaces around the dash)
        ("1.5.0", "1.2.3 - 2.0.0", True),
    ],
)
def test_npm_version_satisfies_range(version: str, range_constraint: str, expected: bool) -> None:
    assert npm_version_satisfies_range(version, range_constraint) == expected


def test_npm_version_satisfies_range_allow_beta() -> None:
    assert npm_version_satisfies_range("1.3.0-rc.1", ">=1.2.0", allow_beta=True) is True


# ── _fallback_evaluate_bounds ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        # single comparator clauses
        ("1.5.0", ">=1.0.0", True),
        ("0.9.0", ">=1.0.0", False),
        ("0.9.0", "<1.0.0", True),
        ("1.0.0", "=1.0.0", True),
        ("1.0.1", "!=1.0.0", True),
        ("1.0.0", "!=1.0.0", False),
        # bare version → implicit "="
        ("1.0.0", "1.0.0", True),
        ("1.0.1", "1.0.0", False),
        # AND within a branch (space-separated clauses)
        ("3.5.0", ">=3.0.0 <4.0.0", True),
        ("4.5.0", ">=3.0.0 <4.0.0", False),
        # OR branches
        ("5.5.0", ">=3.0.0 <4.0.0 || >=5.0.0 <6.0.0", True),
        ("4.5.0", ">=3.0.0 <4.0.0 || >=5.0.0 <6.0.0", False),
        # overlapping prerelease boundaries that crash strict parsers
        ("3.5.0", ">=2.9.0 || >=3.0.0-0 <3.0.0", True),
        ("2.0.0", ">=3.0.0-0 <3.0.0", False),
        # whitespace between operator and version is tolerated
        ("1.5.0", ">= 1.0.0", True),
        # unparseable clause value is skipped, not fatal
        ("1.5.0", ">=not-a-version >=1.0.0", True),
    ],
)
def test_fallback_evaluate_bounds(version: str, constraint: str, expected: bool) -> None:
    assert _fallback_evaluate_bounds(SemverVersion(version), constraint) == expected  # type: ignore


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
        # unknown engine → passthrough True
        ("bun", "1.0.0", ">=1.0.0", True),
    ],
)
def test_engine_version_satisfies_requirement(
    engine_key: str, context_version: str, requirement: str, expected: bool
) -> None:
    assert engine_version_satisfies_requirement(engine_key, context_version, requirement) == expected


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
