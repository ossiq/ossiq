"""B3 — PyPI and npm must behave the same way under equivalent exact pins.

Runs the real constraint parser, the real SAT solver, the real B2 ladder fallback, and the real
agent/MCP-format builder end to end for both ecosystems on structurally equivalent scenarios
(exact pin, same-major drift beyond it, no CVEs). Unlike test_build_pipeline.py's per-function
tests, this exercises the full chain the way a live scan actually would, so a regression in any
one layer's ecosystem handling — the parser, the solver, the ladder, or the formatter — shows up
here as an asymmetry between the two parametrized cases rather than needing its own bespoke test.

Root cause this guards against (see the OSS IQ defect report, B3): a bare npm version like
"4.17.1" was silently caret-expanded to "^4.17.1" by the constraint parser, so npm's solver
looked like it could move past a pin that PyPI's "==4.17.1" correctly refused to cross. Fixed in
solver/version_matchers.py; this test is the parity check the report asked for.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ossiq.adapters.api_interfaces import AbstractPackageRegistryApi, VersionRules
from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion
from ossiq.service.agent import build_update_decide
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.project.recommendations import apply_version_ladder_fallback
from ossiq.service.project.records import compute_latest_in_major, compute_latest_in_range
from ossiq.settings import Settings
from ossiq.solver.dependencies_solver import solve_direct


def _pv(version: str) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url="x",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00Z",
    )


class _FakeDep:
    """Matches the shape solve_direct expects from a project's parsed Dependency."""

    def __init__(self, canonical_name: str, version: str, constraint: str) -> None:
        self.canonical_name = canonical_name
        self.version = version
        self.version_constraint = constraint
        self.constraint_info = ConstraintSource(type=ConstraintType.PINNED, source_file="manifest")
        self.all_constraints: list[str] = []


def _fake_registry(real_rules: VersionRules, versions_by_name: dict[str, list[PackageVersion]]) -> MagicMock:
    """A registry double: real I/O faked, but version comparison delegates to the real adapter -
    so this test exercises the actual constraint-parsing and comparison logic, not a re-implementation
    of it.
    """
    registry = MagicMock(spec=AbstractPackageRegistryApi)
    registry.package_registry = real_rules.package_registry
    registry.package_versions.side_effect = lambda name: versions_by_name.get(name, [])
    registry.package_version_requires.side_effect = lambda name, version: {}
    registry.compare_versions.side_effect = real_rules.compare_versions
    return registry


@pytest.mark.parametrize(
    "real_rules_cls, package_name, installed, all_versions, constraint",
    [
        pytest.param(
            PackageRegistryApiPypi,
            "requests",
            "2.28.1",
            ["2.28.1", "2.29.0", "2.30.0", "2.31.0", "2.34.2"],
            "==2.28.1",
            id="pypi-exact-pin",
        ),
        pytest.param(
            PackageRegistryApiNpm,
            "express",
            "4.17.1",
            ["4.17.1", "4.18.0", "4.19.0", "4.20.0", "4.22.2"],
            "4.17.1",  # npm's bare-version exact pin, as written by `npm install --save-exact`
            id="npm-bare-exact-pin",
        ),
    ],
)
def test_equivalent_exact_pins_produce_structurally_equivalent_responses(
    real_rules_cls: type[VersionRules],
    package_name: str,
    installed: str,
    all_versions: list[str],
    constraint: str,
) -> None:
    real_rules = real_rules_cls(Settings())
    versions = [_pv(v) for v in all_versions]
    registry = _fake_registry(real_rules, {package_name: versions})
    latest_version = all_versions[-1]

    # 1. Real solver + real constraint parser: an exact pin must yield no in-range move, in
    #    either ecosystem. This is the assertion that catches B3's actual root cause - if either
    #    ecosystem's parser under- or over-constrains a bare/exact pin, this line fails first.
    dep = _FakeDep(package_name, installed, constraint)
    solver_output = solve_direct([dep], registry, {})
    assert solver_output.recommendations[package_name] == installed

    # 2. Real B2 ladder data, computed from the same release list every scan would use.
    latest_in_range = compute_latest_in_range(versions, installed, constraint, real_rules)
    latest_in_major = compute_latest_in_major(versions, installed, real_rules)
    assert latest_in_range == installed  # nothing else satisfies the declared exact pin
    assert latest_in_major == latest_version  # the newest release stays within the same major

    record = ScanRecord(
        package_name=package_name,
        dependency_name=None,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=latest_version,
        versions_diff_index=real_rules.difference_versions(installed, latest_version),
        time_lag_days=None,
        releases_lag=None,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.PINNED, source_file="manifest"),
        version_constraint=constraint,
        recommended_version=solver_output.recommendations[package_name],
        latest_in_range=latest_in_range,
        latest_in_major=latest_in_major,
    )
    apply_version_ladder_fallback([record])

    # 3. Real agent/MCP-format output.
    scan = ScanResult(
        project_name="p",
        packages_registry=real_rules.package_registry.value,
        project_path=".",
        production_packages=[record],
        optional_packages=[],
    )
    entry = build_update_decide(scan)["updates"][0]

    # Structural parity: the same relationships must hold regardless of ecosystem or the literal
    # version strings involved.
    assert entry["to"] == latest_version
    assert entry["to"] != entry["from"]
    assert entry["target_exceeds_declared_range"] is True
    assert entry["latest_in_range"] == installed
    assert entry["latest_in_major"] == latest_version
    assert entry["next_action"] == "Constrained. Check newer version"
