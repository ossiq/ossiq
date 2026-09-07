"""Tests for ossiq.service.project.epss."""

from collections.abc import Iterable

import pytest

from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.service.project.epss import populate_epss
from ossiq.service.project.models import ScanRecord


def make_dependency(name: str, *children: Dependency, optional: Iterable[Dependency] = ()) -> Dependency:
    return Dependency(
        name=name,
        version_installed="1.0.0",
        canonical_name=name,
        dependencies={child.name: child for child in children},
        optional_dependencies={child.name: child for child in optional},
    )


def make_walker(*prod_roots: Dependency, optional: Iterable[Dependency] = ()) -> GraphExporter:
    return GraphExporter(make_dependency("root", *prod_roots, optional=optional))


def make_cve(*, epss: float | None) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="example",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="example vulnerability",
        severity=Severity.CRITICAL,
        affected_versions=("1.0.0",),
        published=None,
        link="https://example.test/advisory",
        epss=epss,
    )


def make_record(
    *,
    package_name: str,
    version_age_days: int | None = 365,
    cve: list[CVE] | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name=package_name,
        dependency_name=package_name,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "ignored"),
        time_lag_days=0,
        releases_lag=0,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        version_age_days=version_age_days,
    )


def test_worked_example_from_the_plan():
    b2 = make_dependency("B2")
    b1 = make_dependency("B1", b2)
    b = make_dependency("B", b1)
    a1 = make_dependency("A1")
    a2 = make_dependency("A2")
    a = make_dependency("A", a1, a2)
    c = make_dependency("C")
    walker = make_walker(a, b, c)

    records = [make_record(package_name=name) for name in ("A", "A1", "A2", "B", "B1", "B2", "C")]
    by_name = {record.package_name: record for record in records}
    by_name["A1"].cve = [make_cve(epss=0.1)]
    by_name["B2"].cve = [make_cve(epss=0.3)]

    result = populate_epss(records, walker)

    assert result.by_direct == pytest.approx({"A": 0.10, "B": 0.30})
    assert "C" not in result.by_direct
    assert result.score == pytest.approx(1 - (1 - 0.10) * (1 - 0.30))
    assert result.scored_packages == 2


def test_package_shared_between_two_roots_counted_once_in_project_score():
    shared = make_dependency("shared")
    a = make_dependency("A", shared)
    b = make_dependency("B", shared)
    walker = make_walker(a, b)

    records = [
        make_record(package_name="A"),
        make_record(package_name="B"),
        make_record(package_name="shared", cve=[make_cve(epss=0.4)]),
    ]

    result = populate_epss(records, walker)

    assert result.score == pytest.approx(0.4)
    assert result.scored_packages == 1
    assert result.by_direct == pytest.approx({"A": 0.4, "B": 0.4})


def test_cycle_terminates_and_does_not_double_count():
    a = make_dependency("a")
    b = make_dependency("b", a)
    a.dependencies["b"] = b

    records = [make_record(package_name="a"), make_record(package_name="b", cve=[make_cve(epss=0.2)])]

    result = populate_epss(records, make_walker(a))

    assert result.by_direct == pytest.approx({"a": 0.2})
    assert result.scored_packages == 1


def test_all_unscored_project_score_is_none_not_zero():
    walker = make_walker(make_dependency("a"), make_dependency("b"))
    records = [make_record(package_name="a"), make_record(package_name="b")]

    result = populate_epss(records, walker)

    assert result.score is None
    assert result.scored_packages == 0
    assert result.by_direct == {}


def test_post_cutoff_record_excluded_from_both_groups():
    walker = make_walker(make_dependency("a"))
    record = make_record(package_name="a", version_age_days=-30, cve=[make_cve(epss=0.9)])

    result = populate_epss([record], walker)

    assert record.epss is None
    assert result.score is None
    assert result.scored_packages == 0
    assert result.by_direct == {}
    assert result.unscored_cve_packages == 0


def test_package_with_cve_but_no_epss_counts_as_unscored_cve_package():
    walker = make_walker(make_dependency("x"))
    record = make_record(package_name="x", cve=[make_cve(epss=None)])

    result = populate_epss([record], walker)

    assert result.unscored_cve_packages == 1
    assert result.scored_packages == 0
    assert result.score is None
