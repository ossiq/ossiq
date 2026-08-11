"""Tests for ossiq.service.project.health."""

import math
from collections.abc import Iterable

import pytest

from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource, Dependency
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.risk.exposure import FITNESS_DECAY_RATE
from ossiq.risk.p_supplychain import FRESH_HAZARD_WEIGHT
from ossiq.service.project.health import GraphMetrics, compute_dependency_tree_metrics, populate_health_fields
from ossiq.service.project.models import ScanRecord

COOLDOWN_DAYS = 7


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


def make_cve(
    *,
    epss: float | None = 0.5,
    reachable: bool | None = None,
    fix_age_days: int | None = None,
    fix_available: bool = False,
    severity: Severity = Severity.CRITICAL,
) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="example",
        package_registry=ProjectPackagesRegistry.PYPI,
        summary="example vulnerability",
        severity=severity,
        affected_versions=("1.0.0",),
        published=None,
        link="https://example.test/advisory",
        epss=epss,
        fix_available=fix_available,
        fix_age_days=fix_age_days,
        reachable=reachable,
    )


def make_record(
    *,
    package_name: str = "example",
    version_age_days: int | None = 365,
    cve: list[CVE] | None = None,
    exposure_window_days: float | None = 30.0,
    runs_code_at_install: bool | None = False,
    is_installed_deprecated: bool = False,
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
        exposure_window_days=exposure_window_days,
        runs_code_at_install=runs_code_at_install,
        is_installed_deprecated=is_installed_deprecated,
    )


# --- compute_dependency_tree_metrics -------------------------------------------------------------------


def test_shared_transitive_reached_by_every_production_root():
    shared = make_dependency("shared")
    metrics = compute_dependency_tree_metrics(make_walker(make_dependency("a", shared), make_dependency("b", shared)))

    assert metrics["shared"].tier == "runtime"
    assert metrics["shared"].normalized_fan_out == 1.0


def test_transitive_reached_by_one_of_two_production_roots():
    metrics = compute_dependency_tree_metrics(
        make_walker(make_dependency("a", make_dependency("solo")), make_dependency("b"))
    )

    assert metrics["solo"].tier == "runtime"
    assert metrics["solo"].normalized_fan_out == 0.5


def test_dev_fan_out_is_normalized_against_dev_roots_only():
    dev_roots = [make_dependency("dev-x", make_dependency("dev-only")), make_dependency("dev-y")]
    prod_roots = [make_dependency("a"), make_dependency("b"), make_dependency("c")]
    metrics = compute_dependency_tree_metrics(make_walker(*prod_roots, optional=dev_roots))

    assert metrics["dev-only"].tier == "dev"
    # 1 of 2 dev roots reaches it. Against the 3 production roots it would have been 1/3.
    assert metrics["dev-only"].normalized_fan_out == 0.5


def test_runtime_wins_when_reachable_from_both_tiers():
    shared = make_dependency("shared")
    metrics = compute_dependency_tree_metrics(
        make_walker(make_dependency("a", shared), optional=[make_dependency("dev-x", shared)])
    )

    assert metrics["shared"].tier == "runtime"
    assert metrics["shared"].normalized_fan_out == 1.0


def test_direct_dependency_without_children():
    metrics = compute_dependency_tree_metrics(make_walker(make_dependency("a")))

    assert metrics["a"] == GraphMetrics(tier="runtime", normalized_fan_out=1.0, transitive_count=0)


def test_direct_dependency_counts_unique_descendants():
    shared = make_dependency("shared", make_dependency("leaf"))
    metrics = compute_dependency_tree_metrics(
        make_walker(make_dependency("a", shared, make_dependency("other", shared)))
    )

    # shared, leaf, other - each counted once despite two paths into shared.
    assert metrics["a"].transitive_count == 3


def test_optional_roots_excluded_drops_the_dev_subtree():
    dev_root = make_dependency("dev-x", make_dependency("dev-only"))
    metrics = compute_dependency_tree_metrics(
        make_walker(make_dependency("a"), optional=[dev_root]), include_optional_roots=False
    )

    assert "dev-only" not in metrics
    assert metrics["dev-x"].tier == "dev"  # still an installed direct dependency


def test_cycle_terminates():
    a = make_dependency("a")
    b = make_dependency("b", a)
    a.dependencies["b"] = b

    metrics = compute_dependency_tree_metrics(make_walker(a))

    assert set(metrics) == {"a", "b"}


# --- populate_health_fields ------------------------------------------------------------------


def runtime_metrics(transitive_count: int = 0) -> dict[str, GraphMetrics]:
    return {"example": GraphMetrics(tier="runtime", normalized_fan_out=1.0, transitive_count=transitive_count)}


def test_clean_mature_record_scores_zero_risk():
    record = make_record(version_age_days=365, cve=[])

    populate_health_fields([record], runtime_metrics(), COOLDOWN_DAYS)

    assert record.p_vuln == 0.0
    assert record.p_supplychain == 0.0
    # runtime tier * full fan-out * no install execution * no transitive reach.
    assert record.impact == pytest.approx(1.0)
    assert record.expected_exposure == 0.0
    assert record.fitness == 100
    assert record.gate_decision == ("pass", "ok")


def test_freshly_published_record_carries_supplychain_hazard():
    record = make_record(version_age_days=0, cve=[])

    populate_health_fields([record], runtime_metrics(), COOLDOWN_DAYS)

    impact = record.impact
    expected_exposure = record.expected_exposure
    assert impact is not None
    assert expected_exposure is not None

    assert record.p_supplychain == pytest.approx(FRESH_HAZARD_WEIGHT)
    assert record.p_vuln == 0.0
    assert expected_exposure == pytest.approx(impact * FRESH_HAZARD_WEIGHT)
    assert record.fitness == round(100 * math.exp(-FITNESS_DECAY_RATE * expected_exposure))
    assert record.gate_decision == ("quarantine", f"0d old (cooldown < {COOLDOWN_DAYS}d)")


def test_record_with_cve_populates_the_full_chain():
    record = make_record(cve=[make_cve(epss=0.5, reachable=True, fix_age_days=60)], exposure_window_days=30.0)

    populate_health_fields([record], runtime_metrics(), COOLDOWN_DAYS)

    impact = record.impact
    p_vuln = record.p_vuln
    assert impact is not None
    assert p_vuln is not None

    assert p_vuln > 0.0
    assert record.expected_exposure == pytest.approx(impact * p_vuln)
    assert record.fitness is not None and 0 <= record.fitness < 100
    assert record.gate_decision == ("pass", "ok")


@pytest.mark.parametrize(
    ("cve", "exposure_window_days"),
    [
        ([make_cve(epss=None)], 30.0),
        ([make_cve(epss=0.5)], None),
    ],
    ids=["unknown-epss", "unknown-exposure-window"],
)
def test_unknown_vuln_inputs_propagate_none_but_never_skip_the_gate(
    cve: list[CVE], exposure_window_days: float | None
) -> None:
    record = make_record(cve=cve, exposure_window_days=exposure_window_days)

    populate_health_fields([record], runtime_metrics(), COOLDOWN_DAYS)

    assert record.p_vuln is None
    assert record.expected_exposure is None
    assert record.fitness is None
    # Impact and the Gate are independent of the probability channels.
    assert record.impact is not None
    assert record.gate_decision == ("pass", "ok")


def test_install_execution_raises_impact():
    quiet = make_record()
    noisy = make_record(runs_code_at_install=True)

    populate_health_fields([quiet, noisy], runtime_metrics(), COOLDOWN_DAYS)

    quiet_impact = quiet.impact
    noisy_impact = noisy.impact
    assert quiet_impact is not None
    assert noisy_impact is not None

    assert noisy_impact > quiet_impact


def test_every_tier_of_record_resolves_against_one_transitive_tree_metrics_pass():
    """Production, optional, and transitive records all find their metrics - no KeyError, no None left."""

    walker = make_walker(
        make_dependency("prod-a", make_dependency("trans-a")),
        make_dependency("prod-b"),
        optional=[make_dependency("dev-x", make_dependency("dev-only"))],
    )
    records = [make_record(package_name=name) for name in ("prod-a", "prod-b", "trans-a", "dev-x", "dev-only")]

    populate_health_fields(records, compute_dependency_tree_metrics(walker), COOLDOWN_DAYS)

    assert all(record.impact is not None for record in records)
    assert all(record.gate_decision is not None for record in records)
    assert all(record.fitness == 100 for record in records)
