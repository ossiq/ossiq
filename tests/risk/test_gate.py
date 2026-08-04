"""Tests for ossiq.risk.gate."""

import time

import pytest

from ossiq.domain.common import ConstraintType, CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_LATEST, VersionsDifference
from ossiq.risk.gate import get_gate_decision
from ossiq.service.project.models import ScanRecord


def make_cve(severity: Severity = Severity.CRITICAL, *, fix_available: bool = True) -> CVE:
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
        fix_available=fix_available,
    )


def make_record(
    *,
    is_installed_package_unpublished: bool = False,
    is_installed_deprecated: bool = False,
    version_age_days: int | None = None,
    cve: list[CVE] | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name="example",
        dependency_name="example",
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "ignored"),
        time_lag_days=0,
        releases_lag=0,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
        is_installed_package_unpublished=is_installed_package_unpublished,
        is_installed_deprecated=is_installed_deprecated,
        version_age_days=version_age_days,
    )


def test_pass_when_nothing_is_wrong() -> None:
    assert get_gate_decision(make_record()) == ("pass", "ok")


def test_blocks_unpublished_package() -> None:
    status, reason = get_gate_decision(make_record(is_installed_package_unpublished=True))

    assert status == "block"
    assert "does not exist" in reason


def test_blocks_deprecated_package() -> None:
    status, _ = get_gate_decision(make_record(is_installed_deprecated=True))

    assert status == "block"


def test_unpublished_takes_precedence_over_deprecated() -> None:
    record = make_record(is_installed_package_unpublished=True, is_installed_deprecated=True)

    status, reason = get_gate_decision(record)

    assert status == "block"
    assert "does not exist" in reason


def test_deprecated_takes_precedence_over_critical_cve() -> None:
    record = make_record(is_installed_deprecated=True, cve=[make_cve()])

    status, reason = get_gate_decision(record)

    assert status == "block"
    assert "deprecated" in reason


def test_blocks_critical_cve_with_fix_available() -> None:
    record = make_record(cve=[make_cve(Severity.CRITICAL, fix_available=True)])

    status, reason = get_gate_decision(record)

    assert status == "block"
    assert "critical CVE" in reason


def test_critical_cve_takes_precedence_over_cooldown() -> None:
    record = make_record(version_age_days=1, cve=[make_cve(Severity.CRITICAL, fix_available=True)])

    status, _ = get_gate_decision(record)

    assert status == "block"


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.MEDIUM, Severity.LOW])
def test_non_critical_cve_does_not_block(severity: Severity) -> None:
    status, _ = get_gate_decision(make_record(cve=[make_cve(severity, fix_available=True)]))

    assert status != "block"


def test_critical_cve_without_fix_does_not_block() -> None:
    status, _ = get_gate_decision(make_record(cve=[make_cve(Severity.CRITICAL, fix_available=False)]))

    assert status != "block"


def test_quarantines_fresh_version_with_no_cve() -> None:
    assert get_gate_decision(make_record(version_age_days=3)) == ("quarantine", "3d old (cooldown < 7d)")


def test_cooldown_bypassed_when_fresh_version_already_has_a_cve() -> None:
    record = make_record(version_age_days=3, cve=[make_cve(Severity.LOW, fix_available=False)])

    status, reason = get_gate_decision(record)

    assert status == "pass"
    assert "cooldown bypassed" in reason


def test_boundary_age_equal_to_cooldown_passes() -> None:
    assert get_gate_decision(make_record(version_age_days=7)) == ("pass", "ok")


def test_boundary_age_one_day_under_cooldown_quarantines() -> None:
    status, _ = get_gate_decision(make_record(version_age_days=6))

    assert status == "quarantine"


def test_unknown_age_does_not_quarantine() -> None:
    assert get_gate_decision(make_record(version_age_days=None)) == ("pass", "ok")


def test_disabled_cooldown_never_quarantines() -> None:
    assert get_gate_decision(make_record(version_age_days=0), cooldown_days=0) == ("pass", "ok")


def test_custom_cooldown_period() -> None:
    status, _ = get_gate_decision(make_record(version_age_days=10), cooldown_days=14)

    assert status == "quarantine"


def test_scan_record_defaults_gate_decision_to_none() -> None:
    assert make_record().gate_decision is None


def test_get_gate_decision_is_fast() -> None:
    record = make_record(cve=[make_cve(Severity.HIGH, fix_available=True)])

    start = time.perf_counter()
    for _ in range(1000):
        get_gate_decision(record)
    elapsed = time.perf_counter() - start

    assert elapsed < 0.5
