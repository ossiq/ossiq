from ossiq.domain.common import CveDatabase, ProjectPackagesRegistry
from ossiq.domain.cve import CVE, Severity
from ossiq.risk.epss import grouped_epss, package_epss


def _cve(epss: float | None) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="pkg",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="test",
        severity=Severity.HIGH,
        affected_versions=("<1.0.0",),
        published="2024-01-01T00:00:00Z",
        link="https://example.com/advisory",
        epss=epss,
    )


def test_package_epss_takes_highest_score() -> None:
    assert package_epss([_cve(0.1), _cve(0.4), _cve(0.2)]) == 0.4


def test_package_epss_none_when_no_cve_scored() -> None:
    assert package_epss([_cve(None), _cve(None)]) is None


def test_grouped_epss_two_package_product() -> None:
    assert grouped_epss([0.10, 0.30]) == 1 - (1 - 0.10) * (1 - 0.30)


def test_grouped_epss_empty_group_is_none() -> None:
    assert grouped_epss([]) is None


def test_grouped_epss_all_unscored_group_is_none() -> None:
    scores = [s for s in [package_epss([_cve(None)]), package_epss([_cve(None)])] if s is not None]
    assert grouped_epss(scores) is None


def test_grouped_epss_single_max_score_member() -> None:
    assert grouped_epss([1.0]) == 1.0


def test_grouped_epss_clamps_out_of_range_scores() -> None:
    assert grouped_epss([-0.5, 1.5]) == 1 - (1 - 0.0) * (1 - 1.0)
