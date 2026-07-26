from copy import deepcopy
from typing import cast

import pytest

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import (
    VERSION_DIFF_BUILD,
    VERSION_DIFF_MAJOR,
    VERSION_DIFF_MINOR,
    VERSION_DIFF_PATCH,
    VERSION_DIFF_PRERELEASE,
    VERSION_LATEST,
    VERSION_NO_DIFF,
    VersionsDifference,
)
from ossiq.risk.exposure_window import compute_exposure_window
from ossiq.service.project.models import ScanRecord


def make_record(
    diff_index: int,
    releases_lag: int | None,
    *,
    time_lag_days: int | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name="example",
        dependency_name="example",
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="2.0.0",
        versions_diff_index=VersionsDifference("1.0.0", "2.0.0", diff_index, "ignored"),
        time_lag_days=time_lag_days,
        releases_lag=releases_lag,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
    )


@pytest.mark.parametrize(
    ("ecosystem", "diff_index", "expected"),
    [
        pytest.param(ProjectPackagesRegistry.PYPI, VERSION_LATEST, 60.0, id="pypi-latest"),
        pytest.param(ProjectPackagesRegistry.PYPI, VERSION_DIFF_PATCH, 64.5, id="pypi-patch"),
        pytest.param(ProjectPackagesRegistry.PYPI, VERSION_DIFF_MINOR, 73.5, id="pypi-minor"),
        pytest.param(ProjectPackagesRegistry.PYPI, VERSION_DIFF_MAJOR, 90.0, id="pypi-major"),
        pytest.param(ProjectPackagesRegistry.NPM, VERSION_LATEST, 37.0, id="npm-latest"),
        pytest.param(ProjectPackagesRegistry.NPM, VERSION_DIFF_PATCH, 41.5, id="npm-patch"),
        pytest.param(ProjectPackagesRegistry.NPM, VERSION_DIFF_MINOR, 50.5, id="npm-minor"),
        pytest.param(ProjectPackagesRegistry.NPM, VERSION_DIFF_MAJOR, 67.0, id="npm-major"),
    ],
)
def test_zero_release_lag_matrix(
    ecosystem: ProjectPackagesRegistry,
    diff_index: int,
    expected: float,
) -> None:
    assert compute_exposure_window(make_record(diff_index, 0), ecosystem) == expected


@pytest.mark.parametrize("diff_index", [VERSION_DIFF_PRERELEASE, VERSION_DIFF_BUILD])
def test_prerelease_and_build_are_patch_sized(diff_index: int) -> None:
    assert (
        compute_exposure_window(
            make_record(diff_index, 0),
            ProjectPackagesRegistry.PYPI,
        )
        == 64.5
    )


def test_release_count_growth() -> None:
    result = compute_exposure_window(
        make_record(VERSION_DIFF_MAJOR, 3),
        ProjectPackagesRegistry.PYPI,
    )

    assert result == pytest.approx(131.58883083359672)


@pytest.mark.parametrize("releases_lag", [None, -1])
def test_invalid_release_lag_returns_none(releases_lag: int | None) -> None:
    assert (
        compute_exposure_window(
            make_record(VERSION_DIFF_MAJOR, releases_lag),
            ProjectPackagesRegistry.PYPI,
        )
        is None
    )


@pytest.mark.parametrize("diff_index", [VERSION_NO_DIFF, 999])
def test_unknown_version_difference_returns_none(diff_index: int) -> None:
    assert (
        compute_exposure_window(
            make_record(diff_index, 0),
            ProjectPackagesRegistry.PYPI,
        )
        is None
    )


def test_unsupported_ecosystem_returns_none() -> None:
    unsupported = cast(ProjectPackagesRegistry, "RUBYGEMS")

    assert compute_exposure_window(make_record(VERSION_DIFF_MAJOR, 0), unsupported) is None


def test_time_lag_days_does_not_affect_result() -> None:
    without_time_lag = make_record(VERSION_DIFF_MAJOR, 3, time_lag_days=None)
    with_time_lag = make_record(VERSION_DIFF_MAJOR, 3, time_lag_days=10_000)

    assert compute_exposure_window(
        without_time_lag,
        ProjectPackagesRegistry.PYPI,
    ) == compute_exposure_window(
        with_time_lag,
        ProjectPackagesRegistry.PYPI,
    )


def test_input_record_remains_unchanged() -> None:
    record = make_record(VERSION_DIFF_MAJOR, 3)
    original = deepcopy(record)

    compute_exposure_window(record, ProjectPackagesRegistry.PYPI)

    assert record == original
