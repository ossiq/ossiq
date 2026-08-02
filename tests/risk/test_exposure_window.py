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


def make_diff(diff_index: int) -> VersionsDifference:
    return VersionsDifference("1.0.0", "2.0.0", diff_index, "ignored")


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
    assert compute_exposure_window(ecosystem, 0, make_diff(diff_index)) == expected


@pytest.mark.parametrize("diff_index", [VERSION_DIFF_PRERELEASE, VERSION_DIFF_BUILD])
def test_prerelease_and_build_are_patch_sized(diff_index: int) -> None:
    assert compute_exposure_window(ProjectPackagesRegistry.PYPI, 0, make_diff(diff_index)) == 64.5


def test_release_count_growth() -> None:
    result = compute_exposure_window(ProjectPackagesRegistry.PYPI, 3, make_diff(VERSION_DIFF_MAJOR))

    assert result == pytest.approx(131.58883083359672)


@pytest.mark.parametrize("releases_lag", [None, -1])
def test_invalid_release_lag_returns_none(releases_lag: int | None) -> None:
    assert compute_exposure_window(ProjectPackagesRegistry.PYPI, releases_lag, make_diff(VERSION_DIFF_MAJOR)) is None


@pytest.mark.parametrize("diff_index", [VERSION_NO_DIFF, 999])
def test_unknown_version_difference_returns_none(diff_index: int) -> None:
    assert compute_exposure_window(ProjectPackagesRegistry.PYPI, 0, make_diff(diff_index)) is None


def test_unsupported_ecosystem_returns_none() -> None:
    unsupported = cast(ProjectPackagesRegistry, "RUBYGEMS")

    assert compute_exposure_window(unsupported, 0, make_diff(VERSION_DIFF_MAJOR)) is None


def test_input_diff_remains_unchanged() -> None:
    diff = make_diff(VERSION_DIFF_MAJOR)
    original = deepcopy(diff)

    compute_exposure_window(ProjectPackagesRegistry.PYPI, 3, diff)

    assert diff == original


def test_scan_record_defaults_exposure_window_to_none() -> None:
    record = ScanRecord(
        package_name="example",
        dependency_name="example",
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="2.0.0",
        versions_diff_index=make_diff(VERSION_LATEST),
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="pyproject.toml"),
    )

    assert record.exposure_window_days is None
