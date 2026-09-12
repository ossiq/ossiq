"""Unit tests for service.project.ladder.compute_version_ladder.

Uses real PackageRegistryApiPypi/PackageRegistryApiNpm instances as `version_rules` — their
constructors do no I/O, and compare_versions/newest_version/package_registry are pure, so this
exercises the actual PEP 440 / semver semantics rather than a hand-rolled comparator.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.version import PackageVersion
from ossiq.service.project.ladder import compute_version_ladder
from ossiq.settings import Settings

PYPI = PackageRegistryApiPypi(Settings())
NPM = PackageRegistryApiNpm(Settings())


def _pv(
    version: str, *, published: str | None = "2024-01-01T00:00:00Z", yanked: bool = False, unpublished: bool = False
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        is_yanked=yanked,
        is_unpublished=unpublished,
    )


class TestPyPILadder:
    def test_pydantic_latest_in_major_is_1_10_26(self):
        """The named regression: held back on a major, still has somewhere to go inside it."""
        releases = [_pv(f"1.10.{i}") for i in range(13, 27)]  # 1.10.13 .. 1.10.26
        releases += [_pv(f"2.{i}.0") for i in range(0, 40)]  # >30 2.x releases: beats CANDIDATE_CAP
        releases += [_pv("2.13.5")]

        ladder = compute_version_ladder(releases, "1.10.13", "==1.10.13", PYPI, latest_version="2.13.5")

        assert ladder.latest_in_major == "1.10.26"
        assert ladder.latest_in_range == "1.10.13"  # equals installed — explicit equality, not None
        assert ladder.latest_overall == "2.13.5"

    def test_rungs_equal_installed_when_nothing_newer(self):
        ladder = compute_version_ladder([_pv("1.0.0")], "1.0.0", None, PYPI, latest_version="1.0.0")

        assert ladder.latest_in_range == "1.0.0"
        assert ladder.latest_in_major == "1.0.0"
        assert ladder.latest_overall == "1.0.0"

    def test_yanked_and_unpublished_excluded(self):
        releases = [
            _pv("1.0.0"),
            _pv("1.1.0", yanked=True),
            _pv("1.2.0", unpublished=True),
            _pv("1.3.0"),
        ]
        ladder = compute_version_ladder(releases, "1.0.0", None, PYPI)

        assert ladder.latest_in_range == "1.3.0"
        assert ladder.latest_in_major == "1.3.0"

    def test_versions_after_cutoff_excluded(self):
        releases = [
            _pv("1.0.0", published="2024-01-01T00:00:00Z"),
            _pv("1.1.0", published="2024-06-01T00:00:00Z"),
            _pv("1.2.0", published="2024-12-01T00:00:00Z"),
        ]
        now = datetime(2024, 7, 1, tzinfo=UTC)
        ladder = compute_version_ladder(releases, "1.0.0", None, PYPI, now=now)

        assert ladder.latest_in_range == "1.1.0"

    def test_epoch_is_a_major_boundary(self):
        """PEP 440 epoch is part of the major-line identity, not just release[0]."""
        releases = [_pv("1.0"), _pv("1.5"), _pv("1!1.0")]
        ladder = compute_version_ladder(releases, "1.0", None, PYPI)

        assert ladder.latest_in_major == "1.5"

    def test_unparseable_version_excluded_from_major_bucket(self):
        releases = [_pv("1.0.0"), _pv("not-a-version")]
        ladder = compute_version_ladder(releases, "1.0.0", None, PYPI)

        assert ladder.latest_in_major == "1.0.0"

    def test_no_constraint_collapses_in_range_to_overall(self):
        releases = [_pv("1.0.0"), _pv("2.0.0")]
        ladder = compute_version_ladder(releases, "1.0.0", None, PYPI, latest_version="2.0.0")

        assert ladder.latest_in_range == ladder.latest_overall == "2.0.0"

    def test_empty_release_list_yields_all_none_except_known_latest(self):
        ladder = compute_version_ladder([], "1.0.0", None, PYPI)

        assert ladder.latest_in_range is None
        assert ladder.latest_in_major is None
        assert ladder.latest_overall is None

    def test_constraint_only_satisfiable_below_installed_yields_none_in_range(self):
        """Manifest/lockfile divergence: nothing in `releases_since_installed` (floored at
        installed) can satisfy a constraint that only admits versions below it."""
        releases = [_pv("2.0.0"), _pv("2.1.0")]
        ladder = compute_version_ladder(releases, "2.0.0", "<1.0.0", PYPI)

        assert ladder.latest_in_range is None


class TestNpmLadder:
    def test_npm_caret_range(self):
        releases = [_pv("7.0.0"), _pv("7.0.3"), _pv("7.5.0"), _pv("11.0.0")]
        ladder = compute_version_ladder(releases, "7.0.0", "^7.0.0", NPM, latest_version="11.0.0")

        assert ladder.latest_in_range == "7.5.0"
        assert ladder.latest_in_major == "7.5.0"
        assert ladder.latest_overall == "11.0.0"

    def test_npm_alias_spec(self):
        releases = [_pv("7.0.0"), _pv("7.0.3"), _pv("11.0.0")]
        ladder = compute_version_ladder(releases, "7.0.0", "npm:uuid@^7.0.0", NPM, latest_version="11.0.0")

        assert ladder.latest_in_range == "7.0.3"
        assert ladder.latest_in_major == "7.0.3"
