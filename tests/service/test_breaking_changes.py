"""Unit tests for service.project.breaking_changes.

Mirrors tests/service/test_version_ladder.py: real PackageRegistryApiPypi/PackageRegistryApiNpm
instances as version_rules (their constructors do no I/O), plain PackageVersion fixtures, no
mocking of the registries themselves.
"""

from __future__ import annotations

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import ModuleSystem, ProjectPackagesRegistry
from ossiq.domain.version import PackageVersion
from ossiq.service.project.breaking_changes import (
    breaking_majors,
    compute_latest_compatible_major,
    module_system_label,
)
from ossiq.settings import Settings

PYPI = PackageRegistryApiPypi(Settings())
NPM = PackageRegistryApiNpm(Settings())


def _pv(
    version: str,
    *,
    published: str | None = "2024-01-01T00:00:00Z",
    yanked: bool = False,
    unpublished: bool = False,
    module_system: ModuleSystem | None = None,
) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso=published,
        is_yanked=yanked,
        is_unpublished=unpublished,
        module_system=module_system,
    )


class TestBreakingMajorsPyPI:
    def test_pypi_never_flagged_pending_remote_registry(self):
        """No curated list anymore — PyPI breaking-change detection is a deliberate no-op until a
        remote API-break registry replaces it (see breaking_changes.py's module docstring)."""
        releases = [_pv("1.10.13"), _pv("2.0.0")]

        assert breaking_majors("pydantic", releases, ProjectPackagesRegistry.PYPI) == {}

    def test_unknown_package_not_flagged(self):
        assert breaking_majors("some-unlisted-package", [], ProjectPackagesRegistry.PYPI) == {}


class TestBreakingMajorsNpm:
    def test_major_flagged_when_every_release_is_esm_only(self):
        releases = [
            _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
            _pv("5.1.0", module_system=ModuleSystem.ESM_ONLY),
        ]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM)

        assert flagged == {(0, 5): "ESM-only from 5.0.0"}

    def test_major_not_flagged_when_later_patch_dual_publishes(self):
        releases = [
            _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
            _pv("5.1.0", module_system=ModuleSystem.DUAL),
        ]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM)

        assert flagged == {}

    def test_major_not_flagged_when_module_system_unknown_for_some_release(self):
        releases = [
            _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
            _pv("5.1.0", module_system=None),
        ]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM)

        assert flagged == {}

    def test_cjs_major_not_flagged(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS)]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM)

        assert flagged == {}


class TestComputeLatestCompatibleMajor:
    def test_pypi_reaches_across_majors_with_no_curated_data(self):
        """PyPI breaking-change detection is currently a no-op (TestBreakingMajorsPyPI) — nothing
        is flagged, so this reaches the newest release overall, not just the installed major."""
        releases = [_pv(f"1.10.{i}") for i in range(13, 27)]
        releases += [_pv(f"2.{i}.0") for i in range(0, 5)]

        result = compute_latest_compatible_major("pydantic", releases, "1.10.13", PYPI, ProjectPackagesRegistry.PYPI)

        assert result == "2.4.0"

    def test_diverges_from_latest_in_major_across_a_clean_intermediate_major(self):
        """Synthetic chalk-shaped case: installed major 2, major 3 clean, major 4 ESM-only break.

        latest_in_major (item 1) stays at the newest 2.x; latest_compatible_major reaches the
        newest 3.x — the coincide-vs-diverge case the design doc calls out.
        """
        releases = [
            _pv("2.0.0", module_system=ModuleSystem.CJS),
            _pv("2.1.0", module_system=ModuleSystem.CJS),
            _pv("3.0.0", module_system=ModuleSystem.CJS),
            _pv("3.1.0", module_system=ModuleSystem.CJS),
            _pv("4.0.0", module_system=ModuleSystem.ESM_ONLY),
        ]

        result = compute_latest_compatible_major("pkg", releases, "2.0.0", NPM, ProjectPackagesRegistry.NPM)

        assert result == "3.1.0"

    def test_none_when_every_major_flagged(self):
        releases = [_pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

        result = compute_latest_compatible_major("chalk", releases, "5.0.0", NPM, ProjectPackagesRegistry.NPM)

        assert result is None

    def test_none_for_empty_release_list(self):
        result = compute_latest_compatible_major("pkg", [], "1.0.0", NPM, ProjectPackagesRegistry.NPM)

        assert result is None


class TestModuleSystemLabel:
    def test_chalk_breaking_change_reported(self):
        releases = [
            _pv("4.1.2", module_system=ModuleSystem.CJS),
            _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
        ]

        module_system, breaking_change = module_system_label(
            "chalk", "4.1.2", "5.0.0", releases, ProjectPackagesRegistry.NPM, project_declares_esm=False
        )

        assert module_system == ModuleSystem.ESM_ONLY
        assert breaking_change == "ESM-only from 5.0.0"

    def test_no_breaking_change_when_project_declares_esm(self):
        releases = [_pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

        module_system, breaking_change = module_system_label(
            "chalk", "4.1.2", "5.0.0", releases, ProjectPackagesRegistry.NPM, project_declares_esm=True
        )

        assert module_system == ModuleSystem.ESM_ONLY
        assert breaking_change is None

    def test_no_breaking_change_for_non_flagged_major(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("4.2.0", module_system=ModuleSystem.CJS)]

        module_system, breaking_change = module_system_label(
            "chalk", "4.1.2", "4.2.0", releases, ProjectPackagesRegistry.NPM, project_declares_esm=False
        )

        assert module_system == ModuleSystem.CJS
        assert breaking_change is None

    def test_target_not_found_yields_none_module_system(self):
        module_system, breaking_change = module_system_label(
            "chalk", "4.1.2", "9.9.9", [], ProjectPackagesRegistry.NPM, project_declares_esm=False
        )

        assert module_system is None
        assert breaking_change is None

    def test_pypi_breaking_change_always_none_for_now(self):
        """No curated list anymore — see TestBreakingMajorsPyPI."""
        releases = [_pv("1.10.13"), _pv("2.0.0")]

        module_system, breaking_change = module_system_label(
            "pydantic", "1.10.13", "2.0.0", releases, ProjectPackagesRegistry.PYPI, project_declares_esm=False
        )

        assert module_system is None
        assert breaking_change is None
