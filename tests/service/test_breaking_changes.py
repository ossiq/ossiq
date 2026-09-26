"""Unit tests for service.project.breaking_changes.

Mirrors tests/service/test_version_ladder.py: real PackageRegistryApiPypi/PackageRegistryApiNpm
instances as version_rules (their constructors do no I/O), plain PackageVersion fixtures, no
mocking of the registries themselves.
"""

from __future__ import annotations

import pytest

from ossiq.adapters.api_npm import PackageRegistryApiNpm
from ossiq.adapters.api_pypi import PackageRegistryApiPypi
from ossiq.domain.common import ModuleSystem, ProjectPackagesRegistry
from ossiq.domain.version import PackageVersion
from ossiq.service.project.breaking_changes import (
    NODE_REQUIRE_ESM_MIN_STABLE,
    breaking_majors,
    compute_latest_compatible_major,
    compute_latest_preserving_module_system,
    crosses_module_system,
    module_system_label,
    module_system_note,
    node_supports_require_esm,
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


# ============================================================================
# N3: Node's require(esm) support was detected but never consulted
# ============================================================================


class TestNodeSupportsRequireEsm:
    """Node landed require() of a synchronous ES module without a flag in 22.12.0, backported to
    20.19.0 on the 20.x LTS line. Reference: https://nodejs.org/en/blog/release/v22.12.0
    """

    def test_above_threshold_on_22_x(self):
        assert node_supports_require_esm("22.22.2") is True  # the report's own detected version
        assert node_supports_require_esm("22.12.0") is True  # exactly at the threshold
        assert node_supports_require_esm("23.0.0") is True

    def test_below_threshold_on_22_x(self):
        assert node_supports_require_esm("22.11.9") is False

    def test_above_threshold_on_20_x_lts_backport(self):
        assert node_supports_require_esm("20.19.0") is True
        assert node_supports_require_esm("20.19.5") is True

    def test_below_threshold_on_20_x(self):
        assert node_supports_require_esm("20.18.9") is False

    def test_21_x_conservatively_unsupported(self):
        """Non-LTS, long EOL, backport status unconfirmed - treated as unsupported rather than
        guessed at.
        """
        assert node_supports_require_esm("21.7.3") is False

    def test_older_majors_unsupported(self):
        assert node_supports_require_esm("18.20.0") is False
        assert node_supports_require_esm("16.20.2") is False

    def test_none_and_unparseable_are_unsupported(self):
        assert node_supports_require_esm(None) is False
        assert node_supports_require_esm("") is False
        assert node_supports_require_esm("not-a-version") is False

    def test_majors_above_the_table_survive_a_new_backport_entry(self, monkeypatch):
        """The ceiling is NODE_REQUIRE_ESM_UNIVERSAL_FROM, not the table's highest key: a line added
        later because it needed its own threshold must not unsupport the majors already above it.
        """
        monkeypatch.setitem(NODE_REQUIRE_ESM_MIN_STABLE, 26, "26.4.0")
        assert node_supports_require_esm("23.0.0") is True
        assert node_supports_require_esm("25.1.0") is True
        assert node_supports_require_esm("26.3.0") is False  # the new line's own threshold applies
        assert node_supports_require_esm("26.4.0") is True


class TestBreakingMajorsNodeAwareness:
    def test_esm_only_major_not_flagged_when_node_supports_require_esm(self):
        releases = [_pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM, node_version="22.22.2")
        assert flagged == {}

    def test_esm_only_major_still_flagged_on_old_node(self):
        releases = [_pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM, node_version="16.20.2")
        assert flagged == {(0, 5): "ESM-only from 5.0.0"}

    def test_esm_only_major_still_flagged_when_node_version_unknown(self):
        """Unknown Node - the pre-fix default - must stay conservative, not assume support."""
        releases = [_pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]
        flagged = breaking_majors("chalk", releases, ProjectPackagesRegistry.NPM, node_version=None)
        assert flagged == {(0, 5): "ESM-only from 5.0.0"}

    def test_node_awareness_is_npm_only(self):
        """PyPI has no module-system signal at all yet (see the module docstring) - a node_version
        must not accidentally start flagging or unflagging anything there.
        """
        releases = [_pv("2.0.0")]
        flagged = breaking_majors("pydantic", releases, ProjectPackagesRegistry.PYPI, node_version="22.22.2")
        assert flagged == {}


class TestComputeLatestCompatibleMajorNodeAwareness:
    def test_uuid_shaped_regression(self):
        """The report's own reproduction: uuid installed on a CJS major, with every release in
        the next major ESM-only. Without Node awareness the ladder is stuck at installed; with a
        modern Node detected it correctly reaches the newest release. v0.1.10 (pre-N3-fix)
        recommended 11.1.1 here; this asserts the actually-correct 14.0.2.
        """
        releases = [
            _pv("9.0.1", module_system=ModuleSystem.CJS),
            _pv("11.0.0", module_system=ModuleSystem.ESM_ONLY),
            _pv("11.1.1", module_system=ModuleSystem.ESM_ONLY),
            _pv("14.0.2", module_system=ModuleSystem.ESM_ONLY),
        ]

        stuck = compute_latest_compatible_major("uuid", releases, "9.0.1", NPM, ProjectPackagesRegistry.NPM)
        assert stuck == "9.0.1"

        unlocked = compute_latest_compatible_major(
            "uuid", releases, "9.0.1", NPM, ProjectPackagesRegistry.NPM, node_version="22.22.2"
        )
        assert unlocked == "14.0.2"

    def test_old_node_stays_stuck(self):
        releases = [
            _pv("9.0.1", module_system=ModuleSystem.CJS),
            _pv("14.0.2", module_system=ModuleSystem.ESM_ONLY),
        ]
        result = compute_latest_compatible_major(
            "uuid", releases, "9.0.1", NPM, ProjectPackagesRegistry.NPM, node_version="18.20.0"
        )
        assert result == "9.0.1"


class TestModuleSystemLabelIgnoresTheRuntime:
    """require(esm) returns the module namespace, so a default-export-only package (chalk) breaks a
    CommonJS caller on every Node. The runtime qualifies the break; it never erases it."""

    def test_breaking_change_is_reported_whatever_the_runtime(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

        module_system, breaking_change = module_system_label(
            "chalk", "4.1.2", "5.0.0", releases, ProjectPackagesRegistry.NPM, project_declares_esm=False
        )

        assert module_system == ModuleSystem.ESM_ONLY
        assert breaking_change == "ESM-only from 5.0.0"

    def test_an_esm_only_install_already_copes_with_esm(self):
        releases = [
            _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
            _pv("6.0.0", module_system=ModuleSystem.ESM_ONLY),
        ]

        _, breaking_change = module_system_label(
            "chalk", "5.0.0", "6.0.0", releases, ProjectPackagesRegistry.NPM, project_declares_esm=False
        )

        assert breaking_change is None


class TestCrossesModuleSystem:
    @pytest.mark.parametrize(
        ("installed", "candidate", "declares_esm", "crosses"),
        [
            (ModuleSystem.CJS, ModuleSystem.ESM_ONLY, False, True),
            (ModuleSystem.DUAL, ModuleSystem.ESM_ONLY, False, True),
            (None, ModuleSystem.ESM_ONLY, False, True),
            (ModuleSystem.CJS, ModuleSystem.DUAL, False, False),
            (ModuleSystem.DUAL, ModuleSystem.CJS, False, False),
            (ModuleSystem.CJS, None, False, False),
            (ModuleSystem.ESM_ONLY, ModuleSystem.ESM_ONLY, False, False),
            (ModuleSystem.CJS, ModuleSystem.ESM_ONLY, True, False),
        ],
    )
    def test_only_a_move_to_esm_only_crosses(self, installed, candidate, declares_esm, crosses):
        assert crosses_module_system(installed, candidate, declares_esm) is crosses


class TestLatestPreservingModuleSystem:
    def test_stops_at_the_newest_release_the_installed_module_system_loads(self):
        releases = [
            _pv("8.3.2", module_system=ModuleSystem.DUAL),
            _pv("11.1.1", module_system=ModuleSystem.DUAL),
            _pv("12.0.0", module_system=ModuleSystem.ESM_ONLY),
        ]

        result = compute_latest_preserving_module_system(
            releases, "8.3.2", ModuleSystem.DUAL, NPM, project_declares_esm=False
        )

        assert result == "11.1.1"

    def test_equals_installed_when_nothing_newer_loads(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

        assert (
            compute_latest_preserving_module_system(
                releases, "4.1.2", ModuleSystem.CJS, NPM, project_declares_esm=False
            )
            == "4.1.2"
        )

    def test_an_esm_project_reaches_the_newest(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

        assert (
            compute_latest_preserving_module_system(releases, "4.1.2", ModuleSystem.CJS, NPM, project_declares_esm=True)
            == "5.0.0"
        )


class TestModuleSystemNote:
    RELEASES = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY)]

    @pytest.mark.parametrize(
        ("node_version", "fragment"),
        [
            ("26.8.1", "only if the package has named exports"),
            ("20.18.3", "won't load via require() on Node 20.18.3"),
            (None, "runtime unknown"),
        ],
    )
    def test_the_note_follows_the_runtime(self, node_version, fragment):
        note = module_system_note(
            self.RELEASES, "4.1.2", ModuleSystem.CJS, NPM, project_declares_esm=False, node_version=node_version
        )

        assert note is not None
        assert fragment in note

    def test_no_note_when_nothing_newer_crosses(self):
        releases = [_pv("4.1.2", module_system=ModuleSystem.CJS), _pv("4.2.0", module_system=ModuleSystem.CJS)]

        assert module_system_note(releases, "4.1.2", ModuleSystem.CJS, NPM, project_declares_esm=False) is None


# chalk as the npm registry serves it: 5.6.1 was the compromised September 2025 release, pulled
# from `versions` but still listed in `time`, so PackageRegistryApiNpm keeps it as an unpublished
# PackageVersion with no module_system.
CHALK_WITH_TOMBSTONE = [
    _pv("4.1.2", module_system=ModuleSystem.CJS),
    _pv("5.0.0", module_system=ModuleSystem.ESM_ONLY),
    _pv("5.6.0", module_system=ModuleSystem.ESM_ONLY),
    _pv("5.6.1", unpublished=True),
    _pv("5.6.2", module_system=ModuleSystem.ESM_ONLY),
    _pv("6.0.0", module_system=ModuleSystem.ESM_ONLY),
]


class TestBreakingMajorsIgnoresUnpublished:
    """D1 reproduction: one unpublished tombstone unflags a whole ESM-only major."""

    def test_unpublished_release_does_not_unflag_esm_major(self):
        flagged = breaking_majors("chalk", CHALK_WITH_TOMBSTONE, ProjectPackagesRegistry.NPM)

        assert flagged == {(0, 5): "ESM-only from 5.0.0", (0, 6): "ESM-only from 6.0.0"}

    def test_latest_compatible_major_stays_on_the_cjs_line(self):
        result = compute_latest_compatible_major(
            "chalk", CHALK_WITH_TOMBSTONE, "4.1.2", NPM, ProjectPackagesRegistry.NPM
        )

        assert result == "4.1.2"
