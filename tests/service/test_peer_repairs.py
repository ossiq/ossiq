"""Tests for service/project/peer_repairs.py — putting out-of-reach peers back where npm resolves them."""

from unittest.mock import MagicMock

from packaging.version import Version

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.project import ConstraintSource, IncomingEdge, InstalledCopy, UnresolvedPeer
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.peer_repairs import plan_peer_repairs
from ossiq.service.update_impact import ImpactKind

SOURCE = ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json")
OUT_OF_REACH = UnresolvedPeer("@vue/server-renderer", "3.x", optional=True, installed_elsewhere=("3.5.43",))


def pv(version: str) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url="",
        declared_dependencies={},
        published_date_iso="2026-01-01T00:00:00Z",
    )


def registry(versions: dict[str, list[str]], requires: dict[tuple[str, str], dict[str, str]]) -> MagicMock:
    registry = MagicMock()
    registry.package_registry = ProjectPackagesRegistry.NPM
    registry.one_copy_per_name = False
    registry.package_versions.side_effect = lambda name: [pv(v) for v in versions.get(name, [])]
    registry.package_version_requires.side_effect = lambda name, version: requires.get((name, version), {})
    registry.package_version_peers.side_effect = lambda name, version: {}

    def compare(v1: str, v2: str) -> int:
        a, b = Version(v1), Version(v2)
        return -1 if a < b else (1 if a > b else 0)

    registry.compare_versions.side_effect = compare
    registry.newest_version.side_effect = lambda found: max(found, key=lambda p: Version(p.version), default=None)
    return registry


def record(
    name: str,
    *copies: InstalledCopy,
    dev: bool = False,
    declared: str | None = None,
    path: list[str] | None = None,
) -> ScanRecord:
    result = ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=dev,
        installed_version=copies[0].version if copies else "1.0.0",
        latest_version=None,
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST"),
        time_lag_days=None,
        releases_lag=None,
        cve=[],
        constraint_info=SOURCE,
        version_constraint_declared=declared,
        dependency_path=path,
    )
    result.installed_copies = list(copies)
    return result


def copy(version: str, *edges: tuple[str, str, str]) -> InstalledCopy:
    return InstalledCopy(version, tuple(IncomingEdge(*edge) for edge in edges), SOURCE)


class TestFrontendSplit:
    """The frontend/ layout after vue 3.5.43 was installed beside the stale 3.5.42 @vue family."""

    def scan(self, *, shared_pinned_by_outsider: bool = False):
        test_utils = record("@vue/test-utils", copy("2.5.1"), dev=True)
        test_utils.unresolved_peers = [OUT_OF_REACH]
        vue = record("vue", copy("3.5.43"), declared="~3.5.43")
        renderer = record("@vue/server-renderer", copy("3.5.43", ("vue", "3.5.43", "3.5.43")))
        stale_owner = (
            ("legacy-plugin", "1.0.0", "3.5.42") if shared_pinned_by_outsider else ("babel-jsx", "1.0.0", "^3.5.18")
        )
        shared = record(
            "@vue/shared",
            copy("3.5.43", ("vue", "3.5.43", "3.5.43"), ("@vue/server-renderer", "3.5.43", "3.5.43")),
            copy("3.5.42", stale_owner),
        )
        npm = registry(
            {"@vue/shared": ["3.5.42", "3.5.43"]},
            {
                ("vue", "3.5.43"): {"@vue/server-renderer": "3.5.43", "@vue/shared": "3.5.43"},
                ("@vue/server-renderer", "3.5.43"): {"@vue/shared": "3.5.43"},
            },
        )
        return plan_peer_repairs([vue, test_utils], [renderer, shared], npm)

    def test_the_peer_is_added_in_its_familys_style_and_the_stale_copies_move(self):
        (repair,) = self.scan()

        assert (repair.package, repair.spec, repair.is_dev, repair.requirers) == (
            "@vue/server-renderer",
            "~3.5.43",
            True,
            ("@vue/test-utils",),
        )
        assert [(m.package_name, m.current_version, m.projected_version, m.kind) for m in repair.family_moves] == [
            ("@vue/shared", "3.5.42", "3.5.43", ImpactKind.OVERRIDE_BUMP)
        ]

    def test_a_stale_copy_someone_else_pins_stays_but_the_peer_is_still_added(self):
        (repair,) = self.scan(shared_pinned_by_outsider=True)

        assert repair.package == "@vue/server-renderer"
        assert repair.family_moves == ()


class TestPlanPeerRepairs:
    def test_a_newer_copy_is_never_moved_back(self):
        test_utils = record("t", copy("1.0.0"), dev=True)
        test_utils.unresolved_peers = [UnresolvedPeer("x", "^1", optional=True, installed_elsewhere=("1.0.0",))]
        owner = record("owner", copy("2.0.0"))
        target = record("x", copy("1.0.0", ("owner", "2.0.0", "1.0.0")))
        shared = record("shared", copy("1.0.0", ("owner", "2.0.0", "1.0.0")), copy("1.1.0", ("other", "1.0.0", "^1")))
        npm = registry({"shared": ["1.0.0", "1.1.0"]}, {("owner", "2.0.0"): {"x": "1.0.0", "shared": "1.0.0"}})

        (repair,) = plan_peer_repairs([test_utils, owner], [target, shared], npm)

        assert repair.family_moves == ()

    def test_no_repair_when_nothing_installed_elsewhere_fits_the_range(self):
        requirer = record("t", copy("1.0.0"))
        requirer.unresolved_peers = [UnresolvedPeer("x", "^2", optional=True, installed_elsewhere=("1.0.0",))]

        assert plan_peer_repairs([requirer], [record("x", copy("1.0.0"))], registry({}, {})) == []

    def test_a_transitive_requirer_under_a_production_dependency_adds_to_dependencies(self):
        app = record("app-lib", copy("1.0.0"))
        requirer = record("plugin", copy("1.0.0"), path=["app-lib"])
        requirer.unresolved_peers = [UnresolvedPeer("x", "^1", installed_elsewhere=("1.2.0",))]

        (repair,) = plan_peer_repairs([app], [requirer, record("x", copy("1.2.0"))], registry({}, {}))

        assert (repair.is_dev, repair.spec) == (False, "~1.2.0")

    def test_one_repair_per_peer_shared_by_several_requirers(self):
        dev_one = record("a", copy("1.0.0"), dev=True)
        prod_two = record("b", copy("1.0.0"))
        for requirer in (dev_one, prod_two):
            requirer.unresolved_peers = [UnresolvedPeer("x", "^1", optional=True, installed_elsewhere=("1.2.0",))]

        (repair,) = plan_peer_repairs([dev_one, prod_two], [record("x", copy("1.2.0"))], registry({}, {}))

        assert repair.requirers == ("a", "b")
        assert repair.is_dev is False
