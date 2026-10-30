# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for pnpm/lockfile.py: reading pnpm-lock.yaml (lockfile v9) and the dependency graph built
from it, down to which copy each edge lands on.
"""

from pathlib import Path

import pytest

from ossiq.adapters.package_managers.pnpm.lockfile import (
    PnpmTreeBuilderV9,
    installed_copies,
    load_lockfile,
    package_identity,
    ref_to_key,
    registry_parents,
    split_key,
    strip_peer_suffix,
)
from ossiq.domain.common import ConstraintType
from ossiq.domain.exceptions import PackageManagerLockfileParsingError
from ossiq.domain.project import Dependency, UnresolvedPeer

TESTDATA_PNPM = Path(__file__).parents[4] / "testdata" / "pnpm"
ROOT = ("p", "1.0.0")


def pnpm_lock(importer: dict, packages: dict | None = None, snapshots: dict | None = None, **top: dict) -> dict:
    """A minimal v9 project document whose root importer is `importer`."""
    return {
        "lockfileVersion": "9.0",
        "importers": {".": importer},
        "packages": packages or {},
        "snapshots": snapshots or {},
        **top,
    }


def direct(**refs: str) -> dict:
    """Importer `dependencies` whose specifier is `^1` and whose resolved value is each keyword's."""
    return {"dependencies": {name: {"specifier": "^1", "version": ref} for name, ref in refs.items()}}


def build(lock: dict, ranges: dict | None = None, ossiq_overrides: dict | None = None) -> Dependency:
    root = PnpmTreeBuilderV9(lock, ROOT, ranges).build_graph(ROOT[0], ossiq_overrides)
    assert root is not None
    return root


# ============================================================================
# Reading the file and its keys
# ============================================================================
class TestLoadLockfile:
    def test_single_document(self):
        assert load_lockfile("lockfileVersion: '9.0'\nimporters: {}\n")["lockfileVersion"] == "9.0"

    def test_project_graph_is_the_last_of_several_documents(self):
        """pnpm 11 puts a config-dependencies document first, and it has an `importers['.']` too."""
        text = (
            "---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    configDependencies: {}\n"
            "---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n"
            "      a: {specifier: ^1, version: 1.0.0}\n"
        )

        assert "dependencies" in load_lockfile(text)["importers"]["."]

    def test_real_lockfile_with_a_pnpm_pin_reads_the_project_document(self):
        lock = load_lockfile((TESTDATA_PNPM / "workspace-config" / "pnpm-lock.yaml").read_text())

        assert set(lock["importers"]["."]["dependencies"]) == {"debug", "lodash", "react"}

    @pytest.mark.parametrize("text", ["a: [unclosed", "", "- just\n- a list\n"])
    def test_unreadable_text_raises(self, text):
        with pytest.raises(PackageManagerLockfileParsingError):
            load_lockfile(text)


class TestKeys:
    @pytest.mark.parametrize(
        "key, expected",
        [
            ("react-dom@18.3.1(react@18.3.1)", "react-dom@18.3.1"),
            ("a@1.0.0(b@1.0.0)(c@2.0.0)", "a@1.0.0"),
            ("a@1.0.0(patch_hash=abc123)", "a@1.0.0"),
            ("a@1.0.0", "a@1.0.0"),
        ],
    )
    def test_strip_peer_suffix(self, key, expected):
        assert strip_peer_suffix(key) == expected

    @pytest.mark.parametrize(
        "key, expected",
        [
            ("lodash@4.17.21", ("lodash", "4.17.21")),
            ("@scope/pkg@1.2.3", ("@scope/pkg", "1.2.3")),
            ("a@git+ssh://git@github.com/o/r.git#abc", ("a", "git+ssh://git@github.com/o/r.git#abc")),
            ("nover", ("nover", "")),
        ],
    )
    def test_split_key_ends_the_name_at_the_first_at_past_the_scope(self, key, expected):
        assert split_key(key) == expected

    @pytest.mark.parametrize(
        "ref, name, expected",
        [
            ("4.1.2", "chalk", "chalk@4.1.2"),
            ("chalk@4.1.2", "chalk-legacy", "chalk@4.1.2"),
            ("@scope/x@1.0.0", "y", "@scope/x@1.0.0"),
            ("18.3.1(react@18.3.1)", "react-dom", "react-dom@18.3.1(react@18.3.1)"),
            ("file:../x", "x", "x@file:../x"),
            ("https://codeload.github.com/o/r/tar.gz/abc", "r", "r@https://codeload.github.com/o/r/tar.gz/abc"),
            ("git+ssh://git@github.com/o/r.git#abc", "r", "r@git+ssh://git@github.com/o/r.git#abc"),
            ("link:../x", "x", None),
        ],
    )
    def test_ref_to_key(self, ref, name, expected):
        assert ref_to_key(ref, name) == expected

    def test_package_identity_prefers_the_version_packages_records(self):
        packages = {"foo@https://x/foo.tgz": {"version": "1.2.3"}}

        assert package_identity(packages, "foo@https://x/foo.tgz") == ("foo", "1.2.3")
        assert package_identity(packages, "lodash@4.17.21") == ("lodash", "4.17.21")
        assert package_identity(packages, "react-dom@18.3.1(react@18.3.1)") == ("react-dom", "18.3.1")


# ============================================================================
# The graph
# ============================================================================
class TestBuildGraph:
    def test_importer_sections_become_categories(self):
        lock = pnpm_lock(
            {
                "dependencies": {"a": {"specifier": "^1", "version": "1.0.0"}},
                "devDependencies": {"b": {"specifier": "^1", "version": "1.0.0"}},
                "optionalDependencies": {"c": {"specifier": "^1", "version": "1.0.0"}},
            },
            snapshots={"a@1.0.0": {}, "b@1.0.0": {}, "c@1.0.0": {}},
        )

        root = build(lock)

        assert "a" in root.dependencies
        assert (root.optional_dependencies["b"].categories, root.optional_dependencies["c"].categories) == (
            ["development"],
            ["optional"],
        )

    def test_declared_ranges_become_the_constraints_of_the_children(self):
        lock = pnpm_lock(direct(a="1.0.0"), snapshots={"a@1.0.0": {"dependencies": {"b": "2.0.0"}}, "b@2.0.0": {}})

        child = build(lock, {("a", "1.0.0"): {"b": "^2.0.0"}}).dependencies["a"].dependencies["b"]

        assert (child.version_installed, child.parent_constraints, child.version_defined) == (
            "2.0.0",
            ["^2.0.0"],
            "^2.0.0",
        )

    def test_edge_without_a_known_range_still_links_and_carries_no_constraint(self):
        lock = pnpm_lock(direct(a="1.0.0"), snapshots={"a@1.0.0": {"dependencies": {"b": "2.0.0"}}, "b@2.0.0": {}})

        child = build(lock).dependencies["a"].dependencies["b"]

        assert (child.version_installed, child.parent_constraints) == ("2.0.0", [])

    def test_each_edge_lands_on_the_version_its_parent_recorded(self):
        lock = pnpm_lock(
            direct(a="1.0.0", b="1.0.0", m="2.0.0"),
            snapshots={
                "a@1.0.0": {"dependencies": {"m": "1.0.0"}},
                "b@1.0.0": {"dependencies": {"m": "2.0.0"}},
                "m@1.0.0": {},
                "m@2.0.0": {},
            },
        )

        root = build(lock)

        assert [root.dependencies[name].dependencies["m"].version_installed for name in ("a", "b")] == [
            "1.0.0",
            "2.0.0",
        ]

    def test_peer_variants_of_one_version_are_one_node(self):
        lock = pnpm_lock(
            direct(a="1.0.0(p@1.0.0)", b="1.0.0(p@2.0.0)"),
            snapshots={
                "a@1.0.0(p@1.0.0)": {"dependencies": {"x": "1.0.0(p@1.0.0)"}},
                "b@1.0.0(p@2.0.0)": {"dependencies": {"x": "1.0.0(p@2.0.0)"}},
                "x@1.0.0(p@1.0.0)": {},
                "x@1.0.0(p@2.0.0)": {},
            },
        )
        builder = PnpmTreeBuilderV9(lock, ROOT)

        root = builder.build_graph(ROOT[0])

        assert root is not None
        assert [key for key in builder.registry if key[0] == "x"] == [("x", "1.0.0")]
        assert root.dependencies["a"].dependencies["x"] is root.dependencies["b"].dependencies["x"]

    def test_alias_is_a_node_of_its_own_with_the_real_name_as_canonical(self):
        lock = pnpm_lock(
            {"dependencies": {"chalk-legacy": {"specifier": "npm:chalk@^4.1.2", "version": "chalk@4.1.2"}}},
            packages={"chalk@4.1.2": {"resolution": {"integrity": "x"}}},
            snapshots={"chalk@4.1.2": {"dependencies": {"ansi": "4.3.0"}}, "ansi@4.3.0": {}},
        )

        alias = build(lock).dependencies["chalk-legacy"]

        assert (alias.name, alias.canonical_name, alias.version_installed) == ("chalk-legacy", "chalk", "4.1.2")
        assert alias.dependencies["ansi"].version_installed == "4.3.0"

    def test_resolved_peer_links_once_as_a_peer(self):
        lock = pnpm_lock(
            direct(x="1.0.0(y@1.0.0)", y="1.0.0"),
            packages={"x@1.0.0": {"peerDependencies": {"y": "^1"}}},
            snapshots={"x@1.0.0(y@1.0.0)": {"dependencies": {"y": "1.0.0"}}, "y@1.0.0": {}},
        )

        x = build(lock).dependencies["x"]

        assert "y" not in x.dependencies
        assert x.optional_dependencies["y"].categories == ["peer"]
        assert [(r.requirer_name, r.spec, r.optional) for r in x.optional_dependencies["y"].peer_requirements] == [
            ("x", "^1", False)
        ]

    def test_unprovided_peer_is_recorded_missing_only_when_required(self):
        lock = pnpm_lock(
            direct(x="1.0.0"),
            packages={
                "x@1.0.0": {
                    "peerDependencies": {"y": "^1", "z": "^2"},
                    "peerDependenciesMeta": {"z": {"optional": True}},
                }
            },
            snapshots={"x@1.0.0": {}},
        )

        x = build(lock).dependencies["x"]

        assert x.unresolved_peers == [UnresolvedPeer(package="y", spec="^1", optional=False, installed_elsewhere=())]

    def test_link_to_the_workspace_is_skipped(self):
        lock = pnpm_lock({"dependencies": {"sibling": {"specifier": "workspace:*", "version": "link:../sibling"}}})

        assert build(lock).dependencies == {}

    @pytest.mark.parametrize(
        "specifier, catalog",
        [("catalog:", "default"), ("catalog:default", "default"), ("catalog:evergreen", "evergreen")],
    )
    def test_catalog_specifier_resolves_through_the_lockfile_catalogs(self, specifier, catalog):
        lock = pnpm_lock(
            {"dependencies": {"react": {"specifier": specifier, "version": "18.3.1"}}},
            snapshots={"react@18.3.1": {}},
            catalogs={catalog: {"react": {"specifier": "^18.2.0", "version": "18.3.1"}}},
        )

        react = build(lock).dependencies["react"]

        assert (react.version_defined, react.constraint_info.type) == ("^18.2.0", ConstraintType.DECLARED)

    def test_tarball_package_takes_its_version_and_source_from_packages(self):
        url = "https://codeload.github.com/o/foo/tar.gz/abc"
        lock = pnpm_lock(
            {"dependencies": {"foo": {"specifier": "github:o/foo", "version": url}}},
            packages={f"foo@{url}": {"version": "1.2.3", "resolution": {"tarball": url}}},
            snapshots={f"foo@{url}": {}},
        )

        foo = build(lock).dependencies["foo"]

        assert (foo.version_installed, foo.source) == ("1.2.3", url)

    def test_node_engine_requirement_comes_from_packages(self):
        lock = pnpm_lock(
            direct(a="1.0.0"),
            packages={"a@1.0.0": {"engines": {"node": ">=18"}}},
            snapshots={"a@1.0.0": {}},
        )

        assert (build(lock).dependencies["a"].required_engine or "").startswith("node:")


class TestOverrides:
    def lock_with_override(self, key: str) -> dict:
        return pnpm_lock(
            direct(qar="1.0.0", lodash="4.17.21"),
            snapshots={"qar@1.0.0": {"dependencies": {"zoo": "2.0.0"}}, "zoo@2.0.0": {}, "lodash@4.17.21": {}},
            overrides={key: "2.0.0" if "zoo" in key else "4.17.21"},
        )

    def test_root_rule_marks_the_copy_and_is_ossiq_authored_when_the_metadata_matches(self):
        lodash = build(self.lock_with_override("lodash"), ossiq_overrides={"lodash": "4.17.21"}).dependencies["lodash"]

        assert "overridden" in lodash.categories
        info = lodash.constraint_info
        assert (info.type, info.source_file, info.is_ossiq_authored) == (
            ConstraintType.OVERRIDE,
            "pnpm-workspace.yaml",
            True,
        )

    def test_root_rule_is_the_users_without_matching_metadata(self):
        lodash = build(self.lock_with_override("lodash")).dependencies["lodash"]

        assert lodash.constraint_info.is_ossiq_authored is False

    def test_scoped_rule_is_never_ossiq_authored(self):
        zoo = (
            build(self.lock_with_override("qar@1>zoo"), ossiq_overrides={"qar@1>zoo": "2.0.0"})
            .dependencies["qar"]
            .dependencies["zoo"]
        )

        assert (zoo.constraint_info.scope_path, zoo.constraint_info.is_ossiq_authored) == (["qar"], False)


class TestRegistryParents:
    def test_only_registry_packages_that_require_others_are_listed_once(self):
        lock = pnpm_lock(
            {},
            packages={
                "tarball@https://x/t.tgz": {"version": "1.0.0", "resolution": {"tarball": "https://x/t.tgz"}},
                "dirpkg@file:../d": {"resolution": {"directory": "../d", "type": "directory"}},
            },
            snapshots={
                "a@1.0.0": {"dependencies": {"b": "1.0.0"}},
                "a@1.0.0(p@1.0.0)": {"dependencies": {"b": "1.0.0", "p": "1.0.0"}},
                "leaf@1.0.0": {},
                "opt@1.0.0": {"optionalDependencies": {"x": "1.0.0"}},
                "tarball@https://x/t.tgz": {"dependencies": {"b": "1.0.0"}},
                "dirpkg@file:../d": {"dependencies": {"b": "1.0.0"}},
            },
        )

        assert registry_parents(lock) == [("a", "1.0.0"), ("opt", "1.0.0")]


class TestInstalledCopies:
    def test_every_package_is_named_by_its_registry_identity(self):
        lock = {
            "packages": {
                "react-dom@18.3.1": {},
                "@scope/x@1.0.0": {},
                # A tarball key carries its location; the entry records the version it installs.
                "foo@https://example.com/foo-2.0.0.tgz": {"version": "2.0.0"},
            }
        }
        assert installed_copies(lock) == {("react-dom", "18.3.1"), ("@scope/x", "1.0.0"), ("foo", "2.0.0")}

    def test_a_lockfile_without_packages_installs_nothing(self):
        assert installed_copies({"lockfileVersion": "9.0"}) == set()


# ============================================================================
# Real lockfiles
# ============================================================================
@pytest.fixture(params=["project1", "peers-aliases", "workspace-config"])
def real_builder(request) -> PnpmTreeBuilderV9:
    lock = load_lockfile((TESTDATA_PNPM / request.param / "pnpm-lock.yaml").read_text())
    builder = PnpmTreeBuilderV9(lock, ROOT)
    builder.build_graph(ROOT[0])
    return builder


class TestRealLockfiles:
    def test_every_edge_lands_on_the_version_its_parent_recorded(self, real_builder):
        for entry in real_builder.entries:
            parent = real_builder.registry[(entry["name"], entry["version"])]
            children = {**parent.dependencies, **parent.optional_dependencies}
            for name, ref in entry["refs"].items():
                key = ref_to_key(ref, name)
                if key is not None:
                    assert children[name].version_installed == package_identity(real_builder.packages, key)[1], (
                        entry["name"],
                        name,
                    )

    def test_two_versions_of_one_name_and_an_alias_stay_apart(self):
        lock = load_lockfile((TESTDATA_PNPM / "peers-aliases" / "pnpm-lock.yaml").read_text())

        root = build(lock)

        assert root.dependencies["minimatch"].version_installed != (
            root.dependencies["editorconfig"].dependencies["minimatch"].version_installed
        )
        assert (root.dependencies["chalk"].version_installed, root.dependencies["chalk-legacy"].canonical_name) == (
            "5.6.2",
            "chalk",
        )
        assert root.dependencies["ws"].unresolved_peers == []

    def test_catalog_and_override_in_a_workspace_fixture(self):
        lock = load_lockfile((TESTDATA_PNPM / "workspace-config" / "pnpm-lock.yaml").read_text())

        root = build(lock)

        assert root.dependencies["react"].version_defined == "^18.2.0"
        assert root.dependencies["lodash"].constraint_info.type == ConstraintType.OVERRIDE
        assert root.dependencies["debug"].dependencies["ms"].constraint_info.scope_path == ["debug"]
