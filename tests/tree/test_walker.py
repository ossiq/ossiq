"""Tests for DependencyWalker."""

import pytest

from ossiq.tree.walker import DependencyWalker
from tests.tree.helpers import (
    PeerBuilder,
    graph_of,
    lock_dep,
    lock_edge,
    lock_pkg,
    make_lockfile,
)


class TestWalkEnabledExtras:
    @staticmethod
    def walked_names(lockfile, **walk_options):
        root = graph_of(lockfile)
        return {node.name for node, _ in DependencyWalker(root).walk_all_paths(**walk_options)}

    def test_what_an_extra_installs_is_not_walked_by_default(self, extras_lockfile):
        assert "httptools" not in self.walked_names(extras_lockfile)

    def test_what_an_enabled_extra_installs_is_walked_on_request(self, extras_lockfile):
        assert "httptools" in self.walked_names(extras_lockfile, include_enabled_extras=True)

    def test_an_extra_nobody_enabled_stays_out(self, extras_lockfile):
        names = self.walked_names(extras_lockfile, include_enabled_extras=True)

        assert "pytest" not in names

    @pytest.mark.parametrize("include_enabled_extras", [False, True])
    def test_regular_transitive_dependencies_are_walked_either_way(self, extras_lockfile, include_enabled_extras):
        assert "click" in self.walked_names(extras_lockfile, include_enabled_extras=include_enabled_extras)

    def test_extra_names_match_across_spellings(self):
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", deps=[lock_edge("allauth", "65.19.4", "Social_Account")]),
            lock_pkg("allauth", "65.19.4", optional_deps={"social-account": [lock_dep("oauthlib", "3.3.1")]}),
            lock_pkg("oauthlib", "3.3.1"),
        )

        assert "oauthlib" in self.walked_names(lockfile, include_enabled_extras=True)


class TestWalkInstalledPeers:
    """npm installs a required peer for its requirer, though it sits on no production edge."""

    @staticmethod
    def walk(lockfile, **walk_options):
        root = PeerBuilder(lockfile).build_graph("my-app")
        assert root is not None
        return [(node.name, path) for node, path in DependencyWalker(root).walk_all_paths(**walk_options)]

    @staticmethod
    def with_ui_peering_on_typescript(*, optional: bool = False, also_direct: bool = False):
        ui = lock_pkg("ui", "4.0.0", optional_deps={"peer": [lock_dep("typescript", "5.9.3")]})
        if optional:
            ui["optional_peers"] = ["typescript"]
        return make_lockfile(
            lock_pkg(
                "my-app",
                "1.0.0",
                deps=[lock_dep("ui", "4.0.0"), *([lock_dep("typescript", "5.9.3")] if also_direct else [])],
            ),
            ui,
            lock_pkg("typescript", "5.9.3", deps=[lock_dep("tslib", "2.8.1")]),
            lock_pkg("tslib", "2.8.1"),
        )

    def test_a_required_peer_is_walked_with_its_requirer_as_the_path(self):
        walked = dict(self.walk(self.with_ui_peering_on_typescript()))

        assert walked["typescript"] == ["ui"]

    def test_what_a_peer_depends_on_is_walked_too(self):
        walked = dict(self.walk(self.with_ui_peering_on_typescript()))

        assert walked["tslib"] == ["ui", "typescript"]

    def test_an_optional_peer_is_not_installed_for_its_requirer(self):
        names = [name for name, _ in self.walk(self.with_ui_peering_on_typescript(optional=True))]

        assert "typescript" not in names

    def test_a_peer_the_project_already_depends_on_is_not_entered_again(self):
        names = [name for name, _ in self.walk(self.with_ui_peering_on_typescript(also_direct=True))]

        assert names == ["tslib"]

    def test_the_peers_of_a_development_package_follow_the_roots_asked_for(self):
        lockfile = make_lockfile(
            lock_pkg("my-app", "1.0.0", optional_deps={"development": [lock_dep("tool", "1.0.0")]}),
            lock_pkg("tool", "1.0.0", optional_deps={"peer": [lock_dep("typescript", "5.9.3")]}),
            lock_pkg("typescript", "5.9.3"),
        )

        assert "typescript" not in [name for name, _ in self.walk(lockfile)]
        assert "typescript" in [name for name, _ in self.walk(lockfile, include_optional_roots=True)]
