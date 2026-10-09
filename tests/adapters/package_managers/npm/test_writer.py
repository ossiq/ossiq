# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for npm/writer.py: specifiers and overrides written back into package.json.
"""

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.dependency_tree import GraphExporter
from ossiq.adapters.package_managers.npm.writer import (
    add_peer_repairs,
    apply_direct_specs,
    write_transitive_overrides,
)
from ossiq.service.project.models import PeerRepair
from tests.adapters.package_managers.npm.helpers import make_npm_update_entry, make_npm_update_plan


# ============================================================================
# Test dev-chain transitive dependency visibility (js-cookie / CVE scenario)
# ============================================================================
@pytest.fixture
def npm_project_with_dev_transitive_deps(temp_project_dir):
    """
    Project where a devDependency (test-utils) has a production dep (js-helper)
    which in turn has a production dep (js-cookie).

    This mirrors the real-world scenario:
      root (devDependencies) → @vue/test-utils
      @vue/test-utils (dependencies) → js-beautify
      js-beautify (dependencies) → js-cookie  ← has CVE, must not be invisible
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "test-project",
        "version": "1.0.0",
        "devDependencies": {"test-utils": "^1.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "test-project",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "test-project", "devDependencies": {"test-utils": "^1.0.0"}},
            "node_modules/test-utils": {
                "version": "1.0.0",
                "dev": True,
                "dependencies": {"js-helper": "^2.0.0"},
            },
            "node_modules/js-helper": {
                "version": "2.0.0",
                "dev": True,
                "dependencies": {"js-cookie": "^3.0.5"},
            },
            "node_modules/js-cookie": {"version": "3.0.5", "dev": True},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


class TestDevTransitiveDeps:
    """Test that transitive deps of devDependencies are reachable in the graph."""

    def test_graph_links_dev_transitive_chain(self, npm_project_with_dev_transitive_deps, settings):
        """The graph must correctly wire dev dep → js-helper → js-cookie via production edges."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        tree = project.dependency_tree

        test_utils = tree.optional_dependencies["test-utils"]
        assert "js-helper" in test_utils.dependencies, "js-helper must be a production edge of test-utils"
        js_helper = test_utils.dependencies["js-helper"]
        assert "js-cookie" in js_helper.dependencies, "js-cookie must be a production edge of js-helper"

    def test_walk_with_optional_roots_discovers_dev_transitive(self, npm_project_with_dev_transitive_deps, settings):
        """walk_all_paths(include_optional_roots=True) must yield js-cookie."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        walker = GraphExporter(project.dependency_tree)

        discovered = {node.name for node, _ in walker.walk_all_paths(include_optional_roots=True)}
        assert "js-cookie" in discovered
        assert "js-helper" in discovered

    def test_walk_without_optional_roots_misses_dev_transitive(self, npm_project_with_dev_transitive_deps, settings):
        """walk_all_paths(include_optional_roots=False) must NOT yield js-cookie (no prod chain)."""
        npm_manager = PackageManagerJsNpm(npm_project_with_dev_transitive_deps, settings)
        project = npm_manager.project_info()
        walker = GraphExporter(project.dependency_tree)

        discovered = {node.name for node, _ in walker.walk_all_paths(include_optional_roots=False)}
        assert "js-cookie" not in discovered
        assert "js-helper" not in discovered


class TestApplyDirectSpecsWithAliases:
    """The manifest rewrite iterates manifest keys, so it has to be keyed on them.

    An npm alias declares `uuid-v7: "npm:uuid@^7.0.0"`; the entry's registry name is `uuid`, which
    matches no key in any DEP_SECTIONS map. Keying on package_name meant apply silently wrote
    nothing for every aliased dependency, and a plain `uuid` declared alongside an aliased
    `uuid-*` could pick up the wrong entry's version.
    """

    def test_aliased_dep_is_matched_and_left_untouched(self):
        pkg = {"dependencies": {"uuid-v7": "npm:uuid@^7.0.0"}}
        entry = make_npm_update_entry("uuid", "7.0.3", "7.1.0", dependency_name="uuid-v7")

        apply_direct_specs(pkg, make_npm_update_plan(direct=[entry]))

        # relax_spec deliberately returns npm: specs unchanged — but it is now reached at all.
        assert pkg["dependencies"]["uuid-v7"] == "npm:uuid@^7.0.0"

    def test_plain_dep_alongside_an_alias_gets_its_own_entry(self):
        pkg = {"dependencies": {"uuid": "^7.0.0", "uuid-v11": "npm:uuid@>11.0.0"}}
        plan = make_npm_update_plan(
            direct=[
                make_npm_update_entry("uuid", "7.0.3", "7.1.0"),
                make_npm_update_entry("uuid", "13.0.0", "14.0.2", dependency_name="uuid-v11"),
            ]
        )

        apply_direct_specs(pkg, plan)

        assert pkg["dependencies"]["uuid"] == "^7.1.0"
        assert pkg["dependencies"]["uuid-v11"] == "npm:uuid@>11.0.0"

    def test_unaliased_dep_is_unaffected(self):
        pkg = {"dependencies": {"lodash": "^4.17.0"}}
        entry = make_npm_update_entry("lodash", "4.17.21", "4.18.1")

        apply_direct_specs(pkg, make_npm_update_plan(direct=[entry]))

        assert pkg["dependencies"]["lodash"] == "^4.18.1"


class TestWriteTransitiveOverridesOwnership:
    """What counts as a key the user has taken over, at the edges of 'present and different'."""

    def test_key_recorded_by_ossiq_but_deleted_by_user_is_written_again(self):
        pkg = {"name": "app", "version": "1.0.0", "ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}}}
        plan = make_npm_update_plan(transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.5", is_direct=False)])

        write_transitive_overrides(pkg, plan)

        assert pkg["overrides"] == {"ms@2.1.2": "2.1.5"}
        assert pkg["ossiq:metadata"]["overrides"] == {"ms@2.1.2": "2.1.5"}

    def test_key_nulled_by_user_is_written_again(self):
        pkg = {
            "name": "app",
            "version": "1.0.0",
            "overrides": {"ms@2.1.2": None},
            "ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}},
        }
        plan = make_npm_update_plan(transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.5", is_direct=False)])

        write_transitive_overrides(pkg, plan)

        assert pkg["overrides"] == {"ms@2.1.2": "2.1.5"}

    def test_key_edited_by_user_is_left_alone(self):
        pkg = {
            "name": "app",
            "version": "1.0.0",
            "overrides": {"ms@2.1.2": "2.1.9"},
            "ossiq:metadata": {"overrides": {"ms@2.1.2": "2.1.3"}},
        }
        plan = make_npm_update_plan(transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.5", is_direct=False)])

        write_transitive_overrides(pkg, plan)

        assert pkg["overrides"] == {"ms@2.1.2": "2.1.9"}
        assert pkg["ossiq:metadata"]["overrides"] == {"ms@2.1.2": "2.1.3"}


class TestWriteTransitiveOverridesChainedBump:
    """Two nested copies of one package bumped in one plan, where the first copy's target is the
    second copy's current version. The rule written for the first must survive the second."""

    @pytest.mark.parametrize("reverse", [False, True], ids=["first-copy-first", "second-copy-first"])
    def test_both_copies_keep_their_override(self, reverse):
        entries = [
            make_npm_update_entry("foo", "1.0.0", "2.0.0", is_direct=False),
            make_npm_update_entry("foo", "2.0.0", "3.0.0", is_direct=False),
        ]
        if reverse:
            entries.reverse()
        pkg: dict[str, Any] = {"name": "app", "version": "1.0.0"}

        write_transitive_overrides(pkg, make_npm_update_plan(transitive=entries))

        expected = {"foo@1.0.0": "2.0.0", "foo@2.0.0": "3.0.0"}
        assert pkg["overrides"] == expected
        assert pkg["ossiq:metadata"]["overrides"] == expected


class TestAddPeerRepairs:
    """A peer installed out of reach is declared, so npm places it where its requirers load it."""

    @staticmethod
    def plan_with(*repairs: PeerRepair):
        return dataclasses.replace(make_npm_update_plan(), peer_repairs=list(repairs))

    def test_a_development_peer_goes_to_dev_dependencies(self):
        pkg: dict[str, Any] = {"name": "app", "devDependencies": {"@vue/test-utils": "~2.5.1"}}

        add_peer_repairs(pkg, self.plan_with(PeerRepair("@vue/server-renderer", "~3.5.43", True, ("@vue/test-utils",))))

        assert pkg["devDependencies"] == {"@vue/test-utils": "~2.5.1", "@vue/server-renderer": "~3.5.43"}

    def test_a_production_peer_goes_to_dependencies(self):
        pkg: dict[str, Any] = {"name": "app"}

        add_peer_repairs(pkg, self.plan_with(PeerRepair("host", "~1.2.0", False, ("plugin",))))

        assert pkg["dependencies"] == {"host": "~1.2.0"}

    def test_a_package_the_user_already_declares_is_left_as_written(self):
        pkg: dict[str, Any] = {"name": "app", "dependencies": {"host": "^1"}}

        add_peer_repairs(pkg, self.plan_with(PeerRepair("host", "~1.2.0", True, ("plugin",))))

        assert pkg == {"name": "app", "dependencies": {"host": "^1"}}


class TestWriteFamilyMoveOverride:
    def test_a_family_move_is_written_under_its_range_key(self):
        entry = dataclasses.replace(
            make_npm_update_entry("@vue/reactivity", "3.5.42", "3.5.43", is_direct=False),
            override_key="3.5.42 - 3.5.43",
        )
        pkg: dict[str, Any] = {"name": "app"}

        write_transitive_overrides(pkg, make_npm_update_plan(transitive=[entry]))

        assert pkg["overrides"] == {"@vue/reactivity@3.5.42 - 3.5.43": "3.5.43"}
        assert pkg["ossiq:metadata"]["overrides"] == {"@vue/reactivity@3.5.42 - 3.5.43": "3.5.43"}

    def test_it_supersedes_the_rule_oss_iq_wrote_for_the_same_copy(self):
        entry = dataclasses.replace(
            make_npm_update_entry("@vue/reactivity", "3.5.42", "3.5.43", is_direct=False),
            override_key="3.5.42 - 3.5.43",
        )
        pkg: dict[str, Any] = {
            "name": "app",
            "overrides": {"@vue/reactivity@3.5.41": "3.5.42"},
            "ossiq:metadata": {"overrides": {"@vue/reactivity@3.5.41": "3.5.42"}},
        }

        write_transitive_overrides(pkg, make_npm_update_plan(transitive=[entry]))

        assert pkg["overrides"] == {"@vue/reactivity@3.5.42 - 3.5.43": "3.5.43"}
