# pylint: disable=redefined-outer-name,unused-variable,protected-access,unused-argument
"""
Tests for npm/overrides.py: parsing the `overrides` block, which rule governs a copy, and the
ownership record OSS IQ keeps of what it wrote.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.npm.constants import CATEGORIES_OVERRIDDEN
from ossiq.adapters.package_managers.npm.overrides import (
    OverrideRule,
    override_rule_matches_version,
    parse_override_rules,
)
from ossiq.domain.common import ConstraintType
from tests.adapters.package_managers.npm.helpers import (
    build_tree,
    make_npm_update_entry,
    make_npm_update_plan,
    read_package_json,
    write_package_json,
)


@pytest.fixture
def npm_project_with_overrides(temp_project_dir):
    """
    Create a project whose lockfile root entry declares overrides.

    lodash is a transitive dependency of express that is forced to 4.0.0
    via overrides.
    """
    package_json_path = Path(temp_project_dir) / "package.json"
    lockfile_path = Path(temp_project_dir) / "package-lock.json"

    package_json_content = {
        "name": "overrides-test-project",
        "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
        "overrides": {"lodash": "4.0.0"},
    }
    package_json_path.write_text(json.dumps(package_json_content, indent=2))

    lockfile_content = {
        "name": "overrides-test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "overrides-test-project",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {"lodash": "4.0.0"},
            },
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {"lodash": "^4.17.0"},
            },
            "node_modules/lodash": {"version": "4.0.0"},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content, indent=2))

    return temp_project_dir


class TestNpmOverrides:
    """Test suite for npm overrides support."""

    def test_overridden_package_gets_category(self, npm_project_with_overrides, settings):
        """Test that packages listed in overrides receive the 'overridden' category."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_overrides, settings)

        # Act
        project = npm_manager.project_info()

        # Find lodash (transitive dep of express, overridden to 4.0.0)
        lodash = project.dependency_tree.dependencies["express"].dependencies.get("lodash")
        assert lodash is not None
        assert CATEGORIES_OVERRIDDEN in lodash.categories

    def test_non_overridden_packages_have_no_override_category(self, npm_project_with_overrides, settings):
        """Test that packages not in overrides do not get the 'overridden' category."""
        # Arrange
        npm_manager = PackageManagerJsNpm(npm_project_with_overrides, settings)

        # Act
        project = npm_manager.project_info()

        # Assert
        express = project.dependency_tree.dependencies["express"]
        assert CATEGORIES_OVERRIDDEN not in express.categories

    @pytest.mark.parametrize(
        "overrides_input,expected",
        [
            ({}, []),
            (None, []),
            (
                {"foo": "1.0.0", "bar": "2.0.0"},
                [OverrideRule("foo", "1.0.0", raw_key="foo"), OverrideRule("bar", "2.0.0", raw_key="bar")],
            ),
            (
                {"foo": {".": "1.0.0", "bar": "2.0.0"}},
                [
                    OverrideRule("foo", "1.0.0", raw_key="foo"),
                    OverrideRule("bar", "2.0.0", scope_path=("foo",), raw_key="bar"),
                ],
            ),
            # no "." means the package itself is left alone; only its descendants are pinned
            ({"foo": {"bar": "2.0.0"}}, [OverrideRule("bar", "2.0.0", scope_path=("foo",), raw_key="bar")]),
            (
                {"foo@^1.2": "1.2.9", "@scope/pkg@3.0.0": "3.0.1", "@scope/other": "$other"},
                [
                    OverrideRule("foo", "1.2.9", key="^1.2", raw_key="foo@^1.2"),
                    OverrideRule("@scope/pkg", "3.0.1", key="3.0.0", raw_key="@scope/pkg@3.0.0"),
                    OverrideRule("@scope/other", "$other", raw_key="@scope/other"),
                ],
            ),
        ],
    )
    def test_parse_override_rules(self, overrides_input, expected):
        """parse_override_rules handles flat, keyed, scoped, scoped-package and reference entries."""
        assert parse_override_rules(overrides_input) == expected

    @pytest.mark.parametrize(
        "rule,version,expected",
        [
            (OverrideRule("foo", "1.0.0"), "9.9.9", True),
            (OverrideRule("foo", "1.2.9", key="^1.2.0"), "1.2.5", True),
            (OverrideRule("foo", "1.2.9", key="^1.2.0"), "2.0.0", False),
            # a copy already moved to the forced version still counts as governed
            (OverrideRule("foo", "2.0.0", key="^1.2.0"), "2.0.0", True),
            # `$name` defers to a root spec and is never itself a range to match against
            (OverrideRule("foo", "$foo", key="^1.2.0"), "2.0.0", False),
        ],
    )
    def test_override_rule_matches_version(self, rule, version, expected):
        """A keyed rule governs a copy that sits inside its key or already at its value."""
        assert override_rule_matches_version(rule, version) is expected

    def test_overrides_are_read_from_the_manifest_not_the_lockfile(self, temp_project_dir, settings):
        """npm never writes overrides into the lockfile root, so only package.json can say what is forced."""
        # Arrange
        root = Path(temp_project_dir)
        (root / "package.json").write_text(
            json.dumps({"name": "p", "version": "1.0.0", "dependencies": {"a": "^1"}, "overrides": {"b": "2.0.0"}})
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "p",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "p", "version": "1.0.0", "dependencies": {"a": "^1"}},
                        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2"}},
                        "node_modules/b": {"version": "2.0.0"},
                    },
                }
            )
        )

        # Act
        tree = PackageManagerJsNpm(temp_project_dir, settings).project_info().dependency_tree

        # Assert
        b = tree.dependencies["a"].dependencies["b"]
        assert CATEGORIES_OVERRIDDEN in b.categories
        assert b.constraint_info.override_value == "2.0.0"
        assert b.constraint_info.is_ossiq_authored is False

    def test_keyed_override_marks_only_the_copies_it_governs(self):
        """`foo@^9` governs the nested 9.x copy and leaves the hoisted 10.x copy a plain dependency."""
        # Arrange
        lockfile = {
            "name": "p",
            "packages": {
                "": {"name": "p", "dependencies": {"foo": "^10", "bar": "^1"}},
                "node_modules/foo": {"version": "10.2.5"},
                "node_modules/bar": {"version": "1.0.0", "dependencies": {"foo": "^9.0.1"}},
                "node_modules/bar/node_modules/foo": {"version": "9.0.9"},
            },
        }
        # Act
        root = build_tree(lockfile, {"foo@^9.0.0": "9.0.9"}, ossiq_overrides={"foo@^9.0.0": "9.0.9"})

        # Assert
        hoisted = root.dependencies["foo"]
        nested = root.dependencies["bar"].dependencies["foo"]
        assert CATEGORIES_OVERRIDDEN not in hoisted.categories
        assert hoisted.constraint_info.type != ConstraintType.OVERRIDE
        assert CATEGORIES_OVERRIDDEN in nested.categories
        assert nested.constraint_info.override_key == "^9.0.0"
        assert nested.constraint_info.is_ossiq_authored is True

    def test_scoped_override_is_never_ossiq_authored(self):
        """OSS IQ writes root rules only, so a rule scoped under another package is the user's."""
        # Arrange
        lockfile = {
            "name": "p",
            "packages": {
                "": {"name": "p", "dependencies": {"foo": "^1"}},
                "node_modules/foo": {"version": "1.0.0", "dependencies": {"bar": "^2"}},
                "node_modules/bar": {"version": "2.0.0"},
            },
        }

        # Act
        root = build_tree(lockfile, {"foo": {"bar": "2.0.0"}}, ossiq_overrides={"bar": "2.0.0"})

        # Assert
        bar = root.dependencies["foo"].dependencies["bar"]
        assert bar.constraint_info.scope_path == ["foo"]
        assert bar.constraint_info.is_ossiq_authored is False


def write_lockfile_with_override(project_dir: str, name: str, version: str) -> None:
    lockfile_path = Path(project_dir) / "package-lock.json"
    lockfile_content = {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.18.0"},
                "overrides": {name: version},
            },
            "node_modules/express": {"version": "4.18.2", "dependencies": {name: "^2.1.0"}},
            f"node_modules/{name}": {"version": version},
        },
    }
    lockfile_path.write_text(json.dumps(lockfile_content))


class TestOssiqMetadataOwnership:
    """Tests for ossiq:metadata override ownership (item #14): execute_update records what it
    wrote, project_info() compares against it to tell OSS IQ-authored overrides apart from
    user-authored ones, and a later execute_update never clobbers a user's hand-edit."""

    @pytest.fixture
    def npm(self, settings, temp_project_dir):
        return PackageManagerJsNpm(temp_project_dir, settings)

    def test_write_then_read_reports_ossiq_authored(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)

        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"]["ms@2.1.2"] == "2.1.3"
        assert pkg["ossiq:metadata"]["overrides"]["ms@2.1.2"] == "2.1.3"

        # execute_update never touches the lockfile — provide one that already holds the bumped copy
        # so project_info's read side has something to compare against.
        write_lockfile_with_override(temp_project_dir, "ms", "2.1.3")

        project = npm.project_info()
        ms = project.dependency_tree.dependencies["express"].dependencies.get("ms")
        assert ms is not None
        assert ms.constraint_info.is_ossiq_authored is True

    def test_hand_edited_override_is_not_ossiq_authored(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)

        # Simulate the user hand-editing the override value (ossiq:metadata is left untouched).
        pkg = read_package_json(temp_project_dir)
        pkg["overrides"]["ms@2.1.2"] = "2.1.9"
        write_package_json(temp_project_dir, pkg)
        write_lockfile_with_override(temp_project_dir, "ms", "2.1.9")

        project = npm.project_info()
        ms = project.dependency_tree.dependencies["express"].dependencies.get("ms")
        assert ms is not None
        assert ms.constraint_info.is_ossiq_authored is False

    def test_second_update_never_clobbers_hand_edited_override(self, npm, temp_project_dir):
        write_package_json(
            temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}
        )
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan)

        # User hand-edits the override to a value OSS IQ never wrote.
        pkg = read_package_json(temp_project_dir)
        pkg["overrides"]["ms@2.1.2"] = "2.1.9"
        write_package_json(temp_project_dir, pkg)

        # A second run recommends yet another version for the same package.
        plan2 = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.5", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch("ossiq.adapters.package_managers.api_npm.subprocess.run"):
            npm.execute_update(plan2)

        pkg = read_package_json(temp_project_dir)
        assert pkg["overrides"]["ms@2.1.2"] == "2.1.9"
