"""Builders and file helpers shared by the npm adapter tests."""

import json
import os

from ossiq.adapters.package_managers.npm.lockfile import NPMResolverV3
from ossiq.domain.project import Dependency
from ossiq.service.update import UpdateEntry, UpdatePlan


# ============================================================================
# Test overrides
# ============================================================================
def build_tree(lock: dict, overrides: dict | None = None, ossiq_overrides: dict[str, str] | None = None) -> Dependency:
    """Resolve a lockfile into its dependency tree, whose root is the package named `p`."""
    root = NPMResolverV3(lock, overrides).build_graph("p", ossiq_overrides)
    assert root is not None
    return root


# ============================================================================
# Helpers for update-command tests
# ============================================================================
def make_npm_update_entry(
    name: str,
    current: str,
    recommended: str,
    version_defined: str | None = None,
    is_direct: bool = True,
    is_forced: bool = False,
    dependency_name: str | None = None,
) -> UpdateEntry:
    return UpdateEntry(
        package_name=name,
        dependency_name=dependency_name,
        current_version=current,
        recommended_version=recommended,
        is_direct=is_direct,
        reason=None,
        version_defined=version_defined,
        is_forced=is_forced,
    )


def make_npm_update_plan(
    direct: list[UpdateEntry] | None = None,
    transitive: list[UpdateEntry] | None = None,
    project_path: str = "/tmp/test-npm",
    installed_versions: dict[str, str] | None = None,
    pin_all: bool = False,
) -> UpdatePlan:
    return UpdatePlan(
        project_name="test-npm-project",
        project_path=project_path,
        registry_type="NPM",
        package_manager_name="npm",
        direct_entries=direct or [],
        transitive_entries=transitive or [],
        installed_versions=installed_versions or {},
        pin_all=pin_all,
    )


def write_package_json(project_dir: str, pkg: dict) -> None:
    path = os.path.join(project_dir, "package.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pkg, f)


def read_package_json(project_dir: str) -> dict:
    with open(os.path.join(project_dir, "package.json"), encoding="utf-8") as f:
        return json.load(f)
