# pylint: disable=redefined-outer-name,unused-argument
"""
Tests for PackageManagerJsPnpm: detection, registry precedence, manifest-only project_info()
and the refusal of apply/add.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.api_pnpm import PackageManagerJsPnpm, declared_package_manager
from ossiq.domain.exceptions import PackageManagerOperationUnsupported
from ossiq.domain.packages_manager import PNPM


def write_project(root: str, package_json: dict | str, *extra_files: str) -> str:
    """Write package.json (a dict, or raw text) plus empty *extra_files* into *root*."""
    text = package_json if isinstance(package_json, str) else json.dumps(package_json)
    (Path(root) / "package.json").write_text(text)
    for name in extra_files:
        (Path(root) / name).write_text("")
    return root


class TestDeclaredPackageManager:
    @pytest.mark.parametrize(
        "data, expected",
        [
            ({}, None),
            ({"packageManager": "pnpm@10.4.1+sha512.abc"}, "pnpm"),
            ({"packageManager": "npm@10.9.0"}, "npm"),
            ({"devEngines": {"packageManager": {"name": "pnpm", "version": "10"}}}, "pnpm"),
            ({"devEngines": {"packageManager": [{"name": "pnpm"}, {"name": "npm"}]}}, "pnpm"),
            ({"devEngines": {"packageManager": []}}, None),
            ({"devEngines": "pnpm"}, None),
            ({"packageManager": "npm@10", "devEngines": {"packageManager": {"name": "pnpm"}}}, "npm"),
        ],
    )
    def test_reads_the_declaration(self, data, expected):
        assert declared_package_manager(data) == expected


class TestHasPackageManager:
    @pytest.mark.parametrize(
        "package_json, extra_files, expected",
        [
            ({"name": "p"}, ("pnpm-lock.yaml",), True),
            ({"name": "p"}, ("pnpm-workspace.yaml",), True),
            ({"packageManager": "pnpm@10.4.1+sha512.abc"}, (), True),
            ({"devEngines": {"packageManager": {"name": "pnpm"}}}, (), True),
            ({"devEngines": {"packageManager": [{"name": "pnpm"}, {"name": "npm"}]}}, (), True),
            # A declaration wins over a stale pnpm file.
            ({"packageManager": "npm@10.9.0"}, ("pnpm-lock.yaml",), False),
            ({"name": "p"}, (), False),
            ({"name": "p"}, ("package-lock.json",), False),
            ("{not json", ("pnpm-lock.yaml",), False),
        ],
    )
    def test_detection_matrix(self, temp_project_dir, package_json, extra_files, expected):
        write_project(temp_project_dir, package_json, *extra_files)
        assert PackageManagerJsPnpm.has_package_manager(temp_project_dir) is expected

    def test_pnpm_lockfile_without_package_json_does_not_match(self, temp_project_dir):
        (Path(temp_project_dir) / "pnpm-lock.yaml").write_text("")
        assert PackageManagerJsPnpm.has_package_manager(temp_project_dir) is False


class TestCreatePackageManagers:
    def test_pnpm_tree_yields_only_the_pnpm_adapter(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"name": "p"}, "pnpm-lock.yaml")

        managers = list(create_package_managers(temp_project_dir, settings))

        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerJsPnpm)

    def test_plain_npm_project_is_still_npm(self, settings):
        managers = list(create_package_managers("testdata/npm/project1", settings))

        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerJsNpm)

    def test_both_lockfiles_without_a_declaration_go_to_pnpm(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"name": "p"}, "pnpm-lock.yaml", "package-lock.json")

        managers = list(create_package_managers(temp_project_dir, settings))

        assert len(managers) == 1
        assert isinstance(managers[0], PackageManagerJsPnpm)


class TestProjectInfo:
    def test_manifest_only_scan(self, temp_project_dir, settings):
        write_project(
            temp_project_dir,
            {
                "name": "demo",
                "type": "module",
                "engines": {"node": ">=18"},
                "dependencies": {"express": "^4.18.0"},
                "devDependencies": {"jest": "^29.0.0"},
            },
            "pnpm-lock.yaml",
        )

        project = PackageManagerJsPnpm(temp_project_dir, settings).project_info()

        assert project.package_manager_type is PNPM
        assert project.name == "demo"
        assert project.has_lockfile is False
        assert project.declares_esm is True
        assert project.engine_constraints == {"node": "18.0.0"}
        assert "express" in project.dependency_tree.dependencies
        assert "jest" in project.dependency_tree.optional_dependencies

    def test_name_falls_back_to_the_directory(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"dependencies": {"express": "^4.18.0"}}, "pnpm-lock.yaml")

        project = PackageManagerJsPnpm(temp_project_dir, settings).project_info()

        assert project.name == Path(temp_project_dir).name


class TestUnsupportedOperations:
    """apply and add must refuse, never fall back to npm."""

    def test_execute_update_and_install_package_refuse_and_touch_nothing(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"name": "p"}, "pnpm-lock.yaml")
        before = (Path(temp_project_dir) / "package.json").read_bytes()
        pnpm = PackageManagerJsPnpm(temp_project_dir, settings)

        with pytest.raises(PackageManagerOperationUnsupported):
            pnpm.execute_update(MagicMock())
        with pytest.raises(PackageManagerOperationUnsupported):
            pnpm.install_package("lodash")

        assert (Path(temp_project_dir) / "package.json").read_bytes() == before
        assert not (Path(temp_project_dir) / "package-lock.json").exists()
