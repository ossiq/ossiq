# pylint: disable=redefined-outer-name,unused-argument
"""
Tests for PackageManagerJsPnpm: detection, registry precedence, project_info() with and without a
lockfile, the declared-range fetch, the release cutoff, and applying a plan or adding a package.
"""

import difflib
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ossiq.adapters.package_managers import api_pnpm
from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.adapters.package_managers.api_npm import PackageManagerJsNpm
from ossiq.adapters.package_managers.api_pnpm import (
    PROJECT_FILES,
    PackageManagerJsPnpm,
    declared_package_manager,
    fetch_declared_ranges,
)
from ossiq.clients.client_npm import NpmBatchStrategy
from ossiq.domain.exceptions import (
    PackageManagerExecutionError,
    PackageManagerLockfileParsingError,
    PackageManagerUpdateIncomplete,
)
from ossiq.domain.packages_manager import PNPM
from tests.adapters.package_managers.npm.helpers import (
    make_npm_update_entry,
    make_npm_update_plan,
    read_package_json,
    write_package_json,
)


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
            "pnpm-workspace.yaml",
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
        write_project(temp_project_dir, {"dependencies": {"express": "^4.18.0"}}, "pnpm-workspace.yaml")

        project = PackageManagerJsPnpm(temp_project_dir, settings).project_info()

        assert project.name == Path(temp_project_dir).name


TESTDATA = Path(__file__).parents[3] / "testdata"


@pytest.fixture
def no_registry(monkeypatch):
    """Scan lockfiles without asking the registry for the ranges they leave out."""
    monkeypatch.setattr(api_pnpm, "fetch_declared_ranges", lambda parents, settings: {})


class TestProjectInfoWithLockfile:
    def test_installed_versions_come_from_the_lockfile(self, no_registry, settings):
        project = PackageManagerJsPnpm(str(TESTDATA / "pnpm" / "project1"), settings).project_info()

        vue = project.dependency_tree.dependencies["vue"]
        assert project.has_lockfile is True
        assert (vue.version_installed, vue.version_defined) == ("1.0.28", "^1.0.23")

    def test_direct_names_and_constraint_types_match_the_npm_scan(self, no_registry, settings):
        """The same package.json must read the same under either manager."""

        def shape(tree):
            return {
                name: dep.constraint_info.type
                for name, dep in {**tree.dependencies, **tree.optional_dependencies}.items()
            }

        pnpm = PackageManagerJsPnpm(str(TESTDATA / "pnpm" / "project1"), settings).project_info()
        npm = PackageManagerJsNpm(str(TESTDATA / "npm" / "project1"), settings).project_info()

        assert shape(pnpm.dependency_tree) == shape(npm.dependency_tree)

    def test_unsupported_lockfile_version_raises(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"name": "p", "dependencies": {"a": "^1"}})
        (Path(temp_project_dir) / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\nimporters: {}\n")

        with pytest.raises(PackageManagerLockfileParsingError, match="6.0"):
            PackageManagerJsPnpm(temp_project_dir, settings).project_info()

    def test_lockfile_without_dependencies_raises(self, temp_project_dir, settings):
        write_project(temp_project_dir, {"name": "p"})
        (Path(temp_project_dir) / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\nimporters:\n  .: {}\n")

        with pytest.raises(PackageManagerLockfileParsingError):
            PackageManagerJsPnpm(temp_project_dir, settings).project_info()

    def test_overrides_the_tool_wrote_are_read_from_package_json_metadata(
        self, no_registry, temp_project_dir, settings
    ):
        project = TESTDATA / "pnpm" / "workspace-config"
        package_json = json.loads((project / "package.json").read_text())
        package_json["ossiq:metadata"] = {"overrides": {"lodash": "4.17.21"}}
        write_project(temp_project_dir, package_json)
        (Path(temp_project_dir) / "pnpm-lock.yaml").write_text((project / "pnpm-lock.yaml").read_text())

        lodash = PackageManagerJsPnpm(temp_project_dir, settings).project_info().dependency_tree.dependencies["lodash"]

        assert lodash.constraint_info.is_ossiq_authored is True


class TestFetchDeclaredRanges:
    @pytest.fixture
    def registry_url(self, httpserver, monkeypatch) -> str:
        url = httpserver.url_for("/").rstrip("/")
        monkeypatch.setattr(NpmBatchStrategy, "BASE_URL", url)
        return url

    def test_reads_dependencies_and_optional_dependencies(self, registry_url, httpserver, settings):
        httpserver.expect_request("/a").respond_with_json(
            {
                "name": "a",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {"dependencies": {"b": "^2"}, "optionalDependencies": {"c": "~1.0.0"}},
                    "2.0.0": {"dependencies": {"b": "^3"}},
                },
            }
        )

        ranges = fetch_declared_ranges([("a", "1.0.0"), ("a", "2.0.0")], settings)

        assert ranges == {("a", "1.0.0"): {"b": "^2", "c": "~1.0.0"}, ("a", "2.0.0"): {"b": "^3"}}

    def test_registry_that_cannot_answer_yields_nothing(self, registry_url, httpserver, settings):
        httpserver.expect_request("/a").respond_with_data("missing", status=404)

        assert fetch_declared_ranges([("a", "1.0.0")], settings) == {}

    def test_nothing_to_look_up_makes_no_request(self, registry_url, httpserver, settings):
        assert fetch_declared_ranges([], settings) == {}
        assert httpserver.log == []


@pytest.fixture
def clean_pnpm_env(monkeypatch, tmp_path):
    """Keep the developer's pnpm config and env out of the test: an empty global dir, no age variables."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for prefix in ("pnpm_config_", "PNPM_CONFIG_", "npm_config_", "NPM_CONFIG_"):
        for suffix in ("minimum_release_age", "minimum_release_age_strict"):
            monkeypatch.delenv(prefix + suffix, raising=False)


@pytest.mark.usefixtures("clean_pnpm_env")
class TestReleaseCutoff:
    """Reading the cutoff from the fixtures' real settings files."""

    def test_workspace_file_sets_the_cutoff_and_its_exclusions(self, settings):
        project = str(TESTDATA / "pnpm" / "workspace-config")
        week_ago = timedelta(minutes=10080)

        before = datetime.now(UTC) - week_ago
        cutoff = PackageManagerJsPnpm(project, settings).release_cutoff()
        after = datetime.now(UTC) - week_ago

        assert cutoff is not None
        assert cutoff.source == "pnpm minimumReleaseAge"
        assert cutoff.default is not None
        assert before <= cutoff.default <= after
        assert cutoff.cutoff_for("lodash") is None  # excluded by name
        assert cutoff.cutoff_for("loose-envify") is None  # excluded by glob
        assert cutoff.cutoff_for("debug") == cutoff.default  # `debug@4.4.3` is a version entry: ignored

    def test_project_without_settings_has_no_cutoff(self, settings):
        assert PackageManagerJsPnpm(str(TESTDATA / "pnpm" / "project1"), settings).release_cutoff() is None

    def test_environment_overrides_the_workspace_file(self, settings, monkeypatch):
        monkeypatch.setenv("pnpm_config_minimum_release_age", "60")
        project = str(TESTDATA / "pnpm" / "workspace-config")

        cutoff = PackageManagerJsPnpm(project, settings).release_cutoff()

        assert cutoff is not None
        assert cutoff.default is not None
        assert cutoff.default > datetime.now(UTC) - timedelta(hours=2)

    def test_global_config_applies_to_a_project_without_settings(self, settings, tmp_path):
        (tmp_path / "xdg" / "pnpm").mkdir(parents=True)
        (tmp_path / "xdg" / "pnpm" / "config.yaml").write_text("minimumReleaseAge: 10080\n")

        cutoff = PackageManagerJsPnpm(str(TESTDATA / "pnpm" / "project1"), settings).release_cutoff()

        assert cutoff is not None


PNPM_RUN = "ossiq.adapters.package_managers.api_pnpm.subprocess.run"
SIMPLE_PACKAGE = {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}


def pnpm_installs(root: str, *copies: str):
    """A stand-in for a pnpm run that succeeds and writes a lockfile installing *copies* (`name@version`)."""

    def run(command, **kwargs):
        lock = {"lockfileVersion": "9.0", "packages": {copy: {} for copy in copies}}
        (Path(root) / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock))

    return run


def snapshot(root: str) -> dict[str, bytes | None]:
    """The bytes of every file a pnpm run may rewrite; None for one that does not exist."""
    return {name: (Path(root) / name).read_bytes() if (Path(root) / name).exists() else None for name in PROJECT_FILES}


def express_plan(root: str, **kwargs):
    return make_npm_update_plan(
        direct=[make_npm_update_entry("express", "4.18.0", "4.19.0", version_defined="^4.18.0")],
        project_path=root,
        **kwargs,
    )


@pytest.fixture
def workspace_project(temp_project_dir) -> str:
    """A scratch copy of testdata/pnpm/workspace-config: package.json, lockfile and workspace file."""
    shutil.copytree(TESTDATA / "pnpm" / "workspace-config", temp_project_dir, dirs_exist_ok=True)
    return temp_project_dir


class TestExecuteUpdate:
    """execute_update() writes the plan into the project files, then runs `pnpm install`."""

    @pytest.fixture
    def pnpm(self, settings, temp_project_dir):
        return PackageManagerJsPnpm(temp_project_dir, settings)

    def test_installs_without_scripts_and_without_the_frozen_lockfile(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        with patch(PNPM_RUN, side_effect=pnpm_installs(temp_project_dir, "express@4.19.0")) as mock_run:
            pnpm.execute_update(express_plan(temp_project_dir))
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0] == ["pnpm", "install", "--ignore-scripts", "--no-frozen-lockfile"]
        assert mock_run.call_args.kwargs["cwd"] == temp_project_dir

    def test_direct_dependency_is_relaxed_in_package_json(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        with patch(PNPM_RUN, side_effect=pnpm_installs(temp_project_dir, "express@4.19.0")):
            pnpm.execute_update(express_plan(temp_project_dir))
        assert read_package_json(temp_project_dir)["dependencies"]["express"] == "^4.19.0"

    def test_transitive_update_goes_to_workspace_overrides_and_its_record_to_package_json(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        with patch(PNPM_RUN, side_effect=pnpm_installs(temp_project_dir, "ms@2.1.3")):
            pnpm.execute_update(plan)

        pkg = read_package_json(temp_project_dir)
        assert "overrides" not in pkg
        assert pkg["ossiq:metadata"]["overrides"] == {"ms@2.1.2": "2.1.3"}
        workspace = yaml.safe_load((Path(temp_project_dir) / "pnpm-workspace.yaml").read_text())
        assert workspace == {"overrides": {"ms@2.1.2": "2.1.3"}}

    def test_workspace_file_is_created_only_when_something_is_written_to_it(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        with patch(PNPM_RUN, side_effect=pnpm_installs(temp_project_dir, "express@4.19.0")):
            pnpm.execute_update(express_plan(temp_project_dir))
        assert not (Path(temp_project_dir) / "pnpm-workspace.yaml").exists()

    def test_workspace_file_is_left_byte_identical_when_the_plan_does_not_touch_it(self, pnpm, workspace_project):
        before = (Path(workspace_project) / "pnpm-workspace.yaml").read_bytes()
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("lodash", "4.17.21", "4.17.22", version_defined="^4.17.21")],
            project_path=workspace_project,
        )
        with patch(PNPM_RUN, side_effect=pnpm_installs(workspace_project, "lodash@4.17.22")):
            pnpm.execute_update(plan)
        assert (Path(workspace_project) / "pnpm-workspace.yaml").read_bytes() == before

    def test_workspace_comments_survive_and_the_new_override_sits_in_its_block(self, pnpm, workspace_project):
        path = Path(workspace_project) / "pnpm-workspace.yaml"
        before = path.read_text()
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("semver", "7.0.0", "7.5.2", is_direct=False)],
            project_path=workspace_project,
        )
        with patch(PNPM_RUN, side_effect=pnpm_installs(workspace_project, "semver@7.5.2")):
            pnpm.execute_update(plan)

        diff = list(difflib.unified_diff(before.splitlines(), path.read_text().splitlines(), lineterm="", n=0))
        changed = [line for line in diff if line[:1] in "+-" and not line.startswith(("+++", "---"))]
        assert changed == ["+  semver@7.0.0: 7.5.2"]
        # The blank line before the next block's comment stayed behind the overrides block.
        assert "  semver@7.0.0: 7.5.2\n\n# Cooldown" in path.read_text()

    def test_a_scoped_rule_the_user_wrote_blocks_the_write(self, pnpm, workspace_project):
        """`debug@4>ms` governs every copy of ms, so OSS IQ adds nothing beside it."""
        before = snapshot(workspace_project)
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=workspace_project,
        )
        with patch(PNPM_RUN):
            pnpm.execute_update(plan)

        assert (Path(workspace_project) / "pnpm-workspace.yaml").read_bytes() == before["pnpm-workspace.yaml"]
        assert "ossiq:metadata" not in read_package_json(workspace_project)

    def test_catalog_dependency_is_bumped_in_the_workspace_and_left_alone_in_package_json(
        self, pnpm, workspace_project
    ):
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("react", "18.3.1", "18.4.0", version_defined="catalog:")],
            project_path=workspace_project,
        )
        with patch(PNPM_RUN, side_effect=pnpm_installs(workspace_project, "react@18.4.0")):
            pnpm.execute_update(plan)

        assert read_package_json(workspace_project)["dependencies"]["react"] == "catalog:"
        workspace = (Path(workspace_project) / "pnpm-workspace.yaml").read_text()
        assert "  react: ^18.4.0\n" in workspace
        assert "# Versions shared by `catalog:` specifiers in package.json." in workspace

    @staticmethod
    def two_pass_plan(root: str):
        write_package_json(
            root,
            {"name": "app", "version": "1.0.0", "dependencies": {"vue-router": "^5.1.0", "pinia": "^3.0.4"}},
        )
        return make_npm_update_plan(
            direct=[
                make_npm_update_entry("vue-router", "5.1.0", "5.4.0", version_defined="^5.1.0", install_pass=1),
                make_npm_update_entry("pinia", "3.0.4", "4.1.0", version_defined="^3.0.4", install_pass=2),
            ],
            project_path=root,
        )

    def test_a_multi_pass_plan_only_locks_until_the_last_pass(self, pnpm, temp_project_dir):
        plan = self.two_pass_plan(temp_project_dir)
        manifests, announced = [], []

        def fake_run(command, **kwargs):
            manifests.append(read_package_json(temp_project_dir)["dependencies"])
            pnpm_installs(temp_project_dir, "vue-router@5.4.0", "pinia@4.1.0")(command)

        with patch(PNPM_RUN, side_effect=fake_run) as mock_run:
            pnpm.execute_update(plan, on_pass=lambda number, total: announced.append((number, total)))

        assert [call.args[0] for call in mock_run.call_args_list] == [
            ["pnpm", "install", "--ignore-scripts", "--no-frozen-lockfile", "--lockfile-only"],
            ["pnpm", "install", "--ignore-scripts", "--no-frozen-lockfile"],
        ]
        assert manifests == [
            {"vue-router": "^5.4.0", "pinia": "^3.0.4"},
            {"vue-router": "^5.4.0", "pinia": "^4.1.0"},
        ]
        assert announced == [(1, 2), (2, 2)]

    def test_a_one_pass_plan_never_announces_a_pass(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        announced = []
        with patch(PNPM_RUN, side_effect=pnpm_installs(temp_project_dir, "express@4.19.0")):
            pnpm.execute_update(
                express_plan(temp_project_dir), on_pass=lambda number, total: announced.append((number, total))
            )
        assert announced == []

    def test_targets_pnpm_did_not_install_are_reported_and_what_landed_is_kept(self, pnpm, workspace_project):
        """The fixture's own `lodash: 4.17.21` override wins over the bumped spec, and pnpm still exits 0."""
        plan = make_npm_update_plan(
            direct=[
                make_npm_update_entry("lodash", "4.17.21", "4.18.1", version_defined="^4.17.21"),
                make_npm_update_entry("debug", "4.3.4", "4.4.3", version_defined="^4.3.4"),
            ],
            transitive=[make_npm_update_entry("semver", "7.0.0", "7.5.2", is_direct=False)],
            project_path=workspace_project,
        )
        installs = pnpm_installs(workspace_project, "lodash@4.17.21", "debug@4.4.3", "ms@2.1.3")

        with patch(PNPM_RUN, side_effect=installs):
            with pytest.raises(PackageManagerUpdateIncomplete) as raised:
                pnpm.execute_update(plan)

        assert str(raised.value) == (
            "pnpm did not install lodash 4.18.1 (installed: 4.17.21); semver 7.5.2 (installed: none)"
        )
        # Nothing is rolled back: debug landed, and the edits for the rest stay for the user to resolve.
        assert read_package_json(workspace_project)["dependencies"] == {
            "react": "catalog:",
            "lodash": "^4.18.1",
            "debug": "^4.4.3",
        }
        assert "  semver@7.0.0: 7.5.2\n" in (Path(workspace_project) / "pnpm-workspace.yaml").read_text()

    def test_a_failure_in_a_later_pass_restores_all_three_files(self, pnpm, workspace_project):
        plan = make_npm_update_plan(
            direct=[
                make_npm_update_entry("lodash", "4.17.21", "4.17.22", version_defined="^4.17.21", install_pass=1),
                make_npm_update_entry("debug", "4.3.4", "4.4.0", version_defined="^4.3.4", install_pass=2),
            ],
            transitive=[make_npm_update_entry("semver", "7.0.0", "7.5.2", is_direct=False)],
            project_path=workspace_project,
        )
        before = snapshot(workspace_project)
        root = Path(workspace_project)

        def fake_run(command, **kwargs):
            if "--lockfile-only" not in command:
                raise subprocess.CalledProcessError(1, command)
            (root / "pnpm-lock.yaml").write_text("rewritten by pass 1")

        with patch(PNPM_RUN, side_effect=fake_run):
            with pytest.raises(PackageManagerExecutionError, match="pass 2 of 2"):
                pnpm.execute_update(plan)

        assert snapshot(workspace_project) == before

    def test_files_pnpm_created_during_a_failed_run_are_removed(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        plan = make_npm_update_plan(
            transitive=[make_npm_update_entry("ms", "2.1.2", "2.1.3", is_direct=False)],
            project_path=temp_project_dir,
        )
        before = snapshot(temp_project_dir)
        root = Path(temp_project_dir)

        def fake_run(command, **kwargs):
            (root / "pnpm-lock.yaml").write_text("created by pnpm")
            raise subprocess.CalledProcessError(1, command)

        with patch(PNPM_RUN, side_effect=fake_run):
            with pytest.raises(PackageManagerExecutionError, match="pnpm install failed"):
                pnpm.execute_update(plan)

        assert snapshot(temp_project_dir) == before
        assert not (root / "pnpm-workspace.yaml").exists()
        assert not (root / "pnpm-lock.yaml").exists()

    def test_a_missing_pnpm_binary_is_a_clean_error_and_restores_everything(self, pnpm, workspace_project):
        plan = make_npm_update_plan(
            direct=[make_npm_update_entry("lodash", "4.17.21", "4.17.22", version_defined="^4.17.21")],
            transitive=[make_npm_update_entry("semver", "7.0.0", "7.5.2", is_direct=False)],
            project_path=workspace_project,
        )
        before = snapshot(workspace_project)

        with patch(PNPM_RUN, side_effect=FileNotFoundError("pnpm")):
            with pytest.raises(PackageManagerExecutionError, match="pnpm was not found") as raised:
                pnpm.execute_update(plan)

        assert raised.value.hint and "Install pnpm" in raised.value.hint
        assert snapshot(workspace_project) == before

    def test_a_missing_binary_in_a_later_pass_keeps_its_hint(self, pnpm, temp_project_dir):
        plan = self.two_pass_plan(temp_project_dir)
        before = snapshot(temp_project_dir)
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                raise FileNotFoundError("pnpm")

        with patch(PNPM_RUN, side_effect=fake_run):
            with pytest.raises(PackageManagerExecutionError, match="pass 2 of 2") as raised:
                pnpm.execute_update(plan)

        assert raised.value.hint and "Install pnpm" in raised.value.hint
        assert snapshot(temp_project_dir) == before

    def test_an_interrupted_install_restores_the_project_and_keeps_interrupting(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        before = snapshot(temp_project_dir)

        with patch(PNPM_RUN, side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                pnpm.execute_update(express_plan(temp_project_dir))

        assert snapshot(temp_project_dir) == before

    def test_malformed_package_json_raises_clean_error_and_writes_nothing(self, pnpm, temp_project_dir):
        (Path(temp_project_dir) / "package.json").write_text("{not valid json", encoding="utf-8")
        with patch(PNPM_RUN) as mock_run:
            with pytest.raises(PackageManagerExecutionError, match="not valid JSON"):
                pnpm.execute_update(express_plan(temp_project_dir))
        mock_run.assert_not_called()
        assert (Path(temp_project_dir) / "package.json").read_text(encoding="utf-8") == "{not valid json"

    def test_malformed_workspace_file_raises_clean_error_before_anything_is_written(self, pnpm, temp_project_dir):
        write_package_json(temp_project_dir, SIMPLE_PACKAGE)
        (Path(temp_project_dir) / "pnpm-workspace.yaml").write_text("overrides: [unclosed\n")
        before = snapshot(temp_project_dir)

        with patch(PNPM_RUN) as mock_run:
            with pytest.raises(PackageManagerExecutionError, match="pnpm-workspace.yaml is not valid YAML"):
                pnpm.execute_update(express_plan(temp_project_dir))

        mock_run.assert_not_called()
        assert snapshot(temp_project_dir) == before


class TestInstallPackage:
    """install_package() runs `pnpm add <spec>`, which edits package.json itself."""

    @pytest.fixture
    def pnpm(self, settings, temp_project_dir):
        return PackageManagerJsPnpm(temp_project_dir, settings)

    @pytest.mark.parametrize(
        "version, spec", [("4.19.0", "express@4.19.0"), (None, "express")], ids=["pinned", "unpinned"]
    )
    def test_adds_the_spec_without_running_scripts(self, pnpm, temp_project_dir, version, spec):
        write_package_json(temp_project_dir, {"name": "app", "version": "1.0.0", "dependencies": {}})
        with patch(PNPM_RUN) as mock_run:
            result = pnpm.install_package("express", version)
        assert result == 0
        assert mock_run.call_args.args[0] == ["pnpm", "add", "--ignore-scripts", spec]
        assert mock_run.call_args.kwargs["cwd"] == temp_project_dir

    @pytest.mark.parametrize(
        "failure",
        [subprocess.CalledProcessError(1, ["pnpm", "add"]), FileNotFoundError("pnpm")],
        ids=["exit-code", "missing-binary"],
    )
    def test_a_failure_restores_package_json_lockfile_and_workspace(self, pnpm, workspace_project, failure):
        root = Path(workspace_project)
        before = snapshot(workspace_project)

        def fake_run(command, **kwargs):
            # pnpm add rewrites all three files before it fails.
            (root / "package.json").write_text('{"name": "half-written"}')
            (root / "pnpm-lock.yaml").write_text("half written")
            (root / "pnpm-workspace.yaml").write_text("half: written")
            raise failure

        with patch(PNPM_RUN, side_effect=fake_run):
            with pytest.raises(PackageManagerExecutionError):
                pnpm.install_package("express", "4.19.0")

        assert snapshot(workspace_project) == before
