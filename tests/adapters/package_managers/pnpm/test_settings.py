"""Tests for pnpm/settings.py: pnpm's minimumReleaseAge settings read as a ReleaseCutoff."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.pnpm.settings import (
    env_settings,
    global_config_path,
    pnpm_settings_layers,
    read_yaml_settings,
    release_cutoff_from_pnpm_settings,
)
from ossiq.domain.exceptions import PackageManagerLockfileParsingError

NOW = datetime(2026, 10, 30, tzinfo=UTC)
WEEK = 10080


class TestReleaseCutoffFromPnpmSettings:
    def test_no_settings_means_no_cutoff(self):
        # pnpm 10 defaults to 0, and pnpm 11's built-in 1440 is non-strict.
        assert release_cutoff_from_pnpm_settings([{}], now=NOW) is None
        assert release_cutoff_from_pnpm_settings([], now=NOW) is None

    def test_explicit_age_is_a_cutoff(self):
        cutoff = release_cutoff_from_pnpm_settings([{"minimumReleaseAge": WEEK}], now=NOW)
        assert cutoff is not None
        assert cutoff.source == "pnpm minimumReleaseAge"
        assert cutoff.default == NOW - timedelta(days=7)

    def test_strict_false_means_pnpm_falls_back_so_no_cutoff(self):
        layers = [{"minimumReleaseAge": WEEK, "minimumReleaseAgeStrict": False}]
        assert release_cutoff_from_pnpm_settings(layers, now=NOW) is None

    def test_strict_true_makes_the_implicit_age_a_cutoff(self):
        cutoff = release_cutoff_from_pnpm_settings([{"minimumReleaseAgeStrict": True}], now=NOW)
        assert cutoff is not None
        assert cutoff.default == NOW - timedelta(minutes=1440)

    @pytest.mark.parametrize("age", [0, -5])
    def test_age_of_zero_or_less_disables_it(self, age):
        assert release_cutoff_from_pnpm_settings([{"minimumReleaseAge": age}], now=NOW) is None

    def test_env_strings_read_like_yaml_values(self):
        cutoff = release_cutoff_from_pnpm_settings([{"minimumReleaseAge": "10080"}], now=NOW)
        assert cutoff is not None
        assert cutoff.default == NOW - timedelta(days=7)
        layers = [{"minimumReleaseAge": "10080", "minimumReleaseAgeStrict": "false"}]
        assert release_cutoff_from_pnpm_settings(layers, now=NOW) is None

    def test_each_key_comes_from_the_highest_layer_that_sets_it(self):
        env, workspace = {"minimumReleaseAge": "60"}, {"minimumReleaseAge": WEEK, "minimumReleaseAgeStrict": False}
        # The age is the env's, the strictness the workspace's; this is how pnpm layers settings.
        assert release_cutoff_from_pnpm_settings([env, workspace], now=NOW) is None
        assert release_cutoff_from_pnpm_settings([workspace, env], now=NOW) is None
        strict_workspace = {"minimumReleaseAge": WEEK}
        cutoff = release_cutoff_from_pnpm_settings([env, strict_workspace], now=NOW)
        assert cutoff is not None
        assert cutoff.default == NOW - timedelta(minutes=60)

    def test_a_value_pnpm_would_reject_is_no_cutoff(self):
        assert release_cutoff_from_pnpm_settings([{"minimumReleaseAge": "a week"}], now=NOW) is None

    def test_excluded_names_are_lifted(self):
        layers = [{"minimumReleaseAge": WEEK, "minimumReleaseAgeExclude": ["Lodash", "@scope/pkg"]}]
        cutoff = release_cutoff_from_pnpm_settings(layers, now=NOW)
        assert cutoff is not None
        assert cutoff.cutoff_for("lodash") is None
        assert cutoff.cutoff_for("@scope/pkg") is None
        assert cutoff.cutoff_for("react") == NOW - timedelta(days=7)

    def test_excluded_globs_are_lifted(self):
        layers = [{"minimumReleaseAge": WEEK, "minimumReleaseAgeExclude": ["@myorg/*", "loose-*"]}]
        cutoff = release_cutoff_from_pnpm_settings(layers, now=NOW)
        assert cutoff is not None
        assert cutoff.cutoff_for("@myorg/ui") is None
        assert cutoff.cutoff_for("loose-envify") is None
        assert cutoff.cutoff_for("loose") == NOW - timedelta(days=7)

    def test_versioned_entries_are_ignored(self):
        exclude = ["nx@21.6.5", "@scope/pkg@1.0.0", "webpack@4.47.0 || 5.102.1"]
        cutoff = release_cutoff_from_pnpm_settings(
            [{"minimumReleaseAge": WEEK, "minimumReleaseAgeExclude": exclude}], now=NOW
        )
        assert cutoff is not None
        assert cutoff.per_package == {}

    def test_exclude_that_is_not_a_list_is_ignored(self):
        layers = [{"minimumReleaseAge": WEEK, "minimumReleaseAgeExclude": "lodash"}]
        cutoff = release_cutoff_from_pnpm_settings(layers, now=NOW)
        assert cutoff is not None
        assert cutoff.per_package == {}


class TestEnvSettings:
    def test_pnpm_11_spelling(self):
        assert env_settings({"pnpm_config_minimum_release_age": "60"}) == {"minimumReleaseAge": "60"}

    def test_uppercase_spelling(self):
        assert env_settings({"PNPM_CONFIG_MINIMUM_RELEASE_AGE_STRICT": "false"}) == {"minimumReleaseAgeStrict": "false"}

    def test_pnpm_10_spelling(self):
        assert env_settings({"npm_config_minimum_release_age": "60"}) == {"minimumReleaseAge": "60"}

    def test_pnpm_prefix_wins_over_npm_prefix(self):
        environ = {"npm_config_minimum_release_age": "1", "pnpm_config_minimum_release_age": "2"}
        assert env_settings(environ) == {"minimumReleaseAge": "2"}

    def test_empty_value_is_unset(self):
        assert env_settings({"pnpm_config_minimum_release_age": ""}) == {}


class TestGlobalConfigPath:
    def test_xdg_config_home_wins(self):
        assert global_config_path({"XDG_CONFIG_HOME": "/x"}, "linux") == Path("/x/pnpm/config.yaml")

    def test_linux_default(self):
        assert global_config_path({}, "linux") == Path.home() / ".config" / "pnpm" / "config.yaml"

    def test_macos_default(self):
        expected = Path.home() / "Library" / "Preferences" / "pnpm" / "config.yaml"
        assert global_config_path({}, "darwin") == expected

    def test_windows_uses_localappdata(self):
        assert global_config_path({"LOCALAPPDATA": "/local"}, "win32") == Path("/local/pnpm/config/config.yaml")


class TestReadYamlSettings:
    def test_missing_file_reads_as_empty(self, tmp_path: Path):
        assert read_yaml_settings(tmp_path / "pnpm-workspace.yaml") == {}

    def test_reads_the_mapping(self, tmp_path: Path):
        path = tmp_path / "pnpm-workspace.yaml"
        path.write_text("# comment\nminimumReleaseAge: 10080\n")
        assert read_yaml_settings(path) == {"minimumReleaseAge": 10080}

    def test_a_document_that_is_not_a_mapping_reads_as_empty(self, tmp_path: Path):
        path = tmp_path / "pnpm-workspace.yaml"
        path.write_text("- a\n- b\n")
        assert read_yaml_settings(path) == {}

    def test_malformed_yaml_raises(self, tmp_path: Path):
        path = tmp_path / "pnpm-workspace.yaml"
        path.write_text("minimumReleaseAge: [\n")
        with pytest.raises(PackageManagerLockfileParsingError, match="pnpm-workspace.yaml"):
            read_yaml_settings(path)


class TestPnpmSettingsLayers:
    def test_env_workspace_and_global_in_precedence_order(self, tmp_path: Path):
        project, home = tmp_path / "project", tmp_path / "home"
        project.mkdir()
        (home / "pnpm").mkdir(parents=True)
        (project / "pnpm-workspace.yaml").write_text("minimumReleaseAge: 2\n")
        (home / "pnpm" / "config.yaml").write_text("minimumReleaseAge: 3\n")
        environ = {"XDG_CONFIG_HOME": str(home), "pnpm_config_minimum_release_age": "1"}

        layers = pnpm_settings_layers(project, environ)

        assert [layer["minimumReleaseAge"] for layer in layers] == ["1", 2, 3]

    def test_malformed_workspace_file_raises(self, tmp_path: Path):
        (tmp_path / "pnpm-workspace.yaml").write_text("minimumReleaseAge: [\n")
        with pytest.raises(PackageManagerLockfileParsingError):
            pnpm_settings_layers(tmp_path, {"XDG_CONFIG_HOME": str(tmp_path / "none")})
