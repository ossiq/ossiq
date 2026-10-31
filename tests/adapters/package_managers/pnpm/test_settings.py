"""Tests for pnpm/settings.py: pnpm's minimumReleaseAge settings read as a ReleaseCutoff."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ossiq.adapters.package_managers.pnpm.settings import (
    env_settings,
    global_config_path,
    install_cooldown,
    pnpm_settings_layers,
    read_yaml_settings,
    release_cutoff_from_pnpm_settings,
)
from ossiq.domain.exceptions import PackageManagerLockfileParsingError

NOW = datetime(2026, 10, 30, tzinfo=UTC)
WEEK = 10080
DAY = timedelta(days=1)


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

    def test_exclude_list_is_a_json_array(self):
        environ = {"pnpm_config_minimum_release_age_exclude": '["a@1.0.0", "b"]'}
        assert env_settings(environ) == {"minimumReleaseAgeExclude": ["a@1.0.0", "b"]}

    def test_exclude_list_is_read_from_pnpm_11_spelling_only(self):
        # pnpm 10 takes the variable as a plain string and ignores it, so it exempts nothing there.
        assert env_settings({"npm_config_minimum_release_age_exclude": '["a"]'}) == {}

    def test_exclude_list_that_is_not_json_is_skipped(self):
        assert env_settings({"pnpm_config_minimum_release_age_exclude": "a,b"}) == {}


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


def released(*releases: tuple[str, str, float]) -> dict[tuple[str, str], datetime]:
    """Publish times for `(name, version, days old)` releases."""
    return {(name, version): NOW - timedelta(days=age) for name, version, age in releases}


def exclude_list(cooldown) -> list[str]:
    return json.loads(cooldown.environ.get("pnpm_config_minimum_release_age_exclude", "[]"))


class TestInstallCooldown:
    def cooldown(self, layers=None, *, days=7, published=None, picks=(), forced=(), environ=None):
        return install_cooldown(
            environ or {},
            layers if layers is not None else [{}],
            days=days,
            published=published or {},
            picks={*picks, *forced},
            forced=set(forced),
            now=NOW,
        )

    @pytest.mark.parametrize("days", [0, -3])
    def test_no_cooldown_passes_nothing(self, days):
        assert self.cooldown(days=days) is None

    def test_project_without_settings_gets_a_non_strict_cooldown_in_both_spellings(self):
        cooldown = self.cooldown()

        assert cooldown is not None
        for prefix in ("pnpm_config_", "npm_config_"):
            assert cooldown.environ[prefix + "minimum_release_age"] == str(WEEK)
            assert cooldown.environ[prefix + "minimum_release_age_strict"] == "false"
        assert "pnpm_config_minimum_release_age_exclude" not in cooldown.environ
        assert cooldown.exclusions == []

    def test_a_longer_project_age_wins(self):
        cooldown = self.cooldown([{"minimumReleaseAge": 20000, "minimumReleaseAgeStrict": False}])

        assert cooldown is not None
        assert cooldown.environ["pnpm_config_minimum_release_age"] == "20000"

    def test_a_strict_project_stays_strict_and_its_own_flag_is_left_alone(self):
        environ = {"pnpm_config_minimum_release_age_strict": "true"}

        cooldown = self.cooldown([{"minimumReleaseAge": 1440}], environ=environ)

        assert cooldown is not None
        assert cooldown.environ["pnpm_config_minimum_release_age"] == str(WEEK)
        assert cooldown.environ["pnpm_config_minimum_release_age_strict"] == "true"
        assert "npm_config_minimum_release_age_strict" not in cooldown.environ

    def test_a_project_that_set_strict_false_stays_non_strict(self):
        cooldown = self.cooldown([{"minimumReleaseAge": 1440, "minimumReleaseAgeStrict": False}])

        assert cooldown is not None
        assert cooldown.environ["pnpm_config_minimum_release_age_strict"] == "false"

    @pytest.mark.parametrize("age", ["soon", None, -5, [1]])
    def test_an_age_that_is_not_a_positive_number_counts_as_unset(self, age):
        cooldown = self.cooldown([{"minimumReleaseAge": age}])

        assert cooldown is not None
        assert cooldown.environ["pnpm_config_minimum_release_age"] == str(WEEK)

    @pytest.mark.parametrize("project", [0, 60, 1440, 20000])
    @pytest.mark.parametrize("days", [1, 7, 30])
    def test_the_age_is_never_below_the_project_age_or_the_cooldown(self, project, days):
        cooldown = self.cooldown([{"minimumReleaseAge": project}], days=days)

        assert cooldown is not None
        assert int(cooldown.environ["pnpm_config_minimum_release_age"]) == max(project, days * 1440)

    def test_inherited_values_in_any_spelling_give_way_and_the_rest_of_the_environment_is_kept(self):
        environ = {
            "PATH": "/bin",
            "NPM_CONFIG_MINIMUM_RELEASE_AGE": "5",
            "PNPM_CONFIG_MINIMUM_RELEASE_AGE_STRICT": "true",
            "PNPM_CONFIG_MINIMUM_RELEASE_AGE_EXCLUDE": '["x"]',
        }

        cooldown = self.cooldown(environ=environ)

        assert cooldown is not None
        assert cooldown.environ["PATH"] == "/bin"
        assert not {name for name in cooldown.environ if name.startswith(("NPM_CONFIG_", "PNPM_CONFIG_"))}

    def test_a_locked_release_younger_than_the_cooldown_is_exempted_for_the_run_only(self):
        published = released(("young", "1.0.0", 3), ("old", "1.0.0", 30))

        cooldown = self.cooldown(published=published)

        assert cooldown is not None
        assert json.loads(cooldown.environ["pnpm_config_minimum_release_age_exclude"]) == ["young@1.0.0"]
        assert cooldown.exclusions == []

    def test_a_locked_release_younger_than_the_projects_own_age_is_also_persisted(self):
        # pnpm 11 re-checks it on a plain install, where the implicit age is a day.
        published = released(("fresh", "1.0.0", 0.2), ("week", "1.0.0", 3))

        cooldown = self.cooldown(published=published)

        assert cooldown is not None
        assert cooldown.exclusions == ["fresh@1.0.0"]
        assert json.loads(cooldown.environ["pnpm_config_minimum_release_age_exclude"]) == ["fresh@1.0.0", "week@1.0.0"]

    def test_a_pick_younger_than_the_cooldown_is_persisted_and_other_young_releases_are_not(self):
        published = released(("pick", "2.0.0", 3), ("other", "1.0.0", 3))

        cooldown = self.cooldown(published=published, picks={("pick", "2.0.0")})

        assert cooldown is not None
        assert cooldown.exclusions == ["pick@2.0.0"]

    def test_a_pick_older_than_the_cooldown_needs_no_entry(self):
        cooldown = self.cooldown(published=released(("pick", "2.0.0", 30)), picks={("pick", "2.0.0")})

        assert cooldown is not None
        assert cooldown.exclusions == []

    def test_a_release_without_a_publish_time_is_never_exempted(self):
        cooldown = self.cooldown(picks={("pick", "2.0.0")})

        assert cooldown is not None
        assert cooldown.exclusions == []
        assert "pnpm_config_minimum_release_age_exclude" not in cooldown.environ

    def test_the_projects_own_exclusions_are_kept_beside_ours(self):
        layers = [{"minimumReleaseAgeExclude": ["lodash", "@org/*"]}]

        cooldown = self.cooldown(layers, published=released(("young", "1.0.0", 3)))

        assert cooldown is not None
        exclude = json.loads(cooldown.environ["pnpm_config_minimum_release_age_exclude"])
        assert exclude == ["lodash", "@org/*", "young@1.0.0"]

    def test_a_strict_projects_own_rule_is_never_lifted(self):
        # Three days, strict: only the stretch between that and the cooldown is OSS IQ's to exempt.
        published = released(("young", "1.0.0", 1), ("middle", "1.0.0", 5), ("locked", "1.0.0", 1))

        cooldown = self.cooldown(
            [{"minimumReleaseAge": 4320}], published=published, picks={("young", "1.0.0"), ("middle", "1.0.0")}
        )

        assert cooldown is not None
        assert cooldown.exclusions == ["middle@1.0.0"]
        assert exclude_list(cooldown) == ["middle@1.0.0"]

    def test_a_strict_projects_own_exemptions_still_admit_a_release(self):
        layers = [{"minimumReleaseAge": 4320, "minimumReleaseAgeExclude": ["@org/*"]}]

        cooldown = self.cooldown(layers, published=released(("@org/lib", "1.0.0", 1)))

        assert cooldown is not None
        # The user's glob already covers it in the file, so only the run needs it spelled out.
        assert cooldown.exclusions == []
        assert exclude_list(cooldown) == ["@org/*", "@org/lib@1.0.0"]

    def test_an_override_is_exempted_even_from_a_strict_projects_own_rule(self):
        cooldown = self.cooldown(
            [{"minimumReleaseAge": 4320}], published=released(("forced", "1.0.0", 1)), forced={("forced", "1.0.0")}
        )

        assert cooldown is not None
        assert cooldown.exclusions == ["forced@1.0.0"]
        assert exclude_list(cooldown) == ["forced@1.0.0"]

    def test_without_a_cooldown_only_an_override_the_project_refuses_needs_anything(self):
        strict = [{"minimumReleaseAge": 4320}]
        young, old = released(("forced", "1.0.0", 1)), released(("forced", "1.0.0", 30))
        forced = {("forced", "1.0.0")}

        cooldown = self.cooldown(strict, days=0, published=young, forced=forced)

        assert cooldown is not None
        assert cooldown.environ is None
        assert cooldown.exclusions == ["forced@1.0.0"]
        assert self.cooldown(strict, days=0, published=old, forced=forced) is None
        assert self.cooldown([{}], days=0, published=young, forced=forced) is None

    def test_the_boundary_is_the_age_itself(self):
        published = {("edge", "1.0.0"): NOW - 7 * DAY, ("inside", "1.0.0"): NOW - 7 * DAY + timedelta(seconds=1)}

        cooldown = self.cooldown(published=published)

        assert cooldown is not None
        assert json.loads(cooldown.environ["pnpm_config_minimum_release_age_exclude"]) == ["inside@1.0.0"]
