"""Tests for sources/project_config.py: finding and reading a project's .ossiq.yaml."""

from datetime import date

import pytest

from ossiq.domain.exceptions import InvalidPolicyFile
from ossiq.domain.policy import Policy, PolicyException, PolicyRule
from ossiq.domain.provenance import SourceLevel, TrustTier
from ossiq.sources.project_config import (
    CONFIG_FILE_NAME,
    UpgradeConfig,
    find_project_config,
    load_project_policy,
    load_upgrade_config,
)

TODAY = date(2027, 1, 1)

FULL = """\
version: 1
policy:
  cooldown:
    days: 14
  build:
    minimum: provenance
    no-downgrade: true
  source:
    minimum: protected-history
  exceptions:
    - package: chokidar
      versions: ["4.0.3"]
      rules: [build]
      reason: Published from a laptop during the CI migration.
      expires: 2027-01-31
    - package: "@myorg/*"
      rules: [cooldown]
      reason: Our own packages.
    - package: legacy-package
      reason: Archived upstream.
"""


def write(tmp_path, text: str):
    path = tmp_path / CONFIG_FILE_NAME
    path.write_text(text, encoding="utf-8")
    return path


class TestLoadProjectPolicy:
    def test_the_full_example_becomes_a_policy(self, tmp_path):
        policy, warnings = load_project_policy(write(tmp_path, FULL), TODAY)

        assert warnings == []
        assert policy == Policy(
            no_downgrade=True,
            min_build=TrustTier.PROVENANCE,
            min_source=SourceLevel.PROTECTED_HISTORY,
            cooldown_days=14,
            exceptions=(
                PolicyException(
                    package="chokidar",
                    reason="Published from a laptop during the CI migration.",
                    versions=("4.0.3",),
                    rules=frozenset({PolicyRule.BUILD}),
                    expires=date(2027, 1, 31),
                ),
                PolicyException(package="@myorg/*", reason="Our own packages.", rules=frozenset({PolicyRule.COOLDOWN})),
                PolicyException(package="legacy-package", reason="Archived upstream."),
            ),
        )

    @pytest.mark.parametrize("text", ["version: 1\n", "version: 1\npolicy: {}\n"])
    def test_a_file_without_rules_asks_for_nothing(self, tmp_path, text):
        assert load_project_policy(write(tmp_path, text), TODAY) == (Policy(), [])

    def test_a_build_block_with_only_no_downgrade_leaves_the_floor_off(self, tmp_path):
        path = write(tmp_path, "version: 1\npolicy:\n  build:\n    no-downgrade: true\n")

        policy, _ = load_project_policy(path, TODAY)

        assert policy.no_downgrade and policy.min_build is TrustTier.NONE

    def test_an_exception_expires_after_its_last_day(self, tmp_path):
        path = write(tmp_path, FULL)

        on_the_day, _ = load_project_policy(path, date(2027, 1, 31))
        after, warnings = load_project_policy(path, date(2027, 2, 1))

        assert [e.package for e in on_the_day.exceptions] == ["chokidar", "@myorg/*", "legacy-package"]
        assert [e.package for e in after.exceptions] == ["@myorg/*", "legacy-package"]
        assert warnings == [
            "Policy exception for chokidar expired on 2027-01-31, so its rules apply again. "
            f"Renew or remove it in {CONFIG_FILE_NAME}."
        ]

    @pytest.mark.parametrize(
        ("text", "where"),
        [
            ("policy: {}\n", "version"),
            ("version: 2\n", "version"),
            ("version: 1\npolcy: {}\n", "polcy"),
            ("version: 1\npolicy:\n", "policy"),
            ("version: 1\npolicy:\n  build:\n    minimun: provenance\n", "minimun"),
            ("version: 1\npolicy:\n  build:\n    minimum: signed\n", "policy.build.minimum"),
            ("version: 1\npolicy:\n  cooldown:\n    days: -1\n", "policy.cooldown.days"),
            ("version: 1\npolicy:\n  cooldown:\n    days: true\n", "policy.cooldown.days"),
            ("version: 1\npolicy:\n  cooldown: {}\n", "days"),
            ("version: 1\npolicy:\n  source: {}\n", "minimum"),
            ("version: 1\npolicy:\n  exceptions:\n    - package: pkg\n", "policy.exceptions.0"),
            ("version: 1\npolicy:\n  exceptions:\n    - reason: why\n", "policy.exceptions.0"),
            (
                "version: 1\npolicy:\n  exceptions:\n    - {package: pkg, reason: why, rules: [bild]}\n",
                "policy.exceptions.0.rules.0",
            ),
            (
                "version: 1\npolicy:\n  exceptions:\n    - {package: pkg, reason: why, rules: []}\n",
                "policy.exceptions.0.rules",
            ),
            (
                "version: 1\npolicy:\n  exceptions:\n    - {package: pkg, reason: why, versions: [4.0]}\n",
                "policy.exceptions.0.versions.0",
            ),
            (
                "version: 1\npolicy:\n  exceptions:\n    - {package: pkg, reason: why, expires: soon}\n",
                "policy.exceptions.0.expires",
            ),
        ],
    )
    def test_a_file_that_breaks_the_schema_names_where(self, tmp_path, text, where):
        # A typo must stop the run: a mistyped key that was ignored would switch a rule off unseen.
        with pytest.raises(InvalidPolicyFile) as error:
            load_project_policy(write(tmp_path, text), TODAY)

        assert where in str(error.value)
        assert CONFIG_FILE_NAME in str(error.value)

    def test_every_problem_is_reported_at_once(self, tmp_path):
        text = "version: 1\npolicy:\n  build:\n    minimun: provenance\n  cooldown:\n    days: -1\n"

        with pytest.raises(InvalidPolicyFile) as error:
            load_project_policy(write(tmp_path, text), TODAY)

        assert "minimun" in str(error.value) and "policy.cooldown.days" in str(error.value)

    def test_a_newer_version_tells_the_user_to_upgrade(self, tmp_path):
        with pytest.raises(InvalidPolicyFile) as error:
            load_project_policy(write(tmp_path, "version: 2\n"), TODAY)

        assert error.value.hint is not None and "Upgrade OSS IQ" in error.value.hint

    @pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "", "version: [1\n"])
    def test_a_file_that_is_not_a_mapping_is_rejected(self, tmp_path, text):
        with pytest.raises(InvalidPolicyFile):
            load_project_policy(write(tmp_path, text), TODAY)

    def test_an_unreadable_file_is_rejected(self, tmp_path):
        with pytest.raises(InvalidPolicyFile):
            load_project_policy(tmp_path / "missing.yaml", TODAY)


class TestFindProjectConfig:
    def test_the_file_in_the_project_directory(self, tmp_path):
        path = write(tmp_path, "version: 1\n")

        assert find_project_config(tmp_path) == path.resolve()

    def test_a_monorepo_root_file_covers_a_package_below_it(self, tmp_path):
        (tmp_path / ".git").mkdir()
        path = write(tmp_path, "version: 1\n")
        package = tmp_path / "packages" / "web"
        package.mkdir(parents=True)

        assert find_project_config(package) == path.resolve()

    def test_the_nearest_file_wins(self, tmp_path):
        write(tmp_path, "version: 1\n")
        package = tmp_path / "web"
        package.mkdir()
        nearest = write(package, "version: 1\n")

        assert find_project_config(package) == nearest.resolve()

    def test_the_search_stops_at_the_repository_root(self, tmp_path):
        write(tmp_path, "version: 1\n")
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)

        assert find_project_config(repo) is None

    def test_no_file_means_no_policy(self, tmp_path):
        (tmp_path / ".git").mkdir()

        assert find_project_config(tmp_path) is None


class TestLoadUpgradeConfig:
    def test_reads_the_limit_and_the_test_command(self, tmp_path) -> None:
        (tmp_path / ".git").mkdir()
        write(tmp_path, 'version: 1\nupgrade:\n  limit: 3\n  test-command: "npm test"\n')

        config = load_upgrade_config(tmp_path)

        assert (config.limit, config.test_command) == (3, "npm test")

    def test_no_file_or_no_block_means_no_defaults(self, tmp_path) -> None:
        (tmp_path / ".git").mkdir()
        assert load_upgrade_config(tmp_path) == UpgradeConfig()

        write(tmp_path, "version: 1\n")
        assert load_upgrade_config(tmp_path) == UpgradeConfig()

    @pytest.mark.parametrize(
        "block",
        [
            "upgrade:\n  limit: 0\n",
            "upgrade:\n  limit: many\n",
            'upgrade:\n  test-command: ""\n',
            "upgrade:\n  retries: 2\n",
        ],
    )
    def test_a_block_that_breaks_the_schema_is_refused(self, tmp_path, block: str) -> None:
        (tmp_path / ".git").mkdir()
        write(tmp_path, f"version: 1\n{block}")

        with pytest.raises(InvalidPolicyFile):
            load_upgrade_config(tmp_path)

    def test_the_policy_block_still_loads_beside_it(self, tmp_path) -> None:
        path = write(tmp_path, "version: 1\nupgrade:\n  limit: 2\npolicy:\n  cooldown:\n    days: 5\n")

        policy, _ = load_project_policy(path, date(2026, 11, 7))

        assert policy.cooldown_days == 5
