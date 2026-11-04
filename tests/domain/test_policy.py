"""Tests for the policy value types: what a waiver covers and which rules are on."""

import pytest

from ossiq.domain.policy import Policy, PolicyException, PolicyRule
from ossiq.domain.provenance import SourceLevel, TrustTier


def waiver(package: str, *versions: str, rules: frozenset[PolicyRule] = frozenset(PolicyRule)) -> PolicyException:
    return PolicyException(package=package, reason="test", versions=versions, rules=rules)


class TestPolicyException:
    def test_a_bare_name_covers_every_release(self):
        assert waiver("chokidar").covers(PolicyRule.BUILD, "chokidar", "4.0.3")

    def test_listed_versions_cover_those_releases_only(self):
        entry = waiver("chokidar", "4.0.3", "4.0.4")

        assert entry.covers(PolicyRule.BUILD, "chokidar", "4.0.4")
        assert not entry.covers(PolicyRule.BUILD, "chokidar", "4.0.5")

    def test_a_glob_covers_a_scope(self):
        entry = waiver("@myorg/*")

        assert entry.covers(PolicyRule.COOLDOWN, "@myorg/core", "1.0.0")
        assert not entry.covers(PolicyRule.COOLDOWN, "@other/core", "1.0.0")

    def test_a_scoped_name_is_not_matched_by_its_scope_alone(self):
        assert not waiver("@types/node").covers(PolicyRule.BUILD, "@types", "18.0.0")

    def test_every_rule_is_lifted_unless_the_waiver_names_some(self):
        assert all(waiver("pkg").covers(rule, "pkg", "1.0.0") for rule in PolicyRule)

    def test_a_waiver_lifts_only_the_rules_it_names(self):
        entry = waiver("pkg", rules=frozenset({PolicyRule.COOLDOWN}))

        assert entry.covers(PolicyRule.COOLDOWN, "pkg", "1.0.0")
        assert not entry.covers(PolicyRule.SOURCE, "pkg", "1.0.0")

    def test_a_name_is_matched_case_sensitively(self):
        assert not waiver("Pkg").covers(PolicyRule.BUILD, "pkg", "1.0.0")


class TestPolicy:
    def test_every_rule_is_off_by_default(self):
        policy = Policy()

        assert not policy.is_active
        assert policy.cooldown_days is None

    def test_a_min_build_of_none_asks_for_nothing(self):
        assert not Policy(min_build=TrustTier.NONE).is_active

    def test_build_rules_alone_gate_every_package_but_source_rules_do_not(self):
        assert Policy(no_downgrade=True).gates_builds
        assert Policy(min_build=TrustTier.PROVENANCE).gates_builds
        assert not Policy(min_source=SourceLevel.REVIEWED).gates_builds

    def test_a_source_rule_makes_the_policy_active(self):
        assert Policy(min_source=SourceLevel.REVIEWED).is_active

    @pytest.mark.parametrize(
        ("rule", "waived"),
        [(PolicyRule.BUILD, True), (PolicyRule.SOURCE, False)],
    )
    def test_waives_asks_every_exception(self, rule, waived):
        policy = Policy(
            exceptions=(waiver("other"), waiver("pkg", "1.0.0", rules=frozenset({PolicyRule.BUILD}))),
        )

        assert policy.waives(rule, "pkg", "1.0.0") is waived

    def test_no_exceptions_waive_nothing(self):
        assert not Policy().waives(PolicyRule.BUILD, "pkg", "1.0.0")
