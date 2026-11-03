"""Tests for service/project/provenance.py — the wiring between the policy and a scan."""

from unittest.mock import MagicMock

import pytest

from ossiq.domain.common import ConstraintType, ProjectPackagesRegistry
from ossiq.domain.exceptions import UnknownPackageVersion
from ossiq.domain.project import ConstraintSource
from ossiq.domain.provenance import ProvenancePolicy, SourceLevel, TrustTier
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.provenance import (
    canonical_exclude,
    compute_version_blocks,
    populate_provenance,
    registry_policy,
)
from ossiq.settings import Settings

NONE, PROV, TRUSTED = TrustTier.NONE, TrustTier.PROVENANCE, TrustTier.TRUSTED_PUBLISHER
NO_DOWNGRADE = ProvenancePolicy(no_downgrade=True)


def release(version: str, tier: TrustTier | None, published: str) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url="",
        declared_dependencies={},
        published_date_iso=f"{published}T00:00:00Z",
        trust_tier=tier,
    )


def registry_with(
    versions_by_name: dict[str, list[PackageVersion]], kind: ProjectPackagesRegistry = ProjectPackagesRegistry.NPM
) -> MagicMock:
    registry = MagicMock()
    registry.package_registry = kind

    def package_versions(name: str) -> list[PackageVersion]:
        if name not in versions_by_name:
            raise UnknownPackageVersion(name)
        return versions_by_name[name]

    registry.package_versions.side_effect = package_versions
    return registry


def record(name: str, installed: str) -> ScanRecord:
    return ScanRecord(
        package_name=name,
        dependency_name=name,
        is_optional_dependency=False,
        installed_version=installed,
        latest_version=None,
        versions_diff_index=VersionsDifference("1.0.0", "1.0.0", 0, diff_name="LATEST"),
        time_lag_days=None,
        releases_lag=0,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        version_constraint=None,
    )


DIPPED = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", NONE, "2024-02-01")]


class TestCanonicalExclude:
    @pytest.mark.parametrize(
        ("entry", "expected"),
        [
            ("Typing_Extensions", "typing-extensions"),
            ("Typing_Extensions@4.0.0", "typing-extensions@4.0.0"),
            ("zope.interface@5.0", "zope-interface@5.0"),
        ],
    )
    def test_spells_the_name_as_pypi_normalizes_it(self, entry, expected):
        assert canonical_exclude(entry) == expected


class TestRegistryPolicy:
    def test_pypi_exclude_entries_are_normalized(self, monkeypatch):
        monkeypatch.setenv("OSSIQ_POLICY_EXCLUDE", "Typing_Extensions@4.0.0,Flask")

        policy = registry_policy(Settings(), ProjectPackagesRegistry.PYPI)

        assert policy.exclude == ("typing-extensions@4.0.0", "flask")

    def test_npm_exclude_entries_are_matched_as_written(self, monkeypatch):
        monkeypatch.setenv("OSSIQ_POLICY_EXCLUDE", "@Scope/Pkg_x@1.0.0")

        assert registry_policy(Settings(), ProjectPackagesRegistry.NPM).exclude == ("@Scope/Pkg_x@1.0.0",)

    def test_the_other_rules_pass_through(self, monkeypatch):
        monkeypatch.setenv("OSSIQ_POLICY_TRUST", "no-downgrade")
        monkeypatch.setenv("OSSIQ_POLICY_MIN_BUILD", "provenance")

        policy = registry_policy(Settings(), ProjectPackagesRegistry.PYPI)

        assert (policy.no_downgrade, policy.min_build) == (True, PROV)


class TestComputeVersionBlocks:
    def test_without_a_build_rule_the_registry_is_not_read(self):
        registry = registry_with({"pkg": DIPPED})

        blocks = compute_version_blocks(["pkg"], registry, ProvenancePolicy())

        assert blocks == {}
        registry.package_versions.assert_not_called()

    def test_a_source_only_policy_does_not_read_release_history_without_a_measured_repository(self):
        registry = registry_with({"pkg": DIPPED})
        policy = ProvenancePolicy(min_source=SourceLevel.REVIEWED)

        assert compute_version_blocks(["pkg"], registry, policy) == {}
        registry.package_versions.assert_not_called()

    def test_lists_only_the_violating_releases_of_each_package(self):
        registry = registry_with({"dipped": DIPPED, "steady": [release("1.0.0", PROV, "2024-01-01")]})

        blocks = compute_version_blocks(["dipped", "steady"], registry, NO_DOWNGRADE)

        assert set(blocks) == {"dipped"}
        assert set(blocks["dipped"]) == {"1.0.1"}
        assert "trust downgrade" in blocks["dipped"]["1.0.1"][0]

    def test_a_package_the_registry_does_not_know_is_skipped(self):
        registry = registry_with({"dipped": DIPPED})

        assert set(compute_version_blocks(["dipped", "ghost"], registry, NO_DOWNGRADE)) == {"dipped"}

    def test_a_name_listed_twice_is_judged_once(self):
        registry = registry_with({"dipped": DIPPED})

        compute_version_blocks(["dipped", "dipped"], registry, NO_DOWNGRADE)

        assert registry.package_versions.call_count == 1

    def test_an_excluded_release_is_left_out(self):
        registry = registry_with({"dipped": DIPPED})

        policy = ProvenancePolicy(no_downgrade=True, exclude=("dipped@1.0.1",))

        assert compute_version_blocks(["dipped"], registry, policy) == {}

    def test_major_lines_follow_the_registrys_own_versioning(self):
        # 2.0.0 opens a new line, so it is not a downgrade from 1.x on npm.
        registry = registry_with(
            {"pkg": [release("1.0.0", TRUSTED, "2024-01-01"), release("2.0.0", NONE, "2024-02-01")]}
        )

        assert compute_version_blocks(["pkg"], registry, NO_DOWNGRADE) == {}


class TestPopulateProvenance:
    def versions_since(self, name="pkg", installed="1.0.0", releases=None):
        return {(name, installed): releases if releases is not None else DIPPED}

    def test_records_the_installed_releases_tier(self):
        rec = record("pkg", "1.0.0")

        populate_provenance([rec], self.versions_since(), {})

        assert rec.provenance is not None and rec.provenance.build_tier == TRUSTED

    def test_an_installed_release_that_breaks_the_policy_carries_the_reasons(self):
        rec = record("pkg", "1.0.1")
        blocks = {"pkg": {"1.0.1": ("trust downgrade: no provenance",)}}

        populate_provenance([rec], self.versions_since(installed="1.0.1"), blocks)

        assert rec.provenance is not None
        assert rec.provenance.violations == ("trust downgrade: no provenance",)
        assert rec.provenance.build_tier == NONE

    def test_a_clean_installed_release_has_no_violations(self):
        rec = record("pkg", "1.0.0")

        populate_provenance([rec], self.versions_since(), {"pkg": {"1.0.1": ("x",)}})

        assert rec.provenance is not None and rec.provenance.violations == ()

    def test_an_installed_release_the_registry_did_not_list_has_an_unknown_tier(self):
        rec = record("pkg", "9.9.9")

        populate_provenance([rec], self.versions_since(installed="9.9.9"), {})

        assert rec.provenance is not None and rec.provenance.build_tier is None

    def test_an_unreadable_tier_stays_unknown_rather_than_none(self):
        rec = record("pkg", "1.0.0")

        populate_provenance([rec], self.versions_since(releases=[release("1.0.0", None, "2024-01-01")]), {})

        assert rec.provenance is not None and rec.provenance.build_tier is None

    def test_every_record_is_written_even_without_a_policy(self):
        records = [record("a", "1.0.0"), record("b", "1.0.0")]
        since = {("a", "1.0.0"): DIPPED, ("b", "1.0.0"): DIPPED}

        populate_provenance(records, since, {})

        assert all(r.provenance is not None for r in records)


class TestSourceLevelBlocks:
    """A repository below the source floor rules out every release of its package."""

    FLOOR = ProvenancePolicy(min_source=SourceLevel.PROTECTED_HISTORY)
    CLEAN = [release("1.0.0", TRUSTED, "2024-01-01"), release("1.0.1", TRUSTED, "2024-02-01")]

    def test_every_release_is_ruled_out_including_the_installed_one(self):
        registry = registry_with({"pkg": self.CLEAN})

        blocks = compute_version_blocks(["pkg"], registry, self.FLOOR, {"pkg": SourceLevel.VERSION_CONTROLLED})

        assert set(blocks["pkg"]) == {"1.0.0", "1.0.1"}
        assert "below the required protected-history" in blocks["pkg"]["1.0.1"][0]

    def test_a_repository_that_meets_the_floor_blocks_nothing(self):
        registry = registry_with({"pkg": self.CLEAN})

        assert compute_version_blocks(["pkg"], registry, self.FLOOR, {"pkg": SourceLevel.REVIEWED}) == {}

    def test_an_unmeasured_package_is_never_read(self):
        registry = registry_with({"pkg": self.CLEAN})

        assert compute_version_blocks(["pkg"], registry, self.FLOOR, {}) == {}
        registry.package_versions.assert_not_called()

    def test_a_source_policy_does_not_read_history_of_packages_that_pass(self):
        registry = registry_with({"ok": self.CLEAN, "weak": self.CLEAN})
        levels = {"ok": SourceLevel.REVIEWED, "weak": SourceLevel.VERSION_CONTROLLED}

        compute_version_blocks(["ok", "weak"], registry, self.FLOOR, levels)

        assert [c.args[0] for c in registry.package_versions.call_args_list] == ["weak"]

    def test_an_excluded_release_is_left_out(self):
        registry = registry_with({"pkg": self.CLEAN})
        policy = ProvenancePolicy(min_source=SourceLevel.PROTECTED_HISTORY, exclude=("pkg@1.0.0",))

        blocks = compute_version_blocks(["pkg"], registry, policy, {"pkg": SourceLevel.VERSION_CONTROLLED})

        assert set(blocks["pkg"]) == {"1.0.1"}

    def test_the_reasons_of_both_kinds_of_rule_are_kept(self):
        registry = registry_with({"pkg": DIPPED})
        policy = ProvenancePolicy(no_downgrade=True, min_source=SourceLevel.PROTECTED_HISTORY)

        blocks = compute_version_blocks(["pkg"], registry, policy, {"pkg": SourceLevel.VERSION_CONTROLLED})

        assert len(blocks["pkg"]["1.0.1"]) == 2
        assert len(blocks["pkg"]["1.0.0"]) == 1

    def test_the_installed_packages_level_is_recorded_on_its_record(self):
        rec = record("pkg", "1.0.0")

        populate_provenance([rec], {("pkg", "1.0.0"): self.CLEAN}, {}, {"pkg": SourceLevel.REVIEWED})

        assert rec.provenance is not None and rec.provenance.source_level == SourceLevel.REVIEWED

    def test_a_package_that_was_not_measured_has_no_level(self):
        rec = record("pkg", "1.0.0")

        populate_provenance([rec], {("pkg", "1.0.0"): self.CLEAN}, {}, {"other": SourceLevel.REVIEWED})

        assert rec.provenance is not None and rec.provenance.source_level is None
