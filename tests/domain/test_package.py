"""Tests for the registry's verdict on a package, as `Package` and `RegistryStatus` model it."""

import pytest

from ossiq.domain.common import END_OF_LIFE_STATUSES, INACTIVE_STATUSES, ProjectPackagesRegistry, RegistryStatus
from ossiq.domain.package import Package


def package(status: RegistryStatus | None) -> Package:
    return Package(
        registry=ProjectPackagesRegistry.NPM,
        name="demo",
        latest_version="1.0.0",
        next_version=None,
        repo_url=None,
        registry_status=status,
    )


class TestIsDeprecated:
    @pytest.mark.parametrize("status", [RegistryStatus.DEPRECATED, RegistryStatus.ARCHIVED])
    def test_a_package_its_maintainers_retired_is_deprecated(self, status: RegistryStatus) -> None:
        assert package(status).is_deprecated is True

    @pytest.mark.parametrize("status", [RegistryStatus.ACTIVE, None])
    def test_an_active_or_unjudged_package_is_not(self, status: RegistryStatus | None) -> None:
        assert package(status).is_deprecated is False

    def test_quarantine_is_an_administrators_verdict_not_a_deprecation(self) -> None:
        # Counting it as deprecated would drive the maintenance model and end-of-life bumps for
        # what the registry says is unsafe to use at all.
        assert package(RegistryStatus.QUARANTINED).is_deprecated is False

    def test_is_derived_so_it_cannot_be_set_apart_from_the_status(self) -> None:
        with pytest.raises(AttributeError):
            package(RegistryStatus.ACTIVE).is_deprecated = True  # type: ignore[misc]  # ty: ignore[invalid-assignment]


class TestStatusSets:
    def test_end_of_life_is_what_the_maintainers_decided(self) -> None:
        assert END_OF_LIFE_STATUSES == {RegistryStatus.DEPRECATED, RegistryStatus.ARCHIVED}

    def test_inactive_adds_the_registrys_own_safety_verdict(self) -> None:
        assert INACTIVE_STATUSES == END_OF_LIFE_STATUSES | {RegistryStatus.QUARANTINED}

    def test_active_is_in_neither(self) -> None:
        assert RegistryStatus.ACTIVE not in INACTIVE_STATUSES

    def test_values_are_pep_792s_vocabulary(self) -> None:
        assert {status.value for status in RegistryStatus} == {"active", "deprecated", "archived", "quarantined"}
