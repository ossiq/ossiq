"""Tests for service/completeness.py — the one case where silence is a wrong answer."""

from __future__ import annotations

import pytest

from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.domain.exceptions import SecurityDataIncomplete
from ossiq.service.completeness import check_security_data_complete, security_data_degraded
from ossiq.strategy.pyramid import UpdateStrategy

UNREACHABLE_OSV = DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})


def check(completeness: DataCompleteness, strategy: UpdateStrategy, allow_partial: bool = False) -> None:
    check_security_data_complete(completeness, strategy, allow_partial=allow_partial)


class TestCheckSecurityDataComplete:
    @pytest.mark.parametrize("strategy", [UpdateStrategy.SECURITY, UpdateStrategy.DEPRECATION])
    @pytest.mark.parametrize(
        "status", [DataSourceStatus.UNREACHABLE, DataSourceStatus.RATE_LIMITED, DataSourceStatus.PARTIAL]
    )
    def test_minimal_diff_tiers_refuse_every_degraded_status(
        self, strategy: UpdateStrategy, status: DataSourceStatus
    ) -> None:
        with pytest.raises(SecurityDataIncomplete):
            check(DataCompleteness(by_step={ScanStep.VULNERABILITIES: status}), strategy)

    @pytest.mark.parametrize("strategy", [UpdateStrategy.STANDARD, UpdateStrategy.LATEST, UpdateStrategy.CUTTING_EDGE])
    def test_freshness_tiers_answer_anyway(self, strategy: UpdateStrategy) -> None:
        """Drift alone justifies a move above the minimal-diff tiers, so the result is thinner
        rather than empty — and `ossiq status` is deliberately not a CI gate."""
        check(UNREACHABLE_OSV, strategy)

    def test_allow_partial_opts_back_in(self) -> None:
        check(UNREACHABLE_OSV, UpdateStrategy.SECURITY, allow_partial=True)

    def test_a_degraded_epss_step_also_counts(self) -> None:
        """Unscored CVEs read as exploitable, so a degraded EPSS run changes which packages move."""
        with pytest.raises(SecurityDataIncomplete):
            check(DataCompleteness(by_step={ScanStep.EPSS: DataSourceStatus.RATE_LIMITED}), UpdateStrategy.SECURITY)

    def test_a_degraded_repositories_step_does_not(self) -> None:
        """GitHub feeds end_of_life, which thins deprecation's coverage rather than emptying its
        result the way a missing CVE feed does."""
        check(
            DataCompleteness(by_step={ScanStep.REPOSITORIES: DataSourceStatus.UNREACHABLE}),
            UpdateStrategy.DEPRECATION,
        )

    def test_a_clean_scan_passes(self) -> None:
        check(DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.OK}), UpdateStrategy.SECURITY)

    def test_an_untracked_scan_passes(self) -> None:
        """Most steps report no status at all; absence here is the common case, not a failure."""
        check(DataCompleteness(), UpdateStrategy.SECURITY)

    def test_the_message_names_the_step_and_what_it_did(self) -> None:
        with pytest.raises(SecurityDataIncomplete) as excinfo:
            check(UNREACHABLE_OSV, UpdateStrategy.SECURITY)

        assert "vulnerabilities unreachable" in str(excinfo.value)
        assert "--allow-partial" in (excinfo.value.hint or "")


class TestSecurityDataDegraded:
    def test_reports_only_the_security_relevant_steps(self) -> None:
        completeness = DataCompleteness(
            by_step={
                ScanStep.REPOSITORIES: DataSourceStatus.UNREACHABLE,
                ScanStep.VULNERABILITIES: DataSourceStatus.PARTIAL,
                ScanStep.EPSS: DataSourceStatus.OK,
            }
        )

        assert security_data_degraded(completeness) == {ScanStep.VULNERABILITIES: DataSourceStatus.PARTIAL}
