"""Tests for the shared next-action ladder (service.project.next_action)."""

import pytest

from ossiq.domain.common import (
    ConstraintType,
    CooldownHold,
    CveDatabase,
    ProjectPackagesRegistry,
    RecommendationRung,
    RegistryStatus,
    RejectedCandidate,
)
from ossiq.domain.cve import CVE, Severity
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import VERSION_DIFF_MAJOR, VERSION_DIFF_MINOR, VERSION_LATEST, VersionsDifference
from ossiq.risk.maintenance import MaintenanceAssessment, MaintenanceState
from ossiq.service.project.models import ScanRecord
from ossiq.service.project.next_action import (
    CHECK_FOR_THE_FIX,
    CHECK_RELEASE_NOTES,
    CONSIDER_ALTERNATIVE,
    CONSTRAINED_CHECK_NEWER,
    FIND_ALTERNATIVE,
    NEXT_ACTION_PRIORITY,
    UPDATE_IMMEDIATELY,
    WAIT_FOR_COOLDOWN,
    WITHHELD_BY_STRATEGY,
    needs_attention,
    next_action_label,
)
from ossiq.strategy.pyramid import UpdateStrategy
from ossiq.strategy.targeting import StrategySelection

MINOR = VersionsDifference("1.0.0", "1.1.0", VERSION_DIFF_MINOR, "DIFF_MINOR")
MAJOR = VersionsDifference("1.0.0", "2.0.0", VERSION_DIFF_MAJOR, "DIFF_MAJOR")
LATEST = VersionsDifference("1.0.0", "1.0.0", VERSION_LATEST, "LATEST")


def assessment(state: MaintenanceState) -> MaintenanceAssessment:
    not_maintained = state in (MaintenanceState.ABANDONED, MaintenanceState.DEPRECATED)
    return MaintenanceAssessment(
        posterior={s.value: 0.0 for s in MaintenanceState},
        state=state.value,
        p_not_maintained=1.0 if not_maintained else 0.0,
        observations={},
    )


def fake_cve(epss: float | None = None) -> CVE:
    return CVE(
        id="CVE-2024-0001",
        cve_ids=("CVE-2024-0001",),
        source=CveDatabase.OSV,
        package_name="demo",
        package_registry=ProjectPackagesRegistry.NPM,
        summary="",
        severity=Severity.HIGH,
        affected_versions=("1.0.0",),
        published=None,
        link="",
        epss=epss,
    )


def make_record(
    *,
    versions_diff_index: VersionsDifference = LATEST,
    cve: list[CVE] | None = None,
    epss: float | None = None,
    maintenance: MaintenanceAssessment | None = None,
    recommended_version: str | None = None,
    version_constraint: str | None = None,
) -> ScanRecord:
    return ScanRecord(
        package_name="demo",
        dependency_name=None,
        is_optional_dependency=False,
        installed_version="1.0.0",
        latest_version="1.0.0",
        versions_diff_index=versions_diff_index,
        time_lag_days=None,
        releases_lag=None,
        cve=cve or [],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file=None),
        epss=epss,
        maintenance=maintenance,
        recommended_version=recommended_version,
        version_constraint=version_constraint,
    )


def test_active_cve_outranks_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(0.2)], epss=0.2)
    assert next_action_label(record) == CHECK_FOR_THE_FIX


def test_low_epss_cve_falls_through_to_drift():
    record = make_record(versions_diff_index=MINOR, cve=[fake_cve(0.05)], epss=0.05)
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_abandoned_at_latest_is_find_alternative():
    assert next_action_label(make_record(maintenance=assessment(MaintenanceState.ABANDONED))) == FIND_ALTERNATIVE


def test_winding_down_is_consider_alternative():
    record = make_record(versions_diff_index=MINOR, maintenance=assessment(MaintenanceState.WINDING_DOWN))
    assert next_action_label(record) == CONSIDER_ALTERNATIVE


def test_major_drift_is_check_release_notes():
    assert next_action_label(make_record(versions_diff_index=MAJOR)) == CHECK_RELEASE_NOTES


def test_clean_current_package_has_no_action():
    assert next_action_label(make_record(maintenance=assessment(MaintenanceState.MAINTAINED))) is None


# --- drift the declared range will not let you act on -----------------------------------------


def test_in_range_bump_available_is_update_immediately():
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.7", version_constraint="~1.0.0")
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_recommendation_pinned_to_installed_is_constrained():
    """`~1.0.0` with nothing newer inside it: "Update Immediately" would name no target."""
    record = make_record(versions_diff_index=MINOR, recommended_version="1.0.0", version_constraint="~1.0.0")
    assert next_action_label(record) == CONSTRAINED_CHECK_NEWER


def test_no_recommendation_under_a_constraint_is_constrained():
    record = make_record(versions_diff_index=MINOR, recommended_version=None, version_constraint="~1.0.0")
    assert next_action_label(record) == CONSTRAINED_CHECK_NEWER


def test_no_recommendation_and_no_constraint_stays_update_immediately():
    """Nothing is holding it back — the solver simply had no opinion."""
    record = make_record(versions_diff_index=MINOR, recommended_version=None, version_constraint=None)
    assert next_action_label(record) == UPDATE_IMMEDIATELY


def test_major_drift_under_a_constraint_still_reads_release_notes():
    record = make_record(versions_diff_index=MAJOR, recommended_version="1.0.0", version_constraint="~1.0.0")
    assert next_action_label(record) == CHECK_RELEASE_NOTES


def test_active_cve_outranks_a_constrained_package():
    record = make_record(
        versions_diff_index=MINOR,
        cve=[fake_cve(0.2)],
        epss=0.2,
        recommended_version="1.0.0",
        version_constraint="~1.0.0",
    )
    assert next_action_label(record) == CHECK_FOR_THE_FIX


class TestWithheldByStrategy:
    """A tier refusing to move a package is not the declared range capping it.

    scikit-learn 1.8.0 declared `<2.0.0` under --update-strategy security has no writable target,
    and used to report `Constrained. Check newer version` with a sub-row blaming `<2.0.0` — which
    admits 1.9.1 perfectly well. select_target sets withheld_reason on exactly the no-admitted-
    motive branch, and leaves it None when the tier admitted a motive but nothing was reachable.
    """

    def withheld_record(self, withheld_reason: str | None) -> ScanRecord:
        record = make_record(versions_diff_index=MINOR, version_constraint="<2.0.0")
        record.strategy_selection = StrategySelection(
            strategy=UpdateStrategy.SECURITY,
            target_version=None,
            rung=None,
            motives=frozenset(),
            requires_widening=False,
            withheld_reason=withheld_reason,
            available_at=UpdateStrategy.STANDARD if withheld_reason else None,
            escalation=None,
        )
        return record

    def test_tier_withholding_is_its_own_label(self):
        record = self.withheld_record("no motive admitted at security; available under --update-strategy standard")
        assert next_action_label(record) == WITHHELD_BY_STRATEGY

    def test_admitted_motive_with_nothing_reachable_stays_constrained(self):
        assert next_action_label(self.withheld_record(None)) == CONSTRAINED_CHECK_NEWER

    def test_no_strategy_selection_stays_constrained(self):
        """Transitive and ignored records never get a selection — they must not change label."""
        record = make_record(versions_diff_index=MINOR, version_constraint="<2.0.0")
        assert record.strategy_selection is None
        assert next_action_label(record) == CONSTRAINED_CHECK_NEWER

    def test_a_writable_target_outranks_withholding(self):
        """A withheld_reason cannot coexist with a target, but the ladder order must still hold."""
        record = self.withheld_record("no motive admitted at security; available under --update-strategy standard")
        record.recommended_version = "1.1.0"
        assert next_action_label(record) == UPDATE_IMMEDIATELY

    def test_active_cve_outranks_withholding(self):
        record = self.withheld_record("no motive admitted at security; available under --update-strategy standard")
        record.cve = [fake_cve(0.2)]
        record.epss = 0.2
        assert next_action_label(record) == CHECK_FOR_THE_FIX


# --- drift the cooldown will not let you act on yet --------------------------------------------


class TestCooldownHold:
    """A bump the user cannot take yet must not be labelled as one they can.

    That mismatch is the reported defect: `status` said "Update Immediately" for a 5-day-old
    release while `apply` refused it as younger than the 7-day cooldown.
    """

    @staticmethod
    def held_record(
        versions_diff_index: VersionsDifference = MINOR,
        cve: list[CVE] | None = None,
        epss: float | None = None,
    ) -> ScanRecord:
        record = make_record(versions_diff_index=versions_diff_index, cve=cve, epss=epss)
        record.strategy_selection = StrategySelection(
            strategy=UpdateStrategy.STANDARD,
            target_version=None,
            rung=None,
            motives=frozenset(),
            requires_widening=False,
            withheld_reason=None,
            available_at=None,
            escalation=None,
            cooldown_hold=CooldownHold(version="0.10.0", age_days=5, cooldown_period=7),
        )
        return record

    def test_cooldown_hold_is_its_own_label(self):
        assert next_action_label(self.held_record()) == WAIT_FOR_COOLDOWN

    def test_cooldown_hold_outranks_major_drift(self):
        # A major bump the cooldown is holding is still not something to go read release notes
        # about yet — there is nothing to move to.
        assert next_action_label(self.held_record(versions_diff_index=MAJOR)) == WAIT_FOR_COOLDOWN

    def test_an_active_cve_outranks_the_cooldown_hold(self):
        # Belt and braces: select_target escalates past the cooldown for an exploitable CVE rather
        # than setting a hold, so this combination should not arise — but if it does, the CVE wins.
        record = self.held_record(cve=[fake_cve(0.2)], epss=0.2)
        assert next_action_label(record) == CHECK_FOR_THE_FIX

    def test_no_hold_falls_through_to_the_drift_ladder(self):
        record = make_record(versions_diff_index=MINOR, recommended_version="1.1.0")
        assert next_action_label(record) == UPDATE_IMMEDIATELY

    def test_label_is_ranked_below_update_immediately(self):
        order = list(NEXT_ACTION_PRIORITY)
        assert order.index(UPDATE_IMMEDIATELY) < order.index(WAIT_FOR_COOLDOWN)
        assert order.index(WAIT_FOR_COOLDOWN) < order.index(CONSTRAINED_CHECK_NEWER)


class TestNeedsAttention:
    """Which transitives the standard export keeps (D3)."""

    def test_plain_drift_is_not_news(self):
        assert needs_attention(make_record(versions_diff_index=MAJOR)) is False

    def test_a_drift_only_recommendation_is_not_news_either(self):
        assert needs_attention(make_record(versions_diff_index=MAJOR, recommended_version="2.0.0")) is False

    def test_a_cve_is(self):
        assert needs_attention(make_record(cve=[fake_cve(0.0001)])) is True

    def test_a_rejected_candidate_is(self):
        record = make_record(recommended_version="1.1.0")
        record.rejected_candidates = [RejectedCandidate(version="2.0.0", reason="conflicts with a parent")]
        assert needs_attention(record) is True

    def test_a_constraint_conflict_is(self):
        record = make_record()
        record.constraint_conflict = ["peer requires <1.0.0"]
        assert needs_attention(record) is True

    def test_a_release_going_away_is(self):
        for flag in ("is_installed_deprecated", "is_installed_yanked", "is_installed_package_unpublished"):
            record = make_record()
            setattr(record, flag, True)
            assert needs_attention(record) is True, flag

    def test_an_unmaintained_upstream_is_but_a_winding_down_one_is_not(self):
        assert needs_attention(make_record(maintenance=assessment(MaintenanceState.ABANDONED))) is True
        assert needs_attention(make_record(maintenance=assessment(MaintenanceState.DEPRECATED))) is True
        assert needs_attention(make_record(maintenance=assessment(MaintenanceState.WINDING_DOWN))) is False


class TestRetiredByTheRegistry:
    """The registry itself retired the package: no bump inside it helps, so the label is to leave."""

    @staticmethod
    def retired(status: RegistryStatus | None, diff: VersionsDifference, **kwargs) -> ScanRecord:
        record = make_record(versions_diff_index=diff, **kwargs)
        record.registry_status = status
        return record

    @pytest.mark.parametrize("status", [RegistryStatus.DEPRECATED, RegistryStatus.ARCHIVED, RegistryStatus.QUARANTINED])
    @pytest.mark.parametrize("diff", [LATEST, MINOR, MAJOR])
    def test_is_find_alternative_whatever_the_drift(self, status: RegistryStatus, diff: VersionsDifference):
        # MINOR with a recommendation would otherwise read "Update Immediately", MAJOR "Check Release Notes".
        record = self.retired(status, diff, recommended_version="1.1.0")

        assert next_action_label(record) == FIND_ALTERNATIVE

    def test_an_exploitable_cve_still_comes_first(self):
        record = self.retired(RegistryStatus.DEPRECATED, MINOR, cve=[fake_cve(0.2)], epss=0.2)

        assert next_action_label(record) == CHECK_FOR_THE_FIX

    @pytest.mark.parametrize("status", [RegistryStatus.ACTIVE, None])
    def test_an_active_or_unjudged_package_keeps_the_drift_ladder(self, status: RegistryStatus | None):
        # A deprecated *release* of a live package (uuid@3) is the opposite case: updating is the fix.
        record = self.retired(status, MINOR, recommended_version="1.1.0")
        record.is_installed_deprecated = True

        assert next_action_label(record) == UPDATE_IMMEDIATELY

    @pytest.mark.parametrize("status", [RegistryStatus.DEPRECATED, RegistryStatus.ARCHIVED, RegistryStatus.QUARANTINED])
    def test_a_retired_transitive_needs_attention(self, status: RegistryStatus):
        assert needs_attention(self.retired(status, LATEST)) is True

    @pytest.mark.parametrize("status", [RegistryStatus.ACTIVE, None])
    def test_a_live_transitive_does_not(self, status: RegistryStatus | None):
        assert needs_attention(self.retired(status, LATEST)) is False


class TestWideningPick:
    """A pick past the declared range reads "Update Immediately" exactly when `plan` writes it.

    service.update.is_held_for_widening lets such a pick through when an escalating motive carried
    it past the tier or the tier reaches that far on its own; every other one waits for a human to
    widen the range, and that is what "Constrained" says.
    """

    def widening_record(
        self,
        strategy: UpdateStrategy | None,
        *,
        authorized: bool = False,
        versions_diff_index: VersionsDifference = MINOR,
        recommended_version: str = "1.1.0",
    ) -> ScanRecord:
        record = make_record(
            versions_diff_index=versions_diff_index,
            recommended_version=recommended_version,
            version_constraint="1.0.0",
        )
        record.recommended_from_rung = RecommendationRung.LATEST
        if strategy is not None:
            record.strategy_selection = StrategySelection(
                strategy=strategy,
                target_version=recommended_version,
                rung=RecommendationRung.LATEST,
                motives=frozenset(),
                requires_widening=True,
                withheld_reason=None,
                available_at=None,
                escalation=None,
                widening_authorized=authorized,
            )
        return record

    def test_an_escalated_pick_is_an_update(self):
        record = self.widening_record(UpdateStrategy.SECURITY, authorized=True)
        assert next_action_label(record) == UPDATE_IMMEDIATELY

    @pytest.mark.parametrize("strategy", [UpdateStrategy.SECURITY, UpdateStrategy.DEPRECATION, UpdateStrategy.STANDARD])
    def test_an_unauthorized_pick_under_a_tier_that_cannot_reach_it_stays_constrained(self, strategy):
        assert next_action_label(self.widening_record(strategy)) == CONSTRAINED_CHECK_NEWER

    @pytest.mark.parametrize("strategy", [UpdateStrategy.LATEST, UpdateStrategy.CUTTING_EDGE])
    def test_a_tier_that_reaches_the_rung_writes_it(self, strategy):
        assert next_action_label(self.widening_record(strategy)) == UPDATE_IMMEDIATELY

    def test_a_record_without_a_selection_has_no_tier_to_consult(self):
        """Transitive and ignored records never get a selection — they must not change label."""
        assert next_action_label(self.widening_record(None)) == CONSTRAINED_CHECK_NEWER

    def test_an_authorized_pick_equal_to_the_installed_version_moves_nothing(self):
        record = self.widening_record(UpdateStrategy.SECURITY, authorized=True, recommended_version="1.0.0")
        assert next_action_label(record) == CONSTRAINED_CHECK_NEWER

    def test_major_drift_still_reads_release_notes(self):
        record = self.widening_record(UpdateStrategy.SECURITY, authorized=True, versions_diff_index=MAJOR)
        assert next_action_label(record) == CHECK_RELEASE_NOTES

    def test_an_active_cve_still_comes_first(self):
        record = self.widening_record(UpdateStrategy.SECURITY, authorized=True)
        record.cve = [fake_cve(0.2)]
        record.epss = 0.2
        assert next_action_label(record) == CHECK_FOR_THE_FIX
