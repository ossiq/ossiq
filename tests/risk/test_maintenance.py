"""Tests for the deprecation-evidence collector and the naive-Bayes maintenance model."""

import pytest

from ossiq.risk.maintenance import (
    DEPRECATION_NONE,
    DEPRECATION_STRONG,
    DEPRECATION_WEAK,
    INACTIVE_CLASSIFIER,
    NOT_MAINTAINED,
    PRIORS,
    PUSH_AGE_FRESH_DAYS,
    DeprecationEvidence,
    DeprecationSignal,
    MaintenanceState,
    assess_maintenance,
    deprecation_evidence,
    gated_observations,
    maintenance_posterior,
    named_successor,
    push_age_bucket,
    release_age_bucket,
)


def evidence(
    *,
    archived: bool | None = None,
    classifiers: list[str] | None = None,
    all_releases_yanked: bool = False,
    npm_deprecated: bool = False,
    deprecation_message: str | None = None,
    repo_description: str | None = None,
    summary: str | None = None,
    topics: list[str] | None = None,
    readme_head: str | None = None,
    pinned_titles: list[str] | None = None,
) -> DeprecationEvidence:
    return deprecation_evidence(
        archived=archived,
        classifiers=classifiers or [],
        all_releases_yanked=all_releases_yanked,
        npm_deprecated=npm_deprecated,
        deprecation_message=deprecation_message,
        repo_description=repo_description,
        summary=summary,
        topics=topics or [],
        readme_head=readme_head,
        pinned_titles=pinned_titles or [],
    )


class TestDeprecationSignals:
    def test_clean_package_has_no_signals(self) -> None:
        result = evidence()
        assert result.signals == frozenset()
        assert result.strength == DEPRECATION_NONE

    def test_archived_repo(self) -> None:
        assert DeprecationSignal.ARCHIVED in evidence(archived=True).signals

    def test_npm_deprecated_and_all_yanked_are_registry_deprecated(self) -> None:
        assert DeprecationSignal.REGISTRY_DEPRECATED in evidence(npm_deprecated=True).signals
        assert DeprecationSignal.REGISTRY_DEPRECATED in evidence(all_releases_yanked=True).signals

    def test_inactive_classifier(self) -> None:
        result = evidence(classifiers=["Programming Language :: Python", INACTIVE_CLASSIFIER])
        assert DeprecationSignal.INACTIVE_CLASSIFIER in result.signals

    def test_deprecation_topic(self) -> None:
        assert DeprecationSignal.TOPIC_TAGGED in evidence(topics=["python", "deprecated"]).signals

    def test_description_phrase(self) -> None:
        result = evidence(repo_description="[DEPRECATED] no longer maintained, use foo instead")
        assert DeprecationSignal.DESCRIPTION_MARKED in result.signals

    def test_readme_banner(self) -> None:
        result = evidence(readme_head="# my-lib\n\n> This project is deprecated.\n")
        assert DeprecationSignal.README_MARKED in result.signals

    def test_pinned_migration_notice(self) -> None:
        result = evidence(pinned_titles=["Roadmap", "Notice: Project Deprecation & Migration Guide"])
        assert DeprecationSignal.PINNED_NOTICE in result.signals

    def test_successor_named_from_deprecation_message(self) -> None:
        result = evidence(npm_deprecated=True, deprecation_message="This package is deprecated. Use got instead.")
        assert result.successor == "got"
        assert DeprecationSignal.SUCCESSOR_NAMED in result.signals


class TestDeprecationStrength:
    def test_one_strong_signal_is_strong(self) -> None:
        assert evidence(archived=True).strength == DEPRECATION_STRONG

    def test_one_soft_signal_is_weak(self) -> None:
        assert evidence(topics=["deprecated"]).strength == DEPRECATION_WEAK

    def test_two_soft_signals_are_strong(self) -> None:
        result = evidence(topics=["deprecated"], repo_description="no longer maintained")
        assert result.strength == DEPRECATION_STRONG


class TestNamedSuccessor:
    def test_extracts_replacement(self) -> None:
        assert named_successor("Deprecated - please migrate to `urllib3` for new code") == "urllib3"

    def test_none_when_absent(self) -> None:
        assert named_successor("just a normal summary") is None
        assert named_successor(None) is None


class TestPushAgeBucket:
    def test_boundaries(self) -> None:
        assert push_age_bucket(0) == "fresh"
        assert push_age_bucket(44) == "fresh"
        assert push_age_bucket(45) == "recent"
        assert push_age_bucket(89) == "recent"
        assert push_age_bucket(90) == "aging"
        assert push_age_bucket(364) == "aging"
        assert push_age_bucket(365) == "stale"
        assert push_age_bucket(729) == "stale"
        assert push_age_bucket(730) == "ancient"

    def test_unknown(self) -> None:
        assert push_age_bucket(None) is None


class TestReleaseAgeBucket:
    def test_boundaries(self) -> None:
        assert release_age_bucket(0) == "current"
        assert release_age_bucket(89) == "current"
        assert release_age_bucket(90) == "recent"
        assert release_age_bucket(364) == "recent"
        assert release_age_bucket(365) == "stale"
        assert release_age_bucket(729) == "stale"
        assert release_age_bucket(730) == "ancient"

    def test_unknown(self) -> None:
        assert release_age_bucket(None) is None


class TestGatedObservations:
    def test_strong_deprecation_drops_every_activity_observation(self) -> None:
        assert gated_observations(
            deprecation_strength=DEPRECATION_STRONG,
            has_stopped=False,
            push_age="fresh",
            flow_trend="improving",
            release_age="current",
        ) == {"deprecation_strength": DEPRECATION_STRONG}

    def test_a_fresh_push_drops_both_correlated_observations(self) -> None:
        gated = gated_observations(
            deprecation_strength=None,
            has_stopped=False,
            push_age="fresh",
            flow_trend="declining",
            release_age="current",
        )
        assert gated["flow_trend"] is None
        assert gated["release_age"] is None

    def test_release_age_is_kept_once_the_repo_has_gone_quiet(self) -> None:
        gated = gated_observations(
            deprecation_strength=None,
            has_stopped=False,
            push_age="aging",
            flow_trend="stable",
            release_age="current",
        )
        assert gated["release_age"] == "current"


class TestMaintenancePosterior:
    def test_no_observations_returns_the_prior(self) -> None:
        assert maintenance_posterior({}) == PRIORS

    def test_posterior_sums_to_one(self) -> None:
        posterior = maintenance_posterior({"has_stopped": True, "push_age": "ancient"})
        assert sum(posterior.values()) == pytest.approx(1.0)

    def test_strong_deprecation_dominates(self) -> None:
        posterior = maintenance_posterior({"deprecation_strength": DEPRECATION_STRONG})
        assert max(posterior, key=posterior.__getitem__) == MaintenanceState.DEPRECATED

    def test_fresh_and_alive_reads_maintained(self) -> None:
        posterior = maintenance_posterior({"has_stopped": False, "push_age": "fresh", "flow_trend": "stable"})
        assert max(posterior, key=posterior.__getitem__) == MaintenanceState.MAINTAINED

    def test_unknown_observation_names_are_ignored(self) -> None:
        assert maintenance_posterior({"bogus": "value"}) == PRIORS

    def test_a_quiet_repo_that_still_ships_reads_maintained(self) -> None:
        # The fuse.js shape: a couple of months between pushes, a release last quarter, and a
        # declining issue/PR flow. Every one of those is ordinary for a mature library, and the
        # model used to combine them into winding_down at P=0.92.
        posterior = maintenance_posterior(
            {"has_stopped": False, "push_age": "recent", "flow_trend": "declining", "release_age": "current"}
        )
        assert max(posterior, key=posterior.__getitem__) == MaintenanceState.MAINTAINED

    def test_a_quiet_repo_that_has_stopped_shipping_reads_winding_down(self) -> None:
        # Same repository silence, opposite release history - which is the whole point of
        # observing the registry clock as well as the repository one.
        posterior = maintenance_posterior(
            {"has_stopped": False, "push_age": "recent", "flow_trend": "declining", "release_age": "ancient"}
        )
        assert max(posterior, key=posterior.__getitem__) == MaintenanceState.WINDING_DOWN

    def test_the_push_age_boundary_is_a_gradient_not_a_cliff(self) -> None:
        # One day of wall-clock across PUSH_AGE_FRESH_DAYS used to move the verdict from
        # maintained at 0.94 to winding_down at 0.92, because crossing it both swapped the
        # push_age row and switched the gated flow_trend penalty on.
        def posterior_at(days: int) -> dict[str, float]:
            gated = gated_observations(
                deprecation_strength=None,
                has_stopped=False,
                push_age=push_age_bucket(days),
                flow_trend="declining",
                release_age="current",
            )
            return maintenance_posterior({k: v for k, v in gated.items() if v is not None})

        before = posterior_at(PUSH_AGE_FRESH_DAYS - 1)
        after = posterior_at(PUSH_AGE_FRESH_DAYS)
        assert max(before, key=before.__getitem__) == MaintenanceState.MAINTAINED
        assert max(after, key=after.__getitem__) == MaintenanceState.MAINTAINED


class TestAssessMaintenance:
    def test_none_without_any_observation(self) -> None:
        assert assess_maintenance({"has_stopped": None, "push_age": None}) is None

    def test_stopped_ancient_repo_is_not_maintained(self) -> None:
        assessment = assess_maintenance({"has_stopped": True, "push_age": "ancient"})
        assert assessment is not None
        assert assessment.state in NOT_MAINTAINED
        assert assessment.p_not_maintained >= 0.5
        assert assessment.p_maintained == pytest.approx(1.0 - assessment.p_not_maintained)

    def test_observations_recorded(self) -> None:
        assessment = assess_maintenance({"has_stopped": False, "push_age": "fresh", "flow_trend": None})
        assert assessment is not None
        assert assessment.observations == {"has_stopped": False, "push_age": "fresh"}
