"""The diagnostic value types a degraded fetch reports: why it degraded, and the quota behind it.

Pure arithmetic and merging - `DataSourceStatus` says whether a source delivered, these say what
stopped it, and every surface (console, agent JSON, export) renders the same values.
"""

from ossiq.domain.common import (
    DataCompleteness,
    DataSourceStatus,
    DegradeReason,
    FetchDiagnostics,
    RateLimitBudget,
    ScanStep,
    merge_diagnostics,
)


class TestRateLimitBudget:
    def test_short_by_is_the_gap_between_what_is_needed_and_what_is_left(self):
        assert RateLimitBudget(resource="core", remaining=12, needed=90).short_by == 78

    def test_a_budget_that_covers_the_scan_is_not_short(self):
        assert RateLimitBudget(resource="core", remaining=900, needed=90).short_by == 0

    def test_an_observed_budget_carries_no_forecast_and_is_never_short(self):
        assert RateLimitBudget(resource="core", remaining=0).short_by == 0

    def test_seconds_until_reset_never_goes_negative(self):
        assert RateLimitBudget(resource="core", reset_at=100.0).seconds_until_reset(now=500.0) == 0.0

    def test_the_lower_remaining_wins(self):
        early = RateLimitBudget(resource="core", limit=5000, remaining=4000)
        late = RateLimitBudget(resource="core", limit=5000, remaining=120)

        assert early.worse_of(late) == late
        assert late.worse_of(early) == late

    def test_a_reading_without_a_number_never_wins(self):
        """The pre-flight forecast can come back empty-handed; that is not evidence of a tight
        quota, and it must not displace a number a real response reported."""
        silent = RateLimitBudget(resource="core")
        measured = RateLimitBudget(resource="core", remaining=40)

        assert silent.worse_of(measured).remaining == 40
        assert measured.worse_of(silent).remaining == 40

    def test_a_forecast_survives_being_merged_with_an_observation(self):
        """`needed` is only ever set before the scan runs, so the tighter mid-scan reading would
        otherwise drop the one number that says whether the quota covers the run."""
        forecast = RateLimitBudget(resource="core", limit=60, remaining=60, needed=73)
        observed = RateLimitBudget(resource="core", limit=60, remaining=45)

        assert forecast.worse_of(observed) == RateLimitBudget(resource="core", limit=60, remaining=45, needed=73)


class TestFetchDiagnostics:
    def test_failure_counts_add_across_fetches(self):
        first = FetchDiagnostics(failures=((DegradeReason.NOT_FOUND, 2),))
        second = FetchDiagnostics(failures=((DegradeReason.NOT_FOUND, 1), (DegradeReason.UNAVAILABLE, 3)))

        assert first.merge(second).failures == ((DegradeReason.NOT_FOUND, 3), (DegradeReason.UNAVAILABLE, 3))

    def test_budgets_are_kept_one_per_resource(self):
        first = FetchDiagnostics(budgets=(RateLimitBudget(resource="core", remaining=100),))
        second = FetchDiagnostics(
            budgets=(
                RateLimitBudget(resource="core", remaining=80),
                RateLimitBudget(resource="graphql", remaining=5000),
            )
        )

        assert first.merge(second).budgets == (
            RateLimitBudget(resource="core", remaining=80),
            RateLimitBudget(resource="graphql", remaining=5000),
        )

    def test_merging_nothing_is_empty_not_an_error(self):
        assert merge_diagnostics([]) == FetchDiagnostics()


class TestDataCompletenessDiagnostics:
    def test_a_step_without_diagnostics_reports_empty_ones(self):
        completeness = DataCompleteness(by_step={ScanStep.REPOSITORIES: DataSourceStatus.PARTIAL})

        assert completeness.diagnostics_for(ScanStep.REPOSITORIES) == FetchDiagnostics()
        assert completeness.budgets == ()

    def test_budgets_are_collected_across_every_step(self):
        completeness = DataCompleteness(
            by_step={ScanStep.REPOSITORIES: DataSourceStatus.PARTIAL},
            diagnostics={
                ScanStep.REPOSITORIES: FetchDiagnostics(budgets=(RateLimitBudget(resource="core", remaining=7),)),
                ScanStep.VULNERABILITIES: FetchDiagnostics(budgets=(RateLimitBudget(resource="core", remaining=3),)),
            },
        )

        assert completeness.budgets == (RateLimitBudget(resource="core", remaining=3),)
