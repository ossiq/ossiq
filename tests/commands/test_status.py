"""command_status renders whatever the scan produced, whatever the data sources did.

A degraded source is reported, never fatal: the console run gets ui.system's "data sources did
not fully respond" warning, and the agent/export/MCP documents carry `data_completeness` inside
the payload. `ossiq status` is not a CI gate, so a transient OSV blip can't break a pipeline that
only checks the exit code.

The one carve-out is `--update-strategy security`/`deprecation`, which move a package only on a
qualifying CVE: without vulnerability data their "nothing to do" is character-for-character what a
clean project prints, so they refuse rather than answer. `--allow-partial` opts back in.
"""

from __future__ import annotations

import dataclasses
from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.status import CommandStatusOptions, command_status
from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.domain.exceptions import SecurityDataIncomplete
from ossiq.service.project.models import ScanResult
from ossiq.settings import Settings
from ossiq.strategy.pyramid import UpdateStrategy


def make_scan_result(data_completeness: DataCompleteness | None = None) -> ScanResult:
    return ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=[],
        optional_packages=[],
        data_completeness=data_completeness or DataCompleteness(),
    )


def make_context() -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = Settings()
    return ctx


def make_options(**overrides) -> CommandStatusOptions:
    # agent mode: no Rich rendering side effects
    base = CommandStatusOptions(project_path=".", output_format="agent")
    return dataclasses.replace(base, **overrides)


def run_status(scan_result: ScanResult, **option_overrides) -> MagicMock:
    with (
        patch("ossiq.commands.status.project_sources.build_project_sources"),
        patch("ossiq.commands.status.scan", return_value=scan_result),
        patch("ossiq.commands.status.get_renderer") as get_renderer,
    ):
        command_status(make_context(), make_options(**option_overrides))
    return get_renderer


class TestCommandStatusRendersDespiteDegradedData:
    @pytest.mark.parametrize(
        "completeness",
        [
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.OK}),
            # The common case today: most steps don't report completeness at all yet.
            DataCompleteness(),
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE}),
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.RATE_LIMITED}),
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.PARTIAL}),
            DataCompleteness(by_step={ScanStep.REPOSITORIES: DataSourceStatus.UNREACHABLE}),
        ],
        ids=["ok", "untracked", "unreachable", "rate-limited", "partial", "repositories-degraded"],
    )
    def test_renders_for_any_vulnerability_status(self, completeness: DataCompleteness) -> None:
        get_renderer = run_status(make_scan_result(completeness))

        get_renderer.return_value.render.assert_called_once()

    def test_does_not_exit_nonzero_when_vulnerabilities_unreachable(self) -> None:
        """The firewalled-OSV scenario: report it via data_completeness, don't fail the run."""
        scan_result = make_scan_result(
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        )

        with (
            patch("ossiq.commands.status.project_sources.build_project_sources"),
            patch("ossiq.commands.status.scan", return_value=scan_result),
            patch("ossiq.commands.status.get_renderer"),
        ):
            command_status(make_context(), make_options())  # must not raise typer.Exit

    @pytest.mark.parametrize(
        "strategy",
        [UpdateStrategy.STANDARD, UpdateStrategy.LATEST, UpdateStrategy.CUTTING_EDGE],
        ids=["standard", "latest", "cutting-edge"],
    )
    def test_freshness_tiers_render_despite_unreachable_vulnerabilities(self, strategy: UpdateStrategy) -> None:
        """Drift alone justifies an update above the minimal-diff tiers, so a degraded OSV run
        produces a thinner answer rather than a silently empty one."""
        scan_result = make_scan_result(
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        )

        get_renderer = run_status(scan_result, update_strategy=strategy)

        get_renderer.return_value.render.assert_called_once()

    @pytest.mark.parametrize(
        "strategy", [UpdateStrategy.SECURITY, UpdateStrategy.DEPRECATION], ids=["security", "deprecation"]
    )
    def test_minimal_diff_tiers_refuse_an_answer_they_cannot_back_up(self, strategy: UpdateStrategy) -> None:
        """These tiers move a package only on a qualifying CVE, so without vulnerability data
        their "nothing to do" is character-for-character what a clean project prints."""
        scan_result = make_scan_result(
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        )

        with pytest.raises(SecurityDataIncomplete):
            run_status(scan_result, update_strategy=strategy)

    def test_allow_partial_accepts_the_incomplete_answer(self) -> None:
        scan_result = make_scan_result(
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        )

        get_renderer = run_status(scan_result, update_strategy=UpdateStrategy.SECURITY, allow_partial=True)

        get_renderer.return_value.render.assert_called_once()

    def test_a_degraded_repositories_step_is_not_grounds_for_refusing(self) -> None:
        """GitHub feeds end_of_life, which degrades deprecation's coverage rather than emptying
        its result the way a missing CVE feed does."""
        scan_result = make_scan_result(DataCompleteness(by_step={ScanStep.REPOSITORIES: DataSourceStatus.UNREACHABLE}))

        get_renderer = run_status(scan_result, update_strategy=UpdateStrategy.DEPRECATION)

        get_renderer.return_value.render.assert_called_once()

    def test_degradation_stays_visible_in_the_scan_result(self) -> None:
        """Removing the exit code must not remove the evidence: renderers still receive the
        completeness record, which is what the agent/export documents surface.
        """
        completeness = DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        get_renderer = run_status(make_scan_result(completeness))

        rendered = get_renderer.return_value.render.call_args.kwargs["data"]
        assert rendered.data_completeness.degraded_steps == {ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE}
