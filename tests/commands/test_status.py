"""command_status renders whatever the scan produced, whatever the data sources did.

A degraded source is reported, never fatal: the console run gets ui.system's "data sources did
not fully respond" warning, and the agent/export/MCP documents carry `data_completeness` inside
the payload. `ossiq status` itself always exits 0, so a transient OSV blip can't break a pipeline
that only checks the exit code. A CI-shaped experience is separate, unbuilt work.
"""

from __future__ import annotations

import dataclasses
from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.status import CommandStatusOptions, command_status
from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
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

    def test_renders_regardless_of_update_strategy(self) -> None:
        scan_result = make_scan_result(
            DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        )

        get_renderer = run_status(scan_result, update_strategy=UpdateStrategy.SECURITY)

        get_renderer.return_value.render.assert_called_once()

    def test_degradation_stays_visible_in_the_scan_result(self) -> None:
        """Removing the exit code must not remove the evidence: renderers still receive the
        completeness record, which is what the agent/export documents surface.
        """
        completeness = DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        get_renderer = run_status(make_scan_result(completeness))

        rendered = get_renderer.return_value.render.call_args.kwargs["data"]
        assert rendered.data_completeness.degraded_steps == {ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE}
