"""B4 point 4: command_status must refuse to render a status report that could look clean while
actually being based on vulnerability data that couldn't be retrieved - fail closed by default,
opt out explicitly with --allow-partial.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.status import CommandStatusOptions, command_status
from ossiq.domain.common import DataCompleteness, DataSourceStatus
from ossiq.service.project.models import ScanResult
from ossiq.settings import Settings


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
    defaults = {"project_path": ".", "output_format": "agent"}  # agent mode: no Rich rendering side effects
    defaults.update(overrides)
    return CommandStatusOptions(**defaults)


class TestCommandStatusDataCompletenessGate:
    def test_renders_normally_when_vulnerabilities_ok(self):
        scan_result = make_scan_result(DataCompleteness(by_step={"vulnerabilities": DataSourceStatus.OK}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer") as get_renderer:
            command_status(make_context(), make_options())

        get_renderer.return_value.render.assert_called_once()

    def test_renders_normally_when_completeness_untracked(self):
        """The common case today: most projects/steps don't report completeness at all yet -
        an empty DataCompleteness must not be mistaken for a degraded one.
        """
        scan_result = make_scan_result(DataCompleteness())

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer") as get_renderer:
            command_status(make_context(), make_options())

        get_renderer.return_value.render.assert_called_once()

    def test_exits_nonzero_and_does_not_render_when_vulnerabilities_unreachable(self):
        """The report's literal scenario: a firewalled OSV host. Must refuse to render a report
        that would otherwise look clean, and must exit non-zero so CI/automation notices.
        """
        scan_result = make_scan_result(DataCompleteness(by_step={"vulnerabilities": DataSourceStatus.UNREACHABLE}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer") as get_renderer, patch(
            "ossiq.commands.status.show_error"
        ) as show_error:
            with pytest.raises(typer.Exit) as exc_info:
                command_status(make_context(), make_options())

        assert exc_info.value.exit_code == 1
        get_renderer.return_value.render.assert_not_called()
        show_error.assert_called_once()

    def test_exits_nonzero_when_vulnerabilities_rate_limited(self):
        scan_result = make_scan_result(DataCompleteness(by_step={"vulnerabilities": DataSourceStatus.RATE_LIMITED}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer"), patch("ossiq.commands.status.show_error"):
            with pytest.raises(typer.Exit) as exc_info:
                command_status(make_context(), make_options())

        assert exc_info.value.exit_code == 1

    def test_renders_anyway_with_allow_partial(self):
        scan_result = make_scan_result(DataCompleteness(by_step={"vulnerabilities": DataSourceStatus.UNREACHABLE}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer") as get_renderer:
            command_status(make_context(), make_options(allow_partial=True))

        get_renderer.return_value.render.assert_called_once()

    def test_degraded_repositories_alone_does_not_block_rendering(self):
        """B4 point 4 is scoped to vulnerability data specifically - a degraded GitHub fetch
        (stability/maintenance signals) is surfaced via the softer progress-bar warning (point 2),
        not this hard exit-code gate.
        """
        scan_result = make_scan_result(DataCompleteness(by_step={"repositories": DataSourceStatus.UNREACHABLE}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer") as get_renderer:
            command_status(make_context(), make_options())

        get_renderer.return_value.render.assert_called_once()

    def test_gate_applies_regardless_of_security_only_flag(self):
        """CVE data is fetched for every status run, not gated behind --security (which only
        narrows *transitive* solving) - the exit-code gate must not depend on that flag either.
        """
        scan_result = make_scan_result(DataCompleteness(by_step={"vulnerabilities": DataSourceStatus.UNREACHABLE}))

        with patch("ossiq.commands.status.project_sources.build_project_sources"), patch(
            "ossiq.commands.status.scan", return_value=scan_result
        ), patch("ossiq.commands.status.get_renderer"), patch("ossiq.commands.status.show_error"):
            with pytest.raises(typer.Exit):
                command_status(make_context(), make_options(security_only=False))
