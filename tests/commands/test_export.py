"""B8: stdout must carry only the requested payload - not the settings panel, not the progress
stepper, not any warnings - across the whole command_export flow, not just the renderer in
isolation. Runs the real command_export function end to end (scan/sources mocked, everything
else real) with destination="-", in both verbose and non-verbose mode, since those two modes
exercise different diagnostic-output code paths (show_settings vs. the Rich Live progress bar).
"""

from __future__ import annotations

import dataclasses
import json
from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.export import CommandExportOptions, command_export
from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
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


def make_context(verbose: bool) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = Settings(verbose=verbose)
    return ctx


def make_options(**overrides) -> CommandExportOptions:
    base = CommandExportOptions(
        project_path=".",
        registry_type=None,
        production=False,
        output_destination="-",
        schema_version=None,
        allow_prerelease=False,
        allow_prerelease_packages=(),
    )
    return dataclasses.replace(base, **overrides)


@pytest.mark.parametrize("verbose", [True, False])
def test_stdout_carries_only_json_end_to_end(capsys, verbose):
    """Degraded data sources too: this is exactly the scenario the report's evidence hit a
    rate-limit warning during - confirm the warning (if any fires) still never reaches stdout.
    """
    scan_result = make_scan_result(DataCompleteness(by_step={ScanStep.REPOSITORIES: DataSourceStatus.RATE_LIMITED}))

    with (
        patch("ossiq.commands.export.project_sources.ProjectSources"),
        patch("ossiq.commands.export.scan", return_value=scan_result),
    ):
        command_export(make_context(verbose), make_options())

    captured = capsys.readouterr()
    # The entire captured stdout must parse as exactly one JSON document - no warning text,
    # no settings panel, no progress-bar remnants mixed in before or after it.
    data = json.loads(captured.out)
    assert data["project"]["registry"] == "pypi"
