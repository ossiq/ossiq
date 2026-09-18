"""B4: the CLI progress stepper must never render a plain success checkmark for a step whose
data source was actually degraded - see ossiq-defect-report.md, B4.
"""

from io import StringIO
from unittest.mock import MagicMock, patch

from rich.console import Console

from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.settings import Settings
from ossiq.ui.system import STEP_INDEX, render_scan_steps, show_scan_progress, warn_about_degraded_steps


def render_to_text(idx: int, step_status: dict[ScanStep, DataSourceStatus]) -> str:
    buf = StringIO()
    Console(file=buf, width=120, no_color=True, force_terminal=False).print(render_scan_steps(idx, step_status))
    return buf.getvalue()


class TestRenderScanSteps:
    def test_ok_step_shows_plain_checkmark(self):
        text = render_to_text(2, {ScanStep.PACKAGES: DataSourceStatus.OK})
        assert "✓  Fetching package metadata" in text

    def test_unreachable_step_never_shows_a_plain_checkmark(self):
        """The report's literal scenario: a firewalled OSV host. Once the scan has moved past
        the vulnerabilities step, it must not render as an unqualified green ✓.
        """
        idx = STEP_INDEX[ScanStep.VULNERABILITIES] + 1
        text = render_to_text(idx, {ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE})
        assert "✓  Checking for vulnerabilities via OSV.dev" not in text
        assert "✗" in text
        assert "unreachable" in text

    def test_rate_limited_step_never_shows_a_plain_checkmark(self):
        idx = STEP_INDEX[ScanStep.REPOSITORIES] + 1
        text = render_to_text(idx, {ScanStep.REPOSITORIES: DataSourceStatus.RATE_LIMITED})
        assert "✓  Fetching repository info and activity from GitHub" not in text
        assert "rate limited" in text

    def test_partial_step_never_shows_a_plain_checkmark(self):
        idx = STEP_INDEX[ScanStep.REPOSITORIES] + 1
        text = render_to_text(idx, {ScanStep.REPOSITORIES: DataSourceStatus.PARTIAL})
        assert "✓  Fetching repository info and activity from GitHub" not in text
        assert "⚠" in text
        assert "partial" in text

    def test_step_with_no_recorded_status_defaults_to_ok(self):
        """Steps that don't yet report completeness (packages, versions, solver, epss) must keep
        behaving exactly as before - a plain checkmark once passed, no false warnings.
        """
        text = render_to_text(2, {})
        assert "✓  Reading project dependencies" in text
        assert "✓  Fetching package metadata" in text

    def test_current_step_shows_spinner_not_a_status_icon(self):
        idx = STEP_INDEX[ScanStep.VULNERABILITIES]
        text = render_to_text(idx, {})
        lines = [line for line in text.splitlines() if "Checking for vulnerabilities via OSV.dev" in line]
        assert len(lines) == 1
        assert "✓" not in lines[0]
        assert "✗" not in lines[0]

    def test_future_step_shows_pending_marker(self):
        text = render_to_text(0, {})
        assert "○  Fetching package metadata" in text


class TestShowScanProgressIntegration:
    """Drives the real ScanProgress callbacks the way scan.py actually calls them."""

    def test_degraded_step_produces_a_warning_after_the_progress_bar(self):
        settings = Settings(verbose=False)
        with (
            patch("ossiq.ui.system.RICH_AVAILABLE", True),
            patch("ossiq.ui.system.error_console", MagicMock()),
            patch("ossiq.ui.system.show_warning") as warn,
        ):
            with show_scan_progress(settings) as progress:
                progress.on_step_start(ScanStep.PACKAGES)
                progress.on_step_start(ScanStep.VULNERABILITIES)
                progress.on_step_done(ScanStep.VULNERABILITIES, DataSourceStatus.UNREACHABLE)
                progress.on_step_start(ScanStep.EPSS)

        warn.assert_called_once()
        message = warn.call_args.args[0]
        assert "vulnerabilities" in message.lower() or "OSV" in message

    def test_clean_run_produces_no_warning(self):
        settings = Settings(verbose=False)
        with (
            patch("ossiq.ui.system.RICH_AVAILABLE", True),
            patch("ossiq.ui.system.error_console", MagicMock()),
            patch("ossiq.ui.system.show_warning") as warn,
        ):
            with show_scan_progress(settings) as progress:
                progress.on_step_start(ScanStep.PACKAGES)
                progress.on_step_start(ScanStep.VULNERABILITIES)
                progress.on_step_done(ScanStep.VULNERABILITIES, DataSourceStatus.OK)
                progress.on_step_start(ScanStep.EPSS)

        warn.assert_not_called()

    def test_outcome_for_a_step_never_started_is_still_recorded(self):
        """on_step_done is independent of on_step_start: prefetch_scan_data reports the
        repositories outcome after several sub-fetches, and the spinner has already moved on.
        """
        settings = Settings(verbose=False)
        with (
            patch("ossiq.ui.system.RICH_AVAILABLE", True),
            patch("ossiq.ui.system.error_console", MagicMock()),
            patch("ossiq.ui.system.show_warning") as warn,
        ):
            with show_scan_progress(settings) as progress:
                progress.on_step_done(ScanStep.REPOSITORIES, DataSourceStatus.RATE_LIMITED)

        warn.assert_called_once()
        assert "GitHub" in warn.call_args.args[0]

    def test_verbose_mode_yields_a_silent_progress(self):
        """The verbose/agent-format path yields a real ScanProgress whose callbacks do nothing,
        so scan() never has to check whether it has one.
        """
        settings = Settings(verbose=True)
        with show_scan_progress(settings) as progress:
            progress.on_step_start(ScanStep.PACKAGES)
            progress.on_step_done(ScanStep.VULNERABILITIES, DataSourceStatus.UNREACHABLE)


class TestWarnAboutDegradedSteps:
    """The warning reads degradation off DataCompleteness.degraded_steps rather than
    re-implementing that filter — one definition of "this step did not come back ok"."""

    def test_no_warning_for_a_clean_completeness(self):
        with patch("ossiq.ui.system.show_warning") as warn:
            warn_about_degraded_steps(DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.OK}))

        warn.assert_not_called()

    def test_warning_lists_only_the_degraded_steps_by_label(self):
        completeness = DataCompleteness(
            by_step={
                ScanStep.REPOSITORIES: DataSourceStatus.OK,
                ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE,
            }
        )
        with patch("ossiq.ui.system.show_warning") as warn:
            warn_about_degraded_steps(completeness)

        message = warn.call_args.args[0]
        assert "Checking for vulnerabilities via OSV.dev: unreachable" in message
        assert "GitHub" not in message

    def test_empty_completeness_is_not_a_warning(self):
        with patch("ossiq.ui.system.show_warning") as warn:
            warn_about_degraded_steps(DataCompleteness())

        warn.assert_not_called()
