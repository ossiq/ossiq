"""B4: the CLI progress stepper must never render a plain success checkmark for a step whose
data source was actually degraded - see ossiq-defect-report.md, B4.
"""

from io import StringIO
from unittest.mock import MagicMock, patch

from rich.console import Console

from ossiq.domain.common import DataSourceStatus
from ossiq.settings import Settings
from ossiq.ui.system import SCAN_STEPS, render_scan_steps, show_scan_progress


def render_to_text(idx: int, step_status: dict[str, DataSourceStatus]) -> str:
    buf = StringIO()
    Console(file=buf, width=120, no_color=True, force_terminal=False).print(render_scan_steps(idx, step_status))
    return buf.getvalue()


class TestRenderScanSteps:
    def test_ok_step_shows_plain_checkmark(self):
        text = render_to_text(2, {"packages": DataSourceStatus.OK})
        assert "✓  Fetching package metadata" in text

    def test_unreachable_step_never_shows_a_plain_checkmark(self):
        """The report's literal scenario: a firewalled OSV host. Once the scan has moved past
        the vulnerabilities step, it must not render as an unqualified green ✓.
        """
        idx = SCAN_STEPS.index(("vulnerabilities", "Checking for vulnerabilities via OSV.dev")) + 1
        text = render_to_text(idx, {"vulnerabilities": DataSourceStatus.UNREACHABLE})
        assert "✓  Checking for vulnerabilities via OSV.dev" not in text
        assert "✗" in text
        assert "unreachable" in text

    def test_rate_limited_step_never_shows_a_plain_checkmark(self):
        idx = SCAN_STEPS.index(("repositories", "Fetching repository info and activity from GitHub")) + 1
        text = render_to_text(idx, {"repositories": DataSourceStatus.RATE_LIMITED})
        assert "✓  Fetching repository info and activity from GitHub" not in text
        assert "rate limited" in text

    def test_partial_step_never_shows_a_plain_checkmark(self):
        idx = SCAN_STEPS.index(("repositories", "Fetching repository info and activity from GitHub")) + 1
        text = render_to_text(idx, {"repositories": DataSourceStatus.PARTIAL})
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
        idx = SCAN_STEPS.index(("vulnerabilities", "Checking for vulnerabilities via OSV.dev"))
        text = render_to_text(idx, {})
        lines = [line for line in text.splitlines() if "Checking for vulnerabilities via OSV.dev" in line]
        assert len(lines) == 1
        assert "✓" not in lines[0]
        assert "✗" not in lines[0]

    def test_future_step_shows_pending_marker(self):
        text = render_to_text(0, {})
        assert "○  Fetching package metadata" in text


class TestShowScanProgressIntegration:
    """Drives the real on_step callback the way scan.py actually calls it."""

    def test_degraded_step_produces_a_warning_after_the_progress_bar(self):
        settings = Settings(verbose=False)
        with (
            patch("ossiq.ui.system.RICH_AVAILABLE", True),
            patch("ossiq.ui.system.error_console", MagicMock()),
            patch("ossiq.ui.system.show_warning") as warn,
        ):
            with show_scan_progress(settings) as on_step:
                on_step("packages")
                on_step("vulnerabilities")
                on_step("vulnerabilities", DataSourceStatus.UNREACHABLE)
                on_step("epss")

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
            with show_scan_progress(settings) as on_step:
                on_step("packages")
                on_step("vulnerabilities")
                on_step("vulnerabilities", DataSourceStatus.OK)
                on_step("epss")

        warn.assert_not_called()

    def test_verbose_mode_yields_a_noop_accepting_the_status_arg(self):
        """Must not crash when called with a status - callers in scan.py always pass one
        positionally now, including the verbose/agent-format silent path.
        """
        settings = Settings(verbose=True)
        with show_scan_progress(settings) as on_step:
            on_step("packages")
            on_step("vulnerabilities", DataSourceStatus.UNREACHABLE)
