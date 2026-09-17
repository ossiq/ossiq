"""Tests for adapters.runtime_environment — best-effort actual-runtime detection.

Every probe must resolve to None on failure, never raise, regardless of cause (missing binary,
timeout, garbage output).
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from ossiq.adapters.runtime_environment import (
    detect_actual_node_version,
    detect_actual_npm_cli_version,
    detect_actual_python_version,
)


def _completed(stdout: str = "", stderr: str = "") -> MagicMock:
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    return result


class TestDetectActualPythonVersion:
    def test_reads_pyvenv_cfg_version(self, tmp_path):
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.11.9\n")

        assert detect_actual_python_version(str(tmp_path)) == "3.11.9"

    def test_falls_back_to_python_version_file(self, tmp_path):
        (tmp_path / ".python-version").write_text("3.12.1\n")

        assert detect_actual_python_version(str(tmp_path)) == "3.12.1"

    def test_pyvenv_cfg_takes_priority_over_python_version_file(self, tmp_path):
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("version = 3.11.9\n")
        (tmp_path / ".python-version").write_text("3.9.0\n")

        assert detect_actual_python_version(str(tmp_path)) == "3.11.9"

    @patch("subprocess.run")
    def test_falls_back_to_subprocess_when_no_local_files(self, mock_run, tmp_path):
        mock_run.return_value = _completed(stdout="Python 3.13.1\n")

        assert detect_actual_python_version(str(tmp_path)) == "3.13.1"

    @patch("subprocess.run")
    def test_returns_none_when_binary_missing(self, mock_run, tmp_path):
        mock_run.side_effect = FileNotFoundError()

        assert detect_actual_python_version(str(tmp_path)) is None

    @patch("subprocess.run")
    def test_returns_none_on_timeout(self, mock_run, tmp_path):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="python3", timeout=3)

        assert detect_actual_python_version(str(tmp_path)) is None

    def test_returns_none_when_nothing_available(self, tmp_path):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            assert detect_actual_python_version(str(tmp_path)) is None


class TestDetectActualNodeVersion:
    @patch("subprocess.run")
    def test_strips_leading_v(self, mock_run):
        mock_run.return_value = _completed(stdout="v20.11.0\n")

        assert detect_actual_node_version() == "20.11.0"

    @patch("subprocess.run")
    def test_returns_none_when_node_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        assert detect_actual_node_version() is None

    @patch("subprocess.run")
    def test_returns_none_on_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="node", timeout=3)

        assert detect_actual_node_version() is None

    @patch("subprocess.run")
    def test_returns_none_on_garbage_output(self, mock_run):
        mock_run.return_value = _completed(stdout="not a version\n")

        assert detect_actual_node_version() is None


class TestDetectActualNpmCliVersion:
    @patch("subprocess.run")
    def test_reads_version(self, mock_run):
        mock_run.return_value = _completed(stdout="10.2.4\n")

        assert detect_actual_npm_cli_version() == "10.2.4"

    @patch("subprocess.run")
    def test_returns_none_when_npm_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        assert detect_actual_npm_cli_version() is None
