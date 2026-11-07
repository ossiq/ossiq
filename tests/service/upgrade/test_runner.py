from __future__ import annotations

from ossiq.service.upgrade.runner import TAIL_LINES, run_command


def test_a_passing_command_reports_exit_zero_and_its_output(tmp_path) -> None:
    run = run_command("echo hello", tmp_path)

    assert (run.exit_code, run.output_tail) == (0, "hello")


def test_a_failing_command_reports_its_exit_code_and_both_streams(tmp_path) -> None:
    run = run_command("echo out; echo err >&2; exit 3", tmp_path)

    assert run.exit_code == 3
    assert set(run.output_tail.splitlines()) == {"out", "err"}


def test_lines_are_streamed_to_the_sink_after_the_command_itself(tmp_path) -> None:
    lines: list[str] = []

    run_command("echo a; echo b", tmp_path, lines.append)

    assert lines == ["$ echo a; echo b", "a", "b"]


def test_the_command_runs_in_the_project_directory(tmp_path) -> None:
    (tmp_path / "marker").write_text("")

    assert run_command("test -f marker", tmp_path).exit_code == 0


def test_only_the_tail_of_a_long_output_is_kept(tmp_path) -> None:
    run = run_command(f"seq 1 {TAIL_LINES * 3}", tmp_path)

    lines = run.output_tail.splitlines()
    assert len(lines) == TAIL_LINES
    assert lines[-1] == str(TAIL_LINES * 3)
