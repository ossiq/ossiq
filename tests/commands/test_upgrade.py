from __future__ import annotations

import subprocess
import sys

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from ossiq.cli import app
from ossiq.commands.upgrade import ENGINE_CALLS, menu_line, run_interactive, stdout_to_stderr
from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.service.upgrade import store
from ossiq.settings import Settings
from tests.service.upgrade.helpers import BREAKS_ON_UPGRADE, env_for, make_project, start

runner = CliRunner()


def test_a_child_process_writes_to_stderr_while_stdout_is_redirected(capfd) -> None:
    with stdout_to_stderr():
        subprocess.run(["echo", "from npm"], check=True)
    print("after")
    sys.stdout.flush()

    captured = capfd.readouterr()
    assert captured.out.strip() == "after"
    assert "from npm" in captured.err


def test_every_subcommand_is_listed() -> None:
    result = runner.invoke(app, ["upgrade", "--help"])

    assert result.exit_code == 0
    for name in ("start", "status", "changelog", "apply", "test", "rollback", "skip", "continue", "finish", "abort"):
        assert name in result.stdout


def test_a_subcommand_without_a_session_says_how_to_start_one(tmp_path) -> None:
    result = runner.invoke(app, ["upgrade", "test", str(tmp_path)])

    assert result.exit_code == 1
    assert "No upgrade session" in result.output
    assert "ossiq upgrade start" in result.output


def test_abort_without_a_session_fails_the_same_way(tmp_path) -> None:
    result = runner.invoke(app, ["upgrade", "abort", str(tmp_path)])

    assert result.exit_code == 1
    assert "No upgrade session" in result.output


class TestInteractiveMenu:
    """The menu is a loop over the engine calls the subcommands make; it holds no logic of its own."""

    @pytest.fixture
    def project(self, tmp_path, monkeypatch):
        return make_project(tmp_path, monkeypatch)

    @staticmethod
    def answers(monkeypatch, *replies: str) -> list[str]:
        asked: list[str] = []
        queue = list(replies)

        def prompt(text, *args, **kwargs):
            asked.append(text)
            return queue.pop(0)

        monkeypatch.setattr(typer, "prompt", prompt)
        return asked

    def run(self, project, first_view):
        ctx = typer.Context(typer.main.get_command(app), obj=Settings())
        run_interactive(ctx, env_for(project), first_view, str(project.root))

    def test_apply_then_next_walks_a_step_through_and_quit_keeps_the_session(
        self, project, monkeypatch, capsys
    ) -> None:
        view = start(project, test_command="true")
        self.answers(monkeypatch, "a", "n", "q")

        self.run(project, view)

        out = capsys.readouterr().out
        assert project.installed() == {"vite": "2.0.0", "zod": "1.0.0"}
        assert "step 2 of 2" in out
        assert "Session kept" in out
        assert store.exists(project.root)

    def test_a_key_the_state_does_not_offer_is_asked_again(self, project, monkeypatch, capsys) -> None:
        view = start(project)
        asked = self.answers(monkeypatch, "n", "z", "q")

        self.run(project, view)

        assert len(asked) == 3
        assert capsys.readouterr().out.count("Pick one of") == 2

    def test_rollback_after_a_failing_step_returns_to_the_choice(self, project, monkeypatch) -> None:
        view = start(project, test_command=BREAKS_ON_UPGRADE)
        self.answers(monkeypatch, "a", "r", "q")

        self.run(project, view)

        assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}

    def test_abort_asks_first_and_a_no_changes_nothing(self, project, monkeypatch) -> None:
        view = start(project)
        self.answers(monkeypatch, "x", "q")
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: False)

        self.run(project, view)

        assert store.exists(project.root)

    def test_abort_confirmed_ends_the_session(self, project, monkeypatch) -> None:
        view = start(project)
        self.answers(monkeypatch, "x")
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)

        self.run(project, view)

        assert not store.exists(project.root)

    def test_skip_keeps_the_reason_it_was_given(self, project, monkeypatch) -> None:
        view = start(project)
        self.answers(monkeypatch, "s", "needs a rewrite", "q")

        self.run(project, view)

        assert store.load(project.root).steps[0].note == "needs a rewrite"

    def test_an_error_is_shown_and_the_menu_goes_on(self, project, monkeypatch, capsys) -> None:
        view = start(project)
        self.answers(monkeypatch, "a", "q")

        def refuse(env, path):
            raise UpgradeSessionError("boom")

        monkeypatch.setitem(ENGINE_CALLS, "apply", refuse)

        self.run(project, view)

        captured = capsys.readouterr()
        assert "boom" in captured.out + captured.err
        assert "Session kept" in captured.out

    def test_the_menu_lists_only_what_the_state_allows(self) -> None:
        pending = menu_line(("changelog", "apply", "skip", "finish", "abort"))
        failing = menu_line(("test", "rollback", "skip", "abort"))

        assert "w web" in pending and "n continue" not in pending
        assert "t test" in failing and "a apply" not in failing and "w web" not in failing
