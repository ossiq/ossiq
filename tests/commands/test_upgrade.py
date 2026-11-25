from __future__ import annotations

import dataclasses
import json
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
from ossiq.service.upgrade.engine import PASSING_COMMANDS
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
    for name in (
        "plan",
        "start",
        "status",
        "changelog",
        "apply",
        "test",
        "rollback",
        "skip",
        "continue",
        "finish",
        "abort",
    ):
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


class TestUpgradePlan:
    """`upgrade plan` plans once, checks the overrides, shows the steps and writes nothing."""

    @pytest.fixture
    def project(self, tmp_path, monkeypatch):
        project = make_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "ossiq.commands.upgrade.plan_project", lambda settings, options, progress=None: project.plan(options)
        )
        return project

    def test_it_lists_the_steps_and_leaves_the_project_alone(self, project) -> None:
        result = runner.invoke(app, ["upgrade", "plan", str(project.root)])

        assert result.exit_code == 0
        assert "Upgrade: planned" in result.output and "vite 1.0.0 → 2.0.0" in result.output
        assert "zod 1.0.0 → 2.0.0" in result.output
        assert not store.exists(project.root)
        assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}

    def test_the_agent_format_prints_one_json_document(self, project) -> None:
        result = runner.invoke(app, ["upgrade", "plan", str(project.root), "--format", "agent"])

        payload = json.loads(result.stdout)
        assert result.exit_code == 0 and payload["outcome"] == "PLANNED"
        assert [s["packages"][0]["name"] for s in payload["steps"]] == ["vite", "zod"]

    def test_an_override_for_a_package_outside_the_tree_exits_2(self, project, monkeypatch) -> None:
        def with_unknown(settings, options, progress=None):
            sources, scan, plan = project.plan(options)
            return sources, scan, dataclasses.replace(plan, unknown_override_packages=("no-such-pkg",))

        monkeypatch.setattr("ossiq.commands.upgrade.plan_project", with_unknown)

        result = runner.invoke(app, ["upgrade", "plan", str(project.root), "--override", "no-such-pkg==1.0.0"])

        assert result.exit_code == 2
        assert "no-such-pkg" in result.output

    def test_start_refuses_a_session_in_the_way_before_it_scans(self, project, monkeypatch) -> None:
        start(project)

        def never(settings, options, progress=None):
            raise AssertionError("scanned")

        monkeypatch.setattr("ossiq.commands.upgrade.plan_project", never)

        result = runner.invoke(app, ["upgrade", "start", str(project.root)])

        assert result.exit_code == 1 and "already in progress" in result.output

    def test_start_shows_the_first_step_and_the_session_stays_for_the_next_command(self, project) -> None:
        result = runner.invoke(app, ["upgrade", "start", str(project.root), "--limit", "1"])

        assert result.exit_code == 0
        assert "step 1 of 1" in result.output
        assert store.exists(project.root)


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

    def test_after_the_last_step_the_menu_offers_finish_and_abort(self, project, monkeypatch, capsys) -> None:
        view = start(project, limit=1)
        self.answers(monkeypatch, "a", "n", "f")

        self.run(project, view)

        out = capsys.readouterr().out
        assert "f finish   x abort   q quit" in out
        assert not store.exists(project.root)

    def test_the_menu_lists_only_what_the_state_allows(self) -> None:
        pending = menu_line(("changelog", "apply", "skip", "finish", "abort"))
        failing = menu_line(("test", "rollback", "skip", "abort"))

        assert "w web" in pending and "n next step" not in pending
        assert "t test" in failing and "a apply" not in failing and "w web" not in failing
        assert "n next step" in menu_line(PASSING_COMMANDS)
