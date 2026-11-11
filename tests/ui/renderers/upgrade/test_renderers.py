"""The upgrade renderers: the agent JSON shape every subcommand shares, and the console reading of a step."""

from __future__ import annotations

import json
import os
from typing import Any, cast

from ossiq.domain.changelog import ChangelogItem, ChangelogStatus, MigrationGuide, RangeChangelog
from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.update.models import PlanOptions
from ossiq.service.upgrade.models import CommandRun, StepPackage, StepStatus, UpgradeSession, UpgradeStep
from ossiq.service.upgrade.view import Outcome, PackagePreview, StepPreview, UpgradeView
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.renderers.upgrade.console import ConsoleUpgradeRenderer, without_front_matter

CHANGELOG = RangeChangelog(
    status=ChangelogStatus.OK,
    source_url="https://api.changelogiq.dev/v1/npm/packages/zod/changelog?from=1.0.0&to=2.0.0",
    web_url="https://changelogiq.dev/?ecosystem=npm&package=zod&from=1.0.0&to=2.0.0",
    risk_level="HIGH",
    breaking_change=True,
    security_fix=True,
    cve_references=("CVE-2024-1",),
    items=(ChangelogItem("2.0.0", "Removed", "Remove the shim", True, ("https://github.com/o/r/issues/1",)),),
    guides=(MigrationGuide("2.0.0", "Upgrading", "https://example.com/up"),),
    markdown="---\nrisk_level: HIGH\n---\n\n# Changelog\n",
)


def package(name: str, *, direct: bool = True) -> StepPackage:
    return StepPackage(f"{name}@1.0.0", name, name, direct, "1.0.0", "2.0.0")


def session(*steps: UpgradeStep, test_command: str | None = "npm test") -> UpgradeSession:
    return UpgradeSession(
        session_id="seq_1",
        created_at="2026-11-07T00:00:00Z",
        package_manager="npm",
        registry="npm",
        options=PlanOptions(project_path="/work/app"),
        test_command=test_command,
        snapshot_files=("package.json",),
        steps=steps,
        peer_repairs=False,
        baseline=CommandRun(0, "t", ""),
    )


def pending_view(**kwargs: Any) -> UpgradeView:
    step = UpgradeStep(1, StepStatus.PENDING, (package("zod"), package("helper", direct=False)))
    preview = StepPreview(
        packages=(
            PackagePreview(step.packages[0], None, None, None, CHANGELOG),
            PackagePreview(step.packages[1], None, None, None),
        ),
        engine_context=cast(Any, None),
    )
    return UpgradeView(
        Outcome.IN_PROGRESS,
        session(step, UpgradeStep(2, StepStatus.PENDING, (package("vite"),))),
        step,
        preview=preview,
        commands=("changelog", "apply", "skip"),
        **kwargs,
    )


def render_agent(view: UpgradeView, capsys) -> dict[str, Any]:
    get_renderer(Command.UPGRADE, UserInterfaceType.AGENT, Settings()).render(data=view)
    return json.loads(capsys.readouterr().out)


def test_agent_output_has_the_same_top_level_keys_in_every_state(capsys) -> None:
    states = [
        pending_view(),
        UpgradeView(Outcome.ABORTED, None, None, message="gone"),
        UpgradeView(Outcome.NOTHING_TO_DO, None, None),
    ]

    shapes = {tuple(render_agent(view, capsys)) for view in states}

    assert shapes == {("outcome", "needs_attention", "message", "session", "step", "changelogs", "commands")}


def test_agent_pending_step_lists_every_package_with_its_move(capsys) -> None:
    payload = render_agent(pending_view(), capsys)

    assert payload["session"]["step"] == 1 and payload["session"]["total_steps"] == 2
    assert payload["session"]["pending"] == 2
    assert [(p["name"], p["is_direct"], p["from"], p["to"]) for p in payload["step"]["packages"]] == [
        ("zod", True, "1.0.0", "2.0.0"),
        ("helper", False, "1.0.0", "2.0.0"),
    ]
    assert payload["commands"] == ["changelog", "apply", "skip"]


def test_agent_applied_step_carries_the_last_test_run(capsys) -> None:
    step = UpgradeStep(
        1,
        StepStatus.AWAITING_REFACTOR,
        (package("zod"),),
        last_run=CommandRun(1, "2026-11-07T00:00:01Z", "1 failed"),
    )
    view = UpgradeView(Outcome.IN_PROGRESS, session(step), step, attention=True, message="Tests failed")

    payload = render_agent(view, capsys)

    assert payload["needs_attention"] is True
    assert payload["step"]["status"] == "AWAITING_REFACTOR"
    assert payload["step"]["last_test"] == {"exit_code": 1, "ran_at": "2026-11-07T00:00:01Z", "output_tail": "1 failed"}


def test_agent_changelog_view_carries_the_whole_document(capsys) -> None:
    step = UpgradeStep(1, StepStatus.PENDING, (package("zod"),))
    view = UpgradeView(
        Outcome.IN_PROGRESS, session(step), step, changelogs=((step.packages[0], CHANGELOG),), commands=("apply",)
    )

    (entry,) = render_agent(view, capsys)["changelogs"]

    assert entry["name"] == "zod" and entry["markdown"] == CHANGELOG.markdown
    assert entry["breaking"] == [
        {
            "version": "2.0.0",
            "category": "Removed",
            "text": "Remove the shim",
            "references": ["https://github.com/o/r/issues/1"],
        }
    ]
    assert entry["migration_guides"] == [{"version": "2.0.0", "title": "Upgrading", "url": "https://example.com/up"}]


def test_console_shows_the_queue_the_changelog_summary_and_the_next_commands(capsys) -> None:
    get_renderer(Command.UPGRADE, UserInterfaceType.CONSOLE, Settings()).render(data=pending_view(message="Hello"))

    out = capsys.readouterr().out
    assert "step 1 of 2" in out
    assert "zod 1.0.0 → 2.0.0" in out and "vite 1.0.0 → 2.0.0" in out
    assert "moves with it" in out
    assert "risk HIGH" in out and "CVE-2024-1" in out
    assert "Remove the shim" in out
    assert "Migration guide 2.0.0: Upgrading" in out
    assert "ossiq upgrade apply /work/app" in out


def test_console_says_so_when_a_changelog_is_missing(capsys) -> None:
    missing = RangeChangelog(ChangelogStatus.NOT_FOUND, "api", "https://changelogiq.dev/?x", detail="unknown")
    view = pending_view()
    assert view.preview is not None
    first = view.preview.packages[0]
    preview = StepPreview(
        (PackagePreview(first.package, None, None, None, missing), *view.preview.packages[1:]), cast(Any, None)
    )

    get_renderer(Command.UPGRADE, UserInterfaceType.CONSOLE, Settings()).render(
        data=UpgradeView(view.outcome, view.session, view.step, preview=preview, commands=view.commands)
    )

    out = capsys.readouterr().out
    assert "Not available (not_found)" in out and "https://changelogiq.dev/?x" in out


def test_console_shows_the_tail_of_a_failing_test_run(capsys) -> None:
    step = UpgradeStep(
        1,
        StepStatus.AWAITING_REFACTOR,
        (package("zod"),),
        last_run=CommandRun(1, "t", "line one\nAssertionError: boom"),
    )
    view = UpgradeView(Outcome.IN_PROGRESS, session(step), step, commands=("test", "rollback"), attention=True)

    get_renderer(Command.UPGRADE, UserInterfaceType.CONSOLE, Settings()).render(data=view)

    out = capsys.readouterr().out
    assert "exited with 1" in out and "AssertionError: boom" in out


def test_the_changelog_pager_keeps_colours_unless_the_user_configured_less(capsys, monkeypatch) -> None:
    view = UpgradeView(Outcome.IN_PROGRESS, None, None, changelogs=((package("zod"), CHANGELOG),))
    renderer = ConsoleUpgradeRenderer(Settings())

    monkeypatch.delenv("LESS", raising=False)
    renderer.render_changelogs(view)
    assert os.environ["LESS"] == "-R"

    monkeypatch.setenv("LESS", "-X")
    renderer.render_changelogs(view)
    assert os.environ["LESS"] == "-X"


def test_the_front_matter_is_left_out_of_the_pager_view() -> None:
    assert without_front_matter("---\nrisk_level: HIGH\n---\n\n# Changelog\n") == "# Changelog\n"
    assert without_front_matter("# Changelog\n") == "# Changelog\n"


def test_console_prints_square_brackets_from_tests_and_changelogs_as_they_are(capsys) -> None:
    """Test output and changelog text are not Rich markup: `[/tmp/x]` must not crash, `[Symbol.iterator]` must show."""
    tricky = RangeChangelog(
        ChangelogStatus.OK,
        "api",
        "web",
        items=(ChangelogItem("2.0.0", "Changed", "Drop [Symbol.iterator] and [/tmp/x] support", True),),
        guides=(MigrationGuide("2.0.0", "Moving [/old] to [new]", "https://example.com/[x]"),),
    )
    step = UpgradeStep(
        1,
        StepStatus.AWAITING_REFACTOR,
        (package("zod"),),
        last_run=CommandRun(1, "t", "FAIL [/tmp/x] in [suite]"),
    )
    renderer = ConsoleUpgradeRenderer(Settings())

    renderer.render(data=UpgradeView(Outcome.IN_PROGRESS, session(step), step, attention=True, message="Bad [/x] news"))
    renderer.render_changelog_summary(tricky)

    out = capsys.readouterr().out
    assert "FAIL [/tmp/x] in [suite]" in out and "Bad [/x] news" in out
    assert "Drop [Symbol.iterator] and [/tmp/x] support" in out
    assert "Moving [/old] to [new]" in out
