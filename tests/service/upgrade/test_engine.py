"""The upgrade state machine, driven on real files with a fake package manager and real shell test commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.service.upgrade import engine, store
from ossiq.service.upgrade.engine import UpgradeEnv
from ossiq.service.upgrade.models import StepStatus
from ossiq.service.upgrade.view import Outcome, UpgradeView
from tests.service.upgrade.helpers import BREAKS_ON_UPGRADE, FIXABLE, Project, env_for, make_project, start


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Project:
    return make_project(tmp_path, monkeypatch)


def current(view: UpgradeView) -> tuple[int, StepStatus]:
    assert view.step is not None
    return view.step.number, view.step.status


def test_start_queues_one_step_per_package_and_shows_the_first(project: Project) -> None:
    view = start(project)

    assert view.outcome is Outcome.IN_PROGRESS
    assert view.session is not None
    assert [[p.name for p in s.packages] for s in view.session.steps] == [["vite"], ["zod"]]
    assert current(view) == (1, StepStatus.PENDING)
    assert view.commands == engine.PENDING_COMMANDS
    assert store.exists(project.root)


def test_start_limit_and_package_narrow_the_queue(project: Project) -> None:
    assert len(cast(Any, start(project, limit=1).session).steps) == 1
    store.end(project.root)
    assert [p.name for p in cast(Any, start(project, package="zod").session).steps[0].packages] == ["zod"]


def test_start_refuses_to_run_over_a_session(project: Project) -> None:
    start(project)

    with pytest.raises(UpgradeSessionError, match="already in progress"):
        start(project)


def test_start_refuses_a_package_manager_without_session_support(project: Project) -> None:
    project.manager.supports_upgrade_session = False

    with pytest.raises(UpgradeSessionError, match="does not support npm"):
        start(project)
    assert not store.exists(project.root)


def test_start_with_nothing_to_upgrade_writes_no_session(project: Project) -> None:
    project.targets = project.installed()

    assert start(project).outcome is Outcome.NOTHING_TO_DO
    assert not store.exists(project.root)


def test_start_refuses_when_the_tests_already_fail(project: Project) -> None:
    with pytest.raises(UpgradeSessionError, match="already fails"):
        start(project, test_command="echo broken; false")
    assert not store.exists(project.root)


def test_apply_installs_the_step_and_keeps_it_when_tests_pass(project: Project) -> None:
    start(project, test_command="true")

    view = engine.apply(env_for(project), str(project.root))

    assert current(view) == (1, StepStatus.AWAITING_REVIEW)
    assert project.installed() == {"vite": "2.0.0", "zod": "1.0.0"}
    assert not view.attention
    assert "continue" in view.commands


def test_continue_completes_the_step_and_previews_the_next(project: Project) -> None:
    start(project, test_command="true")
    engine.apply(env_for(project), str(project.root))

    view = engine.accept(env_for(project), str(project.root))

    assert current(view) == (2, StepStatus.PENDING)
    assert [p.name for p in cast(Any, view.step).packages] == ["zod"]


def test_the_last_continue_ends_the_session(project: Project) -> None:
    start(project, limit=1)
    engine.apply(env_for(project), str(project.root))

    view = engine.accept(env_for(project), str(project.root))

    assert view.outcome is Outcome.COMPLETED
    assert not (project.root / ".ossiq").exists()


def test_failing_tests_need_attention_and_block_continue(project: Project) -> None:
    start(project, test_command=BREAKS_ON_UPGRADE)

    view = engine.apply(env_for(project), str(project.root))

    assert current(view) == (1, StepStatus.AWAITING_REFACTOR)
    assert view.attention
    assert "continue" not in view.commands
    refused = engine.accept(env_for(project), str(project.root))
    assert refused.attention and current(refused) == (1, StepStatus.AWAITING_REFACTOR)


def test_tests_can_be_rerun_until_they_pass(project: Project) -> None:
    start(project, test_command=FIXABLE)
    engine.apply(env_for(project), str(project.root))

    (project.root / "fixed").write_text("")
    view = engine.run_tests(env_for(project), str(project.root))

    assert current(view) == (1, StepStatus.AWAITING_REVIEW)
    assert cast(Any, view.step).last_run.exit_code == 0


def test_rollback_restores_the_files_and_shows_the_same_step_again(project: Project) -> None:
    start(project, test_command=BREAKS_ON_UPGRADE)
    engine.apply(env_for(project), str(project.root))

    view = engine.rollback(env_for(project), str(project.root))

    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert project.manager.synced == 1
    assert current(view) == (1, StepStatus.PENDING)
    assert "working tree" in (view.message or "")


def test_skip_rolls_an_applied_step_back_and_moves_on(project: Project) -> None:
    start(project, test_command=BREAKS_ON_UPGRADE)
    engine.apply(env_for(project), str(project.root))

    view = engine.skip(env_for(project), str(project.root), "breaks the build")

    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert current(view) == (2, StepStatus.PENDING)
    assert cast(Any, view.session).steps[0].note == "breaks the build"


def test_skip_a_pending_step_touches_no_file(project: Project) -> None:
    start(project)

    view = engine.skip(env_for(project), str(project.root))

    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert project.manager.synced == 0
    assert current(view) == (2, StepStatus.PENDING)


def test_a_refused_install_restores_the_files_and_leaves_the_step_pending(project: Project) -> None:
    start(project)
    project.manager.refuse = True

    view = engine.apply(env_for(project), str(project.root))

    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert current(view) == (1, StepStatus.PENDING)
    assert view.attention and "refused" in (view.message or "")


def test_apply_will_not_install_a_version_the_user_has_not_seen(project: Project) -> None:
    start(project)
    project.targets["vite"] = "2.1.0"

    view = engine.apply(env_for(project), str(project.root))

    assert project.installed()["vite"] == "1.0.0"
    assert view.attention
    assert cast(Any, view.step).packages[0].target == "2.1.0"


def test_a_step_that_is_no_longer_recommended_is_skipped(project: Project) -> None:
    start(project)
    project.targets["vite"] = "1.0.0"

    view = engine.status(env_for(project), str(project.root))

    assert current(view) == (2, StepStatus.PENDING)
    assert "no longer recommended" in (view.message or "")


def test_apply_needs_a_pending_step(project: Project) -> None:
    start(project)
    engine.apply(env_for(project), str(project.root))

    with pytest.raises(UpgradeSessionError, match="PENDING"):
        engine.apply(env_for(project), str(project.root))


def test_finish_keeps_the_applied_step_and_ends_the_session(project: Project) -> None:
    start(project, test_command="true")
    engine.apply(env_for(project), str(project.root))

    view = engine.finish(env_for(project), str(project.root))

    assert view.outcome is Outcome.FINISHED
    assert project.installed()["vite"] == "2.0.0"
    assert not (project.root / ".ossiq").exists()


def test_finish_refuses_while_the_tests_fail(project: Project) -> None:
    start(project, test_command=BREAKS_ON_UPGRADE)
    engine.apply(env_for(project), str(project.root))

    view = engine.finish(env_for(project), str(project.root))

    assert view.attention and store.exists(project.root)


def test_abort_restores_what_start_saw_and_syncs_the_environment(project: Project) -> None:
    start(project, test_command="true")
    engine.apply(env_for(project), str(project.root))
    engine.accept(env_for(project), str(project.root))
    engine.apply(env_for(project), str(project.root))

    view = engine.abort(env_for(project), str(project.root))

    assert view.outcome is Outcome.ABORTED
    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert project.manager.synced == 1
    assert not (project.root / ".ossiq").exists()


def test_abort_before_anything_was_applied_does_not_reinstall(project: Project) -> None:
    start(project)

    engine.abort(env_for(project), str(project.root))

    assert project.manager.synced == 0


def test_status_survives_a_new_process(project: Project) -> None:
    start(project, test_command=BREAKS_ON_UPGRADE)
    engine.apply(env_for(project), str(project.root))

    view = engine.status(env_for(project), str(project.root))

    assert current(view) == (1, StepStatus.AWAITING_REFACTOR)
    assert "test" in view.commands


def test_changelog_fetches_the_range_of_each_direct_package_of_the_step(project: Project) -> None:
    from ossiq.domain.changelog import ChangelogStatus, RangeChangelog

    asked: list[tuple[str, str, str, str]] = []

    def fetch(ecosystem: str, package: Any) -> RangeChangelog:
        asked.append((ecosystem, package.registry_name, package.current, package.target))
        return RangeChangelog(ChangelogStatus.OK, "api", "web")

    start(project)
    env = UpgradeEnv(settings=cast(Any, None), plan=project.plan, fetch_changelog=fetch)

    view = engine.changelog(env, str(project.root))

    assert asked == [("npm", "vite", "1.0.0", "2.0.0")]
    assert [package.name for package, _ in view.changelogs] == ["vite"]
    assert view.commands == engine.PENDING_COMMANDS


def test_changelog_without_a_fetcher_shows_nothing_rather_than_failing(project: Project) -> None:
    start(project)

    assert engine.changelog(env_for(project), str(project.root)).changelogs == ()


def test_web_links_name_the_page_for_each_direct_package_without_fetching(project: Project) -> None:
    start(project)

    ((package, url),) = engine.web_links(str(project.root))

    assert package.name == "vite"
    assert url == "https://changelogiq.dev/?ecosystem=npm&package=vite&from=1.0.0&to=2.0.0"


def test_start_takes_the_limit_and_test_command_from_the_project_file(project: Project) -> None:
    (project.root / ".git").mkdir()
    (project.root / ".ossiq.yaml").write_text('version: 1\nupgrade:\n  limit: 1\n  test-command: "true"\n')

    view = start(project)

    assert view.session is not None
    assert len(view.session.steps) == 1 and view.session.test_command == "true"


def test_a_flag_beats_the_project_file(project: Project) -> None:
    (project.root / ".git").mkdir()
    (project.root / ".ossiq.yaml").write_text('version: 1\nupgrade:\n  limit: 1\n  test-command: "false"\n')

    view = start(project, limit=2, test_command="true")

    assert view.session is not None
    assert len(view.session.steps) == 2 and view.session.test_command == "true"
