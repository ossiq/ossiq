"""The upgrade state machine, driven on real files with a fake package manager and real shell test commands."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, cast

import pytest

from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.domain.update_plan import PeerRepair
from ossiq.messages import HELP_PLAN_NO_RECOMMENDATIONS, HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER
from ossiq.service.upgrade import engine, store
from ossiq.service.upgrade.engine import UpgradeEnv
from ossiq.service.upgrade.models import StepStatus
from ossiq.service.upgrade.view import Outcome, UpgradeView
from ossiq.strategy.pyramid import UpdateStrategy
from tests.service.upgrade.helpers import (
    BREAKS_ON_UPGRADE,
    FIXABLE,
    Project,
    env_for,
    make_project,
    options,
    start,
)


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
        start(project, test_command="echo broken && false")
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


def test_continue_on_a_pending_step_shows_it_and_installs_nothing(project: Project) -> None:
    start(project)

    view = engine.accept(env_for(project), str(project.root))

    assert current(view) == (1, StepStatus.PENDING)
    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}


def test_the_last_continue_keeps_the_session_open_for_finish_or_abort(project: Project) -> None:
    start(project, limit=1)
    engine.apply(env_for(project), str(project.root))

    view = engine.accept(env_for(project), str(project.root))

    assert view.outcome is Outcome.COMPLETED
    assert view.commands == ("finish", "abort")
    assert store.exists(project.root)
    assert engine.status(env_for(project), str(project.root)).outcome is Outcome.COMPLETED

    assert engine.finish(env_for(project), str(project.root)).outcome is Outcome.FINISHED
    assert not store.exists(project.root)


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


def test_a_move_the_plan_now_ties_to_the_step_joins_it_and_its_own_step_skips(project: Project) -> None:
    start(project)
    project.together = [("vite@1.0.0", "zod@1.0.0")]

    view = engine.apply(env_for(project), str(project.root))

    assert view.attention
    assert [p.name for p in cast(Any, view.step).packages] == ["vite", "zod"]
    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}

    engine.apply(env_for(project), str(project.root))
    assert project.installed() == {"vite": "2.0.0", "zod": "2.0.0"}

    view = engine.accept(env_for(project), str(project.root))
    assert view.outcome is Outcome.COMPLETED


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


def test_a_peer_repair_is_a_step_that_installs_only_when_its_turn_comes(project: Project) -> None:
    project.repairs = [PeerRepair("peer", "~1.2.0", False, ("vite",))]

    view = start(project, test_command="true")

    assert [[p.name for p in s.packages] for s in cast(Any, view.session).steps] == [["vite"], ["peer"], ["zod"]]
    engine.apply(env_for(project), str(project.root))
    assert "peer" not in project.installed()

    engine.accept(env_for(project), str(project.root))
    engine.apply(env_for(project), str(project.root))
    assert project.installed()["peer"] == "~1.2.0"


def test_a_repair_with_a_new_range_is_shown_again_and_one_the_plan_dropped_is_skipped(project: Project) -> None:
    project.repairs = [PeerRepair("peer", "~1.2.0", False, ("vite",))]
    start(project, test_command="true")
    engine.apply(env_for(project), str(project.root))
    engine.accept(env_for(project), str(project.root))

    project.repairs = [PeerRepair("peer", "~1.3.0", False, ("vite",))]
    view = engine.apply(env_for(project), str(project.root))

    assert view.attention and "peer" not in project.installed()
    assert cast(Any, view.step).packages[0].target == "~1.3.0"

    project.repairs = []
    view = engine.status(env_for(project), str(project.root))

    assert current(view) == (3, StepStatus.PENDING)
    assert "no longer recommended" in (view.message or "")


def test_abort_after_every_step_is_done_puts_back_what_start_saw(project: Project) -> None:
    start(project, test_command="true")
    for _ in range(2):
        engine.apply(env_for(project), str(project.root))
        engine.accept(env_for(project), str(project.root))

    view = engine.abort(env_for(project), str(project.root))

    assert view.outcome is Outcome.ABORTED
    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}
    assert project.manager.synced == 1
    assert not store.exists(project.root)


def test_plan_lists_every_step_with_the_plan_and_writes_nothing(project: Project) -> None:
    view = engine.plan(env_for(project), options(project))

    assert view.outcome is Outcome.PLANNED
    assert [[p.name for p in s.packages] for s in cast(Any, view.session).steps] == [["vite"], ["zod"]]
    assert view.step is None and view.commands == () and view.plan is not None
    assert not (project.root / ".ossiq").exists()
    assert project.installed() == {"vite": "1.0.0", "zod": "1.0.0"}


def test_plan_ignores_the_project_file_limit_that_start_honours(project: Project) -> None:
    (project.root / ".git").mkdir()
    (project.root / ".ossiq.yaml").write_text("version: 1\nupgrade:\n  limit: 1\n")

    assert len(cast(Any, engine.plan(env_for(project), options(project)).session).steps) == 2
    assert len(cast(Any, start(project).session).steps) == 1


def test_plan_and_start_reuse_a_plan_they_are_given(project: Project) -> None:
    planned = project.plan(options(project))

    def never(_: Any) -> Any:
        raise AssertionError("planned twice")

    env = UpgradeEnv(settings=cast(Any, None), plan=never)
    assert engine.plan(env, options(project), planned=planned).outcome is Outcome.PLANNED
    assert engine.start(env, options(project), planned=planned).outcome is Outcome.IN_PROGRESS


def test_plan_with_nothing_to_move_says_so_and_still_carries_the_plan(project: Project) -> None:
    project.targets = project.installed()

    view = engine.plan(env_for(project), options(project))

    assert (view.outcome, view.message) == (Outcome.NOTHING_TO_DO, HELP_PLAN_NO_RECOMMENDATIONS)
    assert view.plan is not None
    assert not (project.root / ".ossiq").exists()


def test_the_message_for_nothing_to_move_names_a_tier_other_than_the_default(project: Project) -> None:
    project.targets = project.installed()
    project.strategy = UpdateStrategy.SECURITY

    view = engine.plan(env_for(project), options(project))

    assert view.message == HELP_PLAN_NO_RECOMMENDATIONS_FOR_TIER.format(tier="security")


def test_plan_refuses_a_package_manager_without_session_support(project: Project) -> None:
    project.manager.supports_upgrade_session = False

    with pytest.raises(UpgradeSessionError, match="does not support npm"):
        engine.plan(env_for(project), options(project))


def test_start_carries_the_plan_for_its_holds_and_a_later_status_does_not(project: Project) -> None:
    assert start(project).plan is not None
    assert engine.status(env_for(project), str(project.root)).plan is None


def test_start_over_a_session_refuses_before_it_scans(project: Project) -> None:
    start(project)

    def never(_: Any) -> Any:
        raise AssertionError("scanned")

    with pytest.raises(UpgradeSessionError, match="already in progress"):
        engine.start(UpgradeEnv(settings=cast(Any, None), plan=never), options(project))


def test_a_changed_flag_on_a_move_is_not_a_new_version_to_review(project: Project) -> None:
    start(project)
    session = store.load(project.root)
    stale = dataclasses.replace(session.steps[0].packages[0], is_security=True, needs_ack=True)
    store.save(project.root, session.with_step(dataclasses.replace(session.steps[0], packages=(stale,))))

    view = engine.apply(env_for(project), str(project.root))

    assert project.installed()["vite"] == "2.0.0" and not view.attention
