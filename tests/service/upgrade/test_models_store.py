from __future__ import annotations

import pytest

from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.service.update.models import PlanOptions
from ossiq.service.upgrade import store
from ossiq.service.upgrade.models import (
    CommandRun,
    StepPackage,
    StepStatus,
    UpgradeSession,
    UpgradeStep,
    session_from_json,
    session_to_json,
)
from ossiq.strategy.pyramid import UpdateStrategy


def package(name: str = "zod") -> StepPackage:
    return StepPackage(
        move_key=f"{name}@1.0.0", name=name, registry_name=name, is_direct=True, current="1.0.0", target="2.0.0"
    )


def session(*statuses: StepStatus) -> UpgradeSession:
    steps = tuple(UpgradeStep(number=i + 1, status=s, packages=(package(f"p{i}"),)) for i, s in enumerate(statuses))
    return UpgradeSession(
        session_id="seq_1",
        created_at="2026-11-07T11:00:00Z",
        package_manager="npm",
        registry="npm",
        options=PlanOptions(
            project_path="/p",
            registry_type="npm",
            update_strategy=UpdateStrategy.LATEST,
            strategy_overrides=(("zod", UpdateStrategy.SECURITY),),
            overrides=(("left-pad", "1.3.0"),),
        ),
        test_command="npm test",
        snapshot_files=("package.json", "package-lock.json"),
        steps=steps,
        peer_repairs=True,
        baseline=CommandRun(exit_code=0, ran_at="2026-11-07T11:00:05Z", output_tail="ok"),
    )


def test_a_session_survives_a_round_trip_through_json() -> None:
    original = session(StepStatus.COMPLETED, StepStatus.PENDING)

    assert session_from_json(session_to_json(original)) == original


def test_the_current_step_is_the_first_one_not_finished() -> None:
    current = session(
        StepStatus.COMPLETED, StepStatus.SKIPPED, StepStatus.AWAITING_REFACTOR, StepStatus.PENDING
    ).current

    assert current is not None and current.number == 3


def test_no_current_step_once_every_step_is_finished() -> None:
    assert session(StepStatus.COMPLETED, StepStatus.SKIPPED).current is None


def test_a_file_that_is_not_a_session_names_the_way_out() -> None:
    with pytest.raises(UpgradeSessionError, match="unreadable") as raised:
        session_from_json('{"version": 1}')

    assert "abort" in (raised.value.hint or "")


def test_a_session_from_another_version_is_refused() -> None:
    with pytest.raises(UpgradeSessionError, match="version 9"):
        session_from_json('{"version": 9}')


def test_load_without_a_session_says_how_to_start_one(tmp_path) -> None:
    with pytest.raises(UpgradeSessionError, match="No upgrade session"):
        store.load(tmp_path)


def test_save_keeps_the_state_out_of_version_control(tmp_path) -> None:
    store.save(tmp_path, session(StepStatus.PENDING))

    assert (tmp_path / ".ossiq" / ".gitignore").read_text() == "*\n"
    assert store.load(tmp_path) == session(StepStatus.PENDING)


def test_restore_puts_files_back_and_removes_ones_that_did_not_exist(tmp_path) -> None:
    (tmp_path / "package.json").write_text("before")
    store.snapshot(tmp_path, "step-1", ["package.json", "package-lock.json"])

    (tmp_path / "package.json").write_text("after")
    (tmp_path / "package-lock.json").write_text("created by the step")
    store.restore(tmp_path, "step-1", ["package.json", "package-lock.json"])

    assert (tmp_path / "package.json").read_text() == "before"
    assert not (tmp_path / "package-lock.json").exists()


def test_end_removes_the_state_directory(tmp_path) -> None:
    store.save(tmp_path, session(StepStatus.PENDING))
    store.snapshot(tmp_path, store.START, ["package.json"])

    store.end(tmp_path)

    assert not (tmp_path / ".ossiq").exists()


def test_end_leaves_a_directory_that_holds_something_else(tmp_path) -> None:
    store.save(tmp_path, session(StepStatus.PENDING))
    (tmp_path / ".ossiq" / "mine.txt").write_text("not yours")

    store.end(tmp_path)

    assert [p.name for p in (tmp_path / ".ossiq").iterdir()] == ["mine.txt"]
