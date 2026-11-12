"""What an upgrade session remembers between commands: its steps, their states and the last test run."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ossiq.domain.exceptions import UpgradeSessionError
from ossiq.service.update.models import PlanOptions
from ossiq.strategy.pyramid import UpdateStrategy

SESSION_VERSION = 1


class StepStatus(StrEnum):
    PENDING = "PENDING"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    AWAITING_REFACTOR = "AWAITING_REFACTOR"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"


DONE = (StepStatus.COMPLETED, StepStatus.SKIPPED)
APPLIED = (StepStatus.AWAITING_REVIEW, StepStatus.AWAITING_REFACTOR)


@dataclass(frozen=True)
class StepPackage:
    """One package a step moves."""

    move_key: str
    """`UpdateEntry.move_key`: how the step finds this package in a fresh plan."""
    name: str
    """The manifest key, which an npm alias makes differ from the registry name."""
    registry_name: str
    is_direct: bool
    current: str
    target: str
    """The version the last preview showed; `apply` refuses to install a different one."""


@dataclass(frozen=True)
class CommandRun:
    """The outcome of the test command."""

    exit_code: int
    ran_at: str
    output_tail: str


@dataclass(frozen=True)
class UpgradeStep:
    number: int
    status: StepStatus
    packages: tuple[StepPackage, ...]
    last_run: CommandRun | None = None
    note: str | None = None
    """Why the step was skipped."""


@dataclass(frozen=True)
class UpgradeSession:
    session_id: str
    created_at: str
    package_manager: str
    registry: str
    """"npm" or "pypi": where changelogs are looked up."""
    options: PlanOptions
    test_command: str | None
    snapshot_files: tuple[str, ...]
    steps: tuple[UpgradeStep, ...]
    peer_repairs: bool
    """Whether the last step also carries the plan's peer repairs, which describe the final tree."""
    baseline: CommandRun | None = None

    @property
    def current(self) -> UpgradeStep | None:
        """The first step that is not finished, or None when every step is."""
        return next((step for step in self.steps if step.status not in DONE), None)

    @property
    def is_last(self) -> bool:
        current = self.current
        return current is not None and current.number == self.steps[-1].number

    def with_step(self, step: UpgradeStep) -> UpgradeSession:
        return dataclasses.replace(self, steps=tuple(step if s.number == step.number else s for s in self.steps))


def session_to_json(session: UpgradeSession) -> str:
    return json.dumps({"version": SESSION_VERSION, **dataclasses.asdict(session)}, indent=2) + "\n"


def run_from_dict(data: dict[str, Any] | None) -> CommandRun | None:
    return CommandRun(**data) if data else None


def options_from_dict(data: dict[str, Any]) -> PlanOptions:
    return PlanOptions(
        project_path=data["project_path"],
        registry_type=data["registry_type"],
        allow_prerelease=data["allow_prerelease"],
        allow_prerelease_packages=tuple(data["allow_prerelease_packages"]),
        production=data["production"],
        update_strategy=UpdateStrategy(data["update_strategy"]),
        strategy_overrides=tuple((name, UpdateStrategy(tier)) for name, tier in data["strategy_overrides"]),
        ignore_packages=tuple(data["ignore_packages"]),
        pin_all=data["pin_all"],
        rewrite_versions=data["rewrite_versions"],
        overrides=tuple((name, version) for name, version in data["overrides"]),
        allow_partial=data["allow_partial"],
    )


def session_from_json(text: str) -> UpgradeSession:
    """Read a session file.

    Raises:
        UpgradeSessionError: The text is not a session this version of OSS IQ wrote.
    """
    try:
        data = json.loads(text)
        if data["version"] != SESSION_VERSION:
            raise UpgradeSessionError(
                f"The session file is version {data['version']}; this OSS IQ reads version {SESSION_VERSION}.",
                hint="Run `ossiq upgrade abort` with the OSS IQ that started the session, or delete .ossiq/.",
            )
        steps = tuple(
            UpgradeStep(
                number=step["number"],
                status=StepStatus(step["status"]),
                packages=tuple(StepPackage(**package) for package in step["packages"]),
                last_run=run_from_dict(step["last_run"]),
                note=step["note"],
            )
            for step in data["steps"]
        )
        return UpgradeSession(
            session_id=data["session_id"],
            created_at=data["created_at"],
            package_manager=data["package_manager"],
            registry=data["registry"],
            options=options_from_dict(data["options"]),
            test_command=data["test_command"],
            snapshot_files=tuple(data["snapshot_files"]),
            steps=steps,
            peer_repairs=data["peer_repairs"],
            baseline=run_from_dict(data["baseline"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise UpgradeSessionError(
            f"The session file is unreadable ({exc.__class__.__name__}: {exc}).",
            hint="Run `ossiq upgrade abort` to restore the project files, or delete .ossiq/ to forget the session.",
        ) from exc
