"""The step-by-step upgrade engine: each function takes one subcommand from one session state to the next.

The session lives in `<project>/.ossiq/`, so every function starts from the file, not from memory. Files
OSS IQ writes are snapshotted before a step and put back by `rollback`, `skip` and `abort`; commits are
the user's own.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ossiq.adapters.api_interfaces import AbstractPackageManagerApi
from ossiq.adapters.package_managers.api import create_package_managers
from ossiq.clients.client_changelogiq import web_url
from ossiq.domain.changelog import RangeChangelog
from ossiq.domain.exceptions import (
    PackageManagerExecutionError,
    PackageManagerUpdateIncomplete,
    UpgradeSessionError,
)
from ossiq.domain.update_plan import UpdatePlan
from ossiq.service.project.models import ScanResult
from ossiq.service.update.models import PlanOptions
from ossiq.service.upgrade import store
from ossiq.service.upgrade.models import APPLIED, CommandRun, StepPackage, StepStatus, UpgradeSession, UpgradeStep
from ossiq.service.upgrade.preview import ChangelogFetcher, build_preview
from ossiq.service.upgrade.queue import build_queue
from ossiq.service.upgrade.runner import run_command
from ossiq.service.upgrade.view import Outcome, UpgradeView
from ossiq.settings import Settings
from ossiq.sources.project_config import load_upgrade_config
from ossiq.sources.project_sources import ProjectSources

Planned = tuple[ProjectSources, ScanResult, UpdatePlan]

PENDING_COMMANDS = ("changelog", "apply", "skip", "finish", "abort")
FAILING_COMMANDS = ("test", "rollback", "skip", "abort")
PASSING_COMMANDS = ("test", "rollback", "continue", "skip", "finish", "abort")
BASELINE_TAIL_LINES = 30
ROLLBACK_NOTE = "Code you changed to fit the new version is still in your working tree."
FAILING_NOTE = "The tests are failing. Fix the code and run test, or roll the step back or skip it."


@dataclass(frozen=True)
class UpgradeEnv:
    """What the engine needs from its caller; planning is injected so only the console shows scan progress."""

    settings: Settings
    plan: Callable[[PlanOptions], Planned]
    on_line: Callable[[str], None] | None = None
    """Receives the test command's output as it arrives."""
    fetch_changelog: ChangelogFetcher | None = None
    """Looks up changelogs; None leaves them out of previews and makes `changelog` show nothing."""


def find_manager(settings: Settings, root: Path, name: str) -> AbstractPackageManagerApi:
    """The package manager the session started with, found without scanning the project."""
    for manager in create_package_managers(str(root), settings):
        if manager.package_manager_type.name == name:
            return manager
    raise UpgradeSessionError(
        f"The project no longer looks like a {name} project.",
        hint="Run `ossiq upgrade abort` from the project the session started in.",
    )


def require_step(session: UpgradeSession, *statuses: StepStatus) -> UpgradeStep:
    step = session.current
    if step is None or step.status not in statuses:
        wanted = " or ".join(s.value for s in statuses)
        where = "no step is open" if step is None else f"step {step.number} is {step.status.value}"
        raise UpgradeSessionError(
            f"This needs a step that is {wanted}, but {where}.",
            hint="Run `ossiq upgrade status` to see what can be done now.",
        )
    return step


def sync_step(step: UpgradeStep, targets: Mapping[str, str]) -> UpgradeStep:
    """Bring a step's targets in line with a fresh plan's; a step left with nothing to move is skipped.

    An earlier step may already have moved a package, and a newer release may have appeared.
    """
    kept = tuple(
        dataclasses.replace(package, target=targets[package.move_key])
        for package in step.packages
        if package.move_key in targets
    )
    if not kept:
        return dataclasses.replace(step, status=StepStatus.SKIPPED, note="no longer recommended")
    return dataclasses.replace(step, packages=kept)


def move_targets(plan: UpdatePlan) -> dict[str, str]:
    return {entry.move_key: entry.recommended_version for entry in plan.all_entries}


def step_snapshot(step: UpgradeStep) -> str:
    return f"step-{step.number}"


def pending_view(
    env: UpgradeEnv,
    root: Path,
    session: UpgradeSession,
    planned: Planned | None = None,
    *,
    message: str | None = None,
    attention: bool = False,
) -> UpgradeView:
    """Describe the session's current step, preview and all, or end the session when none is left."""
    sources, scan, plan = planned or env.plan(session.options)
    targets = move_targets(plan)
    notes = []
    while (step := session.current) is not None:
        synced = sync_step(step, targets)
        session = session.with_step(synced)
        if synced.status is not StepStatus.SKIPPED:
            break
        notes.append(f"Step {step.number} is no longer recommended; skipped.")
    if message:
        notes.append(message)
    message = " ".join(notes) or None

    step = session.current
    if step is None:
        store.end(root)
        return UpgradeView(Outcome.COMPLETED, session, None, message=message or "Every step is done.")
    store.save(root, session)
    return UpgradeView(
        Outcome.IN_PROGRESS,
        session,
        step,
        preview=build_preview(sources, scan, step, env.fetch_changelog),
        commands=PENDING_COMMANDS,
        message=message,
        attention=attention,
    )


def applied_view(session: UpgradeSession, *, message: str | None = None, attention: bool = False) -> UpgradeView:
    step = session.current
    assert step is not None
    return UpgradeView(
        Outcome.IN_PROGRESS, session, step, commands=next_commands(session, step), message=message, attention=attention
    )


def next_commands(session: UpgradeSession, step: UpgradeStep) -> tuple[str, ...]:
    """The subcommands that make sense for *step* in its state."""
    if step.status is StepStatus.PENDING:
        return PENDING_COMMANDS
    commands = FAILING_COMMANDS if step.status is StepStatus.AWAITING_REFACTOR else PASSING_COMMANDS
    return commands if session.test_command else tuple(c for c in commands if c != "test")


def start(
    env: UpgradeEnv,
    options: PlanOptions,
    *,
    package: str | None = None,
    limit: int | None = None,
    test_command: str | None = None,
) -> UpgradeView:
    """Plan the project, queue its updates as steps and show the first one.

    Args:
        env: Planning, output and settings.
        options: The project and the tier to plan with; kept so every later step re-plans the same way.
        package: Queue only this direct package.
        limit: Queue only the first this many steps; the project's `upgrade.limit` when None.
        test_command: Run once now, as a baseline, and after every applied step; the project's
            `upgrade.test-command` when None.

    Returns:
        The first step's preview, or a NOTHING_TO_DO view when the plan has no moves.

    Raises:
        UpgradeSessionError: A session exists, the package manager is unsupported, or the test
            command already fails.
    """
    root = Path(options.project_path)
    config = load_upgrade_config(root)
    limit = limit if limit is not None else config.limit
    test_command = test_command or config.test_command
    if store.exists(root):
        raise UpgradeSessionError(
            "An upgrade session is already in progress here.",
            hint="Run `ossiq upgrade status` to resume it, or `ossiq upgrade abort` to discard it.",
        )
    planned = env.plan(options)
    sources, scan, plan = planned
    manager = sources.packages_manager
    name = manager.package_manager_type.name
    if not manager.supports_upgrade_session:
        raise UpgradeSessionError(
            f"`ossiq upgrade` does not support {name} projects yet.",
            hint="It works with npm, pnpm and uv. `ossiq apply` still applies the whole plan at once.",
        )
    epss = {r.package_name: r.epss or 0.0 for r in scan.production_packages + scan.optional_packages}
    steps, peer_repairs = build_queue(
        plan,
        epss,
        lambda current, target: sources.packages_registry.difference_versions(current, target).diff_index,
        package=package,
        limit=limit,
    )
    if not steps:
        return UpgradeView(Outcome.NOTHING_TO_DO, None, None, message="Nothing to upgrade at this tier.")

    baseline = None
    if test_command:
        baseline = run_command(test_command, root, env.on_line)
        if baseline.exit_code != 0:
            tail = "\n".join(baseline.output_tail.splitlines()[-BASELINE_TAIL_LINES:])
            raise UpgradeSessionError(
                f"The test command already fails before any upgrade (exit {baseline.exit_code}). Last output:\n{tail}",
                hint="Fix the failing tests first, or start without a test command.",
            )

    session = UpgradeSession(
        session_id=f"seq_{uuid.uuid4().hex[:10]}",
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        package_manager=name,
        registry=scan.packages_registry.lower(),
        options=options,
        test_command=test_command,
        snapshot_files=manager.snapshot_files(),
        steps=tuple(UpgradeStep(number=i, status=StepStatus.PENDING, packages=s) for i, s in enumerate(steps, 1)),
        peer_repairs=peer_repairs,
        baseline=baseline,
    )
    store.snapshot(root, store.START, session.snapshot_files)
    store.save(root, session)
    return pending_view(env, root, session, planned)


def status(env: UpgradeEnv, path: str) -> UpgradeView:
    """Show the current step: its preview while pending, its test result once applied."""
    root = Path(path)
    session = store.load(root)
    step = session.current
    if step is None or step.status is StepStatus.PENDING:
        return pending_view(env, root, session)
    return applied_view(session)


def changelog(env: UpgradeEnv, path: str) -> UpgradeView:
    """Fetch the full range changelog of each direct package of the current step.

    Raises:
        UpgradeSessionError: No step is open.
    """
    session = store.load(Path(path))
    step = require_step(session, StepStatus.PENDING, *APPLIED)
    found: tuple[tuple[StepPackage, RangeChangelog], ...] = ()
    if env.fetch_changelog is not None:
        found = tuple((p, env.fetch_changelog(session.registry, p)) for p in step.packages if p.is_direct)
    return UpgradeView(Outcome.IN_PROGRESS, session, step, commands=next_commands(session, step), changelogs=found)


def web_links(path: str) -> tuple[tuple[StepPackage, str], ...]:
    """Where to read the current step's changelogs on the web; nothing is fetched to get there.

    Raises:
        UpgradeSessionError: No step is open.
    """
    session = store.load(Path(path))
    step = require_step(session, StepStatus.PENDING, *APPLIED)
    return tuple(
        (p, web_url(session.registry, p.registry_name, p.current, p.target)) for p in step.packages if p.is_direct
    )


def apply(env: UpgradeEnv, path: str) -> UpgradeView:
    """Install the current step, then run the tests.

    Plans again first: if a release appeared since the preview, the step is shown again rather than
    installing something the user has not seen.

    Raises:
        UpgradeSessionError: The current step is not pending.
    """
    root = Path(path)
    session = store.load(root)
    step = require_step(session, StepStatus.PENDING)
    planned = env.plan(session.options)
    sources, _, plan = planned

    synced = sync_step(step, move_targets(plan))
    if synced != step:
        return pending_view(
            env,
            root,
            session.with_step(synced),
            planned,
            message="The versions to install changed since the preview. Review them, then run apply again.",
            attention=True,
        )

    manager = sources.packages_manager
    store.snapshot(root, step_snapshot(step), session.snapshot_files)
    step_plan = plan.only(
        {p.move_key for p in step.packages}, with_peer_repairs=session.peer_repairs and session.is_last
    )
    try:
        manager.execute_update(step_plan)
    except (PackageManagerExecutionError, PackageManagerUpdateIncomplete) as exc:
        undo_step(root, session, step, manager)
        return pending_view(
            env, root, session, planned, message=f"The install was refused. {exc.render()}", attention=True
        )

    run = run_command(session.test_command, root, env.on_line) if session.test_command else None
    return record_run(root, session, step, run)


def record_run(root: Path, session: UpgradeSession, step: UpgradeStep, run: CommandRun | None) -> UpgradeView:
    failed = run is not None and run.exit_code != 0
    session = session.with_step(
        dataclasses.replace(
            step, status=StepStatus.AWAITING_REFACTOR if failed else StepStatus.AWAITING_REVIEW, last_run=run
        )
    )
    store.save(root, session)
    if run is None:
        message = "Installed. No test command is set, so nothing was checked."
    elif failed:
        message = f"Installed, but the tests failed (exit {run.exit_code})."
    else:
        message = "Installed. The tests passed."
    return applied_view(session, message=message, attention=failed)


def run_tests(env: UpgradeEnv, path: str) -> UpgradeView:
    """Run the test command again on the applied step, e.g. after fixing the code.

    Raises:
        UpgradeSessionError: The step is not applied, or the session has no test command.
    """
    root = Path(path)
    session = store.load(root)
    step = require_step(session, *APPLIED)
    if not session.test_command:
        raise UpgradeSessionError(
            "This session has no test command.",
            hint="Start the session with --test-command, or set upgrade.test-command in .ossiq.yaml.",
        )
    return record_run(root, session, step, run_command(session.test_command, root, env.on_line))


def undo_step(root: Path, session: UpgradeSession, step: UpgradeStep, manager: AbstractPackageManagerApi) -> None:
    """Put the step's files back and make the installed packages match them."""
    snapshot = step_snapshot(step)
    store.restore(root, snapshot, session.snapshot_files)
    store.drop_snapshot(root, snapshot)
    manager.sync_environment()


def rollback(env: UpgradeEnv, path: str) -> UpgradeView:
    """Undo the applied step and show its preview again, to choose once more.

    Raises:
        UpgradeSessionError: The step is not applied.
    """
    root = Path(path)
    session = store.load(root)
    step = require_step(session, *APPLIED)
    undo_step(root, session, step, find_manager(env.settings, root, session.package_manager))
    session = session.with_step(dataclasses.replace(step, status=StepStatus.PENDING, last_run=None))
    return pending_view(env, root, session, message=f"Step {step.number} is rolled back. {ROLLBACK_NOTE}")


def skip(env: UpgradeEnv, path: str, reason: str | None = None) -> UpgradeView:
    """Leave the current step out, rolling it back first if it was applied.

    Raises:
        UpgradeSessionError: No step is open.
    """
    root = Path(path)
    session = store.load(root)
    step = require_step(session, StepStatus.PENDING, *APPLIED)
    if step.status in APPLIED:
        undo_step(root, session, step, find_manager(env.settings, root, session.package_manager))
    session = session.with_step(
        dataclasses.replace(step, status=StepStatus.SKIPPED, note=reason or "skipped", last_run=None)
    )
    return pending_view(env, root, session, message=f"Step {step.number} skipped.")


def accept(env: UpgradeEnv, path: str) -> UpgradeView:
    """Keep the applied step and move to the next one.

    A step whose tests fail cannot be kept: it is shown again with what it needs.

    Raises:
        UpgradeSessionError: The step is not applied.
    """
    root = Path(path)
    session = store.load(root)
    step = require_step(session, *APPLIED)
    if step.status is StepStatus.AWAITING_REFACTOR:
        return applied_view(
            session,
            message=FAILING_NOTE,
            attention=True,
        )
    store.drop_snapshot(root, step_snapshot(step))
    session = session.with_step(dataclasses.replace(step, status=StepStatus.COMPLETED))
    return pending_view(env, root, session, message=f"Step {step.number} done.")


def finish(env: UpgradeEnv, path: str) -> UpgradeView:
    """Stop here and keep what is installed. An applied step with passing tests counts as kept."""
    root = Path(path)
    session = store.load(root)
    step = session.current
    if step is not None and step.status is StepStatus.AWAITING_REFACTOR:
        return applied_view(
            session,
            message=FAILING_NOTE,
            attention=True,
        )
    store.end(root)
    done = sum(1 for s in session.steps if s.status is StepStatus.COMPLETED)
    kept = f" Step {step.number} was applied and is kept." if step and step.status in APPLIED else ""
    return UpgradeView(
        Outcome.FINISHED, session, None, message=f"Session ended with {done} of {len(session.steps)} steps done.{kept}"
    )


def abort(env: UpgradeEnv, path: str) -> UpgradeView:
    """Put the project files back as they were at `start` and end the session."""
    root = Path(path)
    session = store.load(root)
    changed = any(s.status in (StepStatus.COMPLETED, *APPLIED) for s in session.steps)
    store.restore(root, store.START, session.snapshot_files)
    if changed:
        find_manager(env.settings, root, session.package_manager).sync_environment()
    store.end(root)
    return UpgradeView(
        Outcome.ABORTED, session, None, message=f"Session aborted. The project files are as they were. {ROLLBACK_NOTE}"
    )
