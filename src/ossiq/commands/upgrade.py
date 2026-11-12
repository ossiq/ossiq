"""`ossiq upgrade`: step through the updates `plan` lists, one at a time."""

from __future__ import annotations

import dataclasses
import os
import sys
import webbrowser
from collections.abc import Callable, Generator
from contextlib import contextmanager, nullcontext
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.domain.exceptions import ApplicationError
from ossiq.service.update.models import PlanOptions
from ossiq.service.update.plan import plan_project
from ossiq.service.upgrade import engine
from ossiq.service.upgrade.engine import Planned, UpgradeEnv
from ossiq.service.upgrade.preview import changelog_fetcher
from ossiq.service.upgrade.view import Outcome, UpgradeView
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer
from ossiq.ui.system import show_error, show_scan_progress

NEEDS_ATTENTION_EXIT = 3
WEB_KEY, QUIT_KEY = "w", "q"
MENU_KEYS = {
    "changelog": "c",
    "apply": "a",
    "test": "t",
    "rollback": "r",
    "skip": "s",
    "continue": "n",
    "finish": "f",
    "abort": "x",
}
ENGINE_CALLS: dict[str, Callable[[UpgradeEnv, str], UpgradeView]] = {
    "changelog": engine.changelog,
    "apply": engine.apply,
    "test": engine.run_tests,
    "rollback": engine.rollback,
    "continue": engine.accept,
    "finish": engine.finish,
    "abort": engine.abort,
}


@contextmanager
def stdout_to_stderr() -> Generator[None, None, None]:
    """Send everything written to stdout, including by child processes, to stderr for a while.

    An agent reads JSON from stdout, and npm, uv and the test command write to the same file
    descriptor; redirecting only Python's `sys.stdout` would leave them free to corrupt it.
    """
    sys.stdout.flush()
    saved = os.dup(1)
    os.dup2(2, 1)
    try:
        yield
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)


def make_env(settings: Settings, output_format: Literal["console", "agent"]) -> UpgradeEnv:
    # On stderr in both formats: it is progress, and an agent reads stdout.
    fetch_changelog = changelog_fetcher(on_wait=lambda text: typer.echo(f"  changelog IQ: {text}", err=True))
    if output_format == "agent":
        return UpgradeEnv(
            settings=settings, plan=lambda options: plan_project(settings, options), fetch_changelog=fetch_changelog
        )

    def plan(options: PlanOptions) -> Planned:
        with show_scan_progress(settings) as progress:
            return plan_project(settings, options, progress)

    return UpgradeEnv(
        settings=settings, plan=plan, on_line=lambda line: typer.echo(f"    {line}"), fetch_changelog=fetch_changelog
    )


def emit(ctx: typer.Context, view: UpgradeView, output_format: Literal["console", "agent"]) -> None:
    """Render the view; exit 3 when the step needs the user, so a script or an agent can branch on it."""
    get_renderer(Command.UPGRADE, UserInterfaceType(output_format), ctx.obj).render(data=view)
    if view.attention:
        raise typer.Exit(NEEDS_ATTENTION_EXIT)


def run_engine(
    ctx: typer.Context,
    output_format: Literal["console", "agent"],
    call: Callable[[UpgradeEnv], UpgradeView],
    interactive_path: str | None = None,
) -> None:
    """Run one engine call and show its view; with *interactive_path*, carry on as a menu in that project."""
    env = make_env(ctx.obj, output_format)
    with stdout_to_stderr() if output_format == "agent" else nullcontext():
        view = call(env)
    if interactive_path is not None:
        run_interactive(ctx, env, view, interactive_path)
    else:
        emit(ctx, view, output_format)


def menu_keys(commands: tuple[str, ...]) -> dict[str, str]:
    """Key → action for what the view offers; `web` comes with `changelog`."""
    by_key = {MENU_KEYS[c]: c for c in commands if c in MENU_KEYS}
    if "changelog" in commands:
        by_key[WEB_KEY] = "web"
    return by_key


def menu_line(commands: tuple[str, ...]) -> str:
    entries = [*menu_keys(commands).items(), (QUIT_KEY, "quit")]
    return "  " + "   ".join(f"{key} {name}" for key, name in entries)


def run_interactive(ctx: typer.Context, env: UpgradeEnv, view: UpgradeView, project_path: str) -> None:
    """Show the step, ask what to do with it, and repeat until the session ends or the user quits.

    Each choice calls the engine function its subcommand calls, so the menu holds no logic of its own.
    Quitting leaves the session as it is; `status --interactive` picks it up again.
    """
    renderer = get_renderer(Command.UPGRADE, UserInterfaceType.CONSOLE, ctx.obj)
    while True:
        renderer.render(data=dataclasses.replace(view, commands=()))
        if view.outcome is not Outcome.IN_PROGRESS:
            return
        by_key = menu_keys(view.commands)
        typer.echo(menu_line(view.commands))
        key = ask_key([*by_key, QUIT_KEY])
        if key == QUIT_KEY:
            typer.echo("Session kept. Resume it with `ossiq upgrade status --interactive`.")
            return
        try:
            view = choose(env, by_key[key], project_path, view)
        except ApplicationError as exc:
            show_error(str(exc), title=exc.title, hint=exc.hint)


def ask_key(allowed: list[str]) -> str:
    while True:
        key = typer.prompt("Choose").strip().lower()
        if key in allowed:
            return key
        typer.echo(f"  Pick one of: {', '.join(allowed)}")


def choose(env: UpgradeEnv, command: str, project_path: str, view: UpgradeView) -> UpgradeView:
    """Do what the menu entry says; return the view to show next."""
    if command == "web":
        open_web(project_path)
        return view
    if command == "skip":
        reason = typer.prompt("Why (optional)", default="", show_default=False).strip()
        return engine.skip(env, project_path, reason or None)
    if command == "abort" and not typer.confirm("Put the project files back as they were and end the session?"):
        return view
    return ENGINE_CALLS[command](env, project_path)


def open_web(project_path: str) -> None:
    for package, url in engine.web_links(project_path):
        typer.echo(f"{package.name}: {url}")
        webbrowser.open(url)


def command_upgrade_start(
    ctx: typer.Context,
    options: PlanOptions,
    *,
    package: str | None,
    limit: int | None,
    test_command: str | None,
    output_format: Literal["console", "agent"],
    interactive: bool = False,
) -> None:
    run_engine(
        ctx,
        output_format,
        lambda env: engine.start(env, options, package=package, limit=limit, test_command=test_command),
        options.project_path if interactive else None,
    )


def command_upgrade(
    ctx: typer.Context,
    run: Callable[[UpgradeEnv, str], UpgradeView],
    project_path: str,
    output_format: Literal["console", "agent"],
    interactive: bool = False,
) -> None:
    run_engine(ctx, output_format, lambda env: run(env, project_path), project_path if interactive else None)


def command_upgrade_changelog(
    ctx: typer.Context, project_path: str, web: bool, output_format: Literal["console", "agent"]
) -> None:
    """Show the current step's changelogs, or with *web* open them on changelogiq.dev instead."""
    if web:
        open_web(project_path)
        return
    command_upgrade(ctx, engine.changelog, project_path, output_format)
