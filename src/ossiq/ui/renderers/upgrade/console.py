"""Console renderer for `ossiq upgrade`: the queue, the step in front of you and what to run next."""

from __future__ import annotations

import os
import shlex
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.rule import Rule

from ossiq.domain.changelog import ChangelogStatus, RangeChangelog
from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.upgrade.models import CommandRun, StepStatus, UpgradeStep
from ossiq.service.upgrade.view import PackagePreview, StepPreview, UpgradeView
from ossiq.settings import Settings
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer
from ossiq.ui.renderers.info.console import installed_blocks
from ossiq.ui.renderers.status.console import ConsoleStatusRenderer

MARKS = {
    StepStatus.COMPLETED: "[green]✓[/green]",
    StepStatus.SKIPPED: "[dim]–[/dim]",
    StepStatus.PENDING: " ",
    StepStatus.AWAITING_REVIEW: "[green]●[/green]",
    StepStatus.AWAITING_REFACTOR: "[red]✗[/red]",
}
OUTPUT_TAIL_LINES = 15
LAG_THRESHOLD_DAYS = 180
BREAKING_SHOWN = 8


def without_front_matter(markdown: str) -> str:
    """The document without its `---` block, which the preview already says in a line."""
    if not markdown.startswith("---\n"):
        return markdown
    return markdown[4:].partition("\n---\n")[2].lstrip("\n")


def step_line(step: UpgradeStep, is_current: bool) -> str:
    lead = step.packages[0]
    more = f" [dim]+{len(step.packages) - 1} more[/dim]" if len(step.packages) > 1 else ""
    note = f" [dim]({escape(step.note)})[/dim]" if step.note else ""
    pointer = "▶" if is_current else " "
    return (
        f"  {pointer} {MARKS[step.status]} {step.number:>2}  {lead.name} {lead.current} → {lead.target}{more}"
        f"  [dim]{step.status.value}[/dim]{note}"
    )


class ConsoleUpgradeRenderer(AbstractUserInterfaceRenderer):
    """Render an `UpgradeView` for a person at a terminal."""

    command = Command.UPGRADE
    user_interface_type = UserInterfaceType.CONSOLE

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self.console = Console()

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.UPGRADE and user_interface_type == UserInterfaceType.CONSOLE

    def render(self, data: UpgradeView, **kwargs: Any) -> None:
        view = data
        session, step = view.session, view.step
        self.console.print()
        if session and step:
            title = f"OSS IQ — Upgrade: step {step.number} of {len(session.steps)}"
        else:
            title = f"OSS IQ — Upgrade: {view.outcome.value.replace('_', ' ').lower()}"
        self.console.print(Rule(title, style="bold"))
        if session:
            for each in session.steps:
                self.console.print(step_line(each, step is not None and each.number == step.number))
            self.console.print()
        if view.message:
            self.console.print(f"  [{'yellow' if view.attention else 'bold'}]{escape(view.message)}[/]")
            self.console.print()
        if view.changelogs:
            self.render_changelogs(view)
        elif view.preview:
            self.render_preview(view.preview)
        elif step and step.last_run and step.last_run.exit_code != 0:
            self.render_failed_run(step.last_run)
        if view.commands:
            self.render_commands(view)

    def render_failed_run(self, run: CommandRun) -> None:
        self.console.print(f"  [red]Test command exited with {run.exit_code}.[/red] Last output:")
        for line in run.output_tail.splitlines()[-OUTPUT_TAIL_LINES:]:
            self.console.print(f"    [dim]{escape(line)}[/dim]", highlight=False)
        self.console.print()

    def render_preview(self, preview: StepPreview) -> None:
        status_table = ConsoleStatusRenderer(self.settings)
        for item in preview.packages:
            package = item.package
            kind = "" if package.is_direct else " [dim](moves with it)[/dim]"
            self.console.print(Rule(f"{package.name} {package.current} → {package.target}{kind}", style="dim"))
            self.console.print()
            if item.record:
                status_table.print_full_table([item.record], LAG_THRESHOLD_DAYS, preview.engine_context)
            if item.detail:
                for block in installed_blocks(item.detail):
                    self.console.print(block)
                    self.console.print()
            self.render_breaks(item)
            if item.changelog:
                self.render_changelog_summary(item.changelog)

    def render_changelog_summary(self, changelog: RangeChangelog) -> None:
        self.console.print("  [bold]Changelog[/bold] [dim](changelog IQ)[/dim]")
        if changelog.status is not ChangelogStatus.OK:
            self.print_unavailable(changelog, indent="    ")
            self.console.print()
            return
        flags = []
        if changelog.risk_level:
            flags.append(f"risk {changelog.risk_level}")
        if changelog.security_fix:
            cves = f" ({', '.join(changelog.cve_references)})" if changelog.cve_references else ""
            flags.append(f"security fix{cves}")
        self.console.print("    " + " · ".join(flags or ["no risk level given"]))
        breaking = changelog.breaking_items
        if breaking:
            noun = "change" if len(breaking) == 1 else "changes"
            self.console.print(f"    [yellow]{len(breaking)} breaking {noun}:[/yellow]")
            for item in breaking[:BREAKING_SHOWN]:
                self.console.print(f"      {item.version}  {escape(item.text)}", highlight=False)
            if len(breaking) > BREAKING_SHOWN:
                self.console.print(
                    f"      [dim]… and {len(breaking) - BREAKING_SHOWN} more in the full changelog[/dim]"
                )
        for guide in changelog.guides:
            self.console.print(
                f"    Migration guide {guide.version}: {escape(guide.title)}  [dim]{escape(guide.url)}[/dim]",
                highlight=False,
            )
        self.console.print(
            f"    [dim]Full range: ossiq upgrade changelog   On the web: {changelog.web_url}[/dim]", highlight=False
        )
        self.console.print()

    def print_unavailable(self, changelog: RangeChangelog, indent: str = "") -> None:
        detail = escape(changelog.detail or "")
        self.console.print(f"{indent}[yellow]Not available ({changelog.status.value}):[/yellow] {detail}")
        self.console.print(f"{indent}Read it on the web: {changelog.web_url}")

    def render_changelogs(self, view: UpgradeView) -> None:
        """Print each changelog whole, through a pager when this is a terminal so a long one can be read."""
        # Without -R, less prints colour codes as raw ESC text; like git, only when the user has no LESS of their own.
        os.environ.setdefault("LESS", "-R")
        with self.console.pager(styles=True):
            for package, changelog in view.changelogs:
                self.console.print(Rule(f"{package.name} {package.current} → {package.target}", style="dim"))
                if changelog.status is ChangelogStatus.OK:
                    self.console.print(Markdown(without_front_matter(changelog.markdown)))
                else:
                    self.print_unavailable(changelog)
                self.console.print()

    def render_breaks(self, item: PackagePreview) -> None:
        context = item.update_context
        if not context or "error" in context:
            return
        self.console.print("  [bold]What changes[/bold]")
        module_system = context["module_system"]
        if context["breaking_change"]:
            self.console.print(
                f"    [yellow]Module-system break:[/yellow] {module_system['from']} → {module_system['to']}"
            )
        else:
            self.console.print("    No module-system break known.")
        engine = context["engine"]
        if engine["compatible"] is False:
            self.console.print(
                f"    [red]Needs {engine['requirement']}[/red], the scan checked {engine['context_version']}."
            )
        for reason in context["comparison"]["reasons"]:
            self.console.print(f"    {escape(reason)}")
        self.console.print()

    def render_commands(self, view: UpgradeView) -> None:
        path = view.session.options.project_path if view.session else "."
        suffix = "" if path == "." else f" {shlex.quote(path)}"
        self.console.print("  [bold]Next[/bold]")
        for command in view.commands:
            self.console.print(f"    ossiq upgrade {command}{suffix}")
        self.console.print()
