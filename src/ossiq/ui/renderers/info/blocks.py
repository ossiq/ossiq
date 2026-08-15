"""Renderable builders for the info (package deep-dive) console output.

Every function here is pure: it takes scan data and returns a Rich renderable. Nothing prints,
so the renderer in `console.py` owns output order and spacing on its own.
"""

from collections import defaultdict
from typing import Any

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ossiq.domain.common import ConstraintType
from ossiq.domain.cve import CVE
from ossiq.service.package import PackageDetailResult, PackageInsight, PackageWarning, TransitiveCVEGroup
from ossiq.service.project.models import ScanRecord
from ossiq.timeutil import format_time_days
from ossiq.ui.renderers.impact_utils import (
    format_fitness,
    format_lag_status,
    format_probability,
    format_status_badge,
    format_time_delta,
)

SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "default",
}

GATE_STYLE: dict[str, str] = {
    "block": "bold red",
    "quarantine": "bold yellow",
    "pass": "green",
}

LAG_THRESHOLD_DAYS = 180

DASH = "—"


def section(title: str, *body: RenderableType) -> Group:
    """Bold section heading followed by its body renderables."""
    return Group(f"[bold]{title}[/bold]", *body)


def or_dash(value: object | None, template: str = "{}") -> str:
    """Formatted value, or an em dash when it is missing."""
    if value is None:
        return DASH
    return template.format(value)


def or_dash_days(days: float | None) -> str:
    """Humanised day count, or an em dash when it is missing."""
    if days is None:
        return DASH
    return format_time_days(int(days))


def collect_licenses(records: list[ScanRecord]) -> list[str]:
    """Unique licenses across all occurrences, in first-seen order."""
    return list(dict.fromkeys(lic for record in records for lic in record.license or []))


def unique_cves(records: list[ScanRecord]) -> list[CVE]:
    """CVEs across all occurrences, deduplicated by id, in first-seen order."""
    return list({cve.id: cve for record in records for cve in record.cve}.values())


def cve_lines(cves: list[CVE], indent: str = "  ") -> list[Text]:
    """One severity-styled line per CVE, with its summary underneath when present.

    Built as Text rather than markup because severity is padded inside square brackets,
    which Rich would otherwise read as a style tag.
    """
    lines: list[Text] = []
    for cve in cves:
        line = Text(indent)
        line.append(f"[{cve.severity:<8}]", style=SEVERITY_STYLE.get(cve.severity.upper(), "default"))
        line.append(f"  {cve.id}", style="bold")
        line.append(f"  (via {cve.source})")
        lines.append(line)
        if cve.summary:
            lines.append(Text(f"{indent}{cve.summary}"))
    return lines


def header(records: list[ScanRecord]) -> Group:
    """Identity line for an installed package: dependency kinds, lifecycle, license and homepage."""
    record = records[0]
    parts: list[str] = []

    if any(occurrence.dependency_path is None for occurrence in records):
        parts.append("[bold green]DIRECT[/bold green]")
    if any(occurrence.dependency_path is not None for occurrence in records):
        parts.append("[bold yellow]TRANSITIVE[/bold yellow]")

    badge = format_status_badge(record)
    if badge:
        parts.append(badge.strip())

    licenses = collect_licenses(records)
    if licenses:
        label = licenses[0]
        if len(licenses) > 1:
            label += f" +{len(licenses) - 1} more"
        parts.append(label)

    if record.package_url:
        parts.append(f"[dim]{record.package_url}[/dim]")

    title = f"OSS IQ — {record.package_name}  {record.installed_version}"
    return Group(Rule(title, style="bold"), "  " + "  |  ".join(parts))


def prospective_header(data: PackageDetailResult) -> Group:
    """Identity line for a package that is not installed in the project."""
    package = data.prospective_package
    title = f"OSS IQ — {data.prospective_name or 'unknown'}"
    if data.insight and data.insight.latest_version:
        title += f"  {data.insight.latest_version}"

    parts = ["[bold yellow]PROSPECTIVE[/bold yellow]"]
    if package and package.license:
        parts.append(package.license)
    else:
        parts.append("License N/A")
    if package and package.package_url:
        parts.append(f"[dim]{package.package_url}[/dim]")

    lines: list[RenderableType] = [Rule(title, style="bold"), "  " + "  |  ".join(parts)]
    if package and package.description:
        lines += ["", f"  [dim]{package.description}[/dim]"]
    return Group(*lines)


def warnings_panel(warnings: list[PackageWarning]) -> Panel:
    """Prominent panel for policy warnings; red border when any of them is critical."""
    critical = any(warning.severity == "critical" for warning in warnings)

    body = Text()
    for warning in warnings:
        icon = "[bold red]  ✗[/bold red]" if warning.severity == "critical" else "[bold yellow]  ![/bold yellow]"
        body.append_text(Text.from_markup(f"{icon}  [{warning.rule_id}]  {warning.message}\n"))

    title = "⚠  WARNINGS" if critical else "⚠  NOTICES"
    border_style = "bold red" if critical else "bold yellow"
    return Panel(body, title=title, border_style=border_style, expand=False)


def health_metrics(insight: PackageInsight, records: list[ScanRecord] | None = None) -> Group:
    """Registry health signals, plus the risk decomposition when the package is installed."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="dim")
    table.add_column("Value")

    table.add_row("Downloads (last month)", or_dash(insight.downloads_recent, "{:,}"))
    table.add_row("Versions published", str(insight.versions_count))
    table.add_row("Maintainers", or_dash(insight.maintainers_count))
    table.add_row("Latest version age", or_dash_days(insight.latest_version_age_days))

    if insight.recommended_version and insight.recommended_version != insight.latest_version:
        table.add_row("Recommended version age", or_dash_days(insight.recommended_version_age_days))

    if insight.cooldown_days_remaining:
        table.add_row("Cooldown remaining", Text(f"{insight.cooldown_days_remaining} days", style="bold yellow"))
    else:
        table.add_row("Cooldown remaining", DASH)

    if not records:
        return section("Health Metrics", table)

    marker = " *" if len(records) > 1 else ""
    add_risk_rows(table, records[0], marker)
    if not marker:
        return section("Health Metrics", table)

    footnote = f"  [dim]* for occurrence 1 of {len(records)} ({records[0].installed_version}); others may differ[/dim]"
    return section("Health Metrics", table, footnote)


def add_risk_rows(table: Table, record: ScanRecord, marker: str) -> None:
    """Append the health-score channel decomposition for a single occurrence."""
    if record.gate_decision is not None:
        status, reason = record.gate_decision
        table.add_row(f"Gate{marker}", Text(f"{status} — {reason}", style=GATE_STYLE.get(status, "default")))

    table.add_row(f"Fitness{marker}", format_fitness(record.fitness))
    table.add_row(f"Expected exposure{marker}", or_dash(record.expected_exposure, "{:.4f}"))
    table.add_row(f"Impact (blast radius){marker}", or_dash(record.impact, "{:.2f}"))
    table.add_row(f"P(vulnerability){marker}", format_probability(record.p_vuln))
    table.add_row(f"P(supply chain){marker}", format_probability(record.p_supplychain))
    table.add_row(f"Exposure window{marker}", or_dash_days(record.exposure_window_days))


def drift_status(record: ScanRecord) -> Group:
    """Installed-versus-latest position: lag class, both versions and elapsed time."""
    latest_style = "bold green" if record.latest_version else "bold red"
    releases = DASH
    if record.releases_lag:
        releases = f"[bold]{record.releases_lag} versions behind[/bold]"

    return section(
        "Drift Status",
        f"  Status    : {format_lag_status(record.versions_diff_index)}",
        f"  Installed : [bold]{record.installed_version}[/bold]{format_status_badge(record)}",
        f"  Latest    : [{latest_style}]{record.latest_version or 'N/A'}[/]",
        f"  Time Lag  : {format_time_delta(record.time_lag_days, LAG_THRESHOLD_DAYS)}",
        f"  Releases  : {releases}",
    )


def dependency_tree(record: ScanRecord) -> Group:
    """Root-to-package trace showing where this occurrence sits in the dependency graph."""
    path = record.dependency_path or []
    ancestors = [f"  {'  ' * depth}[dim]└─[/dim] {name}" for depth, name in enumerate(path, start=1)]
    leaf_indent = "  " * (len(path) + 1)
    leaf = f"  {leaf_indent}[dim]└─[/dim] [bold]{record.package_name}[/bold]  [dim]← you are here[/dim]"
    return section("Dependency Tree", "  [bold]→[/bold] root", *ancestors, leaf)


def policy_compliance(record: ScanRecord) -> Group:
    """Declared constraint versus what was resolved, plus conflicts and constraint overrides."""
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    table.add_column("Parameter")
    table.add_column("Value")

    table.add_row("Constraint", record.version_constraint or DASH)
    table.add_row("Resolved", Text(record.installed_version, style="bold"))
    table.add_row("Latest", Text(record.latest_version or DASH, style="bold green"))

    if record.recommended_version:
        reason = record.recommended_version_reason
        is_latest = reason is not None and reason.is_latest
        table.add_row(
            "Recommended", Text(record.recommended_version, style="bold green" if is_latest else "bold yellow")
        )

    if record.constraint_conflict:
        specs = ", ".join(record.constraint_conflict)
        table.add_row("Resolution", Text(f"NO VALID VERSION — conflicting constraints: {specs}", style="bold red"))

    constraint = record.constraint_info
    if constraint.type != ConstraintType.DECLARED:
        style = "bold red" if constraint.type == ConstraintType.OVERRIDE else "bold yellow"
        detail = f"{constraint.type.value}  (from {constraint.source_file})"
        table.add_row("Constraint Type", Text(detail, style=style))

    return section("Policy Compliance", table)


def recommendation_rationale(version: str, reason: Any, age_days: int | None) -> Group:
    """Why this version was selected: what was eliminated, what was penalised, what won.

    ponytail: `reason` is a RecommendationReason, but tests/test_import_boundaries.py forbids
    renderers importing ossiq.solver and walks every import unconditionally. Annotate it properly
    once that check learns to skip TYPE_CHECKING blocks.
    """
    age_suffix = ""
    if age_days is not None:
        age_suffix = f"  ({age_days} days old)"

    lines: list[RenderableType] = [f"  Recommended : [bold yellow]{version}[/bold yellow]{age_suffix}"]

    if reason is None:
        lines.append("  (no rationale available)")
        return section("Recommendation Rationale", *lines)

    if reason.constraint:
        lines.append(f"  Constraint  : {reason.constraint}")

    if reason.hard_rejections:
        eliminated: defaultdict[str, list[str]] = defaultdict(list)
        for rejection in reason.hard_rejections:
            eliminated[rejection.detail].append(rejection.version)
        lines += ["", "  Eliminated (hard constraints):"]
        lines += [f"    [bold red]•[/bold red] {', '.join(v)}  — {detail}" for detail, v in eliminated.items()]

    if reason.soft_rejections:
        lines += ["", "  Penalised (soft constraints):"]
        lines += [f"    [bold yellow]•[/bold yellow] {r.version}  — {r.detail}" for r in reason.soft_rejections]

    lines.append("")
    if reason.is_latest:
        lines.append(f"  [bold green]✓[/bold green] {version} selected: latest eligible version")
    else:
        selected_age = ""
        if reason.age_days is not None:
            selected_age = f" ({reason.age_days} days old)"
        lines.append(f"  [bold green]✓[/bold green] {version} selected: best stable candidate{selected_age}")

    return section("Recommendation Rationale", *lines)


def peer_requirements(record: ScanRecord) -> Group:
    """Peer constraints other packages declare against this one, and whether they hold."""
    violated = {requirement.spec for requirement in record.peer_violations}
    via_override = record.constraint_info.type == ConstraintType.OVERRIDE

    lines: list[Text] = []
    for requirement in record.peer_requirements:
        line = Text()
        if requirement.spec in violated:
            line.append("  ✗ ", style="bold red")
        else:
            line.append("  ✓ ", style="bold yellow" if via_override else "bold green")
        line.append(requirement.requirer_name, style="bold")
        line.append(f"  requires  {requirement.spec}")
        if requirement.spec in violated:
            line.append(f"  (installed: {record.installed_version})", style="red")
        elif via_override:
            line.append("  via override", style="yellow")
        lines.append(line)

    return section("Peer Requirements", *lines)


def security_advisories(cves: list[CVE]) -> Group:
    """Advisories affecting the package itself, or an all-clear line."""
    if not cves:
        return section("Security Advisories", "  [bold green]✓[/bold green] No known vulnerabilities")
    return section(f"Security Advisories ({len(cves)} found)", *cve_lines(cves))


def transitive_cves(groups: list[TransitiveCVEGroup]) -> Group:
    """Advisories reached through dependencies, grouped by the package carrying them."""
    lines: list[RenderableType] = []
    for group in groups:
        if lines:
            lines.append("")
        title = Text()
        title.append(f"  {group.name}", style="bold")
        title.append(f"  v{group.version}", style="dim")
        title.append(f"  [{len(group.cves)} CVE{'s' if len(group.cves) != 1 else ''}]", style="bold red")
        lines.append(title)
        lines += cve_lines(group.cves, indent="    ")

    return section(f"Transitive CVEs ({len(groups)} affected)", *lines)


def licenses_block(licenses: list[str]) -> Group:
    """All distinct licenses seen across the package's occurrences."""
    return section("Licenses", "", *[f"  [bold]{lic}[/bold]" for lic in licenses])
