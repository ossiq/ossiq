"""Agent renderer for `ossiq upgrade`: one JSON document per subcommand, the same shape every time."""

from __future__ import annotations

import dataclasses
import json
from collections import Counter
from typing import Any

from ossiq.domain.changelog import RangeChangelog
from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.agent import build_update_entry, cve_summary
from ossiq.service.upgrade.models import StepPackage, StepStatus, UpgradeSession, UpgradeStep
from ossiq.service.upgrade.view import PackagePreview, StepPreview, UpgradeView
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer


def changelog_payload(changelog: RangeChangelog, *, full: bool = False) -> dict[str, Any]:
    """The summary of a changelog; the whole UCS document too when *full* (it is inert text, safe to read)."""
    payload: dict[str, Any] = {
        "status": changelog.status.value,
        "detail": changelog.detail,
        "risk_level": changelog.risk_level,
        "breaking_change": changelog.breaking_change,
        "security_fix": changelog.security_fix,
        "cve_references": list(changelog.cve_references),
        "breaking": [
            {"version": i.version, "category": i.category, "text": i.text, "references": list(i.references)}
            for i in changelog.breaking_items
        ],
        "migration_guides": [dataclasses.asdict(guide) for guide in changelog.guides],
        "source_url": changelog.source_url,
        "web_url": changelog.web_url,
    }
    if full:
        payload["markdown"] = changelog.markdown
    return payload


def move_payload(package: StepPackage) -> dict[str, Any]:
    return {"name": package.name, "is_direct": package.is_direct, "from": package.current, "to": package.target}


def package_payload(item: PackagePreview, preview: StepPreview) -> dict[str, Any]:
    payload = move_payload(item.package)
    if item.record is None:
        return payload
    if item.package.is_direct:
        payload["update"] = build_update_entry(item.record, preview.engine_context)
        payload["update_context"] = item.update_context
        payload["changelog"] = changelog_payload(item.changelog) if item.changelog else None
    else:
        payload["cves"] = [cve_summary(cve) for cve in item.record.cve]
    return payload


def step_payload(step: UpgradeStep, preview: StepPreview | None) -> dict[str, Any]:
    if preview:
        packages = [package_payload(item, preview) for item in preview.packages]
    else:
        packages = [move_payload(package) for package in step.packages]
    payload: dict[str, Any] = {
        "step": step.number,
        "status": step.status.value,
        "packages": packages,
        "last_test": dataclasses.asdict(step.last_run) if step.last_run else None,
    }
    if step.note:
        payload["note"] = step.note
    return payload


def session_payload(session: UpgradeSession, step: UpgradeStep | None) -> dict[str, Any]:
    counts = Counter(s.status for s in session.steps)
    return {
        "id": session.session_id,
        "step": step.number if step else None,
        "total_steps": len(session.steps),
        "completed": counts[StepStatus.COMPLETED],
        "skipped": counts[StepStatus.SKIPPED],
        "pending": len(session.steps) - counts[StepStatus.COMPLETED] - counts[StepStatus.SKIPPED],
        "test_command": session.test_command,
        "baseline_exit_code": session.baseline.exit_code if session.baseline else None,
    }


def view_payload(view: UpgradeView) -> dict[str, Any]:
    return {
        "outcome": view.outcome.value,
        "needs_attention": view.attention,
        "message": view.message,
        "session": session_payload(view.session, view.step) if view.session else None,
        "step": step_payload(view.step, view.preview) if view.step else None,
        "changelogs": [
            {"name": package.name, "from": package.current, "to": package.target, **changelog_payload(c, full=True)}
            for package, c in view.changelogs
        ],
        "commands": list(view.commands),
    }


class AgentUpgradeRenderer(AbstractUserInterfaceRenderer):
    """Render an `UpgradeView` as JSON on stdout, for an LLM agent or a script."""

    command = Command.UPGRADE
    user_interface_type = UserInterfaceType.AGENT

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.UPGRADE and user_interface_type == UserInterfaceType.AGENT

    def render(self, data: UpgradeView, **kwargs: Any) -> None:
        print(json.dumps(view_payload(data), indent=2))
