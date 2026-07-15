"""Agent-oriented JSON renderers for the info and status commands.

Emit a compact verdict (see ``service.agent``) to stdout for consumption by an
AI agent. Mirrors the export JSON renderer but with the small verdict shape.
"""

import json
from typing import Any

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.agent import build_add_verdict, build_update_verdict
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanResult
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer


class AgentInfoRenderer(AbstractUserInterfaceRenderer):
    """Render a single-package add verdict as JSON."""

    command = Command.INFO
    user_interface_type = UserInterfaceType.AGENT

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command in (Command.INFO, Command.ADD) and user_interface_type == UserInterfaceType.AGENT

    def render(self, data: Any, **kwargs) -> None:
        detail: PackageDetailResult = data
        verdict = build_add_verdict(detail, requested_version=kwargs.get("requested_version"))
        print(json.dumps(verdict, indent=2))


class AgentStatusRenderer(AbstractUserInterfaceRenderer):
    """Render a project update verdict as JSON."""

    command = Command.STATUS
    user_interface_type = UserInterfaceType.AGENT

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        return command == Command.STATUS and user_interface_type == UserInterfaceType.AGENT

    def render(self, data: Any, **kwargs) -> None:
        scan: ScanResult = data
        print(json.dumps(build_update_verdict(scan), indent=2))
