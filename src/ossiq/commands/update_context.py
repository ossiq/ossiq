"""Single-package version diff: what changes between installed and an arbitrary target."""

from dataclasses import dataclass
from typing import Literal

import typer

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.update_context import build_update_context_payload
from ossiq.settings import Settings
from ossiq.ui.registry import get_renderer


@dataclass(frozen=True)
class CommandUpdateContextOptions:
    project_path: str
    package_name: str
    to_version: str | None = None
    registry_type: Literal["npm", "pypi"] | None = None
    allow_prerelease: bool = False


def command_update_context(ctx: typer.Context, options: CommandUpdateContextOptions) -> None:
    """Diff a package's installed (or prospective) version against an arbitrary target: module-
    system/API breaks, engine compatibility, and structural rejections along the way. Unlike
    `recommended_version`, the target here need not be OSS IQ's own pick.
    """
    settings: Settings = ctx.obj
    payload = build_update_context_payload(
        settings,
        project_path=options.project_path,
        package_name=options.package_name,
        target_version=options.to_version,
        registry_type=options.registry_type,
        allow_prerelease=options.allow_prerelease,
    )

    renderer = get_renderer(
        command=Command.UPDATE_CONTEXT,
        user_interface_type=UserInterfaceType.AGENT,
        settings=settings,
    )
    renderer.render(data=payload)
