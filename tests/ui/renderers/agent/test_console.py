"""Tests for the agent-format JSON renderers in ui.renderers.agent.console."""

from __future__ import annotations

import json

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.settings import Settings
from ossiq.ui.renderers.agent.console import AgentUpdateContextRenderer


def test_supports_only_update_context_and_agent():
    assert AgentUpdateContextRenderer.supports(Command.UPDATE_CONTEXT, UserInterfaceType.AGENT) is True
    assert AgentUpdateContextRenderer.supports(Command.UPDATE_CONTEXT, UserInterfaceType.CONSOLE) is False
    assert AgentUpdateContextRenderer.supports(Command.INFO, UserInterfaceType.AGENT) is False


def test_render_prints_the_payload_it_was_handed(capsys):
    """The renderer assembles nothing: service.update_context does that for both front doors, so
    the renderer never sees a registry handle or a raw release list."""
    payload = {"package": "newpkg", "from_version": None, "to_version": "1.0.0"}
    renderer = AgentUpdateContextRenderer(Settings())

    renderer.render(data=payload)

    assert json.loads(capsys.readouterr().out) == payload
