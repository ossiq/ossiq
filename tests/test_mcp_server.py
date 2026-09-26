"""
Tests for the stdlib MCP server JSON-RPC dispatch (mcp.server).

The tool handlers hit the network, so these tests exercise the protocol layer
with a stubbed handler and verify framing, initialize, tools/list, and errors.
"""

import io
import json
from unittest.mock import MagicMock, patch

from ossiq.domain.common import DataCompleteness, DataSourceStatus, ScanStep
from ossiq.mcp import server
from ossiq.service.project.models import ScanResult
from ossiq.settings import Settings


def test_scan_is_called_without_a_progress_callback():
    """Regression: stdout is reserved for JSON-RPC, so the MCP front door must never drive the
    progress stepper. It used to pass a hand-rolled `noop_step` whose signature had to track
    scan()'s; now it passes nothing and `ScanProgress`'s own defaults do the swallowing.
    """
    with (
        patch.object(server, "scan") as scan,
        patch.object(server, "project_sources"),
        patch.object(server, "build_update_decide"),
    ):
        server.evaluate_updates(MagicMock(), {"project_path": ".", "runtime": "unknown"})

    assert scan.call_args.kwargs == {}
    assert len(scan.call_args.args) == 1


def test_initialize_echoes_protocol_and_advertises_tools():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response is not None
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "ossiq"
    assert "tools" in response["result"]["capabilities"]


def test_tools_list_returns_all_tools():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert response is not None
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert names == {"ossiq_evaluate_dependency", "ossiq_evaluate_updates", "ossiq_update_context"}


def test_notifications_get_no_response():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response is None


def test_unknown_method_returns_error():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"})
    assert response is not None
    assert response["error"]["code"] == -32601


def test_tools_call_serializes_decision(monkeypatch):
    monkeypatch.setitem(
        server.TOOL_HANDLERS, "ossiq_evaluate_updates", lambda _s, _a: {"next_action": "no action needed"}
    )
    params = {"name": "ossiq_evaluate_updates", "arguments": {"project_path": "."}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": params})
    assert response is not None
    assert response["result"]["content"][0]["text"] == '{"next_action": "no action needed"}'
    assert "isError" not in response["result"]


def test_tools_call_update_context_round_trip(monkeypatch):
    monkeypatch.setitem(
        server.TOOL_HANDLERS,
        "ossiq_update_context",
        lambda _s, _a: {"package": "chalk", "to_version": "6.0.0", "breaking_change": "ESM-only from 5.0.0"},
    )
    params = {"name": "ossiq_update_context", "arguments": {"package": "chalk", "target_version": "6.0.0"}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params})
    assert response is not None
    assert "isError" not in response["result"]
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload == {"package": "chalk", "to_version": "6.0.0", "breaking_change": "ESM-only from 5.0.0"}


def test_tools_call_unknown_tool_is_error():
    params = {"name": "nope", "arguments": {}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params})
    assert response is not None
    assert response["result"]["isError"] is True


def test_ping_returns_empty_result():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 7, "method": "ping"})
    assert response == {"jsonrpc": "2.0", "id": 7, "result": {}}


def test_tool_schemas_required_fields_exist_in_properties():
    for tool in server.TOOLS:
        schema = tool["inputSchema"]
        for field in schema.get("required", []):
            assert field in schema["properties"], f"{tool['name']}: required '{field}' missing from properties"
        assert tool["name"] in server.TOOL_HANDLERS


def test_serve_loop_end_to_end(monkeypatch, capsys):
    """Full stdio session: framing, blank lines, garbage JSON, and notifications are handled."""
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        "",
        "not json at all",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(lines) + "\n"))
    server.serve(MagicMock())
    output = capsys.readouterr().out
    responses = [json.loads(line) for line in output.strip().splitlines()]
    assert [response["id"] for response in responses] == [1, 2]
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
    assert {tool["name"] for tool in responses[1]["result"]["tools"]} == set(server.TOOL_HANDLERS)


def test_tools_call_handler_exception_is_reported(monkeypatch):
    def boom(_s, _a):
        raise ValueError("kaboom")

    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", boom)
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": params})
    assert response is not None
    assert response["result"]["isError"] is True
    assert "kaboom" in response["result"]["content"][0]["text"]


def test_tools_call_application_error_includes_title_and_hint(monkeypatch):
    """cli.py's error_boundary() already renders title+hint for ApplicationError; the MCP
    handler used to discard both and print only the class name and message, which is the
    direct source of the bare 'UnknownProjectPackageManager: Unable to identify Package
    Manager' text with no remedy that PLAN.md reported."""
    from ossiq.domain.exceptions import UnknownProjectPackageManager

    def boom(_s, _a):
        raise UnknownProjectPackageManager("Unable to identify Package Manager for project at .")

    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", boom)
    params = {"name": "ossiq_evaluate_updates", "arguments": {}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": params})
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "Unknown Package Manager" in text  # .title
    assert "ossiq supports" in text  # .hint, not just the exception name + message


def test_evaluate_updates_surfaces_degraded_data_sources(monkeypatch):
    """B4 on the MCP surface: an agent calling ossiq_evaluate_updates while OSV is unreachable
    must see that in the payload. The console gets show_scan_progress's warning; MCP bypasses
    the stepper entirely, so data_completeness inside the document is its only channel.
    """
    scan_result = ScanResult(
        project_name="proj",
        packages_registry="PYPI",
        project_path=".",
        production_packages=[],
        optional_packages=[],
        data_completeness=DataCompleteness(by_step={ScanStep.VULNERABILITIES: DataSourceStatus.UNREACHABLE}),
    )
    monkeypatch.setattr(server, "project_sources", MagicMock())
    monkeypatch.setattr(server, "scan", lambda _sources: scan_result)

    decision = server.evaluate_updates(Settings(), {"project_path": ".", "runtime": "unknown"})

    assert decision["data_completeness"]["overall"] == "unreachable"
    assert {"step": "vulnerabilities", "status": "unreachable"} in decision["data_completeness"]["sources"]


def test_a_missing_runtime_is_a_titled_error_not_a_probe():
    """D1-1: the MCP server never falls back to probing its own PATH - that probe answers for the
    wrong shell, and it made identical requests disagree."""
    params = {"name": "ossiq_evaluate_updates", "arguments": {"project_path": "."}}

    response = server.handle_request(Settings(), {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params})

    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "Runtime Not Provided" in text
    assert "node -v" in text


def test_a_stated_runtime_replaces_the_probe(monkeypatch):
    seen: list[Settings] = []
    monkeypatch.setattr(server, "project_sources", MagicMock())
    monkeypatch.setattr(server, "scan", MagicMock())
    monkeypatch.setattr(server, "build_update_decide", MagicMock(return_value={}))
    monkeypatch.setattr(
        server.project_sources, "build_project_sources", lambda settings, *_a, **_k: seen.append(settings)
    )

    server.evaluate_updates(Settings(), {"project_path": ".", "runtime": {"node": "22.12.0"}})
    server.evaluate_updates(Settings(), {"project_path": ".", "runtime": "unknown"})

    stated, unknown = seen
    assert (stated.probe_runtime, stated.engine_versions, stated.runtime_unknown) == (False, {"node": "22.12.0"}, False)
    assert (unknown.probe_runtime, unknown.engine_versions, unknown.runtime_unknown) == (False, {}, True)


def test_every_scanning_tool_requires_a_runtime():
    assert all("runtime" in tool["inputSchema"]["required"] for tool in server.TOOLS)
