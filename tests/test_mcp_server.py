"""
Tests for the stdlib MCP server JSON-RPC dispatch (mcp.server).

The tool handlers hit the network, so these tests exercise the protocol layer
with a stubbed handler and verify framing, initialize, tools/list, and errors.
"""

import io
import json
from unittest.mock import MagicMock

from ossiq.mcp import server


def test_initialize_echoes_protocol_and_advertises_tools():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response is not None
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "ossiq"
    assert "tools" in response["result"]["capabilities"]


def test_tools_list_returns_both_tools():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert response is not None
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert names == {"ossiq_evaluate_dependency", "ossiq_evaluate_updates"}


def test_notifications_get_no_response():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response is None


def test_unknown_method_returns_error():
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"})
    assert response is not None
    assert response["error"]["code"] == -32601


def test_tools_call_serializes_verdict(monkeypatch):
    monkeypatch.setitem(server.TOOL_HANDLERS, "ossiq_evaluate_updates", lambda _s, _a: {"verdict": "ok"})
    params = {"name": "ossiq_evaluate_updates", "arguments": {"project_path": "."}}
    response = server.handle_request(MagicMock(), {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": params})
    assert response is not None
    assert response["result"]["content"][0]["text"] == '{"verdict": "ok"}'
    assert "isError" not in response["result"]


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
